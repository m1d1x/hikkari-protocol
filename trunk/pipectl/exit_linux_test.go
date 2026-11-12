package pipectl

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// The exit's pipe is rust/exit's hk-exit, built for this box (rust/README.md):
// HK_EXIT=/path/to/hk-exit. Without it the tests on the Rust exit are skipped.
func exitBin(t *testing.T) string {
	bin := os.Getenv("HK_EXIT")
	if bin == "" {
		t.Skip("HK_EXIT is not set: no exit's pipe to run")
	}
	return bin
}

// testExit is the exit a test runs against: the Go exit (trunk.Exit over
// udpwire, the reference) or the Rust exit's pipe under this brain (R1.6).
type testExit interface {
	addr() netip.AddrPort
	// buried is how many members it buried, by their stall or by Quiet
	// (trunk Stats.MembersStall).
	buried() int64
	// counts is its clients' flows open, datagrams delivered to the relay,
	// copies dropped (trunk Stats.Flows, DgramsIn, DgramsCopy), as of now.
	counts() (flows int, in, copies int64)
	// pid is the exit's own process; 0 for one inside the test.
	pid() int
}

// exits are both exits under test, the reference first.
var exits = []struct {
	name string
	mk   func(t *testing.T, ctx context.Context, ports ...uint16) testExit
}{{"goexit", newGoExit}, {"rustexit", newRustExit}}

// onEachExit runs f on each exit in a subtest of its own.
func onEachExit(t *testing.T, f func(t *testing.T, mk func(*testing.T, context.Context, ...uint16) testExit)) {
	for _, x := range exits {
		t.Run(x.name, func(t *testing.T) { f(t, x.mk) })
	}
}

type goExit struct {
	x *trunk.Exit
	l *udpwire.Listener
}

func newGoExit(t *testing.T, ctx context.Context, _ ...uint16) testExit {
	x := trunk.NewExit(trunk.Config{}, local{})
	go x.Run(ctx)
	l, err := udpwire.Listen("127.0.0.1:0", []string{testKey}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &goExit{x, l}
}

func (g *goExit) addr() netip.AddrPort { return g.l.Addr() }
func (g *goExit) buried() int64 {
	_, st := g.x.Stats()
	return st.MembersStall
}
func (g *goExit) counts() (int, int64, int64) {
	_, st := g.x.Stats()
	return st.Flows, st.DgramsIn, st.DgramsCopy
}
func (g *goExit) pid() int { return 0 }

type rustExit struct {
	x *Exit
	a netip.AddrPort
}

// newRustExit: hk-exit under this brain, one udp wire on a socket the brain
// bound, the test's trunk key, ports open to the trunk.
func newRustExit(t *testing.T, ctx context.Context, ports ...uint16) testExit {
	x, err := StartExit(ExitConfig{Bin: exitBin(t), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := x.SetWire(ExitWire{ID: healthWire, Conn: c, Keys: []string{testKey}}); err != nil {
		t.Fatal(err)
	}
	if err := x.SetPorts(ports); err != nil {
		t.Fatal(err)
	}
	return &rustExit{x, c.LocalAddr().(*net.UDPAddr).AddrPort()}
}

func (r *rustExit) addr() netip.AddrPort { return r.a }

// fresh is a tick sent after the call: what the exit counts now, a second
// late at most.
func (r *rustExit) fresh() ExitTick {
	asked := time.Now()
	for {
		tk, at := r.x.Tick()
		if at.After(asked) {
			return tk
		}
		select {
		case <-r.x.Done():
			return tk
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (r *rustExit) buried() int64 {
	tk, _ := r.x.Tick()
	return int64(tk.Silent + tk.Quiet)
}
func (r *rustExit) counts() (int, int64, int64) {
	tk := r.fresh()
	return tk.Flows, int64(tk.DgramsIn), int64(tk.DgramsCopy)
}
func (r *rustExit) pid() int { return r.x.Pid() }

// TestAPortNotOpenToTheTrunkGetsNothing: the Rust exit reaches only the
// loopback ports the brain opened, as the edge's trunkLocal.DialFlow
// refuses the others (errTrunkPort): a flow to another port opens no
// socket and is answered nothing, a flow to an open one is, and the trunk's
// call (port 0) always is. The Go entry carries both.
func TestAPortNotOpenToTheTrunkGetsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	open, shut := udpEcho(t), udpEcho(t)
	x := newRustExit(t, ctx, open).(*rustExit)
	e := newGoEntry(t, 0)
	if err := e.AddWire(trunk.Wire{ID: healthWire, Name: "udp", Shape: "random", Members: 2, Packet: true,
		Dial: udpwire.Dialer{Exit: x.addr(), Key: testKey}.Dial}); err != nil {
		t.Fatal(err)
	}
	e.SetRoute(trunk.Route{Voice: healthWire, Bulk: healthWire})
	go e.Run(ctx)
	waitFor(t, 5*time.Second, "the Go entry's members up", func() bool { return e.Wires()[healthWire].Members == 2 })
	heard := map[uint16]int{}
	var mu sync.Mutex
	for _, port := range []uint16{open, shut, trunk.EchoPort} {
		f := e.Session().OpenFlowWith(port, trunk.FlowOptions{Copies: 1, Pin: trunk.AnyWire}, func([]byte) {
			mu.Lock()
			heard[port]++
			mu.Unlock()
		}, nil)
		for range 10 {
			f.Send([]byte("hello"))
			time.Sleep(2 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond)
	tk := x.fresh()
	mu.Lock()
	defer mu.Unlock()
	t.Logf("answers by port %v; exit: flows %d, delivered %d, refused %d", heard, tk.Flows, tk.DgramsIn, tk.Refused)
	if heard[open] != 10 || heard[shut] != 0 || heard[trunk.EchoPort] != 10 {
		t.Errorf("answers by port %v: want 10 from the open port and the call, none from the shut one", heard)
	}
	if tk.Flows != 1 || tk.DgramsIn != 10 || tk.Refused != 10 {
		t.Errorf("exit flows %d, delivered %d, refused %d; want 1, 10, 10", tk.Flows, tk.DgramsIn, tk.Refused)
	}
}
