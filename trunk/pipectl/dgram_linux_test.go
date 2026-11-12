package pipectl

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// Datagrams of the pipe against each exit (the Go exit, and the Rust exit's
// pipe of R1.6), each scenario run through the Go entry as well (R1.2, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»):
// copies 1 and 2, copies dropped by seq at both ends (spec/trunk.md,
// "Datagrams"), and a client's flow ended unused. The Go entry is what the
// production entry runs: trunk.Entry with the udp wire, a flow per client
// address as trunkentry's udpPort opens it. Both entries must count as one.

const dgramWire trunk.WireID = 2

// dgramEntry is either entry under test: a client port in front of it, the
// trunk's counts of its clients' datagrams, and the exit behind it.
type dgramEntry struct {
	name   string
	client netip.AddrPort
	exit   testExit
	counts func() (flows int, out, in, copies, idle int64)
}

// entries are both entries under test, the reference first.
var entries = []struct {
	name string
	mk   func(*testing.T, context.Context, exitMaker, int, time.Duration) *dgramEntry
}{{"go", goEntry}, {"pipe", pipeEntry}}

type exitMaker = func(*testing.T, context.Context, ...uint16) testExit

// onEach runs f on a stand of each entry before each exit, in a subtest of
// its own: its pipes, its exit and its sockets end with it.
func onEach(t *testing.T, name string, copies int, idle time.Duration, f func(*testing.T, *dgramEntry)) {
	for _, x := range exits {
		for _, en := range entries {
			t.Run(name+"/"+en.name+"/"+x.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				f(t, en.mk(t, ctx, x.mk, copies, idle))
			})
		}
	}
}

// newDgramExit is an exit over the udp wire, the relay behind it an echo.
func newDgramExit(t *testing.T, ctx context.Context, mk exitMaker) (testExit, netip.AddrPort, uint16) {
	echo := udpEcho(t)
	x := mk(t, ctx, echo)
	return x, x.addr(), echo
}

// pipeEntry: the pipe under this brain, one udp wire of 2 members, a
// client port of `copies` copies; flows unused for idle end.
func pipeEntry(t *testing.T, ctx context.Context, mk exitMaker, copies int, idle time.Duration) *dgramEntry {
	x, wire, echo := newDgramExit(t, ctx, mk)
	var args []string
	if idle > 0 {
		args = []string{"--flow-idle-ms", strconv.Itoa(int(idle / time.Millisecond))}
	}
	p, err := Start(Config{Bin: pipeBin(t), Args: args, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: wire, Key: testKey, Members: 2}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: dgramWire})
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Listen(0, lc, trunk.ClassVoice, echo, copies); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the pipe's members up", func() bool { return wireUp(p, dgramWire, 2) })
	return &dgramEntry{name: "pipe", client: lc.LocalAddr().(*net.UDPAddr).AddrPort(), exit: x,
		counts: func() (int, int64, int64, int64, int64) {
			tk, _ := p.Tick()
			return tk.Flows, int64(tk.DgramsOut), int64(tk.DgramsIn), int64(tk.DgramsCopy), int64(tk.FlowsIdle)
		}}
}

// goEntry: the Go entry the same way, its one pool member a plain pipe to
// the exit (the pool carries no datagram here: the route is the udp wire).
func goEntry(t *testing.T, ctx context.Context, mk exitMaker, copies int, idle time.Duration) *dgramEntry {
	x, wire, echo := newDgramExit(t, ctx, mk)
	e := newGoEntry(t, idle)
	if err := e.AddWire(trunk.Wire{ID: dgramWire, Name: "udp", Shape: "random", Members: 2, Packet: true,
		Dial: udpwire.Dialer{Exit: wire, Key: testKey}.Dial}); err != nil {
		t.Fatal(err)
	}
	e.SetRoute(trunk.Route{Voice: dgramWire, Bulk: dgramWire})
	go e.Run(ctx)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go serveGoPort(e, pc, echo, copies)
	waitFor(t, 5*time.Second, "the Go entry's members up", func() bool { return e.Wires()[dgramWire].Members == 2 })
	return &dgramEntry{name: "go", client: pc.LocalAddr().(*net.UDPAddr).AddrPort(), exit: x,
		counts: func() (int, int64, int64, int64, int64) {
			st := e.Session().Stats()
			return st.Flows, st.DgramsOut, st.DgramsIn, st.DgramsCopy, -1 // Stats has no idle count
		}}
}

// newGoEntry is the Go entry the tests add their udp wire to. Its pool
// never comes up: the Rust exit serves no stream member yet (R1.7), and the
// datagrams go on the udp wire, the route of both classes.
func newGoEntry(t *testing.T, idle time.Duration) *trunk.Entry {
	ports, err := trunk.NewPortBook(20000, 30000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pool := func(ctx context.Context, _ int) (io.ReadWriteCloser, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	e, err := trunk.NewEntry(trunk.Config{FlowIdle: idle}, 1, pool, ports, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// serveGoPort is trunkentry's udpPort: a flow per client address, opened on
// its first datagram and forgotten at its end.
func serveGoPort(e *trunk.Entry, pc *net.UDPConn, to uint16, copies int) {
	var mu sync.Mutex
	flows := map[netip.AddrPort]*trunk.Flow{}
	buf := make([]byte, trunk.MaxPayload)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		mu.Lock()
		f := flows[from]
		if f == nil {
			var nf *trunk.Flow
			nf = e.Session().OpenFlowWith(to, trunk.FlowOptions{Copies: copies, Class: trunk.ClassVoice, Pin: trunk.AnyWire},
				func(b []byte) { _, _ = pc.WriteToUDPAddrPort(b, from) },
				func() {
					mu.Lock()
					if flows[from] == nf {
						delete(flows, from)
					}
					mu.Unlock()
				})
			flows[from] = nf
			f = nf
		}
		mu.Unlock()
		f.Send(buf[:n])
	}
}

// burst sends n datagrams numbered from first, one every 2 ms, from one
// client socket, and counts the answers by number until quiet for 300 ms.
type burst struct {
	c    *net.UDPConn
	mu   sync.Mutex
	got  map[uint64]int
	done chan struct{}
}

func newBurst(t *testing.T, to netip.AddrPort) *burst {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	b := &burst{c: c, got: map[uint64]int{}, done: make(chan struct{})}
	go func() {
		p := make([]byte, 2048)
		for {
			n, err := c.Read(p)
			if err != nil {
				return
			}
			if n >= 8 {
				b.mu.Lock()
				b.got[binary.BigEndian.Uint64(p)]++
				b.mu.Unlock()
			}
		}
	}()
	return b
}

func (b *burst) send(first, n uint64) {
	p := make([]byte, 160)
	for s := first; s < first+n; s++ {
		binary.BigEndian.PutUint64(p, s)
		_, _ = b.c.Write(p)
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
}

// answers is how many numbers were answered, and how many more than once.
func (b *burst) answers() (once, twice int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range b.got {
		once++
		if k > 1 {
			twice++
		}
	}
	return once, twice
}

// TestCopiesAreCountedAndDroppedAsByTheGoEntry: n datagrams of one client
// through each entry, its port of one copy and of two. One copy: every
// datagram on one member, no copy at either end. Two: each on both members;
// the exit drops one of every two and, once a copy came, answers on two as
// well, so the entry drops the copies of nearly every answer. The client
// hears each datagram once, and the pipe counts what the Go entry counts,
// the Rust exit what the Go exit counts.
func TestCopiesAreCountedAndDroppedAsByTheGoEntry(t *testing.T) {
	const n = 200
	for _, copies := range []int{1, 2} {
		type row struct {
			flows                   int
			out, in, cp, xin, xcopy int64
		}
		var rows []row
		onEach(t, "copies"+strconv.Itoa(copies), copies, 0, func(t *testing.T, e *dgramEntry) {
			b := newBurst(t, e.client)
			b.send(1, n)
			once, twice := b.answers()
			if once != n || twice != 0 {
				t.Errorf("%s copies %d: %d of %d answered, %d more than once", e.name, copies, once, n, twice)
			}
			var r row
			waitFor(t, 3*time.Second, e.name+" counts every answer", func() bool {
				r.flows, r.out, r.in, r.cp, _ = e.counts()
				return r.in == n
			})
			_, r.xin, r.xcopy = e.exit.counts()
			t.Logf("%s copies %d: flows %d, out %d, in %d, copies dropped %d; exit: relayed %d, copies dropped %d",
				e.name, copies, r.flows, r.out, r.in, r.cp, r.xin, r.xcopy)
			if r.flows != 1 || r.out != n || r.xin != n {
				t.Errorf("%s copies %d: flows %d, out %d, exit relayed %d; want 1, %d, %d", e.name, copies, r.flows, r.out, r.xin, n, n)
			}
			wantX := int64(0)
			if copies == 2 {
				wantX = n
			}
			if r.xcopy != wantX {
				t.Errorf("%s copies %d: the exit dropped %d copies, want %d", e.name, copies, r.xcopy, wantX)
			}
			// The exit answers on one member until a copy arrives: the
			// first answer or two may come once.
			if copies == 1 && r.cp != 0 || copies == 2 && (r.cp < n-2 || r.cp > n) {
				t.Errorf("%s copies %d: the entry dropped %d copies of %d answers", e.name, copies, r.cp, n)
			}
			rows = append(rows, r)
		})
		// The Go entry before the Go exit is the reference for every other
		// pair (a pair skipped for a pipe not built is missing).
		for i := 1; i < len(rows); i++ {
			if g, p := rows[0], rows[i]; g.out != p.out || g.in != p.in || g.xin != p.xin || g.xcopy != p.xcopy || absDiff(g.cp, p.cp) > 2 {
				t.Errorf("copies %d: pair %d counts %+v, the Go entry before the Go exit %+v", copies, i, p, g)
			}
		}
	}
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

// TestAClientsFlowUnusedEndsAndItsNextDatagramOpensANewOne: a client's flow
// ends after FlowIdle unused (1 s here, 2 minutes in the trunk); the next
// datagram from the same address opens a new flow, a new stream id at the
// exit, and is answered as the first one was. The Go entry the same, before
// either exit.
func TestAClientsFlowUnusedEndsAndItsNextDatagramOpensANewOne(t *testing.T) {
	onEach(t, "idle", 1, time.Second, func(t *testing.T, e *dgramEntry) {
		b := newBurst(t, e.client)
		b.send(1, 20)
		// The pipe's counts come with its tick, once a second.
		waitFor(t, 2*time.Second, e.name+": one flow, 20 datagrams each way", func() bool {
			f, out, in, _, _ := e.counts()
			return f == 1 && out == 20 && in == 20
		})
		waitFor(t, 4*time.Second, e.name+": the flow ends unused", func() bool {
			f, _, _, _, idle := e.counts()
			return f == 0 && (idle == 1 || idle == -1)
		})
		b.send(21, 20)
		once, twice := b.answers()
		if once != 40 || twice != 0 {
			t.Errorf("%s: %d of 40 answered, %d more than once", e.name, once, twice)
		}
		waitFor(t, 2*time.Second, e.name+": 40 datagrams each way", func() bool {
			_, out, in, _, _ := e.counts()
			return out == 40 && in == 40
		})
		xflows, _, _ := e.exit.counts()
		f, out, in, _, _ := e.counts()
		t.Logf("%s: flows %d, out %d, in %d; exit flows %d (its own idle is 2 min)", e.name, f, out, in, xflows)
		if f != 1 || xflows != 2 {
			t.Errorf("%s: %d flows at the entry, %d at the exit; want 1 and 2 (a new stream id for the address)", e.name, f, xflows)
		}
	})
}
