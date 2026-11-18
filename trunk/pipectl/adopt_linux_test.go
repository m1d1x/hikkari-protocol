package pipectl

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// A rollout of the entry cuts no live flow (owner's decision of 18.11;
// spec/trunk.md, "An entry's own process replaced"): the old pipe hands its
// flows to the new one, which the exit adopts under its own session with
// the same socket to the relay. 17.11 20:40:52 the old generation left 30
// minutes after a rollout and cut 2 flows of a tester's call.

// sourceEcho is a relay's UDP port that sends each datagram back and keeps
// every address it heard from: an exit that kept a flow's socket shows one.
type sourceEcho struct {
	port uint16
	mu   sync.Mutex
	from map[netip.AddrPort]int
}

func newSourceEcho(t *testing.T) *sourceEcho {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	e := &sourceEcho{port: uint16(c.LocalAddr().(*net.UDPAddr).Port), from: map[netip.AddrPort]int{}}
	go func() {
		b := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			e.mu.Lock()
			e.from[from]++
			e.mu.Unlock()
			_, _ = c.WriteToUDPAddrPort(b[:n], from)
		}
	}()
	return e
}

func (e *sourceEcho) sources() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.from)
}

// adoptPipe is a pipe under this brain to the exit of r: a udp wire of 2
// members and a pool of 2, voice on the wire; up.
func adoptPipe(t *testing.T, r *rustReload) *Pipe {
	p, err := Start(Config{Bin: pipeBin(t), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: r.wire.LocalAddr().(*net.UDPAddr).AddrPort(), Key: testKey, Members: 2}); err != nil {
		t.Fatal(err)
	}
	if err := p.SetPool(Pool{ID: trunk.PoolWire, Members: 2, Exit: netip.MustParseAddrPort(r.pool.Addr().String())}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: trunk.PoolWire})
	waitFor(t, 5*time.Second, "the pipe's wire and pool up", func() bool { return wireUp(p, dgramWire, 2) && wireUp(p, trunk.PoolWire, 2) })
	return p
}

// TestAReloadHandsALiveCallToTheNewPipe: a client calls through pipe a; the
// brain reloads it into pipe b. a hands the call's flow to b within
// seconds, not when the call ends, and drains; the call hears no pause over
// 150 ms and loses nothing; the relay hears it from one socket all along.
func TestAReloadHandsALiveCallToTheNewPipe(t *testing.T) {
	r := newRustReload(t)
	echo := newSourceEcho(t)
	if err := r.old.SetPorts([]uint16{echo.port, r.tcp}); err != nil {
		t.Fatal(err)
	}
	a := adoptPipe(t, r)
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := a.Listen(0, lc, trunk.ClassVoice, echo.port, 1); err != nil {
		t.Fatal(err)
	}
	k := newCaller(t, lc.LocalAddr().(*net.UDPAddr).AddrPort())
	k.call()
	time.Sleep(time.Second)

	b := adoptPipe(t, r)
	if err := a.Handoff(b); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.Drained():
	case <-time.After(5 * time.Second):
		t.Fatalf("a did not drain in 5 s under a live call: flows a %d, b %d", flowsOn(a), flowsOn(b))
	}
	time.Sleep(2 * time.Second)
	if fa, fb := flowsOn(a), flowsOn(b); fa != 0 || fb != 1 {
		t.Errorf("flows: a %d, b %d; want the call b's", fa, fb)
	}
	a.Close()
	time.Sleep(time.Second)
	checkCall(t, "the call handed over", k, 0, 150*time.Millisecond)
	if n := echo.sources(); n != 1 {
		t.Errorf("the relay heard the call from %d sockets, want 1", n)
	}
}

// TestAnExitThatDoesNotAdoptLeavesTheCallWithTheOldPipe: the Go exit never
// says it adopts, as an exit that predates adopt: the old pipe carries the
// call as before, and nothing is cut or lost at the reload.
func TestAnExitThatDoesNotAdoptLeavesTheCallWithTheOldPipe(t *testing.T) {
	ctx := t.Context()
	_, wire, echo := newDgramExit(t, ctx, newGoExit)
	mk := func() *Pipe {
		p := genPipe(t, wire, 0)
		return p
	}
	a := mk()
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := a.Listen(0, lc, trunk.ClassVoice, echo, 1); err != nil {
		t.Fatal(err)
	}
	k := newCaller(t, lc.LocalAddr().(*net.UDPAddr).AddrPort())
	k.call()
	time.Sleep(time.Second)
	b := mk()
	if err := a.Handoff(b); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if fa, fb := flowsOn(a), flowsOn(b); fa != 1 || fb != 0 {
		t.Errorf("flows: a %d, b %d; want the call left with a", fa, fb)
	}
	checkCall(t, "the call left with the old pipe", k, 0, 150*time.Millisecond)
}
