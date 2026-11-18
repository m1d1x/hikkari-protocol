package pipectl

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
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

// countingEcho is a relay's TCP port that sends every byte back and counts
// the connections it took: an exit that kept a stream's connection shows
// one.
func countingEcho(t *testing.T) (port uint16, conns *atomic.Int32) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	conns = &atomic.Int32{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port), conns
}

// pattern is byte i of what the client sends.
func pattern(i int64) byte { return byte(i % 251) }

// TestAReloadHandsALiveStreamToTheNewPipe: a client's TCP connection
// carries bytes both ways through pipe a, 16 KiB every 10 ms or as fast as
// the windows let it (chunks kept past holes, bytes waiting for the client:
// what the old pipe must not lose); the brain
// reloads a into b. a hands the stream, its client's connection with it, to
// b within seconds and drains; every byte comes back once and in order, the
// client's connection never ends, its longest wait for bytes stays under a
// second, and the relay holds one connection all along.
func TestAReloadHandsALiveStreamToTheNewPipe(t *testing.T) {
	for _, pace := range []time.Duration{10 * time.Millisecond, 0} {
		t.Run(fmt.Sprintf("every %v", pace), func(t *testing.T) { handStream(t, pace) })
	}
}

func handStream(t *testing.T, pace time.Duration) {
	r := newRustReload(t)
	port, conns := countingEcho(t)
	if err := r.old.SetPorts([]uint16{r.udp, port}); err != nil {
		t.Fatal(err)
	}
	a := adoptPipe(t, r)
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := a.TCPListen(0, ln, port); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	var sent, got atomic.Int64
	stop := make(chan struct{})
	writeErr := make(chan error, 1)
	go func() {
		b := make([]byte, 16<<10)
		for {
			select {
			case <-stop:
				writeErr <- nil
				return
			case <-time.After(pace):
			}
			at := sent.Load()
			for i := range b {
				b[i] = pattern(at + int64(i))
			}
			if _, err := c.Write(b); err != nil {
				writeErr <- err
				return
			}
			sent.Add(int64(len(b)))
		}
	}()
	readErr := make(chan error, 1)
	var stall atomic.Int64
	go func() {
		b := make([]byte, 64<<10)
		last := time.Now()
		for {
			n, err := c.Read(b)
			now := time.Now()
			if d := now.Sub(last); n > 0 && got.Load() > 0 && int64(d) > stall.Load() {
				stall.Store(int64(d))
			}
			last = now
			at := got.Load()
			for i := 0; i < n; i++ {
				if b[i] != pattern(at+int64(i)) {
					readErr <- fmt.Errorf("byte %d is %d, want %d", at+int64(i), b[i], pattern(at+int64(i)))
					return
				}
			}
			got.Add(int64(n))
			if err != nil {
				readErr <- err
				return
			}
		}
	}()
	time.Sleep(time.Second)

	b := adoptPipe(t, r)
	if err := a.Handoff(b); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.Drained():
	case err := <-readErr:
		t.Fatalf("the client's connection under the reload: %v", err)
	case <-time.After(8 * time.Second):
		t.Fatalf("a did not drain in 8 s under a live stream: a has %d bytes back of %d sent", got.Load(), sent.Load())
	}
	a.Close()
	time.Sleep(2 * time.Second)
	close(stop)
	if err := <-writeErr; err != nil {
		t.Fatalf("writing after the reload: %v", err)
	}
	waitFor(t, 5*time.Second, "every byte back", func() bool { return got.Load() == sent.Load() })
	select {
	case err := <-readErr:
		t.Fatalf("the client's connection: %v", err)
	default:
	}
	t.Logf("the stream handed over: %d bytes each way, longest wait %v", sent.Load(), time.Duration(stall.Load()).Round(time.Millisecond))
	if n := conns.Load(); n != 1 {
		t.Errorf("the relay took %d connections, want 1", n)
	}
	if d := time.Duration(stall.Load()); d > time.Second {
		t.Errorf("the client waited %v for bytes", d)
	}
}
