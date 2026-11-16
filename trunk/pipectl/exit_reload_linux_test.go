package pipectl

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// A reload of the Rust exit (R6.4.1, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»;
// spec/trunk.md, "An exit's own process replaced"): two hk-exit under this
// brain on the same sockets, the old one drains to the new one, and the
// pipe answers the drain as it answers the Go exit's (R4.1,
// exit_drain_linux_test.go). Here nothing stands between the pipe and the
// exits' sockets: which process a member reaches is the exits' own doing.

// exitIdle is the exits' and the pipe's idle limit of a flow in these
// tests: a call hung up ends in half a second, not 2 minutes.
const exitIdle = "500"

// rustReload is the Rust exit's generations behind one udp wire socket and
// one pool port, the relay behind them echoes (udp and tcp).
type rustReload struct {
	old, next *Exit
	wire      *net.UDPConn
	pool      *net.TCPListener
	udp, tcp  uint16
	t         *testing.T
}

func startRustExit(t *testing.T, gen byte) *Exit {
	x, err := StartExit(ExitConfig{Bin: exitBin(t), Args: []string{"--flow-idle-ms", exitIdle}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.Close() })
	if err := x.SetGeneration(gen); err != nil {
		t.Fatal(err)
	}
	return x
}

func newRustReload(t *testing.T) *rustReload {
	r := &rustReload{old: startRustExit(t, 0), udp: udpEcho(t), tcp: tcpEcho(t), t: t}
	var err error
	if r.wire, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.wire.Close() })
	if err := r.old.SetWire(ExitWire{ID: dgramWire, Conn: r.wire, Keys: []string{testKey}}); err != nil {
		t.Fatal(err)
	}
	if r.pool, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.pool.Close() })
	if err := r.old.SetPool(r.pool, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.old.SetPorts([]uint16{r.udp, r.tcp}); err != nil {
		t.Fatal(err)
	}
	return r
}

// reload starts the exit's next generation and drains the old one to it.
func (r *rustReload) reload() {
	r.next = startRustExit(r.t, 1)
	if err := r.old.Handoff(r.next, 1); err != nil {
		r.t.Fatal(err)
	}
}

// freshExit is a tick the exit sent after the call.
func freshExit(x *Exit) ExitTick {
	asked := time.Now()
	for {
		tk, at := x.Tick()
		if at.After(asked) {
			return tk
		}
		select {
		case <-x.Done():
			return tk
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// reloadPipe is a pipe under this brain with a udp wire of 4 members to r
// and a client port (voice, one copy) to the udp echo, up; the brain's call
// is pinned to the wire.
func reloadPipe(t *testing.T, r *rustReload) (*Pipe, *net.UDPConn) {
	p, err := Start(Config{Bin: pipeBin(t), Args: []string{"--flow-idle-ms", exitIdle}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: r.wire.LocalAddr().(*net.UDPAddr).AddrPort(), Key: testKey, Members: 4}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: dgramWire})
	waitFor(t, 5*time.Second, "the pipe's members up", func() bool { return wireUp(p, dgramWire, 4) })
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := p.Listen(0, lc, trunk.ClassVoice, r.udp, 1); err != nil {
		t.Fatal(err)
	}
	return p, lc
}

// brainCall is the brain's own call on the pipe (port 0, pinned to the
// wire) and the longest pause between its answers. Its times are ns since
// start by the monotonic clock: the wall clock steps (WSL2 sets it seconds
// at a time), and a step read as a pause failed the test with 3.4 to 3.6 s.
type brainCall struct {
	start          time.Time
	got, last, gap atomic.Int64
	// gapEnd is when the longest pause ended.
	gapEnd     atomic.Int64
	stop, done chan struct{}
}

// ended is when the longest pause ended.
func (c *brainCall) ended() time.Time {
	return c.start.Add(time.Duration(c.gapEnd.Load()))
}

func startBrainCall(p *Pipe, wire trunk.WireID) *brainCall {
	c := &brainCall{start: time.Now(), stop: make(chan struct{}), done: make(chan struct{})}
	f := p.OpenCallFlow(trunk.FlowOptions{Class: trunk.ClassVoice, Copies: 1, Pin: wire}, func([]byte) {
		now := int64(time.Since(c.start))
		if l := c.last.Swap(now); l != 0 && now-l > c.gap.Load() {
			c.gap.Store(now - l)
			c.gapEnd.Store(now)
		}
		c.got.Add(1)
	})
	go func() {
		defer close(c.done)
		defer f.Close()
		tk := time.NewTicker(callEvery)
		defer tk.Stop()
		b := make([]byte, 64)
		for {
			select {
			case <-c.stop:
				return
			case <-tk.C:
				f.Send(b)
			}
		}
	}()
	return c
}

func (c *brainCall) hangUp() time.Duration {
	close(c.stop)
	<-c.done
	return time.Duration(c.gap.Load())
}

// TestACallGoesThroughAReloadOfTheRustExit: a client and the brain's own
// call go through the pipe on the udp wire when the exit reloads. The old
// exit tells the pipe it drains; the pipe's new session reaches the new
// exit, whose socket is the old one's. The calls hear no pause over 150 ms
// and lose nothing: the old session's members are the old exit's, their
// datagrams read by the new exit and handed over. A call after the takeover
// is the new exit's. Once the first call hangs up, the old exit carries
// nothing and says so, and the client's next call is the new exit's.
func TestACallGoesThroughAReloadOfTheRustExit(t *testing.T) {
	r := newRustReload(t)
	p, lc := reloadPipe(t, r)
	client := lc.LocalAddr().(*net.UDPAddr).AddrPort()
	call := startBrainCall(p, dgramWire)
	first := newCaller(t, client)
	first.call()
	time.Sleep(time.Second)
	if tk := freshExit(r.old); tk.Members != 4 || tk.Flows != 1 {
		t.Fatalf("the old exit before the reload: %d members, %d flows; want 4 and 1", tk.Members, tk.Flows)
	}

	at := time.Now()
	r.reload()
	took := waitFor(t, 5*time.Second, "the pipe's new session at the new exit", func() bool { return freshExit(r.next).Members == 4 })
	t.Logf("the new session's 4 members at the new exit %v after the reload", took.Round(time.Millisecond))
	waitFor(t, 5*time.Second, "the pipe's takeover", func() bool { tk := freshTick(p); return !tk.Coming && tk.Retired == 1 })
	second := newCaller(t, client)
	second.call()
	time.Sleep(1500 * time.Millisecond)
	checkCall(t, "the call through the reload", first, 0, 150*time.Millisecond)
	checkCall(t, "a call after the takeover", second, 0, 150*time.Millisecond)
	if fo, fn := freshExit(r.old).Flows, freshExit(r.next).Flows; fo != 1 || fn != 1 {
		t.Errorf("flows: old exit %d, new %d; want 1 and 1", fo, fn)
	}
	if o := freshExit(r.old); o.Joined != 4 {
		t.Errorf("the old exit saw %d members join, want the first session's 4: none after the drain", o.Joined)
	}
	gap := call.hangUp()
	t.Logf("the brain's call: %d answers, longest pause %v, ended %v after the reload", call.got.Load(), gap.Round(time.Millisecond),
		call.ended().Sub(at).Round(time.Millisecond))
	if gap > 150*time.Millisecond {
		t.Errorf("the brain's call paused %v through the reload", gap)
	}

	first.hangUp()
	select {
	case <-r.old.Drained():
		t.Logf("the old exit drained %v after the reload", time.Since(at).Round(time.Millisecond))
	case <-time.After(5 * time.Second):
		t.Fatalf("the old exit did not drain: %+v", freshExit(r.old))
	}
	waitFor(t, 5*time.Second, "the pipe's retired session closed", func() bool { return sessionsClosed(p) })
	r.old.Close()
	first.call()
	time.Sleep(time.Second)
	checkCall(t, "the first client's next call", first, 0, 150*time.Millisecond)
	if f := freshExit(r.next).Flows; f != 2 {
		t.Errorf("the new exit carries %d flows, want both clients'", f)
	}
}

// TestAStreamThroughAReloadOfTheRustExitEndsByteForByte: the pipe's stream
// members (plain TCP to the pool's port) carry a stream of 64 MiB when the
// exit reloads. The stream goes on to its end at the old exit, which keeps
// the connections it accepted, byte for byte; the new session's members are
// accepted by the new exit, and a stream after the takeover is its own. The
// old exit drains once the first stream ends.
func TestAStreamThroughAReloadOfTheRustExitEndsByteForByte(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := newRustReload(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := l.Addr().String()
	l.Close()
	cmd := exec.CommandContext(ctx, pipeBin(t), "--tcp-wire", r.pool.Addr().String(), "--tcp-listen", at, "--tcp-to", fmt.Sprint(r.tcp),
		"--tcp-members", "4", "--members", "0", "--listen", "127.0.0.1:0", "--wire", "127.0.0.1:9")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitFor(t, 5*time.Second, "the pipe's stream members at the exit", func() bool { return freshExit(r.old).Links == 4 })
	var c1 net.Conn
	waitFor(t, 5*time.Second, "hk-pipe's client port", func() bool {
		c1, err = net.Dial("tcp", at)
		return err == nil
	})
	defer c1.Close()
	var moved atomic.Int64
	errc := make(chan error, 1)
	go func() { errc <- echoed(c1, 64<<20, &moved) }()
	waitFor(t, 10*time.Second, "the stream under way", func() bool { return moved.Load() > 4<<20 })
	r.reload()
	waitFor(t, 5*time.Second, "the new session's members at the new exit", func() bool { return freshExit(r.next).Links == 4 })
	time.Sleep(200 * time.Millisecond)
	c2, err := net.Dial("tcp", at)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if err := echoed(c2, 1<<20, nil); err != nil {
		t.Errorf("the stream after the takeover: %v", err)
	}
	if err := <-errc; err != nil {
		t.Errorf("the stream through the reload: %v", err)
	}
	o, n := freshExit(r.old), freshExit(r.next)
	if o.StreamsOpened != 1 || n.StreamsOpened != 1 || o.ResetPeer+o.ResetLocal+n.ResetPeer+n.ResetLocal != 0 {
		t.Errorf("streams opened: old exit %d, new %d, reset %d; want 1, 1, 0", o.StreamsOpened, n.StreamsOpened,
			o.ResetPeer+o.ResetLocal+n.ResetPeer+n.ResetLocal)
	}
	c1.Close()
	select {
	case <-r.old.Drained():
	case <-time.After(5 * time.Second):
		t.Fatalf("the old exit did not drain after its stream ended: %+v", freshExit(r.old))
	}
}

// TestAQuicWireCallGoesThroughAReloadOfTheRustExit: the same reload on the
// Chromium QUIC wire (needs HK_CRONET): the old session's members are QUIC
// connections the old exit accepted, whose packets the new exit reads and
// hands over by their connection ids (each names the generation that issued
// it); the new session's connections are the new exit's. A client calling
// over the wire hears no pause over 150 ms.
func TestAQuicWireCallGoesThroughAReloadOfTheRustExit(t *testing.T) {
	bin, lib := pipeBin(t), cronetLib(t)
	certFile, keyFile, roots := selfSigned(t, t.TempDir())
	r := &rustReload{old: startRustExit(t, 3), udp: udpEcho(t), t: t}
	var err error
	if r.wire, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.wire.Close() })
	if err := r.old.SetWire(ExitWire{ID: 6, Form: FormH3Dgram, Conn: r.wire, Keys: []string{testKey}, CertFile: certFile, KeyFile: keyFile}); err != nil {
		t.Fatal(err)
	}
	if err := r.old.SetPorts([]uint16{r.udp}); err != nil {
		t.Fatal(err)
	}
	p, err := Start(Config{Bin: bin, Args: []string{"--flow-idle-ms", exitIdle}, Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	err = p.SetWire(Wire{ID: 6, Name: "h3dgram", Exit: r.wire.LocalAddr().(*net.UDPAddr).AddrPort(), Key: testKey, Members: 4,
		H3: &H3Form{SNI: "hk.example", Cronet: lib, Roots: roots, Ports: [2]uint16{32000, 32999}}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: 6, Bulk: 6})
	waitFor(t, 10*time.Second, "the QUIC wire's four members up", func() bool { return wireUp(p, 6, 4) })
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := p.Listen(0, lc, trunk.ClassVoice, r.udp, 1); err != nil {
		t.Fatal(err)
	}
	call := startBrainCall(p, 6)
	first := newCaller(t, lc.LocalAddr().(*net.UDPAddr).AddrPort())
	first.call()
	time.Sleep(time.Second)

	reloadAt := time.Now()
	r.next = startRustExit(t, 4)
	if err := r.old.Handoff(r.next, 4); err != nil {
		t.Fatal(err)
	}
	took := waitFor(t, 10*time.Second, "the new session's members at the new exit", func() bool { return freshExit(r.next).Members == 4 })
	t.Logf("the new session's 4 QUIC members at the new exit %v after the reload", took.Round(time.Millisecond))
	waitFor(t, 10*time.Second, "the pipe's takeover", func() bool { tk := freshTick(p); return !tk.Coming && tk.Retired == 1 })
	second := newCaller(t, lc.LocalAddr().(*net.UDPAddr).AddrPort())
	second.call()
	time.Sleep(1500 * time.Millisecond)
	checkCall(t, "the call through the reload", first, 0, 150*time.Millisecond)
	checkCall(t, "a call after the takeover", second, 0, 150*time.Millisecond)
	if fo, fn := freshExit(r.old).Flows, freshExit(r.next).Flows; fo != 1 || fn != 1 {
		t.Errorf("flows: old exit %d, new %d; want 1 and 1", fo, fn)
	}
	gap := call.hangUp()
	t.Logf("the brain's call: %d answers, longest pause %v, ended %v after the reload", call.got.Load(), gap.Round(time.Millisecond),
		call.ended().Sub(reloadAt).Round(time.Millisecond))
	if gap > 150*time.Millisecond {
		t.Errorf("the brain's call paused %v through the reload", gap)
	}
	first.hangUp()
	select {
	case <-r.old.Drained():
	case <-time.After(5 * time.Second):
		t.Fatalf("the old exit did not drain: %+v", freshExit(r.old))
	}
}
