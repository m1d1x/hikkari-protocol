package pipectl

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// The exit's drain on the pipe (R4.1, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»;
// spec/trunk.md, "Frames": Drain): the exit's process is replaced without a
// cut, and the pipe answers as the Go entry does (trunk entry.go: drained,
// takeOver; trunk_test.go TestExitDrainWaitsForThePool,
// TestRetiredEntryIgnoresExitDrain). The exit is the Go one, its two
// processes two trunk.Exit behind one address: the members that came before
// the switch stay with the old one, a member that comes after it (a new
// peer, as a new socket is to the kernel) reaches the new one, as the edge's
// generations share their sockets.

// drainExit is an exit's two processes behind one udp wire address and one
// pool port, the relay behind them echoes (udp and tcp).
type drainExit struct {
	old, next *trunk.Exit
	wire      netip.AddrPort
	pool      string
	udp, tcp  uint16
	switched  atomic.Bool
	// slow holds each member of the new process this long before it is
	// served: the new process slow to take the new session's members.
	slow atomic.Int64
}

func newDrainExit(t *testing.T, ctx context.Context) *drainExit {
	d := &drainExit{old: trunk.NewExit(trunk.Config{}, local{}), next: trunk.NewExit(trunk.Config{}, local{}),
		udp: udpEcho(t), tcp: tcpEcho(t)}
	go d.old.Run(ctx)
	go d.next.Run(ctx)
	serve := func(c io.ReadWriteCloser) {
		if !d.switched.Load() {
			_ = d.old.ServeMember(c)
			return
		}
		time.Sleep(time.Duration(d.slow.Load()))
		_ = d.next.ServeMember(c)
	}
	l, err := udpwire.Listen("127.0.0.1:0", []string{testKey}, serve)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	d.wire = l.Addr()
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pl.Close() })
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()
	d.pool = pl.Addr().String()
	return d
}

// replace starts the exit's new process and drains the old one.
func (d *drainExit) replace() {
	d.switched.Store(true)
	d.old.Drain()
}

// freshTick is a tick the pipe sent after the call.
func freshTick(p *Pipe) Tick {
	asked := time.Now()
	for {
		tk, at := p.Tick()
		if at.After(asked) {
			return tk
		}
		select {
		case <-p.Done():
			return tk
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// sessionsClosed: the pipe has no retired session and none coming up.
func sessionsClosed(p *Pipe) bool {
	tk := freshTick(p)
	return tk.Retired == 0 && !tk.Coming
}

func stats(x *trunk.Exit) trunk.Stats {
	_, st := x.Stats()
	return st
}

// drainArgs are the pipe's flags of a drain test: flows unused for 500 ms
// end, a retired session is cut after retire (0: the trunk's 30 minutes).
func drainArgs(retire time.Duration) []string {
	args := []string{"--flow-idle-ms", "500"}
	if retire > 0 {
		args = append(args, "--retire-ms", strconv.Itoa(int(retire/time.Millisecond)))
	}
	return args
}

// drainPipe is a pipe under this brain with a udp wire of 4 members to d
// and a client port (voice, one copy) to the udp echo, up.
func drainPipe(t *testing.T, d *drainExit, retire time.Duration) (*Pipe, netip.AddrPort) {
	p, err := Start(Config{Bin: pipeBin(t), Args: drainArgs(retire), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: d.wire, Key: testKey, Members: 4}); err != nil {
		t.Fatal(err)
	}
	p.SetRoute(trunk.Route{Voice: dgramWire, Bulk: dgramWire})
	waitFor(t, 5*time.Second, "the pipe's members up", func() bool { return wireUp(p, dgramWire, 4) })
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Close() })
	if err := p.Listen(0, lc, trunk.ClassVoice, d.udp, 1); err != nil {
		t.Fatal(err)
	}
	return p, lc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// TestAnExitDrainWaitsForAQuarterOfTheNewPoolThenMovesWhatIsNew: a client
// calls through the pipe when the exit's process is replaced, and the new
// process is slow to take members. Until a quarter of the new session is
// up, a new call still goes to the old process; then the new session takes
// over, a call after it reaches the new process, and the first calls stay
// with the old one to their end with no pause over 150 ms. Once they end,
// the retired session closes: the old process keeps no member of it.
func TestAnExitDrainWaitsForAQuarterOfTheNewPoolThenMovesWhatIsNew(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := newDrainExit(t, ctx)
	p, client := drainPipe(t, d, 0)
	first := newCaller(t, client)
	first.call()
	time.Sleep(500 * time.Millisecond)

	d.slow.Store(int64(600 * time.Millisecond))
	d.replace()
	time.Sleep(150 * time.Millisecond)
	if m := stats(d.next).Members; m != 0 {
		t.Fatalf("the new process has %d members 150 ms into a wait of 600", m)
	}
	second := newCaller(t, client) // during the wait: the old session
	second.call()
	time.Sleep(300 * time.Millisecond)
	if f := stats(d.old).Flows; f != 2 {
		t.Fatalf("the old process carries %d flows during the wait, want both calls", f)
	}
	if tk := freshTick(p); !tk.Coming || tk.Retired != 0 {
		t.Fatalf("during the wait the tick says coming %v, retired %d; want true and 0", tk.Coming, tk.Retired)
	}

	waitFor(t, 5*time.Second, "the new session's members at the new process", func() bool { return stats(d.next).Members == 4 })
	time.Sleep(200 * time.Millisecond)
	third := newCaller(t, client)
	third.call()
	time.Sleep(time.Second)
	checkCall(t, "the call through the drain", first, 0, 150*time.Millisecond)
	checkCall(t, "a call during the wait", second, 0, 150*time.Millisecond)
	checkCall(t, "a call after the takeover", third, 0, 150*time.Millisecond)
	if fo, fn := stats(d.old).Flows, stats(d.next).Flows; fo != 2 || fn != 1 {
		t.Errorf("flows: old process %d, new %d; want 2 and 1", fo, fn)
	}
	if st := stats(d.next); st.MembersJoined != 4 {
		t.Errorf("the new process saw %d members join, want the new session's 4", st.MembersJoined)
	}
	if !wireUp(p, dgramWire, 4) {
		t.Errorf("the brain sees the current session's wire without its 4 members: %+v", p.Wires()[dgramWire])
	}
	if tk := freshTick(p); tk.Coming || tk.Retired != 1 {
		t.Errorf("after the takeover the tick says coming %v, retired %d; want false and 1", tk.Coming, tk.Retired)
	}

	first.hangUp()
	second.hangUp()
	waitFor(t, 5*time.Second, "the retired session closed", func() bool { return sessionsClosed(p) })
	if f := stats(d.next).Flows; f != 1 {
		t.Errorf("the new process carries %d flows after the old session closed, want 1", f)
	}
	first.call()
	time.Sleep(500 * time.Millisecond)
	checkCall(t, "the first client's next call", first, 0, 150*time.Millisecond)
	if f := stats(d.next).Flows; f != 2 {
		t.Errorf("the new process carries %d flows, want 2", f)
	}
}

// TestTheBrainsCallMovesToTheNewSession: the trunk's call (a flow of the
// brain's own, port 0, pinned to the wire) goes on through the drain with
// no pause over 150 ms, and at the takeover moves to the new session: it
// never keeps a retired one open (spec/trunk.md, "Datagrams"). The exit's
// new process numbers its answers from 1 again: answers of the old one's
// numbers would have them dropped as copies for as long as the call had
// run (the first run of this test: a pause of 520 ms).
func TestTheBrainsCallMovesToTheNewSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := newDrainExit(t, ctx)
	p, _ := drainPipe(t, d, 0)
	var got atomic.Int64
	var last atomic.Int64
	var gap atomic.Int64
	f := p.OpenCallFlow(trunk.FlowOptions{Class: trunk.ClassVoice, Copies: 1, Pin: dgramWire}, func(b []byte) {
		now := time.Now().UnixNano()
		if l := last.Swap(now); l != 0 && now-l > gap.Load() {
			gap.Store(now - l)
		}
		got.Add(1)
	})
	defer f.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tk := time.NewTicker(callEvery)
		defer tk.Stop()
		b := make([]byte, 64)
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				f.Send(b)
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	d.replace()
	waitFor(t, 5*time.Second, "the new session's members at the new process", func() bool { return stats(d.next).Members == 4 })
	time.Sleep(time.Second)
	close(stop)
	<-done
	time.Sleep(200 * time.Millisecond)
	t.Logf("the call: %d answers, longest pause %v", got.Load(), time.Duration(gap.Load()))
	if g := time.Duration(gap.Load()); g > 150*time.Millisecond {
		t.Errorf("the brain's call paused %v through the drain", g)
	}
	// The call left the retired session, which carried nothing else.
	waitFor(t, 3*time.Second, "the retired session closed", func() bool { return sessionsClosed(p) })
}

// TestAPipeDrainingItselfOpensNoSessionForTheExitsDrain: the pipe's own
// process is being replaced (a reload into pipe b, R4) when the exit's is
// too. The old pipe a opens no session for the exit's drain: the new
// process sees members of b's new session alone. a's call goes on to its
// end through the exit's old process.
func TestAPipeDrainingItselfOpensNoSessionForTheExitsDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := newDrainExit(t, ctx)
	a, client := drainPipe(t, d, 0)
	k := newCaller(t, client)
	k.call()
	time.Sleep(500 * time.Millisecond)
	b, err := Start(Config{Bin: pipeBin(t), Args: drainArgs(0), Stderr: os.Stderr, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	if err := b.SetWire(Wire{ID: dgramWire, Name: "udp", Exit: d.wire, Key: testKey, Members: 2}); err != nil {
		t.Fatal(err)
	}
	b.SetRoute(trunk.Route{Voice: dgramWire, Bulk: dgramWire})
	waitFor(t, 5*time.Second, "b's members up", func() bool { return wireUp(b, dgramWire, 2) })
	if err := a.Handoff(b); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	d.replace()
	waitFor(t, 5*time.Second, "b's new session at the new process", func() bool { return stats(d.next).Members == 2 })
	time.Sleep(time.Second)
	if st := stats(d.next); st.MembersJoined != 2 {
		t.Errorf("the new process saw %d members join, want b's 2 alone", st.MembersJoined)
	}
	checkCall(t, "a's call through both drains", k, 0, 150*time.Millisecond)
	if tk := freshTick(a); tk.Coming || tk.Retired != 0 {
		t.Errorf("a's tick says coming %v, retired %d; want false and 0", tk.Coming, tk.Retired)
	}
	if f := stats(d.old).Flows; f != 1 {
		t.Errorf("the old process carries %d flows, want a's call", f)
	}
}

// TestARetiredSessionIsCutAfterItsLimit: a call that never ends keeps the
// retired session open only up to its limit (here 1 s, the trunk's 30
// minutes); then it is cut, and the call's next datagram opens its flow on
// the current session, at the new process.
func TestARetiredSessionIsCutAfterItsLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := newDrainExit(t, ctx)
	p, client := drainPipe(t, d, time.Second)
	k := newCaller(t, client)
	k.call()
	time.Sleep(500 * time.Millisecond)
	d.replace()
	waitFor(t, 5*time.Second, "the new session's members at the new process", func() bool { return stats(d.next).Members == 4 })
	waitFor(t, 5*time.Second, "the retired session cut", func() bool { return sessionsClosed(p) })
	waitFor(t, 3*time.Second, "the call's flow at the new process", func() bool { return stats(d.next).Flows == 1 })
	checkCall(t, "the call through the cut", k, 120, 2500*time.Millisecond)
}

// TestAStreamThroughAnExitDrainEndsByteForByte: the pipe's stream members
// (alone, plain TCP: the brain does not steer its streams yet) carry a
// stream of 64 MiB when the exit's process is replaced. The stream goes on
// to its end at the old process, byte for byte; a stream after the
// takeover is the new process's; then the retired session closes.
func TestAStreamThroughAnExitDrainEndsByteForByte(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := newDrainExit(t, ctx)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := l.Addr().String()
	l.Close()
	cmd := exec.CommandContext(ctx, pipeBin(t), "--tcp-wire", d.pool, "--tcp-listen", at, "--tcp-to", fmt.Sprint(d.tcp),
		"--tcp-members", "4", "--members", "0", "--listen", "127.0.0.1:0", "--wire", "127.0.0.1:9")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	waitFor(t, 5*time.Second, "the pipe's stream members at the exit", func() bool { return stats(d.old).Members == 4 })
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
	d.replace()
	waitFor(t, 5*time.Second, "the new session's members at the new process", func() bool { return stats(d.next).Members == 4 })
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
		t.Errorf("the stream through the drain: %v", err)
	}
	if o, n := stats(d.old), stats(d.next); o.StreamsOpened != 1 || n.StreamsOpened != 1 || o.StreamsReset+n.StreamsReset != 0 {
		t.Errorf("streams opened: old process %d, new %d, reset %d; want 1, 1, 0", o.StreamsOpened, n.StreamsOpened, o.StreamsReset+n.StreamsReset)
	}
	c1.Close()
	waitFor(t, 5*time.Second, "the retired session closed at the old process", func() bool { return stats(d.old).Members == 0 })
}
