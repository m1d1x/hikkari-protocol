package pipectl

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// Members' health of the pipe against the Go exit (R1.1, hikkari-client
// plans/2026-11-11-entry-hot-path-and-unit-economics.md, «Труба на Rust»):
// the scenarios of trunk's TestOtherEndPaused, TestPathCut and TestOwnPause,
// and a member that dies alone, with the pipe as the entry and the Go exit
// (trunk.Exit over udpwire) as the other end, a cutter on the path between.
// The pipe's own unit tests run the same rules on a clock of their own
// (pipe-rs/src/health.rs).

const healthWire trunk.WireID = 2

// memberEvent is one member event the pipe told the brain.
type memberEvent struct {
	at    time.Time
	index int
	up    bool
	why   byte
}

type healthStand struct {
	t      *testing.T
	x      *trunk.Exit
	cut    *cutter
	p      *Pipe
	client *client
	mu     sync.Mutex
	events []memberEvent
}

// newHealthStand: a Go exit, one udp wire of n members to it through a
// cutter, a client calling through the pipe, every member up.
func newHealthStand(t *testing.T, ctx context.Context, n int) *healthStand {
	bin := pipeBin(t)
	h := &healthStand{t: t}
	h.x = trunk.NewExit(trunk.Config{}, local{})
	go h.x.Run(ctx)
	l, err := udpwire.Listen("127.0.0.1:0", []string{testKey}, func(c io.ReadWriteCloser) { _ = h.x.ServeMember(c) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	h.cut = newCutter(t, l.Addr())
	h.p, err = Start(Config{Bin: bin, Stderr: os.Stderr, Logf: t.Logf, OnMember: func(w trunk.WireID, i int, up bool, why byte) {
		h.mu.Lock()
		h.events = append(h.events, memberEvent{time.Now(), i, up, why})
		h.mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.p.Close() })
	if err := h.p.SetWire(Wire{ID: healthWire, Name: "udp", Exit: h.cut.addr(), Key: testKey, Members: n}); err != nil {
		t.Fatal(err)
	}
	h.p.SetRoute(trunk.Route{Voice: healthWire, Bulk: healthWire})
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.p.Listen(0, lc, trunk.ClassVoice, udpEcho(t), 1); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "every member up", func() bool { return wireUp(h.p, healthWire, n) })
	h.client = runClient(ctx, t, lc.LocalAddr().(*net.UDPAddr).AddrPort())
	time.Sleep(time.Second)
	return h
}

// since is the member events at or after t0.
func (h *healthStand) since(t0 time.Time) []memberEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []memberEvent
	for _, e := range h.events {
		if !e.at.Before(t0) {
			out = append(out, e)
		}
	}
	return out
}

func (h *healthStand) downs(t0 time.Time) []memberEvent {
	var out []memberEvent
	for _, e := range h.since(t0) {
		if !e.up {
			out = append(out, e)
		}
	}
	return out
}

// member is the local address of the brain's socket for member i.
func (h *healthStand) member(i int) netip.AddrPort {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	return h.p.wires[healthWire].members[i].LocalAddr().(*net.UDPAddr).AddrPort()
}

func (h *healthStand) members() map[netip.AddrPort]bool {
	h.p.mu.Lock()
	defer h.p.mu.Unlock()
	out := map[netip.AddrPort]bool{}
	for _, c := range h.p.wires[healthWire].members {
		out[c.LocalAddr().(*net.UDPAddr).AddrPort()] = true
	}
	return out
}

func (h *healthStand) exitBuried() int64 {
	_, st := h.x.Stats()
	return st.MembersStall
}

// TestAMemberAloneSilentDiesByItsStall: one member's path dies while the
// others answer. It is dead by its stall (Stall 300 ms plus the ping
// interval, from its first unanswered ping), long before Quiet; the others
// are untouched, its replacement comes up on a new socket, and the client's
// flow, which kept to it, goes on on another member.
func TestAMemberAloneSilentDiesByItsStall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHealthStand(t, ctx, 4)
	// The flow keeps to member id % 4; cut the one it is on, so the death
	// is heard by a client too. Its id is the first flow the pipe opened.
	victim := 1
	cutAt := time.Now()
	h.cut.cutOne(h.member(victim))
	waitFor(t, 3*time.Second, "the cut member down", func() bool { return len(h.downs(cutAt)) > 0 })
	time.Sleep(1500 * time.Millisecond)
	downs := h.downs(cutAt)
	if len(downs) != 1 || downs[0].index != victim || downs[0].why != WhySilent {
		t.Fatalf("downs after cutting member %d: %+v", victim, downs)
	}
	after := downs[0].at.Sub(cutAt)
	t.Logf("member %d down %v after its cut", victim, after.Round(time.Millisecond))
	if after < 400*time.Millisecond || after > 650*time.Millisecond {
		t.Errorf("down %v after its cut, want 400–650 ms (Stall 300 + ping 100, the first ping within 100, the clock 25)", after)
	}
	waitFor(t, 3*time.Second, "its replacement up", func() bool { return wireUp(h.p, healthWire, 4) })
	g, n := h.client.gapMax(cutAt, time.Now())
	t.Logf("client: %d answers since the cut, longest pause %v", n, g.Round(time.Millisecond))
	if g2, n2 := h.client.gapMax(downs[0].at.Add(100*time.Millisecond), time.Now()); n2 < 40 || g2 > 150*time.Millisecond {
		t.Errorf("the client's flow did not go on after the death: %d answers, longest pause %v", n2, g2)
	}
	// A UDP member has no close the exit could read: the exit buries the
	// one the pipe left by its own stall, as its other members prove the
	// entry alive. That one, and no other.
	waitFor(t, 3*time.Second, "the exit's own end of the dead member buried", func() bool { return h.exitBuried() >= 1 })
	time.Sleep(500 * time.Millisecond)
	if b := h.exitBuried(); b != 1 {
		t.Errorf("the exit buried %d members for the one the pipe left", b)
	}
}

// TestTheExitPausedBuriesNoMember (trunk TestOtherEndPaused, the other way
// round): the exit is not run for 700 ms, under the pipe's Quiet; what the
// members sent meanwhile it answers when it runs again. Every member is
// silent at once: that is the other end, not the members, and none is
// buried, by its stall or by Quiet.
func TestTheExitPausedBuriesNoMember(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHealthStand(t, ctx, 6)
	for range 3 {
		t0 := time.Now()
		h.cut.setHold(true)
		time.Sleep(700 * time.Millisecond)
		h.cut.setHold(false)
		time.Sleep(1500 * time.Millisecond)
		if d := h.downs(t0); len(d) != 0 {
			t.Fatalf("members buried for the exit's pause: %+v", d)
		}
		if !wireUp(h.p, healthWire, 6) {
			tk, _ := h.p.Tick()
			t.Fatalf("not every member up after the pause: %+v", tk.Wires)
		}
		g, n := h.client.gapMax(t0.Add(time.Second), time.Now())
		t.Logf("after the pause: client %d answers, longest pause %v", n, g.Round(time.Millisecond))
		if n < 30 || g > 150*time.Millisecond {
			t.Errorf("the client does not go on after the pause: %d answers, longest pause %v", n, g)
		}
	}
	if b := h.exitBuried(); b != 0 {
		t.Errorf("the exit buried %d members", b)
	}
}

// TestAPathCutEndsMembersByQuiet (trunk TestPathCut): the path drops every
// member at once. Nobody shows progress, so it is Quiet (1 s), not the
// stall, that ends them; the brain dials new ones spread over a second, and
// once the path heals they come up and the client goes on.
func TestAPathCutEndsMembersByQuiet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHealthStand(t, ctx, 4)
	old := h.members()
	cutAt := time.Now()
	h.cut.cut.Store(true)
	waitFor(t, 3*time.Second, "every member down", func() bool { return len(h.downs(cutAt)) >= 4 })
	time.Sleep(1500 * time.Millisecond) // the replacements dial, into the cut
	if b := h.exitBuried(); b != 0 {
		t.Errorf("the exit buried %d members within its 30 s Quiet of a cut of the whole path", b)
	}
	downs := h.downs(cutAt)
	for _, d := range downs {
		after := d.at.Sub(cutAt)
		t.Logf("member %d down %v after the cut (why %d)", d.index, after.Round(time.Millisecond), d.why)
		if d.why != WhyQuiet {
			t.Errorf("member %d down by why %d in a cut of the whole path, want Quiet", d.index, d.why)
		}
		if after < time.Second || after > 1250*time.Millisecond {
			t.Errorf("member %d down %v after the cut, want Quiet 1 s from its first unanswered ping", d.index, after)
		}
	}
	if len(downs) != 4 {
		t.Errorf("%d downs for 4 members: %+v", len(downs), downs)
	}
	seen := h.cut.firstSeen(old)
	if len(seen) != 4 {
		t.Fatalf("%d new members dialed, want 4", len(seen))
	}
	span := seen[len(seen)-1].Sub(seen[0])
	t.Logf("replacements dialed over %v", span.Round(time.Millisecond))
	if span < 50*time.Millisecond {
		t.Errorf("the replacements came as one burst: over %v", span)
	}
	healAt := time.Now()
	h.cut.cut.Store(false)
	back := waitFor(t, 3*time.Second, "the new members up", func() bool { return wireUp(h.p, healthWire, 4) })
	t.Logf("healed: up again after %v", back.Round(time.Millisecond))
	time.Sleep(time.Second)
	if g, n := h.client.gapMax(healAt.Add(back).Add(200*time.Millisecond), time.Now()); n < 30 || g > 150*time.Millisecond {
		t.Errorf("the client does not go on after the heal: %d answers, longest pause %v", n, g)
	}
	// Under its 30 s Quiet the exit kept the cut members; once the new ones
	// prove the entry alive, it buries the 4 the pipe left, and no other.
	waitFor(t, 3*time.Second, "the exit's ends of the cut members buried", func() bool { return h.exitBuried() >= 4 })
	time.Sleep(500 * time.Millisecond)
	if b := h.exitBuried(); b != 4 {
		t.Errorf("the exit buried %d members for the 4 the pipe left", b)
	}
}

// TestThePipesOwnPauseBuriesNoMember (trunk TestOwnPause): the pipe itself
// is not run for 2 s (stopped, as a box starved by its neighbours). Its debts
// count from the end of the pause, so no member is buried for the time the
// pipe did not run, by its stall or by Quiet; the pause is told in the
// pipe's tick, and the exit, whose Quiet is 30 s, buries none either.
func TestThePipesOwnPauseBuriesNoMember(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newHealthStand(t, ctx, 4)
	tk0, _ := h.p.Tick()
	pid := h.p.cmd.Process.Pid
	t0 := time.Now()
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	resumed := time.Now()
	time.Sleep(2500 * time.Millisecond)
	if d := h.downs(t0); len(d) != 0 {
		t.Fatalf("members buried for the pipe's own pause: %+v", d)
	}
	if !wireUp(h.p, healthWire, 4) {
		tk, _ := h.p.Tick()
		t.Fatalf("not every member up after the pause: %+v", tk.Wires)
	}
	tk, _ := h.p.Tick()
	t.Logf("pauses %d → %d, latest %v ago", tk0.Pauses, tk.Pauses, tk.PauseAgo)
	if tk.Pauses != tk0.Pauses+1 {
		t.Errorf("the pipe told %d pauses of its own for one", tk.Pauses-tk0.Pauses)
	}
	if lp := h.p.LastPause(); lp.Before(resumed.Add(-300*time.Millisecond)) || lp.After(resumed.Add(300*time.Millisecond)) {
		t.Errorf("the brain has the pipe's pause at %v, it ended at %v", lp, resumed)
	}
	if g, n := h.client.gapMax(resumed.Add(200*time.Millisecond), time.Now()); n < 80 || g > 150*time.Millisecond {
		t.Errorf("the client does not go on after the pause: %d answers, longest pause %v", n, g)
	}
	if b := h.exitBuried(); b != 0 {
		t.Errorf("the exit buried %d members", b)
	}
}
