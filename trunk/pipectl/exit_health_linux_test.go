package pipectl

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// Members' health of the exit with the Go entry on the other end (R1.6,
// hikkari-client plans/2026-11-11-entry-hot-path-and-unit-economics.md,
// «Труба на Rust»): the scenarios of health_linux_test.go with the
// production entry (trunk.Entry and its udp wire) instead of the pipe, on
// the Go exit (the reference) and on the Rust exit alike, and the exit's own
// pause on the Rust exit with either entry. What the exit buries it judges
// by spec/trunk.md, "Members' health": a member owing past its stall while
// another member proved the entry alive, or every member silent past Quiet
// (30 s on the exit).

// goStand is a Go entry with one udp wire of n members to an exit through a
// cutter, a client calling through it.
type goStand struct {
	x      testExit
	cut    *cutter
	e      *trunk.Entry
	client *client
}

func newGoStand(t *testing.T, ctx context.Context, n int, mk exitMaker) *goStand {
	echo := udpEcho(t)
	g := &goStand{x: mk(t, ctx, echo)}
	g.cut = newCutter(t, g.x.addr())
	g.e = newGoEntry(t, 0)
	if err := g.e.AddWire(trunk.Wire{ID: healthWire, Name: "udp", Shape: "random", Members: n, Packet: true,
		Dial: udpwire.Dialer{Exit: g.cut.addr(), Key: testKey}.Dial}); err != nil {
		t.Fatal(err)
	}
	g.e.SetRoute(trunk.Route{Voice: healthWire, Bulk: healthWire})
	go g.e.Run(ctx)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go serveGoPort(g.e, pc, echo, 1)
	waitFor(t, 5*time.Second, "the Go entry's members up", func() bool { return g.up() == n })
	g.client = runClient(ctx, t, pc.LocalAddr().(*net.UDPAddr).AddrPort())
	time.Sleep(time.Second)
	return g
}

// anyMember is the address of one member the cutter carries.
func (c *cutter) anyMember() netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	for a := range c.up {
		return a
	}
	return netip.AddrPort{}
}

func (g *goStand) up() int { return g.e.Wires()[healthWire].Members }

func (g *goStand) entryBuried() int64 { return g.e.Session().Stats().MembersStall }

// TestAGoEntrysMemberCutAloneIsBuriedOnceAtEachEnd: one member's path dies
// while the others answer. The entry buries it by its stall and dials a new
// one; the exit buries its end of it by its stall too, as the other members
// prove the entry alive, and no other; the client goes on.
func TestAGoEntrysMemberCutAloneIsBuriedOnceAtEachEnd(t *testing.T) {
	onEachExit(t, func(t *testing.T, mk exitMaker) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g := newGoStand(t, ctx, 4, mk)
		old := g.cut.firstSeen(nil)
		if len(old) != 4 {
			t.Fatalf("%d members seen on the path, want 4", len(old))
		}
		cutAt := time.Now()
		g.cut.cutOne(g.cut.anyMember())
		waitFor(t, 3*time.Second, "the entry buries the cut member", func() bool { return g.entryBuried() >= 1 })
		down := time.Since(cutAt)
		waitFor(t, 3*time.Second, "its replacement up", func() bool { return g.up() == 4 })
		waitFor(t, 3*time.Second, "the exit buries its end of the cut member", func() bool { return g.x.buried() >= 1 })
		time.Sleep(1500 * time.Millisecond)
		t.Logf("entry buried it %v after its cut; entry buried %d, exit %d", down.Round(time.Millisecond), g.entryBuried(), g.x.buried())
		if b := g.entryBuried(); b != 1 {
			t.Errorf("the entry buried %d members for one cut", b)
		}
		if b := g.x.buried(); b != 1 {
			t.Errorf("the exit buried %d members for the one the entry left", b)
		}
		if g2, n := g.client.gapMax(cutAt.Add(down).Add(200*time.Millisecond), time.Now()); n < 40 || g2 > 150*time.Millisecond {
			t.Errorf("the client's flow did not go on after the death: %d answers, longest pause %v", n, g2)
		}
	})
}

// TestAGoEntrysPathHeldBuriesNoMemberAtTheExit: the path holds everything
// both ways for 700 ms, then lets it through (trunk TestOtherEndPaused, as
// either end sees it): every member silent at once, under the entry's Quiet
// and the exit's; no member is buried at either end, and the client goes on.
func TestAGoEntrysPathHeldBuriesNoMemberAtTheExit(t *testing.T) {
	onEachExit(t, func(t *testing.T, mk exitMaker) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g := newGoStand(t, ctx, 6, mk)
		for range 3 {
			t0 := time.Now()
			g.cut.setHold(true)
			time.Sleep(700 * time.Millisecond)
			g.cut.setHold(false)
			time.Sleep(1500 * time.Millisecond)
			if g2, n := g.client.gapMax(t0.Add(time.Second), time.Now()); n < 30 || g2 > 150*time.Millisecond {
				t.Errorf("the client does not go on after the hold: %d answers, longest pause %v", n, g2)
			}
		}
		time.Sleep(time.Second) // the Rust exit's counts come with its tick
		if b, x := g.entryBuried(), g.x.buried(); b != 0 || x != 0 {
			t.Errorf("members buried for a path held 700 ms: entry %d, exit %d", b, x)
		}
	})
}

// TestAGoEntrysPathCutEndsItsMembersByQuietAndTheExitKeepsThemTill30s: the
// path drops every member at once for 2 s (trunk TestPathCut). The entry
// buries its 4 by Quiet (1 s) and dials new ones; the exit, whose Quiet is
// 30 s, buries none within the cut. Healed, the new members come up, the
// client goes on, and the exit buries the 4 old ones by their stall, as the
// new ones prove the entry alive.
func TestAGoEntrysPathCutEndsItsMembersByQuietAndTheExitKeepsThemTill30s(t *testing.T) {
	onEachExit(t, func(t *testing.T, mk exitMaker) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g := newGoStand(t, ctx, 4, mk)
		cutAt := time.Now()
		g.cut.cut.Store(true)
		waitFor(t, 3*time.Second, "the entry buries every member", func() bool { return g.entryBuried() >= 4 })
		t.Logf("the entry buried its 4 members %v after the cut", time.Since(cutAt).Round(time.Millisecond))
		time.Sleep(time.Until(cutAt.Add(2 * time.Second)))
		time.Sleep(1100 * time.Millisecond) // a tick of the Rust exit from within the cut
		if b := g.x.buried(); b != 0 {
			t.Errorf("the exit buried %d members within its 30 s Quiet of a cut of the whole path", b)
		}
		healAt := time.Now()
		g.cut.cut.Store(false)
		back := waitFor(t, 5*time.Second, "the new members up", func() bool { return g.up() == 4 })
		t.Logf("healed: up again after %v", back.Round(time.Millisecond))
		time.Sleep(time.Second)
		if g2, n := g.client.gapMax(healAt.Add(back).Add(300*time.Millisecond), time.Now()); n < 30 || g2 > 150*time.Millisecond {
			t.Errorf("the client does not go on after the heal: %d answers, longest pause %v", n, g2)
		}
		waitFor(t, 3*time.Second, "the exit buries the 4 cut members", func() bool { return g.x.buried() >= 4 })
		time.Sleep(1500 * time.Millisecond)
		if b := g.x.buried(); b != 4 {
			t.Errorf("the exit buried %d members for the 4 the entry left", b)
		}
	})
}

// TestTheExitsOwnPauseBuriesNoMember (trunk TestOwnPause, on the exit): the
// Rust exit is not run for 700 ms (stopped, as a box starved by its
// neighbours), under the entry's Quiet. Its debts count from the end of the
// pause, so it buries no member for the time it did not run, and tells the
// pause in its tick; the entry buries none either, and the client goes on.
// With the pipe as the entry and with the Go entry.
func TestTheExitsOwnPauseBuriesNoMember(t *testing.T) {
	pause := func(t *testing.T, x testExit) time.Time {
		if err := syscall.Kill(x.pid(), syscall.SIGSTOP); err != nil {
			t.Fatal(err)
		}
		time.Sleep(700 * time.Millisecond)
		if err := syscall.Kill(x.pid(), syscall.SIGCONT); err != nil {
			t.Fatal(err)
		}
		return time.Now()
	}
	pauses := func(x testExit) int {
		tk, _ := x.(*rustExit).x.Tick()
		return tk.Pauses
	}
	t.Run("pipe", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := newHealthStand(t, ctx, 4, newRustExit)
		p0 := pauses(h.x)
		t0 := time.Now()
		resumed := pause(t, h.x)
		time.Sleep(2500 * time.Millisecond)
		if d := h.downs(t0); len(d) != 0 {
			t.Errorf("the pipe buried members for the exit's own pause: %+v", d)
		}
		if p := pauses(h.x); p != p0+1 {
			t.Errorf("the exit told %d pauses of its own for one", p-p0)
		}
		if b := h.x.buried(); b != 0 {
			t.Errorf("the exit buried %d members for its own pause", b)
		}
		if g, n := h.client.gapMax(resumed.Add(200*time.Millisecond), time.Now()); n < 80 || g > 150*time.Millisecond {
			t.Errorf("the client does not go on after the pause: %d answers, longest pause %v", n, g)
		}
	})
	t.Run("goentry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g := newGoStand(t, ctx, 4, newRustExit)
		p0 := pauses(g.x)
		resumed := pause(t, g.x)
		time.Sleep(2500 * time.Millisecond)
		if b := g.entryBuried(); b != 0 {
			t.Errorf("the Go entry buried %d members for the exit's own pause", b)
		}
		if p := pauses(g.x); p != p0+1 {
			t.Errorf("the exit told %d pauses of its own for one", p-p0)
		}
		if b := g.x.buried(); b != 0 {
			t.Errorf("the exit buried %d members for its own pause", b)
		}
		if g2, n := g.client.gapMax(resumed.Add(200*time.Millisecond), time.Now()); n < 80 || g2 > 150*time.Millisecond {
			t.Errorf("the client does not go on after the pause: %d answers, longest pause %v", n, g2)
		}
	})
}
