package trunk

import (
	"context"
	"slices"
	"testing"
	"time"
)

var (
	selPool = Wire{ID: PoolWire, Name: "pool", Shape: "browser", Streams: true}
	selQuic = Wire{ID: testQuic, Name: "quic", Shape: "browser", Streams: true}
	selUDP  = Wire{ID: testUDP, Name: "udp", Shape: "random", Packet: true}
)

// calm is a minute of a call that heard nothing wrong.
func calm(to time.Time, p99 time.Duration) CallWindow {
	return CallWindow{From: to.Add(-time.Minute), To: to, Sent: 3000, Got: 3000, RTTP99: p99, GapMax: 40 * time.Millisecond}
}

// rough is a red minute: pauses a call hears.
func rough(to time.Time) CallWindow {
	w := calm(to, 60*time.Millisecond)
	w.Gaps60, w.Gaps150, w.GapMax = 4, 2, 900*time.Millisecond
	return w
}

func liveAll(now time.Time, ids ...WireID) map[WireID]WireState {
	out := map[WireID]WireState{}
	for _, id := range ids {
		out[id] = WireState{ID: id, Members: 4, Proof: now}
	}
	return out
}

// TestSelectorLeavesARedWireAtOnce: voice is on the packet wire; its members
// owe progress for longer than RedSilence while the pool proves the path
// alive. One Choose moves voice off it, with no Hold.
func TestSelectorLeavesARedWireAtOnce(t *testing.T) {
	now := time.Now()
	sel := NewSelector(SelectorConfig{}, selPool, selUDP)
	for i := 0; i < 10; i++ {
		sel.Call(testUDP, calm(now.Add(-time.Duration(i)*time.Minute), 50*time.Millisecond))
		sel.Call(PoolWire, rough(now.Add(-time.Duration(i)*time.Minute)))
	}
	c := sel.Choose(now, liveAll(now, PoolWire, testUDP))
	if c.Route.Voice != testUDP || c.Route.Bulk != PoolWire {
		t.Fatalf("first choice %+v", c.Route)
	}
	later := now.Add(time.Second)
	live := liveAll(later, PoolWire, testUDP)
	live[testUDP] = WireState{ID: testUDP, Members: 2, Proof: now, Owed: 600 * time.Millisecond}
	c = sel.Choose(later, live)
	if c.Route.Voice != PoolWire || !slices.Contains(c.Red, testUDP) {
		t.Fatalf("voice stayed on a red wire: %+v", c)
	}
	// The hub reads this line back part by part (cascadewatch).
	if c.Why != "voice: udp is red, to pool" {
		t.Fatalf("the log says %q", c.Why)
	}
}

// TestSelectorPauseRedsNobody: every wire owes at once (this box was not
// run, or the whole path is cut): no wire is to blame, nothing moves.
func TestSelectorPauseRedsNobody(t *testing.T) {
	now := time.Now()
	sel := NewSelector(SelectorConfig{}, selPool, selUDP)
	sel.Call(testUDP, calm(now, 50*time.Millisecond))
	first := sel.Choose(now, liveAll(now, PoolWire, testUDP)).Route
	live := map[WireID]WireState{
		PoolWire: {ID: PoolWire, Members: 4, Proof: now, Owed: 2 * time.Second},
		testUDP:  {ID: testUDP, Members: 2, Proof: now, Owed: 2 * time.Second},
	}
	c := sel.Choose(now.Add(2*time.Second), live)
	if len(c.Red) != 0 || c.Route != first {
		t.Fatalf("a pause moved traffic: %+v, was %+v", c, first)
	}
}

// TestSelectorHolds: a wire better by the margin takes the class only after
// it stayed better for Hold; one better by less never does.
func TestSelectorHolds(t *testing.T) {
	now := time.Now()
	sel := NewSelector(SelectorConfig{Hold: 3 * time.Minute}, selPool, selQuic)
	// Bulk starts on the pool: it alone has downloads.
	sel.Download(PoolWire, Download{At: now, OK: true, Took: 100 * time.Millisecond, Bytes: 1 << 20})
	if r := sel.Choose(now, liveAll(now, PoolWire, testQuic)).Route; r.Bulk != PoolWire {
		t.Fatalf("bulk on %d", r.Bulk)
	}
	// quic downloads 10% faster: below the margin, never taken.
	sel.Download(testQuic, Download{At: now, OK: true, Took: 90 * time.Millisecond, Bytes: 1 << 20})
	for m := 0; m < 10; m++ {
		at := now.Add(time.Duration(m) * time.Minute)
		if r := sel.Choose(at, liveAll(at, PoolWire, testQuic)).Route; r.Bulk != PoolWire {
			t.Fatalf("minute %d: bulk moved for 10%%", m)
		}
	}
	// Twice as fast: taken after Hold, not before.
	start := now.Add(11 * time.Minute)
	for i := 0; i < 4; i++ {
		sel.Download(testQuic, Download{At: start, OK: true, Took: 40 * time.Millisecond, Bytes: 1 << 20})
	}
	for s := 0; s < 179; s += 30 {
		at := start.Add(time.Duration(s) * time.Second)
		if r := sel.Choose(at, liveAll(at, PoolWire, testQuic)).Route; r.Bulk != PoolWire {
			t.Fatalf("bulk moved after %ds, before Hold", s)
		}
	}
	at := start.Add(3 * time.Minute)
	c := sel.Choose(at, liveAll(at, PoolWire, testQuic))
	if c.Route.Bulk != testQuic {
		t.Fatalf("bulk did not move after Hold: %+v", c)
	}
}

// TestSelectorBulkNeedsStreams: a packet wire, however good its call, never
// gets bulk.
func TestSelectorBulkNeedsStreams(t *testing.T) {
	now := time.Now()
	sel := NewSelector(SelectorConfig{}, selPool, selUDP)
	sel.Call(testUDP, calm(now, 40*time.Millisecond))
	sel.Download(testUDP, Download{At: now, OK: true, Took: time.Millisecond, Bytes: 1 << 20})
	live := liveAll(now, PoolWire, testUDP)
	if r := sel.Choose(now, live).Route; r.Bulk != PoolWire || r.Voice != testUDP {
		t.Fatalf("route %+v", r)
	}
	live[PoolWire] = WireState{ID: PoolWire} // the pool is down
	if r := sel.Choose(now.Add(time.Second), live).Route; r.Bulk == testUDP {
		t.Fatalf("bulk on a packet wire: %+v", r)
	}
}

// TestSelectorWarmPairTakesTwoShapes: with voice on quic (browser), the warm
// one for voice is the random-shaped udp, not the pool of the same shape.
func TestSelectorWarmPairTakesTwoShapes(t *testing.T) {
	now := time.Now()
	sel := NewSelector(SelectorConfig{}, selPool, selQuic, selUDP)
	sel.Call(testQuic, calm(now, 40*time.Millisecond))
	sel.Call(PoolWire, calm(now, 45*time.Millisecond))
	sel.Call(testUDP, rough(now))
	c := sel.Choose(now, liveAll(now, PoolWire, testQuic, testUDP))
	if c.Route.Voice != testQuic {
		t.Fatalf("voice on %d", c.Route.Voice)
	}
	if !slices.Contains(c.Warm, testUDP) {
		t.Fatalf("warm %v: no wire of another shape", c.Warm)
	}
}

// TestSteerLeavesACutWire: the entry steered by the selector carries bulk on
// quic; quic is cut. The route moves to the pool within the stage's 5
// seconds (stage plan, раздел 7), and the transfer under it completes.
func TestSteerLeavesACutWire(t *testing.T) {
	SteerEvery = 50 * time.Millisecond
	defer func() { SteerEvery = time.Second }()
	h := newWireHarness(t, Config{Stall: 100 * time.Millisecond, Quiet: 10 * time.Second}, 2, 2, 1)
	now := time.Now()
	sel := NewSelector(SelectorConfig{}, selPool, selQuic, selUDP)
	sel.Download(testQuic, Download{At: now, OK: true, Took: 40 * time.Millisecond, Bytes: 1 << 20})
	sel.Download(PoolWire, Download{At: now, OK: true, Took: 80 * time.Millisecond, Bytes: 1 << 20})
	sel.Call(testUDP, calm(now, 40*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.entry.Steer(ctx, sel, t.Logf)
	waitFor(t, func() bool { return h.entry.Route() == Route{Voice: testUDP, Bulk: testQuic} })

	c := h.carry()
	defer c.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		roundTrip(t, c, 16<<20)
	}()
	waitFor(t, func() bool { return h.wires[testQuic].out.Load() > 4<<20 })
	cut := time.Now()
	h.wires[testQuic].cut.Store(true)
	waitFor(t, func() bool { return h.entry.Route().Bulk == PoolWire })
	if d := time.Since(cut); d > 5*time.Second {
		t.Fatalf("the route left the cut wire after %s", d)
	} else {
		t.Logf("the route left the cut wire after %s", d.Round(time.Millisecond))
	}
	<-done
	if st := h.entry.Session().Stats(); st.StreamsReset != 0 {
		t.Fatalf("the stream was reset: %+v", st)
	}
}

// TestSelectorHoldsThroughOwnPause: what the entry did on 11.11 (hikkari-client
// plans/research/2026-11-12-selector-own-pause.md). Voice is on udp; this box
// is not run for 0.5–1.5 s, and after it udp has no member up (the pause
// buried them, they redial) or owes, while the pool shows progress at once.
// That is this box's pause, not udp: voice stays. A wire still red PauseGrace
// after the last pause is left; a wire cut with no pause is left at once.
func TestSelectorHoldsThroughOwnPause(t *testing.T) {
	for _, pause := range []time.Duration{500 * time.Millisecond, time.Second, 1500 * time.Millisecond} {
		for _, how := range []string{"no member", "owes"} {
			now := time.Now()
			sel := NewSelector(SelectorConfig{}, selPool, selUDP)
			for i := 0; i < 10; i++ {
				sel.Call(testUDP, calm(now.Add(-time.Duration(i)*time.Minute), 50*time.Millisecond))
				sel.Call(PoolWire, rough(now.Add(-time.Duration(i)*time.Minute)))
			}
			if r := sel.Choose(now, liveAll(now, PoolWire, testUDP)).Route; r.Voice != testUDP {
				t.Fatalf("first choice %+v", r)
			}
			end := now.Add(pause)
			// Untold of the pause (the selector before 12.11), it moves
			// voice on the first Choose after it.
			blind := NewSelector(SelectorConfig{}, selPool, selUDP)
			for i := 0; i < 10; i++ {
				blind.Call(testUDP, calm(now.Add(-time.Duration(i)*time.Minute), 50*time.Millisecond))
				blind.Call(PoolWire, rough(now.Add(-time.Duration(i)*time.Minute)))
			}
			blind.Choose(now, liveAll(now, PoolWire, testUDP))
			bl := liveAll(end, PoolWire, testUDP)
			if how == "no member" {
				delete(bl, testUDP)
			} else {
				bl[testUDP] = WireState{ID: testUDP, Members: 2, Proof: now, Owed: pause + 100*time.Millisecond}
			}
			if c := blind.Choose(end, bl); c.Route.Voice != PoolWire {
				t.Fatalf("pause %s, udp %s: the blind selector kept voice: %+v", pause, how, c)
			}
			sel.Paused(end)
			for at := end; at.Sub(end) < DefaultPauseGrace; at = at.Add(time.Second) {
				live := liveAll(at, PoolWire, testUDP)
				if how == "no member" {
					delete(live, testUDP)
				} else {
					live[testUDP] = WireState{ID: testUDP, Members: 2, Proof: end, Owed: at.Sub(end) + 600*time.Millisecond}
				}
				c := sel.Choose(at, live)
				if c.Route.Voice != testUDP {
					t.Fatalf("pause %s, udp %s: voice left udp %s after the pause: %+v", pause, how, at.Sub(end), c)
				}
				if !slices.Contains(c.Held, testUDP) {
					t.Fatalf("pause %s: udp red and not held: %+v", pause, c)
				}
			}
			at := end.Add(DefaultPauseGrace + time.Second)
			live := liveAll(at, PoolWire, testUDP)
			delete(live, testUDP)
			if c := sel.Choose(at, live); c.Route.Voice != PoolWire {
				t.Fatalf("pause %s: udp still down past the grace and voice stayed: %+v", pause, c)
			}
		}
	}
}

// TestSelectorAllRedMovesNothing: every wire red at once, each by no member
// or by owing while another proved alive a moment ago: no wire is to blame.
func TestSelectorAllRedMovesNothing(t *testing.T) {
	now := time.Now()
	sel := NewSelector(SelectorConfig{}, selPool, selQuic, selUDP)
	sel.Call(testUDP, calm(now, 40*time.Millisecond))
	sel.Download(testQuic, Download{At: now, OK: true, Took: 40 * time.Millisecond, Bytes: 1 << 20})
	first := sel.Choose(now, liveAll(now, PoolWire, testQuic, testUDP)).Route
	at := now.Add(time.Second)
	c := sel.Choose(at, map[WireID]WireState{})
	if c.Route != first {
		t.Fatalf("every wire down moved traffic: %+v, was %+v", c.Route, first)
	}
}

// TestSteerHoldsThroughOwnPause: the entry's session comes back from a pause
// of its own (its clock ran late) and udp is cut right then: Steer keeps
// voice on udp through PauseGrace, then leaves it, well within the stage's
// 5 seconds of the grace's end.
func TestSteerHoldsThroughOwnPause(t *testing.T) {
	SteerEvery = 50 * time.Millisecond
	defer func() { SteerEvery = time.Second }()
	h := newWireHarness(t, Config{Stall: 100 * time.Millisecond, Quiet: 10 * time.Second}, 2, 0, 1)
	now := time.Now()
	const grace = 1500 * time.Millisecond
	sel := NewSelector(SelectorConfig{PauseGrace: grace}, selPool, selUDP)
	sel.Call(testUDP, calm(now, 40*time.Millisecond))
	sel.Call(PoolWire, rough(now))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.entry.Steer(ctx, sel, t.Logf)
	waitFor(t, func() bool { return h.entry.Route().Voice == testUDP })

	s := h.entry.Session()
	s.mu.Lock()
	s.resumed = time.Now() // as tick does after a late turn of the clock
	s.mu.Unlock()
	pausedAt := time.Now()
	h.wires[testUDP].cut.Store(true)
	for time.Since(pausedAt) < grace-300*time.Millisecond {
		if r := h.entry.Route(); r.Voice != testUDP {
			t.Fatalf("voice left udp %s after this box's pause", time.Since(pausedAt).Round(time.Millisecond))
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitFor(t, func() bool { return h.entry.Route().Voice == PoolWire })
	if d := time.Since(pausedAt); d > grace+5*time.Second {
		t.Fatalf("the route left the cut wire %s after the pause", d)
	} else {
		t.Logf("the route left the cut wire %s after the pause (grace %s)", d.Round(time.Millisecond), grace)
	}
}
