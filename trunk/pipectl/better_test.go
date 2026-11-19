package pipectl

import (
	"strings"
	"testing"
	"time"
)

// minute is a minute of the call to rx from from: clean (0 pauses over
// 150 ms) or with pauses.
func minute(rx byte, from time.Time, pauses int) RxWindow {
	return RxWindow{Rx: rx, From: from, Sent: 3000, Got: 3000, Gaps150: pauses}
}

// aezamsk1 19.11 12:10:01: a silence of 5.3 s on the whole path, both
// receivers unheard; the spare ams3 (1) woke first and the entry moved
// there, then stood on it, its call red every minute (1–8 pauses over
// 150 ms; the VM froze 2–3 times a minute), the main unl1 (0) clean beside
// it. The entry goes back to the better one by itself after BetterMinutes,
// and once there two receivers worse by turns move it no more often than
// BetterHold.
func TestAfterASilenceOfTheWholePathTheEntryGoesBackToTheBetterReceiver(t *testing.T) {
	t0 := time.Date(2026, 11, 19, 12, 10, 1, 0, time.UTC)
	var j Judge
	both := func(active byte, activeAgo, standbyAgo time.Duration) (Tick, Receivers) {
		other := byte(1 - active)
		return Tick{Wires: heard(4, activeAgo)}, Receivers{Active: active, Standby: []ReceiverTick{standby(other, 4, standbyAgo)}}
	}
	// The whole path silent: no move, whatever DeadAfter.
	for d := time.Duration(0); d < 5300*time.Millisecond; d += 100 * time.Millisecond {
		tk, rs := both(0, d, d)
		if v := j.Step(t0.Add(d), tk, rs, -1); v.Move {
			t.Fatalf("moved at +%s while the whole path was silent: %s", d, v.Why)
		}
	}
	// The spare wakes first: off the dead one at once, as before.
	moved := t0.Add(5300 * time.Millisecond)
	tk, rs := both(0, 5300*time.Millisecond, 50*time.Millisecond)
	v := j.Step(moved, tk, rs, -1)
	if !v.Move || v.To != 1 || !strings.Contains(v.Why, "unheard for 5.3s") {
		t.Fatalf("the spare woke first: %+v", v)
	}
	// On the spare: the minute of the move counts for nothing, two red
	// minutes after it move no one, the third does.
	m0 := time.Date(2026, 11, 19, 12, 11, 0, 0, time.UTC)
	j.Hear(minute(1, m0.Add(-time.Minute), 5))
	j.Hear(minute(0, m0.Add(-time.Minute), 1))
	for i := 0; i < BetterMinutes; i++ {
		from := m0.Add(time.Duration(i) * time.Minute)
		j.Hear(minute(1, from, 3+i))
		j.Hear(minute(0, from, 0))
		tk, rs := both(1, 100*time.Millisecond, 200*time.Millisecond)
		v := j.Step(from.Add(time.Minute+2*time.Second), tk, rs, -1)
		if i < BetterMinutes-1 && v.Move {
			t.Fatalf("moved after %d red minute(s): %s", i+1, v.Why)
		}
		if i == BetterMinutes-1 && (!v.Move || v.To != 0 || !strings.Contains(v.Why, "worse for 3 min (12 pauses over 150 ms")) {
			t.Fatalf("after %d red minutes beside a clean one: %+v", BetterMinutes, v)
		}
	}
	back := m0.Add(BetterMinutes*time.Minute + 2*time.Second)
	// Now the main one is worse and the spare clean: within BetterHold the
	// entry stays where it is.
	for i := 0; i < 10; i++ {
		from := m0.Add(time.Duration(BetterMinutes+i) * time.Minute)
		j.Hear(minute(0, from, 4))
		j.Hear(minute(1, from, 0))
		tk, rs := both(0, 100*time.Millisecond, 200*time.Millisecond)
		if v := j.Step(from.Add(time.Minute+2*time.Second), tk, rs, -1); v.Move {
			t.Fatalf("moved %s after the last move to a better one: %s", from.Add(time.Minute).Sub(back), v.Why)
		}
	}
	// Past BetterHold it goes.
	from := back.Add(BetterHold).Truncate(time.Minute)
	for i := 0; i < BetterMinutes; i++ {
		j.Hear(minute(0, from.Add(time.Duration(i)*time.Minute), 4))
		j.Hear(minute(1, from.Add(time.Duration(i)*time.Minute), 0))
	}
	tk, rs = both(0, 100*time.Millisecond, 200*time.Millisecond)
	if v := j.Step(from.Add(BetterMinutes*time.Minute+2*time.Second), tk, rs, -1); !v.Move || v.To != 1 {
		t.Fatalf("past BetterHold: %+v", v)
	}
}

// Worse is not enough: the standby must be measured and clean in every one
// of the same minutes, and heard now.
func TestTheEntryStaysWhenNoStandbyIsCleanBesideIt(t *testing.T) {
	m0 := time.Date(2026, 11, 19, 13, 0, 0, 0, time.UTC)
	now := m0.Add(BetterMinutes*time.Minute + 2*time.Second)
	cases := []struct {
		name    string
		standby []int // its pauses each minute; -1: no minute heard
		ago     time.Duration
	}{
		{"the standby as bad", []int{3, 3, 3}, 100 * time.Millisecond},
		{"the standby one pause in one minute", []int{0, 1, 0}, 100 * time.Millisecond},
		{"the standby not measured one minute", []int{0, -1, 0}, 100 * time.Millisecond},
		{"the standby clean but unheard now", []int{0, 0, 0}, 2 * DeadAfter},
	}
	for _, c := range cases {
		var j Judge
		for i, p := range c.standby {
			from := m0.Add(time.Duration(i) * time.Minute)
			j.Hear(minute(0, from, 5))
			if p >= 0 {
				j.Hear(minute(1, from, p))
			}
		}
		v := j.Step(now, Tick{Wires: heard(4, 100*time.Millisecond)}, Receivers{Active: 0, Standby: []ReceiverTick{standby(1, 4, c.ago)}}, -1)
		if v.Move {
			t.Errorf("%s: moved: %s", c.name, v.Why)
		}
	}
	// One minute of the active with a single pause breaks the run.
	var j Judge
	for i, p := range []int{5, 1, 5} {
		from := m0.Add(time.Duration(i) * time.Minute)
		j.Hear(minute(0, from, p))
		j.Hear(minute(1, from, 0))
	}
	if v := j.Step(now, Tick{Wires: heard(4, 100*time.Millisecond)}, Receivers{Active: 0, Standby: []ReceiverTick{standby(1, 4, 100*time.Millisecond)}}, -1); v.Move {
		t.Fatalf("moved on minutes not all worse: %s", v.Why)
	}
}
