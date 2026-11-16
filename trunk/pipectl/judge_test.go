package pipectl

import (
	"net/netip"
	"testing"
	"time"
)

// heard is a wire of n members up whose latest proof is ago old (negative:
// none ever).
func heard(n int, ago time.Duration) []WireTick {
	return []WireTick{{ID: 2, Members: 4, Up: n, ProofAgo: ago}}
}

func standby(rx byte, n int, ago time.Duration) ReceiverTick {
	return ReceiverTick{Rx: rx, IP: netip.MustParseAddr("10.0.0.2"), Wires: heard(n, ago)}
}

// TestTheJudgeMovesOnlyOffADeadReceiverToAHeardOne: the rule of judge.go,
// step by step on one clock.
func TestTheJudgeMovesOnlyOffADeadReceiverToAHeardOne(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	warm := Receivers{Active: 0, Standby: []ReceiverTick{standby(1, 4, 100*time.Millisecond)}}
	cases := []struct {
		name   string
		active []WireTick
		rs     Receivers
		paused time.Duration
		move   bool
	}{
		{"active heard", heard(4, 100*time.Millisecond), warm, -1, false},
		{"active's members down, proof 1 s old: dying, not dead", heard(0, time.Second), warm, -1, false},
		{"active's members down, proof just short of DeadAfter", heard(0, DeadAfter-time.Millisecond), warm, -1, false},
		{"active's members down, proof DeadAfter old", heard(0, DeadAfter), warm, -1, true},
		{"active unheard 3 s, standby heard", heard(0, 3*time.Second), warm, -1, true},
		{"active unheard, a pause of the entry's own 1 s ago", heard(0, 3*time.Second), warm, time.Second, false},
		{"active unheard, standby unheard too: the whole path", heard(0, 3*time.Second),
			Receivers{Standby: []ReceiverTick{standby(1, 0, 4*time.Second)}}, -1, false},
		{"active unheard, nothing on standby", heard(0, 3*time.Second), Receivers{}, -1, false},
	}
	for _, c := range cases {
		var j Judge
		v := j.Step(t0, Tick{Wires: c.active}, c.rs, c.paused)
		if v.Move != c.move {
			t.Errorf("%s: move %v (%s), want %v", c.name, v.Move, v.Why, c.move)
		}
		if v.Move && v.To != 1 {
			t.Errorf("%s: to %d, want 1", c.name, v.To)
		}
	}

	// Never heard (a pipe just started on a dead receiver): dead after
	// DeadAfter of watching, not before.
	var j Judge
	never := heard(0, -1)
	if v := j.Step(t0, Tick{Wires: never}, warm, -1); v.Move {
		t.Fatalf("moved off a receiver never heard at once: %s", v.Why)
	}
	if v := j.Step(t0.Add(DeadAfter-time.Millisecond), Tick{Wires: never}, warm, -1); v.Move {
		t.Fatalf("moved off a receiver never heard just short of DeadAfter: %s", v.Why)
	}
	v := j.Step(t0.Add(DeadAfter), Tick{Wires: never}, warm, -1)
	if !v.Move || v.To != 1 {
		t.Fatalf("did not move off a receiver never heard after %v: %s", DeadAfter, v.Why)
	}
	// Settle: the new active one, not heard yet, is not left at once.
	back := Receivers{Active: 1, Standby: []ReceiverTick{standby(0, 4, 100*time.Millisecond)}}
	if v := j.Step(t0.Add(DeadAfter+time.Second), Tick{Wires: heard(0, Settle)}, back, -1); v.Move {
		t.Fatalf("moved again 1 s after a move: %s", v.Why)
	}

	// The standby with the most members up wins.
	var k Judge
	two := Receivers{Standby: []ReceiverTick{standby(1, 1, 100*time.Millisecond), standby(2, 4, 100*time.Millisecond)}}
	if v := k.Step(t0, Tick{Wires: heard(0, 5*time.Second)}, two, -1); !v.Move || v.To != 2 {
		t.Fatalf("moved to %d (%v), want 2, the warmer", v.To, v.Move)
	}
}
