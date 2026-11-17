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

// receiverOf is a receiver's wires: a datagram wire (2) heard dgramAgo ago
// with 4 members up, and the pool (0) with poolUp members up heard poolAgo
// ago (negative: never).
func receiverOf(dgramAgo time.Duration, poolUp int, poolAgo time.Duration) []WireTick {
	return []WireTick{
		{ID: 2, Members: 4, Up: 4, ProofAgo: dgramAgo},
		{ID: 0, Members: 32, Up: poolUp, ProofAgo: poolAgo},
	}
}

// TestTheJudgeMovesOffAReceiverWhosePoolIsDeadWhileItsDatagramsLive: the
// pool carries every client's stream, so its death is a receiver's death
// for them (17.11 13:51, unl1: udp and h3dgram heard every second, the
// pool cut 65 s). The same DeadAfter, holds and Settle as for the whole
// receiver, and only to a standby whose pool is heard.
func TestTheJudgeMovesOffAReceiverWhosePoolIsDeadWhileItsDatagramsLive(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	young := 100 * time.Millisecond
	warm := Receivers{Active: 0, Standby: []ReceiverTick{{Rx: 1, IP: netip.MustParseAddr("10.0.0.2"),
		Wires: receiverOf(young, 14, young)}}}
	poolless := Receivers{Active: 0, Standby: []ReceiverTick{{Rx: 1, IP: netip.MustParseAddr("10.0.0.2"),
		Wires: receiverOf(young, 0, 6*time.Second)}}}
	cases := []struct {
		name   string
		active []WireTick
		rs     Receivers
		paused time.Duration
		move   bool
	}{
		{"both heard", receiverOf(young, 32, young), warm, -1, false},
		{"idle pool, its proof 1.2 s old as the judge sees it", receiverOf(young, 32, 1200*time.Millisecond), warm, -1, false},
		{"pool down, its proof 1 s old: dying", receiverOf(young, 0, time.Second), warm, -1, false},
		{"pool down, its proof just short of PoolDeadAfter", receiverOf(young, 0, PoolDeadAfter-time.Millisecond), warm, -1, false},
		{"pool down PoolDeadAfter, datagrams heard", receiverOf(young, 0, PoolDeadAfter), warm, -1, true},
		{"one pool member up, silent 5 s", receiverOf(young, 1, 5*time.Second), warm, -1, true},
		{"pool dead, a pause of the entry's own", receiverOf(young, 0, 5*time.Second), warm, time.Second, false},
		{"pool dead, the standby's pool dead too", receiverOf(young, 0, 5*time.Second), poolless, -1, false},
		{"pool dead, nothing on standby", receiverOf(young, 0, 5*time.Second), Receivers{}, -1, false},
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

	// A pool never heard while the datagrams are: dead after PoolDeadAfter
	// of watching, and the move says it was the pool.
	var j Judge
	never := receiverOf(young, 0, -1)
	if v := j.Step(t0, Tick{Wires: never}, warm, -1); v.Move {
		t.Fatalf("moved off a pool never heard at once: %s", v.Why)
	}
	if v := j.Step(t0.Add(PoolDeadAfter-time.Millisecond), Tick{Wires: never}, warm, -1); v.Move {
		t.Fatalf("moved off a pool never heard just short of PoolDeadAfter: %s", v.Why)
	}
	v := j.Step(t0.Add(PoolDeadAfter), Tick{Wires: never}, warm, -1)
	if !v.Move || v.To != 1 || v.Why != "the active receiver's pool unheard for 2s" {
		t.Fatalf("after %v of a pool never heard: move %v to %d (%s)", PoolDeadAfter, v.Move, v.To, v.Why)
	}
	// Settle holds a pool dead on the new receiver too.
	back := Receivers{Active: 1, Standby: []ReceiverTick{{Rx: 0, Wires: receiverOf(young, 32, young)}}}
	if v := j.Step(t0.Add(PoolDeadAfter+time.Second), Tick{Wires: receiverOf(young, 0, Settle)}, back, -1); v.Move {
		t.Fatalf("moved again 1 s after a move: %s", v.Why)
	}
	// A pool that comes back before PoolDeadAfter forgets its silence.
	var k Judge
	k.Step(t0, Tick{Wires: receiverOf(young, 0, -1)}, warm, -1)
	k.Step(t0.Add(2*time.Second), Tick{Wires: receiverOf(young, 32, young)}, warm, -1)
	if v := k.Step(t0.Add(4*time.Second), Tick{Wires: receiverOf(young, 0, -1)}, warm, -1); v.Move {
		t.Fatalf("a pool heard in between still counted its old silence: %s", v.Why)
	}
}
