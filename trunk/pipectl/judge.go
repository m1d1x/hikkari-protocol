package pipectl

// judge.go: when the entry moves to another receiver (hikkari-client
// plans/2026-11-16-second-receiver.md, "Где живёт переключение"). The rule
// reads what the pipe says, the active receiver's wires in its tick and
// each standby's in its receivers, their proofs aged by the time since the
// pipe said them, and nothing else: a receiver is heard while one of its
// wires heard its exit within DeadAfter. The entry
// moves when the active one is not heard and a standby is, to the standby
// with the most members up; it holds while the pipe or the brain paused (a
// pause makes every proof old at once, as the selector's own-pause rule of
// 12.11), for Settle after a move, and when no receiver is heard (a cut of
// the whole path: moving would cut everyone for nothing). It never moves
// back on its own: a move is a cut for every client.
//
// The pool is judged on its own too (17.11, plans research
// 2026-11-17-pool-reset-unl1-1351.md): it is the only wire that carries the
// clients' streams, so an active receiver whose datagram wires are heard
// and whose pool is not carries no client's TCP. The entry moves then as
// for a dead receiver, to a standby whose pool is heard, by the same holds
// and Settle: on 17.11 the pool to unl1 was cut and took 65 s to come back
// while udp and h3dgram proved unl1 alive every second, and every client's
// TCP stood that minute with a warm pool to ams3 at hand. The pool is
// judged by PoolDeadAfter, not DeadAfter: the pipe keeps an idle pool's
// proof under 250 ms and a round trip (its keep_proof), where a datagram
// wire's is 100 ms, and the judge sees either only by the pipe's tick, once
// a second.

import (
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

const (
	// DeadAfter is how long a receiver goes unheard before it is dead: past
	// the members' Quiet (1 s), so a receiver's own pause of a second does
	// not move everyone; every second more is a second of every client's
	// traffic standing (the owner's choice of 16.11 over 3 s). A move only
	// ever goes to a receiver heard, so a cut of the whole path moves no
	// one whatever DeadAfter is.
	DeadAfter = 1500 * time.Millisecond
	// Settle is how long the entry holds after a move: the new receiver's
	// members prove themselves, and two moves never come back to back.
	Settle = 5 * time.Second
	// PoolDeadAfter is how long the pool goes unheard before it is dead
	// while the receiver's other wires are heard. The pipe pings an idle
	// pool every 250 ms (keep_proof) and says it once a second, so the judge
	// saw an idle pool's proof up to 1.17 s old (TestTheBrainMovesOffA
	// ReceiverWhosePoolDied, a pool of 4 carrying nothing); 2 s is that and
	// 0.8 s more. Before keep_proof an idle pool pinged a second after its
	// last send, its proof reached 1.95 s and the pool needed 4 s. The
	// pool's silences of 17.11 13:51 were 5.7 s first, then up to 12 s, back
	// to back for a minute.
	PoolDeadAfter = 2 * time.Second
)

// Judge decides moves between receivers. Its zero value is ready.
type Judge struct {
	movedAt time.Time
	// silentSince is when the active receiver was first not heard, by rx: a
	// receiver nobody has heard since the pipe started is dead only after
	// DeadAfter of its own. poolSilentSince is the same for its pool alone.
	silentSince, poolSilentSince map[byte]time.Time
}

// Verdict is a judge's answer: move to To, or hold, and why.
type Verdict struct {
	Move bool
	To   byte
	Why  string
}

// heardWithin: one of wires heard its exit within d (and has a member up).
func heardWithin(wires []WireTick, d time.Duration) bool {
	for _, w := range wires {
		if w.Up > 0 && w.ProofAgo >= 0 && w.ProofAgo < d {
			return true
		}
	}
	return false
}

func membersUp(wires []WireTick) int {
	n := 0
	for _, w := range wires {
		n += w.Up
	}
	return n
}

// poolOf is the pool among wires, nil when it has none.
func poolOf(wires []WireTick) []WireTick {
	for i, w := range wires {
		if w.ID == trunk.PoolWire {
			return wires[i : i+1]
		}
	}
	return nil
}

// Step judges the pipe's latest tick and receivers at now. paused is how
// long ago the pipe or the brain came back from a pause (negative: none).
func (j *Judge) Step(now time.Time, tick Tick, rs Receivers, paused time.Duration) Verdict {
	if j.silentSince == nil {
		j.silentSince = map[byte]time.Time{}
		j.poolSilentSince = map[byte]time.Time{}
	}
	pool := poolOf(tick.Wires)
	whole := heardWithin(tick.Wires, DeadAfter)
	if whole {
		delete(j.silentSince, rs.Active)
	}
	if pool == nil || heardWithin(pool, PoolDeadAfter) {
		delete(j.poolSilentSince, rs.Active)
		if whole {
			return Verdict{Why: "the active receiver is heard"}
		}
	}
	// What is unheard: the whole receiver, or, the rest of it heard, its
	// pool, and with it every client's stream.
	wires, silent, what, dead := tick.Wires, j.silentSince, "the active receiver", DeadAfter
	if whole {
		wires, silent, what, dead = pool, j.poolSilentSince, "the active receiver's pool", PoolDeadAfter
	}
	since, ok := silent[rs.Active]
	if !ok {
		since = now
		silent[rs.Active] = now
	}
	switch {
	case len(rs.Standby) == 0:
		return Verdict{Why: "no receiver on standby"}
	case paused >= 0 && paused < DeadAfter:
		return Verdict{Why: "a pause of the entry's own: every proof is old"}
	case !j.movedAt.IsZero() && now.Sub(j.movedAt) < Settle:
		return Verdict{Why: "settling after a move"}
	}
	// Dead: its youngest proof is dead old, or none came in dead of watching
	// it (a pipe just started, a receiver dead from the start). Members down
	// with a young proof are dying, not dead: the proof ages.
	if age := proofAge(wires); age >= 0 && age < dead || age < 0 && now.Sub(since) < dead {
		return Verdict{Why: what + " not heard, not dead yet"}
	}
	// A standby must be heard, and, when the pool is what died, its pool
	// heard: moving to a receiver whose pool is dead carries no stream.
	best, bestUp := -1, 0
	for i, r := range rs.Standby {
		ws, within := r.Wires, DeadAfter
		if whole {
			ws, within = poolOf(r.Wires), PoolDeadAfter
		}
		if !heardWithin(ws, within) {
			continue
		}
		if up := membersUp(ws); best < 0 || up > bestUp {
			best, bestUp = i, up
		}
	}
	if best < 0 {
		if whole {
			return Verdict{Why: "the active receiver's pool not heard, no standby's pool is: the whole path"}
		}
		return Verdict{Why: "no receiver is heard: the whole path"}
	}
	j.movedAt = now
	delete(j.silentSince, rs.Active)
	delete(j.poolSilentSince, rs.Active)
	to := rs.Standby[best]
	return Verdict{Move: true, To: to.Rx, Why: what + " unheard for " + unheard(wires, now.Sub(since)).String()}
}

// proofAge is the youngest proof of wires, negative when none ever heard.
func proofAge(wires []WireTick) time.Duration {
	age := time.Duration(-1)
	for _, w := range wires {
		if w.ProofAgo >= 0 && (age < 0 || w.ProofAgo < age) {
			age = w.ProofAgo
		}
	}
	return age
}

// unheard is how long the active receiver has gone unheard: its youngest
// proof, or how long the judge has watched it silent when none.
func unheard(wires []WireTick, watched time.Duration) time.Duration {
	if a := proofAge(wires); a >= 0 {
		return a.Round(100 * time.Millisecond)
	}
	return watched.Round(100 * time.Millisecond)
}
