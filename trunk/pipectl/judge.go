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

import "time"

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
)

// Judge decides moves between receivers. Its zero value is ready.
type Judge struct {
	movedAt time.Time
	// silentSince is when the active receiver was first not heard, by rx: a
	// receiver nobody has heard since the pipe started is dead only after
	// DeadAfter of its own.
	silentSince map[byte]time.Time
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

// Step judges the pipe's latest tick and receivers at now. paused is how
// long ago the pipe or the brain came back from a pause (negative: none).
func (j *Judge) Step(now time.Time, tick Tick, rs Receivers, paused time.Duration) Verdict {
	if j.silentSince == nil {
		j.silentSince = map[byte]time.Time{}
	}
	if heardWithin(tick.Wires, DeadAfter) {
		delete(j.silentSince, rs.Active)
		return Verdict{Why: "the active receiver is heard"}
	}
	since, ok := j.silentSince[rs.Active]
	if !ok {
		since = now
		j.silentSince[rs.Active] = now
	}
	switch {
	case len(rs.Standby) == 0:
		return Verdict{Why: "no receiver on standby"}
	case paused >= 0 && paused < DeadAfter:
		return Verdict{Why: "a pause of the entry's own: every proof is old"}
	case !j.movedAt.IsZero() && now.Sub(j.movedAt) < Settle:
		return Verdict{Why: "settling after a move"}
	}
	// Dead: its youngest proof is DeadAfter old, or none came in DeadAfter
	// of watching it (a pipe just started, a receiver dead from the start).
	// Members down with a young proof are dying, not dead: the proof ages.
	if age := proofAge(tick.Wires); age >= 0 && age < DeadAfter || age < 0 && now.Sub(since) < DeadAfter {
		return Verdict{Why: "the active receiver not heard, not dead yet"}
	}
	best, bestUp := -1, 0
	for i, r := range rs.Standby {
		if !heardWithin(r.Wires, DeadAfter) {
			continue
		}
		if up := membersUp(r.Wires); best < 0 || up > bestUp {
			best, bestUp = i, up
		}
	}
	if best < 0 {
		return Verdict{Why: "no receiver is heard: the whole path"}
	}
	j.movedAt = now
	delete(j.silentSince, rs.Active)
	to := rs.Standby[best]
	return Verdict{Move: true, To: to.Rx, Why: "the active receiver unheard for " + unheard(tick.Wires, now.Sub(since)).String()}
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
