package trunk

import (
	"math"
	"time"
)

// What a listener heard in each second, for the selector's fast moves
// (spec/trunk.md, Wires; hikkari-client plans/2026-11-15-live-udp-two-fates.md,
// раздел 5). The minute (hearing.go) ranks wires; a minute is too late to give
// a call a third copy or to move video off a wire that went bad. So each
// second, once its answers have had time to come, RunCalls hears it again: the
// voice set's calls as one listener, and each call pinned to a wire alone.
//
// A second is judged against the best delays of every frame the calls still
// keep (the open window and the one in its grace), not of its own minute,
// which is not over yet: the clocks' offset goes with that best, as in hear.

// The buffers a second is heard with: the voice set as the selector ranks
// voice, a wire's own call as video plays.
const (
	secondVoiceBuffer = 60 * time.Millisecond
	secondVideoBuffer = 200 * time.Millisecond
	// secondJudgeAfter is how long after its end a second is judged: its
	// last frame's answer, and the exit's map telling of frames whose
	// answers were lost, came well within it.
	secondJudgeAfter = time.Second
	// secondsAtOnce is the most seconds judged in one tick: after a pause of
	// this box the seconds it missed are the box's, not the path's.
	secondsAtOnce = 5
)

// CallSecond is what a listener heard in one second.
type CallSecond struct {
	At time.Time // the second's start
	// Set is the set heard (CallSet.Name); "" for a call pinned to a wire.
	Set string
	// Wire is the pinned call's wire; AnyWire for a set.
	Wire WireID
	// Frames is the frames judged up; 0 is not heard (an exit that stamps
	// nothing), and RunCalls does not report it.
	Frames int
	// Bad says the second was bad up or down (badSecondHoles and
	// badSecondPct, hearing.go) at its buffer: secondVoiceBuffer for a set,
	// secondVideoBuffer for a wire.
	Bad bool
}

// seconds judges the seconds that are due: those that ended secondJudgeAfter
// before now and were not judged yet, at most secondsAtOnce.
func (g *callGroup) seconds(now time.Time) []CallSecond {
	last := now.Add(-secondJudgeAfter).Truncate(time.Second).Add(-time.Second)
	if g.judged.IsZero() || last.Sub(g.judged) > secondsAtOnce*time.Second {
		g.judged = last.Add(-time.Second)
	}
	if !last.After(g.judged) {
		return nil
	}
	for _, c := range g.legs {
		c.mu.Lock()
	}
	defer func() {
		for _, c := range g.legs {
			c.mu.Unlock()
		}
	}()
	var out []CallSecond
	sets := make([][]heardFrame, len(g.sets))
	for k := range g.sets {
		sets[k] = g.keptFrames(uint8(1) << k)
	}
	legs := make([][]heardFrame, len(g.legs))
	for i, c := range g.legs {
		if c.cfg.OnWire {
			legs[i] = c.keptFramesLocked()
		}
	}
	for at := g.judged.Add(time.Second); !at.After(last); at = at.Add(time.Second) {
		for k, set := range g.sets {
			if n, bad := judgeSecond(sets[k], at, secondVoiceBuffer); n > 0 {
				out = append(out, CallSecond{At: at, Set: set.Name, Wire: AnyWire, Frames: n, Bad: bad})
			}
		}
		for i, c := range g.legs {
			if legs[i] == nil {
				continue
			}
			if n, bad := judgeSecond(legs[i], at, secondVideoBuffer); n > 0 {
				out = append(out, CallSecond{At: at, Wire: c.cfg.Wire, Frames: n, Bad: bad})
			}
		}
	}
	g.judged = last
	return out
}

// keptFrames is every frame the calls keep that set bit had a wire of, by
// frame number, oldest first.
func (g *callGroup) keptFrames(bit uint8) []heardFrame {
	var first, end uint64 = math.MaxUint64, 0
	for _, c := range g.legs {
		if c.n > 0 {
			first, end = min(first, c.base), max(end, c.base+uint64(c.n))
		}
	}
	if first >= end {
		return nil
	}
	byFrame := make([]heardFrame, end-first)
	for _, c := range g.legs {
		for j := 0; j < c.n; j++ {
			r := &c.ring[(c.head+j)&(len(c.ring)-1)]
			if r.b == nil || r.sets&bit == 0 {
				continue
			}
			f := &byFrame[c.base+uint64(j)-first]
			f.at = r.at
			f.legs = append(f.legs, r)
		}
	}
	out := byFrame[:0]
	for _, f := range byFrame {
		if len(f.legs) > 0 {
			out = append(out, f)
		}
	}
	return out
}

// keptFramesLocked is every frame the call keeps, alone.
func (c *call) keptFramesLocked() []heardFrame {
	out := make([]heardFrame, 0, c.n)
	for j := 0; j < c.n; j++ {
		if r := &c.ring[(c.head+j)&(len(c.ring)-1)]; r.b != nil {
			out = append(out, heardFrame{at: r.at, legs: []*callSent{r}, lead: -1})
		}
	}
	return out
}

// judgeSecond hears the frames sent in the second from at as one listener
// with buffer buf, against the best delays of all of frames, and says how
// many it judged up and whether the second was bad either way. 0 when the
// exit stamped none of frames.
func judgeSecond(frames []heardFrame, at time.Time, buf time.Duration) (int, bool) {
	minUp, minDown := int64(math.MaxInt64), int64(math.MaxInt64)
	for _, f := range frames {
		for _, r := range f.legs {
			if r.exit != 0 {
				minUp = min(minUp, r.exit-f.at.UnixNano())
				minDown = min(minDown, r.back-r.exit)
			}
		}
	}
	if minUp == math.MaxInt64 {
		return 0, false
	}
	b := int64(buf)
	end := at.Add(time.Second)
	upN, upHoles, downN, downHoles := 0, 0, 0, 0
	for _, f := range frames {
		if f.at.Before(at) || !f.at.Before(end) {
			continue
		}
		upOK, had, downOK := false, false, false
		for _, r := range f.legs {
			switch {
			case r.exit != 0:
				upOK = upOK || r.exit-f.at.UnixNano()-minUp <= b
				downOK = downOK || r.back-r.exit-minDown <= b
				had = true
			case r.had:
				upOK, had = true, true
			}
		}
		upN++
		if !upOK {
			upHoles++
		}
		if had {
			downN++
			if !downOK {
				downHoles++
			}
		}
	}
	return upN, badSecond(upHoles, upN) || badSecond(downHoles, downN)
}

// badSecond is the minute's rule for a bad second (hearCount.flush).
func badSecond(holes, frames int) bool {
	return holes >= badSecondHoles && holes*100 >= badSecondPct*frames
}
