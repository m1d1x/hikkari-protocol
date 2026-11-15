package trunk

import (
	"math"
	"slices"
	"sort"
	"time"
)

// What a listener hears of the trunk's call (spec/trunk.md, "What a listener
// hears"): not the pauses between answers but the holes at the moment of
// play. A listener plays frame n at the best one-way delay of the window plus
// its jitter buffer; a frame that came later, or never, is a hole. Up is a
// listener at the exit (the exit's stamp and map, echo.go), down one at the
// entry (its own receipt of the answer). The ends' clocks are not one: the
// best delay of the window is taken off every frame's, and that takes the
// clocks' offset with it.
//
// An application's real buffer is not known and moves by itself, so the same
// arrivals are heard with three buffers at once (CallBuffers): 40 ms is the
// worst case to look at, 100 ms the best, the selector ranks voice by 60.

// CallBuffers are the jitter buffers a call is heard with, in this order in
// CallHearing.
var CallBuffers = [3]time.Duration{40 * time.Millisecond, 60 * time.Millisecond, 100 * time.Millisecond}

// A second is bad (heard as a robot voice) when this share of its frames or
// more are holes, and at least badSecondHoles: 3 of a second's 50 frames.
const (
	badSecondPct   = 6
	badSecondHoles = 3
)

// CallHearing is what a listener heard of one direction in a window, for
// each of CallBuffers.
//
// Frames is the frames judged: up every frame sent, down every frame the exit
// had (a frame lost on the way up has no answer to lose on the way down). 0
// when the exit stamped nothing (an exit older than its echo map): nothing
// was heard then. A frame the exit's map says it had, whose answer was lost,
// is on time up: its delay up is not known.
type CallHearing struct {
	Frames  int
	Seconds int // seconds with a frame judged
	Holes   [3]int
	Runs2   [3]int // runs of 2 holes or more: a syllable swallowed (one frame PLC hides)
	BadS    [3]int // bad seconds
}

// HolesPct is the share of holes in per cent for buffer i of CallBuffers.
func (h CallHearing) HolesPct(i int) float64 {
	if h.Frames == 0 {
		return 0
	}
	return float64(h.Holes[i]) * 100 / float64(h.Frames)
}

// CallLag is how much later one copy of a frame came than another, over the
// frames both came on: negative when it came first.
type CallLag struct {
	N             int
	P50, P95, Max time.Duration
}

// CallSetWindow is what one window of a set of wires heard (CallSet).
type CallSetWindow struct {
	Name     string
	From, To time.Time
	// Wires are those the set had in the window with a call held to them,
	// the ones that were first first.
	Wires    []WireID
	Up, Down CallHearing
	// LagUp and LagDown are how much later the copy on another wire of the
	// set came than the copy on its first (the pool's copy behind the
	// datagrams', in the voice set), up at the exit and down at the entry.
	LagUp, LagDown CallLag
}

// heardFrame is one frame as the calls of a view had it; lead is the place in
// legs of the set's first wire, -1 for none.
type heardFrame struct {
	at   time.Time
	legs []*callSent
	lead int
}

// heard is what hear makes of a view's frames.
type heard struct {
	up, down       CallHearing
	lagUp, lagDown CallLag
	minUp, minDown int64
}

// hearCount counts one direction's holes for one buffer, frame by frame in
// order.
type hearCount struct {
	h        *CallHearing
	i        int
	run      int
	sec      int64
	inSec    int
	holesSec int
}

func (c *hearCount) add(at time.Time, hole bool) {
	if s := at.Unix(); s != c.sec || c.inSec == 0 {
		c.flush()
		c.sec = s
	}
	c.inSec++
	if c.i == 0 {
		c.h.Frames++
	}
	if !hole {
		c.run = 0
		return
	}
	c.holesSec++
	c.h.Holes[c.i]++
	if c.run++; c.run == 2 {
		c.h.Runs2[c.i]++
	}
}

func (c *hearCount) flush() {
	if c.inSec == 0 {
		return
	}
	if c.i == 0 {
		c.h.Seconds++
	}
	if badSecond(c.holesSec, c.inSec) {
		c.h.BadS[c.i]++
	}
	c.inSec, c.holesSec = 0, 0
}

// hear judges frames, in frame order, as one listener: a frame is on time if
// it came in time on one of its calls, its delay over the best of the view
// taken against each buffer.
func hear(frames []heardFrame) heard {
	out := heard{minUp: math.MaxInt64, minDown: math.MaxInt64}
	for _, f := range frames {
		for _, r := range f.legs {
			if r.exit == 0 {
				continue
			}
			out.minUp = min(out.minUp, r.exit-f.at.UnixNano())
			out.minDown = min(out.minDown, r.back-r.exit)
		}
	}
	if out.minUp == math.MaxInt64 {
		return heard{}
	}
	for i, buf := range CallBuffers {
		b := int64(buf)
		up := hearCount{h: &out.up, i: i}
		down := hearCount{h: &out.down, i: i}
		for _, f := range frames {
			upOK, had, downOK := false, false, false
			for _, r := range f.legs {
				switch {
				case r.exit != 0:
					upOK = upOK || r.exit-f.at.UnixNano()-out.minUp <= b
					downOK = downOK || r.back-r.exit-out.minDown <= b
					had = true
				case r.had:
					upOK, had = true, true
				}
			}
			up.add(f.at, !upOK)
			if had {
				down.add(f.at, !downOK)
			}
		}
		up.flush()
		down.flush()
	}
	out.lagUp, out.lagDown = lags(frames)
	return out
}

// lags is how much later the other calls' copies came than the lead's.
func lags(frames []heardFrame) (up, down CallLag) {
	var ups, downs []time.Duration
	for _, f := range frames {
		if f.lead < 0 || f.legs[f.lead].exit == 0 {
			continue
		}
		l := f.legs[f.lead]
		for j, r := range f.legs {
			if j == f.lead || r.exit == 0 {
				continue
			}
			ups = append(ups, time.Duration(r.exit-l.exit))
			downs = append(downs, time.Duration((r.back-r.exit)-(l.back-l.exit)))
		}
	}
	return lagOf(ups), lagOf(downs)
}

func lagOf(d []time.Duration) CallLag {
	if len(d) == 0 {
		return CallLag{}
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return CallLag{N: len(d), P50: quantile(d, 50), P95: quantile(d, 95), Max: d[len(d)-1]}
}

// callGroup is the calls of RunCalls and the sets heard from them.
type callGroup struct {
	legs []*call
	sets []CallSet
	// judged is the start of the latest second heard (second.go).
	judged time.Time
}

// members marks, for each call, the sets its wire is in now (in) and those
// it is the first of (lead).
func (g *callGroup) members(in, lead []uint8) {
	clear(in)
	clear(lead)
	for k, set := range g.sets {
		for j, w := range set.Wires() {
			for i, c := range g.legs {
				if c.cfg.OnWire && c.cfg.Wire == w {
					in[i] |= 1 << k
					if j == 0 {
						lead[i] |= 1 << k
					}
				}
			}
		}
	}
}

// due takes every call's windows whose Grace is over, and each set's of the
// same windows, before their datagrams leave the calls' rings.
func (g *callGroup) due(now time.Time) ([][]CallWindow, []CallSetWindow) {
	for _, c := range g.legs {
		c.mu.Lock()
	}
	defer func() {
		for _, c := range g.legs {
			c.mu.Unlock()
		}
	}()
	legWs := make([][]CallWindow, len(g.legs))
	done := make([][]*callBucket, len(g.legs))
	closed := false
	for i, c := range g.legs {
		if done[i] = c.closeLocked(now); done[i] != nil {
			legWs[i] = c.windowsLocked(done[i])
			closed = true
		}
	}
	if !closed {
		return nil, nil
	}
	var setWs []CallSetWindow
	for k, set := range g.sets {
		for _, from := range windowsOf(done) {
			if w, ok := g.setWindow(k, set.Name, from, done); ok {
				setWs = append(setWs, w)
			}
		}
	}
	for _, c := range g.legs {
		c.dropLocked()
	}
	return legWs, setWs
}

// windowsOf is the starts of the windows closed, each once, oldest first.
func windowsOf(done [][]*callBucket) []time.Time {
	var out []time.Time
	seen := map[time.Time]bool{}
	for _, bs := range done {
		for _, b := range bs {
			if !seen[b.from] {
				seen[b.from] = true
				out = append(out, b.from)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// setWindow is set k's window from from its calls' datagrams in the rings;
// false when no call of the set sent in it.
func (g *callGroup) setWindow(k int, name string, from time.Time, done [][]*callBucket) (CallSetWindow, bool) {
	bit := uint8(1) << k
	bySeq := map[uint64]*heardFrame{}
	inSet := make([]bool, len(g.legs))
	wasLead := make([]bool, len(g.legs))
	var to time.Time
	for i, c := range g.legs {
		var b *callBucket
		for _, x := range done[i] {
			if x.from.Equal(from) {
				b = x
			}
		}
		if b == nil {
			continue
		}
		to = b.to
		for j := 0; j < c.n; j++ {
			r := &c.ring[(c.head+j)&(len(c.ring)-1)]
			if r.b != b || r.sets&bit == 0 {
				continue
			}
			seq := c.base + uint64(j)
			f := bySeq[seq]
			if f == nil {
				f = &heardFrame{at: r.at, lead: -1}
				bySeq[seq] = f
			}
			if r.lead&bit != 0 {
				f.lead = len(f.legs)
				wasLead[i] = true
			}
			f.legs = append(f.legs, r)
			inSet[i] = true
		}
	}
	if len(bySeq) == 0 {
		return CallSetWindow{}, false
	}
	seqs := make([]uint64, 0, len(bySeq))
	for s := range bySeq {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	frames := make([]heardFrame, 0, len(seqs))
	for _, s := range seqs {
		frames = append(frames, *bySeq[s])
	}
	h := hear(frames)
	w := CallSetWindow{Name: name, From: from, To: to, Up: h.up, Down: h.down, LagUp: h.lagUp, LagDown: h.lagDown}
	for _, first := range []bool{true, false} {
		for i, c := range g.legs {
			if inSet[i] && wasLead[i] == first && !slices.Contains(w.Wires, c.cfg.Wire) {
				w.Wires = append(w.Wires, c.cfg.Wire)
			}
		}
	}
	return w, true
}
