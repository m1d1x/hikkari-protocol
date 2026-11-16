package trunk

import (
	"fmt"
	"slices"
	"sort"
	"time"
)

// The selector's live classes (spec/trunk.md, Wires; hikkari-client
// plans/2026-11-15-live-udp-two-fates.md, раздел 5): voice is a set of two
// fates, video one wire, both ranked by what a listener heard of each wire's
// own call (hearing.go), not by the pauses between its answers.
//
// Two speeds again. A wire better than the one in its place takes it after
// Hold, a red one is left at once (Selector.pickLocked). A set that heard bad
// seconds gets a third copy at once, and loses it after Hold with no bad
// second: a copy moves no traffic, there is nothing to hold it against. Video
// leaves a wire that had bad seconds for one of another fate at once: it has
// no copy to hide them.

const (
	// voiceBuffer is the place in CallBuffers voice is ranked by: 60 ms.
	voiceBuffer = 1
	// rttEqual is how far apart two round trips are still one: a call does
	// not hear 50 ms more of delay (the plan's goal, «rtt +20–50 мс не
	// считается»).
	rttEqual = 50 * time.Millisecond
	// callKeep is how old a wire's latest call window may be to rank it: the
	// minute just over and the one before, should a report come late.
	callKeep = 2 * time.Minute
	// secondsKept is how long a wire's seconds rank it for video.
	secondsKept = time.Minute
	// recentSeconds is how many of the last seconds the fast moves look
	// at, and recentFor how old the oldest of them may be: seconds that stop
	// coming (no call, an old exit) are not counted against now.
	recentSeconds = 5
	recentFor     = 10 * time.Second
	// boostBad is how many bad seconds of the set's last recentSeconds give
	// voice its third copy, videoLeaveBad how many of a wire's move video.
	boostBad      = 2
	videoLeaveBad = 3
	// thirdCopyAfter is how long after the first the third copy leaves: a
	// burst of loss that took the first is over by then (voice-night-lab).
	thirdCopyAfter = 10 * time.Millisecond
)

// VoiceSetName is the voice class's set as RunCalls hears it (VoiceCallSet):
// the selector takes this set's seconds for the third copy.
const VoiceSetName = "voice"

// VoiceCallSet is the voice class's set as route gives it now, to be heard
// from the calls pinned to its wires: the route's set, or its main wire and
// the pool (the other fate a route without a set gets while the pool is up),
// or the pool alone when voice has no main wire of its own.
func VoiceCallSet(route func() Route) CallSet {
	return CallSet{Name: VoiceSetName, Wires: func() []WireID {
		r := route()
		if n := r.VoiceSet.Len(); n > 0 {
			out := make([]WireID, 0, n)
			for i := 0; i < n; i++ {
				if w := r.VoiceSet.At(i).Wire; w != AnyWire && !slices.Contains(out, w) {
					out = append(out, w)
				}
			}
			return out
		}
		if r.Voice == AnyWire || r.Voice == PoolWire {
			return []WireID{PoolWire}
		}
		return []WireID{r.Voice, PoolWire}
	}}
}

// Second takes one second a listener heard: of the voice set, or of a call
// pinned to one wire.
func (s *Selector) Second(c CallSecond) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case c.Set == VoiceSetName:
		s.voiceSecs = append(s.voiceSecs, c)
		if len(s.voiceSecs) > recentSeconds {
			s.voiceSecs = s.voiceSecs[len(s.voiceSecs)-recentSeconds:]
		}
		if end := c.At.Add(time.Second); c.Bad && end.After(s.lastBad) {
			s.lastBad = end
		}
	case c.Set == "":
		if sw := s.wires[c.Wire]; sw != nil {
			sw.secs = append(sw.secs, c)
		}
	}
}

// voiceScore is what a wire is ranked by for voice: what a listener heard of
// its call's latest minute at the 60 ms buffer, up and down together, then
// its round trip. known is false for a wire not heard yet.
type voiceScore struct {
	known               bool
	badS, runs2, holesK int // holesK: holes per 1000 frames
	rtt                 time.Duration
}

func (v voiceScore) better(o voiceScore) bool {
	switch {
	case v.known != o.known:
		return v.known
	case v.badS != o.badS:
		return v.badS < o.badS
	case v.runs2 != o.runs2:
		return v.runs2 < o.runs2
	case v.holesK != o.holesK:
		return v.holesK < o.holesK
	}
	return v.rtt+rttEqual < o.rtt
}

// voiceLocked is sw's voice score from its latest call window. A window an
// exit stamped nothing in is heard by what the call has: lost datagrams as
// holes, pauses over 60 ms as runs, over 150 ms as bad seconds.
func (s *Selector) voiceLocked(sw *selWire) voiceScore {
	var w *CallWindow
	for i := range sw.calls {
		if w == nil || sw.calls[i].To.After(w.To) {
			w = &sw.calls[i]
		}
	}
	if w == nil {
		return voiceScore{}
	}
	v := voiceScore{known: true, rtt: w.RTTP50}
	if n := w.Up.Frames + w.Down.Frames; n > 0 {
		v.badS = w.Up.BadS[voiceBuffer] + w.Down.BadS[voiceBuffer]
		v.runs2 = w.Up.Runs2[voiceBuffer] + w.Down.Runs2[voiceBuffer]
		v.holesK = (w.Up.Holes[voiceBuffer] + w.Down.Holes[voiceBuffer]) * 1000 / n
		return v
	}
	v.badS, v.runs2 = w.Gaps150, w.Gaps60
	if w.Sent > 0 {
		v.holesK = w.Lost() * 1000 / w.Sent
	}
	return v
}

func (s *Selector) voiceBetterLocked(a, b WireID) bool {
	return s.voiceLocked(s.wires[a]).better(s.voiceLocked(s.wires[b]))
}

// rankVoiceLocked is the wires of ids not left whose fate keep takes, best
// first for voice; ties keep the order of ids.
func (s *Selector) rankVoiceLocked(ids []WireID, left map[WireID]bool, keep func(Fate) bool) []WireID {
	var out []WireID
	for _, id := range ids {
		if !left[id] && keep(s.wires[id].w.fate()) {
			out = append(out, id)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return s.voiceBetterLocked(out[i], out[j]) })
	return out
}

// chooseVoiceLocked puts voice's set on next: the best wire of fate udp as
// its main wire (of any other fate while there is none to be had), the best
// wire of another fate with one copy, and the third copy while the set's
// seconds call for it. It says what changed.
func (s *Selector) chooseVoiceLocked(next *Route, ids []WireID, left map[WireID]bool, now time.Time) []string {
	var why []string
	say := func(w string) {
		if w != "" {
			why = append(why, w)
		}
	}
	ranked := s.rankVoiceLocked(ids, left, func(f Fate) bool { return f == FateUDP })
	if len(ranked) == 0 {
		ranked = s.rankVoiceLocked(ids, left, func(Fate) bool { return true })
	}
	main, moved := s.pickLocked(slotVoice, s.cur.Voice, ranked, left, s.voiceBetterLocked, now)
	say(moved)
	if main == AnyWire {
		s.voice2 = AnyWire
		next.Voice = AnyWire
		return why
	}
	fate := s.wires[main].w.fate()
	other := s.rankVoiceLocked(ids, left, func(f Fate) bool { return f != fate })
	v2 := AnyWire
	if len(other) > 0 {
		v2, moved = s.pickLocked(slotVoice2, s.voice2, other, left, s.voiceBetterLocked, now)
		say(moved)
	} else {
		s.chall[slotVoice2].wire = AnyWire
	}
	s.voice2 = v2
	say(s.boostLocked(main, now))

	set := SetOf(Carry{Wire: main})
	if v2 != AnyWire {
		set.add(Carry{Wire: v2, Copies: 1})
	}
	if s.boosted && fate == FateUDP {
		set.add(Carry{Wire: main, Copies: 1, After: thirdCopyAfter})
	}
	next.Voice, next.VoiceSet = main, set
	return why
}

// boostLocked gives voice its third copy after boostBad bad seconds of the
// set's last ones, and takes it after Hold with no bad second.
func (s *Selector) boostLocked(main WireID, now time.Time) string {
	if !s.boosted {
		if n := recentBad(s.voiceSecs, now); n >= boostBad {
			s.boosted = true
			return fmt.Sprintf("voice: third copy on %s (%d bad seconds of %d)", s.wires[main].w.Name, n, recentSeconds)
		}
		return ""
	}
	if now.Sub(s.lastBad) >= s.cfg.Hold {
		s.boosted = false
		return fmt.Sprintf("voice: third copy off (no bad second for %s)", s.cfg.Hold)
	}
	return ""
}

// recentBad is how many of the last recentSeconds of secs, oldest first,
// were bad, counting none older than recentFor.
func recentBad(secs []CallSecond, now time.Time) int {
	n := 0
	for i := max(0, len(secs)-recentSeconds); i < len(secs); i++ {
		if secs[i].Bad && now.Sub(secs[i].At) <= recentFor {
			n++
		}
	}
	return n
}

// videoBadLocked is how many bad seconds sw's call heard in the last minute
// at the video buffer.
func (s *Selector) videoBadLocked(sw *selWire, now time.Time) int {
	n := 0
	for _, c := range sw.secs {
		if c.Bad && now.Sub(c.At) <= secondsKept {
			n++
		}
	}
	return n
}

// videoBetterLocked ranks a over b for video: fewer bad seconds over the
// last minute, then the voice rank, then a wire of fate udp.
func (s *Selector) videoBetterLocked(a, b WireID, now time.Time) bool {
	wa, wb := s.wires[a], s.wires[b]
	if na, nb := s.videoBadLocked(wa, now), s.videoBadLocked(wb, now); na != nb {
		return na < nb
	}
	va, vb := s.voiceLocked(wa), s.voiceLocked(wb)
	if va.better(vb) || vb.better(va) {
		return va.better(vb)
	}
	return wa.w.fate() == FateUDP && wb.w.fate() != FateUDP
}

// chooseVideoLocked puts video's one wire on next: off a wire that had
// videoLeaveBad bad seconds of its last ones at once, to the best wire of
// another fate (of any, with none); to a better one after Hold. It says what
// changed.
func (s *Selector) chooseVideoLocked(next *Route, ids []WireID, left map[WireID]bool, now time.Time) string {
	var ranked []WireID
	for _, id := range ids {
		if !left[id] {
			ranked = append(ranked, id)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return s.videoBetterLocked(ranked[i], ranked[j], now) })
	cur := s.video
	if cur != AnyWire && slices.Contains(ranked, cur) {
		if n := recentBad(s.wires[cur].secs, now); n >= videoLeaveBad {
			if to := s.otherFateLocked(cur, ranked); to != AnyWire {
				s.chall[slotVideo].wire = AnyWire
				s.video = to
				*next = next.WithVideo(to)
				return fmt.Sprintf("video: %s had %d bad seconds of %d, to %s", s.wires[cur].w.Name, n, recentSeconds, s.wires[to].w.Name)
			}
		}
	}
	pick, moved := s.pickLocked(slotVideo, cur, ranked, left, func(a, b WireID) bool { return s.videoBetterLocked(a, b, now) }, now)
	s.video = pick
	*next = next.WithVideo(pick)
	return moved
}

// otherFateLocked is the first wire of ranked of another fate than cur's,
// else the first that is not cur; AnyWire for none.
func (s *Selector) otherFateLocked(cur WireID, ranked []WireID) WireID {
	fate := s.wires[cur].w.fate()
	for _, id := range ranked {
		if s.wires[id].w.fate() != fate {
			return id
		}
	}
	for _, id := range ranked {
		if id != cur {
			return id
		}
	}
	return AnyWire
}
