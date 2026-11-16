package trunk

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// The selector: which wire each class goes on, chosen by the entry from its
// own measurements (hikkari-client plans/2026-11-11-trunk-wires-stage4.md,
// раздел 6). No order of wires is fixed in code: the pool is one wire among
// the others, ranked by the same numbers.
//
// Two speeds:
//
//   - A red wire is left at once. Red is no member up, or every member
//     owing progress for RedSilence (WireState.Owed) while another wire
//     proved the path alive in that time. Every wire silent together is a pause of this box
//     or a cut of the whole path: nobody is red for it (as Quiet in the
//     pool), and nothing moves. Nor does a wire red within PauseGrace of a
//     pause of this box (Paused): a box that was not run buries and owes
//     on every wire, and which one comes back last is luck, not the wire
//     (11.11: every move of voice off udp came in a train of the entry's
//     own pauses, at the stand's rounds). Such a wire is Held, not left;
//     while it has no member the session carries its traffic on any member
//     that can, as for any wire without one.
//   - Otherwise the rank is slow. Bulk is ranked by its 1 MiB downloads
//     over BulkSpan: fewer failed, then the faster median, then less CPU,
//     and a wire takes bulk from the one carrying it only when it is better
//     by BulkMargin and stays so for Hold. Voice is a set of two fates and
//     video one wire, both ranked by what a listener heard of each wire's
//     call (selector_voice.go).
//
// The warm wires: for each class the chosen wire and the best other wire of
// another shape, so that one rule against one form does not take both, and
// every wire of voice's set.

// SelectorConfig tunes a Selector. Zero fields take the defaults.
type SelectorConfig struct {
	RedSilence time.Duration // 500 ms
	BulkSpan   time.Duration // 1 h of downloads
	Hold       time.Duration // 5 min a challenger must stay better
	// BulkMargin is how much faster a challenger's median download must be,
	// as a fraction (0.25: a quarter), at as few failures.
	BulkMargin float64
	// PauseGrace is how long after a pause of this box (Paused) a red wire
	// is held rather than left.
	PauseGrace time.Duration // 10 s
}

const (
	DefaultRedSilence = 500 * time.Millisecond
	DefaultBulkSpan   = time.Hour
	// The margin and the hold from the stand's night (11.11 01:00–05:46
	// UTC, hikkari-client plans/research/2026-11-11-trunk-selector-thresholds.md):
	// voice moved between wires as good as each other did not lower its red
	// minutes, only shook the call; a 1 MiB download measures a round trip
	// or two of slow start, its medians of equal wires differ by up to 12%.
	DefaultHold       = 5 * time.Minute
	DefaultBulkMargin = 0.25
	// A pause train of the entry at a round of the stand (11.11) took its
	// udp members and kept the wire red 7 s after the last pause, while they
	// redialed: the grace covers it with room.
	DefaultPauseGrace = 10 * time.Second
)

func (c SelectorConfig) withDefaults() SelectorConfig {
	if c.RedSilence <= 0 {
		c.RedSilence = DefaultRedSilence
	}
	if c.BulkSpan <= 0 {
		c.BulkSpan = DefaultBulkSpan
	}
	if c.Hold <= 0 {
		c.Hold = DefaultHold
	}
	if c.BulkMargin <= 0 {
		c.BulkMargin = DefaultBulkMargin
	}
	if c.PauseGrace <= 0 {
		c.PauseGrace = DefaultPauseGrace
	}
	return c
}

// Download is one 1 MiB fetch of a wire's synthetic.
type Download struct {
	At    time.Time
	OK    bool          // all of it came
	Took  time.Duration // how long it took
	Bytes int64
	// CPU is the entry's CPU seconds per minute the wire cost around it;
	// 0 is unknown.
	CPU float64
}

// Choice is what the selector chose.
type Choice struct {
	Route Route
	// Warm are the wires to keep up for traffic: each class's wire and its
	// best other wire of another shape.
	Warm []WireID
	// Red are the wires red now.
	Red []WireID
	// Held are the wires of Red that are not left: red within PauseGrace
	// of this box's own pause, or every wire red at once.
	Held []WireID
	// Why says what changed, for the log; empty when nothing did. One
	// part per class that moved, joined by "; ", each one of
	// "<class>: on <wire>", "<class>: <wire> is red, to <wire>" and
	// "<class>: <wire> better than <wire> for <hold>" (hub cascadewatch
	// reads them back as events); <class> is bulk, voice (the set's main
	// wire), voice2 (its wire of another fate) or video. Voice's third copy
	// says "voice: third copy on <wire> (<n> bad seconds of 5)" and "voice:
	// third copy off (no bad second for <hold>)", video's quick move
	// "video: <wire> had <n> bad seconds of 5, to <wire>".
	Why string
}

type selWire struct {
	w     Wire
	calls []CallWindow
	dls   []Download
	// secs are the seconds its pinned call heard (CallSecond), the last
	// minute's.
	secs []CallSecond
}

// Selector ranks an entry's wires. Feed it each wire's call windows and
// seconds, the voice set's seconds and the downloads; Choose gives the route.
type Selector struct {
	cfg SelectorConfig

	mu    sync.Mutex
	wires map[WireID]*selWire
	cur   Route
	// voice2 is the set's wire of another fate, video video's wire; AnyWire
	// for none (cur holds them too, as its set and WithVideo).
	voice2, video WireID
	chall         [slots]challenger
	// voiceSecs are the voice set's last seconds, oldest first; boosted says
	// voice has its third copy, lastBad when the set last had a bad second.
	voiceSecs []CallSecond
	boosted   bool
	lastBad   time.Time
	// paused is when this box last came back from a pause of its own.
	paused time.Time
}

type challenger struct {
	wire  WireID
	since time.Time
}

// slot is a place of the route the selector fills.
type slot uint8

const (
	slotBulk slot = iota
	slotVoice
	slotVoice2
	slotVideo
	slots
)

func (sl slot) String() string {
	return [slots]string{"bulk", "voice", "voice2", "video"}[sl]
}

// NewSelector ranks the given wires (the pool among them, if the entry has
// one).
func NewSelector(cfg SelectorConfig, wires ...Wire) *Selector {
	s := &Selector{cfg: cfg.withDefaults(), wires: map[WireID]*selWire{}, cur: AnyRoute, voice2: AnyWire, video: AnyWire}
	for i := range s.chall {
		s.chall[i].wire = AnyWire
	}
	for _, w := range wires {
		s.wires[w.ID] = &selWire{w: w}
	}
	return s
}

// Paused tells the selector this box was not run until end: the session's
// clock ran late (Session.LastPause), or the selector's own tick did.
func (s *Selector) Paused(end time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if end.After(s.paused) {
		s.paused = end
	}
}

// Call takes one window of a wire's call.
func (s *Selector) Call(id WireID, w CallWindow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sw := s.wires[id]; sw != nil {
		sw.calls = append(sw.calls, w)
	}
}

// Download takes one download of a wire's synthetic.
func (s *Selector) Download(id WireID, d Download) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sw := s.wires[id]; sw != nil {
		sw.dls = append(sw.dls, d)
	}
}

type bulkScore struct {
	known  bool
	failed int
	mbps   float64 // median
	cpu    float64 // median; 0 unknown
}

func (b bulkScore) better(o bulkScore) bool {
	if b.known != o.known {
		return b.known
	}
	if b.failed != o.failed {
		return b.failed < o.failed
	}
	if b.mbps != o.mbps {
		return b.mbps > o.mbps
	}
	return b.cpu < o.cpu
}

func (s *Selector) bulkLocked(sw *selWire, now time.Time) bulkScore {
	var b bulkScore
	var rates, cpus []float64
	for _, d := range sw.dls {
		if now.Sub(d.At) > s.cfg.BulkSpan {
			continue
		}
		b.known = true
		if !d.OK || d.Took <= 0 {
			b.failed++
			continue
		}
		rates = append(rates, float64(d.Bytes)*8/d.Took.Seconds()/1e6)
		if d.CPU > 0 {
			cpus = append(cpus, d.CPU)
		}
	}
	b.mbps, b.cpu = median(rates), median(cpus)
	return b
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	return v[len(v)/2]
}

// forgetLocked drops what no rank looks at any more: calls older than
// callKeep, seconds older than secondsKept, downloads older than BulkSpan.
func (s *Selector) forgetLocked(now time.Time) {
	for _, sw := range s.wires {
		keep := sw.calls[:0]
		for _, w := range sw.calls {
			if now.Sub(w.To) <= callKeep {
				keep = append(keep, w)
			}
		}
		sw.calls = keep
		sk := sw.secs[:0]
		for _, c := range sw.secs {
			if now.Sub(c.At) <= secondsKept {
				sk = append(sk, c)
			}
		}
		sw.secs = sk
		dk := sw.dls[:0]
		for _, d := range sw.dls {
			if now.Sub(d.At) <= s.cfg.BulkSpan {
				dk = append(dk, d)
			}
		}
		sw.dls = dk
	}
}

// Choose gives the route for now, given what the session sees of its wires
// (Session.Wires).
func (s *Selector) Choose(now time.Time, live map[WireID]WireState) Choice {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgetLocked(now)

	// Red: no member, or owing for RedSilence while another wire proved
	// the path alive in that time.
	alive := func(not WireID) bool {
		for id := range s.wires {
			if l := live[id]; id != not && l.Members > 0 && l.Owed <= s.cfg.RedSilence && now.Sub(l.Proof) <= s.cfg.RedSilence {
				return true
			}
		}
		return false
	}
	red := map[WireID]bool{}
	for id := range s.wires {
		l := live[id]
		if l.Members == 0 || l.Owed > s.cfg.RedSilence && alive(id) {
			red[id] = true
		}
	}

	ids := make([]WireID, 0, len(s.wires))
	for id := range s.wires {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	// Left: the red wires to blame. None within PauseGrace of this box's
	// pause, none when every wire is red.
	left := red
	if len(red) == len(s.wires) || !s.paused.IsZero() && now.Sub(s.paused) <= s.cfg.PauseGrace {
		left = map[WireID]bool{}
	}

	var why []string
	say := func(w string) {
		if w != "" {
			why = append(why, w)
		}
	}
	var bulk []WireID
	for _, id := range ids {
		if !left[id] && s.wires[id].w.Streams {
			bulk = append(bulk, id)
		}
	}
	sort.SliceStable(bulk, func(i, j int) bool { return s.bulkBetterLocked(bulk[i], bulk[j], now) })
	bulkOn, moved := s.pickLocked(slotBulk, s.cur.Bulk, bulk, left, func(a, b WireID) bool { return s.byMarginLocked(a, b, now) }, now)
	say(moved)
	next := Route{Voice: AnyWire, Bulk: bulkOn}
	for _, w := range s.chooseVoiceLocked(&next, ids, left, now) {
		say(w)
	}
	say(s.chooseVideoLocked(&next, ids, left, now))
	s.cur = next

	c := Choice{Route: next}
	for _, id := range ids {
		if red[id] {
			c.Red = append(c.Red, id)
			if !left[id] {
				c.Held = append(c.Held, id)
			}
		}
	}
	warm := map[WireID]bool{}
	for i := 0; i < next.VoiceSet.Len(); i++ {
		warm[next.VoiceSet.At(i).Wire] = true
	}
	for _, class := range []Class{ClassVoice, ClassBulk, ClassVideo} {
		chosen := next.of(class)
		if chosen == AnyWire {
			continue
		}
		warm[chosen] = true
		// The best other wire of another shape, for this class.
		var second WireID = AnyWire
		for _, id := range ids {
			if id == chosen || left[id] || s.wires[id].w.Shape == s.wires[chosen].w.Shape {
				continue
			}
			if class == ClassBulk && !s.wires[id].w.Streams {
				continue
			}
			if second == AnyWire || s.classBetterLocked(class, id, second, now) {
				second = id
			}
		}
		if second != AnyWire {
			warm[second] = true
		}
	}
	for _, id := range ids {
		if warm[id] {
			c.Warm = append(c.Warm, id)
		}
	}
	if len(why) > 0 {
		c.Why = strings.Join(why, "; ")
	}
	return c
}

// pickLocked keeps or moves the wire in slot sl, cur now: ranked are the
// wires that may take it, best first, and better says a beats b by enough to
// take it from b once it stays so for Hold. A wire not among ranked is left
// at once for ranked[0]; with none ranked cur stays (the session falls back
// to any member that can carry the class). It says what moved, "" for
// nothing.
func (s *Selector) pickLocked(sl slot, cur WireID, ranked []WireID, left map[WireID]bool, better func(a, b WireID) bool, now time.Time) (WireID, string) {
	ch := &s.chall[sl]
	switch {
	case len(ranked) == 0:
		ch.wire = AnyWire
		return cur, ""
	case cur == AnyWire || !slices.Contains(ranked, cur):
		ch.wire = AnyWire
		pick := ranked[0]
		if cur != AnyWire && left[cur] {
			return pick, fmt.Sprintf("%s: %s is red, to %s", sl, s.wires[cur].w.Name, s.wires[pick].w.Name)
		}
		return pick, fmt.Sprintf("%s: on %s", sl, s.wires[pick].w.Name)
	case ranked[0] != cur && better(ranked[0], cur):
		if ch.wire != ranked[0] {
			ch.wire, ch.since = ranked[0], now
			return cur, ""
		}
		if now.Sub(ch.since) < s.cfg.Hold {
			return cur, ""
		}
		ch.wire = AnyWire
		return ranked[0], fmt.Sprintf("%s: %s better than %s for %s", sl, s.wires[ranked[0]].w.Name, s.wires[cur].w.Name, s.cfg.Hold)
	}
	ch.wire = AnyWire
	return cur, ""
}

// classBetterLocked ranks a over b for class.
func (s *Selector) classBetterLocked(class Class, a, b WireID, now time.Time) bool {
	switch class {
	case ClassBulk:
		return s.bulkBetterLocked(a, b, now)
	case ClassVideo:
		return s.videoBetterLocked(a, b, now)
	}
	return s.voiceBetterLocked(a, b)
}

func (s *Selector) bulkBetterLocked(a, b WireID, now time.Time) bool {
	return s.bulkLocked(s.wires[a], now).better(s.bulkLocked(s.wires[b], now))
}

// byMarginLocked says a beats b by enough to take bulk from it.
func (s *Selector) byMarginLocked(a, b WireID, now time.Time) bool {
	ba, bb := s.bulkLocked(s.wires[a], now), s.bulkLocked(s.wires[b], now)
	if !ba.known {
		return false
	}
	if !bb.known || ba.failed < bb.failed {
		return true
	}
	return ba.failed == bb.failed && ba.mbps >= bb.mbps*(1+s.cfg.BulkMargin)
}

// SteerEvery is how often Steer chooses.
var SteerEvery = time.Second

// Steered is what a selector steers: the wires as their carrier sees them,
// the carrier's own pauses, and its route. The entry is one (its sessions
// carry the packets); so is the entry's pipe when a pipe carries them
// (pipectl.Pipe).
type Steered interface {
	Wires() map[WireID]WireState
	// LastPause is when the carrier last came back from a pause of its own;
	// zero for none.
	LastPause() time.Time
	Route() Route
	SetRoute(Route)
}

// Steer sets the entry's route from sel every SteerEvery until ctx ends
// (SteerOn the entry).
func (e *Entry) Steer(ctx context.Context, sel *Selector, logf func(string, ...any)) {
	SteerOn(ctx, e, sel, logf)
}

// SteerOn sets t's route from sel every SteerEvery until ctx ends.
// It tells sel of the pauses: the carrier's (t.LastPause) and its own (a
// tick later than two SteerEvery). logf gets a line whenever the route
// changes, one whenever the set of red wires does, and one whenever the set
// of held ones does.
func SteerOn(ctx context.Context, e Steered, sel *Selector, logf func(string, ...any)) {
	t := time.NewTicker(SteerEvery)
	defer t.Stop()
	lastRed, lastHeld := "none", "none"
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// The time we ran, not the time the ticker fired.
			now := time.Now()
			if !last.IsZero() && now.Sub(last) > 2*SteerEvery {
				sel.Paused(now)
			}
			last = now
			if p := e.LastPause(); !p.IsZero() {
				sel.Paused(p)
			}
			c := sel.Choose(now, e.Wires())
			if c.Route != e.Route() {
				e.SetRoute(c.Route)
			}
			if c.Why != "" {
				logf("trunk: route: %s", c.Why)
			}
			if r := sel.names(c.Red); r != lastRed {
				lastRed = r
				logf("trunk: red wires %s", r)
			}
			if h := sel.names(c.Held); h != lastHeld {
				lastHeld = h
				logf("trunk: held red wires %s: this box paused or every wire is red", h)
			}
		}
	}
}

// names are the wires' names joined by ",", "none" for no wire.
func (s *Selector) names(ids []WireID) string {
	if len(ids) == 0 {
		return "none"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if sw := s.wires[id]; sw != nil {
			out = append(out, sw.w.Name)
		} else {
			out = append(out, fmt.Sprint(id))
		}
	}
	return strings.Join(out, ",")
}

// Route is the route the entry gives its sessions.
func (e *Entry) Route() Route {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.route
}

// LastPause is when the entry's current session last came back from a
// pause of its own.
func (e *Entry) LastPause() time.Time { return e.Session().LastPause() }
