package trunk

import (
	"context"
	"encoding/binary"
	"sort"
	"sync"
	"time"
)

// The trunk's own call: what a call between the entry and the exit would
// hear, every second, without a client. The entry sends a small datagram
// every 20 ms on a flow to EchoPort, the exit sends it straight back
// (flows.go), and the entry counts, per minute of the wall clock, how many
// came back, how late, and the pauses between answers a call would hear.
//
// It measures the trunk alone: the leg between the two data centres, its
// members, its pool and the boxes' own pauses, on the session that carries
// clients' flows now (after the exit drains, the new one). A client's call
// crosses the same leg with its own copies (Hikkari v1.02 over both its
// channels): a call with one copy is what one of them gets here, a call with
// two copies is what a client's plain UDP gets.
//
// Calls run side by side tick with one frame number (RunCalls): the call of
// every wire sends frame n at the same moment, so the entry hears any set of
// wires without a datagram more, a frame being heard if it came in time on
// one of them. The exit writes its stamp and map into each answer (echo.go),
// and the entry hears each direction apart, as a listener with a jitter
// buffer would (hearing.go).

// CallConfig shapes a call. Zero fields take the defaults.
type CallConfig struct {
	Copies int           // members per datagram; 0 is DefaultCopies
	Every  time.Duration // one datagram this often; 20 ms, a voice frame
	Size   int           // bytes of each datagram, at least 24 (the exit's stamp and map)
	Window time.Duration // one report per window of the wall clock; a minute
	// Grace is how long after its window an answer still counts. A later
	// one is lost: no call plays a frame two seconds late.
	Grace time.Duration
	// OnWire holds the call to Wire whatever the session's route: the call
	// of one wire, what the selector ranks it by (wires.go). Off, the call
	// follows the route of the voice class.
	OnWire bool
	Wire   WireID
}

const (
	defaultCallEvery  = 20 * time.Millisecond
	defaultCallSize   = 64
	defaultCallWindow = time.Minute
	defaultCallGrace  = 2 * time.Second
	// A pause between answers longer than these is heard: 60 ms is three
	// frames missing, 150 ms a word (the client's diag:voice counts the
	// same, gaps60 and gaps150).
	callGapHeard = 60 * time.Millisecond
	callGapWord  = 150 * time.Millisecond
	// callWorst is how many of a window's longest pauses are kept with their
	// time, to be laid beside the pool's deaths and the boxes' pauses.
	callWorst = 5
)

func (c CallConfig) withDefaults() CallConfig {
	if c.Copies <= 0 {
		c.Copies = DefaultCopies
	}
	if c.Every <= 0 {
		c.Every = defaultCallEvery
	}
	if c.Size < callStamped {
		c.Size = defaultCallSize
	}
	if c.Size > MaxPayload {
		c.Size = MaxPayload
	}
	if c.Window <= 0 {
		c.Window = defaultCallWindow
	}
	if c.Grace <= 0 {
		c.Grace = defaultCallGrace
	}
	return c
}

// CallGap is one pause between answers: when the last answer before it
// came, and how long nothing came.
type CallGap struct {
	At  time.Time
	Len time.Duration
}

// CallWindow is what one window of the call heard.
//
// Sent and Got count the datagrams sent in the window, Got those answered
// within Grace after it; the round trips are theirs. The pauses are between
// answers that arrived in the window, its start and its end counting as
// answers: a pause across the window's end is split between the two windows,
// so Silent adds up, and GapMax and Worst are each window's part of it.
type CallWindow struct {
	Copies   int
	Wire     WireID // the wire the call is held to; AnyWire for a call of the route
	From, To time.Time
	Sent     int
	Got      int
	RTTP50   time.Duration
	RTTP99   time.Duration
	RTTMax   time.Duration
	Gaps60   int           // pauses longer than 60 ms
	Gaps150  int           // pauses longer than 150 ms
	GapMax   time.Duration // the longest pause
	Silent   time.Duration // how much longer than Every the pauses over 60 ms were, in all
	Worst    []CallGap     // the longest pauses over 60 ms, longest first
	Sessions int           // sessions the call used in the window (a drain of the exit moves it)
	// Up and Down are what a listener at the exit and one at the entry
	// heard of the frames sent in the window (hearing.go).
	Up, Down CallHearing
}

// Lost is how many datagrams of the window got no answer in time.
func (w CallWindow) Lost() int { return w.Sent - w.Got }

// callBucket is one window being filled.
type callBucket struct {
	from, to time.Time
	sent     int
	got      int
	rtts     []time.Duration
	arrivals []time.Time
	sessions map[CallCarrier]bool
	last     CallCarrier // the carrier of the last send, to skip the map
	closed   bool        // reported: its datagrams' answers no longer count
}

// callSent is one datagram sent and not yet past its window's Grace.
type callSent struct {
	at       time.Time
	b        *callBucket // its window; nil for a seq never sent
	answered bool
	// had is the exit having had it, by its answer or by the map of a
	// later one; exit is the exit's stamp of it and back when its answer
	// came, unix ns of each end's wall clock, 0 for none (echo.go).
	had        bool
	exit, back int64
	// sets has bit k for each set k of RunCalls the call's wire was in when
	// the datagram went, lead for each the wire was the first of.
	sets, lead uint8
}

// call is a running call's state, shared by its sender and the answers.
//
// The datagrams sent are a ring in seq order (the sender numbers them one
// after another), so an answer finds its datagram by its seq, and a tick only
// looks at the windows still open (two or three) and drops from the ring's
// head what their reports took: no tick walks the minute of datagrams sent.
type call struct {
	cfg   CallConfig
	start time.Time

	mu      sync.Mutex
	buckets []*callBucket // the open windows, oldest first
	ring    []callSent    // a power of two long
	head    int           // the oldest datagram's place in ring
	n       int           // datagrams in ring
	base    uint64        // the oldest datagram's seq
}

func newCall(cfg CallConfig, start time.Time) *call {
	return &call{cfg: cfg, start: start, ring: make([]callSent, 64)}
}

// CallCarrier carries a call's datagrams to the exit's echo and back: the
// entry's session, or the entry's pipe when a pipe carries the packets
// (pipectl).
type CallCarrier interface {
	// OpenCallFlow opens a flow to EchoPort with o; deliver gets each
	// answer.
	OpenCallFlow(o FlowOptions, deliver func([]byte)) CallFlow
}

// CallFlow is a call's flow: Send is false once the flow has ended.
type CallFlow interface {
	Send(p []byte) bool
	Close()
}

// OpenCallFlow is the call's flow on this session.
func (s *Session) OpenCallFlow(o FlowOptions, deliver func([]byte)) CallFlow {
	return s.OpenFlowWith(EchoPort, o, deliver, nil)
}

// RunCall keeps a call going on the session session gives (the entry's
// current one, Entry.Session) until ctx ends, and gives report every window
// once its Grace is over. report runs on the call's own goroutine.
func RunCall(ctx context.Context, session func() *Session, cfg CallConfig, report func(CallWindow)) {
	RunCallOn(ctx, func() CallCarrier { return session() }, cfg, report)
}

// RunCallOn is RunCall on any carrier: carrier gives the current one, and a
// new one is a new flow, counted in the window's Sessions.
func RunCallOn(ctx context.Context, carrier func() CallCarrier, cfg CallConfig, report func(CallWindow)) {
	RunCalls(ctx, carrier, []CallConfig{cfg}, nil, CallReports{Leg: func(_ int, w CallWindow) { report(w) }})
}

// CallSet is a set of wires a listener hears as one: a frame is heard if it
// came in time on one of them (the voice class over two fates, hikkari-client
// plans/2026-11-15-live-udp-two-fates.md).
type CallSet struct {
	Name string
	// Wires is the set at the moment, asked every frame; a wire without a
	// call held to it among the calls of RunCalls is not heard. The others'
	// lag is measured behind the first (CallSetWindow).
	Wires func() []WireID
}

// CallReports takes what RunCalls hears: Leg each call's window by its
// place in the calls given, Set each set's, Second each second of each set
// and of each call pinned to a wire (second.go). All run on the calls' own
// goroutine; any may be nil.
type CallReports struct {
	Leg    func(i int, w CallWindow)
	Set    func(w CallSetWindow)
	Second func(s CallSecond)
}

// maxCallSets is how many sets RunCalls hears (a bit of callSent's sets each).
const maxCallSets = 8

// callLeg is one call of RunCalls on its current carrier.
type callLeg struct {
	cfg     CallConfig
	c       *call
	cur     CallCarrier
	flow    CallFlow
	payload []byte
}

// send sends frame seq on carrier s, opening the call's flow anew on a new
// carrier or after the last one ended.
func (l *callLeg) send(s CallCarrier, seq uint64, now time.Time, sets, lead uint8) {
	if s != l.cur || l.flow == nil {
		if l.flow != nil {
			l.flow.Close()
		}
		l.cur = s
		o := FlowOptions{Copies: l.cfg.Copies, Class: ClassVoice, Pin: AnyWire}
		if l.cfg.OnWire {
			o.Pin = l.cfg.Wire
		}
		l.flow = s.OpenCallFlow(o, l.c.answer)
	}
	binary.BigEndian.PutUint64(l.payload, seq)
	l.c.sentIn(seq, now, s, sets, lead)
	if !l.flow.Send(l.payload) {
		// The flow ended (the exit restarted under the session, or the
		// session closed): this datagram is lost, the next opens anew.
		l.flow = nil
	}
}

// RunCalls keeps calls going side by side on one ticker until ctx ends: each
// of legs sends frame n at the same moment (legs[0] gives Every, Window and
// Grace to all), and each of sets (at most 8) is heard from the calls held
// to its wires. carrier gives the current carrier, as for RunCallOn.
func RunCalls(ctx context.Context, carrier func() CallCarrier, legs []CallConfig, sets []CallSet, rep CallReports) {
	if len(legs) == 0 {
		return
	}
	sets = sets[:min(len(sets), maxCallSets)]
	g := &callGroup{sets: sets}
	ls := make([]callLeg, len(legs))
	start := time.Now()
	for i, cfg := range legs {
		cfg = cfg.withDefaults()
		if i > 0 {
			cfg.Every, cfg.Window, cfg.Grace = ls[0].cfg.Every, ls[0].cfg.Window, ls[0].cfg.Grace
		}
		ls[i] = callLeg{cfg: cfg, c: newCall(cfg, start), payload: make([]byte, cfg.Size)}
		g.legs = append(g.legs, ls[i].c)
	}
	defer func() {
		for _, l := range ls {
			if l.flow != nil {
				l.flow.Close()
			}
		}
	}()
	t := time.NewTicker(ls[0].cfg.Every)
	defer t.Stop()
	var seq uint64
	in, lead := make([]uint8, len(ls)), make([]uint8, len(ls))
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			g.members(in, lead)
			s := carrier()
			seq++
			for i := range ls {
				ls[i].send(s, seq, now, in[i], lead[i])
			}
			legWs, setWs := g.due(now)
			for i, ws := range legWs {
				for _, w := range ws {
					if rep.Leg != nil {
						rep.Leg(i, w)
					}
				}
			}
			for _, w := range setWs {
				if rep.Set != nil {
					rep.Set(w)
				}
			}
			if rep.Second != nil {
				for _, sec := range g.seconds(now) {
					rep.Second(sec)
				}
			}
		}
	}
}

// bucketLocked is the open window at falls in, opened if there is none.
func (c *call) bucketLocked(at time.Time) *callBucket {
	for i := len(c.buckets) - 1; i >= 0; i-- {
		if b := c.buckets[i]; !at.Before(b.from) && at.Before(b.to) {
			return b
		}
	}
	from := at.Truncate(c.cfg.Window)
	per := min(int(c.cfg.Window/c.cfg.Every)+1, 1<<14)
	b := &callBucket{from: from, to: from.Add(c.cfg.Window), sessions: map[CallCarrier]bool{},
		rtts: make([]time.Duration, 0, per), arrivals: make([]time.Time, 0, per)}
	i := len(c.buckets)
	for i > 0 && c.buckets[i-1].from.After(from) {
		i--
	}
	c.buckets = append(c.buckets, nil)
	copy(c.buckets[i+1:], c.buckets[i:])
	c.buckets[i] = b
	return b
}

// slot is seq's place in the ring, if it is there.
func (c *call) slot(seq uint64) *callSent {
	if seq < c.base || seq-c.base >= uint64(c.n) {
		return nil
	}
	return &c.ring[(c.head+int(seq-c.base))&(len(c.ring)-1)]
}

// push adds one datagram at the ring's tail, growing it when full.
func (c *call) push(r callSent) {
	if c.n == len(c.ring) {
		grown := make([]callSent, 2*len(c.ring))
		for i := 0; i < c.n; i++ {
			grown[i] = c.ring[(c.head+i)&(len(c.ring)-1)]
		}
		c.ring, c.head = grown, 0
	}
	c.ring[(c.head+c.n)&(len(c.ring)-1)] = r
	c.n++
}

func (c *call) sent(seq uint64, at time.Time, s CallCarrier) { c.sentIn(seq, at, s, 0, 0) }

// sentIn notes datagram seq sent at at on s, its wire in the sets of sets
// and the first of those of lead.
func (c *call) sentIn(seq uint64, at time.Time, s CallCarrier, sets, lead uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.bucketLocked(at)
	b.sent++
	if b.last != s || len(b.sessions) == 0 {
		b.sessions[s] = true
		b.last = s
	}
	if c.n == 0 {
		c.base = seq
	}
	switch {
	case seq < c.base:
		// Older than every datagram kept: RunCall never numbers back.
	case seq-c.base < uint64(c.n):
		r := c.slot(seq)
		r.at, r.b, r.sets, r.lead = at, b, sets, lead
	default:
		for c.base+uint64(c.n) < seq {
			c.push(callSent{}) // a seq skipped: nothing was sent under it
		}
		c.push(callSent{at: at, b: b, sets: sets, lead: lead})
	}
}

// answer takes one datagram back. It runs with the session locked (a flow's
// deliver), so it only notes it.
func (c *call) answer(p []byte) { c.answerAt(time.Now(), p) }

func (c *call) answerAt(now time.Time, p []byte) {
	if len(p) < 8 {
		return
	}
	seq := binary.BigEndian.Uint64(p)
	var exit int64
	var bits uint64
	if len(p) >= callStamped {
		exit = int64(binary.BigEndian.Uint64(p[callStampAt:]))
		bits = binary.BigEndian.Uint64(p[callMapAt:])
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if exit != 0 {
		// The exit's map: the frames before this one it has had, whose
		// answers may be lost on the way down.
		for i := uint64(1); i < 64 && i < seq; i++ {
			if bits&(1<<i) == 0 {
				continue
			}
			if q := c.slot(seq - i); q != nil && q.b != nil && !q.b.closed {
				q.had = true
			}
		}
	}
	r := c.slot(seq)
	if r == nil || r.b == nil || r.b.closed || r.answered {
		return // a window already reported, or a copy the replay window let by
	}
	r.answered = true
	if exit != 0 {
		r.had, r.exit, r.back = true, exit, now.UnixNano()
	}
	r.b.got++
	r.b.rtts = append(r.b.rtts, now.Sub(r.at))
	ab := c.bucketLocked(now)
	ab.arrivals = append(ab.arrivals, now)
}

// due takes the windows whose Grace is over.
func (c *call) due(now time.Time) []CallWindow {
	c.mu.Lock()
	defer c.mu.Unlock()
	done := c.closeLocked(now)
	if done == nil {
		return nil
	}
	out := c.windowsLocked(done)
	c.dropLocked()
	return out
}

// closeLocked closes the windows whose Grace is over, oldest first: their
// datagrams' answers no longer count.
func (c *call) closeLocked(now time.Time) []*callBucket {
	var done []*callBucket
	open := c.buckets[:0]
	for _, b := range c.buckets {
		if now.Sub(b.to) >= c.cfg.Grace {
			b.closed = true
			done = append(done, b)
		} else {
			open = append(open, b)
		}
	}
	for i := len(open); i < len(c.buckets); i++ {
		c.buckets[i] = nil
	}
	c.buckets = open
	sort.Slice(done, func(i, j int) bool { return done[i].from.Before(done[j].from) })
	return done
}

// windowsLocked is what the closed windows done heard, their datagrams still
// in the ring.
func (c *call) windowsLocked(done []*callBucket) []CallWindow {
	out := make([]CallWindow, 0, len(done))
	for _, b := range done {
		// A window the call did not cover from its start (it started, or
		// the box slept) is still reported: its pauses start at the call's
		// first datagram, not before.
		from := b.from
		if c.start.After(from) {
			from = c.start
		}
		w := c.cfg.window(b, from)
		var frames []heardFrame
		for i := 0; i < c.n; i++ {
			if r := &c.ring[(c.head+i)&(len(c.ring)-1)]; r.b == b {
				frames = append(frames, heardFrame{at: r.at, legs: []*callSent{r}, lead: -1})
			}
		}
		h := hear(frames)
		w.Up, w.Down = h.up, h.down
		out = append(out, w)
	}
	return out
}

// dropLocked takes the datagrams of the windows reported from the ring's
// head. A wall clock set back can leave a later window's datagrams before an
// earlier one's: those stay until the head goes, and their answers do not
// count, their window being closed.
func (c *call) dropLocked() {
	for c.n > 0 {
		r := &c.ring[c.head]
		if r.b != nil && !r.b.closed {
			break
		}
		*r = callSent{}
		c.head = (c.head + 1) & (len(c.ring) - 1)
		c.n--
		c.base++
	}
}

func (cfg CallConfig) window(b *callBucket, from time.Time) CallWindow {
	w := CallWindow{Copies: cfg.Copies, Wire: AnyWire, From: b.from, To: b.to, Sent: b.sent, Got: b.got, Sessions: len(b.sessions)}
	if cfg.OnWire {
		w.Wire = cfg.Wire
	}
	if len(b.rtts) > 0 {
		sort.Slice(b.rtts, func(i, j int) bool { return b.rtts[i] < b.rtts[j] })
		w.RTTP50 = quantile(b.rtts, 50)
		w.RTTP99 = quantile(b.rtts, 99)
		w.RTTMax = b.rtts[len(b.rtts)-1]
	}
	sort.Slice(b.arrivals, func(i, j int) bool { return b.arrivals[i].Before(b.arrivals[j]) })
	points := append(append([]time.Time{from}, b.arrivals...), b.to)
	for i := 1; i < len(points); i++ {
		gap := points[i].Sub(points[i-1])
		if gap > w.GapMax {
			w.GapMax = gap
		}
		if gap <= callGapHeard {
			continue
		}
		w.Gaps60++
		if gap > callGapWord {
			w.Gaps150++
		}
		w.Silent += gap - cfg.Every
		w.Worst = append(w.Worst, CallGap{At: points[i-1], Len: gap})
	}
	sort.Slice(w.Worst, func(i, j int) bool { return w.Worst[i].Len > w.Worst[j].Len })
	if len(w.Worst) > callWorst {
		w.Worst = w.Worst[:callWorst]
	}
	return w
}

// quantile is the q-th percentile of sorted durations.
func quantile(sorted []time.Duration, q int) time.Duration {
	i := (len(sorted)*q + 99) / 100
	if i < 1 {
		i = 1
	}
	return sorted[i-1]
}
