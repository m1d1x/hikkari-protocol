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

// CallConfig shapes a call. Zero fields take the defaults.
type CallConfig struct {
	Copies int           // members per datagram; 0 is DefaultCopies
	Every  time.Duration // one datagram this often; 20 ms, a voice frame
	Size   int           // bytes of each datagram, at least 16
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
	if c.Size < 16 {
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
	sessions map[*Session]bool
	last     *Session // the session of the last send, to skip the map
	closed   bool     // reported: its datagrams' answers no longer count
}

// callSent is one datagram sent and not yet past its window's Grace.
type callSent struct {
	at       time.Time
	b        *callBucket // its window; nil for a seq never sent
	answered bool
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

// RunCall keeps a call going on the session session gives (the entry's
// current one, Entry.Session) until ctx ends, and gives report every window
// once its Grace is over. report runs on the call's own goroutine.
func RunCall(ctx context.Context, session func() *Session, cfg CallConfig, report func(CallWindow)) {
	cfg = cfg.withDefaults()
	c := newCall(cfg, time.Now())
	var (
		cur  *Session
		flow *Flow
		seq  uint64
	)
	defer func() {
		if flow != nil {
			flow.Close()
		}
	}()
	t := time.NewTicker(cfg.Every)
	defer t.Stop()
	payload := make([]byte, cfg.Size)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if s := session(); s != cur || flow == nil {
				if flow != nil {
					flow.Close()
				}
				cur = s
				o := FlowOptions{Copies: cfg.Copies, Class: ClassVoice, Pin: AnyWire}
				if cfg.OnWire {
					o.Pin = cfg.Wire
				}
				flow = s.OpenFlowWith(EchoPort, o, c.answer, nil)
			}
			seq++
			binary.BigEndian.PutUint64(payload, seq)
			c.sent(seq, now, cur)
			if !flow.Send(payload) {
				// The flow ended (the exit restarted under the session, or the
				// session closed): this datagram is lost, the next opens anew.
				flow = nil
			}
			for _, w := range c.due(now) {
				report(w)
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
	b := &callBucket{from: from, to: from.Add(c.cfg.Window), sessions: map[*Session]bool{},
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

func (c *call) sent(seq uint64, at time.Time, s *Session) {
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
		r.at, r.b = at, b
	default:
		for c.base+uint64(c.n) < seq {
			c.push(callSent{}) // a seq skipped: nothing was sent under it
		}
		c.push(callSent{at: at, b: b})
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
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.slot(seq)
	if r == nil || r.b == nil || r.b.closed || r.answered {
		return // a window already reported, or a copy the replay window let by
	}
	r.answered = true
	r.b.got++
	r.b.rtts = append(r.b.rtts, now.Sub(r.at))
	ab := c.bucketLocked(now)
	ab.arrivals = append(ab.arrivals, now)
}

// due takes the windows whose Grace is over.
func (c *call) due(now time.Time) []CallWindow {
	c.mu.Lock()
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
	if done == nil {
		c.mu.Unlock()
		return nil
	}
	// The datagrams of the windows reported leave from the ring's head. A
	// wall clock set back can leave a later window's datagrams before an
	// earlier one's: those stay until the head goes, and their answers do
	// not count, their window being closed.
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
	c.mu.Unlock()
	sort.Slice(done, func(i, j int) bool { return done[i].from.Before(done[j].from) })
	out := make([]CallWindow, 0, len(done))
	for _, b := range done {
		// A window the call did not cover from its start (it started, or
		// the box slept) is still reported: its pauses start at the call's
		// first datagram, not before.
		from := b.from
		if c.start.After(from) {
			from = c.start
		}
		out = append(out, c.cfg.window(b, from))
	}
	return out
}

func (cfg CallConfig) window(b *callBucket, from time.Time) CallWindow {
	w := CallWindow{Copies: cfg.Copies, From: b.from, To: b.to, Sent: b.sent, Got: b.got, Sessions: len(b.sessions)}
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
