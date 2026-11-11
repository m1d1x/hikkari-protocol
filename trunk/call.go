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
}

// call is a running call's state, shared by its sender and the answers.
type call struct {
	cfg   CallConfig
	start time.Time

	mu      sync.Mutex
	buckets map[time.Time]*callBucket
	answers map[uint64]bool // seqs answered, of the windows still open
	sentAt  map[uint64]time.Time
}

// RunCall keeps a call going on the session session gives (the entry's
// current one, Entry.Session) until ctx ends, and gives report every window
// once its Grace is over. report runs on the call's own goroutine.
func RunCall(ctx context.Context, session func() *Session, cfg CallConfig, report func(CallWindow)) {
	cfg = cfg.withDefaults()
	c := &call{cfg: cfg, start: time.Now(), buckets: map[time.Time]*callBucket{}, answers: map[uint64]bool{}, sentAt: map[uint64]time.Time{}}
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

func (c *call) bucketLocked(at time.Time) *callBucket {
	from := at.Truncate(c.cfg.Window)
	b := c.buckets[from]
	if b == nil {
		b = &callBucket{from: from, to: from.Add(c.cfg.Window), sessions: map[*Session]bool{}}
		c.buckets[from] = b
	}
	return b
}

func (c *call) sent(seq uint64, at time.Time, s *Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.bucketLocked(at)
	b.sent++
	b.sessions[s] = true
	c.sentAt[seq] = at
}

// answer takes one datagram back. It runs with the session locked (a flow's
// deliver), so it only notes it.
func (c *call) answer(p []byte) {
	now := time.Now()
	if len(p) < 8 {
		return
	}
	seq := binary.BigEndian.Uint64(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.sentAt[seq]
	if !ok || c.answers[seq] {
		return // a window already reported, or a copy the replay window let by
	}
	c.answers[seq] = true
	if sb := c.buckets[at.Truncate(c.cfg.Window)]; sb != nil {
		sb.got++
		sb.rtts = append(sb.rtts, now.Sub(at))
	}
	ab := c.bucketLocked(now)
	ab.arrivals = append(ab.arrivals, now)
}

// due takes the windows whose Grace is over.
func (c *call) due(now time.Time) []CallWindow {
	c.mu.Lock()
	var done []*callBucket
	for from, b := range c.buckets {
		if now.Sub(b.to) >= c.cfg.Grace {
			done = append(done, b)
			delete(c.buckets, from)
		}
	}
	for seq, at := range c.sentAt {
		if now.Sub(at.Truncate(c.cfg.Window).Add(c.cfg.Window)) >= c.cfg.Grace {
			delete(c.sentAt, seq)
			delete(c.answers, seq)
		}
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
