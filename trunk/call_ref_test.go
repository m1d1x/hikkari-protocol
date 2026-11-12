package trunk

import (
	"encoding/binary"
	"sort"
	"time"
)

// refCall is the call's bookkeeping as it was before the ring (hikkari-protocol
// 2221e46): a map of every datagram sent in the open windows, walked on every
// tick. Kept as the reference the ring must agree with.
type refCall struct {
	cfg     CallConfig
	start   time.Time
	buckets map[time.Time]*callBucket
	answers map[uint64]bool
	sentAt  map[uint64]time.Time
}

func newRefCall(cfg CallConfig, start time.Time) *refCall {
	return &refCall{cfg: cfg, start: start, buckets: map[time.Time]*callBucket{}, answers: map[uint64]bool{}, sentAt: map[uint64]time.Time{}}
}

func (c *refCall) bucket(at time.Time) *callBucket {
	from := at.Truncate(c.cfg.Window)
	b := c.buckets[from]
	if b == nil {
		b = &callBucket{from: from, to: from.Add(c.cfg.Window), sessions: map[*Session]bool{}}
		c.buckets[from] = b
	}
	return b
}

func (c *refCall) sent(seq uint64, at time.Time, s *Session) {
	b := c.bucket(at)
	b.sent++
	b.sessions[s] = true
	c.sentAt[seq] = at
}

func (c *refCall) answerAt(now time.Time, p []byte) {
	if len(p) < 8 {
		return
	}
	seq := binary.BigEndian.Uint64(p)
	at, ok := c.sentAt[seq]
	if !ok || c.answers[seq] {
		return
	}
	c.answers[seq] = true
	if sb := c.buckets[at.Truncate(c.cfg.Window)]; sb != nil {
		sb.got++
		sb.rtts = append(sb.rtts, now.Sub(at))
	}
	ab := c.bucket(now)
	ab.arrivals = append(ab.arrivals, now)
}

func (c *refCall) due(now time.Time) []CallWindow {
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
	sort.Slice(done, func(i, j int) bool { return done[i].from.Before(done[j].from) })
	out := make([]CallWindow, 0, len(done))
	for _, b := range done {
		from := b.from
		if c.start.After(from) {
			from = c.start
		}
		out = append(out, c.cfg.window(b, from))
	}
	return out
}
