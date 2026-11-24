package client

// The health of a client's entries (v1.07, spec/v1.md "Ping" and "Alive,
// silent, active"): a probe carrier on every entry's stream channel pings the
// relay every PingEvery; an entry nothing came back from for EntrySilence is
// silent, and the first answer makes it alive again. New connections take the
// first entry alive.

import (
	"context"
	"crypto/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/observe"
)

const (
	// EntrySilence is how long an entry may not answer before new
	// connections leave it: as the trunk's entry leaves a silent receiver
	// (P4) and the entry a silent country (24.11).
	EntrySilence = 1500 * time.Millisecond
	// PingEvery is the probe's pace: six pings fit in EntrySilence, so one
	// late answer never makes an entry silent.
	PingEvery = 250 * time.Millisecond
	// pingRedial is the pause before a failed probe carrier is dialed again.
	pingRedial = 500 * time.Millisecond
	// healthTick is how often the entries' states are judged for logs and
	// periods; Active judges on its own at every call.
	healthTick = 100 * time.Millisecond
	// pingSlots bounds the pings in flight a round trip is measured for.
	pingSlots = 64
)

type health struct {
	c   *Client
	ctx context.Context

	mu      sync.Mutex
	start   time.Time
	heard   []time.Time // last answer by entry
	anyever bool        // some entry has answered: the relay knows pings
	// What the watcher saw at its last tick.
	silent []bool
	since  []time.Time // when the entry went silent
	shown  int         // the active entry
	tick   time.Time
	counts []observe.Entry // since the book's last take
}

func startHealth(ctx context.Context, c *Client) *health {
	if ctx == nil {
		ctx = context.Background()
	}
	n := len(c.paths)
	now := time.Now()
	h := &health{c: c, ctx: ctx, start: now, tick: now,
		heard: make([]time.Time, n), silent: make([]bool, n), since: make([]time.Time, n), counts: make([]observe.Entry, n)}
	unbook := c.opts.Book.Add(Group, h.take)
	context.AfterFunc(ctx, unbook)
	for i := range c.paths {
		go h.probe(i)
	}
	go h.watch()
	return h
}

// silentAt reports whether entry i is silent at now; h.mu is held.
func (h *health) silentAt(i int, now time.Time) bool {
	if !h.anyever {
		return false
	}
	last := h.heard[i]
	if last.IsZero() {
		last = h.start
	}
	return now.Sub(last) > EntrySilence
}

// activeLocked is the first entry alive; with all silent, the one heard last.
func (h *health) activeLocked(now time.Time) int {
	for i := range h.heard {
		if !h.silentAt(i, now) {
			return i
		}
	}
	best := 0
	for i, t := range h.heard {
		if t.After(h.heard[best]) {
			best = i
		}
	}
	return best
}

func (h *health) active(now time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.activeLocked(now)
}

// answer records a ping of entry i that came back after rtt.
func (h *health) answer(i int, now time.Time, rtt time.Duration) {
	h.mu.Lock()
	h.heard[i] = now
	h.anyever = true
	h.counts[i].PingMS.Add(float64(rtt) / float64(time.Millisecond))
	h.mu.Unlock()
}

// watch judges the entries every healthTick: it logs an entry going silent or
// coming back and counts the seconds of each state.
func (h *health) watch() {
	t := time.NewTicker(healthTick)
	defer t.Stop()
	for {
		select {
		case <-h.ctx.Done():
			return
		case now := <-t.C:
			h.judge(now)
		}
	}
}

func (h *health) judge(now time.Time) {
	log := h.c.opts.Logger
	h.mu.Lock()
	dt := now.Sub(h.tick).Seconds()
	h.tick = now
	active := h.activeLocked(now)
	h.counts[h.shown].ActiveS += dt
	type change struct {
		i      int
		silent bool
		for_   time.Duration
	}
	var changes []change
	for i := range h.heard {
		if h.silent[i] {
			h.counts[i].SilentS += dt
		}
		s := h.silentAt(i, now)
		if s == h.silent[i] {
			continue
		}
		h.silent[i] = s
		if s {
			h.since[i] = now
			h.counts[i].Silences++
			changes = append(changes, change{i, true, 0})
		} else {
			changes = append(changes, change{i, false, now.Sub(h.since[i])})
		}
	}
	moved := active != h.shown
	h.shown = active
	h.mu.Unlock()
	for _, ch := range changes {
		if ch.silent {
			log.WarnContext(h.ctx, "entry ", ch.i, ": silent for ", EntrySilence, ", new connections go by entry ", active)
		} else {
			log.InfoContext(h.ctx, "entry ", ch.i, ": answers again after ", ch.for_.Round(time.Millisecond), " silent")
		}
	}
	if moved && len(changes) == 0 {
		log.InfoContext(h.ctx, "entry ", active, ": new connections go by it")
	}
}

// take adds the entries' period to p; the Book calls it.
func (h *health) take(p *observe.Period) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p.Entries == nil {
		p.Entries = map[string]*observe.Entry{}
	}
	for i := range h.counts {
		e := h.counts[i]
		if i == h.shown {
			e.Now = 1
		}
		n := strconv.Itoa(i)
		if p.Entries[n] == nil {
			p.Entries[n] = &observe.Entry{}
		}
		p.Entries[n].Merge(&e)
		h.counts[i] = observe.Entry{}
	}
}

// probe keeps a probe carrier on entry i's stream channel for the client's
// life, dialing it again pingRedial after it fails.
func (h *health) probe(i int) {
	var id dup.Session
	_, _ = rand.Read(id[:])
	var seq uint64
	for h.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(h.ctx, h.c.opts.ConnectTimeout)
		conn, err := h.c.paths[i].Stream.DialContext(ctx, "tcp", dup.HostAddr())
		cancel()
		if err == nil {
			h.ping(i, conn, id, &seq)
		}
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(pingRedial):
		}
	}
}

// ping sends a ping every PingEvery on conn and records the answers, until
// conn fails or the client's context ends.
func (h *health) ping(i int, conn net.Conn, id dup.Session, seq *uint64) {
	defer conn.Close()
	stop := context.AfterFunc(h.ctx, func() { _ = conn.Close() })
	defer stop()
	var sentMu sync.Mutex
	var sent [pingSlots]struct {
		seq uint64
		at  time.Time
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, dup.MaxFrame)
		for {
			data, err := dup.ReadStream(conn, b)
			if err != nil {
				return
			}
			f, err := dup.Decode(data)
			if err != nil || f.Kind != dup.KindPing || f.Session != id {
				continue
			}
			now := time.Now()
			sentMu.Lock()
			slot := sent[f.Seq%pingSlots]
			sentMu.Unlock()
			rtt := time.Duration(0)
			if slot.seq == f.Seq {
				rtt = now.Sub(slot.at)
			}
			h.answer(i, now, rtt)
		}
	}()
	t := time.NewTicker(PingEvery)
	defer t.Stop()
	for {
		*seq++
		frame, _ := dup.Append(nil, dup.Frame{Kind: dup.KindPing, Session: id, Seq: *seq})
		sentMu.Lock()
		sent[*seq%pingSlots].seq, sent[*seq%pingSlots].at = *seq, time.Now()
		sentMu.Unlock()
		if dup.WriteStream(conn, frame) != nil {
			return
		}
		select {
		case <-done:
			return
		case <-t.C:
		}
	}
}

// silent reports whether entry i is silent now; always false with one entry.
func (c *Client) silent(i int) bool {
	if c.health == nil {
		return false
	}
	c.health.mu.Lock()
	defer c.health.mu.Unlock()
	return c.health.silentAt(i, time.Now())
}
