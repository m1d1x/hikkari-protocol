package client

// The health of a client's entries (v1.07 and v1.08, spec/v1.md "Ping",
// "Alive, silent, active", "v1.08: the best entry"): a probe carrier on every
// entry's stream channel and one on its datagram channel ping the relay every
// PingEvery. An entry nothing came back from on its stream probe for
// EntrySilence is silent and is left at once; the first answer makes it alive
// again. Among the alive entries new connections take the best one by the
// pings of the last minute (entryjudge.go), held there against small swings.

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
	// periods; Active judges silence on its own at every call.
	healthTick = 100 * time.Millisecond
	// scoreEvery is how often the entries are scored and compared.
	scoreEvery = time.Second

	// A better entry takes new connections when its scores are lower than
	// the active one's by moveGain for moveHold on end, and the last move was
	// moveCoolDown ago (spec/v1.md "Moving to a better entry"). Two sound
	// entries differ by a few late pings, each worth 4 ms in a full window:
	// moveGain is ten of them, held for a quarter of the window.
	moveGain     = 40 * time.Millisecond
	moveHold     = 30 * time.Second
	moveCoolDown = 60 * time.Second
)

// fate names the carrier a probe pings on.
type fate int

const (
	fateStream fate = iota
	fateDatagram
)

type health struct {
	c   *Client
	ctx context.Context

	mu      sync.Mutex
	start   time.Time
	heard   []time.Time // last answer by entry on the stream probe
	anyever bool        // some entry has answered: the relay knows pings
	logs    [][2]pingLog
	dgramOK []bool         // the datagram probe has answered once
	fates   [][2]fateScore // each entry's fates at the last scoring
	// The entry new connections take, and since when another one beats it.
	chosen     int
	lastMove   time.Time
	rival      int
	rivalSince time.Time
	// What the watcher saw at its last tick.
	silent    []bool
	since     []time.Time // when the entry went silent
	shown     int         // the active entry
	tick      time.Time
	lastScore time.Time
	counts    []observe.Entry // since the book's last take
}

func startHealth(ctx context.Context, c *Client) *health {
	if ctx == nil {
		ctx = context.Background()
	}
	n := len(c.paths)
	now := time.Now()
	h := &health{c: c, ctx: ctx, start: now, tick: now, lastScore: now,
		heard: make([]time.Time, n), logs: make([][2]pingLog, n), dgramOK: make([]bool, n),
		fates:  make([][2]fateScore, n),
		silent: make([]bool, n), since: make([]time.Time, n), counts: make([]observe.Entry, n)}
	unbook := c.opts.Book.Add(Group, h.take)
	context.AfterFunc(ctx, unbook)
	for i, p := range c.paths {
		go h.probeStream(i)
		if p.Datagram != nil {
			go h.probeDatagram(i)
		}
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

// better reports whether entry i is a better choice than entry j: the lower
// scores where both are scored, else the one scored, else the lower number.
func (h *health) better(i, j int) bool {
	if g, ok := gain(h.fates[j], h.fates[i]); ok && g != 0 {
		return g > 0
	}
	if si, sj := h.fates[i][fateStream].ok, h.fates[j][fateStream].ok; si != sj {
		return si
	}
	return i < j
}

// activeLocked is the chosen entry while it is alive. A silent chosen entry
// gives way at once to the best alive one; with all silent, to the one heard
// last. h.mu is held.
func (h *health) activeLocked(now time.Time) int {
	if !h.silentAt(h.chosen, now) {
		return h.chosen
	}
	next := -1
	for i := range h.heard {
		if !h.silentAt(i, now) && (next < 0 || h.better(i, next)) {
			next = i
		}
	}
	if next < 0 {
		next = h.chosen
		for i, t := range h.heard {
			if t.After(h.heard[next]) {
				next = i
			}
		}
	}
	if next != h.chosen {
		h.chosen, h.lastMove = next, now
		h.rivalSince = time.Time{}
		h.counts[next].MovesSilence++
	}
	return h.chosen
}

func (h *health) active(now time.Time) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.activeLocked(now)
}

// sent records ping seq going out on entry i's fate f.
func (h *health) sent(i int, f fate, seq uint64, now time.Time) {
	h.mu.Lock()
	h.logs[i][f].sent(seq, now)
	h.mu.Unlock()
}

// answer records the answer to ping seq of entry i's fate f.
func (h *health) answer(i int, f fate, seq uint64, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	rtt, ok := h.logs[i][f].answered(seq, now)
	ms := float64(rtt) / float64(time.Millisecond)
	switch f {
	case fateStream:
		h.heard[i] = now
		h.anyever = true
		if ok {
			h.counts[i].PingMS.Add(ms)
		}
	case fateDatagram:
		h.dgramOK[i] = true
		if ok {
			h.counts[i].DgramPingMS.Add(ms)
		}
	}
}

// watch judges the entries every healthTick: it logs an entry going silent or
// coming back, scores the entries every scoreEvery and counts the seconds of
// each state.
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

// change is an entry going silent or answering again.
type change struct {
	i      int
	silent bool
	for_   time.Duration
}

func (h *health) judge(now time.Time) {
	log := h.c.opts.Logger
	h.mu.Lock()
	dt := now.Sub(h.tick).Seconds()
	h.tick = now
	var moved *qualityMove
	if now.Sub(h.lastScore) >= scoreEvery {
		h.lastScore = now
		moved = h.scoreLocked(now)
	}
	active := h.activeLocked(now)
	h.counts[h.shown].ActiveS += dt
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
	shifted := active != h.shown
	h.shown = active
	h.mu.Unlock()
	for _, ch := range changes {
		if ch.silent {
			log.WarnContext(h.ctx, "entry ", ch.i, ": silent for ", EntrySilence, ", new connections go by entry ", active)
		} else {
			log.InfoContext(h.ctx, "entry ", ch.i, ": answers again after ", ch.for_.Round(time.Millisecond), " silent")
		}
	}
	switch {
	case moved != nil:
		log.InfoContext(h.ctx, "entry ", moved.to, ": new connections go by it, its path ", ms(moved.gain),
			" better than entry ", moved.from, "'s for ", moveHold)
	case shifted && len(changes) == 0:
		log.InfoContext(h.ctx, "entry ", active, ": new connections go by it")
	}
}

// qualityMove is the chosen entry giving way to a better one.
type qualityMove struct {
	from, to int
	gain     time.Duration
}

// scoreLocked scores every entry and moves new connections to a better one
// that has held its lead for moveHold (spec/v1.md "Moving to a better
// entry"). h.mu is held.
func (h *health) scoreLocked(now time.Time) *qualityMove {
	for i := range h.logs {
		s := h.logs[i][fateStream].judge(now, lateOverStream)
		var d fateScore
		if h.dgramOK[i] {
			d = h.logs[i][fateDatagram].judge(now, lateOverDatagram)
			if !h.c.datagramUp(i) {
				// UDP of this entry goes over its stream channel: the
				// stream's fate is its fate.
				d.ok = false
			}
		}
		h.counts[i].Pings += s.settled + d.settled
		h.counts[i].Late += s.late + d.late
		h.fates[i] = [2]fateScore{s, d}
		if s.ok {
			sum := s.score
			if d.ok {
				sum += d.score
			}
			h.counts[i].ScoreMS.Add(float64(sum) / float64(time.Millisecond))
		}
	}
	a := h.activeLocked(now)
	rival := -1
	for i := range h.logs {
		if i != a && !h.silentAt(i, now) && (rival < 0 || h.better(i, rival)) {
			rival = i
		}
	}
	g, ok := time.Duration(0), false
	if rival >= 0 {
		g, ok = gain(h.fates[a], h.fates[rival])
	}
	if !ok || g < moveGain {
		h.rivalSince = time.Time{}
		return nil
	}
	if h.rivalSince.IsZero() || h.rival != rival {
		h.rival, h.rivalSince = rival, now
		return nil
	}
	if now.Sub(h.rivalSince) < moveHold || now.Sub(h.lastMove) < moveCoolDown {
		return nil
	}
	h.chosen, h.lastMove, h.rivalSince = rival, now, time.Time{}
	h.counts[rival].MovesQuality++
	return &qualityMove{from: a, to: rival, gain: g}
}

func ms(d time.Duration) string { return d.Round(time.Millisecond).String() }

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

// probeStream keeps a probe carrier on entry i's stream channel for the
// client's life, dialing it again pingRedial after it fails.
func (h *health) probeStream(i int) {
	h.probe(i, fateStream, func(ctx context.Context) (probeCarrier, error) {
		conn, err := h.c.paths[i].Stream.DialContext(ctx, "tcp", dup.HostAddr())
		if err != nil {
			return probeCarrier{}, err
		}
		b := make([]byte, dup.MaxFrame)
		return probeCarrier{
			send:  func(frame []byte) error { return dup.WriteStream(conn, frame) },
			read:  func() ([]byte, error) { return dup.ReadStream(conn, b) },
			close: func() { _ = conn.Close() },
		}, nil
	})
}

// probeDatagram keeps a probe carrier on entry i's datagram channel while
// that channel is up (v1.08, "Two fates of the probe").
func (h *health) probeDatagram(i int) {
	h.probe(i, fateDatagram, func(ctx context.Context) (probeCarrier, error) {
		if !h.c.datagramUp(i) {
			return probeCarrier{}, net.ErrClosed
		}
		var pc net.PacketConn
		err := h.c.tryDatagram(ctx, i, func(ctx context.Context) (err error) {
			pc, err = h.c.paths[i].Datagram.ListenPacket(ctx, dup.HostAddr())
			return
		})
		if err != nil {
			return probeCarrier{}, err
		}
		b := make([]byte, 65535)
		return probeCarrier{
			send: func(frame []byte) error {
				_, err := pc.WriteTo(frame, dup.HostAddr())
				return err
			},
			read: func() ([]byte, error) {
				n, _, err := pc.ReadFrom(b)
				return b[:n], err
			},
			close: func() { _ = pc.Close() },
		}, nil
	})
}

// probeCarrier is a carrier pings go on: a stream or a datagram association.
type probeCarrier struct {
	send  func(frame []byte) error
	read  func() ([]byte, error)
	close func()
}

// probe keeps a carrier from dial on entry i for the client's life, dialing
// it again pingRedial after it fails.
func (h *health) probe(i int, f fate, dial func(context.Context) (probeCarrier, error)) {
	var id dup.Session
	_, _ = rand.Read(id[:])
	var seq uint64
	for h.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(h.ctx, h.c.opts.ConnectTimeout)
		carrier, err := dial(ctx)
		cancel()
		if err == nil {
			h.ping(i, f, carrier, id, &seq)
		}
		select {
		case <-h.ctx.Done():
			return
		case <-time.After(pingRedial):
		}
	}
}

// ping sends a ping every PingEvery on carrier and records the answers, until
// the carrier fails or the client's context ends.
func (h *health) ping(i int, f fate, carrier probeCarrier, id dup.Session, seq *uint64) {
	defer carrier.close()
	stop := context.AfterFunc(h.ctx, carrier.close)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			data, err := carrier.read()
			if err != nil {
				return
			}
			fr, err := dup.Decode(data)
			if err != nil || fr.Kind != dup.KindPing || fr.Session != id {
				continue
			}
			h.answer(i, f, fr.Seq, time.Now())
		}
	}()
	t := time.NewTicker(PingEvery)
	defer t.Stop()
	for {
		*seq++
		frame, _ := dup.Append(nil, dup.Frame{Kind: dup.KindPing, Session: id, Seq: *seq})
		h.sent(i, f, *seq, time.Now())
		if carrier.send(frame) != nil {
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
