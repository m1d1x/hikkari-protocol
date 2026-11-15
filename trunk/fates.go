package trunk

import (
	"io"
	"math/bits"
	"time"
)

// Live datagrams on wires of two fates (spec/trunk.md, Datagrams and Wires;
// hikkari-client plans/2026-11-15-live-udp-two-fates.md, разделы 1–3).
//
// A wire's fate is what must break on the path for it to lose a frame:
// datagrams of IP (the udp wire, Chromium's QUIC, any QUIC) or streams that
// TCP sends again (the pool). On the night of 14.11 the path lost 15–20% of
// every UDP datagram and almost no TCP segment: copies on two members of one
// wire were lost together, a copy on each fate lost almost nothing
// (plans/research/2026-11-15-voice-night-lab.md). So the entry does not
// guess which wire is good today: a voice datagram goes on a set of wires
// of different fates at once, and the exit takes the first copy by its
// flow's seq, as it always did.

// Fate is what a wire's frames share on the path (Wire.Fate).
type Fate string

const (
	// FateUDP is datagrams of IP on the path: the udp wire, h3dgram, QUIC,
	// salamander.
	FateUDP Fate = "udp"
	// FateTCP is streams TCP sends again on the path: the pool.
	FateTCP Fate = "tcp"
)

// fate is w's fate: its own, or for a wire that says none, the pool's for
// the pool and udp for any other.
func (w Wire) fate() Fate {
	return fateOr(w.Fate, w.ID)
}

func fateOr(f Fate, id WireID) Fate {
	switch {
	case f != "":
		return f
	case id == PoolWire:
		return FateTCP
	}
	return FateUDP
}

// MaxCarries is how many wires a set holds.
const MaxCarries = 4

// Carry is one wire of a set: how many of its members carry each datagram,
// and how long after the datagram they send it.
type Carry struct {
	Wire WireID
	// Copies is how many of the wire's members carry each datagram; 0 is
	// the flow's copies (FlowOptions.Copies).
	Copies int
	// After is how long after the datagram the copies leave: a later copy
	// on one wire (+10 ms) misses a burst of loss that took the first.
	After time.Duration
}

// Set is the wires a class's datagrams go on at once (Route.VoiceSet). It is
// a value: a Route that holds one still compares with ==.
type Set struct {
	n int
	c [MaxCarries]Carry
}

// SetOf is the set of the carries given; past MaxCarries they are left out.
func SetOf(carries ...Carry) Set {
	var s Set
	for _, c := range carries {
		if s.n == MaxCarries {
			break
		}
		s.c[s.n] = c
		s.n++
	}
	return s
}

// Len is how many wires the set holds.
func (s Set) Len() int { return s.n }

// At is the set's i-th carry.
func (s Set) At(i int) Carry { return s.c[i] }

// has says whether the set holds wire id.
func (s *Set) has(id WireID) bool {
	for i := 0; i < s.n; i++ {
		if s.c[i].Wire == id {
			return true
		}
	}
	return false
}

// add puts c in the set: a wire once, but for its later copies (After).
func (s *Set) add(c Carry) {
	if s.n == MaxCarries || c.After == 0 && s.has(c.Wire) {
		return
	}
	s.c[s.n] = c
	s.n++
}

// wiresUp is which wires have a member up now, by id.
type wiresUp [4]uint64

func (u *wiresUp) set(id WireID)      { u[id/64] |= 1 << (id % 64) }
func (u *wiresUp) has(id WireID) bool { return u[id/64]&(1<<(id%64)) != 0 }

// fateState is a session's part in the fates: the wires' fates, given by
// the entry (Entry.shareFatesLocked), and the copies that leave later.
type fateState struct {
	fates map[WireID]Fate
	later []laterDgram
	timer *time.Timer
}

// laterDgram is a datagram's copy waiting for its carry's After.
type laterDgram struct {
	due    time.Time
	wire   WireID
	copies int
	frame  []byte
}

// fateLocked is wire id's fate as the entry gave it.
func (s *Session) fateLocked(id WireID) Fate {
	return fateOr(s.fate.fates[id], id)
}

// setFates gives the session the fates of the entry's wires.
func (s *Session) setFates(fates map[WireID]Fate) {
	s.mu.Lock()
	s.fate.fates = fates
	s.mu.Unlock()
}

// upLocked is which wires have a member up.
func (s *Session) upLocked() wiresUp {
	var up wiresUp
	for m := range s.members {
		up.set(m.kind.wire)
	}
	return up
}

// bestUpLocked is the wire of fate f with a member up that set does not
// hold yet, lowest id first (ties between wires of one fate go by id, the
// owner's word of 15.11); AnyWire for none.
func (s *Session) bestUpLocked(up *wiresUp, f Fate, set *Set) WireID {
	for i, word := range up {
		for word != 0 {
			w := WireID(i*64 + bits.TrailingZeros64(word))
			word &= word - 1
			if !set.has(w) && s.fateLocked(w) == f {
				return w
			}
		}
	}
	return AnyWire
}

// carriesLocked is the set a flow's next datagram goes on, and whether it
// is held to it: the entry's pin (held), the route of its class, or on the
// exit the wires the entry sent it on in the last second.
func (s *Session) carriesLocked(f *flow) (Set, bool) {
	if s.local != nil {
		return f.answerSet(time.Now()), false
	}
	if f.pin != AnyWire {
		return SetOf(Carry{Wire: f.pin}), true
	}
	up := s.upLocked()
	var set Set
	switch f.class {
	case ClassVoice:
		set = s.voiceSetLocked(&up)
	case ClassVideo:
		w := s.route.Video()
		if w == AnyWire {
			w = s.bestUpLocked(&up, FateUDP, &set)
		}
		set = s.resolveLocked(&up, SetOf(Carry{Wire: w}))
	default:
		set = s.resolveLocked(&up, SetOf(Carry{Wire: s.route.Bulk}))
	}
	if set.n == 0 {
		set = SetOf(Carry{Wire: AnyWire})
	}
	return set, false
}

// voiceSetLocked is the voice class's set: the route's, or Voice with the
// flow's copies and one copy on the best wire of the other fate. TCP never
// carries voice alone while a wire of fate udp is up.
func (s *Session) voiceSetLocked(up *wiresUp) Set {
	set := s.route.VoiceSet
	if set.n == 0 {
		main := s.route.Voice
		if main == AnyWire || !up.has(main) {
			main = s.bestUpLocked(up, FateUDP, &set)
		}
		if main == AnyWire {
			return set // no wire of fate udp up: the pool alone, as any member
		}
		set.add(Carry{Wire: main})
		other := FateTCP
		if s.fateLocked(main) == FateTCP {
			other = FateUDP
		}
		if w := s.bestUpLocked(up, other, &set); w != AnyWire {
			set.add(Carry{Wire: w, Copies: 1})
		}
	}
	set = s.resolveLocked(up, set)
	for i := 0; i < set.n; i++ {
		if set.c[i].Wire == AnyWire || s.fateLocked(set.c[i].Wire) != FateTCP {
			return set
		}
	}
	if w := s.bestUpLocked(up, FateUDP, &set); w != AnyWire {
		set.add(Carry{Wire: w, Copies: 1})
	}
	return set
}

// resolveLocked takes a set's wires with no member up off it: each goes to
// the best wire of its fate that is up and not in the set yet, or is left
// out.
func (s *Session) resolveLocked(up *wiresUp, in Set) Set {
	var out Set
	for i := 0; i < in.n; i++ {
		c := in.c[i]
		if c.Wire != AnyWire && !up.has(c.Wire) {
			c.Wire = s.bestUpLocked(up, s.fateLocked(c.Wire), &out)
			if c.Wire == AnyWire {
				continue
			}
		}
		out.add(c)
	}
	return out
}

// sendDgramLocked sends a flow's datagram on every wire of its set: a frame
// of the flow's seq, so the other end takes the first copy, whichever wire
// brought it. A datagram is never owed, so a member carrying it is not held
// to account for it.
func (s *Session) sendDgramLocked(f *flow, p []byte) {
	f.seq++
	f.out++
	b := appendDgram(make([]byte, 0, 13+len(p)), f.id, f.seq, f.port, p)
	set, strict := s.carriesLocked(f)
	sent, queued := 0, false
	for i := 0; i < set.n; i++ {
		c := set.c[i]
		copies := c.Copies
		if copies <= 0 {
			copies = f.copies
		}
		if c.After > 0 {
			s.laterLocked(laterDgram{due: time.Now().Add(c.After), wire: c.Wire, copies: copies, frame: b})
			queued = true
			continue
		}
		sent += s.sendOnLocked(c.Wire, copies, b)
	}
	if sent == 0 && !queued && !strict {
		// The set's wires all went down since (on the exit, the wires the
		// entry used): any member that is up.
		s.sendOnLocked(AnyWire, f.copies, b)
	}
}

// sendOnLocked sends frame on copies members of wire (any wire for
// AnyWire), and says on how many. The members go round: each time the one
// of them that sent last the longest ago, so that a stream member's
// retransmit holds up one datagram in N, not every one.
func (s *Session) sendOnLocked(wire WireID, copies int, frame []byte) int {
	if copies <= 0 {
		copies = s.cfg.Copies
	}
	var used [8]*member
	n := 0
	for n < copies && n < len(used) {
		var best *member
		for m := range s.members {
			if wire != AnyWire && m.kind.wire != wire {
				continue
			}
			taken := false
			for _, u := range used[:n] {
				taken = taken || u == m
			}
			if !taken && (best == nil || m.lastSend.Before(best.lastSend)) {
				best = m
			}
		}
		if best == nil {
			break
		}
		used[n] = best
		n++
		best.lastSend = time.Now()
		best.send(frame, true)
	}
	return n
}

// laterLocked queues a copy for its time, in order of it.
func (s *Session) laterLocked(d laterDgram) {
	q := s.fate.later
	i := len(q)
	for i > 0 && q[i-1].due.After(d.due) {
		i--
	}
	q = append(q, laterDgram{})
	copy(q[i+1:], q[i:])
	q[i] = d
	s.fate.later = q
	if i == 0 {
		s.armLaterLocked(time.Until(d.due))
	}
}

func (s *Session) armLaterLocked(d time.Duration) {
	if s.fate.timer == nil {
		s.fate.timer = time.AfterFunc(d, s.sendLater)
		return
	}
	s.fate.timer.Reset(d)
}

// sendLater sends the copies whose time has come.
func (s *Session) sendLater() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		s.fate.later = nil
		return
	}
	now := time.Now()
	q := s.fate.later
	n := 0
	for n < len(q) && !q[n].due.After(now) {
		s.sendOnLocked(q[n].wire, q[n].copies, q[n].frame)
		n++
	}
	rest := copy(q, q[n:])
	clear(q[rest:])
	s.fate.later = q[:rest]
	if rest > 0 {
		s.armLaterLocked(q[0].due.Sub(now))
	}
}

// answerWindow is how long after a datagram of a flow came on a wire the
// exit still answers the flow on that wire.
const answerWindow = time.Second

// heardOn is, on the exit, one wire a flow's datagrams came on: when last,
// the newest seq it brought, and on how many members to answer there.
type heardOn struct {
	wire   WireID
	last   time.Time
	top    uint32
	copies int
}

// heardLocked notes on the exit that a datagram of f came on wire w, a
// copy of one already taken (dup) or not. A copy no newer than what w
// brought before is the entry's Copies on w, not another wire's copy: the
// exit answers on as many members of it.
func (s *Session) heardLocked(f *flow, w WireID, seq uint32, dup bool, now time.Time) {
	slot := -1
	for i := range f.heard {
		h := &f.heard[i]
		if h.copies > 0 && h.wire == w {
			if dup && seq <= h.top {
				h.copies = s.cfg.Copies
			}
			h.last = now
			h.top = max(h.top, seq)
			return
		}
		// A free slot, else the wire heard from the longest ago.
		if slot < 0 || f.heard[slot].copies > 0 && (h.copies == 0 || h.last.Before(f.heard[slot].last)) {
			slot = i
		}
	}
	f.heard[slot] = heardOn{wire: w, last: now, top: seq, copies: 1}
}

// answerSet is the exit's set for f: every wire its datagrams came on in the
// last answerWindow, or the latest one when none did.
func (f *flow) answerSet(now time.Time) Set {
	var set Set
	latest := -1
	for i, h := range f.heard {
		if h.copies == 0 {
			continue
		}
		if latest < 0 || h.last.After(f.heard[latest].last) {
			latest = i
		}
		if now.Sub(h.last) <= answerWindow {
			set.add(Carry{Wire: h.wire, Copies: h.copies})
		}
	}
	if set.n == 0 && latest >= 0 {
		set.add(Carry{Wire: f.heard[latest].wire, Copies: f.heard[latest].copies})
	}
	return set
}

// noDelay turns Nagle off on a member that is a TCP socket: a voice copy on
// the pool is a 160 B frame every 20 ms, and with Nagle the kernel would
// hold it until the last one is acknowledged. A member that is a tunnel
// (Chromium's, the relay's) has its socket's set where it is dialled or
// accepted (chromium portDialer; Go's net sets it on every TCP socket).
func noDelay(conn io.ReadWriteCloser) {
	if c, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = c.SetNoDelay(true)
	}
}
