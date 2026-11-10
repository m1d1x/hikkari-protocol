// Package trunk is the cascade's trunk: the wire between our entry in Russia
// and our exit abroad (hikkari-client plans/2026-11-05-ru-cascade.md, «Магистраль
// вход → выход»). It is fleet infrastructure, not a client protocol: no client
// ever speaks it, and both ends are ours.
//
//	client ─TCP/UDP─► entry (RU) ═══ pool of members ═══► exit ─► 127.0.0.1:port (the relay)
//
// One entry keeps one session with one exit over a pool of members: long
// TLS + HTTP/2 CONNECT tunnels, each on its own TCP connection and source
// port. A client TCP connection is a stream whose bytes are numbered, sent in
// chunks over whichever members have room, acknowledged by the other end and
// sent again on another member when the one that carried them stops making
// progress. A member without progress is closed and replaced on a new source
// port: paths out of Russia kill TCP flows by source port
// (plans/2026-11-02-tcp-flow-loss.md), so a dead flow stays dead and the pool,
// not the flow, is what keeps the bytes moving. A client UDP packet is a
// datagram sent over two members at once; the first copy wins.
//
// Session is symmetric: the entry and the exit run the same reliability, and
// differ only in who opens streams (the entry) and who dials the relay (the
// exit).
package trunk

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Config tunes one session. Zero fields take the defaults below.
type Config struct {
	// Stall is how long a member that owes progress (unacknowledged chunks,
	// an unanswered ping) may stay silent before it is declared dead. The
	// floor; a member's own round trip can raise it (4 × smoothed RTT).
	Stall time.Duration
	// Inflight bounds the unacknowledged bytes on one member, so a member
	// that dies takes little with it and progress is visible within Stall.
	Inflight int
	// Window is a stream's receive window: how far past what it has written
	// to its local connection the other end may send.
	Window int
	// Chunk is the largest data frame.
	Chunk int
	// Copies is how many members carry each datagram.
	Copies int
	// FlowIdle closes a datagram flow nobody used for this long.
	FlowIdle time.Duration
	// Keepalive pings an idle member this often; an unanswered ping is
	// progress owed like a chunk.
	Keepalive time.Duration
	// Quiet is how long every member may owe progress and stay silent
	// together before they are declared dead. Stall alone judges a member
	// only while another one shows the other end is alive: when all go
	// silent at once, it is the other end that paused (a box starved of CPU
	// by its neighbours, plans/research/2026-11-10-trunk-member-deaths.md)
	// or the whole path, and new members would land on the same pause.
	// Zero is DefaultQuiet on the entry, ExitQuiet on the exit (only the
	// entry can dial a member, so the exit waits for it).
	Quiet time.Duration
}

const (
	DefaultStall     = 300 * time.Millisecond
	DefaultInflight  = 256 << 10
	DefaultWindow    = 2 << 20
	DefaultChunk     = 16 << 10
	DefaultCopies    = 2
	DefaultFlowIdle  = 2 * time.Minute
	DefaultKeepalive = time.Second
	DefaultQuiet     = time.Second
	ExitQuiet        = 30 * time.Second
	// tick is the session's clock for stalls, pings and idle flows.
	tick = 25 * time.Millisecond
	// lateTick is how late a tick may come before the session counts the
	// gap as its own pause: the box did not run it.
	lateTick = 4 * tick
	// closedMemory is how long a finished stream's id is remembered, so its
	// late copies are answered instead of reopening it.
	closedMemory = 2 * time.Minute
)

func (c Config) withDefaults() Config {
	if c.Stall <= 0 {
		c.Stall = DefaultStall
	}
	if c.Inflight <= 0 {
		c.Inflight = DefaultInflight
	}
	if c.Window <= 0 {
		c.Window = DefaultWindow
	}
	if c.Chunk <= 0 || c.Chunk > MaxPayload {
		c.Chunk = DefaultChunk
	}
	if c.Copies <= 0 {
		c.Copies = DefaultCopies
	}
	if c.FlowIdle <= 0 {
		c.FlowIdle = DefaultFlowIdle
	}
	if c.Keepalive <= 0 {
		c.Keepalive = DefaultKeepalive
	}
	return c
}

// Stats are a session's counters since it started.
type Stats struct {
	Members       int           // members up now
	MembersJoined int64         // members ever attached
	MembersStall  int64         // members closed for no progress
	MembersBroken int64         // members closed by an error on their connection
	Pauses        int64         // times this end was not run for longer than lateTick
	Paused        time.Duration // how long in all
	Resent        int64         // chunks sent again on another member
	Streams       int           // streams open now
	StreamsOpened int64
	StreamsReset  int64
	Up, Down      int64 // stream bytes read from / written to local connections
	Flows         int   // datagram flows open now
	DgramsOut     int64 // datagrams read from local sockets
	DgramsIn      int64 // datagrams written to local sockets
	DgramsCopy    int64 // datagram copies dropped as already seen
}

// Local is how the exit reaches what a stream or a flow asks for: the relay
// on the exit's own box. The entry has none: it never accepts streams.
type Local interface {
	DialStream(ctx context.Context, port uint16) (net.Conn, error)
	DialFlow(ctx context.Context, port uint16) (net.Conn, error)
}

// Session is one side of a trunk.
type Session struct {
	cfg   Config
	local Local // nil on the entry
	ctx   context.Context
	stop  context.CancelFunc

	mu      sync.Mutex
	cond    *sync.Cond // room on members, credit on streams, members joining
	members map[*member]struct{}
	streams map[uint32]*stream
	closed  map[uint32]time.Time
	flows   map[uint32]*flow
	pending []*segment // chunks owed while no member is up
	// early holds, on the exit, chunks and FINs of streams whose open is
	// still on its way (it left on a member that died): they are taken when
	// it comes, not dropped, since their member will not send them again.
	early      map[uint32]*earlyStream
	earlyBytes int
	nextID     uint32
	shutdown   bool
	empty      time.Time // when the last member left (zero while one is up)
	// proof is the latest progress any member showed: a member is only
	// judged by Stall against members that kept going.
	proof time.Time
	// lastTick and resumed are the clock's: when it last ran, and when it
	// last came back from a pause of its own.
	lastTick, resumed time.Time
	onPause           func(time.Duration)
	paused            time.Duration

	joined, stalls, broken, resent       atomic.Int64
	pauses                               atomic.Int64
	opened, resets, up, down             atomic.Int64
	dgramsOut, dgramsIn, dgramsCopy, tok atomic.Int64
}

// NewSession starts a session. local is nil on the entry.
func NewSession(cfg Config, local Local) *Session {
	s := newSession(cfg, local)
	go s.clock()
	return s
}

func newSession(cfg Config, local Local) *Session {
	ctx, stop := context.WithCancel(context.Background())
	cfg = cfg.withDefaults()
	if cfg.Quiet <= 0 {
		cfg.Quiet = DefaultQuiet
		if local != nil {
			cfg.Quiet = ExitQuiet
		}
	}
	s := &Session{
		cfg: cfg, local: local, ctx: ctx, stop: stop,
		members: map[*member]struct{}{}, streams: map[uint32]*stream{},
		closed: map[uint32]time.Time{}, flows: map[uint32]*flow{}, early: map[uint32]*earlyStream{},
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Close ends every stream and flow and every member.
func (s *Session) Close() {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return
	}
	s.shutdown = true
	for m := range s.members {
		s.dropMemberLocked(m, false)
	}
	for _, st := range s.streams {
		s.endStreamLocked(st, false)
	}
	for _, f := range s.flows {
		s.endFlowLocked(f)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	s.stop()
}

// Reset ends every stream and flow but keeps the members: the other end lost
// them (the exit restarted under the entry's session).
func (s *Session) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		s.endStreamLocked(st, false)
	}
	for _, f := range s.flows {
		s.endFlowLocked(f)
	}
	s.pending = nil
}

// Stats reads the counters.
func (s *Session) Stats() Stats {
	s.mu.Lock()
	members, streams, flows, paused := len(s.members), len(s.streams), len(s.flows), s.paused
	s.mu.Unlock()
	return Stats{
		Members: members, MembersJoined: s.joined.Load(), MembersStall: s.stalls.Load(),
		MembersBroken: s.broken.Load(), Pauses: s.pauses.Load(), Paused: paused, Resent: s.resent.Load(),
		Streams: streams, StreamsOpened: s.opened.Load(), StreamsReset: s.resets.Load(),
		Up: s.up.Load(), Down: s.down.Load(),
		Flows: flows, DgramsOut: s.dgramsOut.Load(), DgramsIn: s.dgramsIn.Load(), DgramsCopy: s.dgramsCopy.Load(),
	}
}

// MemberRTTs is the smoothed round trip of every member up now that has had
// a ping answered, shortest first.
func (s *Session) MemberRTTs() []time.Duration {
	s.mu.Lock()
	out := make([]time.Duration, 0, len(s.members))
	for m := range s.members {
		if m.srtt > 0 {
			out = append(out, m.srtt)
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IdleFor says how long the session has had no member (0 while one is up).
func (s *Session) IdleFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.members) > 0 || s.empty.IsZero() {
		return 0
	}
	return time.Since(s.empty)
}

// ── members ──

// ErrStalled ends a member that owed progress and stayed silent.
var ErrStalled = errors.New("trunk: member stalled")

type member struct {
	s    *Session
	conn io.ReadWriteCloser

	// under s.mu
	segs      map[*segment]struct{}
	inflight  int
	busySince time.Time // when it last went from owing nothing to owing
	// progress is when this member last proved its own round trip: a chunk
	// it carried was confirmed, or its ping answered on it. Frames that
	// merely arrive on it prove nothing about the way out: a flow can die
	// one way and keep carrying the other end's acks.
	progress time.Time
	lastSend time.Time
	ping     uint64
	pingSent time.Time
	srtt     time.Duration
	dead     bool
	why      error

	qmu    sync.Mutex
	hi, lo [][]byte
	wake   chan struct{}
	done   chan struct{}
}

// Serve attaches conn as a member (its hello already exchanged) and carries
// frames until it dies: ErrStalled when it stopped making progress, the read
// or write error otherwise, nil when the session closed.
func (s *Session) Serve(conn io.ReadWriteCloser) error {
	m := &member{s: s, conn: conn, segs: map[*segment]struct{}{}, wake: make(chan struct{}, 1), done: make(chan struct{})}
	now := time.Now()
	m.progress, m.lastSend = now, now
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		conn.Close()
		return nil
	}
	s.members[m] = struct{}{}
	s.empty = time.Time{}
	s.joined.Add(1)
	// What no member could carry goes out now, and every stream says again
	// how far it is: acks sent on a member that died are lost.
	s.drainPendingLocked()
	for _, st := range s.streams {
		s.ackLocked(st, m)
	}
	s.cond.Broadcast()
	s.mu.Unlock()

	go m.writeLoop()
	r := bufio.NewReaderSize(conn, 64<<10)
	var err error
	for {
		var f frame
		if f, err = readFrame(r); err != nil {
			break
		}
		s.handle(m, f)
	}
	s.mu.Lock()
	if m.dead {
		err = m.why
	} else {
		s.dropMemberLocked(m, false)
		if s.shutdown {
			err = nil
		} else {
			s.broken.Add(1)
		}
	}
	s.mu.Unlock()
	return err
}

func (m *member) send(frame []byte, urgent bool) {
	m.qmu.Lock()
	if urgent {
		m.hi = append(m.hi, frame)
	} else {
		m.lo = append(m.lo, frame)
	}
	m.qmu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *member) writeLoop() {
	w := bufio.NewWriterSize(m.conn, 64<<10)
	for {
		m.qmu.Lock()
		var next []byte
		if len(m.hi) > 0 {
			next, m.hi = m.hi[0], m.hi[1:]
		} else if len(m.lo) > 0 {
			next, m.lo = m.lo[0], m.lo[1:]
		}
		m.qmu.Unlock()
		if next == nil {
			if err := w.Flush(); err != nil {
				m.fail(err)
				return
			}
			select {
			case <-m.wake:
				continue
			case <-m.done:
				return
			}
		}
		if _, err := w.Write(next); err != nil {
			m.fail(err)
			return
		}
	}
}

func (m *member) fail(err error) {
	s := m.s
	s.mu.Lock()
	if !m.dead {
		s.broken.Add(1)
		m.why = err
		s.dropMemberLocked(m, false)
	}
	s.mu.Unlock()
}

// dropMemberLocked closes m and moves what it owed to the other members.
func (s *Session) dropMemberLocked(m *member, stalled bool) {
	if m.dead {
		return
	}
	m.dead = true
	if stalled {
		m.why = ErrStalled
		s.stalls.Add(1)
	}
	delete(s.members, m)
	if len(s.members) == 0 {
		s.empty = time.Now()
	}
	close(m.done)
	_ = m.conn.Close()
	owed := make([]*segment, 0, len(m.segs))
	for seg := range m.segs {
		owed = append(owed, seg)
	}
	m.segs = nil
	m.inflight = 0
	// Sent again oldest first, ahead of anything new, as members have room:
	// all of it on one member would only bury that one.
	sort.Slice(owed, func(i, j int) bool {
		if owed[i].st.id != owed[j].st.id {
			return owed[i].st.id < owed[j].st.id
		}
		return owed[i].off < owed[j].off || owed[i].off == owed[j].off && owed[i].kind < owed[j].kind
	})
	for _, seg := range owed {
		seg.m = nil
	}
	s.resent.Add(int64(len(owed)))
	s.pending = append(owed, s.pending...)
	s.drainPendingLocked()
	// Acks this member carried may be lost: say them again elsewhere.
	if next := s.pickLocked(nil, false); next != nil {
		for _, st := range s.streams {
			s.ackLocked(st, next)
		}
	}
	s.cond.Broadcast()
}

// pickLocked chooses the live member with the fewest bytes owed. With room
// set it only takes a member under Inflight (or owing nothing).
func (s *Session) pickLocked(not *member, room bool) *member {
	var best *member
	for m := range s.members {
		if m == not || (room && m.inflight > 0 && m.inflight+s.cfg.Chunk > s.cfg.Inflight) {
			continue
		}
		if best == nil || m.inflight < best.inflight {
			best = m
		}
	}
	return best
}

// clock declares stalled members dead, pings idle ones, retires idle flows
// and forgets old stream ids.
func (s *Session) clock() {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			// The time we ran, not the time the ticker fired: a box that
			// was not run shows here as a late tick.
			s.tick(time.Now())
		}
	}
}

// tick is one turn of the clock at now.
func (s *Session) tick(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastTick.IsZero() {
		if gap := now.Sub(s.lastTick); gap > lateTick {
			// This end was not run: nothing its members owed could have
			// been read. Each gets a fresh Stall from now, as if the pause
			// had not happened, and the pause is told.
			s.resumed = now
			s.pauses.Add(1)
			s.paused += gap
			if s.onPause != nil {
				go s.onPause(gap)
			}
		}
	}
	s.lastTick = now
	for m := range s.members {
		limit := s.cfg.Stall
		if r := 4 * m.srtt; r > limit {
			limit = r
		}
		// Owed progress is counted from the later of the last proof
		// and the moment the debt began: an idle member is not late
		// for a chunk it was handed a moment ago.
		owes := false
		since := m.progress
		if len(m.segs) > 0 {
			owes = true
			if m.busySince.After(since) {
				since = m.busySince
			}
		} else if m.ping != 0 {
			owes = true
			if m.pingSent.After(since) {
				since = m.pingSent
			}
		}
		if s.resumed.After(since) {
			since = s.resumed
		}
		// Late by Stall while another member proved the other end alive
		// after this one's debt began: this flow is dead, not the end.
		// Late with everyone silent: the other end or the whole path, and
		// only Quiet ends it.
		if owes && (now.Sub(since) > limit && s.proof.After(since) || now.Sub(since) > s.cfg.Quiet) {
			s.dropMemberLocked(m, true)
			continue
		}
		if m.ping == 0 && len(m.segs) == 0 && now.Sub(m.lastSend) > s.cfg.Keepalive {
			m.ping = uint64(s.tok.Add(1))
			m.pingSent, m.lastSend = now, now
			m.send(appendPing(nil, fPing, m.ping), true)
		}
	}
	for _, f := range s.flows {
		if now.Sub(f.used) > s.cfg.FlowIdle {
			s.endFlowLocked(f)
		}
	}
	for id, e := range s.early {
		if now.Sub(e.since) > earlyFor {
			delete(s.early, id)
			s.earlyBytes -= e.bytes
		}
	}
	for id, at := range s.closed {
		if now.Sub(at) > closedMemory {
			delete(s.closed, id)
		}
	}
}

// handle acts on one frame that arrived on m.
func (s *Session) handle(m *member, f frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.dead {
		return
	}
	now := time.Now()
	switch f.typ {
	case fPing:
		m.send(appendPing(nil, fPong, f.token), true)
	case fPong:
		if f.token == m.ping {
			rtt := now.Sub(m.pingSent)
			if m.srtt == 0 {
				m.srtt = rtt
			} else {
				m.srtt = (7*m.srtt + rtt) / 8
			}
			m.ping = 0
			m.progress = now
			s.proof = now
		}
	case fOpen:
		s.openLocked(m, f)
	case fData:
		s.dataLocked(m, f)
	case fAck:
		s.ackedLocked(f)
	case fFin:
		s.finLocked(m, f)
	case fRst:
		if st := s.streams[f.stream]; st != nil {
			s.endStreamLocked(st, false)
		}
	case fDgram:
		s.dgramLocked(f)
	}
}

// ── streams ──

// segment is something a stream sent that the other end must confirm: an
// open, a chunk of bytes, or the end of the stream.
type segment struct {
	st   *stream
	kind byte // fOpen, fData, fFin
	off  uint64
	data []byte
	m    *member // the member carrying it now; nil while pending
	done bool
}

type stream struct {
	id    uint32
	port  uint16
	local net.Conn      // nil on the exit until the relay answers
	ready chan struct{} // closed when local is set (or the stream ended)
	gone  chan struct{} // closed when the stream ended

	// sending: local → trunk
	sent    uint64 // bytes read from local and numbered
	credit  uint64 // the other end takes bytes below this
	owed    []*segment
	finSent bool
	finDone bool

	// receiving: trunk → local
	received  uint64            // contiguous bytes received
	ahead     map[uint64][]byte // chunks past a hole
	finAt     int64             // offset of the other end's FIN, -1 until known
	queue     [][]byte          // received, not yet written to local
	written   uint64            // bytes written to local
	advertise uint64            // the credit last told
	wake      chan struct{}
	writeDone bool // local has seen everything (and the FIN) the other end sent

	ended bool
}

func (s *Session) newStreamLocked(id uint32, port uint16, local net.Conn) *stream {
	st := &stream{id: id, port: port, local: local, ready: make(chan struct{}), gone: make(chan struct{}), credit: uint64(s.cfg.Window),
		ahead: map[uint64][]byte{}, finAt: -1, advertise: uint64(s.cfg.Window), wake: make(chan struct{}, 1)}
	if local != nil {
		close(st.ready)
	}
	s.streams[id] = st
	s.opened.Add(1)
	go s.writeLocal(st)
	return st
}

// Carry opens a stream to the exit's port and carries local over it until
// both directions end. Entry only.
func (s *Session) Carry(local net.Conn, port uint16) {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		local.Close()
		return
	}
	s.nextID++
	st := s.newStreamLocked(s.nextID, port, local)
	s.queueLocked(&segment{st: st, kind: fOpen}, true)
	s.mu.Unlock()
	s.readLocal(st)
	<-st.gone
}

// openLocked: the entry opened a stream; the exit dials the relay for it.
func (s *Session) openLocked(m *member, f frame) {
	if s.local == nil {
		return
	}
	if st := s.streams[f.stream]; st != nil {
		s.ackLocked(st, m) // a copy of the open: the first one was answered
		return
	}
	if _, done := s.closed[f.stream]; done {
		m.send(appendRst(nil, f.stream), true)
		return
	}
	st := s.newStreamLocked(f.stream, f.port, nil)
	if e := s.early[f.stream]; e != nil {
		delete(s.early, f.stream)
		s.earlyBytes -= e.bytes
		for _, ef := range e.frames {
			if ef.typ == fData {
				s.dataLocked(m, ef)
			} else {
				s.finLocked(m, ef)
			}
		}
	}
	s.ackLocked(st, m)
	go func() {
		c, err := s.local.DialStream(s.ctx, f.port)
		s.mu.Lock()
		if err != nil || st.ended {
			if c != nil {
				c.Close()
			}
			if !st.ended {
				s.endStreamLocked(st, true)
			}
			s.mu.Unlock()
			return
		}
		st.local = c
		close(st.ready)
		s.cond.Broadcast()
		s.mu.Unlock()
		s.readLocal(st)
	}()
}

// queueLocked numbers seg into its stream and sends it. With wait set it
// waits for a member with room (the reader of a local connection does: that
// is the trunk's backpressure); opens and FINs never wait.
func (s *Session) queueLocked(seg *segment, urgent bool) {
	seg.st.owed = append(seg.st.owed, seg)
	if urgent {
		if m := s.pickLocked(nil, false); m != nil {
			s.transmitLocked(seg, m)
		} else {
			s.pending = append(s.pending, seg)
		}
		return
	}
	for {
		if seg.st.ended || s.shutdown {
			return
		}
		// What is owed again goes before what is new.
		if len(s.pending) == 0 {
			if m := s.pickLocked(nil, true); m != nil {
				s.transmitLocked(seg, m)
				return
			}
		}
		s.cond.Wait()
	}
}

// drainPendingLocked sends what is owed and carried by no member, oldest
// first, as far as members have room. Opens and FINs take no room.
func (s *Session) drainPendingLocked() {
	n := 0
	for ; n < len(s.pending); n++ {
		seg := s.pending[n]
		if seg.done {
			continue
		}
		m := s.pickLocked(nil, len(seg.data) > 0)
		if m == nil {
			break
		}
		s.transmitLocked(seg, m)
	}
	s.pending = append([]*segment(nil), s.pending[n:]...)
}

func (s *Session) transmitLocked(seg *segment, m *member) {
	st := seg.st
	var b []byte
	switch seg.kind {
	case fOpen:
		b = appendOpen(nil, st.id, st.port)
	case fData:
		b = appendData(make([]byte, 0, 15+len(seg.data)), st.id, seg.off, seg.data)
	case fFin:
		b = appendFin(nil, st.id, seg.off)
	}
	if len(m.segs) == 0 {
		m.busySince = time.Now()
	}
	seg.m = m
	m.segs[seg] = struct{}{}
	m.inflight += len(seg.data)
	m.lastSend = time.Now()
	m.send(b, seg.kind != fData)
}

func (s *Session) releaseLocked(seg *segment) {
	if seg.done {
		return
	}
	seg.done = true
	if m := seg.m; m != nil && !m.dead {
		delete(m.segs, seg)
		m.inflight -= len(seg.data)
		m.progress = time.Now()
		s.proof = m.progress
	}
	seg.m = nil
}

// readLocal reads the local connection into chunks while the other end gives
// credit and members have room.
func (s *Session) readLocal(st *stream) {
	buf := make([]byte, s.cfg.Chunk)
	for {
		s.mu.Lock()
		for !st.ended && !s.shutdown && st.sent >= st.credit {
			s.cond.Wait()
		}
		if st.ended || s.shutdown {
			s.mu.Unlock()
			return
		}
		room := st.credit - st.sent
		s.mu.Unlock()
		if room > uint64(len(buf)) {
			room = uint64(len(buf))
		}
		n, err := st.local.Read(buf[:room])
		s.mu.Lock()
		if st.ended {
			s.mu.Unlock()
			return
		}
		if n > 0 {
			s.up.Add(int64(n))
			seg := &segment{st: st, kind: fData, off: st.sent, data: append([]byte(nil), buf[:n]...)}
			st.sent += uint64(n)
			s.queueLocked(seg, false)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				st.finSent = true
				s.queueLocked(&segment{st: st, kind: fFin, off: st.sent}, true)
				s.maybeFinishLocked(st)
			} else {
				s.endStreamLocked(st, true)
			}
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
	}
}

// ackedLocked: the other end says how far it has a stream.
func (s *Session) ackedLocked(f frame) {
	st := s.streams[f.stream]
	if st == nil {
		return
	}
	if f.credit > st.credit {
		st.credit = f.credit
	}
	keep := st.owed[:0]
	for _, seg := range st.owed {
		switch {
		case seg.kind == fOpen,
			seg.kind == fData && (seg.off+uint64(len(seg.data)) <= f.off || seg.off == f.got),
			seg.kind == fFin && f.flags&ackFin != 0:
			if seg.kind == fFin {
				st.finDone = true
			}
			s.releaseLocked(seg)
		default:
			keep = append(keep, seg)
		}
	}
	for i := len(keep); i < len(st.owed); i++ {
		st.owed[i] = nil
	}
	st.owed = keep
	s.drainPendingLocked()
	s.cond.Broadcast()
	s.maybeFinishLocked(st)
}

// dataLocked: a chunk of a stream arrived.
func (s *Session) dataLocked(m *member, f frame) {
	st := s.streams[f.stream]
	if st == nil {
		if _, done := s.closed[f.stream]; done {
			m.send(appendRst(nil, f.stream), true)
		} else {
			s.holdEarlyLocked(f)
		}
		return
	}
	end := f.off + uint64(len(f.payload))
	got := f.off
	switch {
	case end <= st.received:
		// a copy of what is here
	case f.off > st.received:
		if f.off < st.written+uint64(s.cfg.Window)+uint64(s.cfg.Chunk) {
			st.ahead[f.off] = f.payload
		} else {
			got = noGot // past the window: not kept, so not confirmed
		}
	default:
		s.takeLocked(st, f.payload[st.received-f.off:])
		for {
			next, ok := st.ahead[st.received]
			if !ok {
				// A chunk that starts inside what is here (sent again cut
				// differently) still counts for its tail.
				for off, p := range st.ahead {
					if off < st.received {
						delete(st.ahead, off)
						if off+uint64(len(p)) > st.received {
							next, ok = p[st.received-off:], true
							break
						}
					}
				}
				if !ok {
					break
				}
			} else {
				delete(st.ahead, st.received)
			}
			s.takeLocked(st, next)
		}
	}
	s.ackGotLocked(st, m, got)
}

func (s *Session) takeLocked(st *stream, p []byte) {
	if len(p) == 0 {
		return
	}
	st.received += uint64(len(p))
	st.queue = append(st.queue, p)
	select {
	case st.wake <- struct{}{}:
	default:
	}
}

func (s *Session) finLocked(m *member, f frame) {
	st := s.streams[f.stream]
	if st == nil {
		if _, done := s.closed[f.stream]; done {
			// It finished here already: the FIN was ours to confirm.
			m.send(appendAck(nil, f.stream, f.off, f.off, ackFin, noGot), true)
		} else {
			s.holdEarlyLocked(f)
		}
		return
	}
	if st.finAt < 0 {
		st.finAt = int64(f.off)
		select {
		case st.wake <- struct{}{}:
		default:
		}
	}
	s.ackLocked(st, m)
}

func (s *Session) ackLocked(st *stream, m *member) { s.ackGotLocked(st, m, noGot) }

// ackGotLocked acks a stream on m, answering the chunk at got.
func (s *Session) ackGotLocked(st *stream, m *member, got uint64) {
	if m == nil || m.dead || st.ended {
		return
	}
	var flags byte
	if st.finAt >= 0 && st.received == uint64(st.finAt) {
		flags = ackFin
	}
	st.advertise = st.written + uint64(s.cfg.Window)
	m.send(appendAck(nil, st.id, st.received, st.advertise, flags, got), true)
}

// writeLocal writes what arrived, in order, to the local connection, and
// tells the other end its new credit as the window frees.
func (s *Session) writeLocal(st *stream) {
	select {
	case <-st.ready:
	case <-s.ctx.Done():
		return
	}
	for {
		s.mu.Lock()
		if st.ended {
			s.mu.Unlock()
			return
		}
		batch := st.queue
		st.queue = nil
		fin := st.finAt >= 0 && st.received == uint64(st.finAt)
		local := st.local
		s.mu.Unlock()
		for _, p := range batch {
			if _, err := local.Write(p); err != nil {
				s.mu.Lock()
				s.endStreamLocked(st, true)
				s.mu.Unlock()
				return
			}
			s.down.Add(int64(len(p)))
			s.mu.Lock()
			st.written += uint64(len(p))
			if st.written+uint64(s.cfg.Window) >= st.advertise+uint64(s.cfg.Window/4) {
				s.ackLocked(st, s.pickLocked(nil, false))
			}
			s.mu.Unlock()
		}
		if len(batch) == 0 && fin {
			if c, ok := local.(interface{ CloseWrite() error }); ok {
				_ = c.CloseWrite()
			}
			s.mu.Lock()
			st.writeDone = true
			s.maybeFinishLocked(st)
			s.mu.Unlock()
			return
		}
		if len(batch) > 0 {
			continue
		}
		select {
		case <-st.wake:
		case <-s.ctx.Done():
			return
		}
	}
}

// maybeFinishLocked closes a stream both of whose directions are over: our
// FIN confirmed, theirs written.
func (s *Session) maybeFinishLocked(st *stream) {
	if st.ended || !st.finDone || !st.writeDone {
		return
	}
	s.endStreamLocked(st, false)
}

// endStreamLocked closes a stream; reset tells the other end to drop it too.
func (s *Session) endStreamLocked(st *stream, reset bool) {
	if st.ended {
		return
	}
	st.ended = true
	if reset {
		s.resets.Add(1)
		sent := 0
		for m := range s.members {
			m.send(appendRst(nil, st.id), true)
			if sent++; sent == s.cfg.Copies {
				break
			}
		}
	}
	for _, seg := range st.owed {
		s.releaseLocked(seg)
	}
	st.owed = nil
	if st.local != nil {
		_ = st.local.Close()
	} else {
		close(st.ready)
	}
	close(st.gone)
	select {
	case st.wake <- struct{}{}:
	default:
	}
	delete(s.streams, st.id)
	s.closed[st.id] = time.Now()
	s.cond.Broadcast()
}

type earlyStream struct {
	frames []frame
	bytes  int
	since  time.Time
}

// Bounds of what the exit holds for streams not yet open: a stream's window,
// and in all as much as a full pool can carry.
const (
	earlyStreams = 1024
	earlyTotal   = 64 << 20
	earlyFor     = 30 * time.Second
)

// holdEarlyLocked keeps a chunk or FIN of a stream whose open has not come.
// Only the exit holds: the entry opens its own streams.
func (s *Session) holdEarlyLocked(f frame) {
	if s.local == nil {
		return
	}
	e := s.early[f.stream]
	if e == nil {
		if len(s.early) >= earlyStreams {
			return
		}
		e = &earlyStream{since: time.Now()}
		s.early[f.stream] = e
	}
	if e.bytes+len(f.payload) > s.cfg.Window+s.cfg.Chunk || s.earlyBytes+len(f.payload) > earlyTotal {
		return
	}
	e.frames = append(e.frames, f)
	e.bytes += len(f.payload)
	s.earlyBytes += len(f.payload)
}
