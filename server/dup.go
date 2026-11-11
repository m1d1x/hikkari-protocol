package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/connect"
	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/m1d1x/hikkari-protocol/wire/datagram"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// DupGrace is how long a session keeps its exit socket after its last carrier
// left: long enough for a client on a new network to bring a carrier back.
const DupGrace = 30 * time.Second

// dupQueue bounds the frames waiting for one carrier; a carrier that cannot
// keep up loses the newest, the other carrier still has them. A datagram
// carrier hands its frames on at once to the connection's scheduler, where
// they wait by their age (v1.05); a stream carrier's own queue drops a frame
// older than datagram.StaleAfter before its write.
const dupQueue = 256

// legFrame is a frame in a leg's queue: when it was queued, and whether it
// must go whatever its age (an attach).
type legFrame struct {
	b    []byte
	at   time.Time
	keep bool
}

// channelStats is a datagram carrier's association as the scheduler counts
// it (wire/datagram).
type channelStats interface {
	TakeStats() datagram.ChannelStats
}

// DupHub serves duplicated associations (package dup) for both channels of a
// relay: carriers of one session, from either channel, share one exit socket.
type DupHub struct {
	exit  Exit
	idle  time.Duration
	grace time.Duration

	mu       sync.Mutex
	sessions map[dupKey]*dupSession
	book     *observe.Book

	streamLegs, datagramLegs atomic.Int64
}

// A session belongs to the key that opened it: another key naming the same
// session opens its own.
type dupKey struct {
	key string
	id  dup.Session
}

// NewDupHub returns a hub whose sockets leave through exit and close after
// idle without packets (UDPIdle when zero).
func NewDupHub(exit Exit, idle time.Duration) *DupHub {
	if idle <= 0 {
		idle = UDPIdle
	}
	return &DupHub{exit: exit, idle: idle, grace: DupGrace, sessions: map[dupKey]*dupSession{}}
}

// Observe counts the hub's sessions into b by access key (v1.04): the up
// direction's copies, by channel. Call it before the hub serves.
func (h *DupHub) Observe(b *observe.Book) {
	h.mu.Lock()
	h.book = b
	h.mu.Unlock()
}

// Sessions is how many sessions hold an exit socket now.
func (h *DupHub) Sessions() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sessions)
}

// Carriers is how many carriers each channel has brought, ever.
func (h *DupHub) Carriers() (stream, datagram int64) {
	return h.streamLegs.Load(), h.datagramLegs.Load()
}

// carrier is one channel's leg of a session.
type carrier interface {
	via() dup.Via
	readFrame() (dup.Frame, error)
	writeFrame([]byte) error
	close()
}

// ServePacket serves a datagram-channel carrier: a UDP association whose
// packets are addressed to dup.Host. count receives the carrier's own bytes.
func (h *DupHub) ServePacket(ctx context.Context, key string, conn N.PacketConn, count func(up, down int)) error {
	h.datagramLegs.Add(1)
	return h.serve(ctx, key, observe.GroupFrom(ctx, key), &packetCarrier{conn: conn, count: count})
}

// ServeStream serves a stream-channel carrier on conn, the CONNECT tunnel's
// bytes. A session the carrier opens counts in ctx's group
// (observe.WithGroup), key's when it names none.
func (h *DupHub) ServeStream(ctx context.Context, key string, conn net.Conn) error {
	return h.serveStream(ctx, key, observe.GroupFrom(ctx, key), conn)
}

func (h *DupHub) serveStream(ctx context.Context, key, group string, conn net.Conn) error {
	h.streamLegs.Add(1)
	return h.serve(ctx, key, group, &streamCarrier{conn: conn, buf: make([]byte, dup.MaxFrame)})
}

// IsDupHost reports whether a CONNECT asks for a duplicated-association
// carrier.
func IsDupHost(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	return dup.IsHost(host)
}

// WithDup puts a stream carrier on a CONNECT request's context, as WithUoT
// does: the Naive proxy answers the CONNECT behind its own auth and padding,
// the hub serves the other end of the pipe under key, in ctx's group
// (observe.WithGroup).
func WithDup(ctx context.Context, hub *DupHub, key string) context.Context {
	group := observe.GroupFrom(ctx, key)
	return context.WithValue(ctx, connect.ContextKeyDial{}, func(ctx context.Context) (net.Conn, error) {
		proxySide, relaySide := net.Pipe()
		go func() {
			defer relaySide.Close()
			stop := context.AfterFunc(ctx, func() { _ = relaySide.Close() })
			defer stop()
			_ = hub.serveStream(ctx, key, group, relaySide)
		}()
		return proxySide, nil
	})
}

func (h *DupHub) serve(ctx context.Context, key, group string, c carrier) error {
	defer c.close()
	context.AfterFunc(ctx, c.close)
	first, err := c.readFrame()
	if err != nil {
		return err
	}
	s, leg, err := h.attach(ctx, key, group, first.Session, c)
	if err != nil {
		return err
	}
	defer s.detach(leg)
	for f := first; ; {
		if f.Session != s.id.id {
			return dup.ErrFrame
		}
		switch f.Kind {
		case dup.KindPacket:
			s.up(ctx, f, c.via())
		case dup.KindAttach:
			leg.join(s.id.id, f.Lane)
		}
		if f, err = c.readFrame(); err != nil {
			return nil
		}
	}
}

// attach finds or opens the session and adds c as a leg. A session counts in
// the group of the carrier that opened it.
func (h *DupHub) attach(ctx context.Context, key, group string, id dup.Session, c carrier) (*dupSession, *dupLeg, error) {
	k := dupKey{key, id}
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[k]
	if s == nil {
		sock, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, err
		}
		s = &dupSession{hub: h, id: k, sock: sock, legs: map[*dupLeg]struct{}{}, resolved: map[string]netip.AddrPort{}}
		s.timer = time.AfterFunc(h.idle, s.end)
		h.sessions[k] = s
		s.unbook = h.book.Add(group, s.take)
		go s.down()
	}
	leg := &dupLeg{c: c, s: s, queue: make(chan legFrame, dupQueue)}
	if p, ok := c.(*packetCarrier); ok {
		leg.stats, _ = common.Cast[channelStats](p.conn)
	}
	s.mu.Lock()
	s.legs[leg] = struct{}{}
	s.mu.Unlock()
	go leg.write()
	return s, leg, nil
}

type dupLeg struct {
	c     carrier
	s     *dupSession
	stats channelStats // a datagram carrier's; nil for a stream carrier
	queue chan legFrame
	// mu orders put against stop: the session sends answers to a leg that
	// may be detaching.
	mu   sync.Mutex
	done bool
	// lane is the carrier's lane (dup.LaneAll or dup.LaneVoice); an attach
	// on the carrier sets it, a v1.02 client never names one.
	lane atomic.Uint32
}

// join sets the carrier's lane and answers the attach with one naming it: the
// client learns that this relay keeps lanes (v1.03). A datagram carrier on the
// voice lane is the client's voice connection: its QUIC connection gets the
// voice sender (datagram.VoiceWindow), so a long round trip on the user's
// line never holds the call back.
func (l *dupLeg) join(id dup.Session, lane uint8) {
	if lane != dup.LaneVoice {
		lane = dup.LaneAll
	}
	l.lane.Store(uint32(lane))
	if p, ok := l.c.(*packetCarrier); ok && lane == dup.LaneVoice {
		if v, ok := common.Cast[voiceCarrier](p.conn); ok {
			v.CarryVoice()
		}
	}
	ack, _ := dup.Append(nil, dup.Frame{Kind: dup.KindAttach, Session: id, Lane: lane})
	l.queueFrame(legFrame{b: ack, at: time.Now(), keep: true})
}

// voiceCarrier is a datagram association that can say its QUIC connection
// carries voice (wire/datagram).
type voiceCarrier interface{ CarryVoice() }

// put queues a frame without waiting; a stopped leg loses it, and so does a
// full one, which says so: the frame never reached the wire.
func (l *dupLeg) put(frame []byte) (full bool) {
	return l.queueFrame(legFrame{b: frame, at: time.Now()})
}

func (l *dupLeg) queueFrame(f legFrame) (full bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return false
	}
	select {
	case l.queue <- f:
		return false
	default:
		return true
	}
}

func (l *dupLeg) voice() bool { return uint8(l.lane.Load()) == dup.LaneVoice }

// write sends the leg's frames in order. A stream carrier drops an answer
// that waited longer than datagram.StaleAfter: it would come too late to be
// of use (v1.05).
func (l *dupLeg) write() {
	stream := l.c.via() == dup.ViaStream
	for f := range l.queue {
		if stream && !f.keep && time.Since(f.at) > datagram.StaleAfter {
			l.s.mu.Lock()
			l.s.staleStream++
			l.s.mu.Unlock()
			continue
		}
		if l.c.writeFrame(f.b) != nil {
			l.c.close()
			for range l.queue {
			}
			return
		}
	}
}

func (l *dupLeg) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.done {
		l.done = true
		close(l.queue)
	}
}

type dupSession struct {
	hub  *DupHub
	id   dupKey
	sock *net.UDPConn

	mu       sync.Mutex
	legs     map[*dupLeg]struct{}
	ledger   dup.Ledger
	booked   bool   // counted in a period already
	endedBy  string // why it ended, for its last period
	unbook   func()
	downSeq  uint64
	timer    *time.Timer
	ended    bool
	resolved map[string]netip.AddrPort // only the up path touches it
	names    sync.Map                  // netip.AddrPort -> M.Socksaddr
	// Answers a leg's queue had no room for, by the leg's channel.
	fullDatagram, fullStream int64
	// What the legs' channels dropped and how long frames waited (v1.05),
	// taken from the datagram legs and the stream legs' queues.
	staleDatagram, staleStream, rxDrop int64
	queueMS                            observe.Dist
}

// absorb takes what a datagram leg's channel counted into the session; s.mu
// is held.
func (s *dupSession) absorb(leg *dupLeg) {
	if leg.stats == nil {
		return
	}
	st := leg.stats.TakeStats()
	s.staleDatagram += st.Stale
	s.rxDrop += st.RxDrop
	s.queueMS.Merge(&st.Queue)
}

// up sends the first copy of a client packet out of the exit socket.
func (s *dupSession) up(ctx context.Context, f dup.Frame, via dup.Via) {
	s.mu.Lock()
	fresh := s.ledger.Accept(f.Seq, via, time.Now())
	if fresh {
		s.timer.Reset(s.hub.idle)
	}
	s.mu.Unlock()
	if !fresh {
		return
	}
	key := f.Addr.String()
	s.mu.Lock()
	ap, ok := s.resolved[key]
	s.mu.Unlock()
	if !ok {
		var err error
		if ap, err = s.hub.exit.Resolve(ctx, f.Addr); err != nil {
			return
		}
		s.mu.Lock()
		if len(s.resolved) < maxResolved {
			s.resolved[key] = ap
		}
		s.mu.Unlock()
		if f.Addr.IsFqdn() {
			s.names.Store(ap, f.Addr)
		}
	}
	_, _ = s.sock.WriteToUDPAddrPort(f.Payload, ap)
}

// down numbers every answer once and queues it on the legs of its lane. A
// voice-sized answer goes by every voice leg and, unless one of them is a
// datagram carrier, by the whole-lane legs too: voice always has a datagram
// copy beside the stream copy, as the client sends it. Anything larger goes
// by the whole-lane legs, or by every leg while only voice legs are left (a
// client re-attaches its stream carrier to the whole lane when its datagram
// carrier dies).
func (s *dupSession) down() {
	b := make([]byte, 65535)
	for {
		n, from, err := s.sock.ReadFromUDPAddrPort(b)
		if err != nil {
			return
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		src := M.SocksaddrFromNetIP(from)
		if name, ok := s.names.Load(from); ok {
			src = name.(M.Socksaddr)
		}
		voiceSized := dup.IsVoiceSized(n)
		s.mu.Lock()
		s.downSeq++
		seq := s.downSeq
		s.timer.Reset(s.hub.idle)
		var voice, whole []*dupLeg
		voiceDatagram := false
		for leg := range s.legs {
			if leg.voice() {
				voice = append(voice, leg)
				_, isPacket := leg.c.(*packetCarrier)
				voiceDatagram = voiceDatagram || isPacket
			} else {
				whole = append(whole, leg)
			}
		}
		s.mu.Unlock()
		var lane []*dupLeg
		switch {
		case voiceSized && voiceDatagram:
			lane = voice
		case voiceSized:
			lane = append(voice, whole...)
		case len(whole) > 0:
			lane = whole
		default:
			lane = voice
		}
		frame, err := dup.Append(nil, dup.Frame{Kind: dup.KindPacket, Session: s.id.id, Seq: seq, Addr: src, Payload: b[:n]})
		if err != nil {
			continue
		}
		var fullDatagram, fullStream int64
		for _, leg := range lane {
			if leg.put(frame) {
				if leg.c.via() == dup.ViaDatagram {
					fullDatagram++
				} else {
					fullStream++
				}
			}
		}
		if fullDatagram+fullStream > 0 {
			s.mu.Lock()
			s.fullDatagram += fullDatagram
			s.fullStream += fullStream
			s.mu.Unlock()
		}
	}
}

// detach removes a leg; the last one leaves the session the grace period.
func (s *dupSession) detach(leg *dupLeg) {
	s.mu.Lock()
	if _, ok := s.legs[leg]; ok {
		s.absorb(leg)
	}
	delete(s.legs, leg)
	left := len(s.legs)
	if left == 0 && !s.ended {
		s.timer.Reset(s.hub.grace)
	}
	s.mu.Unlock()
	leg.stop()
}

// end closes the socket and every leg and forgets the session.
func (s *dupSession) end() {
	s.hub.mu.Lock()
	if s.hub.sessions[s.id] == s {
		delete(s.hub.sessions, s.id)
	}
	s.hub.mu.Unlock()
	s.mu.Lock()
	s.ended = true
	legs := s.legs
	for leg := range legs {
		s.absorb(leg)
	}
	s.legs = map[*dupLeg]struct{}{}
	s.endedBy = observe.EndIdle
	if len(legs) == 0 {
		s.endedBy = observe.EndGone
	}
	s.ledger.Close()
	s.mu.Unlock()
	s.unbook()
	_ = s.sock.Close()
	for leg := range legs {
		leg.c.close()
		leg.stop()
	}
}

// take adds the session's period to p; the Book calls it.
func (s *dupSession) take(p *observe.Period) {
	if p.Dup == nil {
		p.Dup = &observe.Dup{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p.Dup.Sessions++
	if !s.booked {
		p.Dup.Opened++
		s.booked = true
	}
	if s.endedBy != "" {
		p.Dup.Ends.Add(s.endedBy)
	}
	s.ledger.Take(p.Dup)
	p.Dup.FullDatagram += s.fullDatagram
	p.Dup.FullStream += s.fullStream
	s.fullDatagram, s.fullStream = 0, 0
	for leg := range s.legs {
		s.absorb(leg)
	}
	p.Dup.StaleDatagram += s.staleDatagram
	p.Dup.StaleStream += s.staleStream
	p.Dup.RxDrop += s.rxDrop
	p.Dup.QueueMS.Merge(&s.queueMS)
	s.staleDatagram, s.staleStream, s.rxDrop, s.queueMS = 0, 0, 0, observe.Dist{}
}

type packetCarrier struct {
	conn  N.PacketConn
	count func(up, down int)
}

func (p *packetCarrier) readFrame() (dup.Frame, error) {
	for {
		b := buf.NewPacket()
		_, err := p.conn.ReadPacket(b)
		if err != nil {
			b.Release()
			return dup.Frame{}, err
		}
		if p.count != nil {
			p.count(b.Len(), 0)
		}
		// The frame outlives this read only until up() has written it.
		data := append([]byte(nil), b.Bytes()...)
		b.Release()
		f, err := dup.Decode(data)
		if errors.Is(err, dup.ErrFrame) || errors.Is(err, dup.ErrVersion) {
			continue
		}
		return f, err
	}
}

func (p *packetCarrier) writeFrame(frame []byte) error {
	b := buf.NewSize(len(frame))
	_, _ = b.Write(frame)
	if err := p.conn.WritePacket(b, dup.HostAddr()); err != nil {
		return err
	}
	if p.count != nil {
		p.count(0, len(frame))
	}
	return nil
}

func (p *packetCarrier) close() { _ = p.conn.Close() }

func (p *packetCarrier) via() dup.Via { return dup.ViaDatagram }

type streamCarrier struct {
	conn net.Conn
	buf  []byte
	wmu  sync.Mutex
}

func (s *streamCarrier) readFrame() (dup.Frame, error) {
	data, err := dup.ReadStream(s.conn, s.buf)
	if err != nil {
		return dup.Frame{}, err
	}
	return dup.Decode(data)
}

func (s *streamCarrier) writeFrame(frame []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return dup.WriteStream(s.conn, frame)
}

func (s *streamCarrier) close() { _ = s.conn.Close() }

func (s *streamCarrier) via() dup.Via { return dup.ViaStream }
