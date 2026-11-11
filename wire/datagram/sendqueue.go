package datagram

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/buf"
)

// StaleAfter is the longest a frame may wait in this end's queues before the
// wire (v1.05): live UDP (a call, a game, a screen share) has no use for a
// frame later than this, and holding it only delays the next one. A frame
// older than this is dropped unsent and counted (ChannelStats.Stale).
const StaleAfter = 150 * time.Millisecond

// sessionLimit bounds what one association may hold in the scheduler; over
// it the oldest frames of that association are dropped (and counted stale).
const sessionLimit = 256 << 10

// quantum is the bytes each association may send in its turn of the round.
const quantum = 1500

// defaultMTU is the largest message the scheduler sends unfragmented until
// the connection says it takes less (as udpPacketConn sized it before).
const defaultMTU = 1200 - 3

// datagramSender is the QUIC connection as the scheduler uses it.
type datagramSender interface {
	SendDatagram(p []byte) error
}

// sendQueue is the one sender of DATAGRAM frames on a QUIC connection
// (v1.05, "the datagram channel is a pipe"). Writers put a message and return
// at once; one goroutine sends the associations' messages round by round,
// quantum bytes each a turn (deficit round robin), so a bulk association does
// not delay a game's beside it. Each message carries the time it was put: one
// older than staleAfter right before the wire is dropped and counted, the
// oldest first, so the freshest frame of live traffic is the one that goes.
// A message of several fragments goes, or is dropped, whole.
type sendQueue struct {
	conn       datagramSender
	sender     string // the connection's congestion controller
	done       <-chan struct{}
	staleAfter time.Duration
	limit      int

	// pace, when set, is the connection's rate limit in bytes a second (0:
	// none); the scheduler keeps to it, so QUIC's own queue stays short.
	pace   atomic.Pointer[func() float64]
	budget float64
	refill time.Time
	// ceiling, when set, is the key's limit on a relay (Ceiling).
	ceiling atomic.Pointer[Ceiling]

	mu       sync.Mutex
	mtu      int
	sessions map[uint32]*sessionQueue
	round    []*sessionQueue // associations with frames waiting, in turn order
	closed   bool
	wake     chan struct{}
}

// sessionQueue is one association's waiting messages.
type sessionQueue struct {
	id      uint32
	items   []*queuedMessage
	bytes   int
	deficit int
	inRound bool
}

// queuedMessage is one UDP message the association wrote, copied: the
// writer's buffer is its own again once put returns.
type queuedMessage struct {
	owner       *udpPacketConn
	packetID    uint16
	destination string
	data        []byte
	at          time.Time
}

func (m *queuedMessage) size() int { return len(m.data) + len(m.destination) + 8 }

func newSendQueue(conn datagramSender, done <-chan struct{}) *sendQueue {
	q := &sendQueue{
		conn:       conn,
		done:       done,
		staleAfter: StaleAfter,
		limit:      sessionLimit,
		mtu:        defaultMTU,
		sessions:   map[uint32]*sessionQueue{},
		wake:       make(chan struct{}, 1),
	}
	go q.run()
	return q
}

// newConnSendQueue is the scheduler of a QUIC connection, gone with it; sender
// is the connection's congestion controller.
func newConnSendQueue(conn *quic.Conn, sender string) *sendQueue {
	q := newSendQueue(conn, conn.Context().Done())
	q.sender = sender
	return q
}

func (q *sendQueue) paceBy(rate func() float64) { q.pace.Store(&rate) }

// keepPace waits until n bytes fit the connection's rate limit, if it has one.
func (q *sendQueue) keepPace(n int) {
	f := q.pace.Load()
	if f == nil {
		return
	}
	rate := (*f)()
	if rate <= 0 {
		q.budget, q.refill = 0, time.Time{}
		return
	}
	now := time.Now()
	if q.refill.IsZero() {
		q.refill = now
	}
	burst := max(rate*guardBurst.Seconds(), 2*quantum)
	q.budget = min(burst, q.budget+rate*now.Sub(q.refill).Seconds())
	q.refill = now
	if q.budget < float64(n) {
		wait := time.Duration((float64(n) - q.budget) / rate * float64(time.Second))
		select {
		case <-time.After(wait):
		case <-q.done:
		}
		q.budget, q.refill = float64(n), time.Now()
	}
	q.budget -= float64(n)
}

// put queues m for its association and never waits. Over the association's
// memory the oldest of its messages are dropped.
func (q *sendQueue) put(m *queuedMessage) error {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return net.ErrClosed
	}
	s := q.sessions[m.owner.sessionID]
	if s == nil {
		s = &sessionQueue{id: m.owner.sessionID}
		q.sessions[s.id] = s
	}
	var dropped []*queuedMessage
	for len(s.items) > 0 && s.bytes+m.size() > q.limit {
		dropped = append(dropped, s.pop())
	}
	s.items = append(s.items, m)
	s.bytes += m.size()
	if !s.inRound {
		s.inRound = true
		q.round = append(q.round, s)
	}
	q.mu.Unlock()
	for _, d := range dropped {
		d.owner.stats.stale(1)
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (s *sessionQueue) pop() *queuedMessage {
	m := s.items[0]
	s.items[0] = nil
	s.items = s.items[1:]
	s.bytes -= m.size()
	return m
}

// forget drops an association's waiting messages: it has closed.
func (q *sendQueue) forget(id uint32) {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.sessions[id]
	if s == nil {
		return
	}
	delete(q.sessions, id)
	s.items, s.bytes = nil, 0
	for i, r := range q.round {
		if r == s {
			q.round = append(q.round[:i], q.round[i+1:]...)
			break
		}
	}
}

// next takes the messages of the next association's turn, waiting for one.
func (q *sendQueue) next() ([]*queuedMessage, bool) {
	q.mu.Lock()
	for len(q.round) == 0 {
		q.mu.Unlock()
		select {
		case <-q.done:
			q.close()
			return nil, false
		case <-q.wake:
		}
		q.mu.Lock()
	}
	s := q.round[0]
	q.round = q.round[1:]
	s.deficit += quantum
	var turn []*queuedMessage
	for len(s.items) > 0 && s.items[0].size() <= s.deficit {
		m := s.pop()
		s.deficit -= m.size()
		turn = append(turn, m)
	}
	if len(s.items) > 0 {
		q.round = append(q.round, s)
	} else {
		s.inRound, s.deficit = false, 0
		if q.sessions[s.id] == s {
			delete(q.sessions, s.id)
		}
	}
	q.mu.Unlock()
	return turn, true
}

func (q *sendQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.sessions, q.round = map[uint32]*sessionQueue{}, nil
	q.mu.Unlock()
}

func (q *sendQueue) run() {
	for {
		turn, ok := q.next()
		if !ok {
			return
		}
		for _, m := range turn {
			// Over the limit or the key's ceiling the frame waits here, where
			// it is judged by age.
			q.keepPace(m.size())
			if wait := q.ceiling.Load().take(m.size()); wait > 0 {
				select {
				case <-time.After(wait):
				case <-q.done:
				}
			}
			// The age is read right before the wire: the connection's own
			// queue may have held this goroutine.
			wait := time.Since(m.at)
			if wait > q.staleAfter {
				m.owner.stats.stale(1)
				continue
			}
			if err := q.send(m); err != nil {
				select {
				case <-q.done:
					q.close()
					return
				default:
				}
				continue
			}
			m.owner.stats.sent(wait)
		}
	}
}

// send writes m, in fragments when it is larger than the connection takes.
// A connection that says it takes less than thought gets the smaller size
// from then on and m again in fragments of it.
func (q *sendQueue) send(m *queuedMessage) error {
	q.mu.Lock()
	mtu := q.mtu
	q.mu.Unlock()
	err := q.sendSized(m, mtu)
	var tooLarge *quic.DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		return err
	}
	smaller := int(tooLarge.MaxDatagramPayloadSize - 3)
	if smaller <= (&udpMessage{destination: m.destination}).headerSize() {
		return err
	}
	q.mu.Lock()
	q.mtu = min(q.mtu, smaller)
	q.mu.Unlock()
	return q.sendSized(m, smaller)
}

func (m *queuedMessage) message() *udpMessage {
	message := allocMessage()
	*message = udpMessage{
		sessionID:     m.owner.sessionID,
		packetID:      m.packetID,
		fragmentTotal: 1,
		destination:   m.destination,
		data:          buf.As(m.data),
		referenced:    true,
	}
	return message
}

func (q *sendQueue) sendSized(m *queuedMessage, mtu int) error {
	message := m.message()
	defer message.release()
	fragments := []*udpMessage{message}
	if mtu > message.headerSize() && len(m.data) > mtu-message.headerSize() {
		fragments = fragUDPMessage(message, mtu)
		defer func() {
			for _, f := range fragments {
				f.release()
			}
		}()
	}
	for _, f := range fragments {
		packed := f.pack()
		err := q.conn.SendDatagram(packed.Bytes())
		packed.Release()
		if err != nil {
			return err
		}
	}
	return nil
}

// ChannelStats is what one association's datagram channel did since the
// last take (v1.05 observability).
type ChannelStats struct {
	// Stale are messages the scheduler dropped unsent (StaleAfter, or the
	// association's memory).
	Stale int64
	// RxDrop are received messages the association had no room for.
	RxDrop int64
	// Queue is how long each message sent waited in the scheduler, in ms.
	Queue observe.Dist
}

// channelStats counts for one association.
type channelStats struct {
	mu  sync.Mutex
	cur ChannelStats
}

func (c *channelStats) stale(n int64) {
	c.mu.Lock()
	c.cur.Stale += n
	c.mu.Unlock()
}

func (c *channelStats) rxDrop() {
	c.mu.Lock()
	c.cur.RxDrop++
	c.mu.Unlock()
}

func (c *channelStats) sent(wait time.Duration) {
	c.mu.Lock()
	c.cur.Queue.Add(observe.Ms(wait))
	c.mu.Unlock()
}

func (c *channelStats) take() ChannelStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.cur
	c.cur = ChannelStats{}
	return out
}

// TakeStats hands out what the association's channel did since the last
// take: the dup layer adds it to its session's period.
func (c *udpPacketConn) TakeStats() ChannelStats { return c.stats.take() }
