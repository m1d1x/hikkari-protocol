package client

// A carrier of a duplicated session (v1.02): a queue of frames and the
// goroutine that drains it to one channel.

import (
	"sync"
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/wire/datagram"
)

// legQueue bounds the frames waiting for one carrier. A carrier that cannot
// keep up loses the newest frames, as a UDP path would; the application's
// writes never wait for a carrier. A datagram carrier hands its frames on at
// once to the connection's scheduler, where they wait by their age (v1.05);
// the stream copy's own queue drops a frame older than datagram.StaleAfter
// before its write.
const legQueue = 256

// legFrame is a frame in a carrier's queue: when it was queued, and whether
// it must go whatever its age (an attach).
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

// dupLeg is one carrier: a queue and the goroutine that drains it.
type dupLeg struct {
	lane  uint8 // guarded by dupConn.mu
	via   dup.Via
	send  func([]byte) error
	shut  func()
	stats channelStats // a datagram carrier's; nil for the stream copy
	mu    sync.Mutex
	done  bool
	queue chan legFrame
}

func newLeg(lane uint8, via dup.Via, send func([]byte) error, shut func()) *dupLeg {
	return &dupLeg{lane: lane, via: via, send: send, shut: shut, queue: make(chan legFrame, legQueue)}
}

// put queues an attach without waiting; false when the carrier is gone or
// full. An attach goes whatever its age.
func (l *dupLeg) put(frame []byte) bool {
	ok, _ := l.queueFrame(legFrame{b: frame, at: time.Now(), keep: true})
	return ok
}

// offer queues a packet's frame and also says whether a refused frame found
// the queue full, so it never reached the wire.
func (l *dupLeg) offer(frame []byte) (ok, full bool) {
	return l.queueFrame(legFrame{b: frame, at: time.Now()})
}

func (l *dupLeg) queueFrame(f legFrame) (ok, full bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return false, false
	}
	select {
	case l.queue <- f:
		return true, false
	default:
		return false, true
	}
}

func (l *dupLeg) close() {
	l.mu.Lock()
	if !l.done {
		l.done = true
		close(l.queue)
	}
	l.mu.Unlock()
	l.shut()
}

func attachFrame(id dup.Session, lane uint8) []byte {
	frame, _ := dup.Append(nil, dup.Frame{Kind: dup.KindAttach, Session: id, Lane: lane})
	return frame
}
