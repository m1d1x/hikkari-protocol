package client

// A duplicated session (v1.02, spec/v1.md "v1.02: duplicated UDP"): one UDP
// association of the application, carried by several carriers at once, each
// end delivering the first copy of every packet. With several entries (v1.07)
// a call goes by every entry: dupsteer.go decides which carriers each entry
// holds.

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Mirror is the stream copy's state, for logs and tests.
type Mirror int

const (
	MirrorOff Mirror = iota
	MirrorOn
)

// dupRedial is the pause between attempts to bring a carrier back.
const dupRedial = 2 * time.Second

type inbound struct {
	payload []byte
	addr    M.Socksaddr
}

// dupConn is one UDP association of the application as a duplicated session.
// On every entry (path) it may hold:
//
//	primary  the datagram channel: on the active entry the whole lane, every
//	         packet but a call's voice; on another entry during a call, the
//	         voice lane (v1.07)
//	voice    a datagram connection of its own for calls' voice (v1.03), so
//	         voice never queues behind bulk in one QUIC connection; the
//	         active entry's only
//	mirror   the stream channel: a call's voice, or every packet while the
//	         active entry's datagram channel is down
//
// Answers are taken from whichever carrier brings them first.
type dupConn struct {
	c      *Client
	ctx    context.Context
	cancel context.CancelFunc
	id     dup.Session
	in     chan inbound
	// lanes is set once the relay answers an attach (v1.03).
	lanes atomic.Bool

	mu     sync.Mutex
	seq    uint64
	ledger dup.Ledger
	booked bool // counted in a period already
	closed bool
	unbook func()
	paths  []dupPath // by entry
	det    detector
	pauses observe.PauseMeter
	// Frames a carrier's queue had no room for, by the carrier's channel.
	fullDatagram, fullStream int64
	// What the carriers' channels dropped and how long frames waited (v1.05),
	// taken from the datagram carriers and the stream copy's queue.
	staleDatagram, staleStream, rxDrop int64
	queueMS                            observe.Dist

	deadline     time.Time
	deadlineWake chan struct{}
}

// dupPath is a session's carriers on one entry; dupConn.mu guards it.
type dupPath struct {
	primary, voice, mirror       *dupLeg // nil while off or down
	primaryOpening, voiceOpening bool
	// The last failed dial of each carrier; mirrorErr also marks a dial
	// running.
	primaryErr, voiceErr, mirrorErr time.Time
}

func newDupConn(ctx context.Context, c *Client, at int, primary net.PacketConn) *dupConn {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d := &dupConn{c: c, ctx: ctx, cancel: cancel, in: make(chan inbound, 256), deadlineWake: make(chan struct{}),
		paths: make([]dupPath, len(c.paths))}
	_, _ = rand.Read(d.id[:])
	d.paths[at].primary = d.packetLeg(primary, dup.LaneAll)
	d.unbook = c.opts.Book.Add(Group, d.take)
	return d
}

// take adds the session's period to p; the Book calls it.
func (d *dupConn) take(p *observe.Period) {
	if p.Dup == nil {
		p.Dup = &observe.Dup{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.det.settle(time.Now())
	}
	p.Dup.Sessions++
	if !d.booked {
		p.Dup.Opened++
		d.booked = true
	}
	if d.closed {
		p.Dup.Ends.Add(observe.EndEOF)
	}
	d.ledger.Take(p.Dup)
	d.pauses.Take(p)
	p.Dup.FullDatagram += d.fullDatagram
	p.Dup.FullStream += d.fullStream
	d.fullDatagram, d.fullStream = 0, 0
	for i := range d.paths {
		d.absorb(d.paths[i].primary)
		d.absorb(d.paths[i].voice)
	}
	p.Dup.StaleDatagram += d.staleDatagram
	p.Dup.StaleStream += d.staleStream
	p.Dup.RxDrop += d.rxDrop
	p.Dup.QueueMS.Merge(&d.queueMS)
	d.staleDatagram, d.staleStream, d.rxDrop, d.queueMS = 0, 0, 0, observe.Dist{}
	if d.det.done.N > 0 {
		if p.Calls == nil {
			p.Calls = &observe.Calls{}
		}
		p.Calls.Merge(&d.det.done)
		d.det.done = observe.Calls{}
	}
}

// absorb takes what a datagram carrier's channel counted into the session;
// d.mu is held.
func (d *dupConn) absorb(leg *dupLeg) {
	if leg == nil || leg.stats == nil {
		return
	}
	s := leg.stats.TakeStats()
	d.staleDatagram += s.Stale
	d.rxDrop += s.RxDrop
	d.queueMS.Merge(&s.Queue)
}

// WriteTo numbers the packet and queues it on the carriers of its lane. It
// never waits for a carrier: a call's voice must not sit behind the video in
// the same socket.
func (d *dupConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return d.write(p, M.SocksaddrFromNet(addr))
}

// dupConn speaks sing's packet interface itself. The core hands a packet to a
// plain net.PacketConn as WriteTo(dest.UDPAddr()), and a named destination
// has no IP: the name was lost on the client and the relay dropped every such
// packet as addressed nowhere (17.11, the voice probe's series to
// stun.cloudflare.com, 0 answers of 1500). The relay resolves names itself, at
// the exit, so the name must reach it.
var _ N.NetPacketConn = (*dupConn)(nil)

func (d *dupConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := d.write(buffer.Bytes(), destination)
	return err
}

func (d *dupConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := d.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(addr), nil
}

func (d *dupConn) write(p []byte, dest M.Socksaddr) (int, error) {
	if d.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	lanes := d.lanes.Load()
	voiceSized := dup.IsVoiceSized(len(p))
	active := d.c.Active()
	d.mu.Lock()
	d.seq++
	seq := d.seq
	now := time.Now()
	call := d.det.add(now, len(p), lanes)
	d.pauses.In(now, voiceSized)
	d.mu.Unlock()
	frame, err := dup.Append(nil, dup.Frame{Kind: dup.KindPacket, Session: d.id, Seq: seq, Addr: dest, Payload: p})
	if err != nil {
		return 0, err
	}
	d.steer(call, lanes, active)
	if !d.send(frame, lanes && call && voiceSized, lanes, active) {
		return 0, errors.New("hikkari dup: no carrier")
	}
	return len(p), nil
}

// send queues frame on its carriers. A call's voice goes by every entry and
// both channels of each: by the voice datagram carrier (the primary one while
// it is not up) and by the stream copy. Anything else goes on the active
// entry's whole lane: its datagram carrier, and its stream copy only while
// that carries the whole lane; without lanes (a v1.02 relay) the stream copy,
// when on, carries everything. While the active entry has no carrier for it
// yet (it just became active), a frame goes by any whole-lane carrier left on
// another entry.
func (d *dupConn) send(frame []byte, voice, lanes bool, active int) bool {
	d.mu.Lock()
	var legs []*dupLeg
	for i := range d.paths {
		p := &d.paths[i]
		if i != active && !voice {
			continue
		}
		switch {
		case voice && p.voice != nil:
			legs = append(legs, p.voice)
		case p.primary != nil:
			legs = append(legs, p.primary)
		}
		if p.mirror != nil && (voice || p.mirror.lane == dup.LaneAll || !lanes) {
			legs = append(legs, p.mirror)
		}
	}
	if len(legs) == 0 {
		legs = d.wholeElsewhere(active)
	}
	d.mu.Unlock()
	sent := false
	var fullDatagram, fullStream int64
	for _, leg := range legs {
		ok, full := leg.offer(frame)
		sent = sent || ok
		if full && leg.via == dup.ViaDatagram {
			fullDatagram++
		} else if full {
			fullStream++
		}
	}
	if fullDatagram+fullStream > 0 {
		d.mu.Lock()
		d.fullDatagram += fullDatagram
		d.fullStream += fullStream
		d.mu.Unlock()
	}
	return sent
}

// wholeElsewhere is the first whole-lane carrier on an entry other than
// active; d.mu is held.
func (d *dupConn) wholeElsewhere(active int) []*dupLeg {
	for i := range d.paths {
		if i == active {
			continue
		}
		for _, leg := range []*dupLeg{d.paths[i].primary, d.paths[i].mirror} {
			if leg != nil && leg.lane == dup.LaneAll {
				return []*dupLeg{leg}
			}
		}
	}
	return nil
}

// deliver hands the first copy of an answer to the application. An attach
// from the relay says it keeps lanes.
func (d *dupConn) deliver(data []byte, via dup.Via) {
	f, err := dup.Decode(data)
	if err != nil || f.Session != d.id {
		return
	}
	if f.Kind == dup.KindAttach {
		d.lanes.Store(true)
		return
	}
	if f.Kind != dup.KindPacket {
		return
	}
	d.mu.Lock()
	now := time.Now()
	fresh := d.ledger.Accept(f.Seq, via, now)
	if fresh {
		d.det.answer()
		d.pauses.Out(now, dup.IsVoiceSized(len(f.Payload)), via == dup.ViaStream)
	}
	d.mu.Unlock()
	if !fresh {
		return
	}
	select {
	case d.in <- inbound{payload: append([]byte(nil), f.Payload...), addr: f.Addr}:
	case <-d.ctx.Done():
	default: // the application is not reading; UDP may drop
	}
}

func (d *dupConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		d.mu.Lock()
		deadline, wake := d.deadline, d.deadlineWake
		d.mu.Unlock()
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			timeout = timer.C
		}
		select {
		case m := <-d.in:
			stopTimer(timer)
			return copy(p, m.payload), m.addr, nil
		case <-d.ctx.Done():
			stopTimer(timer)
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-wake:
			stopTimer(timer)
		}
	}
}

func (d *dupConn) Close() error {
	d.cancel()
	d.mu.Lock()
	var legs []*dupLeg
	for i := range d.paths {
		p := &d.paths[i]
		d.absorb(p.primary)
		d.absorb(p.voice)
		legs = append(legs, p.primary, p.voice, p.mirror)
		p.primary, p.voice, p.mirror = nil, nil, nil
	}
	first := !d.closed
	if first {
		d.closed = true
		d.det.finish()
		d.ledger.Close()
	}
	d.mu.Unlock()
	if first {
		d.unbook()
	}
	for _, leg := range legs {
		if leg != nil {
			leg.close()
		}
	}
	return nil
}

func (d *dupConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }

func (d *dupConn) SetDeadline(t time.Time) error { return d.SetReadDeadline(t) }

func (d *dupConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadline = t
	close(d.deadlineWake)
	d.deadlineWake = make(chan struct{})
	d.mu.Unlock()
	return nil
}

func (d *dupConn) SetWriteDeadline(time.Time) error { return nil }

// MirrorState reports whether a stream copy is on.
func (d *dupConn) MirrorState() Mirror {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.paths {
		if d.paths[i].mirror != nil {
			return MirrorOn
		}
	}
	return MirrorOff
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}
