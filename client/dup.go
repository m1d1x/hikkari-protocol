package client

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
	M "github.com/sagernet/sing/common/metadata"
)

// A call is a flow of small packets at a steady rate (Opus: 20 ms frames, 50
// per second, tens to a few hundred bytes). A second of it turns the call's
// carriers on; VoiceOff seconds without it turn the stream copy off.
//
// v1.02 relays see the flow whole: a flow is a call only while all of it is
// voice-shaped (at most VoiceMaxBytes on average), because such a relay sends
// every answer by every carrier. With a relay that keeps lanes (v1.03) only
// the voice-sized packets count, so a call with video in the same socket, as
// Discord and browsers send it, is still a call; its video stays on the
// datagram channel's whole lane.
const (
	VoiceMinPPS   = 15
	VoiceMaxPPS   = 120
	VoiceMaxBytes = 500
	VoiceOff      = 5 * time.Second
)

// Mirror is the stream copy's state, for logs and tests.
type Mirror int

const (
	MirrorOff Mirror = iota
	MirrorOn
)

// dupRedial is the pause between attempts to bring a carrier back.
const dupRedial = 2 * time.Second

// legQueue bounds the frames waiting for one carrier. A carrier that cannot
// keep up loses the newest frames, as a UDP path would; the application's
// writes never wait for a carrier.
const legQueue = 256

type inbound struct {
	payload []byte
	addr    M.Socksaddr
}

// dupConn is one UDP association of the application as a duplicated session.
//
//	primary  the datagram channel, whole lane: every packet but a call's voice
//	voice    a datagram connection of its own for calls' voice (v1.03), so
//	         voice never queues behind bulk in one QUIC connection
//	mirror   the stream channel: a call's voice, or every packet while the
//	         datagram channel is down
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

	mu           sync.Mutex
	seq          uint64
	window       dup.Window
	primary      *dupLeg // nil while down
	voice        *dupLeg // nil while off
	mirror       *dupLeg // nil while off
	redialing    bool
	voiceOpening bool
	voiceErr     time.Time // last failed voice dial
	mirrorErr    time.Time // last failed stream dial, or one running
	det          detector

	deadline     time.Time
	deadlineWake chan struct{}
}

// dupLeg is one carrier: a queue and the goroutine that drains it.
type dupLeg struct {
	lane  uint8 // guarded by dupConn.mu
	send  func([]byte) error
	shut  func()
	mu    sync.Mutex
	done  bool
	queue chan []byte
}

func newLeg(lane uint8, send func([]byte) error, shut func()) *dupLeg {
	return &dupLeg{lane: lane, send: send, shut: shut, queue: make(chan []byte, legQueue)}
}

// put queues a frame without waiting; false when the carrier is gone or full.
func (l *dupLeg) put(frame []byte) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return false
	}
	select {
	case l.queue <- frame:
		return true
	default:
		return false
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

func newDupConn(ctx context.Context, c *Client, primary net.PacketConn) *dupConn {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d := &dupConn{c: c, ctx: ctx, cancel: cancel, in: make(chan inbound, 256), deadlineWake: make(chan struct{})}
	_, _ = rand.Read(d.id[:])
	d.primary = d.packetLeg(primary, dup.LaneAll)
	return d
}

// packetLeg starts a carrier on a datagram connection, attached to lane.
func (d *dupConn) packetLeg(p net.PacketConn, lane uint8) *dupLeg {
	leg := newLeg(lane, func(frame []byte) error {
		_, err := p.WriteTo(frame, dup.HostAddr())
		return err
	}, func() { _ = p.Close() })
	leg.put(attachFrame(d.id, lane))
	go d.drain(leg)
	go d.readPacket(leg, p)
	return leg
}

// drain sends a carrier's frames in order; a failed send ends the carrier.
func (d *dupConn) drain(leg *dupLeg) {
	for frame := range leg.queue {
		if err := leg.send(frame); err != nil {
			d.legDown(leg, err)
			break
		}
	}
	for range leg.queue {
	}
}

// WriteTo numbers the packet and queues it on the carriers of its lane. It
// never waits for a carrier: a call's voice must not sit behind the video in
// the same socket.
func (d *dupConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if d.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	dest := M.SocksaddrFromNet(addr)
	lanes := d.lanes.Load()
	voiceSized := dup.IsVoiceSized(len(p))
	d.mu.Lock()
	d.seq++
	seq := d.seq
	call := d.det.add(time.Now(), len(p), lanes)
	d.mu.Unlock()
	frame, err := dup.Append(nil, dup.Frame{Kind: dup.KindPacket, Session: d.id, Seq: seq, Addr: dest, Payload: p})
	if err != nil {
		return 0, err
	}
	d.steer(call, lanes)
	if !d.send(frame, lanes && call && voiceSized) {
		return 0, errors.New("hikkari dup: no carrier")
	}
	return len(p), nil
}

// send queues frame on its carriers. A call's voice goes by both channels:
// by the voice datagram carrier (the whole-lane one while it is not up) and by
// the stream copy. Anything else goes on the whole lane: the datagram carrier,
// and the stream copy only while it carries the whole lane. Without lanes (a
// v1.02 relay) the stream copy, when on, carries everything.
func (d *dupConn) send(frame []byte, voice bool) bool {
	d.mu.Lock()
	var legs []*dupLeg
	switch {
	case voice && d.voice != nil:
		legs = append(legs, d.voice)
	case d.primary != nil:
		legs = append(legs, d.primary)
	}
	if d.mirror != nil && (voice || d.mirror.lane == dup.LaneAll || !d.lanes.Load()) {
		legs = append(legs, d.mirror)
	}
	d.mu.Unlock()
	sent := false
	for _, leg := range legs {
		if leg.put(frame) {
			sent = true
		}
	}
	return sent
}

// steer brings the carriers in line with the flow: the stream copy is on for
// a call or while the datagram channel is down, on the voice lane only while
// a lanes relay has the datagram channel for the rest; the voice datagram
// carrier comes up for a call when the relay keeps lanes.
func (d *dupConn) steer(call, lanes bool) {
	d.mu.Lock()
	wantMirror := call || d.primary == nil
	lane := dup.LaneAll
	if lanes && d.primary != nil {
		lane = dup.LaneVoice
	}
	var drop *dupLeg
	openMirror, openVoice := false, false
	switch {
	case !wantMirror && d.mirror != nil:
		drop, d.mirror = d.mirror, nil
	case wantMirror && d.mirror != nil && d.mirror.lane != lane:
		if d.mirror.put(attachFrame(d.id, lane)) {
			d.mirror.lane = lane
		}
	case wantMirror && d.mirror == nil && time.Since(d.mirrorErr) >= dupRedial:
		d.mirrorErr = time.Now() // no second dial while this one runs
		openMirror = true
	}
	if call && lanes && d.voice == nil && !d.voiceOpening && d.c.opts.VoiceDatagram != nil && time.Since(d.voiceErr) >= dupRedial {
		d.voiceOpening = true
		openVoice = true
	}
	d.mu.Unlock()
	if drop != nil {
		drop.close()
		d.c.opts.Logger.DebugContext(d.ctx, "dup: stream copy off")
	}
	if openMirror {
		go d.openMirror(lane)
	}
	if openVoice {
		go d.openVoice()
	}
}

func (d *dupConn) openMirror(lane uint8) {
	ctx, cancel := context.WithTimeout(d.ctx, d.c.opts.ConnectTimeout)
	conn, err := d.c.opts.Stream.DialContext(ctx, "tcp", dup.HostAddr())
	cancel()
	if err != nil {
		d.c.opts.Logger.DebugContext(d.ctx, "dup: stream copy failed: ", err)
		return
	}
	leg := newLeg(lane, func(frame []byte) error { return dup.WriteStream(conn, frame) }, func() { _ = conn.Close() })
	leg.put(attachFrame(d.id, lane))
	d.mu.Lock()
	if d.mirror != nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		leg.close()
		return
	}
	d.mirror = leg
	d.mirrorErr = time.Time{}
	d.mu.Unlock()
	d.c.opts.Logger.DebugContext(d.ctx, "dup: stream copy on")
	go d.drain(leg)
	go d.readStream(leg, conn)
}

// openVoice brings up the voice datagram carrier. Its failure says nothing of
// the datagram channel, so it does not mark the channel bad.
func (d *dupConn) openVoice() {
	ctx, cancel := context.WithTimeout(d.ctx, d.c.opts.ConnectTimeout)
	p, err := d.c.opts.VoiceDatagram.ListenPacket(ctx, dup.HostAddr())
	cancel()
	d.mu.Lock()
	d.voiceOpening = false
	if err != nil {
		d.voiceErr = time.Now()
		d.mu.Unlock()
		d.c.opts.Logger.DebugContext(d.ctx, "dup: voice carrier failed: ", err)
		return
	}
	if d.voice != nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		_ = p.Close()
		return
	}
	d.voice = d.packetLeg(p, dup.LaneVoice)
	d.mu.Unlock()
	d.c.opts.Logger.DebugContext(d.ctx, "dup: voice carrier on")
}

func (d *dupConn) readStream(leg *dupLeg, conn net.Conn) {
	b := make([]byte, dup.MaxFrame)
	for {
		data, err := dup.ReadStream(conn, b)
		if err != nil {
			d.legDown(leg, err)
			return
		}
		d.deliver(data)
	}
}

func (d *dupConn) readPacket(leg *dupLeg, p net.PacketConn) {
	b := make([]byte, 65535)
	for {
		n, _, err := p.ReadFrom(b)
		if err != nil {
			d.legDown(leg, err)
			return
		}
		d.deliver(b[:n])
	}
}

// legDown drops a failed carrier. A lost datagram carrier puts the stream copy
// on the whole lane while a new one is brought back under the same session.
func (d *dupConn) legDown(leg *dupLeg, err error) {
	d.mu.Lock()
	primaryLost, redial := false, false
	switch leg {
	case d.primary:
		d.primary = nil
		primaryLost = true
		redial = !d.redialing && d.ctx.Err() == nil
		d.redialing = d.redialing || redial
	case d.voice:
		d.voice = nil
		d.voiceErr = time.Now()
	case d.mirror:
		d.mirror = nil
		d.mirrorErr = time.Now()
	default:
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()
	leg.close()
	if d.ctx.Err() != nil {
		return
	}
	if !primaryLost {
		return
	}
	d.c.opts.Logger.DebugContext(d.ctx, "dup: datagram carrier down: ", err)
	d.steer(true, d.lanes.Load())
	if redial {
		go d.redialPrimary()
	}
}

func (d *dupConn) redialPrimary() {
	defer func() { d.mu.Lock(); d.redialing = false; d.mu.Unlock() }()
	for d.ctx.Err() == nil {
		if d.c.datagramUp() {
			var p net.PacketConn
			err := d.c.tryDatagram(d.ctx, func(ctx context.Context) (err error) {
				p, err = d.c.opts.Datagram.ListenPacket(ctx, dup.HostAddr())
				return
			})
			if err == nil {
				d.mu.Lock()
				if d.ctx.Err() != nil {
					d.mu.Unlock()
					_ = p.Close()
					return
				}
				d.primary = d.packetLeg(p, dup.LaneAll)
				d.mu.Unlock()
				return
			}
		}
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(dupRedial):
		}
	}
}

// deliver hands the first copy of an answer to the application. An attach
// from the relay says it keeps lanes.
func (d *dupConn) deliver(data []byte) {
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
	fresh := d.window.Accept(f.Seq)
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
	legs := []*dupLeg{d.primary, d.voice, d.mirror}
	d.primary, d.voice, d.mirror = nil, nil, nil
	d.mu.Unlock()
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

// MirrorState reports whether the stream copy is on.
func (d *dupConn) MirrorState() Mirror {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.mirror != nil {
		return MirrorOn
	}
	return MirrorOff
}

// detector tells a call from other UDP by the last whole second of packets
// the application sent.
type detector struct {
	second    time.Time // start of the current second
	packets   int
	bytes     int
	small     int // voice-sized packets
	voiceTill time.Time
}

// add counts one packet and reports whether the flow is a call now. lanes
// counts only voice-sized packets (v1.03), otherwise the whole flow must be
// voice-shaped (v1.02).
func (t *detector) add(now time.Time, size int, lanes bool) bool {
	if t.second.IsZero() {
		t.second = now
	}
	if now.Sub(t.second) >= time.Second {
		if now.Sub(t.second) < 2*time.Second && t.call(lanes) {
			t.voiceTill = now.Add(VoiceOff)
		}
		t.second, t.packets, t.bytes, t.small = now, 0, 0, 0
	}
	t.packets++
	t.bytes += size
	if dup.IsVoiceSized(size) {
		t.small++
	}
	return now.Before(t.voiceTill)
}

func (t *detector) call(lanes bool) bool {
	if lanes {
		return t.small >= VoiceMinPPS && t.small <= VoiceMaxPPS
	}
	return t.packets >= VoiceMinPPS && t.packets <= VoiceMaxPPS && t.bytes <= VoiceMaxBytes*t.packets
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}
