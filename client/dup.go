package client

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	M "github.com/sagernet/sing/common/metadata"
)

// Voice is the shape of a flow worth carrying twice: a call sends small
// packets at a steady rate (Opus: 20 ms frames, 50 per second, tens to a few
// hundred bytes). A second of such traffic turns the stream copy on; VoiceOff
// seconds without it turn it off. Video and downloads never qualify.
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

type inbound struct {
	payload []byte
	addr    M.Socksaddr
}

// dupConn is one UDP association of the application as a duplicated session:
// every packet goes by the datagram channel and, while the flow looks like a
// call or the datagram channel is down, by the stream channel too. Answers are
// taken from whichever channel brings them first.
type dupConn struct {
	c      *Client
	ctx    context.Context
	cancel context.CancelFunc
	id     dup.Session
	in     chan inbound

	mu        sync.Mutex
	seq       uint64
	window    dup.Window
	primary   net.PacketConn // datagram carrier; nil while down
	redialing bool
	mirror    *streamLeg // stream carrier; nil while off
	mirrorErr time.Time  // last failed stream dial
	det       detector

	deadline     time.Time
	deadlineWake chan struct{}
}

type streamLeg struct {
	conn  net.Conn
	queue chan []byte
}

func newDupConn(ctx context.Context, c *Client, primary net.PacketConn) *dupConn {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	d := &dupConn{c: c, ctx: ctx, cancel: cancel, in: make(chan inbound, 256), primary: primary, deadlineWake: make(chan struct{})}
	_, _ = rand.Read(d.id[:])
	go d.readPrimary(primary)
	_ = d.writeAttach(primary)
	return d
}

func (d *dupConn) writeAttach(p net.PacketConn) error {
	frame, _ := dup.Append(nil, dup.Frame{Kind: dup.KindAttach, Session: d.id})
	_, err := p.WriteTo(frame, dup.HostAddr())
	return err
}

// WriteTo numbers the packet and sends it by every live carrier.
func (d *dupConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if d.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	dest := M.SocksaddrFromNet(addr)
	d.mu.Lock()
	d.seq++
	seq := d.seq
	voice := d.det.add(time.Now(), len(p))
	primary := d.primary
	d.mu.Unlock()
	frame, err := dup.Append(nil, dup.Frame{Kind: dup.KindPacket, Session: d.id, Seq: seq, Addr: dest, Payload: p})
	if err != nil {
		return 0, err
	}
	d.steer(voice || primary == nil)
	sent := false
	if primary != nil {
		if _, err := primary.WriteTo(frame, dup.HostAddr()); err == nil {
			sent = true
		} else {
			d.primaryDown(primary, err)
		}
	}
	d.mu.Lock()
	mirror := d.mirror
	d.mu.Unlock()
	if mirror != nil {
		select {
		case mirror.queue <- frame:
			sent = true
		default:
		}
	}
	if !sent {
		return 0, errors.New("hikkari dup: no carrier")
	}
	return len(p), nil
}

// steer turns the stream copy on or off.
func (d *dupConn) steer(want bool) {
	d.mu.Lock()
	on := d.mirror != nil
	if want == on {
		d.mu.Unlock()
		return
	}
	if !want {
		leg := d.mirror
		d.mirror = nil
		d.mu.Unlock()
		close(leg.queue)
		_ = leg.conn.Close()
		d.c.opts.Logger.DebugContext(d.ctx, "dup: stream copy off")
		return
	}
	if time.Since(d.mirrorErr) < dupRedial {
		d.mu.Unlock()
		return
	}
	d.mirrorErr = time.Now() // no second dial while this one runs
	d.mu.Unlock()
	go d.openMirror()
}

func (d *dupConn) openMirror() {
	ctx, cancel := context.WithTimeout(d.ctx, d.c.opts.ConnectTimeout)
	conn, err := d.c.opts.Stream.DialContext(ctx, "tcp", dup.HostAddr())
	cancel()
	if err != nil {
		d.c.opts.Logger.DebugContext(d.ctx, "dup: stream copy failed: ", err)
		return
	}
	frame, _ := dup.Append(nil, dup.Frame{Kind: dup.KindAttach, Session: d.id})
	if dup.WriteStream(conn, frame) != nil {
		_ = conn.Close()
		return
	}
	leg := &streamLeg{conn: conn, queue: make(chan []byte, 256)}
	d.mu.Lock()
	if d.mirror != nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		_ = conn.Close()
		return
	}
	d.mirror = leg
	d.mirrorErr = time.Time{}
	d.mu.Unlock()
	d.c.opts.Logger.DebugContext(d.ctx, "dup: stream copy on")
	go func() {
		for frame := range leg.queue {
			if dup.WriteStream(conn, frame) != nil {
				break
			}
		}
		_ = conn.Close()
	}()
	go d.readStream(leg)
}

func (d *dupConn) readStream(leg *streamLeg) {
	b := make([]byte, dup.MaxFrame)
	for {
		data, err := dup.ReadStream(leg.conn, b)
		if err != nil {
			break
		}
		d.deliver(data)
	}
	d.mu.Lock()
	if d.mirror == leg {
		d.mirror = nil
		close(leg.queue)
		d.mirrorErr = time.Now()
	}
	d.mu.Unlock()
}

func (d *dupConn) readPrimary(p net.PacketConn) {
	b := make([]byte, 65535)
	for {
		n, _, err := p.ReadFrom(b)
		if err != nil {
			d.primaryDown(p, err)
			return
		}
		d.deliver(b[:n])
	}
}

// primaryDown drops a failed datagram carrier; the stream copy carries the
// session while a new datagram carrier is brought back under the same session.
func (d *dupConn) primaryDown(p net.PacketConn, err error) {
	d.mu.Lock()
	if d.primary != p {
		d.mu.Unlock()
		return
	}
	d.primary = nil
	start := !d.redialing && d.ctx.Err() == nil
	d.redialing = d.redialing || start
	d.mu.Unlock()
	_ = p.Close()
	if d.ctx.Err() != nil {
		return
	}
	d.c.opts.Logger.DebugContext(d.ctx, "dup: datagram carrier down: ", err)
	d.steer(true)
	if start {
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
			if err == nil && d.writeAttach(p) == nil {
				d.mu.Lock()
				if d.ctx.Err() != nil {
					d.mu.Unlock()
					_ = p.Close()
					return
				}
				d.primary = p
				d.mu.Unlock()
				go d.readPrimary(p)
				return
			}
			if p != nil {
				_ = p.Close()
			}
		}
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(dupRedial):
		}
	}
}

func (d *dupConn) deliver(data []byte) {
	f, err := dup.Decode(data)
	if err != nil || f.Kind != dup.KindPacket || f.Session != d.id {
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
	primary, mirror := d.primary, d.mirror
	d.primary, d.mirror = nil, nil
	d.mu.Unlock()
	if primary != nil {
		_ = primary.Close()
	}
	if mirror != nil {
		close(mirror.queue)
		_ = mirror.conn.Close()
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
	voiceTill time.Time // the stream copy stays on until then
}

func (t *detector) add(now time.Time, size int) bool {
	if t.second.IsZero() {
		t.second = now
	}
	if now.Sub(t.second) >= time.Second {
		if now.Sub(t.second) < 2*time.Second && t.packets >= VoiceMinPPS && t.packets <= VoiceMaxPPS && t.bytes <= VoiceMaxBytes*t.packets {
			t.voiceTill = now.Add(VoiceOff)
		}
		t.second, t.packets, t.bytes = now, 0, 0
	}
	t.packets++
	t.bytes += size
	return now.Before(t.voiceTill)
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}
