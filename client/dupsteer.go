package client

// Which carriers a duplicated session holds on each entry, and bringing them
// up and down (spec/v1.md "v1.02: duplicated UDP", "v1.03: lanes", "v1.07:
// several entries").

import (
	"context"
	"net"
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/wire/datagram"
)

// carrierKind names a carrier of a dupPath.
type carrierKind int

const (
	kindPrimary carrierKind = iota
	kindVoice
	kindMirror
)

type opening struct {
	path int
	kind carrierKind
	lane uint8
}

// steer brings every entry's carriers in line with the flow. The active entry
// holds the whole lane as v1.02–v1.06 do: its datagram carrier, a stream copy
// for a call or while that carrier is down (on the voice lane while a lanes
// relay has the datagram carrier for the rest), and the voice datagram
// carrier for a call. During a call with a relay that keeps lanes, every
// other entry holds a datagram carrier and a stream copy on the voice lane, so
// the call has a copy beside the active entry's when it goes silent. A silent
// entry gets no new carrier but keeps those it has.
func (d *dupConn) steer(call, lanes bool, active int) {
	d.mu.Lock()
	var drops []*dupLeg
	var opens []opening
	for i := range d.paths {
		p := &d.paths[i]
		whole := i == active
		reachable := whole || !d.c.silent(i)
		// The datagram carrier.
		wantPrimary := whole || (call && lanes)
		lane := dup.LaneAll
		if !whole {
			lane = dup.LaneVoice
		}
		switch {
		case !wantPrimary && p.primary != nil:
			d.absorb(p.primary)
			drops = append(drops, p.primary)
			p.primary = nil
		case wantPrimary && p.primary != nil && lanes && p.primary.lane != lane:
			if p.primary.put(attachFrame(d.id, lane)) {
				p.primary.lane = lane
			}
		case wantPrimary && p.primary == nil && reachable && !p.primaryOpening &&
			time.Since(p.primaryErr) >= dupRedial && d.c.datagramUp(i):
			p.primaryOpening = true
			opens = append(opens, opening{i, kindPrimary, lane})
		}
		// The stream copy.
		wantMirror := (whole && (call || p.primary == nil)) || (!whole && call && lanes)
		lane = dup.LaneAll
		if lanes && (p.primary != nil || !whole) {
			lane = dup.LaneVoice
		}
		switch {
		case !wantMirror && p.mirror != nil:
			drops = append(drops, p.mirror)
			p.mirror = nil
		case wantMirror && p.mirror != nil && p.mirror.lane != lane:
			if p.mirror.put(attachFrame(d.id, lane)) {
				p.mirror.lane = lane
			}
		case wantMirror && p.mirror == nil && reachable && time.Since(p.mirrorErr) >= dupRedial:
			p.mirrorErr = time.Now() // no second dial while this one runs
			opens = append(opens, opening{i, kindMirror, lane})
		}
		// The voice connection.
		if whole && call && lanes && p.voice == nil && !p.voiceOpening && d.c.paths[i].VoiceDatagram != nil &&
			time.Since(p.voiceErr) >= dupRedial {
			p.voiceOpening = true
			opens = append(opens, opening{i, kindVoice, dup.LaneVoice})
		}
	}
	d.mu.Unlock()
	for _, leg := range drops {
		leg.close()
	}
	for _, o := range opens {
		switch o.kind {
		case kindPrimary:
			go d.openPrimary(o.path, o.lane)
		case kindMirror:
			go d.openMirror(o.path, o.lane)
		case kindVoice:
			go d.openVoice(o.path)
		}
	}
}

// resteer steers by the flow as it is now: after a carrier came or went, not
// on the application's packet.
func (d *dupConn) resteer() {
	if d.ctx.Err() != nil {
		return
	}
	d.mu.Lock()
	call := d.det.on(time.Now())
	d.mu.Unlock()
	d.steer(call, d.lanes.Load(), d.c.Active())
}

// kick steers again after dupRedial, so a carrier that failed comes back even
// while the application sends nothing.
func (d *dupConn) kick() { time.AfterFunc(dupRedial, d.resteer) }

// openPrimary brings up entry i's datagram carrier on lane. Its failure marks
// that entry's datagram channel bad for RetryAfter, as a failed association
// does.
func (d *dupConn) openPrimary(i int, lane uint8) {
	var p net.PacketConn
	err := d.c.tryDatagram(d.ctx, i, func(ctx context.Context) (err error) {
		p, err = d.c.paths[i].Datagram.ListenPacket(ctx, dup.HostAddr())
		return
	})
	d.mu.Lock()
	dp := &d.paths[i]
	dp.primaryOpening = false
	if err != nil {
		dp.primaryErr = time.Now()
		d.mu.Unlock()
		d.c.opts.Logger.DebugContext(d.ctx, "dup: entry ", i, ": datagram carrier failed: ", err)
		d.kick()
		return
	}
	if dp.primary != nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		_ = p.Close()
		return
	}
	dp.primary = d.packetLeg(p, lane)
	d.mu.Unlock()
	d.c.opts.Logger.DebugContext(d.ctx, "dup: entry ", i, ": datagram carrier on")
	d.resteer()
}

func (d *dupConn) openMirror(i int, lane uint8) {
	ctx, cancel := context.WithTimeout(d.ctx, d.c.opts.ConnectTimeout)
	conn, err := d.c.paths[i].Stream.DialContext(ctx, "tcp", dup.HostAddr())
	cancel()
	if err != nil {
		d.c.opts.Logger.DebugContext(d.ctx, "dup: entry ", i, ": stream copy failed: ", err)
		return
	}
	leg := newLeg(lane, dup.ViaStream, func(frame []byte) error { return dup.WriteStream(conn, frame) }, func() { _ = conn.Close() })
	leg.put(attachFrame(d.id, lane))
	d.mu.Lock()
	dp := &d.paths[i]
	if dp.mirror != nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		leg.close()
		return
	}
	dp.mirror = leg
	dp.mirrorErr = time.Time{}
	d.mu.Unlock()
	d.c.opts.Logger.DebugContext(d.ctx, "dup: entry ", i, ": stream copy on")
	go d.drain(leg)
	go d.readStream(leg, conn)
}

// openVoice brings up entry i's voice datagram carrier. Its failure says
// nothing of the datagram channel, so it does not mark the channel bad.
func (d *dupConn) openVoice(i int) {
	ctx, cancel := context.WithTimeout(d.ctx, d.c.opts.ConnectTimeout)
	p, err := d.c.paths[i].VoiceDatagram.ListenPacket(ctx, dup.HostAddr())
	cancel()
	d.mu.Lock()
	dp := &d.paths[i]
	dp.voiceOpening = false
	if err != nil {
		dp.voiceErr = time.Now()
		d.mu.Unlock()
		d.c.opts.Logger.DebugContext(d.ctx, "dup: entry ", i, ": voice carrier failed: ", err)
		return
	}
	if dp.voice != nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		_ = p.Close()
		return
	}
	// The voice connection carries nothing but calls: it must not hold one
	// back for a long round trip (wire/datagram voiceSender).
	if v, ok := p.(interface{ CarryVoice() }); ok {
		v.CarryVoice()
	}
	dp.voice = d.packetLeg(p, dup.LaneVoice)
	d.mu.Unlock()
	d.c.opts.Logger.DebugContext(d.ctx, "dup: entry ", i, ": voice carrier on")
}

// packetLeg starts a carrier on a datagram connection, attached to lane.
func (d *dupConn) packetLeg(p net.PacketConn, lane uint8) *dupLeg {
	leg := newLeg(lane, dup.ViaDatagram, func(frame []byte) error {
		_, err := p.WriteTo(frame, dup.HostAddr())
		return err
	}, func() { _ = p.Close() })
	leg.stats, _ = p.(channelStats)
	leg.put(attachFrame(d.id, lane))
	go d.drain(leg)
	go d.readPacket(leg, p)
	return leg
}

// drain sends a carrier's frames in order; a failed send ends the carrier.
// The stream copy drops a packet's frame that waited longer than
// datagram.StaleAfter: it would come too late to be of use (v1.05).
func (d *dupConn) drain(leg *dupLeg) {
	for f := range leg.queue {
		if leg.via == dup.ViaStream && !f.keep && time.Since(f.at) > datagram.StaleAfter {
			d.mu.Lock()
			d.staleStream++
			d.mu.Unlock()
			continue
		}
		if err := leg.send(f.b); err != nil {
			d.legDown(leg, err)
			break
		}
	}
	for range leg.queue {
	}
}

func (d *dupConn) readStream(leg *dupLeg, conn net.Conn) {
	b := make([]byte, dup.MaxFrame)
	for {
		data, err := dup.ReadStream(conn, b)
		if err != nil {
			d.legDown(leg, err)
			return
		}
		d.deliver(data, dup.ViaStream)
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
		d.deliver(b[:n], dup.ViaDatagram)
	}
}

// legDown drops a failed carrier and steers at once: a lost datagram carrier
// of the active entry puts its stream copy on the whole lane while a new one
// is brought back under the same session.
func (d *dupConn) legDown(leg *dupLeg, err error) {
	d.mu.Lock()
	i, kind, found := d.find(leg)
	if found {
		p := &d.paths[i]
		switch kind {
		case kindPrimary:
			d.absorb(leg)
			p.primary = nil
		case kindVoice:
			d.absorb(leg)
			p.voice = nil
			p.voiceErr = time.Now()
		case kindMirror:
			p.mirror = nil
			p.mirrorErr = time.Now()
		}
	}
	d.mu.Unlock()
	leg.close()
	if !found || d.ctx.Err() != nil {
		return
	}
	if kind == kindPrimary {
		d.c.opts.Logger.DebugContext(d.ctx, "dup: entry ", i, ": datagram carrier down: ", err)
	}
	d.resteer()
	d.kick()
}

// find names leg's entry and place; d.mu is held.
func (d *dupConn) find(leg *dupLeg) (int, carrierKind, bool) {
	for i := range d.paths {
		switch leg {
		case d.paths[i].primary:
			return i, kindPrimary, true
		case d.paths[i].voice:
			return i, kindVoice, true
		case d.paths[i].mirror:
			return i, kindMirror, true
		}
	}
	return 0, 0, false
}
