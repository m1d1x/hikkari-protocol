package pipectl

// Border points (spec/trunk.md, "Border points"; the pipe's
// rust/pipe/src/pipe/points.rs; hikkari-client
// plans/2026-11-19-border-forwarders.md): the active receiver, the core,
// reached through boxes that only forward its ports to it; its own address
// may be out of the entry's reach, and with points given nothing dials it. Member i
// of every wire goes to point i mod n under one session, so a point that
// freezes or dies takes down its own members alone and the call on the
// others is not heard to pause. The brain dials the bare UDP wires'
// members; the pipe dials the pools and the QUIC wires itself.

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"
)

// SetPoints gives the active receiver's border points, its own address
// among them or not; none: the receiver's own address alone. Give them
// before the wires, so that no member dials the core first. The members whose point
// changed go to their new one (the pipe moves its own, the brain dials the
// bare UDP wires' anew), the others stay as they are. A move to another
// receiver (SetActive) drops them.
func (p *Pipe) SetPoints(ips []netip.Addr) error {
	points := make([]BorderPoint, len(ips))
	for i, ip := range ips {
		points[i].IP = ip
	}
	return p.SetBorderPoints(points)
}

// SetBorderPoints gives the points the hub offers, their addresses and TLS
// names in the same message. The pipe carries on those the point judge
// keeps on the path (RunPoints): all of them until it judged otherwise.
func (p *Pipe) SetBorderPoints(points []BorderPoint) error {
	p.mu.Lock()
	p.offered = slices.Clone(points)
	p.mu.Unlock()
	return p.givePath()
}

// givePath gives the pipe the offered points the judge keeps on the path.
func (p *Pipe) givePath() error {
	p.mu.Lock()
	path := p.offered
	if p.pointJudge != nil {
		keep := p.pointJudge.Path(offeredIPs(p.offered))
		path = slices.DeleteFunc(slices.Clone(p.offered), func(bp BorderPoint) bool { return !slices.Contains(keep, bp.IP) })
	}
	b, ips, err := putBorderPoints(path)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	if err := p.send(b); err != nil {
		p.mu.Unlock()
		return err
	}
	changed := !slices.Equal(p.points, ips)
	p.points = ips
	var udp []Wire
	if changed {
		for _, wc := range p.wires {
			if wc.w.H3 == nil {
				udp = append(udp, wc.w)
			}
		}
	}
	p.mu.Unlock()
	for _, w := range udp {
		if err := p.SetWire(w); err != nil {
			return err
		}
	}
	return nil
}

func offeredIPs(points []BorderPoint) []netip.Addr {
	ips := make([]netip.Addr, len(points))
	for i, bp := range points {
		ips[i] = bp.IP
	}
	return ips
}

// PointChange is a change of the path the point judge made: the points on
// it now, the point that left or came back, why, and what the pipe said.
type PointChange struct {
	Path       []netip.Addr
	Left, Back []netip.Addr
	Why        string
	Err        error
}

// RunPoints judges the offered border points once a second until ctx ends,
// by the pipe's point ticks and their age, and gives the pipe the points the
// judge keeps on the path (pointjudge.go); onChange hears every change.
// Without RunPoints the pipe carries on every point offered.
func (p *Pipe) RunPoints(ctx context.Context, onChange func(PointChange)) {
	j := &PointJudge{}
	p.mu.Lock()
	p.pointJudge = j
	p.mu.Unlock()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-t.C:
		}
		ticks, at := p.Points()
		now := time.Now()
		p.mu.Lock()
		offered := offeredIPs(p.offered)
		resumed := p.resumed
		p.mu.Unlock()
		if at.IsZero() || now.Sub(at) > staleWord {
			continue
		}
		paused := time.Duration(-1)
		if !resumed.IsZero() {
			paused = time.Since(resumed)
		}
		p.mu.Lock()
		v := j.Step(now, offered, ticks, now.Sub(at), paused)
		p.mu.Unlock()
		if !v.Change {
			continue
		}
		err := p.givePath()
		if onChange != nil {
			onChange(PointChange{Path: v.Path, Left: v.Left, Back: v.Back, Why: v.Why, Err: err})
		}
	}
}

// pointAddrLocked is where member i of a wire to exit goes: its border
// point on the wire's port, or exit without points.
func (p *Pipe) pointAddrLocked(exit netip.AddrPort, i int) netip.AddrPort {
	if n := len(p.points); n > 0 {
		return netip.AddrPortFrom(p.points[i%n], exit.Port())
	}
	return exit
}

// memberAddrLocked is where a member dialed anew goes: its border point,
// else the active receiver once the brain moved the entry, else exit.
func (p *Pipe) memberAddrLocked(exit netip.AddrPort, i int) netip.AddrPort {
	if len(p.points) == 0 && p.activeIP.IsValid() {
		return netip.AddrPortFrom(p.activeIP, exit.Port())
	}
	return p.pointAddrLocked(exit, i)
}

// dialedTo is the address a member's socket is connected to.
func dialedTo(c *net.UDPConn) netip.AddrPort {
	if a, ok := c.RemoteAddr().(*net.UDPAddr); ok {
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}
