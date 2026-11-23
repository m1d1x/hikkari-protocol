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
	"net"
	"net/netip"
	"slices"
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

// SetBorderPoints configures the addresses and TLS names in the same message.
func (p *Pipe) SetBorderPoints(points []BorderPoint) error {
	b, ips, err := putBorderPoints(points)
	if err != nil {
		return err
	}
	p.mu.Lock()
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
