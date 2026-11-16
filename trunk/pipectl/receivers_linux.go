package pipectl

// The receivers (hikkari-client plans/2026-11-16-second-receiver.md; the
// pipe's rust/pipe/src/pipe/session.rs): the entry holds the trunk to more
// than one receiver abroad, the same relay for a client at another address
// on the same ports, and carries everything on the active one. The brain
// gives the pipe the receivers on standby (SetReceiver), reads how warm each
// is after every tick (Receivers) and moves the entry (SetActive). Which
// receiver is red and when to move is the brain's.

import (
	"fmt"
	"net/netip"
	"time"
)

// SetReceiver gives the pipe receiver rx on standby at ip, on the active
// receiver's ports, its pools keeping poolMembers (0: as many as the active
// one's); an invalid ip takes it away. The pipe keeps it warm: a session of
// its own with every wire and pool, carrying nothing.
func (p *Pipe) SetReceiver(rx byte, ip netip.Addr, poolMembers int) error {
	b, err := putReceiver(rx, ip, poolMembers)
	if err != nil {
		return err
	}
	return p.send(b)
}

// SetActive makes receiver rx, at ip, the one that carries everything: the
// pipe cuts what the old one carries at once (clients dial again and land
// on rx) and keeps the old one on standby; the brain's new members of the
// bare UDP wires dial ip on their wire's port from now.
func (p *Pipe) SetActive(rx byte, ip netip.Addr) error {
	if !ip.Is4() {
		return fmt.Errorf("pipectl: receiver %d: %s is not IPv4", rx, ip)
	}
	p.mu.Lock()
	p.activeIP = ip
	p.mu.Unlock()
	return p.send(putActive(rx))
}

// Receivers is the pipe's latest word on the receivers and when it came
// (zero before the first: no receiver on standby yet).
func (p *Pipe) Receivers() (Receivers, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.receivers, p.receiversAt
}
