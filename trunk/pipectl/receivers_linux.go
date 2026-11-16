package pipectl

// The receivers (hikkari-client plans/2026-11-16-second-receiver.md; the
// pipe's rust/pipe/src/pipe/session.rs): the entry holds the trunk to more
// than one receiver abroad, the same relay for a client at another address
// on the same ports, and carries everything on the active one. The brain
// gives the pipe the receivers on standby (SetReceiver), reads how warm each
// is after every tick (Receivers) and moves the entry (SetActive). Which
// receiver is red and when to move is the brain's.

import (
	"context"
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

// Move is a move of the entry the judge made: from one receiver to another,
// their addresses, why, and what SetActive said.
type Move struct {
	From, To     byte
	FromIP, ToIP netip.Addr
	Why          string
	Err          error
}

// RunReceivers judges the pipe's receivers once a tick until ctx ends and
// moves the entry (SetActive) when the judge says so; at says each
// receiver's address by rx (the active one's included), onMove hears every
// move. A receiver the pipe does not report has no address here and is
// never moved to.
func (p *Pipe) RunReceivers(ctx context.Context, at map[byte]netip.Addr, onMove func(Move)) {
	var j Judge
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var seen time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-t.C:
		}
		rs, rsAt := p.Receivers()
		tick, tickAt := p.Tick()
		if rsAt.IsZero() || !rsAt.After(seen) || time.Since(tickAt) > 2*time.Second {
			continue // nothing new from the pipe: never judge an old word
		}
		seen = rsAt
		p.mu.Lock()
		resumed := p.resumed
		p.mu.Unlock()
		paused := time.Duration(-1)
		if !resumed.IsZero() {
			paused = time.Since(resumed)
		}
		v := j.Step(time.Now(), tick, rs, paused)
		if !v.Move {
			continue
		}
		ip, ok := at[v.To]
		if !ok {
			continue
		}
		err := p.SetActive(v.To, ip)
		if onMove != nil {
			onMove(Move{From: rs.Active, To: v.To, FromIP: at[rs.Active], ToIP: ip, Why: v.Why, Err: err})
		}
	}
}
