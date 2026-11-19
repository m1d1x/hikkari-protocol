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
	"sync"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
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

// RunReceivers judges the pipe's receivers every judgeEvery until ctx ends,
// their proofs aged by the time since the pipe said them (so a receiver is
// dead DeadAfter after its last proof, not at the next tick), and moves the
// entry (SetActive) when the judge says so; at says each
// receiver's address by rx (the active one's included), onMove hears every
// move. A receiver the pipe does not report has no address here and is
// never moved to.
func (p *Pipe) RunReceivers(ctx context.Context, at map[byte]netip.Addr, onMove func(Move)) {
	var j Judge
	t := time.NewTicker(judgeEvery)
	defer t.Stop()
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
		now := time.Now()
		// The pipe says both once a second: an older word is a pipe (or a
		// brain) not run, and the judge holds.
		if rsAt.IsZero() || now.Sub(tickAt) > staleWord || now.Sub(rsAt) > staleWord {
			continue
		}
		tick.Wires = aged(tick.Wires, now.Sub(tickAt))
		standby := make([]ReceiverTick, len(rs.Standby))
		for i, r := range rs.Standby {
			r.Wires = aged(r.Wires, now.Sub(rsAt))
			standby[i] = r
		}
		rs.Standby = standby
		p.mu.Lock()
		resumed := p.resumed
		p.mu.Unlock()
		paused := time.Duration(-1)
		if !resumed.IsZero() {
			paused = time.Since(resumed)
		}
		p.mu.Lock()
		heard := p.rxCalls
		p.rxCalls = nil
		p.mu.Unlock()
		for _, w := range heard {
			j.Hear(w)
		}
		v := j.Step(now, tick, rs, paused)
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

// RunReceiverCalls calls each receiver of rxs through the pipe until ctx
// ends, a flow held to it (AtReceiver) whichever is active, by cfg: the
// brain gives the people's call (copies1), a datagram every 20 ms to the
// exit's echo by the voice class's route, one copy, a minute's window. Each
// window goes to the judge of RunReceivers (better.go) and to report, on
// the call's goroutine.
func (p *Pipe) RunReceiverCalls(ctx context.Context, rxs []byte, cfg trunk.CallConfig, report func(rx byte, w trunk.CallWindow)) {
	var wg sync.WaitGroup
	for _, rx := range rxs {
		c := p.AtReceiver(rx)
		wg.Add(1)
		go func() {
			defer wg.Done()
			trunk.RunCallOn(ctx, func() trunk.CallCarrier { return c }, cfg, func(w trunk.CallWindow) {
				p.mu.Lock()
				p.rxCalls = append(p.rxCalls, RxWindowOf(rx, w))
				if len(p.rxCalls) > 64 {
					p.rxCalls = p.rxCalls[len(p.rxCalls)-64:]
				}
				p.mu.Unlock()
				if report != nil {
					report(rx, w)
				}
			})
		}()
	}
	wg.Wait()
}

const (
	// judgeEvery is how often RunReceivers judges: a move comes within it of
	// DeadAfter.
	judgeEvery = 100 * time.Millisecond
	// staleWord is how old the pipe's word may be for the judge to read it.
	staleWord = 2500 * time.Millisecond
)

// aged is wires with their proofs older by d: what the pipe said d ago.
func aged(wires []WireTick, d time.Duration) []WireTick {
	out := make([]WireTick, len(wires))
	for i, w := range wires {
		if w.ProofAgo >= 0 {
			w.ProofAgo += d
		}
		out[i] = w
	}
	return out
}
