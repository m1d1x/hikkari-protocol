package pipectl

import (
	"maps"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// The route the brain gives the pipe and the wires' fates that go with it
// (putRoute; rust/pipe/src/route.rs): voice on a set of wires of different
// fates, video and bulk on one wire each (trunk fates.go).

// Route is the route the brain last gave the pipe.
func (p *Pipe) Route() trunk.Route {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.route
}

// SetRoute gives the pipe the wires of each class: its next datagram of
// each class goes on them (trunk.Steered), voice on wires of two fates.
func (p *Pipe) SetRoute(r trunk.Route) {
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	if err := p.send(putRoute(r, p.fatesCopy())); err != nil {
		p.cfg.Logf("pipectl: route: %v", err)
		return
	}
	p.mu.Lock()
	p.route = r
	p.mu.Unlock()
}

// setFate notes wire id's fate ("": none said) and gives the pipe the route
// again when it changed: the fates go with the route.
func (p *Pipe) setFate(id trunk.WireID, f trunk.Fate) error {
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	p.mu.Lock()
	same := p.fates[id] == f
	if f == "" {
		delete(p.fates, id)
	} else {
		p.fates[id] = f
	}
	r := p.route
	p.mu.Unlock()
	if same {
		return nil
	}
	return p.send(putRoute(r, p.fatesCopy()))
}

func (p *Pipe) fatesCopy() map[trunk.WireID]trunk.Fate {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.fates)
}
