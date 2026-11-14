package pipectl

import (
	"fmt"
	"os"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// Generations of the exit's pipe (spec/trunk.md, "An exit's own process
// replaced"; rust/exit/src/exit/generation.rs): a reload starts a new exit
// on the same sockets, the old one tells every entry it drains and carries
// what it has until it ends. The relay's generations (edge handoff.go) run
// them: each edge process is the brain of its own exit, and the reload's
// socket (HandoffLink) goes to the old one's Drain and the new one's Adopt.

// ExitRetireLimit is the longest an old exit carries what it has after a
// reload (the relay's 30 minutes): the brain closes it then whatever it
// still carries.
const ExitRetireLimit = 30 * time.Minute

// SetGeneration says the exit's generation: every QUIC connection id it
// issues names it, so that a newer exit on the same socket hands it the
// packets of its connections. It comes before any wire; each generation of
// one exit has its own (the relay's generation numbers do).
func (x *Exit) SetGeneration(gen byte) error { return x.send([]byte{xGen, gen}) }

// Drain makes x the old exit of a reload: it sends drain on every member of
// every session, stops reading its wires' sockets and accepting on the
// pool's port, tells the new exit at the other end of link its generation
// and its UDP wire's entry addresses, and carries what it has (the packets
// of its members reach it through the new exit) until it ends. Drained is
// closed once it carries nothing more; the brain closes it then, or at
// ExitRetireLimit. Its sockets are the new exit's: Close leaves them open.
func (x *Exit) Drain(link *os.File) error {
	if err := x.send([]byte{xDrain}, link); err != nil {
		return err
	}
	x.mu.Lock()
	x.wires = map[trunk.WireID]ExitWire{}
	x.pool = nil
	x.mu.Unlock()
	return nil
}

// Adopt makes x the new exit of a reload, link the other end of the old
// exit's Drain. Adopt comes before x gets the old exit's wires: x reads
// none of them before the old exit said whose addresses it keeps.
func (x *Exit) Adopt(link *os.File) error { return x.send([]byte{xAdopt}, link) }

// Drained is closed once x, draining, carries nothing more: no client's
// flow, no stream.
func (x *Exit) Drained() <-chan struct{} { return x.drained }

// Handoff is a reload within one brain: next, of generation gen (another
// than x's), adopts x, gets x's wires (the same sockets), pool and ports,
// and every new member; x drains to it.
func (x *Exit) Handoff(next *Exit, gen byte) error {
	old, nw, err := HandoffLink()
	if err != nil {
		return err
	}
	defer old.Close()
	defer nw.Close()
	if err := next.SetGeneration(gen); err != nil {
		return err
	}
	if err := next.Adopt(nw); err != nil {
		return err
	}
	x.mu.Lock()
	wires := make([]ExitWire, 0, len(x.wires))
	for _, w := range x.wires {
		wires = append(wires, w)
	}
	pool, ports := x.pool, append([]uint16(nil), x.ports...)
	x.mu.Unlock()
	for _, w := range wires {
		if err := next.SetWire(w); err != nil {
			return fmt.Errorf("pipectl: handoff: %w", err)
		}
	}
	if pool != nil {
		if err := next.SetPool(pool.l, pool.stall, pool.quiet); err != nil {
			return fmt.Errorf("pipectl: handoff: %w", err)
		}
	}
	if err := next.SetPorts(ports); err != nil {
		return err
	}
	return x.Drain(old)
}
