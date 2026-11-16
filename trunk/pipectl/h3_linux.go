package pipectl

import "github.com/m1d1x/hikkari-protocol/trunk/h3dgram"

// setH3 gives the pipe a QUIC wire: no sockets, the pipe opens its members
// (tunnels from its book of ports) and replaces the dead ones itself.
func (p *Pipe) setH3(w Wire) error {
	f := *w.H3
	if f.Ports == [2]uint16{} {
		f.Ports = defaultPorts
	}
	w.H3 = &f
	token, err := h3dgram.Token(w.Key)
	if err != nil {
		return err
	}
	msg, err := putH3(w.ID, w.Glue, w.GlueMax, w.Stall, token, w.Members, w.Exit, f)
	if err != nil {
		return err
	}
	if err := p.send(msg); err != nil {
		return err
	}
	p.mu.Lock()
	if old := p.wires[w.ID]; old != nil {
		closeAll(old.members)
	}
	p.wires[w.ID] = &wireConf{w: w}
	p.mu.Unlock()
	return nil
}
