package pipectl

import (
	"net"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// defaultPorts is the pipe's own book of source ports without a range from
// the brain (rust/trunk/src/ports.rs LO, HI).
var defaultPorts = [2]uint16{20000, 32767}

// tcpListenConf is a client port of streams as the brain gave it, to give
// it again to the next pipe of a reload.
type tcpListenConf struct {
	l  *net.TCPListener
	to uint16
}

// TCPListen gives the pipe a client port of streams: every connection
// accepted on l is a stream to port `to` at the exit, on the pools'
// members (rust/pipe/src/pipe/pool.rs). The brain keeps l for the next
// pipe of a reload.
func (p *Pipe) TCPListen(id byte, l *net.TCPListener, to uint16) error {
	if err := sendWith(p.conn, &p.wmu, putTCPListen(id, to), l); err != nil {
		return err
	}
	p.mu.Lock()
	if old := p.tcpListens[id]; old != nil && old.l != l {
		old.l.Close()
	}
	p.tcpListens[id] = &tcpListenConf{l: l, to: to}
	p.mu.Unlock()
	return nil
}

// SetPool gives the pipe a pool, or new settings of one it has. The pipe
// dials the members itself, from its book of source ports: the same pool
// sent again changes only the stall, a new form, exit or number of members
// brings them up anew, and no stream is reset by it.
func (p *Pipe) SetPool(w Pool) error {
	if w.Stall == 0 {
		w.Stall = trunk.DefaultStall
	}
	if w.Ports == [2]uint16{} {
		w.Ports = defaultPorts
	}
	msg, err := putPool(w)
	if err != nil {
		return err
	}
	return sendWith(p.conn, &p.wmu, msg)
}

// tcpListensCopy is the client ports of streams, for a reload.
func (p *Pipe) tcpListensCopy() map[byte]*tcpListenConf {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[byte]*tcpListenConf, len(p.tcpListens))
	for id, l := range p.tcpListens {
		out[id] = l
	}
	return out
}
