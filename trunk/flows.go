package trunk

import (
	"net"
	"time"
)

// A flow is one client UDP association: on the entry, one client address on
// one forwarded port; on the exit, one socket to the relay. Its datagrams go
// on every wire of its set at once (fates.go), Copies members of its main
// wire, and are never sent again: a call wants the first copy now, not a
// late one. A flow whose sender copies its datagrams itself (Hikkari v1.02
// sends a call over both its channels) is opened with one copy: a second
// copy on its main wire would make four of every packet.
//
// A flow to EchoPort is the trunk's own synthetic call (call.go): the exit
// sends every datagram straight back, without a socket, and neither end
// counts it among its clients' flows and datagrams.

// EchoPort is the port of the exit's echo: no loopback service has port 0.
const EchoPort uint16 = 0

type flow struct {
	id      uint32
	port    uint16
	seq     uint32
	replay  replay
	deliver func([]byte) // entry: back to the client
	conn    net.Conn     // exit: the socket to the relay
	used    time.Time
	ended   bool
	onEnd   func()
	// copies is how many members carry each datagram of the flow. The
	// entry's is chosen at open; the exit's follows the entry's (dgramLocked).
	copies int
	// echo is a flow to EchoPort: the trunk's own call, not a client's.
	echo bool
	// class and pin are the entry's: the route it follows, or the one wire
	// it is held to (wires.go). heard is the exit's: the wires the entry
	// sent it on, where the answers go (fates.go answerSet).
	class Class
	pin   WireID
	heard [MaxCarries]heardOn

	// What an observed flow reports (observe.go).
	opened          time.Time
	obs             uint64
	out, in, copied int64
	endWhy          string
	tag             string
}

// Flow is the entry's handle on one datagram flow.
type Flow struct {
	s *Session
	f *flow
}

// OpenFlow starts a datagram flow to the exit's port. deliver gets every
// datagram that comes back; it runs with the session locked and must not
// block (a write to a UDP socket). onEnd runs when the flow ends (idle, or
// the session closes). Entry only.
func (s *Session) OpenFlow(port uint16, deliver func([]byte), onEnd func()) *Flow {
	return s.OpenFlowCopies(port, 0, deliver, onEnd)
}

// OpenFlowCopies is OpenFlow with each datagram carried by copies members;
// 0 is the session's Copies.
func (s *Session) OpenFlowCopies(port uint16, copies int, deliver func([]byte), onEnd func()) *Flow {
	return s.OpenFlowWith(port, FlowOptions{Copies: copies, Pin: AnyWire}, deliver, onEnd)
}

// OpenFlowWith is OpenFlow shaped by o: its copies, its class, its pin.
func (s *Session) OpenFlowWith(port uint16, o FlowOptions, deliver func([]byte), onEnd func()) *Flow {
	copies := o.Copies
	if copies <= 0 {
		copies = s.cfg.Copies
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	f := &flow{id: s.nextID, port: port, deliver: deliver, used: time.Now(), onEnd: onEnd, copies: copies, opened: time.Now(), echo: port == EchoPort,
		class: o.Class, pin: o.Pin}
	if s.shutdown {
		f.ended = true
	} else {
		s.flows[f.id] = f
	}
	return &Flow{s, f}
}

// Send carries one datagram to the exit. It reports false once the flow has
// ended.
func (h *Flow) Send(p []byte) bool {
	if len(p) > MaxPayload {
		return true // not carriable; dropped as an oversized datagram would be
	}
	s := h.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if h.f.ended {
		return false
	}
	h.f.used = time.Now()
	if !h.f.echo {
		s.dgramsOut.Add(1)
	}
	s.sendDgramLocked(h.f, p)
	return true
}

// Close ends the flow on this end; the other end's lets it idle out.
func (h *Flow) Close() {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	h.s.endFlowLocked(h.f)
}

// dgramLocked: a datagram arrived on m.
func (s *Session) dgramLocked(m *member, fr frame) {
	f := s.flows[fr.stream]
	if f == nil {
		if s.local == nil {
			return // the entry's flow is over
		}
		if fr.port == EchoPort {
			f = &flow{id: fr.stream, port: fr.port, used: time.Now(), copies: 1, opened: time.Now(), echo: true}
			s.flows[f.id] = f
			s.dgramLocked(m, fr)
			return
		}
		conn, err := s.local.DialFlow(withTarget(s.ctx, Target{s, ObsFlow, fr.stream}), fr.port)
		if err != nil {
			return
		}
		// The exit answers a flow as the entry sends it: on the wires its
		// datagrams come on, each on one member until a copy comes on it,
		// then on Copies (fates.go heardLocked).
		f = &flow{id: fr.stream, port: fr.port, conn: conn, used: time.Now(), copies: 1, opened: time.Now()}
		s.flows[f.id] = f
		go s.readFlow(f)
	}
	dup := f.replay.seen(fr.seq)
	if s.local != nil {
		s.heardLocked(f, m.kind.wire, fr.seq, dup, time.Now()) // answers follow the entry's set
	}
	if dup {
		if !f.echo {
			s.dgramsCopy.Add(1)
		}
		f.copied++
		return
	}
	f.used = time.Now()
	f.in++
	if f.echo && s.local != nil {
		s.sendDgramLocked(f, fr.payload) // the exit's echo: straight back
		return
	}
	if !f.echo {
		s.dgramsIn.Add(1)
	}
	if f.conn != nil {
		_, _ = f.conn.Write(fr.payload)
	} else if f.deliver != nil {
		f.deliver(fr.payload)
	}
}

// readFlow carries what the relay answers back to the entry. Exit only.
func (s *Session) readFlow(f *flow) {
	buf := make([]byte, MaxPayload)
	for {
		n, err := f.conn.Read(buf)
		if err != nil {
			s.mu.Lock()
			if f.endWhy == "" {
				f.endWhy = EndLocal
			}
			s.endFlowLocked(f)
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		if f.ended {
			s.mu.Unlock()
			return
		}
		f.used = time.Now()
		s.dgramsOut.Add(1)
		s.sendDgramLocked(f, buf[:n])
		s.mu.Unlock()
	}
}

func (s *Session) endFlowLocked(f *flow) {
	if f.ended {
		return
	}
	f.ended = true
	delete(s.flows, f.id)
	if f.endWhy == "" {
		f.endWhy = EndSession
	}
	if f.obs != 0 {
		s.reportLocked(s.flowReportLocked(f, PhaseEnd))
	}
	if f.conn != nil {
		_ = f.conn.Close()
	}
	if f.onEnd != nil {
		go f.onEnd()
	}
}

// replay drops copies: a sliding window of the last 1024 sequence numbers.
type replay struct {
	top  uint32
	bits [16]uint64
}

func (r *replay) seen(seq uint32) bool {
	const size = 1024
	if seq == 0 {
		return true
	}
	if seq > r.top {
		shift := seq - r.top
		if shift >= size {
			r.bits = [16]uint64{}
		} else {
			for i := r.top + 1; i <= seq; i++ {
				r.bits[(i%size)/64] &^= 1 << (i % 64)
			}
		}
		r.top = seq
	} else if r.top-seq >= size {
		return true // too old to tell: dropped as a late copy
	}
	word, bit := (seq%size)/64, uint64(1)<<(seq%64)
	if r.bits[word]&bit != 0 {
		return true
	}
	r.bits[word] |= bit
	return false
}

// clientFlowsLocked is how many flows are clients', not the trunk's own call.
func (s *Session) clientFlowsLocked() int {
	n := 0
	for _, f := range s.flows {
		if !f.echo {
			n++
		}
	}
	return n
}
