package trunk

import (
	"net"
	"time"
)

// A flow is one client UDP association: on the entry, one client address on
// one forwarded port; on the exit, one socket to the relay. Its datagrams go
// over Copies members at once and are never sent again: a call wants the
// first copy now, not a late one. A flow whose sender copies its datagrams
// itself (Hikkari v1.02 sends a call over both its channels) is opened with
// one copy: a second copy here would make four of every packet.

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
	if copies <= 0 {
		copies = s.cfg.Copies
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	f := &flow{id: s.nextID, port: port, deliver: deliver, used: time.Now(), onEnd: onEnd, copies: copies, opened: time.Now()}
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
	s.dgramsOut.Add(1)
	s.sendDgramLocked(h.f, p)
	return true
}

func (s *Session) sendDgramLocked(f *flow, p []byte) {
	f.seq++
	f.out++
	b := appendDgram(make([]byte, 0, 13+len(p)), f.id, f.seq, f.port, p)
	// The Copies least loaded members; a datagram is never owed, so a member
	// carrying it is not held to account for it.
	copies := f.copies
	if copies <= 0 {
		copies = s.cfg.Copies
	}
	var used []*member
	for len(used) < copies {
		var best *member
		for m := range s.members {
			taken := false
			for _, u := range used {
				taken = taken || u == m
			}
			if !taken && (best == nil || m.inflight < best.inflight) {
				best = m
			}
		}
		if best == nil {
			break
		}
		used = append(used, best)
		best.lastSend = time.Now()
		best.send(b, true)
	}
}

// dgramLocked: a datagram arrived.
func (s *Session) dgramLocked(fr frame) {
	f := s.flows[fr.stream]
	if f == nil {
		if s.local == nil {
			return // the entry's flow is over
		}
		conn, err := s.local.DialFlow(withTarget(s.ctx, Target{s, ObsFlow, fr.stream}), fr.port)
		if err != nil {
			return
		}
		// The exit answers a flow as the entry sends it: on one member
		// until a copy arrives, then on Copies.
		f = &flow{id: fr.stream, port: fr.port, conn: conn, used: time.Now(), copies: 1, opened: time.Now()}
		s.flows[f.id] = f
		go s.readFlow(f)
	}
	if f.replay.seen(fr.seq) {
		s.dgramsCopy.Add(1)
		f.copied++
		if s.local != nil {
			f.copies = s.cfg.Copies
		}
		return
	}
	f.used = time.Now()
	s.dgramsIn.Add(1)
	f.in++
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
