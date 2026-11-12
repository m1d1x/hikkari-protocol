//! The entry's datagrams on a wire (trunk exit.go ServeMember, session.go
//! handle, flows.go dgramLocked on the exit): an address's first datagram
//! that opens under one of the wire's keys makes it a peer; its hello joins
//! it to the session the hello names and is answered with the session's
//! epoch, every copy of it again; pings are answered, pongs prove; a dgram
//! goes to its flow, opened on its first one.

use hikkari_sys::{self as sys, BATCH};
use hikkari_trunk::flow::ECHO_PORT;
use hikkari_trunk::frame::{self, Frame, DGRAM_HEAD, F_PONG, KIND_PACKET, KIND_STREAMS};
use hikkari_trunk::health::Health;

use super::Exit;

impl Exit {
    /// Everything each readable wire has, batch by batch.
    pub(super) fn read_wires(&mut self, now: u64) {
        let first = self.ctl.is_some() as usize;
        let mut rb = self.wrecv.take().expect("the wire's batch");
        for wi in 0..self.wires.len() {
            if !self.poll.readable(first + wi) {
                continue;
            }
            loop {
                let n = rb.recv(self.wires[wi].fd());
                for i in 0..n {
                    let (from, len, slot) = (rb.addr[i], rb.len[i], rb.slot);
                    self.datagram(wi, from, &mut rb.buf[i * slot..i * slot + len], now);
                }
                if n < BATCH {
                    break;
                }
            }
        }
        self.wrecv = Some(rb);
    }

    /// One sealed datagram from `from` on wire wi: opened in place, its
    /// frames handled in order.
    fn datagram(&mut self, wi: usize, from: sys::sockaddr_in, d: &mut [u8], now: u64) {
        let at = sys::addr_key(&from) | (wi as u64) << 48;
        let (pi, n) = match self.peer_of(at) {
            Some(pi) => match self.peers[pi].seal.open(d) {
                Some(n) => (pi, n),
                None => {
                    self.t.bad += 1;
                    return;
                }
            },
            None => {
                let opened = self.wires[wi].openers.iter().enumerate().find_map(|(k, o)| o.open(d).map(|n| (k, n)));
                let Some((k, n)) = opened else {
                    // Under no key: a stranger, answered nothing.
                    self.t.bad += 1;
                    return;
                };
                match self.take_peer(from, at, wi, k, now) {
                    Some(pi) => (pi, n),
                    None => return,
                }
            }
        };
        self.t.w_in += 1;
        self.moved += 1;
        self.peers[pi].heard = now;
        let p = &d[12..12 + n];
        let mut at = 0;
        while at < p.len() {
            let Some((f, next)) = frame::next_frame(p, at) else {
                self.t.bad += 1;
                return;
            };
            match f {
                Frame::Hello => self.hello(pi, p, at, now),
                Frame::Ping(t) => {
                    if self.peers[pi].joined() {
                        let w = self.peers[pi].wire;
                        self.wires[w].glue(&mut self.peers[pi], 9, now, |b| frame::put_ping(b, F_PONG, t));
                    }
                }
                Frame::Pong(t) => {
                    let p = &mut self.peers[pi];
                    if p.joined() {
                        p.h.pong(&mut self.sessions.all[p.session].judge, t, now);
                    }
                }
                Frame::Dgram { stream, seq, port, off, len } => self.dgram(pi, stream, seq, port, &p[off..off + len], now),
                // A packet member carries no stream's frames (spec/trunk.md,
                // "Wires": dropped there), and drain and observe go the
                // other way.
                _ => {}
            }
            at = next;
        }
    }

    /// A hello on peer pi: a packet member joins the session it names, made
    /// on its first hello; a copy is answered again, the first answer may
    /// have been lost. A member of streams is not this pipe's (R1.7): it
    /// gets no answer.
    fn hello(&mut self, pi: usize, p: &[u8], at: usize, now: u64) {
        let Some(h) = frame::read_hello(p, at) else {
            self.t.bad += 1;
            return;
        };
        let (wire_id, flags) = h.t2.unwrap_or((0, KIND_STREAMS));
        if flags & KIND_PACKET == 0 || flags & KIND_STREAMS != 0 {
            return;
        }
        let Exit { wires, peers, sessions, t, pause, moved, .. } = self;
        let peer = &mut peers[pi];
        if !peer.joined() {
            let s = sessions.of(h.session, wires[peer.wire].quiet_ns, now);
            let sess = &mut sessions.all[s];
            sess.judge.resumed = sess.judge.resumed.max(pause.resumed);
            peer.session = s;
            peer.wire_id = wire_id;
            peer.flags = flags;
            peer.h = Health::new(true);
            peer.h.join(now);
            sess.join((pi, peer.gen), wire_id);
            t.members += 1;
            t.joined += 1;
        }
        let sess = &sessions.all[peer.session];
        let (id, epoch, kind) = (sess.id, sess.epoch, Some((peer.wire_id, peer.flags)));
        wires[peer.wire].alone(peer, 31, now, |b| frame::put_hello(b, &id, &epoch, kind));
        *moved += 1;
    }

    /// A datagram of flow `stream` on member pi (trunk dgramLocked on the
    /// exit): its flow opened on the first one (a socket to the loopback
    /// port, none for the call's port 0), copies dropped by seq, the call
    /// answered straight back, a client's datagram written to its relay.
    fn dgram(&mut self, pi: usize, stream: u32, seq: u32, port: u16, payload: &[u8], now: u64) {
        let p = &self.peers[pi];
        if !p.joined() {
            return;
        }
        let (s, m, wire_id) = (p.session, (pi, p.gen), p.wire_id);
        let fi = match self.sessions.all[s].flows.get(&stream) {
            Some(&fi) => fi,
            None => {
                if port != ECHO_PORT && !self.ports[port as usize] {
                    self.t.refused += 1;
                    return;
                }
                let fi = self.flows.open(&mut self.sessions.all[s].flows, s, stream, port, now);
                if port != ECHO_PORT && self.relay_open(fi).is_err() {
                    self.end_flow(fi);
                    self.t.refused += 1;
                    return;
                }
                fi
            }
        };
        let f = &mut self.flows.all[fi];
        if f.arrived(m, wire_id, seq) {
            if !f.echo() {
                self.t.dgrams_copy += 1;
            }
            return;
        }
        f.used = now;
        if f.echo() {
            self.answer(fi, payload, now);
            return;
        }
        self.t.dgrams_in += 1;
        if !sys::send_nowait(f.fd, payload) {
            self.t.refused += 1;
        }
    }

    /// One answer of flow fi down to the entry: the flow's next seq, glued
    /// for the members that carry it (flow::Flow::carriers).
    pub(super) fn answer(&mut self, fi: usize, payload: &[u8], now: u64) {
        let Exit { flows, sessions, peers, wires, carriers, .. } = self;
        let f = &mut flows.all[fi];
        f.seq = f.seq.wrapping_add(1);
        let (stream, seq, port, s) = (f.stream, f.seq, f.port, f.session);
        let sess = &sessions.all[s];
        let up = |m: (usize, u32)| peers.get(m.0).is_some_and(|p| p.live && p.gen == m.1 && p.session == s);
        let n = f.carriers(up, sess.of_wire(f.wire), &sess.members, carriers);
        for &(pi, _) in &carriers[..n] {
            let p = &mut peers[pi];
            wires[p.wire].glue(p, DGRAM_HEAD + payload.len(), now, |b| frame::put_dgram(b, stream, seq, port, payload));
        }
    }
}
