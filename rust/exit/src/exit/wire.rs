//! The entry's datagrams on a wire (trunk exit.go ServeMember, session.go
//! handle, flows.go dgramLocked on the exit): an address's first datagram
//! that opens under one of the wire's keys makes it a peer; its hello joins
//! it to the session the hello names and is answered with the session's
//! epoch, every copy of it again; pings are answered, pongs prove; a dgram
//! goes to its flow, opened on its first one.

use hikkari_sys::{self as sys, BATCH};
use hikkari_trunk::flow::ECHO_PORT;
use hikkari_trunk::frag::Reasm;
use hikkari_trunk::frame::{self, Frame, DGRAM_HEAD, F_PONG, KIND_PACKET, KIND_STREAMS};
use hikkari_trunk::health::Health;
use hikkari_trunk::observe::END_LOCAL;

use super::Exit;
use crate::flow::{link_slot, Heard, Seen, LINK_SEEN};
use crate::peer::{Class, Form};

/// A peer's key among the exit's: its wire's index and its address.
#[inline]
pub(super) fn peer_key(wi: usize, from: &sys::sockaddr_in) -> u64 {
    sys::addr_key(from) | (wi as u64) << 48
}

impl Exit {
    /// Everything each readable wire has, batch by batch.
    pub(super) fn read_wires(&mut self, now: u64) {
        if !self.reads_wires() {
            return;
        }
        let first = self.wires_at;
        let mut rb = self.wrecv.take().expect("the wire's batch");
        for wi in 0..self.wires.len() {
            if !self.poll.readable(first + wi) {
                continue;
            }
            if self.wires[wi].h3().is_some() {
                self.read_h3(wi, &mut rb, now);
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
    /// frames handled in order; one of an address an older generation
    /// keeps goes to it (generation.rs).
    pub(super) fn datagram(&mut self, wi: usize, from: sys::sockaddr_in, d: &mut [u8], now: u64) {
        if let Some(o) = self.gens.owner_of(self.wires[wi].id, &from) {
            self.gens.forward(o, self.wires[wi].id, &from, d);
            return;
        }
        let at = peer_key(wi, &from);
        let (pi, n) = match self.peer_of(at) {
            Some(pi) => match self.peers[pi].seal.open(d) {
                Some(n) => (pi, n),
                None => {
                    self.t.bad += 1;
                    return;
                }
            },
            None => {
                let Form::Udp(u) = &self.wires[wi].form else { return };
                let opened = u.openers.iter().enumerate().find_map(|(k, o)| o.open(d).map(|n| (k, n)));
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
        self.frames(pi, &d[12..12 + n], now);
    }

    /// The frames of one datagram that opened on peer pi, in order (on the
    /// QUIC wire, an HTTP Datagram of its request).
    pub(super) fn frames(&mut self, pi: usize, p: &[u8], now: u64) {
        self.t.w_in += 1;
        self.moved += 1;
        self.peers[pi].heard = now;
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
                        self.wires[w].glue(&mut self.peers[pi], Class::Own, 9, now, |b| frame::put_ping(b, F_PONG, t));
                    }
                }
                Frame::Pong(t) => {
                    let p = &mut self.peers[pi];
                    if p.joined() {
                        p.h.pong(&mut self.sessions.all[p.session].judge, t, now);
                    }
                }
                Frame::Dgram { stream, seq, port, off, len } => self.dgram(pi, stream, seq, port, &p[off..off + len], now),
                Frame::Frag { id, index, count, off, len } => self.piece(pi, id, index, count, &p[off..off + len], now),
                // A packet member carries no stream's frames (spec/trunk.md,
                // "Wires": dropped there), and drain and observe go the
                // other way.
                _ => {}
            }
            at = next;
        }
    }

    /// A piece of a frame the entry cut, on peer pi (spec/trunk.md,
    /// `h3dgram`: a frame over the room): the frame once whole is the one
    /// dgram it must be; its payload is written to the relay at once, so its
    /// slot is free again.
    fn piece(&mut self, pi: usize, id: u16, index: u8, count: u8, p: &[u8], now: u64) {
        let gen = self.peers[pi].gen;
        let mut r = self.peers[pi].reasm.take().unwrap_or_else(|| Box::new(Reasm::new()));
        if let Some(whole) = r.piece(now, id, index, count, p) {
            match frame::next_frame(whole, 0) {
                Some((Frame::Dgram { stream, seq, port, off, len }, end)) if end == whole.len() => {
                    self.dgram(pi, stream, seq, port, &whole[off..off + len], now)
                }
                _ => self.t.bad += 1,
            }
            r.release();
        }
        if self.peers[pi].gen != gen {
            r.clear();
        }
        self.peers[pi].reasm = Some(r);
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
        let Exit { wires, peers, sessions, t, pause, moved, gens, .. } = self;
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
            sess.observe |= h.epoch[0] & frame::CAP_OBSERVE != 0;
            if gens.told {
                wires[peer.wire].glue(peer, Class::Own, 1, now, frame::put_drain);
            }
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
        self.flow_dgram(s, m, wire_id, stream, seq, port, payload, now);
    }

    /// A datagram of flow `stream` of session s that came on member m (a
    /// peer, or a stream member: LINK_SEEN) of wire `wire_id`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn flow_dgram(&mut self, s: usize, m: Seen, wire_id: u8, stream: u32, seq: u32, port: u16, payload: &[u8], now: u64) {
        let fi = match self.sessions.all[s].flows.get(&stream) {
            Some(&fi) => fi,
            None => {
                if port != ECHO_PORT && !self.ports[port as usize] {
                    self.t.refused += 1;
                    return;
                }
                let fi = self.flows.open(&mut self.sessions.all[s].flows, s, stream, port, now);
                if port != ECHO_PORT && self.relay_open(fi).is_err() {
                    self.end_flow(fi, END_LOCAL, now);
                    self.t.refused += 1;
                    return;
                }
                fi
            }
        };
        let f = &mut self.flows.all[fi];
        if f.arrived(m, wire_id, seq, now) {
            if !f.echo() {
                self.t.dgrams_copy += 1;
                f.obs.copies += 1;
            }
            return;
        }
        f.used = now;
        if f.echo() {
            self.answer(fi, payload, now);
            return;
        }
        self.t.dgrams_in += 1;
        if sys::send_nowait(f.fd, payload) {
            f.obs.delivered += 1;
        } else {
            self.t.refused += 1;
        }
    }

    /// One answer of flow fi down to the entry: the flow's next seq, glued
    /// for the members of every wire it goes on (flow::Flow::answer_on,
    /// Heard::carriers), a wire of stream members (the pool) as any other.
    /// A set that has no member up goes on any member up of the session,
    /// packet members first (trunk sendDgramLocked on the exit).
    pub(super) fn answer(&mut self, fi: usize, payload: &[u8], now: u64) {
        let Exit { flows, sessions, peers, wires, carriers, links, .. } = self;
        let f = &mut flows.all[fi];
        f.seq = f.seq.wrapping_add(1);
        f.obs.out += 1;
        let (stream, seq, port, s) = (f.stream, f.seq, f.port, f.session);
        let sess = &sessions.all[s];
        let la = &links.all;
        let link_up = move |li: usize, gen: u32| la.get(li).is_some_and(|l| l.live && l.gen as u32 == gen && l.session == s && l.h.up);
        let up = |m: Seen| match link_slot(m) {
            Some(li) => link_up(li, m.1),
            None => peers.get(m.0).is_some_and(|p| p.live && p.gen == m.1 && p.session == s),
        };
        // A wire's stream members up (any wire's for None), as Seen.
        let links_of = |wire: Option<u8>| {
            sess.links
                .iter()
                .filter(move |&&(li, w)| wire.is_none_or(|x| x == w) && link_up(li, la[li].gen as u32))
                .map(move |&(li, _)| (li | LINK_SEEN, la[li].gen as u32))
        };
        let mut n = 0;
        for h in f.answer_on(now) {
            n = h.carriers(up, sess.of_wire(h.wire).iter().copied().chain(links_of(Some(h.wire))), carriers, n);
        }
        if n == 0 {
            n = Heard { copies: 1, ..Heard::FREE }.carriers(up, sess.members.iter().copied().chain(links_of(None)), carriers, 0);
        }
        let len = DGRAM_HEAD + payload.len();
        for &m in &carriers[..n] {
            match link_slot(m) {
                // A member whose buffer is full takes no writes and dies by
                // its stall: the answer is lost, as on a full socket.
                Some(li) => {
                    let _ = links.all[li].out.frame(len, |b| frame::put_dgram(b, stream, seq, port, payload));
                }
                None => {
                    let p = &mut peers[m.0];
                    wires[p.wire].glue(p, Class::Flow(stream), len, now, |b| frame::put_dgram(b, stream, seq, port, payload));
                }
            }
        }
    }
}
