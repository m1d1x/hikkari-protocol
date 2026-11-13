//! The packets: clients → wires, wires → clients and the brain.

use std::os::fd::AsRawFd;

use hikkari_sys::{self as sys, now_ns, BATCH};
use hikkari_trunk::frame::{self, Frame};

use hikkari_sys::SeqPacket;

use super::generation::{forward, owner_key};
use super::{Event, Listen, Pipe, Slot};
use crate::carry::carry;
use crate::ctl::{self, ANY_WIRE};
use crate::flow::{Dest, Flow, Flows};

impl Pipe {
    /// Clients → wires; a datagram from an address whose flow an older
    /// generation keeps goes to it (generation.rs).
    pub(super) fn read_clients(&mut self) {
        let Pipe { poll, slots, listens, crecv, flows, wires, swires, route, moved, older, owners, msg, cur, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            let Slot::Listen(li) = *s else { continue };
            if !poll.readable(si) {
                continue;
            }
            let l = &listens[li];
            let fd = l.sock.as_raw_fd();
            loop {
                let n = crecv.recv(fd);
                let now = now_ns();
                for i in 0..n {
                    let addr = crecv.addr[i];
                    let key = client_key(li, &addr);
                    let seg = crecv.seg[i];
                    let len = crecv.len[i];
                    let step = if seg == 0 { len } else { seg };
                    let p = &crecv.buf[i * crecv.slot..i * crecv.slot + len];
                    if !owners.is_empty() {
                        if let Some(&o) = owners.get(&owner_key(l.id, &addr)) {
                            forward(&mut older[o as usize], msg, l.id, &addr, p, step);
                            continue;
                        }
                    }
                    take_client(flows, wires, swires, *route, l, li, addr, key, p, step, now, moved, *cur);
                }
                if n < BATCH {
                    break;
                }
            }
        }
    }

    /// Wires → clients and the brain.
    pub(super) fn read_wires(&mut self) {
        let Pipe { poll, slots, wires, wrecv, flows, listens, ctl, out, events, moved, bad, judge, drains, cur, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            let Slot::Member(wi, mi) = *s else { continue };
            if !poll.readable(si) {
                continue;
            }
            let w = &mut wires[wi];
            let (wid, glue_max, sess) = (w.id, w.glue_max, w.sess);
            let m = &mut w.members[mi];
            if m.fd < 0 {
                continue;
            }
            loop {
                let n = wrecv.recv(m.fd);
                let now = now_ns();
                for i in 0..n {
                    let slot = wrecv.slot;
                    let len = wrecv.len[i];
                    let d = &mut wrecv.buf[i * slot..i * slot + len];
                    let Some(pn) = m.seal.open(d) else {
                        *bad += 1;
                        continue;
                    };
                    let p = &d[12..12 + pn];
                    let mut at = 0;
                    while let Some((fr, nx)) = frame::next_frame(p, at) {
                        match fr {
                            Frame::Dgram { stream, seq, off, len, .. } => {
                                w.t.down_pkts += 1;
                                w.t.down_bytes += len as u64;
                                *moved += 1;
                                deliver(flows, listens, ctl, out, &p[off..off + len], stream, seq, now, sess);
                            }
                            Frame::Hello => {
                                if !m.h.up {
                                    m.h.join(now);
                                    if sess == *cur {
                                        events.push(Event { wire: wid, index: mi as u8, up: true, why: ctl::WHY_HELLO });
                                    }
                                }
                            }
                            // The exit's process is being replaced: answered
                            // once per session, on the turn after (session.rs).
                            Frame::Drain => *drains |= 1u32 << sess,
                            Frame::Ping(t) => {
                                m.glue_frame(9, glue_max, now, |b| frame::put_ping(b, frame::F_PONG, t));
                            }
                            Frame::Pong(t) => {
                                if m.h.pong(judge, t, now) {
                                    w.proof = now;
                                }
                            }
                            // A packet member without the streams flag carries
                            // no stream frames (spec/trunk.md, "Wires").
                            Frame::Open { .. }
                            | Frame::Data { .. }
                            | Frame::Ack { .. }
                            | Frame::Fin { .. }
                            | Frame::Rst { .. }
                            | Frame::Other => {}
                        }
                        at = nx;
                    }
                }
                // The answers point into wrecv: send them before reading again.
                for l in listens.iter_mut() {
                    l.down.flush(l.sock.as_raw_fd());
                }
                if n < BATCH {
                    break;
                }
            }
            if m.glue_n > 0 {
                m.seal_glue(); // pongs go at once
                m.flush_out();
            }
        }
        self.send_events();
    }
}

/// A datagram of trunk stream `stream` from the exit, on a member of session
/// `sess`: to its client (queued in the listen's batch, pointing into the
/// receive buffer) or to the brain; a copy already seen is dropped
/// (spec/trunk.md, "Datagrams"), as is one whose flow ended here, and one
/// from another session than its flow's (a brain's call moved to the new
/// one: the exit's old process still answers what it had).
#[allow(clippy::too_many_arguments)]
#[inline]
pub(super) fn deliver(flows: &mut Flows, listens: &mut [Listen], ctl: &mut Option<SeqPacket>, out: &mut [u8], p: &[u8], stream: u32, seq: u32, now: u64, sess: u8) {
    let Some((f, counts)) = flows.with_counts(stream) else { return };
    if f.sess != sess {
        return;
    }
    let echo = f.echo();
    if f.replay.seen(seq) {
        if !echo {
            counts.copies += 1;
        }
        return;
    }
    f.used = now;
    if !echo {
        counts.delivered += 1;
    }
    match &f.dest {
        Dest::Client { listen, addr } => {
            let l = &mut listens[*listen as usize];
            if l.down.full() {
                l.down.flush(l.sock.as_raw_fd());
            }
            l.down.push(p.as_ptr(), p.len(), Some(addr));
        }
        Dest::Brain { tag } => {
            if let Some(c) = ctl {
                let k = ctl::put_dgram(out, *tag, p);
                c.send(&out[..k]);
            }
        }
        Dest::Gone => {}
    }
}

/// A client's key in the flows: its listen (by index) and address.
#[inline]
pub(super) fn client_key(li: usize, addr: &sys::sockaddr_in) -> u64 {
    ((li as u64) << 48) | sys::addr_key(addr)
}

/// A client datagram (segments of `step` bytes in p, as GRO read them) on
/// its flow, opened by its first on session `sess`; false when no flow could
/// be opened (MAX_FLOWS open).
#[allow(clippy::too_many_arguments)]
#[inline]
pub(super) fn take_client(
    flows: &mut Flows,
    wires: &mut [crate::member::Wire],
    swires: &mut [crate::link::StreamWire],
    route: [u8; 2],
    l: &Listen,
    li: usize,
    addr: sys::sockaddr_in,
    key: u64,
    p: &[u8],
    step: usize,
    now: u64,
    moved: &mut u64,
    sess: u8,
) -> bool {
    let new = || {
        let mut f = Flow::new(Dest::Client { listen: li as u16, addr }, l.class, ANY_WIRE, l.to, l.copies, now);
        f.sess = sess;
        f
    };
    let Some(id) = flows.client(key, new) else {
        return false;
    };
    let Some((f, counts)) = flows.with_counts(id) else { return false };
    let mut at = 0;
    while at < p.len() {
        carry(wires, swires, route, f, id, &p[at..(at + step).min(p.len())], now);
        if !f.echo() {
            counts.out += 1;
        }
        *moved += 1;
        at += step;
    }
    true
}
