//! The packets: clients → wires, wires → clients and the brain.

use std::os::fd::AsRawFd;

use hikkari_sys::{self as sys, now_ns, BATCH};
use hikkari_trunk::frame::{self, Frame};

use hikkari_sys::SeqPacket;

use super::{Event, Listen, Pipe, Slot};
use crate::carry::carry;
use crate::ctl::{self, ANY_WIRE};
use crate::flow::{Dest, Flow, Flows};

impl Pipe {
    /// Clients → wires.
    pub(super) fn read_clients(&mut self) {
        let Pipe { poll, slots, listens, crecv, flows, wires, route, moved, .. } = self;
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
                    let key = ((li as u64) << 48) | sys::addr_key(&crecv.addr[i]);
                    let addr = crecv.addr[i];
                    let Some(id) = flows.client(key, || Flow::new(Dest::Client { listen: li as u16, addr }, l.class, ANY_WIRE, l.to, l.copies, now))
                    else {
                        continue; // MAX_FLOWS open: no flow for a new client
                    };
                    let seg = crecv.seg[i];
                    let len = crecv.len[i];
                    let step = if seg == 0 { len } else { seg };
                    let base = i * crecv.slot;
                    let Some((f, counts)) = flows.with_counts(id) else { continue };
                    let mut at = 0;
                    while at < len {
                        let p = &crecv.buf[base + at..base + (at + step).min(len)];
                        carry(wires, *route, f, id, p, now);
                        if !f.echo() {
                            counts.out += 1;
                        }
                        *moved += 1;
                        at += step;
                    }
                }
                if n < BATCH {
                    break;
                }
            }
        }
    }

    /// Wires → clients and the brain.
    pub(super) fn read_wires(&mut self) {
        let Pipe { poll, slots, wires, wrecv, flows, listens, ctl, out, events, moved, bad, judge, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            let Slot::Member(wi, mi) = *s else { continue };
            if !poll.readable(si) {
                continue;
            }
            let w = &mut wires[wi];
            let (wid, glue_max) = (w.id, w.glue_max);
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
                                deliver(flows, listens, ctl, out, &p[off..off + len], stream, seq, now);
                            }
                            Frame::Hello => {
                                if !m.h.up {
                                    m.h.join(now);
                                    events.push(Event { wire: wid, index: mi as u8, up: true, why: ctl::WHY_HELLO });
                                }
                            }
                            Frame::Ping(t) => {
                                m.glue_frame(9, glue_max, now, |b| frame::put_ping(b, frame::F_PONG, t));
                            }
                            Frame::Pong(t) => {
                                if m.h.pong(judge, t, now) {
                                    w.proof = now;
                                }
                            }
                            Frame::Drain | Frame::Other => {}
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

/// A datagram of trunk stream `stream` from the exit: to its client (queued
/// in the listen's batch, pointing into the receive buffer) or to the brain;
/// a copy already seen is dropped (spec/trunk.md, "Datagrams"), as is one
/// whose flow ended here.
#[allow(clippy::too_many_arguments)]
#[inline]
fn deliver(flows: &mut Flows, listens: &mut [Listen], ctl: &mut Option<SeqPacket>, out: &mut [u8], p: &[u8], stream: u32, seq: u32, now: u64) {
    let Some((f, counts)) = flows.with_counts(stream) else { return };
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
