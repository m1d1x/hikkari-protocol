//! A stream member's death (spec/trunk.md, "Member": dead, its chunks sent
//! again on the other members oldest first as they have room). What it
//! carried unconfirmed, opens, chunks and FINs, waits as stranded in each
//! stream and goes again ahead of anything new, a chunk with the bytes its
//! stream kept (hikkari_trunk::stream::Kept); no stream is reset by it. The
//! reference is trunk session.go: dropMemberLocked, drainPendingLocked.

use hikkari_sys as sys;
use hikkari_trunk::frame::{self, NO_GOT};

use super::tcp::{ack, pick};
use super::{Event, Pipe};
use crate::ctl;
use crate::link::carrier;

impl Pipe {
    /// What dead members carried, sent again oldest first (stream by stream
    /// in the order they were opened, each in the order it sent) as far as
    /// the members up have room; a chunk only on a member with room under
    /// INFLIGHT (trunk drainPendingLocked). Whether nothing waits any more.
    pub(super) fn resend(&mut self, now: u64) -> bool {
        let Pipe { streams, swires, route, stranded, moved, .. } = self;
        while let Some(&id) = stranded.first() {
            let Some(slot) = streams.slot_of(id) else {
                stranded.pop_first();
                continue;
            };
            let (st, n) = streams.with_counts(slot).unwrap();
            while let Some(i) = st.send.next_stranded() {
                let o = st.send.owed[i];
                let Some((wi, li)) = pick(swires, route[0], o.kind == frame::F_DATA) else { return false };
                let l = &mut swires[wi].links[li];
                let went = match o.kind {
                    frame::F_OPEN => l.out.frame(7, |b| frame::put_open(b, st.id, st.port)),
                    frame::F_FIN => l.out.frame(13, |b| frame::put_fin(b, st.id, o.off)),
                    _ => {
                        let len = o.len as usize;
                        if l.out.chunk_room(len) < len {
                            false
                        } else {
                            l.out.chunk_buf(len).copy_from_slice(st.send.kept.get(o.off, len));
                            l.out.chunk_done(st.id, o.off, len);
                            n.resent += 1;
                            *moved += 1;
                            true
                        }
                    }
                };
                if !went {
                    return false;
                }
                st.send.resent(i, carrier(wi, li, l.gen));
                l.owe(o.len as usize, now);
            }
            stranded.pop_first();
        }
        true
    }

    /// Member li of wire wi is down (trunk dropMemberLocked): what it carried
    /// unconfirmed goes again on the other members, every stream acks again
    /// elsewhere (the acks it carried may be lost), and it is dialed anew
    /// within a second, spread as the UDP members are.
    pub(super) fn link_down(&mut self, wi: usize, li: usize, why: u8, now: u64) {
        let l = &mut self.swires[wi].links[li];
        let (was_up, c) = (l.h.up, carrier(wi, li, l.gen));
        l.drop_sock();
        let mut r = [0u8; 8];
        sys::urandom(&mut r);
        l.renew_at = now + 1 + u64::from_le_bytes(r) % super::timers::SPREAD;
        self.dirty = true;
        if was_up || why == ctl::WHY_GONE {
            let wid = self.swires[wi].id;
            self.events.push(Event { wire: wid, index: li as u8, up: false, why });
        }
        let Pipe { streams, stranded, .. } = self;
        let mut hit = 0;
        for slot in 0..streams.slots() {
            let Some((st, n)) = streams.with_counts(slot) else { continue };
            if st.send.strand(c) {
                stranded.insert(st.id);
                hit += 1;
                n.deaths += 1;
            }
        }
        if hit > 0 {
            self.resend(now);
        }
        let Pipe { streams, swires, route, .. } = self;
        for slot in 0..streams.slots() {
            let Some((st, _)) = streams.with_counts(slot) else { continue };
            if !st.opened {
                continue;
            }
            let Some((wi, li)) = pick(swires, route[0], false) else { break };
            ack(&mut swires[wi].links[li].out, st, NO_GOT);
        }
    }
}
