//! A stream member's death (spec/trunk.md, "Member": dead, its chunks sent
//! again on the other members oldest first as they have room). What it
//! carried unconfirmed, opens, chunks and FINs, waits as stranded in each
//! stream and goes again ahead of anything new, a chunk with the bytes its
//! stream kept (hikkari_trunk::stream::Kept); no stream is reset by it. The
//! reference is trunk session.go: dropMemberLocked, drainPendingLocked.

use hikkari_sys as sys;
use hikkari_trunk::frame::{self, NO_GOT};

use super::tcp::{ack, pick};
use super::timers::SPREAD;
use super::{Event, Pipe};
use crate::ctl;
use crate::link::{carrier, Dialed};

impl Pipe {
    /// What dead members carried, sent again oldest first (stream by stream
    /// in the order they were opened, each in the order it sent) as far as
    /// the members up have room; a chunk only on a member with room under
    /// INFLIGHT (trunk drainPendingLocked). Each session's members carry its
    /// own streams' alone, so a session that has no room waits without
    /// holding the others. The sessions that still have something waiting,
    /// a bit each.
    pub(super) fn resend(&mut self, now: u64) -> u32 {
        let Pipe { streams, swires, route, stranded, moved, .. } = self;
        let mut waits = 0u32;
        let mut from = 0u32;
        while let Some(&id) = stranded.range(from..).next() {
            from = id.saturating_add(1);
            let Some(slot) = streams.slot_of(id) else {
                stranded.remove(&id);
                continue;
            };
            let (st, n) = streams.with_counts(slot).unwrap();
            if waits & (1 << st.sess) != 0 {
                continue;
            }
            let mut done = true;
            while let Some(i) = st.send.next_stranded() {
                let o = st.send.owed[i];
                let Some((wi, li)) = pick(swires, st.sess, route[0], o.kind == frame::F_DATA) else {
                    done = false;
                    break;
                };
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
                    done = false;
                    break;
                }
                st.send.resent(i, carrier(wi, li, l.gen));
                l.owe(o.len as usize, now);
            }
            if done {
                stranded.remove(&id);
            } else {
                waits |= 1 << st.sess;
            }
            if id == u32::MAX {
                break;
            }
        }
        waits
    }

    /// Member li of wire wi is down (trunk dropMemberLocked): what it carried
    /// unconfirmed goes again on the other members, every stream acks again
    /// elsewhere (the acks it carried may be lost), and it is dialed anew
    /// after its backoff, spread over a second as the UDP members are. A
    /// port the path killed (the member stalled, or its dial or hello got no
    /// answer) stays out of use for an hour (spec/trunk.md, "Members'
    /// health"; trunk Entry.slot).
    pub(super) fn link_down(&mut self, wi: usize, li: usize, down: Down, now: u64) {
        let Pipe { swires, ports, .. } = self;
        let l = &mut swires[wi].links[li];
        let (was_up, c) = (l.h.up, carrier(wi, li, l.gen));
        if matches!(down, Down::Stalled { .. } | Down::Silent) && l.port != 0 {
            ports.dead(l.port, now);
        }
        match down {
            // The path killed the flow, not the exit: another port now. Many
            // in a row is the path itself, and the member waits.
            Down::Stalled { .. } => {
                l.stalls += 1;
                if l.stalls > 3 {
                    l.grow();
                } else {
                    l.backoff_ns = 0;
                }
            }
            Down::Silent | Down::Failed => l.grow(),
            Down::Lost if l.up_at != 0 && now - l.up_at >= LIVED => (l.stalls, l.backoff_ns) = (0, 0),
            Down::Lost => {
                l.stalls = 0;
                l.grow();
            }
        }
        l.drop_sock(ports);
        // Only the session that takes everything new replaces its members
        // (session.rs); the brain hears the current session's.
        let sess = self.swires[wi].sess;
        if self.taker() == Some(sess) {
            self.renew(wi, li, now);
        }
        // A stall is judged on a member up (its health took it down a moment
        // ago): the brain hears every stall, every failed socket, and the
        // end of any member it was told was up.
        let why = down.why();
        if sess == self.cur && (was_up || matches!(down, Down::Stalled { .. }) || why == ctl::WHY_GONE) {
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
            if !st.opened || st.sess != sess {
                continue;
            }
            let Some((wi, li)) = pick(swires, sess, route[0], false) else { break };
            ack(&mut swires[wi].links[li].out, st, NO_GOT);
        }
    }
}

/// Why a stream member went down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Down {
    /// It owed progress and proved none (hikkari_trunk::health): trunk
    /// ErrStalled.
    Stalled { quiet: bool },
    /// Its connection or its hello got no answer in time: trunk ErrSilent.
    Silent,
    /// Its connection failed or closed before the exit's hello.
    Failed,
    /// Its connection failed or closed after it.
    Lost,
}

impl Down {
    /// What the brain is told.
    pub(super) fn why(self) -> u8 {
        match self {
            Down::Stalled { quiet: true } => ctl::WHY_QUIET,
            Down::Stalled { quiet: false } => ctl::WHY_SILENT,
            Down::Silent | Down::Failed | Down::Lost => ctl::WHY_GONE,
        }
    }
}

/// A member that lived this long after its hello and then went down is
/// dialed anew without a wait (trunk Entry.slot: 5 s).
const LIVED: u64 = 5_000_000_000;

impl Pipe {
    /// Member li of wire wi is dialed anew after its backoff and a random
    /// part of SPREAD: members that die together do not come back as one
    /// burst of new connections from one box (trunk replaceSpread).
    pub(super) fn renew(&mut self, wi: usize, li: usize, now: u64) {
        let l = &mut self.swires[wi].links[li];
        let mut r = [0u8; 8];
        sys::urandom(&mut r);
        l.renew_at = now + 1 + l.backoff_ns + u64::from_le_bytes(r) % SPREAD;
        self.dirty = true;
    }

    /// Member li of wire wi dials now; a dial that could not begin waits
    /// as a failed one.
    pub(super) fn redial(&mut self, wi: usize, li: usize, now: u64) {
        let Pipe { swires, ports, sessions, dirty, .. } = self;
        let w = &mut swires[wi];
        let l = &mut w.links[li];
        *dirty = true;
        match l.dial(&w.reach, &sessions[w.sess as usize].id, ports, now) {
            Dialed::Begun => {}
            Dialed::NoPort => {
                let (dead, _) = ports.counts(now);
                eprintln!("hk-pipe: wire {} member {li}: no source port free, {dead} dead", w.id);
                l.grow();
                self.renew(wi, li, now);
            }
            Dialed::Failed => {
                l.grow();
                self.renew(wi, li, now);
            }
        }
    }
}
