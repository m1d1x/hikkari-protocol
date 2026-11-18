//! The exit's flows (spec/trunk.md, "Datagrams"; trunk flows.go on the
//! exit): one per stream id of a session, a socket of its own to the
//! loopback port (or none for the trunk's own call, port 0, answered straight
//! back). Copies are dropped by the entry's seq (hikkari_trunk::flow::Replay).
//! The exit answers a flow as the entry sends it (trunk fates.go:
//! heardLocked, answerSet): on every wire its datagrams came on in the last
//! second (ANSWER_NS), the entry's set of wires of different fates; with none
//! in that window, on the wire they came on last. On each wire, on one
//! member until a copy of a datagram comes on that same wire, then on 2: a
//! copy that came on another wire is the set's, not the wire's Copies.
//!
//! Which members of a wire carry an answer: the ones the flow last came on
//! there, newest first, while they are up; failing those, any member up of
//! the session on that wire. A set that carried nothing goes on any member
//! up. Keeping to the members the entry chose keeps a flow on the paths the
//! entry's members hear.

use std::collections::HashMap;
use std::net::UdpSocket;

use hikkari_trunk::echo::EchoMap;
use hikkari_trunk::demand::Holes;
use hikkari_trunk::flow::{Replay, ANSWER_NS, COPIES, ECHO_PORT, MAX_CARRIES};
use hikkari_trunk::observe::FlowObs;

use crate::peer::NONE;

/// A member a flow came on: its slot and the slot's use (Peer.gen, or
/// Link.gen for a stream member, whose slot has LINK_SEEN set).
pub type Seen = (usize, u32);

/// Marks a Seen slot as a stream member's (a link slot), not a peer's.
pub const LINK_SEEN: usize = 1 << 48;

/// The link slot of m, if m is a stream member.
#[inline]
pub fn link_slot(m: Seen) -> Option<usize> {
    (m.0 != NONE && m.0 & LINK_SEEN != 0).then_some(m.0 & !LINK_SEEN)
}

pub struct Flow {
    pub live: bool,
    /// Counts the slot's uses: a relay socket's readiness names a flow by
    /// slot and gen, so a late one for a flow that ended finds nothing.
    pub gen: u32,
    pub session: usize,
    pub stream: u32,
    pub port: u16,
    /// The exit's own seq of its answers.
    pub seq: u32,
    pub replay: Replay,
    /// Its datagrams that came on packet wires, to tell their holes there
    /// (hikkari_trunk::demand).
    pub holes: Holes,
    /// The wires it came on, the newest MAX_CARRIES.
    pub heard: [Heard; MAX_CARRIES],
    pub sock: Option<UdpSocket>,
    pub fd: i32,
    pub used: u64,
    /// What it did, for a tester's report (spec/trunk.md, "Observation"),
    /// and its relay socket's port, which the brain knows it by.
    pub obs: FlowObs,
    pub local_port: u16,
    /// The trunk's call: the frames the exit has had (hikkari_trunk::echo).
    pub echoed: EchoMap,
    /// The session and id it had before the entry's new process adopted it
    /// (exit/adopt.rs), which still reach it; NONE for none.
    pub alias: (usize, u32),
}

impl Flow {
    fn vacant() -> Flow {
        Flow {
            live: false,
            gen: 0,
            session: NONE,
            stream: 0,
            port: 0,
            seq: 0,
            replay: Replay::default(),
            holes: Holes::default(),
            heard: [Heard::FREE; MAX_CARRIES],
            sock: None,
            fd: -1,
            used: 0,
            obs: FlowObs::default(),
            local_port: 0,
            echoed: EchoMap::default(),
            alias: (NONE, 0),
        }
    }

    #[inline]
    pub fn echo(&self) -> bool {
        self.port == ECHO_PORT
    }

    /// A datagram of it came on member `m` of wire `wire` at `now`; whether
    /// it is a copy (seq seen). A copy no newer than what this wire brought
    /// before is the entry's copies on this wire: its answers there go on
    /// COPIES members (trunk heardLocked).
    #[inline]
    pub fn arrived(&mut self, m: Seen, wire: u8, seq: u32, now: u64) -> bool {
        let dup = self.replay.seen(seq);
        // Its wire's slot; else a free one, else the wire heard the longest ago.
        let mut slot = 0;
        for i in 0..MAX_CARRIES {
            let older = self.heard[slot].copies > 0 && (self.heard[i].copies == 0 || self.heard[i].last < self.heard[slot].last);
            let h = &mut self.heard[i];
            if h.copies > 0 && h.wire == wire {
                if dup && seq <= h.top {
                    h.copies = COPIES;
                }
                h.last = now;
                h.top = h.top.max(seq);
                if h.came[0] != m {
                    h.came = [m, h.came[0]];
                }
                return dup;
            }
            if older {
                slot = i;
            }
        }
        self.heard[slot] = Heard { wire, last: now, top: seq, copies: 1, came: [m, (NONE, 0)] };
        dup
    }

    /// The wires an answer goes on at `now`: every wire heard in the last
    /// ANSWER_NS, or the latest one heard when none was (trunk answerSet).
    pub fn answer_on(&self, now: u64) -> impl Iterator<Item = &Heard> {
        let latest = self.heard.iter().filter(|h| h.copies > 0).max_by_key(|h| h.last).map(|h| h.last);
        let none_near = !self.heard.iter().any(|h| h.copies > 0 && now.saturating_sub(h.last) <= ANSWER_NS);
        self.heard.iter().filter(move |h| h.copies > 0 && (now.saturating_sub(h.last) <= ANSWER_NS || none_near && Some(h.last) == latest))
    }
}

/// A wire a flow came on (trunk heardOn): when last, the newest seq it
/// brought, on how many members to answer there (0: a free slot), and the
/// last two members of it the flow came on, newest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heard {
    pub wire: u8,
    pub last: u64,
    pub top: u32,
    pub copies: u8,
    pub came: [Seen; 2],
}

impl Heard {
    pub const FREE: Heard = Heard { wire: 0, last: 0, top: 0, copies: 0, came: [(NONE, 0); 2] };

    /// The members of this wire an answer goes on, after the `n` of `out`
    /// already taken: the ones the flow came on here while up, then the
    /// session's members up on this wire, `wire` (as Seen). Says how many
    /// there are now.
    pub fn carriers(&self, up: impl Fn(Seen) -> bool, wire: impl Iterator<Item = Seen>, out: &mut [Seen], mut n: usize) -> usize {
        let end = (n + (self.copies as usize).clamp(1, 2)).min(out.len());
        for m in self.came.iter().copied().filter(|&m| m.0 != NONE && up(m)).chain(wire) {
            if n == end {
                break;
            }
            if m.0 != NONE && !out[..n].contains(&m) {
                out[n] = m;
                n += 1;
            }
        }
        n
    }
}

/// Every session's flows in one slab, each session's found by stream id.
pub struct Flows {
    pub all: Vec<Flow>,
    free: Vec<usize>,
    /// The clients' flows open (the trunk's own call left out).
    pub clients: u32,
}

impl Default for Flows {
    fn default() -> Flows {
        Flows::new()
    }
}

impl Flows {
    pub fn new() -> Flows {
        Flows { all: Vec::with_capacity(1024), free: Vec::new(), clients: 0 }
    }

    /// A new flow of session `s`, registered in its map.
    pub fn open(&mut self, by_stream: &mut HashMap<u32, usize>, s: usize, stream: u32, port: u16, now: u64) -> usize {
        let i = self.free.pop().unwrap_or_else(|| {
            self.all.push(Flow::vacant());
            self.all.len() - 1
        });
        let gen = self.all[i].gen.wrapping_add(1);
        self.all[i] = Flow { live: true, gen, session: s, stream, port, used: now, obs: FlowObs::new(now), ..Flow::vacant() };
        by_stream.insert(stream, i);
        if port != ECHO_PORT {
            self.clients += 1;
        }
        i
    }

    /// Ends flow i: out of its session's map, its socket closed (the caller
    /// took it off the poll first). Returns whether it was a client's.
    pub fn end(&mut self, by_stream: &mut HashMap<u32, usize>, i: usize) -> bool {
        let f = &mut self.all[i];
        if !f.live {
            return false;
        }
        f.live = false;
        f.sock = None;
        f.fd = -1;
        if by_stream.get(&f.stream) == Some(&i) {
            by_stream.remove(&f.stream);
        }
        self.free.push(i);
        let client = f.port != ECHO_PORT;
        if client {
            self.clients -= 1;
        }
        client
    }

    /// Flow i if it is still the use `gen` names.
    #[inline]
    pub fn at(&mut self, i: usize, gen: u32) -> Option<&mut Flow> {
        self.all.get_mut(i).filter(|f| f.live && f.gen == gen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> Flow {
        Flow { live: true, port: 443, ..Flow::vacant() }
    }

    const S: u64 = 1_000_000_000;

    /// The wires an answer goes on now, as (wire, copies).
    fn on(f: &Flow, now: u64) -> Vec<(u8, u8)> {
        let mut v: Vec<_> = f.answer_on(now).map(|h| (h.wire, h.copies)).collect();
        v.sort();
        v
    }

    /// trunk dgramLocked on the exit: on a wire, one member until a copy
    /// comes on that same wire, then 2; a copy is dropped by seq.
    #[test]
    fn answers_go_as_the_entry_sends() {
        let mut f = flow();
        let mut out = [(NONE, 0); 8];
        assert!(!f.arrived((3, 1), 2, 1, 0));
        let h = f.answer_on(0).next().copied().unwrap();
        assert_eq!(h.carriers(|_| true, [(3, 1), (4, 1)].into_iter(), &mut out, 0), 1);
        assert_eq!(out[0], (3, 1), "on the member it came on");
        assert!(!f.arrived((4, 1), 2, 2, 0), "a new seq on another member is new");
        assert_eq!(on(&f, 0), [(2, 1)]);
        let h = f.answer_on(0).next().copied().unwrap();
        assert_eq!(h.carriers(|_| true, [].into_iter(), &mut out, 0), 1);
        assert_eq!(out[0], (4, 1), "the newest member first");
        assert!(f.arrived((3, 1), 2, 2, 0), "the same seq on another member is a copy");
        assert_eq!(on(&f, 0), [(2, COPIES)]);
        let h = f.answer_on(0).next().copied().unwrap();
        assert_eq!(h.carriers(|_| true, [].into_iter(), &mut out, 0), 2);
        assert_eq!(out[..2], [(3, 1), (4, 1)]);
    }

    /// TestTheExitAnswersOnEveryWireOfTheSet: a flow the entry sends on two
    /// wires is answered on both, one member each: the copy that came on the
    /// pool is the set's, not the pool's Copies. A wire not heard for a
    /// second is left out; with none heard in a second, the latest.
    #[test]
    fn the_exit_answers_on_every_wire_of_the_set() {
        let mut f = flow();
        assert!(!f.arrived((3, 1), 1, 1, 0));
        assert!(f.arrived((7 | LINK_SEEN, 1), 0, 1, 0), "the pool's copy");
        assert_eq!(on(&f, 0), [(0, 1), (1, 1)]);
        let mut out = [(NONE, 0); 8];
        let mut n = 0;
        for h in f.answer_on(0) {
            n = h.carriers(|_| true, [].into_iter(), &mut out, n);
        }
        assert_eq!((n, out[0], out[1]), (2, (3, 1), (7 | LINK_SEEN, 1)), "one member of each, in the order heard");
        f.arrived((3, 1), 1, 2, S / 2);
        assert_eq!(on(&f, S + S / 4), [(1, 1)], "the pool not heard for a second");
        assert_eq!(on(&f, 5 * S), [(1, 1)], "none heard in a second: the latest");
    }

    /// A flow heard on more wires than MAX_CARRIES keeps the newest.
    #[test]
    fn a_flow_keeps_the_wires_it_heard_last() {
        let mut f = flow();
        for (i, w) in [1u8, 2, 3, 4, 5].iter().enumerate() {
            f.arrived((i, 1), *w, i as u32 + 1, i as u64);
        }
        assert_eq!(on(&f, 4), [(2, 1), (3, 1), (4, 1), (5, 1)], "wire 1 heard the longest ago gave its slot");
    }

    /// A member the flow came on that is gone (down, or its slot taken by
    /// another member) is passed over for the session's members on that
    /// wire; never the same member twice.
    #[test]
    fn answers_pass_over_a_dead_member() {
        let mut f = flow();
        f.arrived((3, 1), 2, 1, 0);
        f.arrived((4, 1), 2, 1, 0);
        let h = f.answer_on(0).next().copied().unwrap();
        let mut out = [(NONE, 0); 8];
        let up = |m: Seen| m != (4, 1);
        assert_eq!(h.carriers(up, [(5, 1), (3, 1)].into_iter(), &mut out, 0), 2);
        assert_eq!(out[..2], [(3, 1), (5, 1)], "the live one it came on, then the wire's");
        let any = Heard { copies: 1, ..Heard::FREE };
        assert_eq!(any.carriers(|_| false, [(9, 1)].into_iter(), &mut out, 0), 1);
        assert_eq!(out[0], (9, 1), "no member of the set up: any member up");
        assert_eq!(any.carriers(|_| false, [].into_iter(), &mut out, 0), 0, "no member up: the answer is lost");
    }

    #[test]
    fn a_slot_used_again_is_a_new_flow() {
        let mut fl = Flows::new();
        let mut map = HashMap::new();
        let i = fl.open(&mut map, 0, 7, 443, 1);
        let g = fl.all[i].gen;
        assert_eq!(fl.clients, 1);
        assert!(fl.end(&mut map, i));
        assert!(map.is_empty() && fl.clients == 0);
        let j = fl.open(&mut map, 0, 8, ECHO_PORT, 2);
        assert_eq!((i, fl.clients), (j, 0), "the slot is used again; the call is no client's");
        assert!(fl.at(i, g).is_none(), "the old flow's readiness finds nothing");
        assert!(fl.at(j, fl.all[j].gen).is_some());
    }
}
