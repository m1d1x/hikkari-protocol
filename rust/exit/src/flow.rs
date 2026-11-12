//! The exit's flows (spec/trunk.md, "Datagrams"; trunk flows.go on the
//! exit): one per stream id of a session, a socket of its own to the
//! loopback port (or none for the trunk's own call, port 0, answered straight
//! back). Copies are dropped by the entry's seq (hikkari_trunk::flow::Replay).
//! The exit answers a flow as the entry sends it: on one member until a copy
//! arrives, then on 2, on the wire the entry last sent it on.
//!
//! Which members carry an answer: the ones the flow last came on, newest
//! first, while they are up; failing those, any member up of the session on
//! the flow's wire, then any member up. The Go exit takes the members with
//! the least unconfirmed bytes, which on packet members (none) is any of the
//! wire's; keeping to the ones the entry chose keeps a flow on the paths the
//! entry's members hear.

use std::collections::HashMap;
use std::net::UdpSocket;

use hikkari_trunk::flow::{Replay, COPIES, ECHO_PORT};

use crate::peer::NONE;

/// A member a flow came on: its slot and the slot's use (Peer.gen).
pub type Seen = (usize, u32);

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
    /// How many members carry each answer: 1 until a copy arrives.
    pub copies: u8,
    /// The wire the entry last sent it on.
    pub wire: u8,
    /// The last two members it came on, newest first.
    pub came: [Seen; 2],
    pub sock: Option<UdpSocket>,
    pub fd: i32,
    pub used: u64,
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
            copies: 1,
            wire: 0,
            came: [(NONE, 0); 2],
            sock: None,
            fd: -1,
            used: 0,
        }
    }

    #[inline]
    pub fn echo(&self) -> bool {
        self.port == ECHO_PORT
    }

    /// A datagram of it came on member `m` of wire `wire`; whether it is a
    /// copy (seq seen), which makes the answers go on COPIES members.
    #[inline]
    pub fn arrived(&mut self, m: Seen, wire: u8, seq: u32) -> bool {
        self.wire = wire;
        if self.came[0] != m {
            self.came[1] = self.came[0];
            self.came[0] = m;
        }
        if self.replay.seen(seq) {
            self.copies = COPIES;
            return true;
        }
        false
    }

    /// The members an answer goes on, into `out` (at most `copies`):
    /// `up(m)` says a member it came on is still up in its session, `wire`
    /// and `any` are the session's members up on the flow's wire and on any.
    pub fn carriers(&self, up: impl Fn(Seen) -> bool, wire: &[Seen], any: &[Seen], out: &mut [Seen; 2]) -> usize {
        let want = (self.copies as usize).clamp(1, 2);
        let mut n = 0;
        let mut add = |m: Seen, n: &mut usize| {
            if *n < want && m.0 != NONE && !out[..*n].contains(&m) {
                out[*n] = m;
                *n += 1;
            }
        };
        for &m in &self.came {
            if m.0 != NONE && up(m) {
                add(m, &mut n);
            }
        }
        for &m in wire.iter().chain(any) {
            add(m, &mut n);
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
        self.all[i] = Flow { live: true, gen, session: s, stream, port, used: now, ..Flow::vacant() };
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

    /// trunk dgramLocked on the exit: one member until a copy arrives,
    /// then 2; a copy is dropped by seq.
    #[test]
    fn answers_go_as_the_entry_sends() {
        let mut f = flow();
        let mut out = [(NONE, 0); 2];
        assert!(!f.arrived((3, 1), 2, 1));
        assert_eq!(f.carriers(|_| true, &[(3, 1), (4, 1)], &[], &mut out), 1);
        assert_eq!(out[0], (3, 1), "on the member it came on");
        assert!(!f.arrived((4, 1), 2, 2), "a new seq on another member is new");
        assert_eq!(f.copies, 1);
        assert_eq!(f.carriers(|_| true, &[], &[], &mut out), 1);
        assert_eq!(out[0], (4, 1), "the newest member first");
        assert!(f.arrived((3, 1), 2, 2), "the same seq on another member is a copy");
        assert_eq!(f.copies, COPIES);
        assert_eq!(f.carriers(|_| true, &[], &[], &mut out), 2);
        assert_eq!(out, [(3, 1), (4, 1)]);
    }

    /// A member the flow came on that is gone (down, or its slot taken by
    /// another member) is passed over for the session's members on the
    /// flow's wire, then any; never the same member twice.
    #[test]
    fn answers_pass_over_a_dead_member() {
        let mut f = flow();
        f.arrived((3, 1), 2, 1);
        f.arrived((4, 1), 2, 1);
        let mut out = [(NONE, 0); 2];
        let up = |m: Seen| m != (4, 1);
        assert_eq!(f.carriers(up, &[(5, 1), (3, 1)], &[(9, 1)], &mut out), 2);
        assert_eq!(out, [(3, 1), (5, 1)], "the live one it came on, then the wire's");
        f.copies = 1;
        assert_eq!(f.carriers(|_| false, &[], &[(9, 1)], &mut out), 1);
        assert_eq!(out[0], (9, 1), "no member of its wire up: any member up");
        assert_eq!(f.carriers(|_| false, &[], &[], &mut out), 0, "no member up: the answer is lost");
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
