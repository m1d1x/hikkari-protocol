//! Border points (spec/trunk.md, "Border points"; hikkari-client
//! plans/2026-11-19-border-forwarders.md): the active receiver, the core,
//! reached through boxes that only forward its ports. The core's own
//! address (its wires' and pools' exit) may be one of them or none: the
//! core may be out of the entry's reach, and with points given nothing
//! dials it. Member i of every wire and pool of the active receiver's
//! sessions goes to point i mod n on its wire's port, under the session's
//! one id; the exit joins each by its hello. A point that freezes or dies
//! takes down its own members alone, by their health, and they dial it
//! again as any member does: nothing here chooses a point.
//!
//! The brain dials the members of the current session's bare UDP wires
//! (pipectl SetPoints gives them anew with B_WIRE); the pipe dials every
//! other member itself: the pools' connections, the QUIC wire's tunnels,
//! and the bare UDP members of the sessions it opens on its own.

use std::net::{Ipv4Addr, SocketAddrV4};

use super::death::Down;
use super::Pipe;
use crate::link::NO_SESSION;
use crate::member::member_to;

/// Member i's point: none without points (the wire's own address).
pub(super) fn point(points: &[Ipv4Addr], i: usize) -> Option<Ipv4Addr> {
    (!points.is_empty()).then(|| points[i % points.len()])
}

/// The wire's address at point p, on the wire's port.
pub(super) fn at(exit: SocketAddrV4, p: Option<Ipv4Addr>) -> SocketAddrV4 {
    p.map_or(exit, |ip| SocketAddrV4::new(ip, exit.port()))
}

impl Pipe {
    /// The points the members of a session of receiver rx go to: the
    /// active receiver's alone; a receiver on standby is reached at its own
    /// address.
    pub(super) fn points_of(&self, rx: u8) -> &[Ipv4Addr] {
        if rx == self.sessions[self.cur as usize].rx {
            &self.points
        } else {
            &[]
        }
    }

    /// Each wire and pool says how many points its members are spread
    /// over (carry.rs reads it): the active receiver's sessions as many as
    /// the points, the others none. Once a turn: a handful of wires, and
    /// nothing that makes or moves a wire has to remember it.
    pub(super) fn mark_points(&mut self) {
        let rx = self.sessions[self.cur as usize].rx;
        let n = self.points.len() as u8;
        for w in self.wires.iter_mut() {
            w.points = if w.rx == rx { n } else { 0 };
        }
        for w in self.swires.iter_mut() {
            let on = w.sess != NO_SESSION && self.sessions.get(w.sess as usize).is_some_and(|s| s.live && s.rx == rx);
            w.points = if on { n } else { 0 };
        }
    }

    /// The brain's border points (B_POINTS): the members whose point
    /// changed go to their new one, the others stay as they are. A pool's
    /// member is taken down (what it carried goes again on the others) and
    /// dialed anew; a QUIC wire's member opens its tunnel anew; a bare UDP
    /// member of a session the pipe dials for itself gets a new socket. A
    /// member that waits to dial again (its old address did not answer: the
    /// core out of reach before the points came) dials its new point now:
    /// its backoff was the old address's.
    pub(super) fn set_points(&mut self, ips: Vec<Ipv4Addr>, now: u64) {
        let old = std::mem::replace(&mut self.points, ips);
        if old == self.points {
            return;
        }
        let rx = self.sessions[self.cur as usize].rx;
        let moved = |i: usize| point(&old, i) != point(&self.points, i);
        let mut downs = Vec::new();
        let mut waits = Vec::new();
        for (wi, w) in self.swires.iter().enumerate() {
            if w.sess == NO_SESSION || self.sessions[w.sess as usize].rx != rx {
                continue;
            }
            for (li, l) in w.links.iter().enumerate().filter(|(li, _)| moved(*li)) {
                if l.sock.is_some() {
                    downs.push((wi, li));
                } else if l.renew_at != 0 {
                    waits.push((wi, li));
                }
            }
        }
        let (cur, brains) = (self.cur, self.ctl.is_some());
        let mut events = Vec::new();
        for w in self.wires.iter_mut().filter(|w| w.rx == rx) {
            for (mi, m) in w.members.iter_mut().enumerate() {
                if !moved(mi) {
                    continue;
                }
                if w.h3 {
                    if m.tun.is_none() {
                        // Waiting to open: it opens to its new point now.
                        m.renew_at = 0;
                        continue;
                    }
                    if let Some(h) = self.h3s.iter_mut().find(|h| h.id == w.id && h.rx == w.rx) {
                        h.let_go(w.sess, mi, m.port);
                    }
                    if m.h.up && brains && w.sess == cur {
                        events.push(super::Event { wire: w.id, index: mi as u8, up: false, why: crate::ctl::WHY_GONE });
                    }
                    m.set_tunnel(None, 0);
                    m.renew_at = 0;
                } else if m.fd >= 0 && !(brains && w.sess == cur) {
                    let to = w.exit.map(|e| at(e, point(&self.points, mi)));
                    m.set_sock(to.and_then(|e| member_to(e).ok()));
                }
            }
        }
        self.events.extend(events);
        let n = downs.len();
        for &(wi, li) in &downs {
            self.link_down(wi, li, Down::Lost, now);
        }
        // A new address owes nothing of the old one's backoff: each member
        // the pipe dials again dials after the spread alone.
        for (wi, li) in downs.into_iter().chain(waits) {
            let l = &mut self.swires[wi].links[li];
            l.backoff_ns = 0;
            if l.renew_at != 0 {
                self.renew(wi, li, now);
            }
        }
        eprintln!("hk-pipe: trunk: border points {:?}: {n} pool member(s) move", self.points);
        self.dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// spec/trunk.md, "Border points": member i to point i mod n, on the
    /// wire's port; no points, the wire's own address.
    #[test]
    fn members_go_to_the_points_in_turn() {
        let ps: Vec<Ipv4Addr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let exit: SocketAddrV4 = "10.0.0.1:20461".parse().unwrap();
        let to: Vec<SocketAddrV4> = (0..4).map(|i| at(exit, point(&ps, i))).collect();
        assert_eq!(to, ["10.0.0.1:20461", "10.0.0.2:20461", "10.0.0.1:20461", "10.0.0.2:20461"].map(|a| a.parse().unwrap()));
        assert_eq!(at(exit, point(&[], 3)), exit);
    }
}
