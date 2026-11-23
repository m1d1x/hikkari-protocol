//! The entry's book of members' source ports (spec/trunk.md, "Members'
//! health": a dead member's source port is rested). A
//! flow the path killed by its source port dies again on that port, the
//! same verdict a minute later (plans/2026-11-02-tcp-flow-loss.md), so a
//! port that took a member down rests for 15 minutes, or one hour for a repeat.
//!
//! Members die about once a second on a bad hour, and in 1-3 h most of the
//! range is dead (11457 of 12768 on 12.11), so every call is O(1): the free
//! ports are a list, a take is one random index into it, the dead come back
//! from one expiry queue per rest duration, and a book with nothing
//! free says so instead of looking. The reference is trunk ports.go
//! (PortBook); like the rest of this crate it reads no clock and draws no
//! randomness of its own: each call takes `now`, a take its random number.

use std::collections::VecDeque;

/// The default rest for a first kill and a recent repeat (trunk ports.go).
const FIRST_DEAD_NS: u64 = 900_000_000_000;
pub const REPEAT_DEAD_NS: u64 = 3_600_000_000_000;

/// The entry's range of source ports (bench goentry's, trunk's default).
pub const LO: u16 = 20000;
pub const HI: u16 = 32767;

/// Not in the free list.
const NOT_FREE: u32 = u32::MAX;

pub struct Book {
    lo: u16,
    dead_for_ns: u64,
    /// Ports neither dead nor in use, in no order.
    free: Vec<u16>,
    /// pos[port - lo]: its index in free, or NOT_FREE.
    pos: Vec<u32>,
    in_use: Vec<bool>,
    /// until[port - lo]: dead until then; 0 when not dead.
    until: Vec<u64>,
    /// Previous kill, even after expiry. Empty for a fixed duration.
    last: Vec<Option<u64>>,
    /// Short and long expiry queues. Entries with an old deadline are stale.
    queues: [VecDeque<(u16, u64)>; 2],
    dead: usize,
    kills: u64,
}

impl Book {
    /// A book of the ports [lo, hi]: at least 256 of them, above 1023.
    pub fn new(lo: u16, hi: u16, dead_for_ns: u64) -> Result<Book, String> {
        if lo < 1024 || hi < lo || hi - lo < 256 {
            return Err(format!("source ports {lo}-{hi}: need at least 256 above 1023"));
        }
        let span = (hi - lo) as usize + 1;
        Ok(Book {
            lo,
            dead_for_ns,
            free: (lo..=hi).collect(),
            pos: (0..span as u32).collect(),
            in_use: vec![false; span],
            until: vec![0; span],
            last: if dead_for_ns == 0 { vec![None; span] } else { Vec::new() },
            queues: Default::default(),
            dead: 0,
            kills: 0,
        })
    }

    /// A port neither dead nor in use, picked by `r` (any random number),
    /// now in use until `release`; None when every port is dead or in use,
    /// and the caller waits as on any failed dial.
    pub fn take(&mut self, now: u64, r: u64) -> Option<u16> {
        self.expire(now);
        if self.free.is_empty() {
            return None;
        }
        let port = self.free[(r % self.free.len() as u64) as usize];
        self.unfree(port);
        let i = self.at(port);
        self.in_use[i] = true;
        Some(port)
    }

    /// A port taken is no longer in use: free again unless it died. A port
    /// not in use is left as it is, so a second release changes nothing.
    pub fn release(&mut self, port: u16) {
        let Some(i) = self.index(port) else { return };
        if !self.in_use[i] {
            return;
        }
        self.in_use[i] = false;
        if self.until[i] == 0 {
            self.add_free(port);
        }
    }

    /// A port the path killed: its rest starts at this kill.
    pub fn dead(&mut self, port: u16, now: u64) {
        let Some(i) = self.index(port) else { return };
        self.expire(now);
        if self.until[i] == 0 {
            self.dead += 1;
            self.unfree(port);
        }
        let (duration, queue) = if let Some(last) = self.last.get_mut(i) {
            let repeat = last.is_some_and(|t| now - t < REPEAT_DEAD_NS);
            *last = Some(now);
            if repeat { (REPEAT_DEAD_NS, 1) } else { (FIRST_DEAD_NS, 0) }
        } else {
            (self.dead_for_ns, 1)
        };
        let until = now + duration;
        self.until[i] = until;
        self.queues[queue].push_back((port, until));
        self.kills += 1;
    }

    /// Ports out of use now, and every kill it saw.
    pub fn counts(&mut self, now: u64) -> (usize, u64) {
        self.expire(now);
        (self.dead, self.kills)
    }

    /// Ports free, and out of use as of the last call that took `now`.
    pub fn free(&self) -> usize {
        self.free.len()
    }

    pub fn dead_now(&self) -> (usize, u64) {
        (self.dead, self.kills)
    }

    /// Each queue has a fixed duration and expires in insertion order.
    fn expire(&mut self, now: u64) {
        for queue in 0..self.queues.len() {
            while let Some(&(port, until)) = self.queues[queue].front() {
                if until > now {
                    break;
                }
                self.queues[queue].pop_front();
                let i = self.at(port);
                if self.until[i] != until {
                    continue; // killed again later: a later entry brings it back
                }
                self.until[i] = 0;
                self.dead -= 1;
                if !self.in_use[i] {
                    self.add_free(port);
                }
            }
        }
    }

    fn index(&self, port: u16) -> Option<usize> {
        let i = port.checked_sub(self.lo)? as usize;
        (i < self.pos.len()).then_some(i)
    }

    fn at(&self, port: u16) -> usize {
        (port - self.lo) as usize
    }

    fn unfree(&mut self, port: u16) {
        let i = self.at(port);
        let p = self.pos[i];
        if p == NOT_FREE {
            return;
        }
        let moved = self.free.swap_remove(p as usize);
        debug_assert_eq!(moved, port);
        if let Some(&last) = self.free.get(p as usize) {
            let li = self.at(last);
            self.pos[li] = p;
        }
        self.pos[i] = NOT_FREE;
    }

    fn add_free(&mut self, port: u16) {
        let i = self.at(port);
        if self.pos[i] != NOT_FREE {
            return;
        }
        self.pos[i] = self.free.len() as u32;
        self.free.push(port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = REPEAT_DEAD_NS;
    const T0: u64 = 1_000_000_000;

    /// 257 ports, as trunk ports_test.go bookAt.
    fn book() -> Book {
        Book::new(20000, 20256, HOUR).unwrap()
    }

    fn frees(b: &Book) -> Vec<u16> {
        let mut f = b.free.clone();
        f.sort_unstable();
        f
    }

    /// trunk TestAFullBookSaysSoAndDoesNotHang: a book with every port dead
    /// or in use answers None at once; a double release frees one port.
    #[test]
    fn a_full_book_says_so_and_does_not_hang() {
        let mut b = book();
        for p in (20000..=20256).step_by(2) {
            b.dead(p, T0);
        }
        let mut held = vec![];
        for r in 0..128u64 {
            let p = b.take(T0, r * 7919).expect("a free odd port");
            assert_eq!(p % 2, 1, "took dead port {p}");
            held.push(p);
        }
        assert_eq!(b.take(T0, 1), None, "full book");
        b.release(held[0]);
        b.release(held[0]); // twice is once
        assert_eq!(b.take(T0, 5), Some(held[0]));
        assert_eq!(b.take(T0, 5), None, "a double release freed two ports");
    }

    /// trunk TestDeadPortsComeBackOnTime: a port comes back dead_for after
    /// its last kill; one killed in use stays out after its release, and
    /// one expired in use comes back on release.
    #[test]
    fn dead_ports_come_back_on_time() {
        let mut b = book();
        let port = b.take(T0, 3).unwrap();
        b.dead(port, T0); // killed under a member
        b.release(port);
        let other = if port == 20000 { 20001 } else { 20000 };
        b.dead(other, T0);
        let half = HOUR / 2;
        b.dead(other, T0 + half); // again: its hour starts over
        assert_eq!(b.counts(T0 + half), (2, 3));
        let t = T0 + HOUR + 1_000_000_000;
        assert_eq!(b.counts(t).0, 1);
        assert!(frees(&b).contains(&port) && !frees(&b).contains(&other));
        let t = t + half;
        assert_eq!(b.counts(t).0, 0);
        assert_eq!(b.free(), 257);
        let port = b.take(t, 11).unwrap();
        b.dead(port, t);
        let t = t + 2 * HOUR;
        b.counts(t);
        assert!(!frees(&b).contains(&port), "a port in use came back as free");
        b.release(port);
        assert!(frees(&b).contains(&port), "an expired port in use did not come back on release");
    }

    #[test]
    fn a_first_kill_expires_before_an_older_repeat() {
        let mut b = Book::new(20000, 20256, 0).unwrap();
        b.dead(20000, T0);
        let retry = T0 + FIRST_DEAD_NS;
        assert_eq!(b.counts(retry), (0, 1));
        b.dead(20000, retry);
        b.dead(20001, retry + 1);
        assert_eq!(b.counts(retry + FIRST_DEAD_NS + 1), (1, 3));
        assert!(!frees(&b).contains(&20000));
        assert!(frees(&b).contains(&20001));
        assert_eq!(b.counts(retry + HOUR), (0, 3));
    }

    /// The list and its index agree after any mix of takes, kills, releases
    /// and expiries: every port is in exactly one of free, in use, dead.
    #[test]
    fn every_port_is_free_in_use_or_dead() {
        let mut b = book();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut held: Vec<u16> = vec![];
        let mut now = T0;
        for step in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            now += 1_000_000_000;
            match x % 4 {
                0 | 1 => {
                    if let Some(p) = b.take(now, x >> 8) {
                        held.push(p);
                    }
                }
                2 if !held.is_empty() => {
                    let p = held.swap_remove((x >> 8) as usize % held.len());
                    if x & 0x100 != 0 {
                        b.dead(p, now);
                    }
                    b.release(p);
                }
                _ => b.dead(20000 + (x >> 8) as u16 % 257, now),
            }
            let (dead, _) = b.counts(now);
            for (i, &p) in b.free.iter().enumerate() {
                let at = b.at(p);
                assert_eq!(b.pos[at] as usize, i, "step {step}: index of {p}");
                assert!(!b.in_use[at] && b.until[at] == 0, "step {step}: {p} free and taken or dead");
            }
            let free_or_used = (0..257).filter(|&i| b.until[i] == 0).count();
            assert_eq!(free_or_used + dead, 257, "step {step}");
            assert_eq!(b.free.len() + b.in_use.iter().enumerate().filter(|&(i, &u)| u && b.until[i] == 0).count(), free_or_used);
        }
    }

    #[test]
    fn a_range_under_256_ports_is_refused() {
        assert!(Book::new(20000, 20100, HOUR).is_err());
        assert!(Book::new(80, 1000, HOUR).is_err());
        assert!(Book::new(LO, HI, 0).is_ok());
    }
}
