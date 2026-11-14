//! The scheduler of a Chromium QUIC member's connection (spec/trunk.md,
//! `h3dgram`, "How each end sends"; Go wire/datagram sendqueue.go, the
//! reference), at both ends: the exit's down, the entry's up. The frames
//! bound for the member wait here, not in QUIC's queue, so that while the guard holds the connection to a rate they age
//! here and the freshest of live traffic is what goes. The member's own
//! frames go first; the flows' by deficit round robin over BUCKETS buckets
//! by stream id, QUANTUM bytes a turn; a frame that waited over STALE_NS is
//! dropped right before a datagram is made.
//!
//! A bucket holds its frames in slots of a fixed size; a slot is allocated
//! the first time a bucket holds that many frames and kept: nothing is
//! allocated per frame once the buckets have their depth.

use std::collections::VecDeque;

use crate::guard::Guard;

/// The longest a frame may wait (datagram.StaleAfter).
pub const STALE_NS: u64 = 150_000_000;
/// The bytes a bucket may send in its turn (sendqueue quantum); over FRAME,
/// so that a turn always sends a frame.
const QUANTUM: i64 = 1500;
/// Buckets of flows: a flow shares one with the flows of the same stream id
/// modulo BUCKETS.
pub const BUCKETS: usize = 32;
/// Frames a bucket holds; over it its oldest is dropped. At 150 ms this is
/// 426 frames a second of one bucket, more than any call or game sends; a
/// flood is what it holds back.
const DEPTH: usize = 64;
/// The largest frame (a QUIC DATAGRAM frame's worth, the exit's h3wire DGRAM).
pub const FRAME: usize = 1400;
/// The member's own bucket, after the flows'.
const OWN: usize = BUCKETS;

/// What a frame is to the scheduler.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// The member's own (ping, pong): before any flow's.
    Own,
    /// The member's own that goes in a datagram of its own (the hello's
    /// answer, which the Go entry reads apart from the frames after it).
    Alone,
    /// A flow's, by its stream id.
    Flow(u32),
}

struct Slot {
    at: u64,
    n: u16,
    alone: bool,
    b: [u8; FRAME],
}

#[derive(Default)]
struct Bucket {
    q: VecDeque<Box<Slot>>,
    /// Slots of frames gone, for the next ones. Boxed: a slot moves between
    /// the queue and here as a pointer, not as its 1.4 KB.
    #[allow(clippy::vec_box)]
    spare: Vec<Box<Slot>>,
    deficit: i64,
    active: bool,
}

impl Bucket {
    fn pop(&mut self) -> Box<Slot> {
        self.q.pop_front().expect("a frame")
    }
}

/// What the scheduler counts since the connection came.
#[derive(Default, Clone, Copy, Debug)]
pub struct Counts {
    /// Frames dropped unsent: by age, the oldest of a full bucket, or one
    /// no datagram holds.
    pub stale: u64,
    /// Frames sent, and the sum and the longest of their waits here.
    pub sent: u64,
    pub wait_ns: u64,
    pub wait_max_ns: u64,
}

pub struct Sched {
    /// The flows' buckets, then the member's own (OWN).
    b: Vec<Bucket>,
    /// Flow buckets with frames, in round order; whether the front one has
    /// had its quantum this turn.
    round: VecDeque<usize>,
    turn: bool,
    queued: usize,
    pub n: Counts,
}

impl Default for Sched {
    fn default() -> Sched {
        Sched::new()
    }
}

impl Sched {
    pub fn new() -> Sched {
        Sched {
            b: (0..=BUCKETS).map(|_| Bucket::default()).collect(),
            round: VecDeque::with_capacity(BUCKETS),
            turn: false,
            queued: 0,
            n: Counts::default(),
        }
    }

    /// Frames waiting.
    #[inline]
    pub fn queued(&self) -> usize {
        self.queued
    }

    /// One frame of at most `n` bytes (at most FRAME) of class c, written by
    /// `put`, which returns its length; put at `now`.
    pub fn put(&mut self, c: Class, n: usize, now: u64, put: impl FnOnce(&mut [u8]) -> usize) {
        let (i, alone) = match c {
            Class::Own => (OWN, false),
            Class::Alone => (OWN, true),
            Class::Flow(s) => (s as usize % BUCKETS, false),
        };
        let b = &mut self.b[i];
        let mut s = if b.q.len() >= DEPTH {
            self.n.stale += 1;
            self.queued -= 1;
            b.pop()
        } else {
            b.spare.pop().unwrap_or_else(|| Box::new(Slot { at: 0, n: 0, alone: false, b: [0; FRAME] }))
        };
        s.at = now;
        s.alone = alone;
        s.n = put(&mut s.b[..n.min(FRAME)]) as u16;
        b.q.push_back(s);
        self.queued += 1;
        if i != OWN && !b.active {
            b.active = true;
            b.deficit = 0;
            self.round.push_back(i);
        }
    }

    /// Drops what waited over STALE_NS at `now`, the oldest first.
    fn age(&mut self, now: u64) {
        let Sched { b, round, queued, n, .. } = self;
        for i in round.iter().copied().chain(std::iter::once(OWN)) {
            let b = &mut b[i];
            while b.q.front().is_some_and(|s| now.saturating_sub(s.at) > STALE_NS) {
                let s = b.pop();
                b.spare.push(s);
                *queued -= 1;
                n.stale += 1;
            }
        }
    }

    /// The bucket whose front frame goes next: the member's own, else the
    /// flows' by deficit round robin. A frame over `room` is dropped (no
    /// datagram holds it).
    fn pick(&mut self, room: usize) -> Option<usize> {
        loop {
            let i = if self.b[OWN].q.is_empty() { *self.round.front()? } else { OWN };
            let b = &mut self.b[i];
            let Some(front) = b.q.front() else {
                b.active = false;
                b.deficit = 0;
                self.round.pop_front();
                self.turn = false;
                continue;
            };
            let n = front.n as i64;
            if n as usize > room {
                let s = b.pop();
                b.spare.push(s);
                self.queued -= 1;
                self.n.stale += 1;
                continue;
            }
            if i == OWN {
                return Some(OWN);
            }
            if !self.turn {
                b.deficit += QUANTUM;
                self.turn = true;
            }
            if n <= b.deficit {
                return Some(i);
            }
            self.round.rotate_left(1);
            self.turn = false;
        }
    }

    /// Takes the front frame of bucket i (from pick) into `out`; its length.
    fn take(&mut self, i: usize, now: u64, out: &mut [u8]) -> usize {
        let b = &mut self.b[i];
        let s = b.pop();
        let n = s.n as usize;
        out[..n].copy_from_slice(&s.b[..n]);
        if i != OWN {
            b.deficit -= n as i64;
        }
        let wait = now.saturating_sub(s.at);
        b.spare.push(s);
        self.queued -= 1;
        self.n.sent += 1;
        self.n.wait_ns += wait;
        self.n.wait_max_ns = self.n.wait_max_ns.max(wait);
        n
    }

    /// Makes datagrams of the waiting frames, each at most `room` bytes of
    /// frames: one is begun only while the connection's guard lets a packet
    /// go, and is written at `buf[at..at + len]` and handed to
    /// `send(buf, at, len)`, which says whether QUIC took it (false: nothing
    /// more goes now); the guard is charged its frames and `over`, what its
    /// packet adds. Frames that waited over STALE_NS are dropped first.
    #[allow(clippy::too_many_arguments)]
    pub fn drain(
        &mut self,
        now: u64,
        room: usize,
        buf: &mut [u8],
        at: usize,
        guard: &mut Guard,
        over: usize,
        mut send: impl FnMut(&mut [u8], usize, usize) -> bool,
    ) {
        self.age(now);
        let room = room.min(buf.len().saturating_sub(at));
        if room == 0 {
            return;
        }
        while self.queued > 0 && guard.may_send(now) {
            let mut len = 0;
            while let Some(i) = self.pick(room) {
                let (n, alone) = {
                    let f = self.b[i].q.front().expect("a picked frame");
                    (f.n as usize, f.alone)
                };
                if len > 0 && (alone || len + n > room) {
                    break;
                }
                len += self.take(i, now, &mut buf[at + len..]);
                if alone {
                    break;
                }
            }
            if len == 0 || !send(buf, at, len) {
                return;
            }
            guard.spent(len + over);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    fn frame(fill: u8, n: usize) -> impl FnOnce(&mut [u8]) -> usize {
        move |b: &mut [u8]| {
            b[..n].fill(fill);
            n
        }
    }

    /// Every datagram drain makes, as its frames' bytes in order, while
    /// QUIC takes `limit` of them; the guard holds nothing back.
    fn drain_all(s: &mut Sched, now: u64, room: usize, limit: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 2000];
        s.drain(now, room, &mut buf, 8, &mut Guard::default(), 0, |b, at, len| {
            if out.len() == limit {
                return false;
            }
            out.push(b[at..at + len].to_vec());
            true
        });
        out
    }

    /// A datagram's frames as (fill, bytes) runs.
    fn runs(d: &[u8]) -> Vec<(u8, usize)> {
        let mut r: Vec<(u8, usize)> = Vec::new();
        for &x in d {
            match r.last_mut() {
                Some((f, n)) if *f == x => *n += 1,
                _ => r.push((x, 1)),
            }
        }
        r
    }

    /// As TestSendQueueBulkDoesNotDelayGame (Go sendqueue_test.go): a bulk
    /// flow's backlog does not hold back a game's frame put after it; the
    /// member's own frames go first, and the hello's answer alone.
    #[test]
    fn a_flood_does_not_hold_back_a_call_and_own_frames_go_first() {
        let mut s = Sched::new();
        for _ in 0..40 {
            s.put(Class::Flow(1), 1000, 0, frame(1, 1000));
        }
        s.put(Class::Flow(2), 160, 0, frame(2, 160));
        s.put(Class::Own, 9, 0, frame(9, 9));
        s.put(Class::Alone, 40, 0, frame(7, 40));
        let d = drain_all(&mut s, MS, 1200, 4);
        assert_eq!(runs(&d[0]), vec![(9, 9)], "the ping, alone because the answer after it goes alone");
        assert_eq!(runs(&d[1]), vec![(7, 40)], "the hello's answer in a datagram of its own");
        assert_eq!(runs(&d[2]), vec![(1, 1000), (2, 160)], "one bulk frame, then the call's in its turn");
        assert_eq!(d.len(), 4, "QUIC took four datagrams");
        assert_eq!(s.queued(), 40 - 3, "the fifth datagram's frames, refused, are gone; the rest wait");
    }

    /// Frames older than 150 ms are dropped before a datagram is made, the
    /// oldest first; a full bucket drops its oldest; what waited is counted.
    #[test]
    fn frames_that_waited_too_long_are_dropped_and_counted() {
        let mut s = Sched::new();
        s.put(Class::Flow(3), 100, 0, frame(1, 100));
        s.put(Class::Flow(3), 100, 100 * MS, frame(2, 100));
        let d = drain_all(&mut s, 160 * MS, 1200, 10);
        assert_eq!(d.iter().map(|d| runs(d)).collect::<Vec<_>>(), vec![vec![(2, 100)]]);
        assert_eq!((s.n.stale, s.n.sent, s.n.wait_max_ns), (1, 1, 60 * MS));

        for k in 0..(DEPTH as u8 + 5) {
            s.put(Class::Flow(35), 10, 200 * MS, frame(k, 10));
        }
        assert_eq!(s.queued(), DEPTH, "flow 35 shares flow 3's bucket, and the bucket holds DEPTH");
        assert_eq!(s.n.stale, 6);
        let d = drain_all(&mut s, 201 * MS, 1200, 10);
        assert_eq!(runs(&d[0])[0], (5, 10), "the five oldest went");
    }

    /// While the guard holds the connection, a datagram goes only on its
    /// budget; the rest wait for the next drain.
    #[test]
    fn a_held_connection_keeps_its_frames_for_later() {
        use crate::guard::Snap;
        let mut g = Guard::default();
        g.judge(MS, Snap::default(), 0);
        g.judge(501 * MS, Snap { sent_bytes: 1_000_000, lost_bytes: 500_000, acked_bytes: 500_000, sent: 1000 }, 0);
        assert!(g.rate() > 0.0, "the guard holds the connection to a rate");
        let mut s = Sched::new();
        for _ in 0..10 {
            s.put(Class::Flow(1), 1000, 501 * MS, frame(1, 1000));
        }
        let mut buf = vec![0u8; 2000];
        let mut sent = 0;
        s.drain(501 * MS, 1200, &mut buf, 8, &mut g, 0, |_, _, _| {
            sent += 1;
            true
        });
        assert_eq!((sent, s.queued()), (0, 10), "the budget starts empty");
        // 700 kB/s: in 5 ms 3500 bytes, three packets' worth.
        s.drain(506 * MS, 1200, &mut buf, 8, &mut g, 0, |_, _, _| {
            sent += 1;
            true
        });
        assert_eq!((sent, s.queued()), (3, 7));
    }
}
