//! The pool's members of copies and their window (spec/trunk.md, "Copies on
//! the pool"; hikkari-client plans/2026-11-15-pool-copy-coalescing.md).
//!
//! A datagram's copy on the pool costs one write into Chromium whatever it
//! holds (its own HTTP/2 frame, TLS record, sendmsg and hand-over to cronet's
//! thread): spread over 32 members, every copy is a write of its own. So K
//! members of the pool carry the copies and nothing of the clients' streams
//! (a copy behind a download on the same TCP connection comes too late to
//! help), and the copies of one window all go on one of them, held for the
//! window (hikkari_trunk::buf::Out::frame_held) and written at once; the
//! next window goes on the next member of copies. One write a window for the
//! whole entry, not one a copy.
//!
//! A member of copies that went down gives its place at the next window to
//! the member up that owes least (ties: the lowest index), so copies never
//! wait for a new connection. K = 0 is the pool as before: copies go round
//! every member, each due at once.

use crate::link::StreamWire;

/// A pool's members of copies and the window they are held for.
#[derive(Default)]
pub struct Copies {
    /// How many members carry copies (0: none, the pool as before).
    pub want: usize,
    pub window_ns: u64,
    /// Which links are members of copies, by the link's index.
    pub of: Vec<bool>,
    /// The window's member and when the window ends.
    pub at: usize,
    pub until: u64,
    /// Writes of copies' windows and copies in them, for the minute's log.
    pub windows: u64,
    pub frames: u64,
}

impl Copies {
    /// Its part of the pipe's minute line: empty with no members of copies.
    pub fn line(&self) -> String {
        if self.want == 0 {
            return String::new();
        }
        format!(" copies={}x{}us windows={} in_windows={}", self.want, self.window_ns / 1000, self.windows, self.frames)
    }
}

impl StreamWire {
    /// Sets the members of copies and their window (the brain's B_COPIES).
    pub fn set_copies(&mut self, want: usize, window_ns: u64) {
        self.copies.want = want.min(self.links.len());
        self.copies.window_ns = window_ns;
        self.copies.of = vec![false; self.links.len()];
        self.copies.until = 0;
        self.keep_copies();
    }

    /// Whether link li carries copies alone.
    #[inline]
    pub fn is_copy(&self, li: usize) -> bool {
        self.copies.of.get(li).copied().unwrap_or(false)
    }

    /// Members of copies that went down leave; members up that owe least
    /// take their places up to `want`.
    fn keep_copies(&mut self) {
        let Copies { want, of, .. } = &mut self.copies;
        let mut n = 0;
        for (li, l) in self.links.iter().enumerate() {
            if of[li] && !l.h.up {
                of[li] = false;
            }
            n += of[li] as usize;
        }
        while n < *want {
            let best = self.links.iter().enumerate().filter(|&(li, l)| l.h.up && !of[li]).min_by_key(|&(li, l)| (l.inflight, li));
            let Some((li, _)) = best else { break };
            of[li] = true;
            n += 1;
        }
    }

    /// The member the window at `now` goes on: the window's while it lasts
    /// and its member is up, else the next member of copies up after it,
    /// whose window starts now. None: the pool has no members of copies, or
    /// none up.
    pub fn window_member(&mut self, now: u64) -> Option<usize> {
        if self.copies.want == 0 {
            return None;
        }
        let c = &self.copies;
        if now < c.until && c.of[c.at] && self.links[c.at].h.up {
            return Some(c.at);
        }
        self.keep_copies();
        let len = self.links.len();
        let start = self.copies.at;
        let next = (1..=len).map(|k| (start + k) % len).find(|&li| self.copies.of[li] && self.links[li].h.up)?;
        self.copies.at = next;
        self.copies.until = now + self.copies.window_ns.max(1);
        self.copies.windows += 1;
        Some(next)
    }

    /// When the window's held copies are due; 0: none held.
    pub fn copies_due(&self) -> u64 {
        if self.copies.want == 0 {
            return 0;
        }
        self.links.get(self.copies.at).map_or(0, |l| l.out.held_until())
    }
}

#[cfg(test)]
mod tests {
    use crate::link::{Reach, StreamWire};

    fn pool(n: usize) -> StreamWire {
        let mut w = StreamWire::new(0, Reach::Plain("127.0.0.1:1".parse().unwrap()), n, 300_000_000);
        for l in &mut w.links {
            l.h.join(1);
        }
        w
    }

    #[test]
    fn a_window_stays_on_one_member_and_the_next_goes_on_the_next() {
        let mut w = pool(8);
        w.set_copies(4, 4_000_000);
        let first = w.window_member(10).unwrap();
        assert!(w.is_copy(first));
        assert_eq!(w.window_member(3_000_000), Some(first), "the same window");
        let second = w.window_member(4_000_010).unwrap();
        assert!(second != first && w.is_copy(second));
        assert_eq!((0..8).filter(|&i| w.is_copy(i)).count(), 4);
    }

    #[test]
    fn a_member_of_copies_that_died_gives_its_place_at_once() {
        let mut w = pool(8);
        w.links[0].inflight = 1;
        w.set_copies(2, 4_000_000);
        assert!(!w.is_copy(0), "the member that owes most is left to streams");
        let m = w.window_member(10).unwrap();
        w.links[m].h.down();
        let n = w.window_member(20).expect("another member up");
        assert!(n != m && w.is_copy(n) && !w.is_copy(m));
        assert_eq!((0..8).filter(|&i| w.is_copy(i)).count(), 2, "its place taken");
    }

    #[test]
    fn no_members_of_copies_is_the_pool_as_before() {
        let mut w = pool(4);
        w.set_copies(0, 4_000_000);
        assert_eq!(w.window_member(10), None);
        assert!((0..4).all(|i| !w.is_copy(i)));
    }
}
