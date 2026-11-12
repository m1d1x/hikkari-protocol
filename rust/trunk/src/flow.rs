//! A datagram flow's rules (spec/trunk.md, "Datagrams"), the same at both
//! ends: copies dropped by seq in a window of 1024, a flow ended after 2
//! minutes unused. The reference is trunk flows.go (replay, FlowIdle).

/// A flow nobody used for this long ends (trunk DefaultFlowIdle): neither
/// a datagram sent nor one received that was not a copy.
pub const FLOW_IDLE_NS: u64 = 120_000_000_000;

/// How many members carry each datagram of a flow whose sender does not
/// copy its datagrams itself (trunk DefaultCopies).
pub const COPIES: u8 = 2;

/// The port of the exit's echo (trunk EchoPort): no loopback service has
/// port 0, so a flow to it is the trunk's own call. Neither end counts it
/// among its clients' flows and datagrams.
pub const ECHO_PORT: u16 = 0;

/// The replay window's size in sequence numbers.
const WINDOW: u32 = 1024;

/// Drops copies: a sliding window of the last 1024 sequence numbers, as
/// trunk replay. A member sends each datagram once, so a seq seen again is
/// a copy from another member; seq 0 is never sent (a flow's first is 1)
/// and counts as a copy, as does one too old for the window to tell.
#[derive(Default, Clone)]
pub struct Replay {
    top: u32,
    bits: [u64; (WINDOW / 64) as usize],
}

impl Replay {
    /// Whether seq was seen before, so the datagram is a copy and must be
    /// dropped; a new seq is marked seen.
    #[inline]
    pub fn seen(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return true;
        }
        if seq > self.top {
            let shift = seq - self.top;
            if shift >= WINDOW {
                self.bits = Default::default();
            } else {
                // The seqs the window moves over are new: clear their bits
                // (one or two per datagram in order).
                for i in self.top + 1..=seq {
                    self.bits[((i % WINDOW) / 64) as usize] &= !(1u64 << (i % 64));
                }
            }
            self.top = seq;
        } else if self.top - seq >= WINDOW {
            return true;
        }
        let (word, bit) = (((seq % WINDOW) / 64) as usize, 1u64 << (seq % 64));
        if self.bits[word] & bit != 0 {
            return true;
        }
        self.bits[word] |= bit;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // trunk's replay has no test of its own; these are its rules as
    // flows.go writes them.
    #[test]
    fn replay_drops_copies_and_lets_late_ones_by_once() {
        let mut r = Replay::default();
        assert!(r.seen(0), "seq 0 is always a copy");
        assert!(!r.seen(1), "the first of a seq is new");
        assert!(r.seen(1), "the same seq again is a copy");
        for s in 2..=100 {
            assert!(!r.seen(s), "{s} is new");
        }
        assert!(r.seen(50), "a seq within the window is a copy");
        assert!(!r.seen(200), "a jump forward is new");
        assert!(!r.seen(150), "a late one still in the window is new");
        assert!(r.seen(150), "but only once");
        assert!(!r.seen(200 + WINDOW - 1), "the window moves to the newest");
        assert!(r.seen(200), "the window's oldest seq, seen, is a copy");
        assert!(r.seen(199), "one past the window is too old to tell: dropped as a copy");
        assert!(!r.seen(201), "the oldest the window still holds is new");
        assert!(!r.seen(9000), "far ahead, past the whole window, is new");
        assert!(r.seen(9000));
        assert!(!r.seen(8999), "a window cleared at a jump holds nothing old");
    }

    #[test]
    fn replay_wraps_with_the_window_not_the_seq() {
        // Bits are reused modulo the window: seq s and s + 1024 share one.
        let mut r = Replay::default();
        assert!(!r.seen(5));
        assert!(!r.seen(5 + WINDOW), "the same bit a window later is a new seq");
        assert!(r.seen(5 + WINDOW));
        assert!(r.seen(5), "and the old one is too old to tell");
    }
}
