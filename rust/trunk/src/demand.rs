//! Copies on the pool on demand (spec/trunk.md, "Copies on demand";
//! hikkari-client plans/2026-11-18-copies-on-demand.md): the voice class's
//! copy of the other fate goes only while an end lost datagrams of a packet
//! wire lately, not on every datagram. Both ends count the holes in a flow's
//! seq among the datagrams that came on packet wires; the entry turns the
//! copies on for itself, the exit asks the entry with a copies frame.

use crate::flow::Replay;

/// What starts the copies and holds them: over the last one to two spans of
/// SPAN_NS, at least RUN datagrams lost on packet wires and at least
/// RATE_PER_MILLE of those that were due there. The span is short so that
/// the clean span before a cut weighs little against its first losses: at
/// a cut of 14% the share is there some 15 ms into the cut. A share, not a count: the
/// wire's own trickle is 0.08–0.1% of datagrams in a third of the minutes of
/// a day (hikkari-client plans/research/2026-11-18-pipe-chromium-perf.md),
/// which over the 25 000 datagrams a second of 100 people is 25 lost a
/// second, and a count would keep the copies on for good. The stand's cut of
/// 15.11 loses 14–20%.
pub const RUN: u64 = 2;
pub const RATE_PER_MILLE: u64 = 10;
pub const SPAN_NS: u64 = 200_000_000;
/// How long the copies go after the last loss that held them (owner
/// 18.11: «давай 5 минут»): a cut comes in waves, and a pause in a wave
/// shorter than this costs no new start (2–4 voice datagrams of 8 people a
/// start in the bench, hikkari-client plans/research/2026-11-18-copies-on-demand.md).
pub const HOLD_NS: u64 = 300_000_000_000;
/// How often at most the exit asks for the copies while it loses.
pub const ASK_EVERY_NS: u64 = 100_000_000;

/// One end's demand for copies: off while hold_ns is 0 (copies always, as
/// before), else copies until `until`, held for hold_ns from each loss
/// that finds the wire losing (RUN and RATE_PER_MILLE).
#[derive(Default, Clone, Copy, Debug)]
pub struct Demand {
    pub hold_ns: u64,
    pub until: u64,
    /// The current span (from span_at) and the one before it: datagrams due
    /// on packet wires (came or lost) and lost.
    span_at: u64,
    due: u64,
    gone: u64,
    prev_due: u64,
    prev_gone: u64,
    since: u64,
    /// Datagrams lost on packet wires, runs of copies started, and the time
    /// copies were on before the current run.
    pub lost: u64,
    pub runs: u64,
    on_ns: u64,
}

impl Demand {
    pub fn new(hold_ns: u64) -> Demand {
        Demand { hold_ns, ..Demand::default() }
    }

    /// The brain's hold (B_DEMAND), on the go: 0 is copies always; a hold
    /// set from 0 starts with none until a loss.
    pub fn set_hold(&mut self, hold_ns: u64) {
        if hold_ns == 0 {
            self.until = 0;
        } else if self.hold_ns > 0 && self.until > 0 {
            self.until = self.until - self.hold_ns + hold_ns;
        }
        self.hold_ns = hold_ns;
    }

    /// Whether the voice class's copies of the other fate go now.
    #[inline]
    pub fn copies(&self, now: u64) -> bool {
        self.hold_ns == 0 || now < self.until
    }

    /// A datagram came on a packet wire, and judged k others lost there
    /// (Holes): says whether this finds the wire losing, which holds the
    /// copies from now (the exit then asks the entry for them).
    #[inline]
    pub fn arrived(&mut self, k: u32, now: u64) -> bool {
        if self.hold_ns == 0 {
            return false;
        }
        if now.saturating_sub(self.span_at) >= SPAN_NS {
            let fresh = now.saturating_sub(self.span_at) < 2 * SPAN_NS;
            (self.prev_due, self.prev_gone) = if fresh { (self.due, self.gone) } else { (0, 0) };
            (self.span_at, self.due, self.gone) = (now, 0, 0);
        }
        self.due += 1 + k as u64;
        self.gone += k as u64;
        if k == 0 {
            return false;
        }
        self.lost += k as u64;
        let (due, gone) = (self.due + self.prev_due, self.gone + self.prev_gone);
        if gone >= RUN && gone * 1000 >= due * RATE_PER_MILLE {
            self.hold(now);
            return true;
        }
        false
    }

    /// The copies go from now for hold_ns (the exit asked, or the wire here
    /// is losing).
    pub fn hold(&mut self, now: u64) {
        if self.hold_ns == 0 {
            return;
        }
        if now >= self.until {
            self.on_ns += self.until.saturating_sub(self.since);
            self.since = now;
            self.runs += 1;
        }
        self.until = now + self.hold_ns;
    }

    /// How long the copies were on in all, up to now.
    pub fn on_ns(&self, now: u64) -> u64 {
        self.on_ns + now.min(self.until).saturating_sub(self.since)
    }
}

/// How long a hole waits to be filled before it counts as lost: the members
/// of one wire go round (spec/trunk.md, "Datagrams"), and an end reads its
/// members' sockets a batch at a time, so a datagram may come a few after
/// the next ones on another member's socket, but within a turn of the loop.
pub const GRACE_NS: u64 = 20_000_000;
/// The newest seqs a flow's holes are judged by (see Holes).
const MARKS: usize = 16;

/// A flow's seqs that came on packet wires, to tell their holes there: a
/// seq under one that came GRACE_NS ago that still has not come on a packet
/// wire is lost, whatever the pool brought, so the copies hold while the
/// packet wire still loses. The marks are when the newest seq moved: a seq
/// under a mark GRACE_NS old is judged once.
#[derive(Default, Clone)]
pub struct Holes {
    seen: Replay,
    /// Every seq up to judged is judged; marks[i] is (seq, when it came).
    judged: u32,
    marks: [(u32, u64); MARKS],
    at: usize,
}

impl Holes {
    /// seq came on a packet wire at now: says how many seqs this judged lost.
    #[inline]
    pub fn arrived(&mut self, seq: u32, now: u64) -> u32 {
        let top = self.seen.top();
        if self.seen.seen(seq) {
            return 0;
        }
        if top == 0 {
            self.judged = seq;
            return 0;
        }
        if seq > top {
            self.marks[self.at] = (seq, now);
            self.at = (self.at + 1) % MARKS;
        }
        // The newest mark GRACE_NS old: every seq under it had its time.
        let to = self.marks.iter().filter(|&&(s, t)| s > 0 && t + GRACE_NS <= now).map(|&(s, _)| s - 1).max();
        let Some(to) = to.filter(|&to| to > self.judged) else { return 0 };
        let from = self.judged + 1;
        self.judged = to;
        if to - from >= 1024 {
            return 1024;
        }
        (from..=to).filter(|&p| !self.seen.has(p)).count() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    /// n datagrams due from `at` spread over one span, every `every`-th lost.
    fn feed(d: &mut Demand, at: u64, n: u64, every: u64) -> bool {
        let mut wanted = false;
        for i in 1..=n {
            let k = u32::from(every > 0 && i % every == 0);
            wanted |= d.arrived(k, at + i * (SPAN_NS / n) - 1);
        }
        wanted
    }

    #[test]
    fn a_trickle_starts_no_copies_and_a_cut_does() {
        let mut d = Demand::new(HOLD_NS);
        assert!(Demand::new(0).copies(5) && !d.copies(1), "off: always; on: none before a loss");
        assert!(!d.arrived(1, S), "one lost alone is no run");
        assert!(!feed(&mut d, 2 * S, 5000, 1000), "0.1% of 25 000 a second is the trickle");
        assert!(!d.copies(3 * S));
        assert!(feed(&mut d, 3 * S, 5000, 7), "a cut of 14% of the same");
        assert!(d.copies(3 * S + SPAN_NS) && d.copies(3 * S + HOLD_NS) && !d.copies(4 * S + HOLD_NS));
        assert!(!feed(&mut d, 4 * S, 5000, 1000), "a trickle while they go does not hold them");
        assert!(!d.copies(4 * S + HOLD_NS));
        assert_eq!(d.runs, 1);
    }

    #[test]
    fn a_cut_holds_the_copies_five_minutes_past_its_last_loss() {
        let mut d = Demand::new(HOLD_NS);
        assert!(feed(&mut d, 0, 150, 5));
        assert!(feed(&mut d, 100 * S, 150, 5), "a wave a hundred seconds on holds them");
        assert!(d.copies(399 * S) && !d.copies(401 * S));
        assert_eq!(d.runs, 1, "a pause in the wave shorter than the hold starts nothing anew");
        assert!(d.on_ns(1000 * S) > 399 * S && d.on_ns(1000 * S) < 401 * S);
    }

    #[test]
    fn a_hold_off_asks_nothing() {
        let mut d = Demand::new(0);
        assert!(!d.arrived(5, S));
        d.hold(S);
        assert!(d.copies(S) && d.runs == 0);
    }

    #[test]
    fn a_hole_counts_once_it_had_its_time_and_never_came() {
        const MS: u64 = 1_000_000;
        let mut h = Holes::default();
        assert_eq!(h.arrived(7, 0), 0, "the first seen starts the count");
        assert_eq!(h.arrived(8, MS), 0);
        assert_eq!(h.arrived(10, 2 * MS), 0, "9 is not late yet");
        assert_eq!(h.arrived(9, 5 * MS), 0, "9 came on another member, late");
        assert_eq!(h.arrived(13, 6 * MS), 0, "11 and 12 not late yet");
        assert_eq!(h.arrived(14, 30 * MS), 2, "11 and 12 had their 20 ms after 13 came");
        assert_eq!(h.arrived(15, 31 * MS), 0, "each judged once");
        assert_eq!(h.arrived(12, 32 * MS), 0, "one past its time is counted lost already");
    }
}
