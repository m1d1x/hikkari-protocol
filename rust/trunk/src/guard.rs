//! The guard of a Chromium QUIC member's connection (spec/trunk.md,
//! `h3dgram`, "How each end sends"; spec/v1.md, "The sender: a guard"; Go
//! wire/datagram guard.go guardSender, the reference, with its thresholds),
//! at both ends: the exit's down over quiche, the entry's up over Chromium.
//! While the path loses nothing it holds nothing back; more than a tenth of
//! a half second's bytes lost turns a rate limit on, at 70 % of what the path
//! delivered then, and the member's scheduler keeps to it.
//!
//! Neither QUIC stack gives a callback per packet, so each half second is
//! judged from the connection's counters (Snap: bytes sent, lost and
//! acknowledged, packets sent), read when the half second is over; the round
//! trip is the stack's smoothed one where the Go guard takes the latest (it
//! only tells whether the line's queue has drained, which the smoothed one
//! tells a few round trips later).

/// A half second of sending is judged at a time (guardJudge).
pub const JUDGE_NS: u64 = 500_000_000;
/// The limit goes on: this share of a stretch's bytes lost, out of at least
/// this many packets (guardOnLoss, guardOnPackets).
const ON_LOSS: f64 = 0.10;
const ON_PACKETS: u64 = 100;
/// The limit is this share of the rate the path delivered (guardShare).
const SHARE: f64 = 0.70;
/// A stretch this clean, after HOLD such in a row, grows the limit by GROW;
/// it goes once it is OFF times what is sent (guardClean, guardHold,
/// guardGrow, guardOff).
const CLEAN: f64 = 0.02;
const HOLD: u32 = 3;
const GROW: f64 = 1.03;
const OFF: f64 = 2.0;
/// The limit grows only while the round trip is within this of the least
/// seen since it came on (guardProbeRTT).
const PROBE_RTT_NS: u64 = 50_000_000;
/// The least the limit falls to, bytes a second: 1 Mbit/s (guardFloor).
const FLOOR: f64 = 125_000.0;
/// How much of the limit may go at once (guardBurst), and at least two
/// packets of this size.
const BURST_NS: u64 = 10_000_000;
const PACKET: f64 = 1350.0;

/// A connection's counters since it came (quiche::Stats), read at the end
/// of a stretch.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Snap {
    pub sent_bytes: u64,
    pub lost_bytes: u64,
    pub acked_bytes: u64,
    pub sent: u64,
}

#[derive(Default)]
pub struct Guard {
    /// The stretch being judged: when it began and the counters then.
    start: u64,
    base: Snap,
    limited: bool,
    /// Bytes a second while limited.
    rate: f64,
    clean: u32,
    least_rtt_ns: u64,
    /// The pacing budget while limited, bytes, and when it was last filled.
    budget: f64,
    refill: u64,
    /// The time spent limited before the current limit, and when it came on.
    limited_ns: u64,
    since: u64,
}

impl Guard {
    /// Whether the stretch that began at `start` is over at `now`: then the
    /// caller reads the counters for judge.
    #[inline]
    pub fn due(&self, now: u64) -> bool {
        self.start == 0 || now - self.start >= JUDGE_NS
    }

    /// Closes the stretch: the limit goes on, follows the path, or goes
    /// (guardSender.judge). `rtt_ns` is the connection's round trip now.
    pub fn judge(&mut self, now: u64, s: Snap, rtt_ns: u64) {
        if self.start == 0 {
            self.start = now.max(1);
            self.base = s;
            return;
        }
        let secs = (now - self.start) as f64 / 1e9;
        let sent = s.sent_bytes - self.base.sent_bytes;
        let lost = s.lost_bytes - self.base.lost_bytes;
        let delivered = s.acked_bytes - self.base.acked_bytes;
        let packets = s.sent - self.base.sent;
        let loss = if sent > 0 { lost as f64 / sent as f64 } else { 0.0 };
        let lossy = packets >= ON_PACKETS && loss > ON_LOSS;
        let delivered = FLOOR.max(SHARE * delivered as f64 / secs);
        if !self.limited && lossy {
            self.limited = true;
            self.rate = delivered;
            self.budget = 0.0;
            self.refill = now;
            self.clean = 0;
            self.least_rtt_ns = 0;
            self.since = now;
        } else if self.limited && lossy {
            self.rate = self.rate.min(delivered);
            self.clean = 0;
        } else if self.limited && loss >= CLEAN {
            self.clean = 0;
        } else if self.limited {
            self.clean += 1;
            if self.line_empty(rtt_ns) && self.clean > HOLD {
                self.rate *= GROW;
            }
            if self.rate > OFF * sent as f64 / secs {
                self.limited = false;
                self.limited_ns += now - self.since;
                self.since = 0;
            }
        }
        if self.limited {
            self.line_empty(rtt_ns);
        }
        self.start = now;
        self.base = s;
    }

    /// Whether the round trip is back near the least seen while limited:
    /// the queue the excess left on the line has drained (lineEmpty).
    fn line_empty(&mut self, rtt_ns: u64) -> bool {
        if rtt_ns == 0 {
            return true;
        }
        if self.least_rtt_ns == 0 || rtt_ns < self.least_rtt_ns {
            self.least_rtt_ns = rtt_ns;
        }
        rtt_ns <= self.least_rtt_ns + PROBE_RTT_NS
    }

    fn fill(&mut self, now: u64) {
        if now <= self.refill {
            return;
        }
        let burst = (self.rate * BURST_NS as f64 / 1e9).max(2.0 * PACKET);
        self.budget = burst.min(self.budget + self.rate * (now - self.refill) as f64 / 1e9);
        self.refill = now;
    }

    /// Whether a packet may go now (HasPacingBudget): always while not
    /// limited.
    #[inline]
    pub fn may_send(&mut self, now: u64) -> bool {
        if !self.limited {
            return true;
        }
        self.fill(now);
        self.budget >= PACKET
    }

    /// `bytes` went on the wire.
    #[inline]
    pub fn spent(&mut self, bytes: usize) {
        if self.limited {
            self.budget -= bytes as f64;
        }
    }

    /// When a packet may go next, if the guard holds one back now (0: no
    /// wait).
    pub fn next_at(&self) -> u64 {
        if !self.limited || self.budget >= PACKET {
            return 0;
        }
        self.refill + ((PACKET - self.budget) / self.rate * 1e9) as u64
    }

    /// The limit, bytes a second, 0 while there is none.
    pub fn rate(&self) -> f64 {
        if self.limited {
            self.rate
        } else {
            0.0
        }
    }

    /// The time the guard held the connection to a rate, up to `now`.
    pub fn limited_ns(&self, now: u64) -> u64 {
        self.limited_ns + if self.limited { now - self.since } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    /// A stretch's counters: sent and lost of this many 1000-byte packets,
    /// the rest acknowledged.
    fn after(s: Snap, packets: u64, lost: u64) -> Snap {
        Snap {
            sent_bytes: s.sent_bytes + packets * 1000,
            lost_bytes: s.lost_bytes + lost * 1000,
            acked_bytes: s.acked_bytes + (packets - lost) * 1000,
            sent: s.sent + packets,
        }
    }

    /// As TestGuardHoldsNothingBackWithoutLoss and TestGuardLimitsOnLoss
    /// (Go guard_test.go): no loss, no limit; a fifth of the bytes lost out
    /// of 1000 packets limits the connection to 70 % of what got through,
    /// and the limit paces it.
    #[test]
    fn the_guard_limits_only_on_real_loss() {
        let mut g = Guard::default();
        let mut s = Snap::default();
        g.judge(S, s, 20_000_000);
        s = after(s, 1000, 0);
        g.judge(S + S / 2, s, 20_000_000);
        assert_eq!(g.rate(), 0.0, "nothing lost, no limit");
        assert!(g.may_send(S + S / 2));

        s = after(s, 1000, 200);
        g.judge(2 * S, s, 20_000_000);
        // 800 kB delivered in half a second: 1.6 MB/s, the limit 70 % of it.
        assert!((g.rate() - 1_120_000.0).abs() < 1.0, "limit {}", g.rate());
        assert!(!g.may_send(2 * S), "the budget starts empty");
        assert!(g.next_at() > 2 * S);
        assert!(g.may_send(2 * S + 2 * S / 1000), "2 ms later 2240 bytes have come");
        g.spent(1350);
        g.spent(1350);
        assert!(!g.may_send(2 * S + 2 * S / 1000));

        let few = after(s, 50, 40);
        let mut h = Guard::default();
        h.judge(S, s, 0);
        h.judge(S + S / 2, few, 0);
        assert_eq!(h.rate(), 0.0, "under 100 packets judge nothing");
    }

    /// The limit falls to the floor at most, grows only after three clean
    /// stretches on an emptied line, and goes once it is twice what is sent
    /// (TestGuardGrowsBackAndGoes).
    #[test]
    fn the_limit_grows_back_on_an_empty_line_and_goes() {
        let mut g = Guard::default();
        let mut s = Snap::default();
        let mut now = S;
        g.judge(now, s, 20_000_000);
        // Nearly everything lost: the floor.
        now += S / 2;
        s = after(s, 1000, 990);
        g.judge(now, s, 20_000_000);
        assert_eq!(g.rate(), FLOOR);
        let at = now;

        // Clean stretches with the queue still full (round trip 200 ms over
        // the least): no growth.
        for _ in 0..5 {
            now += S / 2;
            s = after(s, 60, 0);
            g.judge(now, s, if g.least_rtt_ns == 0 { 20_000_000 } else { 220_000_000 });
        }
        assert_eq!(g.rate(), FLOOR, "no growth on a full queue");

        // The queue drained: after the hold each clean stretch grows it 3 %.
        for _ in 0..4 {
            now += S / 2;
            s = after(s, 60, 0);
            g.judge(now, s, 20_000_000);
        }
        assert!(g.rate() > FLOOR * 1.12 && g.rate() < FLOOR * 1.13, "4 growths: {}", g.rate());

        // A sender far under the limit: it goes.
        now += S / 2;
        s = after(s, 10, 0);
        g.judge(now, s, 20_000_000);
        assert_eq!(g.rate(), 0.0, "the limit went");
        assert_eq!(g.limited_ns(now + S), now - at);
    }
}
