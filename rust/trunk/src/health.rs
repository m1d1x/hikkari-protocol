//! Members' health (spec/trunk.md, "Members' health"), as the Go session
//! judges it (trunk/session.go: tick, debtLocked; the pong in handle), for
//! any wire's members: what the pipe does with a member's socket is the
//! wire's, when it owes, proves and dies is here. No clock of its own and
//! no I/O: every call takes `now` (monotonic ns), so the tests run it on a
//! clock of their own, as Go's TestOwnPause runs the session's tick.
//!
//! A member owes progress while it carries unconfirmed chunks (`busy_since`,
//! the stream members of R1.4) or an unanswered ping. It proves progress
//! only by the pong of its own ping or the confirmation of its own chunks:
//! frames that merely arrive on it prove nothing about its way out. It is
//! dead when it owes for longer than its limit (max(Stall, 4 × smoothed
//! RTT), plus the ping interval on a packet member) while another member
//! proved progress after its debt began, or for longer than Quiet whatever
//! the others did: every member silent at once is the other end paused, or
//! the whole path, and only Quiet ends that. A turn of the pipe's loop more
//! than LATE after the one before is the pipe's own pause: every debt counts
//! from the end of it (`Judge::resumed`).

/// The entry's defaults (trunk DefaultStall, DefaultQuiet).
pub const STALL: u64 = 300_000_000;
pub const QUIET: u64 = 1_000_000_000;
/// A packet member pings this often whether or not the last ping came back
/// (trunk packetKeepalive); its limit is the member's limit plus this.
pub const PACKET_PING: u64 = 100_000_000;
/// A stream member pings once it has sent nothing for this long and owes
/// nothing (trunk DefaultKeepalive).
pub const KEEPALIVE: u64 = 1_000_000_000;
/// A turn this long after the one before is the side's own pause (trunk lateTick).
pub const LATE: u64 = 100_000_000;

/// What the pipe knows of the others: one per session, shared by every
/// member of every wire (a wire's members prove the exit alive for the
/// others, as the Go session's proof is the session's). The stall is each
/// wire's own (the brain's dead_ms), Quiet the session's.
#[derive(Clone, Copy)]
pub struct Judge {
    pub quiet: u64,
    /// The latest progress any member proved (0: none yet).
    pub proof: u64,
    /// When the pipe last came back from a pause of its own (0: never).
    pub resumed: u64,
    pub pauses: u32,
    /// The pauses' length in all.
    pub paused: u64,
}

impl Judge {
    pub fn new(quiet: u64) -> Judge {
        Judge { quiet, proof: 0, resumed: 0, pauses: 0, paused: 0 }
    }

    /// A turn of the loop at `now` whose turn before was at `prev`. The
    /// loop turns at least once a CLOCK, so a gap over LATE is the pipe not
    /// run, wherever the pause fell (in its sleep or in its work), as the Go
    /// session counts the gap between its ticks. True for a pause.
    pub fn turn(&mut self, prev: u64, now: u64) -> bool {
        if prev == 0 || now <= prev || now - prev <= LATE {
            return false;
        }
        self.resumed = now;
        self.pauses += 1;
        self.paused += now - prev;
        true
    }
}

/// What a member's turn of the clock says to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing: it owes nothing, or not for long enough.
    Fine,
    /// Send this ping token now.
    Ping(u64),
    /// Dead: by its own stall (another member proved the exit alive after
    /// its debt began), or by Quiet.
    Dead { quiet: bool },
}

#[derive(Clone, Copy, Default)]
pub struct Health {
    pub up: bool,
    /// A packet member (t2, flag packet) pings every PACKET_PING; a stream
    /// member pings only when idle.
    pub packet: bool,
    /// When it last proved its own round trip; the moment it joined until
    /// it does.
    pub progress: u64,
    /// When it last went from owing no chunk to owing one (0: it owes none).
    pub busy_since: u64,
    pub last_send: u64,
    /// The oldest ping it owes (0: none) and the newest one sent.
    ping: u64,
    ping_sent: u64,
    ping_last: u64,
    ping_last_sent: u64,
    pub srtt: u64,
    /// The latest round trip measured.
    pub rtt: u64,
}

impl Health {
    pub fn new(packet: bool) -> Health {
        Health { packet, ..Default::default() }
    }

    /// The exit answered its hello: it is up, owing nothing.
    pub fn join(&mut self, now: u64) {
        let packet = self.packet;
        *self = Health { packet, up: true, progress: now, last_send: now, ..Default::default() };
    }

    pub fn down(&mut self) {
        self.up = false;
    }

    /// Since when it owes progress, as the clock counts it: from the later
    /// of its last proof, the start of its debt and the end of the pipe's
    /// own last pause. None: it owes nothing.
    pub fn debt(&self, j: &Judge) -> Option<u64> {
        let mut since = self.progress;
        if self.busy_since != 0 {
            since = since.max(self.busy_since);
        } else if self.ping != 0 {
            since = since.max(self.ping_sent);
        } else {
            return None;
        }
        Some(since.max(j.resumed))
    }

    /// How long it may owe while another member proves the exit alive.
    pub fn limit(&self, stall: u64) -> u64 {
        let l = stall.max(4 * self.srtt);
        if self.packet {
            l + PACKET_PING
        } else {
            l
        }
    }

    /// One turn of the clock at `now` on a wire whose members stall after
    /// `stall`; `tok` is the last ping token, taken only for a Ping.
    pub fn tick(&mut self, j: &Judge, stall: u64, now: u64, tok: &mut u64) -> Verdict {
        if !self.up {
            return Verdict::Fine;
        }
        if let Some(since) = self.debt(j) {
            let owed = now.saturating_sub(since);
            let alone = owed > self.limit(stall) && j.proof > since;
            if alone || owed > j.quiet {
                self.up = false;
                return Verdict::Dead { quiet: !alone };
            }
        }
        let due = if self.packet {
            now.saturating_sub(self.ping_last_sent) >= PACKET_PING
        } else {
            self.ping == 0 && self.busy_since == 0 && now.saturating_sub(self.last_send) > KEEPALIVE
        };
        if !due {
            return Verdict::Fine;
        }
        *tok += 1;
        if self.ping == 0 {
            self.ping = *tok;
            self.ping_sent = now;
        }
        self.ping_last = *tok;
        self.ping_last_sent = now;
        self.last_send = now;
        Verdict::Ping(*tok)
    }

    /// A pong of `tok` came on it: a pong of any ping it owes is its proof
    /// (and the session's); only the newest one's is timed, the others may
    /// have waited behind it. A pong of no ping it owes is nothing.
    pub fn pong(&mut self, j: &mut Judge, tok: u64, now: u64) -> bool {
        if self.ping == 0 || tok < self.ping || tok > self.ping_last {
            return false;
        }
        if tok == self.ping_last {
            let rtt = now.saturating_sub(self.ping_last_sent);
            self.rtt = rtt;
            self.srtt = if self.srtt == 0 { rtt } else { (7 * self.srtt + rtt) / 8 };
        }
        self.ping = 0;
        self.ping_last = 0;
        self.progress = now;
        j.proof = now;
        true
    }

    /// One of its chunks confirmed (R1.4): its proof, and the session's.
    pub fn confirmed(&mut self, j: &mut Judge, now: u64, still_busy: bool) {
        self.progress = now;
        j.proof = now;
        self.busy_since = if still_busy { now } else { 0 };
    }

    pub fn sent(&mut self, now: u64) {
        self.last_send = now;
    }

    /// How long it has owed at `now` (0: nothing), for the brain's tick.
    pub fn owed(&self, j: &Judge, now: u64) -> u64 {
        self.debt(j).map_or(0, |s| now.saturating_sub(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;
    /// Go's session clock: a turn every 25 ms.
    const TURN: u64 = 25 * MS;

    fn ping_of(v: Verdict) -> u64 {
        match v {
            Verdict::Ping(t) => t,
            v => panic!("want a ping, got {v:?}"),
        }
    }

    /// Runs members on the clock from `from` to `to` (inclusive). `answer`
    /// says when the pong of a ping member i sent at t comes back (None:
    /// never); pongs are read before each turn, as the pipe reads its
    /// sockets before its clock. Returns when each died and how (None:
    /// alive at `to`).
    fn run(j: &mut Judge, stall: u64, ms: &mut [Health], tok: &mut u64, from: u64, to: u64, answer: impl Fn(usize, u64) -> Option<u64>) -> Vec<Option<(u64, bool)>> {
        let mut died = vec![None; ms.len()];
        let mut pending: Vec<(u64, usize, u64)> = Vec::new();
        let mut t = from;
        while t <= to {
            pending.sort();
            while let Some(&(at, i, k)) = pending.first() {
                if at > t {
                    break;
                }
                pending.remove(0);
                ms[i].pong(j, k, at);
            }
            for (i, m) in ms.iter_mut().enumerate() {
                if !m.up {
                    continue;
                }
                match m.tick(j, stall, t, tok) {
                    Verdict::Ping(k) => {
                        if let Some(at) = answer(i, t) {
                            pending.push((at, i, k));
                        }
                    }
                    Verdict::Dead { quiet } => died[i] = Some((t, quiet)),
                    Verdict::Fine => {}
                }
            }
            t += TURN;
        }
        died
    }

    fn pool(n: usize, packet: bool, at: u64) -> Vec<Health> {
        (0..n)
            .map(|_| {
                let mut h = Health::new(packet);
                h.join(at);
                h
            })
            .collect()
    }

    /// TestOwnPause on the pipe: a ping owed since t0, the other end reads
    /// and never answers, the pipe not run for 2 s. The member gets a fresh
    /// start from the pause instead of being buried for the time the box
    /// did not run; silent after it, it ends by Quiet as usual.
    #[test]
    fn own_pause() {
        let mut j = Judge::new(1000 * MS);
        let t0 = 10_000 * MS;
        let mut m = Health::new(false);
        m.join(t0);
        m.ping = 1;
        m.ping_sent = t0;
        m.ping_last = 1;
        m.ping_last_sent = t0;
        let mut tok = 1;
        let mut t = t0;
        while t <= t0 + 50 * MS {
            assert_eq!(m.tick(&j, 100 * MS, t, &mut tok), Verdict::Fine);
            j.turn(t.saturating_sub(TURN), t);
            t += TURN;
        }
        // The box was not run for 2 s: the turn after 50 ms comes at 2 s.
        assert!(j.turn(t0 + 50 * MS, t0 + 2000 * MS));
        assert_eq!((j.pauses, j.paused), (1, 1950 * MS));
        let mut t = t0 + 2000 * MS;
        while t <= t0 + 2900 * MS {
            assert_eq!(m.tick(&j, 100 * MS, t, &mut tok), Verdict::Fine, "buried within Quiet of the pause at +{} ms", (t - t0) / MS);
            t += TURN;
        }
        let mut t = t0 + 2925 * MS;
        let mut dead = None;
        while t <= t0 + 3100 * MS && dead.is_none() {
            if let Verdict::Dead { quiet } = m.tick(&j, 100 * MS, t, &mut tok) {
                dead = Some((t - t0) / MS);
                assert!(quiet, "dead by its stall with nobody proving the exit alive");
            }
            t += TURN;
        }
        assert_eq!(dead, Some(3025), "silent past Quiet of the pause and still up");
    }

    /// TestOtherEndPaused on the pipe: the exit is not run for 1.5 s, under
    /// Quiet; what the members sent meanwhile it answers when it runs again.
    /// Every member is silent at once: that is the other end, not the
    /// members, and none is buried, by its stall or otherwise.
    #[test]
    fn other_end_paused() {
        let mut j = Judge::new(10_000 * MS);
        let t0 = 10_000 * MS;
        let mut ms = pool(6, true, t0);
        let mut tok = 0;
        let (p0, p1) = (t0 + 500 * MS, t0 + 2000 * MS);
        let died = run(&mut j, 100 * MS, &mut ms, &mut tok, t0, t0 + 4000 * MS, |_, t| Some(if t < p0 { t + MS } else { (t + MS).max(p1) }));
        assert!(died.iter().all(|d| d.is_none()), "members buried for the exit's pause: {died:?}");
        assert!(j.proof >= t0 + 3900 * MS, "the members did not come back after the pause");
    }

    /// TestPathCut on the pipe: the path drops every member at once.
    /// Nobody shows progress, so it is Quiet, not the stall, that ends them,
    /// a Quiet after their debts began.
    #[test]
    fn path_cut() {
        for packet in [true, false] {
            let mut j = Judge::new(300 * MS);
            let t0 = 10_000 * MS;
            let mut ms = pool(4, packet, t0);
            let mut tok = 0;
            let cut = t0 + 2000 * MS;
            let died = run(&mut j, 100 * MS, &mut ms, &mut tok, t0, t0 + 5000 * MS, |_, t| if t < cut { Some(t + MS) } else { None });
            for (i, d) in died.iter().enumerate() {
                let (at, quiet) = d.unwrap_or_else(|| panic!("member {i} (packet {packet}) alive after the cut"));
                assert!(quiet, "member {i} (packet {packet}) buried by its stall in a cut of the whole path");
                assert!(at > cut + 300 * MS, "member {i} (packet {packet}) dead {} ms after the cut, before Quiet", (at - cut) / MS);
                // Idle stream members owe nothing until their keepalive.
                let latest = if packet { 300 + 2 * 25 } else { 1000 + 300 + 2 * 25 };
                assert!(at <= cut + latest * MS, "member {i} (packet {packet}) dead {} ms after the cut", (at - cut) / MS);
            }
        }
    }

    /// One member's own path dies while the others answer: it is dead by
    /// its stall (limit plus the ping interval on a packet member), long
    /// before Quiet, and the others are untouched.
    #[test]
    fn one_member_dies() {
        let mut j = Judge::new(1000 * MS);
        let t0 = 10_000 * MS;
        let mut ms = pool(4, true, t0);
        let mut tok = 0;
        let cut = t0 + 1000 * MS;
        let died = run(&mut j, 300 * MS, &mut ms, &mut tok, t0, t0 + 3000 * MS, |i, t| if i != 2 || t < cut { Some(t + MS) } else { None });
        assert_eq!(died.iter().filter(|d| d.is_some()).count(), 1, "{died:?}");
        let (at, quiet) = died[2].unwrap();
        assert!(!quiet, "a member alone silent should die by its stall");
        // Its debt starts at its first ping after the cut (≤ 100 ms), the
        // limit is 300 + 100 ms, the clock turns every 25 ms.
        let after = (at - cut) / MS;
        assert!((400..=525).contains(&after), "dead {after} ms after its cut");
    }

    /// A member's round trip raises its stall: 4 × smoothed RTT over Stall.
    #[test]
    fn slow_member_limit() {
        let mut j = Judge::new(1000 * MS);
        let mut m = Health::new(true);
        m.join(0);
        let mut tok = 0;
        let k = ping_of(m.tick(&j, 300 * MS, 1000 * MS, &mut tok));
        assert!(m.pong(&mut j, k, 1150 * MS));
        assert_eq!(m.srtt, 150 * MS);
        assert_eq!(m.limit(300 * MS), 600 * MS + PACKET_PING);
    }

    /// Pongs: any owed ping's pong proves; one of no owed ping proves
    /// nothing; only the newest is timed.
    #[test]
    fn pongs() {
        let mut j = Judge::new(1000 * MS);
        let mut m = Health::new(true);
        m.join(0);
        let mut tok = 0;
        let a = ping_of(m.tick(&j, 300 * MS, 100 * MS, &mut tok));
        let b = ping_of(m.tick(&j, 300 * MS, 200 * MS, &mut tok));
        assert_eq!(m.debt(&j), Some(100 * MS));
        assert!(!m.pong(&mut j, b + 1, 210 * MS));
        assert!(m.pong(&mut j, a, 230 * MS));
        assert_eq!((m.debt(&j), m.srtt, j.proof), (None, 0, 230 * MS));
        assert!(!m.pong(&mut j, b, 240 * MS), "a pong of a ping already proved");
        let c = ping_of(m.tick(&j, 300 * MS, 300 * MS, &mut tok));
        assert!(m.pong(&mut j, c, 320 * MS));
        assert_eq!(m.srtt, 20 * MS);
    }

    /// A stream member pings only when idle past Keepalive, and owes from
    /// its chunks while it carries them.
    #[test]
    fn stream_member_keepalive() {
        let mut j = Judge::new(1000 * MS);
        let mut m = Health::new(false);
        m.join(0);
        let mut tok = 0;
        assert_eq!(m.tick(&j, 300 * MS, 900 * MS, &mut tok), Verdict::Fine);
        let k = ping_of(m.tick(&j, 300 * MS, 1001 * MS, &mut tok));
        assert_eq!(m.tick(&j, 300 * MS, 1100 * MS, &mut tok), Verdict::Fine, "a second ping while one is owed");
        assert!(m.pong(&mut j, k, 1110 * MS));
        m.busy_since = 1200 * MS;
        m.sent(1200 * MS);
        assert_eq!(m.debt(&j), Some(1200 * MS));
        m.confirmed(&mut j, 1250 * MS, false);
        assert_eq!(m.debt(&j), None);
    }
}
