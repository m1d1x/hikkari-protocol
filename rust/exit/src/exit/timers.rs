//! What the exit does on time rather than on packets (trunk session.go tick
//! and Exit.Run, udpwire's reap): members' pings and deaths on the members'
//! clock (stream members' in tcp.rs), flows unused past idle, entry
//! addresses silent past PeerIdle, ended streams' ids and held early frames
//! past their memory, sessions left without members past SessionIdle, the
//! brain's tick, the stats line.

use hikkari_trunk::frame::{self, F_PING};
use hikkari_trunk::health::Verdict;

use super::Exit;
use crate::session::SESSION_IDLE;
use crate::streams::{CLOSED_MEMORY, EARLY_FOR};

/// The members' clock (trunk's tick): pings are sent and debts judged on it,
/// not on every turn of the loop (hk-pipe timers.rs says why).
const CLOCK: u64 = 25_000_000;
pub(super) const TICK_EVERY: u64 = 1_000_000_000;
const STATS_EVERY: u64 = 10_000_000_000;
/// An entry address that sent nothing that opened for this long is
/// forgotten (udpwire PeerIdle).
pub const PEER_IDLE: u64 = 120_000_000_000;

impl Exit {
    /// The members' health on their clock (a ping every 100 ms, the debts
    /// judged: hikkari_trunk::health), the second's sweeps and tick, the
    /// stats line; returns when the next of them is due.
    pub(super) fn timers(&mut self, now: u64) -> u64 {
        if now >= self.clock_at {
            self.clock_at = if self.clock_at + CLOCK > now { self.clock_at + CLOCK } else { now + CLOCK };
            self.members_clock(now);
            self.link_clock(now);
            self.end_doomed(now);
        }
        let mut next = self.clock_at;
        for w in self.wires.iter_mut() {
            if let Some(h) = w.h3() {
                next = next.min(h.timers(now));
            }
        }
        if self.tick_ns == 0 {
            for p in self.peers.iter().filter(|p| p.live && p.glue_since != 0) {
                next = next.min(p.glue_since + self.wires[p.wire].glue_ns);
            }
        }
        if now >= self.tick_at {
            self.sweep(now);
            self.send_tick(now);
            self.tick_at = if self.tick_at + TICK_EVERY > now { self.tick_at + TICK_EVERY } else { now + TICK_EVERY };
        }
        if now - self.stats_at >= STATS_EVERY {
            self.stats_at = now;
            self.log_stats();
        }
        next.min(self.tick_at)
    }

    /// One turn of the members' clock: each member pings or is judged dead,
    /// by its stall (another member of its session proved the entry alive
    /// after its debt began) or by Quiet (every member silent).
    fn members_clock(&mut self, now: u64) {
        for pi in 0..self.peers.len() {
            let Exit { peers, sessions, wires, tok, t, .. } = self;
            let p = &mut peers[pi];
            if !p.joined() {
                continue;
            }
            let w = &mut wires[p.wire];
            match p.h.tick(&sessions.all[p.session].judge, w.stall_ns, now, tok) {
                Verdict::Fine => {}
                Verdict::Ping(k) => {
                    w.glue(p, 9, now, |b| frame::put_ping(b, F_PING, k));
                }
                Verdict::Dead { quiet } => {
                    if quiet {
                        t.quiet += 1;
                    } else {
                        t.silent += 1;
                    }
                    self.drop_peer(pi, now);
                }
            }
        }
    }

    /// Once a second: flows unused past idle end, addresses silent past
    /// PeerIdle are forgotten, ended streams' ids and early frames are
    /// forgotten past their memory, sessions without members past
    /// SessionIdle end with their flows and streams. A second late changes
    /// nothing.
    fn sweep(&mut self, now: u64) {
        for pi in 0..self.peers.len() {
            let p = &self.peers[pi];
            if p.live && now.saturating_sub(p.heard) > PEER_IDLE {
                if p.joined() {
                    self.t.gone += 1;
                }
                self.drop_peer(pi, now);
            }
        }
        for fi in 0..self.flows.all.len() {
            let f = &self.flows.all[fi];
            if f.live && now.saturating_sub(f.used) > self.flow_idle_ns && self.end_flow(fi) {
                self.t.flows_idle += 1;
            }
        }
        for x in self.sessions.all.iter_mut().filter(|x| x.live) {
            x.closed.retain(|_, at| now.saturating_sub(*at) <= CLOSED_MEMORY);
            x.early.retain(|_, e| now.saturating_sub(e.since) <= EARLY_FOR);
            x.early_bytes = x.early.values().map(|e| e.bytes).sum();
        }
        for s in 0..self.sessions.all.len() {
            let x = &self.sessions.all[s];
            if !x.live || !x.no_members() || now.saturating_sub(x.empty_since) <= SESSION_IDLE {
                continue;
            }
            let flows: Vec<usize> = x.flows.values().copied().collect();
            let streams: Vec<usize> = x.streams.values().copied().collect();
            for fi in flows {
                self.end_flow(fi);
            }
            // No member is left to tell: the streams end without a reset
            // (trunk Session.Close).
            for slot in streams {
                if let Some(fd) = self.streams.all[slot].local.as_ref().and_then(|l| l.fd()) {
                    self.tcp.del(std::os::fd::AsRawFd::as_raw_fd(fd));
                }
                self.streams.n.reset_local += 1;
                self.streams.end(slot);
            }
            self.sessions.end(s);
        }
    }
}
