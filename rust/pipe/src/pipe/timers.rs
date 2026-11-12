//! What the pipe does on time rather than on packets: members' hellos,
//! pings and deaths on the members' clock, flows unused past idle, the
//! brain's tick, the stats line.

use hikkari_sys as sys;
use hikkari_trunk::frame;
use hikkari_trunk::health::Verdict;

use super::{Event, Pipe};
use crate::ctl;
use crate::member::member_to;

/// A member's hello is said again this often until answered.
const HELLO_EVERY: u64 = 250_000_000;
/// The members' clock (trunk's tick): pings are sent and debts judged on
/// it, not on every turn of the loop. A pause of the exit ends with every
/// member's pongs at once, a few datagrams apart; judged between the first
/// and the last of them, the others would be buried by the first one's
/// proof.
const CLOCK: u64 = 25_000_000;
/// Members that die together come back spread over this (trunk's
/// replaceSpread), not as one burst of new peers from one box.
pub(super) const SPREAD: u64 = 1_000_000_000;
pub(super) const TICK_EVERY: u64 = 1_000_000_000;
const STATS_EVERY: u64 = 10_000_000_000;

impl Pipe {
    /// The members' own talk and health (hello until answered; on the
    /// members' clock a ping every 100 ms and the debts judged,
    /// hikkari_trunk::health), the brain's tick, the stats line; returns when
    /// the next of them is due.
    pub(super) fn timers(&mut self, now: u64) -> u64 {
        let clock = now >= self.clock_at;
        if clock {
            self.clock_at = if self.clock_at + CLOCK > now { self.clock_at + CLOCK } else { now + CLOCK };
        }
        let mut next = self.clock_at;
        let alone = self.ctl.is_none();
        let Pipe { wires, judge, tok, events, session, dirty, .. } = self;
        for w in wires.iter_mut() {
            for (mi, m) in w.members.iter_mut().enumerate() {
                if m.renew_at != 0 {
                    if now >= m.renew_at {
                        // Alone the pipe dials its own: a new socket is a
                        // new peer to the exit, joined by its hello.
                        let sock = w.exit.and_then(|exit| member_to(exit).ok());
                        m.set_sock(sock);
                        *dirty = true;
                    } else {
                        next = next.min(m.renew_at);
                    }
                }
                if m.fd < 0 {
                    continue;
                }
                if !m.h.up {
                    if now >= m.hello_at {
                        let mut h = [0u8; 64];
                        let n = frame::hello_t2(&mut h[12..], session, w.id);
                        let n = m.seal.seal(&mut h, n);
                        if let Some(s) = &m.sock {
                            let _ = s.send(&h[..n]);
                        }
                        m.hello_at = now + HELLO_EVERY;
                    }
                    next = next.min(m.hello_at);
                } else if clock {
                    match m.h.tick(judge, w.stall_ns, now, tok) {
                        Verdict::Fine => {}
                        Verdict::Ping(t) => {
                            m.glue_frame(9, w.glue_max, now, |b| frame::put_ping(b, frame::F_PING, t));
                            m.seal_glue();
                            m.flush_out();
                        }
                        Verdict::Dead { quiet } => {
                            let why = if quiet { ctl::WHY_QUIET } else { ctl::WHY_SILENT };
                            events.push(Event { wire: w.id, index: mi as u8, up: false, why });
                            // Its socket goes now: what comes on it is no
                            // member's. The brain answers the event with a
                            // new one; alone the pipe dials it within SPREAD.
                            m.set_sock(None);
                            *dirty = true;
                            if alone {
                                let mut r = [0u8; 8];
                                sys::urandom(&mut r);
                                m.renew_at = now + 1 + u64::from_le_bytes(r) % SPREAD;
                                next = next.min(m.renew_at);
                            }
                            continue;
                        }
                    }
                }
                if m.glue_since != 0 {
                    next = next.min(m.glue_since + w.glue_ns);
                }
            }
        }
        let next = self.link_timers(now, clock, next);
        self.send_events();
        if now >= self.tick_at {
            // Flows unused past idle end once a second, as trunk's sweep on
            // its tick: an end a second late changes nothing.
            self.flows.sweep(now, self.flow_idle_ns);
            self.send_tick(now);
            self.tick_at = if self.tick_at + TICK_EVERY > now { self.tick_at + TICK_EVERY } else { now + TICK_EVERY };
        }
        if now - self.stats_at >= STATS_EVERY {
            self.stats_at = now;
            self.log_stats();
        }
        next.min(self.tick_at)
    }
}
