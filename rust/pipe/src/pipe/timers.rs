//! What the pipe does on time rather than on packets: members' hellos,
//! pings and deaths on the members' clock, flows unused past idle, the
//! brain's tick, the stats line.

use hikkari_sys as sys;
use hikkari_trunk::frame;
use hikkari_trunk::sched::Class;
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
pub(super) const CLOCK: u64 = 25_000_000;
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
        let mut next = self.step_sessions(now).min(self.clock_at).min(self.h3_members(now));
        let alone = self.ctl.is_none();
        let (cur, taker) = (self.cur, self.taker());
        let Pipe { wires, judge, tok, events, sessions, dirty, h3s, .. } = self;
        for w in wires.iter_mut() {
            // The brain hears and renews the current session's members; the
            // members of one coming up are the pipe's own (session.rs), and
            // only the session that takes everything new replaces any.
            let (brains, replaces) = (!alone && w.sess == cur, taker == Some(w.sess));
            for (mi, m) in w.members.iter_mut().enumerate() {
                if m.renew_at != 0 {
                    if now >= m.renew_at && w.h3 {
                        // The QUIC wire's member opens its tunnel (h3.rs).
                        m.renew_at = 0;
                    } else if now >= m.renew_at {
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
                    if !m.can_send() {
                        // A tunnel opening: its hello waits for it (h3.rs).
                        continue;
                    }
                    if now >= m.hello_at {
                        let mut h = [0u8; 64];
                        let n = frame::hello_t2(&mut h[12..], &sessions[w.sess as usize].id, w.id);
                        let (at, n) = m.seal_in(&mut h, n);
                        sys::send_nowait(m.fd, &h[at..at + n]);
                        m.hello_at = now + HELLO_EVERY;
                    }
                    next = next.min(m.hello_at);
                } else if clock {
                    match m.h.tick(judge, w.stall_ns, now, tok) {
                        Verdict::Fine => {}
                        Verdict::Ping(t) => {
                            m.frame(Class::Own, 9, w.glue_max, now, |b| frame::put_ping(b, frame::F_PING, t));
                            m.send_now(now);
                        }
                        Verdict::Dead { quiet } => {
                            let why = if quiet { ctl::WHY_QUIET } else { ctl::WHY_SILENT };
                            if brains {
                                events.push(Event { wire: w.id, index: mi as u8, up: false, why });
                            }
                            // Its socket goes now: what comes on it is no
                            // member's. The brain answers the event with a
                            // new one; alone the pipe dials it within SPREAD.
                            // The QUIC wire's member closes its tunnel, its
                            // port rests, and the pipe opens a new one
                            // whatever the brain (h3.rs).
                            if w.h3 {
                                if let Some(h) = h3s.iter_mut().find(|h| h.id == w.id) {
                                    h.give_back(m.port, true, now);
                                }
                                m.set_tunnel(None, 0);
                            } else {
                                m.set_sock(None);
                            }
                            *dirty = true;
                            if replaces && (w.h3 || !brains) {
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
                // What the QUIC wire's guard holds back goes when its budget
                // lets it, or ages out (seal_due drains it each turn).
                if m.queued() > 0 {
                    next = next.min(m.guard.next_at().max(now + 1_000_000));
                }
            }
        }
        let next = self.link_timers(now, clock, next);
        self.send_events();
        if now >= self.tick_at {
            // Flows unused past idle end once a second, as trunk's sweep on
            // its tick: an end a second late changes nothing.
            self.sweep_flows(now);
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
