//! The brain's messages (ctl.rs) and what the pipe tells the brain: member
//! events at once, a tick of every wire a second.

use std::io;

use hikkari_sys::{self as sys, now_ns, SendBatch};
use hikkari_trunk::health;
use hikkari_trunk::udpwire::OVERHEAD;

use super::session::{add_counts, counted};
use super::{ms, Listen, Pipe};
use crate::carry::carry;
use crate::ctl::{self, Msg, PipeTick, WireTick, ANY_WIRE, NONE_MS};
use crate::flow::{Dest, Flow, CLASS_BULK, CLASS_VOICE};
use crate::member::{Member, Wire, SLOT};

impl Pipe {
    /// The brain's messages, all there are; false once the brain is gone.
    pub(super) fn read_brain(&mut self) -> bool {
        if self.ctl.is_none() || !self.poll.readable(0) {
            return true;
        }
        loop {
            self.fds.clear();
            let r = self.ctl.as_mut().unwrap().recv(&mut self.msg, &mut self.fds);
            match r {
                Ok(None) => return true,
                Ok(Some(0)) => return false,
                Ok(Some(n)) => {
                    if let Err(e) = self.handle(n) {
                        self.error(&e);
                    }
                    for fd in self.fds.drain(..) {
                        sys::close_fd(fd); // sockets the message did not take
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => self.error(&e.to_string()),
                Err(_) => return false,
            }
        }
    }

    pub(super) fn error(&mut self, e: &str) {
        let mut b = Vec::with_capacity(1 + e.len());
        b.push(ctl::P_ERROR);
        b.extend_from_slice(e.as_bytes());
        if let Some(c) = &mut self.ctl {
            c.send(&b);
        }
    }

    /// One message of n bytes in self.msg, its sockets in self.fds (what it
    /// takes it removes from there).
    fn handle(&mut self, n: usize) -> Result<(), String> {
        // A handoff's socket, whichever end: the generations' part.
        match ctl::parse(&self.msg[..n]) {
            Some(Msg::Drain) => return self.drain(),
            Some(Msg::Adopt) => return self.adopt(),
            _ => {}
        }
        let (cur, taker) = (self.cur, self.taker());
        let Pipe { msg, fds, wires, swires, flows, route, listens, dirty, gro, moved, gone, .. } = self;
        let Some(m) = ctl::parse(&msg[..n]) else {
            return Err(format!("a message the pipe does not know: type {:#x}, {} bytes", msg[0], n));
        };
        let now = now_ns();
        match m {
            Msg::Hello { ver } => {
                if ver != ctl::VERSION {
                    return Err(format!("brain speaks version {ver}, the pipe {}", ctl::VERSION));
                }
            }
            Msg::Listen { id, class, to, copies } => {
                if fds.len() != 1 {
                    return Err(format!("listen {id}: {} sockets, want 1", fds.len()));
                }
                let sock = sys::udp_from_fd(fds.remove(0)).map_err(|e| e.to_string())?;
                sys::tune(&sock, *gro).map_err(|e| format!("listen {id}: {e}"))?;
                let l = Listen { id, sock, class, to, copies, down: SendBatch::new() };
                match listens.iter_mut().find(|l| l.id == id) {
                    Some(old) => *old = l,
                    None => listens.push(l),
                }
                *dirty = true;
            }
            Msg::Wire { id, form, glue_us, glue_max, dead_ms, key } => {
                if form != ctl::FORM_UDP {
                    return Err(format!("wire {id}: form {form} is not one the pipe carries"));
                }
                if id == ANY_WIRE {
                    return Err("wire 255 is no wire".into());
                }
                // New members join the session that takes everything new
                // (session.rs); a pipe draining itself takes none.
                let Some(sess) = taker else {
                    return Err(format!("wire {id}: the pipe drains, it takes no new member"));
                };
                let mut socks = Vec::with_capacity(fds.len());
                for fd in fds.drain(..) {
                    let s = sys::udp_from_fd(fd).map_err(|e| e.to_string())?;
                    sys::tune(&s, false).map_err(|e| format!("wire {id}: {e}"))?;
                    socks.push(s);
                }
                let at = match wires.iter().position(|w| w.id == id && w.sess == sess) {
                    Some(i) => i,
                    None => {
                        let mut w = Wire::new(id, key, health::STALL);
                        w.sess = sess;
                        wires.push(w);
                        wires.len() - 1
                    }
                };
                let w = &mut wires[at];
                // A session coming up dials its own members where the
                // brain's go.
                if let Some(Ok(std::net::SocketAddr::V4(a))) = socks.first().map(|s| s.peer_addr()) {
                    w.exit = Some(a);
                }
                w.glue_ns = glue_us as u64 * 1000;
                w.glue_max = (glue_max as usize).clamp(64, SLOT - OVERHEAD);
                w.stall_ns = dead_ms.max(1) as u64 * 1_000_000;
                // New sockets (or a new key) start the members over; a member
                // keeps its counters.
                let rekey = w.key != key;
                w.key = key;
                w.members.truncate(socks.len());
                for (i, s) in socks.into_iter().enumerate() {
                    match w.members.get_mut(i) {
                        Some(m) => {
                            m.set_sock(Some(s));
                            if rekey {
                                m.rekey(&key);
                            }
                        }
                        None => w.members.push(Member::new(Some(s), &key)),
                    }
                }
                *dirty = true;
            }
            Msg::Unwire { id } => {
                wires.retain(|w| w.id != id);
                gone.retain(|g| g.id != id);
                *dirty = true;
            }
            Msg::Route { voice, bulk } => {
                route[CLASS_BULK as usize] = bulk;
                route[CLASS_VOICE as usize] = voice;
            }
            Msg::Open { tag, class, pin, port, copies } => {
                let mut f = Flow::new(Dest::Brain { tag }, class, pin, port, copies, now);
                f.sess = cur;
                flows.open(tag, f)?;
            }
            Msg::Dgram { tag, payload } => {
                let Some((id, (f, n))) = flows.tagged(tag).and_then(|id| Some((id, flows.with_counts(id)?))) else {
                    return Ok(()); // closed under it
                };
                carry(wires, swires, *route, f, id, payload, now);
                if !f.echo() {
                    n.out += 1;
                }
                *moved += 1;
            }
            Msg::Close { tag } => flows.close(tag),
            Msg::Drain | Msg::Adopt => unreachable!("taken above"),
            Msg::Member { wire, index } => {
                if fds.len() != 1 {
                    return Err(format!("member {wire}/{index}: {} sockets, want 1", fds.len()));
                }
                let Some(m) = wires.iter_mut().find(|w| w.id == wire && w.sess == cur).and_then(|w| w.members.get_mut(index as usize)) else {
                    return Err(format!("member {wire}/{index}: no such member"));
                };
                // Only a member down of the session that replaces its
                // members takes it (session.rs): one of a session handing
                // over to the next, or retired, comes back to no one, and a
                // socket that comes after a takeover finds a member of the
                // new session up. The socket left in fds is closed.
                if taker != Some(cur) || m.fd >= 0 || m.renew_at != 0 {
                    return Ok(());
                }
                let s = sys::udp_from_fd(fds.remove(0)).map_err(|e| e.to_string())?;
                sys::tune(&s, false).map_err(|e| e.to_string())?;
                m.set_sock(Some(s));
                *dirty = true;
            }
        }
        Ok(())
    }

    /// Member events go to the brain at once, and a tick after them: the
    /// selector reads a wire's members from ticks, and need not wait for the
    /// next second to see one gone.
    pub(super) fn send_events(&mut self) {
        if self.events.is_empty() {
            return;
        }
        let tick = self.ctl.is_some();
        for e in std::mem::take(&mut self.events) {
            match &mut self.ctl {
                Some(c) => {
                    let mut b = [0u8; 8];
                    let n = ctl::put_member(&mut b, e.wire, e.index, e.up, e.why);
                    c.send(&b[..n]);
                }
                None => eprintln!("hk-pipe: wire {} member {} {} (why {})", e.wire, e.index, if e.up { "up" } else { "down" }, e.why),
            }
        }
        if tick {
            self.send_tick(now_ns());
        }
    }

    pub(super) fn send_tick(&mut self, now: u64) {
        let p = PipeTick {
            pause_ago_ms: if self.judge.resumed == 0 { NONE_MS } else { ms(now - self.judge.resumed) },
            pauses: self.judge.pauses,
            late_max_us: (self.late_max / 1000).min(u32::MAX as u64) as u32,
            flows: self.flows.clients,
            dgrams_out: self.flows.n.out,
            dgrams_in: self.flows.n.delivered,
            dgrams_copy: self.flows.n.copies,
            flows_idle: self.flows.n.idle,
            retired: self.sessions.iter().filter(|s| s.live && s.retired_at != 0).count() as u8,
            coming: self.next.is_some(),
        };
        self.late_max = 0;
        let Some(c) = &mut self.ctl else { return };
        let mut ticks = [WireTick::default(); 32];
        let mut n = 0;
        // The current session's wires, with what every session counted on
        // each (session.rs: the brain sees the current one alone).
        for w in self.wires.iter().filter(|w| w.sess == self.cur).take(ticks.len()) {
            let mut t = counted(w);
            for o in self.wires.iter().filter(|o| o.id == w.id && o.sess != w.sess) {
                add_counts(&mut t, &counted(o));
            }
            for g in self.gone.iter().filter(|g| g.id == w.id) {
                add_counts(&mut t, g);
            }
            t.members = w.members.len() as u8;
            t.up = w.up() as u8;
            t.owed_ms = 0;
            t.rtt_us = 0;
            let mut first = true;
            for m in w.members.iter().filter(|m| m.h.up) {
                let owed = ms(m.h.owed(&self.judge, now));
                t.owed_ms = if first { owed } else { t.owed_ms.min(owed) };
                first = false;
                if m.h.rtt > 0 {
                    let us = (m.h.rtt / 1000) as u32;
                    t.rtt_us = if t.rtt_us == 0 { us } else { t.rtt_us.min(us) };
                }
            }
            t.proof_ago_ms = if w.proof == 0 { NONE_MS } else { ms(now - w.proof) };
            ticks[n] = t;
            n += 1;
        }
        let len = ctl::put_tick(&mut self.out, &p, &ticks[..n]);
        c.send(&self.out[..len]);
    }
}
