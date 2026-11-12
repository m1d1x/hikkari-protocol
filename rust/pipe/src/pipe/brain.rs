//! The brain's messages (ctl.rs) and what the pipe tells the brain: member
//! events at once, a tick of every wire a second.

use std::io;

use hikkari_sys::{self as sys, now_ns, SendBatch};
use hikkari_trunk::health;
use hikkari_trunk::udpwire::OVERHEAD;

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

    fn error(&mut self, e: &str) {
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
        let Pipe { msg, fds, wires, flows, route, listens, dirty, gro, moved, .. } = self;
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
                let mut socks = Vec::with_capacity(fds.len());
                for fd in fds.drain(..) {
                    let s = sys::udp_from_fd(fd).map_err(|e| e.to_string())?;
                    sys::tune(&s, false).map_err(|e| format!("wire {id}: {e}"))?;
                    socks.push(s);
                }
                let at = match wires.iter().position(|w| w.id == id) {
                    Some(i) => i,
                    None => {
                        wires.push(Wire::new(id, key, health::STALL));
                        wires.len() - 1
                    }
                };
                let w = &mut wires[at];
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
                *dirty = true;
            }
            Msg::Route { voice, bulk } => {
                route[CLASS_BULK as usize] = bulk;
                route[CLASS_VOICE as usize] = voice;
            }
            Msg::Open { tag, class, pin, port, copies } => {
                flows.open(tag, Flow::new(Dest::Brain { tag }, class, pin, port, copies, now))?;
            }
            Msg::Dgram { tag, payload } => {
                let Some((id, (f, n))) = flows.tagged(tag).and_then(|id| Some((id, flows.with_counts(id)?))) else {
                    return Ok(()); // closed under it
                };
                carry(wires, *route, f, id, payload, now);
                if !f.echo() {
                    n.out += 1;
                }
                *moved += 1;
            }
            Msg::Close { tag } => flows.close(tag),
            Msg::Member { wire, index } => {
                if fds.len() != 1 {
                    return Err(format!("member {wire}/{index}: {} sockets, want 1", fds.len()));
                }
                let s = sys::udp_from_fd(fds.remove(0)).map_err(|e| e.to_string())?;
                sys::tune(&s, false).map_err(|e| e.to_string())?;
                let Some(m) = wires.iter_mut().find(|w| w.id == wire).and_then(|w| w.members.get_mut(index as usize)) else {
                    return Err(format!("member {wire}/{index}: no such member"));
                };
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
        };
        self.late_max = 0;
        let Some(c) = &mut self.ctl else { return };
        let mut ticks = [WireTick::default(); 32];
        let mut n = 0;
        for w in self.wires.iter().take(ticks.len()) {
            let mut t = w.t;
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
            t.dgrams = w.members.iter().map(|m| m.dgrams).sum();
            t.dropped += w.members.iter().map(|m| m.send.dropped).sum::<u64>();
            ticks[n] = t;
            n += 1;
        }
        let len = ctl::put_tick(&mut self.out, &p, &ticks[..n]);
        c.send(&self.out[..len]);
    }
}
