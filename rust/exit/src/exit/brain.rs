//! The brain's messages (ctl.rs) and the exit's tick to it.

use hikkari_sys as sys;

use super::{Exit, Pool};
use crate::ctl::{self, Msg};
use crate::peer::Wire;

impl Exit {
    /// Every message the brain has sent; false once the brain is gone.
    pub(super) fn read_brain(&mut self) -> bool {
        if self.ctl.is_none() || !self.poll.readable(0) {
            return true;
        }
        let mut msg = std::mem::take(&mut self.msg);
        let alive = loop {
            self.fds.clear();
            let c = self.ctl.as_mut().expect("the brain's socket");
            match c.recv(&mut msg, &mut self.fds) {
                Ok(None) => break true,
                Ok(Some(0)) => break false,
                Ok(Some(n)) => {
                    let mut fds = std::mem::take(&mut self.fds);
                    if let Err(e) = self.handle(&msg[..n], &mut fds) {
                        self.error(&e);
                    }
                    for fd in fds.drain(..) {
                        sys::close_fd(fd);
                    }
                    self.fds = fds;
                }
                Err(e) => self.error(&format!("exit: the brain's socket: {e}")),
            }
        };
        self.msg = msg;
        alive
    }

    /// One message; the sockets it uses are taken out of fds, the rest the
    /// caller closes.
    fn handle(&mut self, m: &[u8], fds: &mut Vec<i32>) -> Result<(), String> {
        match ctl::parse(m).ok_or_else(|| format!("exit: a message it cannot read (type {:#x})", m.first().copied().unwrap_or(0)))? {
            Msg::Hello { ver } if ver == ctl::VERSION => Ok(()),
            Msg::Hello { ver } => Err(format!("exit: the brain speaks version {ver}, the exit {}", ctl::VERSION)),
            Msg::Wire { id, form, glue_us, glue_max, dead_ms, quiet_ms, keys } => {
                if form != ctl::FORM_UDP {
                    return Err(format!("exit: wire {id}: form {form} is not one the exit carries"));
                }
                if self.wires.iter().any(|w| w.id == id) {
                    return Err(format!("exit: wire {id} is set already"));
                }
                if fds.len() != 1 {
                    return Err(format!("exit: wire {id} came with {} sockets, want 1", fds.len()));
                }
                let sock = sys::udp_from_fd(fds.remove(0)).map_err(|e| format!("exit: wire {id}: {e}"))?;
                sys::tune(&sock, false).map_err(|e| format!("exit: wire {id}: {e}"))?;
                let keys = keys.chunks(32).map(|k| k.try_into().expect("32")).collect();
                let w = Wire::udp(id, sock, keys, dead_ms as u64 * 1_000_000, quiet_ms as u64 * 1_000_000, glue_us as u64 * 1000, glue_max as usize);
                self.wires.push(w);
                self.dirty = true;
                Ok(())
            }
            Msg::Pool { dead_ms, quiet_ms } => {
                if self.pool.is_some() {
                    return Err("exit: the pool's port is set already".into());
                }
                if fds.len() != 1 {
                    return Err(format!("exit: the pool came with {} sockets, want 1", fds.len()));
                }
                let fd = sys::tcp_from_fd(fds.remove(0)).map_err(|e| format!("exit: the pool's socket: {e}"))?;
                let p = Pool { fd, stall_ns: dead_ms as u64 * 1_000_000, quiet_ns: quiet_ms as u64 * 1_000_000 };
                self.set_pool(p).map_err(|e| format!("exit: the pool's socket: {e}"))?;
                Ok(())
            }
            Msg::Ports { ports } => {
                self.ports.iter_mut().for_each(|p| *p = false);
                for i in 0..ports.len() / 2 {
                    self.ports[ctl::port_at(ports, i) as usize] = true;
                }
                Ok(())
            }
        }
    }

    fn error(&mut self, text: &str) {
        eprintln!("{text}");
        if let Some(c) = self.ctl.as_mut() {
            let mut b = [0u8; 512];
            let n = ctl::put_error(&mut b, text);
            c.send(&b[..n]);
        }
    }

    /// The tick: the exit now and its counters since it started.
    pub(super) fn send_tick(&mut self, now: u64) {
        let t = &mut self.t;
        t.pause_ago_ms = if self.pause.resumed == 0 { ctl::NONE_MS } else { ms(now - self.pause.resumed) };
        t.pauses = self.pause.pauses;
        t.late_max_us = (self.late_max / 1000).min(u32::MAX as u64) as u32;
        self.late_max = 0;
        t.sessions = self.sessions.live();
        t.flows = self.flows.clients;
        t.streams = self.streams.open;
        let n = &self.streams.n;
        (t.streams_opened, t.streams_fin, t.reset_peer, t.reset_local) = (n.opened, n.fin, n.reset_peer, n.reset_local);
        (t.hit, t.resent, t.up, t.down, t.early, t.early_dropped) = (n.deaths, n.resent, n.up, n.down, n.early, n.early_dropped);
        t.w_out = self.wires.iter().map(|w| w.dgrams).sum();
        t.frames_out = self.wires.iter().map(|w| w.frames).sum();
        t.dropped = self.wires.iter().map(|w| w.socket_counts().0 + w.dropped).sum();
        let Some(c) = self.ctl.as_mut() else { return };
        let mut b = [0u8; ctl::TICK_LEN];
        let n = self.t.put(&mut b);
        c.send(&b[..n]);
    }
}

fn ms(ns: u64) -> u32 {
    (ns / 1_000_000).min(u32::MAX as u64 - 1) as u32
}
