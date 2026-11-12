//! Flows to and from the loopback services (trunk flows.go readFlow on the
//! exit): a client's flow has a UDP socket of its own to its port, watched
//! by epoll; what the service answers goes down to the entry as the flow's
//! datagrams. A socket that fails (the service is gone) ends its flow, as
//! the Go exit's read error ends it.

use std::io;
use std::os::fd::AsRawFd;

use hikkari_sys as sys;

use super::Exit;

/// Most datagrams one relay socket gives in one turn: a busy flow does not
/// hold up the others; level-triggered epoll gives it the next turn.
const PER_TURN: usize = 64;

impl Exit {
    /// Opens flow fi's socket to its loopback port and watches it.
    pub(super) fn relay_open(&mut self, fi: usize) -> io::Result<()> {
        let f = &mut self.flows.all[fi];
        let sock = sys::udp_to_loopback(f.port)?;
        let fd = sock.as_raw_fd();
        self.relays.add(fd, fi as u64 | (f.gen as u64) << 32)?;
        f.fd = fd;
        f.sock = Some(sock);
        Ok(())
    }

    /// Ends flow fi: off the poll, out of its session, its socket closed.
    /// Whether it was a client's.
    pub(super) fn end_flow(&mut self, fi: usize) -> bool {
        let f = &self.flows.all[fi];
        if f.fd >= 0 {
            self.relays.del(f.fd);
        }
        let s = f.session;
        self.flows.end(&mut self.sessions.all[s].flows, fi)
    }

    /// Every ready relay socket's answers, down to the entry.
    pub(super) fn read_relays(&mut self, now: u64) {
        let n = self.relays.ready();
        if n == 0 {
            return;
        }
        let mut buf = std::mem::take(&mut self.relay_buf);
        for i in 0..n {
            let d = self.relays.data(i);
            let (fi, gen) = ((d & 0xffff_ffff) as usize, (d >> 32) as u32);
            for _ in 0..PER_TURN {
                let Some(f) = self.flows.at(fi, gen) else { break };
                match sys::recv_dgram(f.fd, &mut buf) {
                    Ok(Some(len)) => {
                        f.used = now;
                        self.t.dgrams_out += 1;
                        self.moved += 1;
                        self.answer(fi, &buf[..len], now);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        self.end_flow(fi);
                        break;
                    }
                }
            }
        }
        self.relay_buf = buf;
    }
}
