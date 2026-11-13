//! The Chromium QUIC wire in the exit's loop (spec/trunk.md, `h3dgram`;
//! h3wire.rs): its packets read in batches, each given to its connection;
//! a CONNECT-UDP with a known token makes a member, whose datagrams' frames
//! are any packet member's (wire.rs, frames); a member whose request ended
//! or whose connection closed is dropped, and a member the exit drops
//! closes its connection.

use hikkari_sys::{RecvBatch, BATCH};

use super::Exit;
use crate::h3wire::Req;

impl Exit {
    /// Everything the QUIC wire wi has, batch by batch.
    pub(super) fn read_h3(&mut self, wi: usize, rb: &mut RecvBatch, now: u64) {
        loop {
            let n = rb.recv(self.wires[wi].fd());
            for i in 0..n {
                let (from, len, slot) = (rb.addr[i], rb.len[i], rb.slot);
                let h = self.wires[wi].h3().expect("a QUIC wire");
                match h.recv(from, &mut rb.buf[i * slot..i * slot + len]) {
                    Some(ci) => self.h3_conn(wi, ci, now),
                    None => self.t.bad += 1,
                }
            }
            if n < BATCH {
                break;
            }
        }
    }

    /// What one packet made of connection ci: requests first (a member's
    /// CONNECT-UDP comes before its datagrams), then the datagrams.
    fn h3_conn(&mut self, wi: usize, ci: usize, now: u64) {
        while let Some(r) = self.wires[wi].h3().expect("a QUIC wire").poll(ci) {
            match r {
                Req::Member(stream) => {
                    let Some(pi) = self.take_request(wi, ci, stream, now) else {
                        self.wires[wi].h3().expect("a QUIC wire").close(ci);
                        return;
                    };
                    let gen = self.peers[pi].gen;
                    self.wires[wi].h3().expect("a QUIC wire").bind(ci, stream, pi, gen);
                }
                Req::Ended(stream) => {
                    let pi = self.peers.iter().position(|p| p.live && p.wire == wi && p.conn == ci && p.stream == stream);
                    if let Some(pi) = pi {
                        self.drop_peer(pi, now);
                    }
                }
            }
        }
        let mut buf = std::mem::take(&mut self.dgram_buf);
        while let Some((pi, at, n)) = self.wires[wi].h3().expect("a QUIC wire").dgram(ci, &mut buf) {
            if self.peers[pi].live && self.peers[pi].conn == ci {
                self.frames(pi, &buf[at..n], now);
            }
        }
        self.dgram_buf = buf;
    }

    /// A peer slot for the CONNECT-UDP of `stream` on connection ci; None
    /// when MAX_PEERS are served.
    fn take_request(&mut self, wi: usize, ci: usize, stream: u64, now: u64) -> Option<usize> {
        if self.peers.len() - self.peers_free.len() >= super::MAX_PEERS {
            return None;
        }
        let i = self.peers_free.pop().unwrap_or_else(|| {
            self.peers.push(crate::peer::Peer::vacant());
            self.peers.len() - 1
        });
        self.peers[i].take_request(wi, ci, stream, now);
        Some(i)
    }

    /// Closed connections forgotten, their members dropped (those still the
    /// slot's: a slot reused since is another member).
    pub(super) fn reap_h3(&mut self, now: u64) {
        let mut gone = std::mem::take(&mut self.gone);
        for wi in 0..self.wires.len() {
            if let Some(h) = self.wires[wi].h3() {
                h.reap(&mut gone);
            }
        }
        for (pi, gen) in gone.drain(..) {
            let p = &mut self.peers[pi];
            if p.live && p.gen == gen {
                p.conn = crate::peer::NONE;
                self.drop_peer(pi, now);
            }
        }
        self.gone = gone;
    }
}
