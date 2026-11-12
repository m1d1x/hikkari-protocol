//! A packet wire on the exit and the entry's members on it (spec/trunk.md,
//! "Wires"; trunk/udpwire Listener): one socket for every member, a member
//! per entry address, joined to its session by its hello. Each member has
//! its health (hikkari_trunk::health, judged by the exit as by the entry)
//! and its glue: the frames bound for it in one tick sealed into one
//! datagram, which the Go exit does not do (trunk session.go writePackets:
//! every frame in a datagram of its own). The entry's packet members read a
//! frame sequence per datagram, so the glue changes nothing for them but
//! the count of datagrams.

use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use hikkari_sys::{self as sys, sockaddr_in, SendBatch, BATCH};
use hikkari_trunk::health::Health;
use hikkari_trunk::udpwire::{Seal, OVERHEAD};

/// The largest datagram on the wire (udpwire MaxDatagram, the IPv4 UDP
/// payload limit): a wire's receive and send slots hold one each.
pub const SLOT: usize = 65507;

/// No index: a member not in a session, a flow's member not known.
pub const NONE: usize = usize::MAX;

/// One packet wire: its socket, the keys a member's first datagram may open
/// under, its members' stall and the session's Quiet, its glue, and the
/// sealed datagrams waiting for one sendmmsg to their addresses.
pub struct Wire {
    pub id: u8,
    sock: UdpSocket,
    pub keys: Vec<[u8; 32]>,
    /// One opener per key: opening takes no nonce of its own.
    pub openers: Vec<Seal>,
    pub stall_ns: u64,
    pub quiet_ns: u64,
    pub glue_ns: u64,
    pub glue_max: usize,
    out: Vec<u8>,
    out_n: usize,
    pub send: SendBatch,
    /// Frames glued and sealed datagrams sent since the wire came: frames
    /// per datagram is the glue down.
    pub frames: u64,
    pub dgrams: u64,
}

impl Wire {
    pub fn new(id: u8, sock: UdpSocket, keys: Vec<[u8; 32]>, stall_ns: u64, quiet_ns: u64, glue_ns: u64, glue_max: usize) -> Wire {
        let openers = keys.iter().map(|k| Seal::from_key(k, [0; 4])).collect();
        Wire {
            id,
            sock,
            keys,
            openers,
            stall_ns,
            quiet_ns,
            glue_ns,
            glue_max: glue_max.clamp(OVERHEAD + 64, SLOT),
            out: vec![0; SLOT * BATCH],
            out_n: 0,
            send: SendBatch::new(),
            frames: 0,
            dgrams: 0,
        }
    }

    #[inline]
    pub fn fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }

    /// Sends every sealed datagram waiting.
    pub fn flush(&mut self) {
        if self.out_n > 0 {
            self.send.flush(self.sock.as_raw_fd());
            self.out_n = 0;
        }
    }

    /// Seals `p`'s glued frames into the next out slot, to its address.
    pub fn seal(&mut self, p: &mut Peer) {
        if p.glue_n == 0 {
            return;
        }
        if self.out_n == BATCH {
            self.flush();
        }
        let slot = &mut self.out[self.out_n * SLOT..(self.out_n + 1) * SLOT];
        slot[12..12 + p.glue_n].copy_from_slice(&p.glue[12..12 + p.glue_n]);
        let n = p.seal.seal(slot, p.glue_n);
        self.send.push(slot.as_ptr(), n, Some(&p.addr));
        self.out_n += 1;
        p.glue_n = 0;
        p.glue_since = 0;
        self.dgrams += 1;
    }

    /// Puts one frame of `need` bytes (written by `put`) into p's glue,
    /// sealing first what is there when it would not fit; a frame alone
    /// over the window's size goes alone. False for a frame no datagram
    /// holds: dropped, as udpwire drops a write over MaxDatagram.
    #[inline]
    pub fn glue(&mut self, p: &mut Peer, need: usize, now: u64, put: impl FnOnce(&mut [u8]) -> usize) -> bool {
        if OVERHEAD + need > SLOT {
            return false;
        }
        if p.glue_n > 0 && OVERHEAD + p.glue_n + need > self.glue_max {
            self.seal(p);
        }
        let n = put(&mut p.glue[12 + p.glue_n..]);
        p.glue_n += n;
        self.frames += 1;
        if p.glue_since == 0 {
            p.glue_since = now;
        }
        true
    }

    /// One frame in a datagram of its own, now: a hello's answer, which the
    /// Go entry reads apart from the frames after it.
    pub fn alone(&mut self, p: &mut Peer, need: usize, now: u64, put: impl FnOnce(&mut [u8]) -> usize) {
        self.seal(p);
        self.glue(p, need, now, put);
        self.seal(p);
    }
}

/// One entry address on a wire: a member once its hello is answered.
pub struct Peer {
    /// A slot of the exit's peers in use; gen counts its uses, so a flow
    /// that remembers an index knows a member that came after the one it
    /// knew.
    pub live: bool,
    pub gen: u32,
    pub addr: sockaddr_in,
    pub key: u64,
    pub wire: usize,
    /// The member's session (NONE until its hello) and its wire as its
    /// hello says it: the wire the answers to a flow it carried go on.
    pub session: usize,
    pub wire_id: u8,
    pub flags: u8,
    pub h: Health,
    /// When it last sent a datagram that opened (udpwire's peer.last).
    pub heard: u64,
    pub seal: Seal,
    glue: Box<[u8]>,
    pub glue_n: usize,
    pub glue_since: u64,
}

impl Peer {
    pub fn vacant() -> Peer {
        Peer {
            live: false,
            gen: 0,
            addr: sys::sockaddr("0.0.0.0:0".parse().unwrap()),
            key: 0,
            wire: 0,
            session: NONE,
            wire_id: 0,
            flags: 0,
            h: Health::new(true),
            heard: 0,
            seal: Seal::from_key(&[0; 32], [0; 4]),
            glue: vec![0; SLOT].into_boxed_slice(),
            glue_n: 0,
            glue_since: 0,
        }
    }

    /// The slot taken by a new address of `wire` whose first datagram
    /// opened under `key`; its seal draws a nonce prefix of its own.
    pub fn take(&mut self, addr: sockaddr_in, wire: usize, key: &[u8; 32], now: u64) {
        let mut prefix = [0u8; 4];
        sys::urandom(&mut prefix);
        self.live = true;
        self.gen = self.gen.wrapping_add(1);
        self.addr = addr;
        self.key = sys::addr_key(&addr);
        self.wire = wire;
        self.session = NONE;
        self.wire_id = 0;
        self.flags = 0;
        self.h = Health::new(true);
        self.heard = now;
        self.seal = Seal::from_key(key, prefix);
        self.glue_n = 0;
        self.glue_since = 0;
    }

    /// A member: its hello answered, in a session.
    #[inline]
    pub fn joined(&self) -> bool {
        self.live && self.session != NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer's glue seals into one datagram that opens to the same frames,
    /// and a frame that would overflow the window seals what was there.
    #[test]
    fn glued_frames_seal_into_one_datagram() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut w = Wire::new(2, sock, vec![[7; 32]], 0, 0, 0, 100);
        let mut p = Peer::vacant();
        p.take(sys::sockaddr("127.0.0.1:9".parse().unwrap()), 0, &[7; 32], 1);
        assert!(w.glue(&mut p, 30, 5, |b| {
            b[..30].fill(1);
            30
        }));
        assert!(w.glue(&mut p, 30, 6, |b| {
            b[..30].fill(2);
            30
        }));
        assert_eq!((p.glue_n, p.glue_since, w.dgrams), (60, 5, 0));
        assert!(w.glue(&mut p, 30, 7, |b| {
            b[..30].fill(3);
            30
        }));
        assert_eq!((p.glue_n, p.glue_since, w.dgrams, w.frames), (30, 7, 1, 3), "a third frame over 100 bytes sealed the first two");
        let first = &mut w.out[..OVERHEAD + 60];
        let n = w.openers[0].open(first).unwrap();
        assert_eq!(n, 60);
        assert!(first[12..42].iter().all(|&b| b == 1) && first[42..72].iter().all(|&b| b == 2));
        assert!(!w.glue(&mut p, SLOT, 8, |_| 0), "a frame no datagram holds");
    }
}
