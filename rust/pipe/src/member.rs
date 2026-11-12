//! Wires and their members: a member is a socket of its own to the exit, its
//! health (hikkari_trunk::health) and its glue, the frames of one tick
//! sealed into one datagram.

use std::io;
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use hikkari_sys::{self as sys, SendBatch, BATCH};
use hikkari_trunk::health::Health;
use hikkari_trunk::udpwire::{Seal, OVERHEAD};

use crate::ctl::WireTick;

/// A wire datagram's slot: a sealed datagram of at most this.
pub const SLOT: usize = 2048;

pub struct Member {
    pub sock: Option<UdpSocket>,
    pub fd: i32,
    /// Up, its pings, its debt: spec/trunk.md, "Members' health".
    pub h: Health,
    pub hello_at: u64,
    /// Without a brain: when a member taken down gets its new socket (0:
    /// not waiting for one).
    pub renew_at: u64,
    /// Sealed datagrams waiting for sendmmsg: BATCH slots.
    out: Vec<u8>,
    out_n: usize,
    pub send: SendBatch,
    /// The frames being glued, at glue[12..12 + glue_n]; glue_since is when
    /// the first of them came (0: empty).
    glue: Box<[u8; SLOT]>,
    pub glue_n: usize,
    pub glue_since: u64,
    pub seal: Seal,
    pub dgrams: u64,
}

impl Member {
    pub fn new(sock: Option<UdpSocket>, key: &[u8; 32]) -> Member {
        let fd = sock.as_ref().map_or(-1, |s| s.as_raw_fd());
        Member {
            sock,
            fd,
            h: Health::new(true),
            hello_at: 0,
            renew_at: 0,
            out: vec![0; SLOT * BATCH],
            out_n: 0,
            send: SendBatch::new(),
            glue: Box::new([0; SLOT]),
            glue_n: 0,
            glue_since: 0,
            seal: new_seal(key),
            dgrams: 0,
        }
    }

    /// A new socket: the member starts over with its hello.
    pub fn set_sock(&mut self, sock: Option<UdpSocket>) {
        self.fd = sock.as_ref().map_or(-1, |s| s.as_raw_fd());
        self.sock = sock;
        self.h.down();
        self.hello_at = 0;
        self.renew_at = 0;
        self.glue_n = 0;
        self.glue_since = 0;
        self.out_n = 0;
        self.send.n = 0;
    }

    /// A new key: the seal starts over with a nonce prefix of its own.
    pub fn rekey(&mut self, key: &[u8; 32]) {
        self.seal = new_seal(key);
    }

    /// Seals the glued frames into the next out slot; sends the batch when
    /// it is full.
    pub fn seal_glue(&mut self) {
        if self.glue_n == 0 {
            return;
        }
        if self.out_n == BATCH {
            self.flush_out();
        }
        let slot = &mut self.out[self.out_n * SLOT..(self.out_n + 1) * SLOT];
        slot[12..12 + self.glue_n].copy_from_slice(&self.glue[12..12 + self.glue_n]);
        let n = self.seal.seal(slot, self.glue_n);
        let ptr = slot.as_ptr();
        self.send.push(ptr, n, None);
        self.out_n += 1;
        self.glue_n = 0;
        self.glue_since = 0;
        self.dgrams += 1;
    }

    pub fn flush_out(&mut self) {
        if self.out_n > 0 {
            self.send.flush(self.fd);
            self.out_n = 0;
        }
    }

    /// Puts one frame (written by `put` into the glue) in, sealing first
    /// when it would not fit; a frame alone over the limit goes alone.
    #[inline]
    pub fn glue_frame(&mut self, need: usize, max: usize, now: u64, put: impl FnOnce(&mut [u8]) -> usize) {
        if self.glue_n > 0 && OVERHEAD + self.glue_n + need > max {
            self.seal_glue();
        }
        let n = put(&mut self.glue[12 + self.glue_n..]);
        self.glue_n += n;
        if self.glue_since == 0 {
            self.glue_since = now;
        }
    }
}

fn new_seal(key: &[u8; 32]) -> Seal {
    let mut prefix = [0u8; 4];
    sys::urandom(&mut prefix);
    Seal::from_key(key, prefix)
}

pub struct Wire {
    pub id: u8,
    pub glue_ns: u64,
    pub glue_max: usize,
    /// Its members' stall (trunk Config.Stall): the brain's dead_ms.
    pub stall_ns: u64,
    pub key: [u8; 32],
    pub members: Vec<Member>,
    /// Without a brain: where a member's new socket goes.
    pub exit: Option<SocketAddrV4>,
    /// When one of its members last proved its round trip (0: never).
    pub proof: u64,
    pub t: WireTick,
}

impl Wire {
    pub fn new(id: u8, key: [u8; 32], stall_ns: u64) -> Wire {
        Wire {
            id,
            glue_ns: 0,
            glue_max: 0,
            stall_ns,
            key,
            members: Vec::new(),
            exit: None,
            proof: 0,
            t: WireTick { id, ..Default::default() },
        }
    }

    pub fn up(&self) -> usize {
        self.members.iter().filter(|m| m.h.up).count()
    }

    pub fn any_up(&self) -> bool {
        self.members.iter().any(|m| m.h.up)
    }
}

/// A member's socket to the exit, bound by the pipe (no brain).
pub fn member_to(exit: SocketAddrV4) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect(exit)?;
    sys::tune(&s, false)?;
    Ok(s)
}
