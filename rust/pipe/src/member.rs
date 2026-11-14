//! Wires and their members: a member is a socket of its own to the exit, its
//! health (hikkari_trunk::health) and its glue, the frames of one tick
//! sealed into one datagram. A member of the Chromium QUIC wire (h3.rs) has
//! its tunnel's end for a socket, and its datagrams are the frames as they
//! are (spec/trunk.md, `h3dgram`: QUIC's TLS keeps them); its frames wait in
//! its scheduler and go under its connection's guard (hikkari_trunk::sched,
//! guard; "How each end sends"), judged from Chromium's own counts, a full
//! queue as loss (Guard::over_a_sender).

use std::io;
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use hikkari_cronet::Tunnel;
use hikkari_sys::{self as sys, SendBatch, BATCH};
use hikkari_trunk::guard::{Guard, Snap};
use hikkari_trunk::sched::{Class, Sched};
use hikkari_trunk::health::Health;
use hikkari_trunk::udpwire::{Seal, OVERHEAD};

use crate::ctl::WireTick;

/// A wire datagram's slot: a sealed datagram of at most this.
pub const SLOT: usize = 2048;
/// What a QUIC wire's datagram adds in its packet, for the guard's budget:
/// Chromium's short header with the exit's 16-byte id, a packet number,
/// AEAD's tag, the DATAGRAM frame's and the HTTP Datagram's heads.
const PACKET_OVER: usize = 1 + 16 + 4 + 16 + 3 + 2;

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
    /// Its datagrams are the frames unsealed (the QUIC wire's members), at
    /// most frames_max bytes each: Chromium resets a tunnel's stream on an
    /// HTTP Datagram over its QUIC packet's room, so one that would not fit
    /// is dropped here and counted in too_big.
    pub plain: bool,
    pub frames_max: usize,
    pub too_big: u64,
    /// The QUIC wire's: frames waiting for its datagrams, and the guard of
    /// its connection (a new one per tunnel).
    pub sched: Option<Box<Sched>>,
    pub guard: Guard,
    /// The QUIC wire's: its CONNECT-UDP tunnel, whose end is fd, and the
    /// source port of its QUIC connection, from the wire's book (h3.rs).
    pub tun: Option<Tunnel>,
    pub port: u16,
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
            plain: false,
            frames_max: 0,
            too_big: 0,
            sched: None,
            guard: Guard::default(),
            tun: None,
            port: 0,
            dgrams: 0,
        }
    }

    /// A member of the QUIC wire, with no tunnel yet (h3.rs opens it),
    /// whose datagrams hold at most frames_max bytes of frames.
    pub fn plain(key: &[u8; 32], frames_max: usize) -> Member {
        let mut m = Member::new(None, key);
        m.plain = true;
        m.frames_max = frames_max;
        m.sched = Some(Box::new(Sched::new()));
        m.guard = Guard::over_a_sender();
        m
    }

    /// A tunnel up or opening: the member starts over with its hello on it.
    /// The one it had goes off the loop (its end waits for cronet's thread).
    pub fn set_tunnel(&mut self, t: Option<Tunnel>, port: u16) {
        self.set_sock(None);
        if let Some(old) = std::mem::replace(&mut self.tun, t) {
            hikkari_cronet::let_go(old);
        }
        self.fd = self.tun.as_ref().map_or(-1, |t| t.fd());
        self.port = port;
        self.guard = Guard::over_a_sender();
    }

    /// One frame of class c (written by `put` at most `need` bytes): on the
    /// QUIC wire into the scheduler, a frame over frames_max dropped and
    /// counted; on the bare UDP wire into the glue.
    #[inline]
    pub fn frame(&mut self, c: Class, need: usize, max: usize, now: u64, put: impl FnOnce(&mut [u8]) -> usize) {
        let fits = need <= self.frames_max;
        match &mut self.sched {
            Some(s) if fits => s.put(c, need, now, put),
            Some(_) => self.too_big += 1,
            None => self.glue_frame(need, max, now, put),
        }
    }

    /// Sends what waits now: the QUIC wire's scheduler drained under its
    /// guard, the bare UDP wire's glue sealed; then the batch.
    #[inline]
    pub fn send_now(&mut self, now: u64) {
        if self.sched.is_some() {
            self.drain(now);
        } else {
            self.seal_glue();
        }
        self.flush_out();
    }

    /// Frames waiting in the QUIC wire's scheduler.
    #[inline]
    pub fn queued(&self) -> usize {
        self.sched.as_ref().map_or(0, |s| s.queued())
    }

    /// The QUIC wire's datagrams of what waits, each begun only while the
    /// guard lets one go, into the out slots; the guard judges the half
    /// second gone first, from the tunnel's counts (Chromium's: bytes and
    /// packets sent, packets lost, the smoothed round trip).
    pub fn drain(&mut self, now: u64) {
        let Member { sched, guard, tun, out, out_n, send, fd, dgrams, glue, frames_max, .. } = self;
        let Some(sched) = sched else { return };
        if guard.due(now) {
            if let Some(t) = tun {
                let c = t.counts();
                guard.judge(now, snap(&c), c.srtt_ns);
            }
        }
        if sched.queued() == 0 || *fd < 0 {
            return;
        }
        let fd = *fd;
        sched.drain(now, *frames_max, &mut glue[..], 0, guard, PACKET_OVER, |b, at, len| {
            if *out_n == BATCH {
                send.flush(fd);
                *out_n = 0;
            }
            let slot = &mut out[*out_n * SLOT..(*out_n + 1) * SLOT];
            slot[..len].copy_from_slice(&b[at..at + len]);
            send.push(slot.as_ptr(), len, None);
            *out_n += 1;
            *dgrams += 1;
            true
        });
    }

    /// Whether the member may say its hello: its socket is there and, on the
    /// QUIC wire, its tunnel is up (a datagram before that waits in the pair
    /// and goes out late, as a burst).
    pub fn can_send(&self) -> bool {
        self.fd >= 0 && self.tun.as_ref().is_none_or(|t| t.state() == hikkari_cronet::State::Up)
    }

    /// The frames of a datagram read from the exit, where they are in d:
    /// opened under the seal, or as they are on the QUIC wire; None for one
    /// that does not open.
    #[inline]
    pub fn open(&mut self, d: &mut [u8]) -> Option<(usize, usize)> {
        if self.plain {
            return Some((0, d.len()));
        }
        self.seal.open(d).map(|n| (12, n))
    }

    /// Seals frames written at b[12..12 + n]: where the datagram is in b.
    #[inline]
    pub fn seal_in(&mut self, b: &mut [u8], n: usize) -> (usize, usize) {
        if self.plain {
            return (12, n);
        }
        (0, self.seal.seal(b, n))
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

/// Chromium's counts as the guard reads them: lost bytes are its lost
/// packets at the connection's mean packet (Chromium counts packets lost,
/// not bytes), and what was not lost was delivered.
fn snap(c: &hikkari_cronet::Counts) -> Snap {
    let lost_bytes = if c.packets_sent == 0 { 0 } else { (c.packets_lost as u128 * c.bytes_sent as u128 / c.packets_sent as u128) as u64 };
    Snap { sent_bytes: c.bytes_sent, lost_bytes, acked_bytes: c.bytes_sent - lost_bytes.min(c.bytes_sent), sent: c.packets_sent }
}

impl Drop for Member {
    fn drop(&mut self) {
        if let Some(t) = self.tun.take() {
            hikkari_cronet::let_go(t);
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
    /// The session its members join (the pipe's session.rs): a wire has
    /// members in each session the pipe has, one Wire per session.
    pub sess: u8,
    pub glue_ns: u64,
    pub glue_max: usize,
    /// Its members' stall (trunk Config.Stall): the brain's dead_ms.
    pub stall_ns: u64,
    pub key: [u8; 32],
    pub members: Vec<Member>,
    /// Where a member's new socket goes: without a brain the flag's, under
    /// one the address the brain's sockets are connected to (the members of
    /// a new session are the pipe's own, session.rs).
    pub exit: Option<SocketAddrV4>,
    /// When one of its members last proved its round trip (0: never).
    pub proof: u64,
    /// The Chromium QUIC wire: its members are tunnels the pipe opens
    /// itself (h3.rs), never the brain's sockets.
    pub h3: bool,
    pub t: WireTick,
}

impl Wire {
    pub fn new(id: u8, key: [u8; 32], stall_ns: u64) -> Wire {
        Wire {
            id,
            sess: 0,
            glue_ns: 0,
            glue_max: 0,
            stall_ns,
            key,
            members: Vec::new(),
            exit: None,
            proof: 0,
            h3: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The QUIC wire's member (spec/trunk.md, `h3dgram`, "How each end
    /// sends"): frames wait in its scheduler and go as one datagram of the
    /// frames as they are, up to its room; one alone over the room is
    /// dropped and counted (Chromium would reset the member's stream on it).
    #[test]
    fn a_quic_members_frames_go_unsealed_up_to_its_room() {
        use std::os::fd::AsRawFd;
        let (ours, theirs) = sys::dgram_pair(1 << 16).unwrap();
        let mut m = Member::plain(&[7; 32], 1194);
        m.fd = ours.as_raw_fd();
        m.frame(Class::Flow(1), 600, 1194, 1, |b| {
            b[..600].fill(1);
            600
        });
        m.frame(Class::Flow(2), 594, 1194, 2, |b| {
            b[..594].fill(2);
            594
        });
        m.frame(Class::Flow(3), 1195, 1194, 3, |_| unreachable!("a frame over the room is not written"));
        assert_eq!((m.queued(), m.too_big, m.glue_n), (2, 1, 0), "two frames wait, nothing in the glue");
        m.send_now(4);
        assert_eq!((m.queued(), m.dgrams), (0, 1));
        let mut b = [0u8; 2048];
        let n = sys::recv_nowait(theirs.as_raw_fd(), &mut b);
        assert_eq!(n, 1194, "one datagram of both frames, no seal around them");
        assert!(b[..600].iter().all(|&x| x == 1) && b[600..1194].iter().all(|&x| x == 2));
        let mut d = [9u8; 40];
        assert_eq!(m.open(&mut d), Some((0, 40)), "what comes down is frames as they are");
        let mut h = [0u8; 64];
        assert_eq!(m.seal_in(&mut h, 30), (12, 30));
        let mut sealed = Member::new(None, &[7; 32]);
        assert_eq!(sealed.seal_in(&mut h, 30), (0, 30 + OVERHEAD), "the bare UDP wire's seal");
    }
}
