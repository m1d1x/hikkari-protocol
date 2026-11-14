//! A packet wire on the exit and the entry's members on it (spec/trunk.md,
//! "Wires"): one socket for every member; on the bare UDP wire
//! (trunk/udpwire Listener) a member per entry address, on the Chromium
//! QUIC wire (h3wire.rs) a member per QUIC connection's CONNECT-UDP; each
//! joined to its session by its hello. Each member has
//! its health (hikkari_trunk::health, judged by the exit as by the entry)
//! and its glue: the frames bound for it in one tick sealed into one
//! datagram, which the Go exit does not do (trunk session.go writePackets:
//! every frame in a datagram of its own). The entry's packet members read a
//! frame sequence per datagram, so the glue changes nothing for them but
//! the count of datagrams. On the QUIC wire a member's frames go into its
//! connection's scheduler instead (h3wire.rs, sched.rs), which glues them
//! into datagrams as the guard lets them go.

use std::net::UdpSocket;
use std::os::fd::AsRawFd;

use hikkari_sys::{self as sys, sockaddr_in, SendBatch, BATCH};
use hikkari_trunk::health::Health;
use hikkari_trunk::udpwire::{Seal, OVERHEAD};

use crate::h3wire::H3Wire;
pub use crate::sched::Class;

/// The largest datagram on the wire (udpwire MaxDatagram, the IPv4 UDP
/// payload limit): a wire's receive and send slots hold one each.
pub const SLOT: usize = 65507;

/// No index: a member not in a session, a flow's member not known.
pub const NONE: usize = usize::MAX;

/// A packet wire's own form: the bare UDP wire's socket and seal, or the
/// Chromium QUIC wire's connections (h3wire.rs).
pub enum Form {
    Udp(Udp),
    H3(Box<H3Wire>),
}

/// The bare UDP wire: its socket, the keys a member's first datagram may
/// open under, and the sealed datagrams waiting for one sendmmsg to their
/// addresses.
pub struct Udp {
    sock: UdpSocket,
    pub keys: Vec<[u8; 32]>,
    /// One opener per key: opening takes no nonce of its own.
    pub openers: Vec<Seal>,
    out: Vec<u8>,
    out_n: usize,
    pub send: SendBatch,
}

/// One packet wire: its form, its members' stall and the session's Quiet,
/// its glue.
pub struct Wire {
    pub id: u8,
    pub form: Form,
    pub stall_ns: u64,
    pub quiet_ns: u64,
    pub glue_ns: u64,
    pub glue_max: usize,
    /// Frames glued and datagrams sent since the wire came: frames per
    /// datagram is the glue down (the QUIC wire's datagrams are its
    /// connections', sent()). Dropped: frames no datagram of the member
    /// held.
    pub frames: u64,
    pub dgrams: u64,
    pub dropped: u64,
}

impl Wire {
    /// A bare UDP wire on `sock` under the wire keys `keys`.
    pub fn udp(id: u8, sock: UdpSocket, keys: Vec<[u8; 32]>, stall_ns: u64, quiet_ns: u64, glue_ns: u64, glue_max: usize) -> Wire {
        let openers = keys.iter().map(|k| Seal::from_key(k, [0; 4])).collect();
        let u = Udp { sock, keys, openers, out: vec![0; SLOT * BATCH], out_n: 0, send: SendBatch::new() };
        Wire::of(id, Form::Udp(u), stall_ns, quiet_ns, glue_ns, glue_max.clamp(OVERHEAD + 64, SLOT))
    }

    /// A Chromium QUIC wire.
    pub fn h3dgram(id: u8, h: H3Wire, stall_ns: u64, quiet_ns: u64, glue_ns: u64, glue_max: usize) -> Wire {
        Wire::of(id, Form::H3(Box::new(h)), stall_ns, quiet_ns, glue_ns, glue_max.max(64))
    }

    fn of(id: u8, form: Form, stall_ns: u64, quiet_ns: u64, glue_ns: u64, glue_max: usize) -> Wire {
        Wire { id, form, stall_ns, quiet_ns, glue_ns, glue_max, frames: 0, dgrams: 0, dropped: 0 }
    }

    #[inline]
    pub fn fd(&self) -> i32 {
        match &self.form {
            Form::Udp(u) => u.sock.as_raw_fd(),
            Form::H3(h) => h.fd(),
        }
    }

    /// The Chromium QUIC wire's connections, if this is one.
    #[inline]
    pub fn h3(&mut self) -> Option<&mut H3Wire> {
        match &mut self.form {
            Form::H3(h) => Some(h),
            Form::Udp(_) => None,
        }
    }

    /// Datagrams sent down since the wire came (on the QUIC wire, those its
    /// connections took).
    pub fn sent(&self) -> u64 {
        match &self.form {
            Form::Udp(_) => self.dgrams,
            Form::H3(h) => h.n.dgrams,
        }
    }

    /// Datagrams the socket refused (a full buffer) and sendmmsg calls.
    pub fn socket_counts(&self) -> (u64, u64) {
        let s = match &self.form {
            Form::Udp(u) => &u.send,
            Form::H3(h) => &h.send,
        };
        (s.dropped, s.calls)
    }

    /// Sends every datagram waiting (on the QUIC wire, what its
    /// connections have to send, and their timers from `now`).
    pub fn flush(&mut self, now: u64) {
        match &mut self.form {
            Form::Udp(u) => {
                if u.out_n > 0 {
                    u.send.flush(u.sock.as_raw_fd());
                    u.out_n = 0;
                }
            }
            Form::H3(h) => h.flush(now),
        }
    }

    /// p's glued frames into one datagram sealed into the next out slot to
    /// its address; on the QUIC wire, what waits in its scheduler goes as
    /// HTTP Datagrams of its request.
    pub fn seal(&mut self, p: &mut Peer, now: u64) {
        if p.glue_since == 0 {
            return;
        }
        let sent = match &mut self.form {
            Form::H3(h) => {
                h.drain(p.conn, p.stream, now);
                p.glue_since = 0;
                return;
            }
            Form::Udp(u) => {
                if u.out_n == BATCH {
                    u.send.flush(u.sock.as_raw_fd());
                    u.out_n = 0;
                }
                let slot = &mut u.out[u.out_n * SLOT..(u.out_n + 1) * SLOT];
                slot[12..12 + p.glue_n].copy_from_slice(&p.glue[12..12 + p.glue_n]);
                let n = p.seal.seal(slot, p.glue_n);
                u.send.push(slot.as_ptr(), n, Some(&p.addr));
                u.out_n += 1;
                true
            }
        };
        if sent {
            self.dgrams += 1;
        } else {
            self.dropped += 1;
        }
        p.glue_n = 0;
        p.glue_since = 0;
    }

    /// The frames one datagram of p holds at most, and the glue's window
    /// (both in frame bytes).
    #[inline]
    fn room(&self, p: &Peer) -> (usize, usize) {
        match &self.form {
            Form::Udp(_) => (SLOT - OVERHEAD, self.glue_max - OVERHEAD),
            Form::H3(h) => {
                let r = h.room(p.conn, p.stream);
                (r, r.min(self.glue_max))
            }
        }
    }

    /// Puts one frame of `need` bytes of class c (written by `put`) into p's
    /// glue, sealing first what is there when it would not fit; a frame
    /// alone over the window's size goes alone. On the QUIC wire it goes
    /// into p's scheduler. False for a frame no datagram holds: dropped, as
    /// udpwire drops a write over MaxDatagram.
    #[inline]
    pub fn glue(&mut self, p: &mut Peer, c: Class, need: usize, now: u64, put: impl FnOnce(&mut [u8]) -> usize) -> bool {
        let (most, window) = self.room(p);
        if need > most {
            self.dropped += 1;
            return false;
        }
        if let Form::H3(h) = &mut self.form {
            h.put(p.conn, p.stream, c, need, now, put);
            self.frames += 1;
            if p.glue_since == 0 {
                p.glue_since = now;
            }
            return true;
        }
        if p.glue_n > 0 && p.glue_n + need > window {
            self.seal(p, now);
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
        self.seal(p, now);
        self.glue(p, Class::Alone, need, now, put);
        self.seal(p, now);
    }
}

/// One entry address on the UDP wire, or one CONNECT-UDP request on the
/// QUIC wire: a member once its hello is answered.
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
    /// The UDP wire's: its seal, and its address above. The QUIC wire's:
    /// its connection and request stream (NONE on the UDP wire).
    pub seal: Seal,
    pub conn: usize,
    pub stream: u64,
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
            conn: NONE,
            stream: 0,
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
        self.addr = addr;
        self.key = sys::addr_key(&addr);
        self.seal = Seal::from_key(key, prefix);
        self.conn = NONE;
        self.reset(wire, now);
    }

    /// The slot taken by the CONNECT-UDP of request `stream` on QUIC
    /// connection `conn` of `wire`: the connection is its address.
    pub fn take_request(&mut self, wire: usize, conn: usize, stream: u64, now: u64) {
        self.addr = sys::sockaddr("0.0.0.0:0".parse().expect("a literal address"));
        self.key = 0;
        self.conn = conn;
        self.stream = stream;
        self.reset(wire, now);
    }

    fn reset(&mut self, wire: usize, now: u64) {
        self.live = true;
        self.gen = self.gen.wrapping_add(1);
        self.wire = wire;
        self.session = NONE;
        self.wire_id = 0;
        self.flags = 0;
        self.h = Health::new(true);
        self.heard = now;
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
        let mut w = Wire::udp(2, sock, vec![[7; 32]], 0, 0, 0, 100);
        let mut p = Peer::vacant();
        p.take(sys::sockaddr("127.0.0.1:9".parse().unwrap()), 0, &[7; 32], 1);
        assert!(w.glue(&mut p, Class::Flow(1), 30, 5, |b| {
            b[..30].fill(1);
            30
        }));
        assert!(w.glue(&mut p, Class::Flow(1), 30, 6, |b| {
            b[..30].fill(2);
            30
        }));
        assert_eq!((p.glue_n, p.glue_since, w.dgrams), (60, 5, 0));
        assert!(w.glue(&mut p, Class::Flow(1), 30, 7, |b| {
            b[..30].fill(3);
            30
        }));
        assert_eq!((p.glue_n, p.glue_since, w.dgrams, w.frames), (30, 7, 1, 3), "a third frame over 100 bytes sealed the first two");
        let Form::Udp(u) = &mut w.form else { unreachable!("a UDP wire") };
        let first = &mut u.out[..OVERHEAD + 60];
        let n = u.openers[0].open(first).unwrap();
        assert_eq!(n, 60);
        assert!(first[12..42].iter().all(|&b| b == 1) && first[42..72].iter().all(|&b| b == 2));
        assert!(!w.glue(&mut p, Class::Flow(1), SLOT, 8, |_| 0), "a frame no datagram holds");
    }
}
