//! The trunk's frames (spec/trunk.md) and the bare UDP wire's seal
//! (trunk/udpwire): what the pipe writes and reads, without allocation.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

pub const F_HELLO: u8 = 1;
pub const F_OPEN: u8 = 2;
pub const F_DATA: u8 = 3;
pub const F_ACK: u8 = 4;
pub const F_FIN: u8 = 5;
pub const F_RST: u8 = 6;
pub const F_DGRAM: u8 = 7;
pub const F_PING: u8 = 8;
pub const F_PONG: u8 = 9;
pub const F_DRAIN: u8 = 10;
pub const F_OBSERVE: u8 = 11;

/// A dgram frame's head: type, stream u32, seq u32, port u16, n u16.
pub const DGRAM_HEAD: usize = 13;
/// The port of the exit's echo (trunk.EchoPort): no loopback service has it,
/// so a dgram to it is the trunk's own call or the bench's users, sent back.
pub const ECHO_PORT: u16 = 0;
/// What the seal adds: a 12-byte nonce and a 16-byte tag.
pub const OVERHEAD: usize = 12 + 16;

/// The exit's answer to a hello: the same session id, the exit session's
/// epoch, and for a t2 hello the same wire and flags.
pub fn put_hello(out: &mut [u8], session: &[u8], epoch: &[u8; 8], t2: Option<(u8, u8)>) -> usize {
    out[0] = F_HELLO;
    out[1..5].copy_from_slice(if t2.is_some() { b"HKT2" } else { b"HKT1" });
    out[5..21].copy_from_slice(&session[..16]);
    out[21..29].copy_from_slice(epoch);
    match t2 {
        Some((wire, flags)) => {
            out[29] = wire;
            out[30] = flags;
            31
        }
        None => 29,
    }
}

/// A t2 hello of a packet member of `wire` (flags: packet, no streams).
pub fn hello_t2(out: &mut [u8], session: &[u8; 16], wire: u8) -> usize {
    out[0] = F_HELLO;
    out[1..5].copy_from_slice(b"HKT2");
    out[5..21].copy_from_slice(session);
    out[21..29].fill(0); // the entry has no epoch; byte 0 is its capabilities (none)
    out[29] = wire;
    out[30] = 2; // kindPacket
    31
}

#[inline]
pub fn put_dgram(out: &mut [u8], stream: u32, seq: u32, port: u16, payload: &[u8]) -> usize {
    out[0] = F_DGRAM;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..9].copy_from_slice(&seq.to_be_bytes());
    out[9..11].copy_from_slice(&port.to_be_bytes());
    out[11..13].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[13..13 + payload.len()].copy_from_slice(payload);
    13 + payload.len()
}

#[inline]
pub fn put_ping(out: &mut [u8], typ: u8, token: u64) -> usize {
    out[0] = typ;
    out[1..9].copy_from_slice(&token.to_be_bytes());
    9
}

/// One frame read from a datagram's plaintext.
pub enum Frame {
    /// A hello: its session id at `at..at + 16`, then the epoch [8]; a t2
    /// one has the wire and its flags after the epoch.
    Hello { at: usize, t2: bool },
    /// A dgram: its stream, its sender's sequence (the receiver drops copies
    /// by it), the destination port (0 is the exit's echo), and the payload
    /// at `off..off + len`.
    Dgram { stream: u32, seq: u32, port: u16, off: usize, len: usize },
    Ping(u64),
    Pong(u64),
    Drain,
    Other,
}

/// Reads the frame at `p[at..]`: the frame and where the next one starts,
/// or None for a torn or unknown frame (the rest of the datagram is dropped).
#[inline]
pub fn next_frame(p: &[u8], at: usize) -> Option<(Frame, usize)> {
    let typ = *p.get(at)?;
    let rest = p.len() - at - 1;
    let b = at + 1;
    let be32 = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
    let be64 = |i: usize| u64::from_be_bytes(p[i..i + 8].try_into().unwrap());
    let fixed = |n: usize| if rest >= n { Some(b + n) } else { None };
    match typ {
        F_HELLO => {
            if rest < 28 {
                return None;
            }
            let t2 = &p[b..b + 4] == b"HKT2";
            if !t2 && &p[b..b + 4] != b"HKT1" {
                return None;
            }
            let n = if t2 { 30 } else { 28 };
            Some((Frame::Hello { at: b + 4, t2 }, fixed(n)?))
        }
        F_DGRAM => {
            if rest < 12 {
                return None;
            }
            let n = u16::from_be_bytes([p[b + 10], p[b + 11]]) as usize;
            if rest < 12 + n {
                return None;
            }
            let seq = be32(b + 4);
            let port = u16::from_be_bytes([p[b + 8], p[b + 9]]);
            Some((Frame::Dgram { stream: be32(b), seq, port, off: b + 12, len: n }, b + 12 + n))
        }
        F_PING => Some((Frame::Ping(be64(fixed(8)? - 8)), b + 8)),
        F_PONG => Some((Frame::Pong(be64(fixed(8)? - 8)), b + 8)),
        F_DRAIN => Some((Frame::Drain, b)),
        F_OPEN => Some((Frame::Other, fixed(6)?)),
        F_ACK => Some((Frame::Other, fixed(29)?)),
        F_FIN => Some((Frame::Other, fixed(12)?)),
        F_RST => Some((Frame::Other, fixed(4)?)),
        F_OBSERVE => Some((Frame::Other, fixed(13)?)),
        F_DATA => {
            if rest < 14 {
                return None;
            }
            let n = u16::from_be_bytes([p[b + 12], p[b + 13]]) as usize;
            Some((Frame::Other, fixed(14 + n)?))
        }
        _ => None,
    }
}

/// Drops copies: a sliding window of the last 1024 sequence numbers, as
/// trunk.replay (trunk/flows.go). A packet member sends each datagram once,
/// so a repeat is a copy from another member or a replayed recording; seq 0
/// is always a copy (an unseqd datagram). The exit dedups a flow this way
/// before it echoes or relays.
#[derive(Default)]
pub struct Replay {
    top: u32,
    bits: [u64; 16],
}

impl Replay {
    /// Whether `seq` was seen before (so it is a copy and must be dropped).
    pub fn seen(&mut self, seq: u32) -> bool {
        const SIZE: u32 = 1024;
        if seq == 0 {
            return true;
        }
        if seq > self.top {
            let shift = seq - self.top;
            if shift >= SIZE {
                self.bits = [0; 16];
            } else {
                let mut i = self.top + 1;
                while i <= seq {
                    self.bits[((i % SIZE) / 64) as usize] &= !(1u64 << (i % 64));
                    i += 1;
                }
            }
            self.top = seq;
        } else if self.top - seq >= SIZE {
            return true; // too old to tell: dropped as a late copy
        }
        let word = ((seq % SIZE) / 64) as usize;
        let bit = 1u64 << (seq % 64);
        if self.bits[word] & bit != 0 {
            return true;
        }
        self.bits[word] |= bit;
        false
    }
}

/// The wire's cipher: AES-256-GCM under HKDF-SHA256(trunk key, "hikkari
/// trunk udp wire"), as trunk/udpwire. The nonce is a random prefix and a
/// counter from a random start, not 12 random bytes per datagram as udpwire
/// draws: every sealer (each member of the entry, each peer of the exit, all
/// under one key) draws its own 12 random bytes once, so two of them meet
/// on a nonce no likelier than udpwire's, and no read of the random source
/// per packet.
pub struct Seal {
    aead: Aes256Gcm,
    prefix: [u8; 4],
    ctr: u64,
}

impl Seal {
    /// The sealer of a trunk key, its nonces from `seed`: 12 random bytes.
    pub fn new(trunk_key: &str, seed: [u8; 12]) -> Seal {
        Seal::with_aead(Seal::aead(trunk_key), seed)
    }

    /// The wire's cipher for a trunk key (derived once, cloned per sealer).
    pub fn aead(trunk_key: &str) -> Aes256Gcm {
        let hk = Hkdf::<Sha256>::new(None, trunk_key.as_bytes());
        let mut k = [0u8; 32];
        hk.expand(b"hikkari trunk udp wire", &mut k).expect("hkdf 32");
        Aes256Gcm::new_from_slice(&k).expect("key")
    }

    pub fn with_aead(aead: Aes256Gcm, seed: [u8; 12]) -> Seal {
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&seed[..4]);
        Seal { aead, prefix, ctr: u64::from_be_bytes(seed[4..].try_into().unwrap()) }
    }

    /// Seals in place: `buf[12..12 + n]` holds the plaintext; writes the
    /// nonce before it and the tag after it, and returns the datagram's size.
    #[inline]
    pub fn seal(&mut self, buf: &mut [u8], n: usize) -> usize {
        self.ctr = self.ctr.wrapping_add(1);
        buf[..4].copy_from_slice(&self.prefix);
        buf[4..12].copy_from_slice(&self.ctr.to_be_bytes());
        let (head, body) = buf.split_at_mut(12);
        let tag = self
            .aead
            .encrypt_in_place_detached(Nonce::from_slice(head), b"", &mut body[..n])
            .expect("seal");
        body[n..n + 16].copy_from_slice(&tag);
        12 + n + 16
    }

    /// Opens a datagram in place; the plaintext is `buf[12..12 + len]`.
    #[inline]
    pub fn open(&self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() < OVERHEAD {
            return None;
        }
        let n = buf.len() - OVERHEAD;
        let (head, body) = buf.split_at_mut(12);
        let (ct, tag) = body.split_at_mut(n);
        self.aead
            .decrypt_in_place_detached(Nonce::from_slice(head), b"", ct, Tag::from_slice(tag))
            .ok()?;
        Some(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_opens() {
        let mut s = Seal::new("k", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let mut b = [0u8; 64];
        b[12..17].copy_from_slice(b"hello");
        let n = s.seal(&mut b, 5);
        assert_eq!(n, 5 + OVERHEAD);
        let m = s.open(&mut b[..n]).unwrap();
        assert_eq!(&b[12..12 + m], b"hello");
        b[20] ^= 1;
        assert!(s.open(&mut b[..n]).is_none());
    }

    #[test]
    fn frames_in_sequence() {
        let mut b = [0u8; 200];
        let mut n = put_dgram(&mut b, 7, 1, 0, b"abc");
        n += put_ping(&mut b[n..], F_PING, 42);
        n += put_dgram(&mut b[n..], 8, 2, 0, b"");
        let mut at = 0;
        let mut seen = vec![];
        while at < n {
            let (f, next) = next_frame(&b[..n], at).unwrap();
            seen.push(match f {
                Frame::Dgram { stream, len, .. } => format!("d{stream}/{len}"),
                Frame::Ping(t) => format!("p{t}"),
                _ => "?".into(),
            });
            at = next;
        }
        assert_eq!(seen, ["d7/3", "p42", "d8/0"]);
        assert!(next_frame(&b[..5], 0).is_none());
    }

    #[test]
    fn replay_drops_copies() {
        let mut r = Replay::default();
        assert!(r.seen(0), "seq 0 is always a copy");
        assert!(!r.seen(1), "the first of a seq is new");
        assert!(r.seen(1), "the same seq again is a copy");
        for s in 2..=100 {
            assert!(!r.seen(s), "{s} is new");
        }
        assert!(r.seen(50), "a seq within the window is a copy");
        assert!(!r.seen(200), "a jump forward is new");
        assert!(!r.seen(150), "a late one still in the window is new");
        assert!(r.seen(150), "but only once");
        let _ = r.seen(5000);
        assert!(r.seen(200), "too old to tell is dropped as a copy");
        assert!(!r.seen(9000), "far ahead, past the whole window, is new");
    }

    #[test]
    fn hello_answered_in_kind() {
        let sid = [7u8; 16];
        let mut b = [0u8; 64];
        let n = hello_t2(&mut b, &sid, 2);
        let Some((Frame::Hello { at, t2: true }, end)) = next_frame(&b[..n], 0) else { panic!("no t2 hello") };
        assert_eq!((end, &b[at..at + 16]), (n, &sid[..]));
        let mut a = [0u8; 64];
        let m = put_hello(&mut a, &b[at..at + 16], &[9; 8], Some((b[at + 24], b[at + 25])));
        assert_eq!((m, &a[..5], a[29], a[30]), (31, &b"\x01HKT2"[..], 2, 2));
        let k = put_hello(&mut a, &sid, &[9; 8], None);
        let Some((Frame::Hello { t2: false, .. }, end)) = next_frame(&a[..k], 0) else { panic!("no t1 hello") };
        assert_eq!(end, 29);
    }
}
