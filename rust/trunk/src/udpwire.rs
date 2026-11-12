//! The bare UDP wire's seal (trunk/udpwire): AES-256-GCM in place over a
//! datagram's frames.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

/// What the seal adds: a 12-byte nonce and a 16-byte tag.
pub const OVERHEAD: usize = 12 + 16;

/// The wire's key for a trunk key: HKDF-SHA256(trunk key, "hikkari trunk
/// udp wire"), as udpwire.Key.
pub fn key(trunk_key: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, trunk_key.as_bytes());
    let mut k = [0u8; 32];
    hk.expand(b"hikkari trunk udp wire", &mut k).expect("hkdf 32");
    k
}

/// The wire's cipher: AES-256-GCM under HKDF-SHA256(trunk key, "hikkari
/// trunk udp wire"), as trunk/udpwire. The nonce is a random prefix and a
/// counter, not 12 random bytes per datagram as udpwire draws: unique per
/// key all the same, and no read of the random source per packet.
pub struct Seal {
    aead: Aes256Gcm,
    prefix: [u8; 4],
    ctr: u64,
}

impl Seal {
    pub fn new(trunk_key: &str, prefix: [u8; 4]) -> Seal {
        Seal::from_key(&key(trunk_key), prefix)
    }

    /// The seal under the wire's key itself (key), as the brain hands it.
    pub fn from_key(k: &[u8; 32], prefix: [u8; 4]) -> Seal {
        Seal { aead: Aes256Gcm::new_from_slice(k).expect("key"), prefix, ctr: 0 }
    }

    /// Seals in place: `buf[12..12 + n]` holds the plaintext; writes the
    /// nonce before it and the tag after it, and returns the datagram's size.
    #[inline]
    pub fn seal(&mut self, buf: &mut [u8], n: usize) -> usize {
        self.ctr += 1;
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
        let mut s = Seal::new("k", [1, 2, 3, 4]);
        let mut b = [0u8; 64];
        b[12..17].copy_from_slice(b"hello");
        let n = s.seal(&mut b, 5);
        assert_eq!(n, 5 + OVERHEAD);
        let m = s.open(&mut b[..n]).unwrap();
        assert_eq!(&b[12..12 + m], b"hello");
        b[20] ^= 1;
        assert!(s.open(&mut b[..n]).is_none());
    }
}
