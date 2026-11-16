//! The Chromium QUIC wire's form (spec/trunk.md, "Wires": `h3dgram`): the
//! token of a CONNECT-UDP request that proves the trunk key, the request's
//! path, and an HTTP Datagram's head (RFC 9297: quarter stream id, then
//! context id 0, both QUIC varints) before the frames of one write.

use hkdf::Hkdf;
use sha2::Sha256;

/// The token's size, raw; it goes in hex.
pub const TOKEN: usize = 32;
/// The longest head an HTTP Datagram of this wire has: a quarter stream id
/// of 8 bytes and the context id of 1.
pub const HEAD_MAX: usize = 9;
/// RFC 9298's default template, before `{host}/{port}/`.
pub const PATH_PREFIX: &str = "/.well-known/masque/udp/";

/// The wire's token for a trunk key: HKDF-SHA256(trunk key, "hikkari trunk
/// h3dgram wire").
pub fn token(trunk_key: &str) -> [u8; TOKEN] {
    let hk = Hkdf::<Sha256>::new(None, trunk_key.as_bytes());
    let mut k = [0u8; TOKEN];
    hk.expand(b"hikkari trunk h3dgram wire", &mut k).expect("hkdf 32");
    k
}

/// The `proxy-authorization` value that carries token `t`.
pub fn authorization(t: &[u8; TOKEN]) -> String {
    let mut s = String::with_capacity(7 + 2 * TOKEN);
    s.push_str("Bearer ");
    for b in t {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The token a `proxy-authorization` value carries, if it is one.
pub fn read_authorization(v: &[u8]) -> Option<[u8; TOKEN]> {
    let hex = v.strip_prefix(b"Bearer ")?;
    if hex.len() != 2 * TOKEN {
        return None;
    }
    let mut t = [0u8; TOKEN];
    for (i, pair) in hex.chunks_exact(2).enumerate() {
        t[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(t)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Whether `t` is one of `known`, every byte of each compared: how long
/// the check takes says nothing of how much of a token was right.
pub fn known(known: &[[u8; TOKEN]], t: &[u8; TOKEN]) -> bool {
    let mut hit = false;
    for k in known {
        let diff = k.iter().zip(t).fold(0u8, |d, (a, b)| d | (a ^ b));
        hit |= diff == 0;
    }
    hit
}

/// Whether a path is the template's `{host}/{port}/` (any target: the
/// exit opens nothing to it).
pub fn connect_udp_path(path: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(PATH_PREFIX.as_bytes()) else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(b"/") else {
        return false;
    };
    let mut parts = rest.split(|&c| c == b'/');
    let (Some(host), Some(port), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !host.is_empty() && !port.is_empty() && port.len() <= 5 && port.iter().all(u8::is_ascii_digit)
}

/// The head's size for request stream `stream`.
#[inline]
pub fn head_len(stream: u64) -> usize {
    varint_len(stream / 4) + 1
}

/// Writes the head for request stream `stream` so that it ends at
/// `out[end]`, where the frames begin, and returns where it starts.
#[inline]
pub fn put_head(out: &mut [u8], end: usize, stream: u64) -> usize {
    let q = stream / 4;
    let n = varint_len(q);
    let at = end - n - 1;
    put_varint(&mut out[at..at + n], q);
    out[end - 1] = 0;
    at
}

/// Reads an HTTP Datagram's head: its request stream and where the frames
/// begin; None for a context id other than 0 or a truncated head.
#[inline]
pub fn read_head(d: &[u8]) -> Option<(u64, usize)> {
    let (q, n) = read_varint(d)?;
    let (ctx, m) = read_varint(&d[n..])?;
    if ctx != 0 {
        return None;
    }
    Some((q * 4, n + m))
}

#[inline]
fn varint_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16383 => 2,
        16384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// RFC 9000, 16: the length's two top bits, then the value big-endian.
#[inline]
fn put_varint(out: &mut [u8], v: u64) {
    let n = out.len();
    let tag = match n {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        _ => 0xc0,
    };
    let be = v.to_be_bytes();
    out.copy_from_slice(&be[8 - n..]);
    out[0] |= tag;
}

#[inline]
fn read_varint(d: &[u8]) -> Option<(u64, usize)> {
    let first = *d.first()?;
    let n = 1usize << (first >> 6);
    let b = d.get(..n)?;
    let mut v = (first & 0x3f) as u64;
    for &x in &b[1..] {
        v = (v << 8) | x as u64;
    }
    Some((v, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The token of the bench's key, golden: the entry's brain (Go) must
    /// derive the same bytes (OpenSSL's `openssl kdf -kdfopt digest:SHA256
    /// -kdfopt key:<trunk key> -kdfopt "info:hikkari trunk h3dgram wire" HKDF`
    /// gives them).
    #[test]
    fn the_token_is_hkdf_of_the_trunk_key() {
        let t = token("bench-trunk-key-0123456789abcdef");
        let a = authorization(&t);
        assert_eq!(a, "Bearer 9b5a7e3dfd075ac568f49f6d67340c6271c816050041def9ae8bfdddf2e036d8");
        assert_eq!(read_authorization(a.as_bytes()), Some(t));
        assert_eq!(&a, &authorization(&token("bench-trunk-key-0123456789abcdef")));
        assert_ne!(t, token("another key"));
        assert!(known(&[token("x"), t], &t));
        assert!(!known(&[token("x")], &t));
        assert_eq!(read_authorization(b"Bearer 00"), None);
        assert_eq!(read_authorization(a.to_uppercase().as_bytes()), None, "upper-case hex is not the token's form");
    }

    #[test]
    fn a_connect_udp_path_names_a_host_and_a_port() {
        assert!(connect_udp_path(b"/.well-known/masque/udp/echo.hikkari.arpa/7/"));
        assert!(connect_udp_path(b"/.well-known/masque/udp/192.0.2.1/443/"));
        assert!(!connect_udp_path(b"/.well-known/masque/udp/echo.hikkari.arpa/7"));
        assert!(!connect_udp_path(b"/.well-known/masque/udp//7/"));
        assert!(!connect_udp_path(b"/.well-known/masque/udp/h/x/"));
        assert!(!connect_udp_path(b"/.well-known/masque/udp/h/7/8/"));
        assert!(!connect_udp_path(b"/index.html"));
    }

    /// The head before the frames, as RFC 9297 puts it: stream 0's is
    /// [0, 0], stream 400's quarter (100) takes two bytes.
    #[test]
    fn a_datagrams_head_reads_back() {
        let mut b = [0xffu8; 16];
        let at = put_head(&mut b, 12, 0);
        assert_eq!((at, &b[at..12]), (10, &[0u8, 0][..]));
        assert_eq!(read_head(&b[at..]), Some((0, 2)));
        let at = put_head(&mut b, 12, 400);
        assert_eq!(&b[at..12], &[0x40, 100, 0]);
        assert_eq!(head_len(400), 3);
        assert_eq!(read_head(&b[at..]), Some((400, 3)));
        let big = 4 * 2_000_000_000u64;
        let at = put_head(&mut b, 12, big);
        assert_eq!((12 - at, read_head(&b[at..])), (HEAD_MAX, Some((big, HEAD_MAX))));
        assert_eq!(read_head(&[0, 1]), None, "context id 1 is not a UDP payload");
        assert_eq!(read_head(&[0x40]), None);
    }
}
