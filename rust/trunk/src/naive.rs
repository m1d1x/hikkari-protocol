//! A pool member's form inside its CONNECT tunnel (spec/trunk.md, "Member"):
//! the Proxy-Authorization of the trunk key, the `padding` header, and Naive
//! padding of the first 8 writes each way (`u16 length, u8 padding, bytes,
//! zeros`). The reference is cronet-go naive_conn.go (paddingConn) on the
//! entry's side and the exit's relay that strips it; the Go trunk/chromium
//! test's exit (unpad) reads it the same way.
//!
//! No randomness of its own: the caller hands the bytes the padding is made
//! of, so a loop without a generator per call can carry it.

/// Writes and reads each way that carry padding.
pub const PADDED: u8 = 8;

/// The largest record a padded write carries (cronet-go maxPaddingChunkSize).
pub const MAX_RECORD: usize = 65535;

/// Head and tail room a padded write needs around its bytes.
pub const HEAD: usize = 3;
pub const TAIL: usize = 255;

/// The CONNECT authority and Proxy-Authorization user of a member (trunk
/// member.go: Host, User).
pub const HOST: &str = "trunk.hikkari.arpa:443";
pub const USER: &str = "trunk";

/// The writing side: the first PADDED writes as padded records.
#[derive(Default)]
pub struct Pad {
    n: u8,
}

impl Pad {
    /// Puts as much of data as fits into out as one write: a padded record
    /// of `pad` zeros while the first PADDED writes last, the bytes as they
    /// are after. Returns (bytes of data taken, bytes of out written); out
    /// needs HEAD + TAIL bytes of room past the data for a padded record.
    pub fn put(&mut self, data: &[u8], out: &mut [u8], pad: u8) -> (usize, usize) {
        if self.n >= PADDED {
            let k = data.len().min(out.len());
            out[..k].copy_from_slice(&data[..k]);
            return (k, k);
        }
        let pad = pad as usize;
        if out.len() < HEAD + pad + 1 || data.is_empty() {
            return (0, 0);
        }
        let k = data.len().min(MAX_RECORD).min(out.len() - HEAD - pad);
        out[0] = (k >> 8) as u8;
        out[1] = k as u8;
        out[2] = pad as u8;
        out[HEAD..HEAD + k].copy_from_slice(&data[..k]);
        out[HEAD + k..HEAD + k + pad].fill(0);
        self.n += 1;
        (k, HEAD + k + pad)
    }

    /// Whether writes still carry padding.
    pub fn padding(&self) -> bool {
        self.n < PADDED
    }

    /// Padded writes made so far.
    pub fn written(&self) -> u8 {
        self.n
    }
}

/// The reading side: the first PADDED records' bytes without their heads
/// and zeros, whatever the reads cut them into.
#[derive(Default)]
pub struct Unpad {
    /// Records begun.
    got: u8,
    /// A record's head read so far.
    head: [u8; HEAD],
    head_n: u8,
    /// Bytes of the current record still to give, then zeros to skip.
    left: usize,
    skip: usize,
}

impl Unpad {
    /// Takes what it can of input into out. Returns (bytes of input taken,
    /// bytes of out written): it stops when either runs out.
    pub fn take(&mut self, input: &[u8], out: &mut [u8]) -> (usize, usize) {
        let (mut i, mut o) = (0, 0);
        while i < input.len() && o < out.len() {
            if self.left > 0 {
                let k = self.left.min(input.len() - i).min(out.len() - o);
                out[o..o + k].copy_from_slice(&input[i..i + k]);
                (i, o, self.left) = (i + k, o + k, self.left - k);
            } else if self.skip > 0 {
                let k = self.skip.min(input.len() - i);
                (i, self.skip) = (i + k, self.skip - k);
            } else if self.got < PADDED {
                self.head[self.head_n as usize] = input[i];
                i += 1;
                self.head_n += 1;
                if self.head_n as usize == HEAD {
                    self.left = (self.head[0] as usize) << 8 | self.head[1] as usize;
                    self.skip = self.head[2] as usize;
                    self.head_n = 0;
                    self.got += 1;
                }
            } else {
                let k = (input.len() - i).min(out.len() - o);
                out[o..o + k].copy_from_slice(&input[i..i + k]);
                (i, o) = (i + k, o + k);
            }
        }
        // Zeros at the very end of the input are skipped now, so a read
        // that ends a record leaves nothing of it behind.
        if self.left == 0 && self.skip > 0 && i < input.len() {
            let k = self.skip.min(input.len() - i);
            (i, self.skip) = (i + k, self.skip - k);
        }
        (i, o)
    }
}

/// The `padding` header's value (cronet-go generatePaddingHeader): 30 to 61
/// characters, the first 16 of them drawn from 16 symbols, `~` after. rnd
/// gives the randomness: rnd[0] the length, rnd[1..9] the symbols.
pub fn padding_header(rnd: &[u8; 9]) -> String {
    const SYMBOLS: &[u8; 16] = b"!#$()+<>?@[]^`{}";
    let len = 30 + (rnd[0] % 32) as usize;
    let mut s = String::with_capacity(len);
    for i in 0..16 {
        let b = rnd[1 + i / 2] >> (4 * (i % 2)) & 15;
        s.push(SYMBOLS[b as usize] as char);
    }
    s.extend(std::iter::repeat_n('~', len - 16));
    s
}

/// `Basic base64("trunk:<key>")`: a member's Proxy-Authorization.
pub fn proxy_authorization(key: &str) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{USER}:{key}");
    let raw = raw.as_bytes();
    let mut s = String::from("Basic ");
    for c in raw.chunks(3) {
        let v = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for j in 0..4 {
            if j <= c.len() {
                s.push(B64[(v >> (18 - 6 * j) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect()
    }

    /// Writes of every size, padded then plain, read back through reads
    /// cut at every size from 1 byte: the bytes come out whole and in order.
    #[test]
    fn padded_writes_read_back_whole_whatever_the_cuts() {
        let data = bytes(300_000, 7);
        let mut pad = Pad::default();
        let mut wire = Vec::new();
        let mut out = vec![0u8; 70_000];
        let (mut at, mut w) = (0, 0usize);
        while at < data.len() {
            let want = [1, 2, 17, 1000, 65535, 70_000][w % 6];
            let end = (at + want).min(data.len());
            let (k, n) = pad.put(&data[at..end], &mut out, (w * 37 % 256) as u8);
            assert!(k > 0, "write {w} took nothing");
            wire.extend_from_slice(&out[..n]);
            at += k;
            w += 1;
        }
        assert!(!pad.padding());
        for cut in [1, 2, 3, 4, 255, 4096, 65536] {
            let mut un = Unpad::default();
            let mut got = Vec::new();
            let mut buf = vec![0u8; 999];
            for piece in wire.chunks(cut) {
                let mut i = 0;
                while i < piece.len() {
                    let (c, o) = un.take(&piece[i..], &mut buf);
                    got.extend_from_slice(&buf[..o]);
                    i += c;
                }
            }
            assert_eq!(got, data, "cut {cut}");
        }
    }

    /// The record's head is Go's: big-endian length, then the padding's
    /// length, then zeros after the bytes.
    #[test]
    fn a_padded_record_is_cronet_gos() {
        let mut pad = Pad::default();
        let mut out = [9u8; 20];
        assert_eq!(pad.put(b"abc", &mut out, 4), (3, 10));
        assert_eq!(&out[..10], &[0, 3, 4, b'a', b'b', b'c', 0, 0, 0, 0]);
    }

    /// A record of no bytes (only zeros) gives nothing and is not lost.
    #[test]
    fn an_empty_record_counts_and_gives_nothing() {
        let mut un = Unpad::default();
        let mut out = [0u8; 8];
        let wire = [0, 0, 2, 0, 0, 0, 1, 0, b'x'];
        assert_eq!(un.take(&wire, &mut out), (9, 1));
        assert_eq!(out[0], b'x');
        assert_eq!(un.got, 2);
    }

    #[test]
    fn the_padding_header_is_cronet_gos_shape() {
        let h = padding_header(&[255, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe]);
        assert_eq!(h.len(), 30 + 31);
        assert_eq!(&h[..16], "!#$()+<>?@[]^`{}");
        assert!(h[16..].bytes().all(|b| b == b'~'));
        assert_eq!(padding_header(&[0; 9]).len(), 30);
    }

    #[test]
    fn the_authorization_is_basic_of_trunk_and_key() {
        // base64("trunk:k") = "dHJ1bms6aw=="
        assert_eq!(proxy_authorization("k"), "Basic dHJ1bms6aw==");
        assert_eq!(proxy_authorization("ke"), "Basic dHJ1bms6a2U=");
        assert_eq!(proxy_authorization("key"), "Basic dHJ1bms6a2V5");
    }
}
