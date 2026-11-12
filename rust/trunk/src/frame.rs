//! The trunk's frames (spec/trunk.md, "Frames"): written into and read out
//! of a caller's buffer, nothing allocated.

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
/// A data frame's head: type, stream u32, offset u64, n u16.
pub const DATA_HEAD: usize = 15;
/// An ack frame: type, stream u32, received u64, credit u64, flags u8, got u64.
pub const ACK_LEN: usize = 30;
/// An ack's flag: the FIN is received.
pub const ACK_FIN: u8 = 1;
/// An ack's got for no chunk in particular (trunk noGot).
pub const NO_GOT: u64 = u64::MAX;

/// A t1 hello (a pool member's: it carries everything), the entry's: its
/// session id and a zero epoch whose first byte is its capabilities (none).
pub fn hello_t1(out: &mut [u8], session: &[u8; 16]) -> usize {
    out[0] = F_HELLO;
    out[1..5].copy_from_slice(b"HKT1");
    out[5..21].copy_from_slice(session);
    out[21..29].fill(0);
    29
}

pub fn put_open(out: &mut [u8], stream: u32, port: u16) -> usize {
    out[0] = F_OPEN;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..7].copy_from_slice(&port.to_be_bytes());
    7
}

/// A data frame's head for n bytes of `stream` at `off`; the n bytes follow
/// it at out[DATA_HEAD..], written there by the caller (read straight from
/// the client's socket).
#[inline]
pub fn put_data_head(out: &mut [u8], stream: u32, off: u64, n: u16) -> usize {
    out[0] = F_DATA;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..13].copy_from_slice(&off.to_be_bytes());
    out[13..15].copy_from_slice(&n.to_be_bytes());
    DATA_HEAD
}

#[inline]
pub fn put_ack(out: &mut [u8], stream: u32, received: u64, credit: u64, flags: u8, got: u64) -> usize {
    out[0] = F_ACK;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..13].copy_from_slice(&received.to_be_bytes());
    out[13..21].copy_from_slice(&credit.to_be_bytes());
    out[21] = flags;
    out[22..30].copy_from_slice(&got.to_be_bytes());
    ACK_LEN
}

pub fn put_fin(out: &mut [u8], stream: u32, off: u64) -> usize {
    out[0] = F_FIN;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..13].copy_from_slice(&off.to_be_bytes());
    13
}

pub fn put_rst(out: &mut [u8], stream: u32) -> usize {
    out[0] = F_RST;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    5
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
    Hello,
    /// A dgram: its flow (stream), its sender's seq (the receiver drops
    /// copies by it, flow::Replay), the exit's port, and the payload at
    /// `off..off + len`.
    Dgram { stream: u32, seq: u32, port: u16, off: usize, len: usize },
    Ping(u64),
    Pong(u64),
    Drain,
    Open { stream: u32, port: u16 },
    /// A chunk of a stream at `off`, its bytes at `at..at + len` of the
    /// datagram or the read buffer.
    Data { stream: u32, off: u64, at: usize, len: usize },
    Ack { stream: u32, received: u64, credit: u64, flags: u8, got: u64 },
    Fin { stream: u32, off: u64 },
    Rst { stream: u32 },
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
            let n = if &p[b..b + 4] == b"HKT2" { 30 } else { 28 };
            Some((Frame::Hello, fixed(n)?))
        }
        F_DGRAM => {
            if rest < 12 {
                return None;
            }
            let n = u16::from_be_bytes([p[b + 10], p[b + 11]]) as usize;
            if rest < 12 + n {
                return None;
            }
            let port = u16::from_be_bytes([p[b + 8], p[b + 9]]);
            Some((Frame::Dgram { stream: be32(b), seq: be32(b + 4), port, off: b + 12, len: n }, b + 12 + n))
        }
        F_PING => Some((Frame::Ping(be64(fixed(8)? - 8)), b + 8)),
        F_PONG => Some((Frame::Pong(be64(fixed(8)? - 8)), b + 8)),
        F_DRAIN => Some((Frame::Drain, b)),
        F_OPEN => {
            let next = fixed(6)?;
            Some((Frame::Open { stream: be32(b), port: u16::from_be_bytes([p[b + 4], p[b + 5]]) }, next))
        }
        F_ACK => {
            let next = fixed(29)?;
            let f = Frame::Ack { stream: be32(b), received: be64(b + 4), credit: be64(b + 12), flags: p[b + 20], got: be64(b + 21) };
            Some((f, next))
        }
        F_FIN => {
            let next = fixed(12)?;
            Some((Frame::Fin { stream: be32(b), off: be64(b + 4) }, next))
        }
        F_RST => {
            let next = fixed(4)?;
            Some((Frame::Rst { stream: be32(b) }, next))
        }
        F_OBSERVE => Some((Frame::Other, fixed(13)?)),
        F_DATA => {
            if rest < 14 {
                return None;
            }
            let n = u16::from_be_bytes([p[b + 12], p[b + 13]]) as usize;
            let next = fixed(14 + n)?;
            Some((Frame::Data { stream: be32(b), off: be64(b + 4), at: b + 14, len: n }, next))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_in_sequence() {
        let mut b = [0u8; 200];
        let mut n = put_dgram(&mut b, 7, 1, 443, b"abc");
        n += put_ping(&mut b[n..], F_PING, 42);
        n += put_dgram(&mut b[n..], 8, 0x0102_0304, 0, b"");
        let mut at = 0;
        let mut seen = vec![];
        while at < n {
            let (f, next) = next_frame(&b[..n], at).unwrap();
            seen.push(match f {
                Frame::Dgram { stream, seq, port, off, len } => format!("d{stream}/{seq}/{port}/{}", String::from_utf8_lossy(&b[off..off + len])),
                Frame::Ping(t) => format!("p{t}"),
                _ => "?".into(),
            });
            at = next;
        }
        assert_eq!(seen, ["d7/1/443/abc", "p42", "d8/16909060/0/"]);
        assert!(next_frame(&b[..5], 0).is_none());
    }

    /// The bytes of trunk wire.go's appendOpen, appendData, appendAck,
    /// appendFin, appendRst and a t1 hello, read back as frames.
    #[test]
    fn stream_frames_as_go_writes_them() {
        let mut b = [0u8; 256];
        let mut n = hello_t1(&mut b, &[0xab; 16]);
        assert_eq!(&b[..5], b"\x01HKT1");
        n += put_open(&mut b[n..], 5, 9000);
        let h = n;
        n += put_data_head(&mut b[n..], 5, 1 << 40, 3);
        b[n..n + 3].copy_from_slice(b"xyz");
        n += 3;
        n += put_ack(&mut b[n..], 5, 7, 2 << 20, ACK_FIN, NO_GOT);
        n += put_fin(&mut b[n..], 5, 7);
        n += put_rst(&mut b[n..], 5);
        let go_data = [3u8, 0, 0, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'x', b'y', b'z'];
        assert_eq!(&b[h..h + go_data.len()], &go_data);
        let mut at = 0;
        let mut seen = vec![];
        while at < n {
            let (f, next) = next_frame(&b[..n], at).unwrap();
            seen.push(match f {
                Frame::Hello => "hello".into(),
                Frame::Open { stream, port } => format!("open {stream} {port}"),
                Frame::Data { stream, off, at, len } => format!("data {stream} {off} {}", String::from_utf8_lossy(&b[at..at + len])),
                Frame::Ack { stream, received, credit, flags, got } => format!("ack {stream} {received} {credit} {flags} {}", got == NO_GOT),
                Frame::Fin { stream, off } => format!("fin {stream} {off}"),
                Frame::Rst { stream } => format!("rst {stream}"),
                _ => "?".into(),
            });
            at = next;
        }
        assert_eq!(seen, ["hello", "open 5 9000", "data 5 1099511627776 xyz", "ack 5 7 2097152 1 true", "fin 5 7", "rst 5"]);
        assert!(next_frame(&b[h..h + DATA_HEAD + 2], 0).is_none(), "a chunk torn short is no frame");
    }
}
