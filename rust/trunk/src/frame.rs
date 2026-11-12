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
}
