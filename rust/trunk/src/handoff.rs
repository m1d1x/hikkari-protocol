//! The messages between two generations of a pipe, the entry's or the
//! exit's (spec/trunk.md, "An entry's own process replaced", "An exit's own
//! process replaced"; the Go entry's mailboxes, trunkentry handoff.go): one
//! local SOCK_SEQPACKET socket the brain made, its ends passed to the old
//! pipe with `drain` and to the new one with `adopt`, one message per
//! datagram.
//!
//! Old → new: `gen` (the exit's: the generation its QUIC connection ids
//! name, before anything else), `own` (addresses the old pipe keeps: the
//! entry's client addresses of its flows, the exit's entry addresses of its
//! bare UDP wire's members; as many as fit one message), `all` (the list of
//! them is whole: the new pipe may read the shared sockets), `free` (the
//! old pipe let that address go; with the datagram it was handed for it, if
//! any, which the new pipe takes itself). New → old: `dgram` (a datagram
//! from an address, or of a connection, the old pipe keeps).
//!
//! The entry's flows handed over (spec/trunk.md, "An entry's own process
//! replaced"): new → old `ready` (the new pipe's session takes everything
//! new and its exit adopts), old → new `move` (a flow: its address, its
//! session's id, its stream id, port, class, copies and next seq), new →
//! old `taken` (the exit adopted it), old → new `moved` (the old pipe forgot
//! it; the seq it got to, 0 for a flow it had ended). A stream: old → new
//! `smove` with the client's connection (SCM_RIGHTS), its session's id, its
//! stream id, port, `up` and `down`; new → old `staken` (the exit adopted
//! it: the old pipe lets it go) or `skept` (it did not: the old pipe goes
//! on with it). An address is
//! the id of its listened port or wire (the brain's, the same in both
//! pipes), the IPv4 address as on the wire, the port; integers
//! little-endian.

use std::net::{Ipv4Addr, SocketAddrV4};

pub const OWN: u8 = 0x01;
pub const ALL: u8 = 0x02;
pub const FREE: u8 = 0x03;
pub const DGRAM: u8 = 0x04;
pub const GEN: u8 = 0x05;
pub const READY: u8 = 0x06;
pub const MOVE: u8 = 0x07;
pub const TAKEN: u8 = 0x08;
pub const MOVED: u8 = 0x09;
pub const SMOVE: u8 = 0x0a;
pub const STAKEN: u8 = 0x0b;
pub const SKEPT: u8 = 0x0c;
/// An smove: kind, session [16], stream u32, port u16, up u64, down u64.
pub const SMOVE_LEN: usize = 1 + 16 + 4 + 2 + 8 + 8;

/// An address: listen, IPv4, port.
pub const ADDR: usize = 1 + 4 + 2;
/// The head of a message about one address: kind and the address.
pub const HEAD: usize = 1 + ADDR;
/// Addresses one own carries at most: well inside a message of 64 KiB.
pub const OWN_MAX: usize = 8192;
/// A move: the head, session [16], stream u32, port u16, class u8, copies
/// u8, seq u32.
pub const MOVE_LEN: usize = HEAD + 16 + 4 + 2 + 1 + 1 + 4;
/// A moved: the head, seq u32.
pub const MOVED_LEN: usize = HEAD + 4;

/// A stream the old pipe hands over (`smove`); its client's connection
/// comes with the message.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct StreamMoving {
    pub session: [u8; 16],
    pub stream: u32,
    pub port: u16,
    pub up: u64,
    pub down: u64,
}

/// A flow the old pipe hands over (`move`).
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Moving {
    pub listen: u8,
    pub addr: SocketAddrV4,
    pub session: [u8; 16],
    pub stream: u32,
    pub port: u16,
    pub class: u8,
    pub copies: u8,
    pub seq: u32,
}

/// One message from the other generation.
#[derive(Debug, PartialEq)]
pub enum Msg<'a> {
    /// The addresses, ADDR bytes each: read them with `addrs`.
    Own { addrs: &'a [u8] },
    All,
    /// The exit's generation (spec/trunk.md: its connection ids name it).
    Gen { gen: u8 },
    Free { listen: u8, addr: SocketAddrV4, payload: &'a [u8] },
    Dgram { listen: u8, addr: SocketAddrV4, payload: &'a [u8] },
    Ready,
    Move(Moving),
    Taken { listen: u8, addr: SocketAddrV4 },
    Moved { listen: u8, addr: SocketAddrV4, seq: u32 },
    StreamMove(StreamMoving),
    StreamTaken { stream: u32 },
    StreamKept { stream: u32 },
}

/// Reads one message; None for one torn or unknown.
pub fn parse(m: &[u8]) -> Option<Msg<'_>> {
    let kind = *m.first()?;
    match kind {
        ALL => return (m.len() == 1).then_some(Msg::All),
        READY => return (m.len() == 1).then_some(Msg::Ready),
        STAKEN | SKEPT => {
            let stream = u32::from_le_bytes(m.get(1..5)?.try_into().ok()?);
            return (m.len() == 5).then_some(if kind == STAKEN { Msg::StreamTaken { stream } } else { Msg::StreamKept { stream } });
        }
        SMOVE => {
            if m.len() != SMOVE_LEN {
                return None;
            }
            let le64 = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap());
            return Some(Msg::StreamMove(StreamMoving {
                session: m[1..17].try_into().ok()?,
                stream: u32::from_le_bytes(m[17..21].try_into().ok()?),
                port: u16::from_le_bytes([m[21], m[22]]),
                up: le64(&m[23..31]),
                down: le64(&m[31..39]),
            }));
        }
        GEN => return (m.len() == 2).then(|| Msg::Gen { gen: m[1] }),
        OWN => return (m.len() - 1).is_multiple_of(ADDR).then_some(Msg::Own { addrs: &m[1..] }),
        _ => {}
    }
    if m.len() < HEAD {
        return None;
    }
    let (listen, addr) = read_addr(&m[1..HEAD]);
    let payload = &m[HEAD..];
    let le32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    Some(match kind {
        FREE => Msg::Free { listen, addr, payload },
        DGRAM => Msg::Dgram { listen, addr, payload },
        TAKEN if payload.is_empty() => Msg::Taken { listen, addr },
        MOVED if m.len() == MOVED_LEN => Msg::Moved { listen, addr, seq: le32(payload) },
        MOVE if m.len() == MOVE_LEN => Msg::Move(Moving {
            listen,
            addr,
            session: payload[..16].try_into().ok()?,
            stream: le32(&payload[16..20]),
            port: u16::from_le_bytes([payload[20], payload[21]]),
            class: payload[22],
            copies: payload[23],
            seq: le32(&payload[24..28]),
        }),
        _ => return None,
    })
}

/// The addresses of an own.
pub fn addrs(b: &[u8]) -> impl Iterator<Item = (u8, SocketAddrV4)> + '_ {
    b.chunks_exact(ADDR).map(read_addr)
}

fn read_addr(b: &[u8]) -> (u8, SocketAddrV4) {
    (b[0], SocketAddrV4::new(Ipv4Addr::new(b[1], b[2], b[3], b[4]), u16::from_le_bytes([b[5], b[6]])))
}

/// Writes an address into out (at least ADDR bytes).
pub fn put_addr(out: &mut [u8], listen: u8, addr: SocketAddrV4) -> usize {
    out[0] = listen;
    out[1..5].copy_from_slice(&addr.ip().octets());
    out[5..7].copy_from_slice(&addr.port().to_le_bytes());
    ADDR
}

/// Writes the head of a message about one address into out (at least HEAD
/// bytes); the payload, if any, goes right after it.
pub fn put_head(out: &mut [u8], kind: u8, listen: u8, addr: SocketAddrV4) -> usize {
    out[0] = kind;
    1 + put_addr(&mut out[1..], listen, addr)
}

/// Writes a move into out (at least MOVE_LEN bytes).
pub fn put_move(out: &mut [u8], m: &Moving) -> usize {
    let h = put_head(out, MOVE, m.listen, m.addr);
    out[h..h + 16].copy_from_slice(&m.session);
    out[h + 16..h + 20].copy_from_slice(&m.stream.to_le_bytes());
    out[h + 20..h + 22].copy_from_slice(&m.port.to_le_bytes());
    out[h + 22] = m.class;
    out[h + 23] = m.copies;
    out[h + 24..h + 28].copy_from_slice(&m.seq.to_le_bytes());
    MOVE_LEN
}

/// Writes an smove into out (at least SMOVE_LEN bytes).
pub fn put_smove(out: &mut [u8], s: &StreamMoving) -> usize {
    out[0] = SMOVE;
    out[1..17].copy_from_slice(&s.session);
    out[17..21].copy_from_slice(&s.stream.to_le_bytes());
    out[21..23].copy_from_slice(&s.port.to_le_bytes());
    out[23..31].copy_from_slice(&s.up.to_le_bytes());
    out[31..39].copy_from_slice(&s.down.to_le_bytes());
    SMOVE_LEN
}

/// Writes an staken or skept (`kind`) of `stream` into out (5 bytes).
pub fn put_stream_answer(out: &mut [u8], kind: u8, stream: u32) -> usize {
    out[0] = kind;
    out[1..5].copy_from_slice(&stream.to_le_bytes());
    5
}

/// Writes a moved into out (at least MOVED_LEN bytes).
pub fn put_moved(out: &mut [u8], listen: u8, addr: SocketAddrV4, seq: u32) -> usize {
    let h = put_head(out, MOVED, listen, addr);
    out[h..h + 4].copy_from_slice(&seq.to_le_bytes());
    MOVED_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_and_its_datagram_read_back_as_written() {
        let a: SocketAddrV4 = "10.1.2.3:50443".parse().unwrap();
        let mut b = [0u8; 64];
        let n = put_head(&mut b, DGRAM, 7, a);
        b[n..n + 2].copy_from_slice(b"hi");
        assert_eq!(&b[..n], &[DGRAM, 7, 10, 1, 2, 3, 0x0b, 0xc5]);
        assert_eq!(parse(&b[..n + 2]), Some(Msg::Dgram { listen: 7, addr: a, payload: b"hi" }));
        let n = put_head(&mut b, FREE, 7, a);
        assert_eq!(parse(&b[..n]), Some(Msg::Free { listen: 7, addr: a, payload: b"" }), "a free without a datagram");
        b[0] = OWN;
        let n = 1 + put_addr(&mut b[1..], 7, a);
        let n = n + put_addr(&mut b[n..], 2, "10.0.0.9:9".parse().unwrap());
        let Some(Msg::Own { addrs: got }) = parse(&b[..n]) else { panic!("not an own") };
        assert_eq!(addrs(got).collect::<Vec<_>>(), vec![(7, a), (2, "10.0.0.9:9".parse().unwrap())]);
        assert_eq!(parse(&[OWN]), Some(Msg::Own { addrs: b"" }), "an own of no address");
        assert_eq!(parse(&[ALL]), Some(Msg::All));
        assert_eq!(parse(&[GEN, 3]), Some(Msg::Gen { gen: 3 }));
    }

    #[test]
    fn a_torn_or_unknown_message_is_none() {
        let a: SocketAddrV4 = "10.1.2.3:443".parse().unwrap();
        let mut b = [0u8; 16];
        let n = put_head(&mut b, OWN, 0, a);
        assert!(parse(&b[..n - 1]).is_none(), "an own torn");
        let n = put_head(&mut b, DGRAM, 0, a);
        assert!(parse(&b[..n - 1]).is_none(), "a dgram torn");
        assert!(parse(&[ALL, 0]).is_none());
        assert!(parse(&[GEN]).is_none(), "a gen torn");
        b[0] = 0x7f;
        assert!(parse(&b[..n]).is_none(), "unknown");
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn a_flow_handed_over_reads_back_as_written() {
        let a: SocketAddrV4 = "10.1.2.3:50443".parse().unwrap();
        let m = Moving { listen: 3, addr: a, session: [9; 16], stream: 0x0010_0002, port: 2053, class: 1, copies: 2, seq: 77 };
        let mut b = [0u8; 64];
        let n = put_move(&mut b, &m);
        assert_eq!(parse(&b[..n]), Some(Msg::Move(m)));
        assert!(parse(&b[..n - 1]).is_none(), "a move torn");
        let n = put_moved(&mut b, 3, a, 78);
        assert_eq!(parse(&b[..n]), Some(Msg::Moved { listen: 3, addr: a, seq: 78 }));
        let n = put_head(&mut b, TAKEN, 3, a);
        assert_eq!(parse(&b[..n]), Some(Msg::Taken { listen: 3, addr: a }));
        assert_eq!(parse(&[READY]), Some(Msg::Ready));
    }

    #[test]
    fn a_stream_handed_over_reads_back_as_written() {
        let s = StreamMoving { session: [4; 16], stream: 77, port: 443, up: 1 << 33, down: 12345 };
        let mut b = [0u8; 64];
        let n = put_smove(&mut b, &s);
        assert_eq!(parse(&b[..n]), Some(Msg::StreamMove(s)));
        assert!(parse(&b[..n - 1]).is_none(), "an smove torn");
        let n = put_stream_answer(&mut b, STAKEN, 77);
        assert_eq!(parse(&b[..n]), Some(Msg::StreamTaken { stream: 77 }));
        let n = put_stream_answer(&mut b, SKEPT, 78);
        assert_eq!(parse(&b[..n]), Some(Msg::StreamKept { stream: 78 }));
    }
}
