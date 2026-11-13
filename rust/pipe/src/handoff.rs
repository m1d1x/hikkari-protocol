//! The messages between two generations of the pipe (spec/trunk.md, "An
//! entry's own process replaced"; the Go entry's mailboxes, trunkentry
//! handoff.go): one local SOCK_SEQPACKET socket the brain made, its ends
//! passed to the old pipe with `drain` and to the new one with `adopt`, one
//! message per datagram.
//!
//! Old → new: `own` (client addresses whose flows the old pipe keeps, as
//! many as fit one message), `all`
//! (the list of them is whole: the new pipe may read the clients' sockets),
//! `free` (the old pipe ended that flow; with the datagram it was handed for
//! it, if any, which the new pipe carries itself). New → old: `dgram` (a
//! client datagram for one of the old pipe's flows). An address is the
//! listened port's id (the brain's, the same in both pipes), the IPv4
//! address as on the wire, the port; integers little-endian.

use std::net::{Ipv4Addr, SocketAddrV4};

pub const OWN: u8 = 0x01;
pub const ALL: u8 = 0x02;
pub const FREE: u8 = 0x03;
pub const DGRAM: u8 = 0x04;

/// An address: listen, IPv4, port.
pub const ADDR: usize = 1 + 4 + 2;
/// The head of a message about one address: kind and the address.
pub const HEAD: usize = 1 + ADDR;
/// Addresses one own carries at most: well inside a message of 64 KiB.
pub const OWN_MAX: usize = 8192;

/// One message from the other generation.
#[derive(Debug, PartialEq)]
pub enum Msg<'a> {
    /// The addresses, ADDR bytes each: read them with `addrs`.
    Own { addrs: &'a [u8] },
    All,
    Free { listen: u8, addr: SocketAddrV4, payload: &'a [u8] },
    Dgram { listen: u8, addr: SocketAddrV4, payload: &'a [u8] },
}

/// Reads one message; None for one torn or unknown.
pub fn parse(m: &[u8]) -> Option<Msg<'_>> {
    let kind = *m.first()?;
    match kind {
        ALL => return (m.len() == 1).then_some(Msg::All),
        OWN => return (m.len() - 1).is_multiple_of(ADDR).then_some(Msg::Own { addrs: &m[1..] }),
        _ => {}
    }
    if m.len() < HEAD {
        return None;
    }
    let (listen, addr) = read_addr(&m[1..HEAD]);
    let payload = &m[HEAD..];
    Some(match kind {
        FREE => Msg::Free { listen, addr, payload },
        DGRAM => Msg::Dgram { listen, addr, payload },
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
        b[0] = 0x7f;
        assert!(parse(&b[..n]).is_none(), "unknown");
        assert!(parse(&[]).is_none());
    }
}
