//! The brain ↔ pipe socket (README.md, «Brain and pipe»): one local
//! SOCK_SEQPACKET socket, one message per datagram, the brain's sockets
//! passed with the message that uses them by SCM_RIGHTS. Integers are
//! little-endian. The Go side is trunk/pipectl (msg.go); both sides hold the
//! same golden bytes in their tests. The socket itself is hikkari_sys::SeqPacket;
//! here are only the messages, so they are tested on any platform.

pub const VERSION: u16 = 2;

// Brain → pipe.
pub const B_HELLO: u8 = 0x01; // ver u16
pub const B_LISTEN: u8 = 0x02; // id u8, class u8, to u16, copies u8; one fd: a bound UDP socket
pub const B_WIRE: u8 = 0x03; // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, key [32]; one fd per member
pub const B_UNWIRE: u8 = 0x04; // id u8
pub const B_ROUTE: u8 = 0x05; // voice u8, bulk u8
pub const B_OPEN: u8 = 0x06; // tag u32, class u8, pin u8, port u16, copies u8
pub const B_DGRAM: u8 = 0x07; // tag u32, payload
pub const B_CLOSE: u8 = 0x08; // tag u32
pub const B_MEMBER: u8 = 0x09; // wire u8, index u8; one fd: the member's new socket

// Pipe → brain.
pub const P_HELLO: u8 = 0x81; // ver u16, pid u32
pub const P_TICK: u8 = 0x82; // see put_tick
pub const P_MEMBER: u8 = 0x83; // wire u8, index u8, up u8, why u8
pub const P_DGRAM: u8 = 0x84; // tag u32, payload
pub const P_ERROR: u8 = 0x85; // text

/// The only wire form so far: the bare UDP wire (trunk/udpwire).
pub const FORM_UDP: u8 = 1;
/// No wire: any member that can carry it (trunk.AnyWire).
pub const ANY_WIRE: u8 = 255;
/// A duration the pipe has no value for (no proof yet, no pause yet).
pub const NONE_MS: u32 = u32::MAX;

// Why a member went up or down.
pub const WHY_HELLO: u8 = 1; // the exit answered its hello
pub const WHY_SILENT: u8 = 2; // it owed an answer past its stall (the wire's dead_ms) while another member proved the exit alive
pub const WHY_GONE: u8 = 3; // its socket failed
pub const WHY_QUIET: u8 = 4; // every member silent at once, past Quiet (1 s): the exit or the whole path

/// Most sockets one message may carry: a wire's members.
pub const MAX_FDS: usize = 64;

/// One message from the brain.
pub enum Msg<'a> {
    Hello { ver: u16 },
    Listen { id: u8, class: u8, to: u16, copies: u8 },
    Wire { id: u8, form: u8, glue_us: u32, glue_max: u16, dead_ms: u16, key: [u8; 32] },
    Unwire { id: u8 },
    Route { voice: u8, bulk: u8 },
    Open { tag: u32, class: u8, pin: u8, port: u16, copies: u8 },
    Dgram { tag: u32, payload: &'a [u8] },
    Close { tag: u32 },
    Member { wire: u8, index: u8 },
}

struct Rd<'a> {
    p: &'a [u8],
    at: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let b = self.p.get(self.at..self.at + n)?;
        self.at += n;
        Some(b)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn rest(&mut self) -> &'a [u8] {
        let b = &self.p[self.at..];
        self.at = self.p.len();
        b
    }
}

/// Reads one message from the brain; None for one torn or unknown.
pub fn parse(m: &[u8]) -> Option<Msg<'_>> {
    let mut r = Rd { p: m, at: 1 };
    Some(match *m.first()? {
        B_HELLO => Msg::Hello { ver: r.u16()? },
        B_LISTEN => Msg::Listen { id: r.u8()?, class: r.u8()?, to: r.u16()?, copies: r.u8()? },
        B_WIRE => Msg::Wire {
            id: r.u8()?,
            form: r.u8()?,
            glue_us: r.u32()?,
            glue_max: r.u16()?,
            dead_ms: r.u16()?,
            key: r.take(32)?.try_into().ok()?,
        },
        B_UNWIRE => Msg::Unwire { id: r.u8()? },
        B_ROUTE => Msg::Route { voice: r.u8()?, bulk: r.u8()? },
        B_OPEN => Msg::Open { tag: r.u32()?, class: r.u8()?, pin: r.u8()?, port: r.u16()?, copies: r.u8()? },
        B_DGRAM => Msg::Dgram { tag: r.u32()?, payload: r.rest() },
        B_CLOSE => Msg::Close { tag: r.u32()? },
        B_MEMBER => Msg::Member { wire: r.u8()?, index: r.u8()? },
        _ => return None,
    })
}

/// One wire in a tick: what the brain's selector reads (trunk.WireState)
/// and the wire's counters since the pipe started.
#[derive(Clone, Copy, Default)]
pub struct WireTick {
    pub id: u8,
    pub members: u8,
    pub up: u8,
    /// The least of its up members' debts: how long they have owed an
    /// answer to a ping and had none (trunk.WireState.Owed).
    pub owed_ms: u32,
    /// How long ago one of its members last heard the exit; NONE_MS before
    /// the first (trunk.WireState.Proof).
    pub proof_ago_ms: u32,
    /// The latest ping's round trip, least over its members; 0 unknown.
    pub rtt_us: u32,
    pub up_pkts: u64,
    pub up_bytes: u64,
    pub down_pkts: u64,
    pub down_bytes: u64,
    /// Sealed datagrams sent: up_pkts / dgrams is the glue.
    pub dgrams: u64,
    pub dropped: u64,
}

/// The pipe's own part of a tick.
#[derive(Clone, Copy, Default)]
pub struct PipeTick {
    /// How long ago the pipe came back from its latest pause (a turn of its
    /// loop more than 100 ms after the one before, as trunk's lateTick); NONE_MS for none.
    pub pause_ago_ms: u32,
    pub pauses: u32,
    /// The latest turn of the loop past due in the last second, in µs.
    pub late_max_us: u32,
    /// Clients' flows open, the trunk's own calls left out (trunk Stats.Flows).
    pub flows: u32,
    /// Since the pipe started, the trunk's own calls left out (trunk
    /// Stats): datagrams read from clients and the brain's flows
    /// (DgramsOut), delivered (DgramsIn), copies dropped (DgramsCopy).
    pub dgrams_out: u64,
    pub dgrams_in: u64,
    pub dgrams_copy: u64,
    /// Clients' flows ended unused.
    pub flows_idle: u64,
}

pub const TICK_HEAD: usize = 1 + 16 + 32 + 1;
pub const TICK_WIRE: usize = 1 + 1 + 1 + 4 + 4 + 4 + 6 * 8;

/// A tick: the pipe's part, then each wire. out must hold
/// TICK_HEAD + wires.len() * TICK_WIRE.
pub fn put_tick(out: &mut [u8], p: &PipeTick, wires: &[WireTick]) -> usize {
    out[0] = P_TICK;
    out[1..5].copy_from_slice(&p.pause_ago_ms.to_le_bytes());
    out[5..9].copy_from_slice(&p.pauses.to_le_bytes());
    out[9..13].copy_from_slice(&p.late_max_us.to_le_bytes());
    out[13..17].copy_from_slice(&p.flows.to_le_bytes());
    for (i, v) in [p.dgrams_out, p.dgrams_in, p.dgrams_copy, p.flows_idle].iter().enumerate() {
        out[17 + i * 8..25 + i * 8].copy_from_slice(&v.to_le_bytes());
    }
    out[49] = wires.len() as u8;
    let mut at = TICK_HEAD;
    for w in wires {
        let b = &mut out[at..at + TICK_WIRE];
        b[0] = w.id;
        b[1] = w.members;
        b[2] = w.up;
        b[3..7].copy_from_slice(&w.owed_ms.to_le_bytes());
        b[7..11].copy_from_slice(&w.proof_ago_ms.to_le_bytes());
        b[11..15].copy_from_slice(&w.rtt_us.to_le_bytes());
        for (i, v) in [w.up_pkts, w.up_bytes, w.down_pkts, w.down_bytes, w.dgrams, w.dropped].iter().enumerate() {
            b[15 + i * 8..23 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
        at += TICK_WIRE;
    }
    at
}

pub fn put_hello(out: &mut [u8], pid: u32) -> usize {
    out[0] = P_HELLO;
    out[1..3].copy_from_slice(&VERSION.to_le_bytes());
    out[3..7].copy_from_slice(&pid.to_le_bytes());
    7
}

pub fn put_member(out: &mut [u8], wire: u8, index: u8, up: bool, why: u8) -> usize {
    out[..5].copy_from_slice(&[P_MEMBER, wire, index, up as u8, why]);
    5
}

pub fn put_dgram(out: &mut [u8], tag: u32, payload: &[u8]) -> usize {
    out[0] = P_DGRAM;
    out[1..5].copy_from_slice(&tag.to_le_bytes());
    out[5..5 + payload.len()].copy_from_slice(payload);
    5 + payload.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    // The same bytes as trunk/pipectl msg_test.go TestGolden.
    const WIRE_GOLDEN: &str = "030301e8030000b0042c01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const TICK_GOLDEN: &str = "82ffffffff020000003905000007000000080000000000000009000000000000000a000000000000000b0000000000000001020302fa00000064000000b80b0000010000000000000002000000000000000300000000000000040000000000000005000000000000000600000000000000";

    #[test]
    fn parses_the_brains_wire() {
        let m = unhex(WIRE_GOLDEN);
        match parse(&m) {
            Some(Msg::Wire { id, form, glue_us, glue_max, dead_ms, key }) => {
                assert_eq!((id, form, glue_us, glue_max, dead_ms), (3, FORM_UDP, 1000, 1200, 300));
                assert_eq!(key[31], 31);
            }
            _ => panic!("not a wire"),
        }
        assert!(parse(&m[..m.len() - 1]).is_none());
        assert!(parse(&[0x7f]).is_none());
        match parse(&[B_DGRAM, 7, 0, 0, 0, b'h', b'i']) {
            Some(Msg::Dgram { tag: 7, payload }) => assert_eq!(payload, b"hi"),
            _ => panic!("not a dgram"),
        }
    }

    #[test]
    fn puts_the_tick_the_brain_reads() {
        let p = PipeTick {
            pause_ago_ms: NONE_MS,
            pauses: 2,
            late_max_us: 1337,
            flows: 7,
            dgrams_out: 8,
            dgrams_in: 9,
            dgrams_copy: 10,
            flows_idle: 11,
        };
        let w = WireTick {
            id: 2,
            members: 3,
            up: 2,
            owed_ms: 250,
            proof_ago_ms: 100,
            rtt_us: 3000,
            up_pkts: 1,
            up_bytes: 2,
            down_pkts: 3,
            down_bytes: 4,
            dgrams: 5,
            dropped: 6,
        };
        let mut b = [0u8; 256];
        let n = put_tick(&mut b, &p, &[w]);
        assert_eq!(n, TICK_HEAD + TICK_WIRE);
        assert_eq!(&b[..n], &unhex(TICK_GOLDEN)[..]);
    }
}
