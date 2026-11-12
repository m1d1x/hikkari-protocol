//! The brain ↔ exit socket (README.md, «The exit»): the same kind of socket
//! as the entry's (one local SOCK_SEQPACKET socket, one message per
//! datagram, sockets passed by SCM_RIGHTS with the message that uses them,
//! integers little-endian), with the exit's own messages. The Go side is
//! trunk/pipectl (exitmsg.go); both sides hold the same golden bytes in their
//! tests. Here are only the messages, so they are tested on any platform.

pub const VERSION: u16 = 2;

// Brain → exit.
pub const B_HELLO: u8 = 0x01; // ver u16
pub const B_WIRE: u8 = 0x03; // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, quiet_ms u32, n u8, keys [32] × n; one fd: the wire's bound socket
pub const B_PORTS: u8 = 0x0a; // n u16, port u16 × n
pub const B_POOL: u8 = 0x0b; // dead_ms u16, quiet_ms u32; one fd: the pool's listening TCP socket

// Exit → brain.
pub const P_HELLO: u8 = 0x81; // ver u16, pid u32
pub const P_TICK: u8 = 0x82; // see put_tick
pub const P_ERROR: u8 = 0x85; // text

/// The only wire form so far: the bare UDP wire (trunk/udpwire).
pub const FORM_UDP: u8 = 1;
/// A duration the exit has no value for (no pause yet).
pub const NONE_MS: u32 = u32::MAX;
/// Most sockets one message may carry: a wire's one, the pool's one.
pub const MAX_FDS: usize = 1;
/// Most trunk keys one wire opens under (the hub's keys of this exit).
pub const MAX_KEYS: usize = 16;

/// One message from the brain.
pub enum Msg<'a> {
    Hello { ver: u16 },
    /// A wire: its socket comes with the message. `keys` holds `n` wire
    /// keys (udpwire.Key of each trunk key: the exit never sees a trunk key).
    Wire { id: u8, form: u8, glue_us: u32, glue_max: u16, dead_ms: u16, quiet_ms: u32, keys: &'a [u8] },
    /// The loopback ports open to the trunk (trunk Local.DialFlow and
    /// DialStream refuse the others); the set replaces the one before.
    Ports { ports: &'a [u8] },
    /// The pool's port: stream members connect to its listening socket,
    /// which comes with the message; their stall and the session's Quiet.
    Pool { dead_ms: u16, quiet_ms: u32 },
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
}

/// Reads one message from the brain; None for one torn or unknown.
pub fn parse(m: &[u8]) -> Option<Msg<'_>> {
    let mut r = Rd { p: m, at: 1 };
    let msg = match *m.first()? {
        B_HELLO => Msg::Hello { ver: r.u16()? },
        B_WIRE => {
            let (id, form, glue_us, glue_max, dead_ms, quiet_ms) = (r.u8()?, r.u8()?, r.u32()?, r.u16()?, r.u16()?, r.u32()?);
            let n = r.u8()? as usize;
            if n == 0 || n > MAX_KEYS {
                return None;
            }
            Msg::Wire { id, form, glue_us, glue_max, dead_ms, quiet_ms, keys: r.take(32 * n)? }
        }
        B_PORTS => {
            let n = r.u16()? as usize;
            Msg::Ports { ports: r.take(2 * n)? }
        }
        B_POOL => Msg::Pool { dead_ms: r.u16()?, quiet_ms: r.u32()? },
        _ => return None,
    };
    if r.at != m.len() {
        return None;
    }
    Some(msg)
}

/// The i-th port of a ports message.
pub fn port_at(ports: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([ports[2 * i], ports[2 * i + 1]])
}

pub fn put_hello(out: &mut [u8], pid: u32) -> usize {
    out[0] = P_HELLO;
    out[1..3].copy_from_slice(&VERSION.to_le_bytes());
    out[3..7].copy_from_slice(&pid.to_le_bytes());
    7
}

pub fn put_error(out: &mut [u8], text: &str) -> usize {
    let n = text.len().min(out.len() - 1);
    out[0] = P_ERROR;
    out[1..1 + n].copy_from_slice(&text.as_bytes()[..n]);
    1 + n
}

/// What the exit tells the brain once a second: itself now, then its
/// counters since it started, as trunk Exit.Stats sums them (the trunk's own
/// call left out of flows and datagrams).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Tick {
    /// How long ago the exit came back from its latest pause of its own (a
    /// turn of its loop more than 100 ms after the one before); NONE_MS for
    /// none yet.
    pub pause_ago_ms: u32,
    pub pauses: u32,
    /// The latest turn of the loop past due in the last second.
    pub late_max_us: u32,
    pub sessions: u32,
    /// Packet members up: entry addresses whose hello was answered and that
    /// are not dead.
    pub members: u32,
    /// The clients' flows open.
    pub flows: u32,
    /// Stream members up, and streams open.
    pub links: u32,
    pub streams: u32,
    /// Members of either kind joined (trunk Stats.MembersJoined); buried by
    /// their stall while another member proved the entry alive, and by Quiet
    /// (both trunk Stats.MembersStall); gone: a packet member's address
    /// forgotten after PeerIdle with nothing from it (udpwire's reap), a
    /// stream member's connection failed or ended (MembersBroken).
    pub joined: u64,
    pub silent: u64,
    pub quiet: u64,
    pub gone: u64,
    /// The clients' datagrams sent to the entry, delivered to the relay,
    /// copies dropped (trunk Stats.DgramsOut, DgramsIn, DgramsCopy).
    pub dgrams_out: u64,
    pub dgrams_in: u64,
    pub dgrams_copy: u64,
    /// Flows ended unused (trunk FlowIdle).
    pub flows_idle: u64,
    /// Datagrams to a port not open to the trunk, dropped (DialFlow's
    /// errTrunkPort), and to a relay that refused them.
    pub refused: u64,
    /// Sealed datagrams opened from the entry, sealed to it, the frames in
    /// those (frames_out / w_out is the glue down).
    pub w_in: u64,
    pub w_out: u64,
    pub frames_out: u64,
    /// Datagrams that opened under no key or were framed wrong.
    pub bad: u64,
    /// Sealed datagrams the wire's socket refused.
    pub dropped: u64,
    /// Streams opened, ended with both FINs, reset by the entry, reset here
    /// (trunk StreamsOpened, StreamsReset is the two resets).
    pub streams_opened: u64,
    pub streams_fin: u64,
    pub reset_peer: u64,
    pub reset_local: u64,
    /// Times a member died carrying a stream's unconfirmed chunks or FIN,
    /// chunks sent again (trunk Resent).
    pub hit: u64,
    pub resent: u64,
    /// Stream bytes read from local ends, written to them (trunk Up, Down).
    pub up: u64,
    pub down: u64,
    /// Chunks and FINs held for streams not open yet, and dropped past the
    /// bounds.
    pub early: u64,
    pub early_dropped: u64,
    /// Opens to a port not open to the trunk or that refused (DialStream's
    /// errors), and datagrams that came on stream members (dropped: R2).
    pub refused_streams: u64,
    pub link_dgrams: u64,
}

const HEADS: usize = 8;
const COUNTERS: usize = 26;
pub const TICK_LEN: usize = 1 + HEADS * 4 + COUNTERS * 8;

impl Tick {
    fn counters(&self) -> [u64; COUNTERS] {
        [
            self.joined,
            self.silent,
            self.quiet,
            self.gone,
            self.dgrams_out,
            self.dgrams_in,
            self.dgrams_copy,
            self.flows_idle,
            self.refused,
            self.w_in,
            self.w_out,
            self.frames_out,
            self.bad,
            self.dropped,
            self.streams_opened,
            self.streams_fin,
            self.reset_peer,
            self.reset_local,
            self.hit,
            self.resent,
            self.up,
            self.down,
            self.early,
            self.early_dropped,
            self.refused_streams,
            self.link_dgrams,
        ]
    }

    pub fn put(&self, out: &mut [u8]) -> usize {
        out[0] = P_TICK;
        let heads: [u32; HEADS] = [self.pause_ago_ms, self.pauses, self.late_max_us, self.sessions, self.members, self.flows, self.links, self.streams];
        for (k, v) in heads.iter().enumerate() {
            out[1 + 4 * k..5 + 4 * k].copy_from_slice(&v.to_le_bytes());
        }
        let at = 1 + HEADS * 4;
        for (k, v) in self.counters().iter().enumerate() {
            out[at + 8 * k..at + 8 + 8 * k].copy_from_slice(&v.to_le_bytes());
        }
        TICK_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same bytes as trunk/pipectl exitmsg_test.go exitWireGolden,
    /// exitTickGolden and exitPoolGolden.
    const WIRE_GOLDEN: &str = "030201e8030000b0042c013075000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TICK_GOLDEN: &str = "82ffffffff01000000390500000200000004000000030000001300000014000000050000000000000006000000000000000700000000000000080000000000000009000000000000000a000000000000000b000000000000000c000000000000000d000000000000000e000000000000000f00000000000000100000000000000011000000000000001200000000000000150000000000000016000000000000001700000000000000180000000000000019000000000000001a000000000000001b000000000000001c000000000000001d000000000000001e000000000000001f000000000000002000000000000000";
    const POOL_GOLDEN: &str = "0b2c0130750000";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn messages_match_the_go_side() {
        let wire = unhex(WIRE_GOLDEN);
        match parse(&wire) {
            Some(Msg::Wire { id: 2, form: FORM_UDP, glue_us: 1000, glue_max: 1200, dead_ms: 300, quiet_ms: 30000, keys }) => {
                assert_eq!(keys.len(), 64);
                assert_eq!((keys[0], keys[32]), (0xaa, 0xbb));
            }
            _ => panic!("wire"),
        }
        assert!(parse(&wire[..wire.len() - 1]).is_none(), "a key torn short");
        let ports = [B_PORTS, 2, 0, 0xfb, 0x20, 0x50, 0x00];
        match parse(&ports) {
            Some(Msg::Ports { ports }) => assert_eq!((port_at(ports, 0), port_at(ports, 1)), (8443, 80)),
            _ => panic!("ports"),
        }
        assert!(parse(&[B_HELLO, 1, 0, 9]).is_none(), "a byte too many");
        assert!(matches!(parse(&unhex(POOL_GOLDEN)), Some(Msg::Pool { dead_ms: 300, quiet_ms: 30000 })));
        let mut b = [0u8; 16];
        let n = put_hello(&mut b, 0x0102_0304);
        assert_eq!(&b[..n], &[P_HELLO, 2, 0, 4, 3, 2, 1]);
        let t = Tick {
            pause_ago_ms: NONE_MS,
            pauses: 1,
            late_max_us: 1337,
            sessions: 2,
            members: 4,
            flows: 3,
            links: 19,
            streams: 20,
            joined: 5,
            silent: 6,
            quiet: 7,
            gone: 8,
            dgrams_out: 9,
            dgrams_in: 10,
            dgrams_copy: 11,
            flows_idle: 12,
            refused: 13,
            w_in: 14,
            w_out: 15,
            frames_out: 16,
            bad: 17,
            dropped: 18,
            streams_opened: 21,
            streams_fin: 22,
            reset_peer: 23,
            reset_local: 24,
            hit: 25,
            resent: 26,
            up: 27,
            down: 28,
            early: 29,
            early_dropped: 30,
            refused_streams: 31,
            link_dgrams: 32,
        };
        let mut out = [0u8; TICK_LEN];
        assert_eq!(t.put(&mut out), TICK_LEN);
        assert_eq!(&out[..], &unhex(TICK_GOLDEN)[..]);
    }
}
