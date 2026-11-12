//! The brain ↔ exit socket (README.md, «The exit»): the same kind of socket
//! as the entry's (one local SOCK_SEQPACKET socket, one message per
//! datagram, sockets passed by SCM_RIGHTS with the message that uses them,
//! integers little-endian), with the exit's own messages. The Go side is
//! trunk/pipectl (exitmsg.go); both sides hold the same golden bytes in their
//! tests. Here are only the messages, so they are tested on any platform.

pub const VERSION: u16 = 1;

// Brain → exit.
pub const B_HELLO: u8 = 0x01; // ver u16
pub const B_WIRE: u8 = 0x03; // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, quiet_ms u32, n u8, keys [32] × n; one fd: the wire's bound socket
pub const B_PORTS: u8 = 0x0a; // n u16, port u16 × n

// Exit → brain.
pub const P_HELLO: u8 = 0x81; // ver u16, pid u32
pub const P_TICK: u8 = 0x82; // see put_tick
pub const P_ERROR: u8 = 0x85; // text

/// The only wire form so far: the bare UDP wire (trunk/udpwire).
pub const FORM_UDP: u8 = 1;
/// A duration the exit has no value for (no pause yet).
pub const NONE_MS: u32 = u32::MAX;
/// Most sockets one message may carry: a wire's one.
pub const MAX_FDS: usize = 1;
/// Most trunk keys one wire opens under (the hub's keys of this exit).
pub const MAX_KEYS: usize = 16;

/// One message from the brain.
pub enum Msg<'a> {
    Hello { ver: u16 },
    /// A wire: its socket comes with the message. `keys` holds `n` wire
    /// keys (udpwire.Key of each trunk key: the exit never sees a trunk key).
    Wire { id: u8, form: u8, glue_us: u32, glue_max: u16, dead_ms: u16, quiet_ms: u32, keys: &'a [u8] },
    /// The loopback ports open to the trunk (trunk Local.DialFlow refuses
    /// the others); the set replaces the one before.
    Ports { ports: &'a [u8] },
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
    /// Members up: entry addresses whose hello was answered and that are
    /// not dead.
    pub members: u32,
    /// The clients' flows open.
    pub flows: u32,
    /// Members joined (trunk Stats.MembersJoined); buried by their stall
    /// while another member proved the entry alive, and by Quiet (both
    /// trunk Stats.MembersStall); forgotten after PeerIdle with nothing
    /// from them (udpwire's reap).
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
}

pub const TICK_LEN: usize = 1 + 6 * 4 + 14 * 8;

impl Tick {
    fn counters(&self) -> [u64; 14] {
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
        ]
    }

    pub fn put(&self, out: &mut [u8]) -> usize {
        out[0] = P_TICK;
        let heads = [self.pause_ago_ms, self.pauses, self.late_max_us, self.sessions, self.members, self.flows];
        for (k, v) in heads.iter().enumerate() {
            out[1 + 4 * k..5 + 4 * k].copy_from_slice(&v.to_le_bytes());
        }
        for (k, v) in self.counters().iter().enumerate() {
            out[25 + 8 * k..33 + 8 * k].copy_from_slice(&v.to_le_bytes());
        }
        TICK_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same bytes as trunk/pipectl exitmsg_test.go exitWireGolden and
    /// exitTickGolden.
    const WIRE_GOLDEN: &str = "030201e8030000b0042c013075000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TICK_GOLDEN: &str = "82ffffffff0100000039050000020000000400000003000000050000000000000006000000000000000700000000000000080000000000000009000000000000000a000000000000000b000000000000000c000000000000000d000000000000000e000000000000000f00000000000000100000000000000011000000000000001200000000000000";

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
        let mut b = [0u8; 16];
        let n = put_hello(&mut b, 0x0102_0304);
        assert_eq!(&b[..n], &[P_HELLO, 1, 0, 4, 3, 2, 1]);
        let t = Tick {
            pause_ago_ms: NONE_MS,
            pauses: 1,
            late_max_us: 1337,
            sessions: 2,
            members: 4,
            flows: 3,
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
        };
        let mut out = [0u8; TICK_LEN];
        assert_eq!(t.put(&mut out), TICK_LEN);
        assert_eq!(&out[..], &unhex(TICK_GOLDEN)[..]);
    }
}
