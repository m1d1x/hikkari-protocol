//! The brain ↔ exit socket (README.md, «The exit»): the same kind of socket
//! as the entry's (one local SOCK_SEQPACKET socket, one message per
//! datagram, sockets passed by SCM_RIGHTS with the message that uses them,
//! integers little-endian), with the exit's own messages. The Go side is
//! trunk/pipectl (exitmsg.go); both sides hold the same golden bytes in their
//! tests. Here are only the messages, so they are tested on any platform.

pub const VERSION: u16 = 4;

// Brain → exit.
pub const B_HELLO: u8 = 0x01; // ver u16
pub const B_WIRE: u8 = 0x03; // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, quiet_ms u32, n u8, keys [32] × n; on FORM_H3DGRAM then cert_len u16, cert path, key_len u16, key path; one fd: the wire's bound socket
pub const B_PORTS: u8 = 0x0a; // n u16, port u16 × n
pub const B_POOL: u8 = 0x0b; // dead_ms u16, quiet_ms u32; one fd: the pool's listening TCP socket, or none (members come by B_LINK)
pub const B_GEN: u8 = 0x0c; // gen u8: the generation the exit's QUIC connection ids name, before any wire
pub const B_DRAIN: u8 = 0x0d; // one fd: the old end of a handoff (hikkari_trunk::handoff)
pub const B_ADOPT: u8 = 0x0e; // one fd: the new end of a handoff
pub const B_MARK: u8 = 0x0f; // kind u8, session [16], stream u32, id u64: a tester's stream or flow (spec/trunk.md, "Observation")
pub const B_COPIES: u8 = 0x11; // window_us u32: answers on a stream member that carried no stream are held this long (spec/trunk.md, "Copies on the pool"); 0: none
pub const B_LINK: u8 = 0x10; // one fd: a stream member's connected socket, as if accepted on the pool's port

// Exit → brain.
pub const P_HELLO: u8 = 0x81; // ver u16, pid u32
pub const P_TICK: u8 = 0x82; // see put_tick
pub const P_ERROR: u8 = 0x85; // text
pub const P_DRAINED: u8 = 0x86; // an exit draining carries nothing more: no client's flow, no stream
pub const P_LOCAL: u8 = 0x87; // open u8, kind u8, port u16, session [16], stream u32: a connection to the relay, see put_local
pub const P_OBSERVED: u8 = 0x88; // a report of a tester's stream or flow: see put_observed

/// The bare UDP wire (trunk/udpwire): its keys are udpwire.Key of each
/// trunk key.
pub const FORM_UDP: u8 = 1;
/// The Chromium QUIC wire (spec/trunk.md, `h3dgram`): its keys are the
/// tokens of each trunk key (h3dgram.Token), and the message names the
/// files of its TLS certificate chain and key (PEM), which the exit reads.
pub const FORM_H3DGRAM: u8 = 2;
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
    /// keys (udpwire.Key or h3dgram.Token of each trunk key: the exit never
    /// sees a trunk key); `cert` and `key` are the QUIC wire's files, empty
    /// for the UDP wire.
    Wire { id: u8, form: u8, glue_us: u32, glue_max: u16, dead_ms: u16, quiet_ms: u32, keys: &'a [u8], cert: &'a [u8], key: &'a [u8] },
    /// The loopback ports open to the trunk (trunk Local.DialFlow and
    /// DialStream refuse the others); the set replaces the one before.
    Ports { ports: &'a [u8] },
    /// The pool's port: stream members connect to its listening socket,
    /// which comes with the message (none: the brain hands each member over
    /// by Link); their stall and the session's Quiet.
    Pool { dead_ms: u16, quiet_ms: u32 },
    /// A stream member the brain accepted itself (the relay takes its
    /// CONNECT): its connected socket comes with the message.
    Link,
    /// How long answers wait on a pool's member of copies for the ones
    /// after them (spec/trunk.md, "Copies on the pool"); 0: not at all.
    Copies { window_us: u32 },
    /// The exit's generation (spec/trunk.md, "An exit's own process
    /// replaced"): every QUIC connection id it issues names it.
    Gen { gen: u8 },
    /// The exit is the old one of a reload: the old end of the handoff
    /// socket comes with the message.
    Drain,
    /// The exit is the new one of a reload: the new end comes with it.
    Adopt,
    /// The relay admitted a tester's key on the connection of this stream
    /// or flow (kind frame::OBS_STREAM or OBS_FLOW) of the session: the exit
    /// marks it with the observation `id` the brain drew.
    Mark { kind: u8, session: [u8; 16], stream: u32, id: u64 },
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
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
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
            let keys = r.take(32 * n)?;
            let (cert, key): (&[u8], &[u8]) = if form == FORM_H3DGRAM {
                let c = r.u16()? as usize;
                let cert = r.take(c)?;
                let k = r.u16()? as usize;
                (cert, r.take(k)?)
            } else {
                (&[], &[])
            };
            if form == FORM_H3DGRAM && (cert.is_empty() || key.is_empty()) {
                return None;
            }
            Msg::Wire { id, form, glue_us, glue_max, dead_ms, quiet_ms, keys, cert, key }
        }
        B_PORTS => {
            let n = r.u16()? as usize;
            Msg::Ports { ports: r.take(2 * n)? }
        }
        B_POOL => Msg::Pool { dead_ms: r.u16()?, quiet_ms: r.u32()? },
        B_GEN => Msg::Gen { gen: r.u8()? },
        B_DRAIN => Msg::Drain,
        B_ADOPT => Msg::Adopt,
        B_LINK => Msg::Link,
        B_COPIES => Msg::Copies { window_us: r.u32()? },
        B_MARK => Msg::Mark { kind: r.u8()?, session: r.take(16)?.try_into().ok()?, stream: r.u32()?, id: r.u64()? },
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

/// A P_LOCAL message's length.
pub const LOCAL_LEN: usize = 25;

/// A connection of the exit to its relay opened (`open` 1) or closed (0):
/// the stream's or flow's kind (frame::OBS_STREAM, OBS_FLOW), the
/// connection's local port on loopback (what the relay sees as its peer's),
/// its session's id and its stream id. The brain knows by it which stream
/// or flow a connection the relay admits is, as the Go exit's trunkTargets.
pub fn put_local(out: &mut [u8], open: bool, kind: u8, port: u16, session: &[u8; 16], stream: u32) -> usize {
    out[0] = P_LOCAL;
    out[1] = open as u8;
    out[2] = kind;
    out[3..5].copy_from_slice(&port.to_le_bytes());
    out[5..21].copy_from_slice(session);
    out[21..25].copy_from_slice(&stream.to_le_bytes());
    LOCAL_LEN
}

/// A P_OBSERVED message's length: the entry pipe's (hk-pipe ctl.rs
/// put_observed), whose client TCP the exit never has.
pub const OBSERVED_LEN: usize = 116;

/// A report of a tester's stream or flow, as the entry pipe's P_OBSERVED:
/// id u64, kind u8, phase u8 (observe::PHASE_*), port u16, age_ms u32, up
/// u64, down u64, chunks u64, resent u64, carriers u8, deaths u32,
/// max_wait_ms u32, dgrams_out u64, dgrams_in u64, copies u64, end u8
/// (observe::END_*), has_tcp u8 (0), 32 zero bytes.
pub fn put_observed(out: &mut [u8], r: &Observed) -> usize {
    out[..OBSERVED_LEN].fill(0);
    out[0] = P_OBSERVED;
    out[1..9].copy_from_slice(&r.id.to_le_bytes());
    out[9] = r.kind;
    out[10] = r.phase;
    out[11..13].copy_from_slice(&r.port.to_le_bytes());
    out[13..17].copy_from_slice(&r.age_ms.to_le_bytes());
    for (k, v) in [r.up, r.down, r.chunks, r.resent].iter().enumerate() {
        out[17 + 8 * k..25 + 8 * k].copy_from_slice(&v.to_le_bytes());
    }
    out[49] = r.carriers;
    out[50..54].copy_from_slice(&r.deaths.to_le_bytes());
    out[54..58].copy_from_slice(&r.max_wait_ms.to_le_bytes());
    for (k, v) in [r.dgrams_out, r.dgrams_in, r.copies].iter().enumerate() {
        out[58 + 8 * k..66 + 8 * k].copy_from_slice(&v.to_le_bytes());
    }
    out[82] = r.end;
    OBSERVED_LEN
}

/// One report of a tester's stream or flow (P_OBSERVED).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Observed {
    pub id: u64,
    pub kind: u8,
    pub phase: u8,
    pub port: u16,
    pub age_ms: u32,
    pub up: u64,
    pub down: u64,
    pub chunks: u64,
    pub resent: u64,
    pub carriers: u8,
    pub deaths: u32,
    pub max_wait_ms: u32,
    pub dgrams_out: u64,
    pub dgrams_in: u64,
    pub copies: u64,
    pub end: u8,
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
    /// errors), and datagrams that came on stream members (carried since
    /// R6.4.3: the pool is UDP's fallback).
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
    /// trunk/pipectl exitmsg_test.go exitH3WireGolden: wire 6, one token
    /// (0xcc), the files /c.pem and /k.pem.
    const H3_WIRE_GOLDEN: &str = "030602e8030000b0042c013075000001cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc06002f632e70656d06002f6b2e70656d";

    /// trunk/pipectl exitmsg_test.go exitObservedGolden, exitLocalGolden,
    /// exitMarkGolden: a stream's report at its mark (id 0x1122334455667788,
    /// port 443, 1.5 s old, 1 KiB up, 2 KiB down, 3 chunks, 1 sent again, 2
    /// members, 1 death, 40 ms the longest wait); a stream's connection to
    /// the relay opened from port 40001, session 00..0f, stream 7; a flow's
    /// mark, session aa × 16, stream 9.
    const OBSERVED_GOLDEN: &str = "8888776655443322110100bb01dc050000000400000000000000080000000000000300000000000000010000000000000002010000002800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const LOCAL_GOLDEN: &str = "870102419c000102030405060708090a0b0c0d0e0f07000000";
    const MARK_GOLDEN: &str = "0f01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa090000000807060504030201";

    #[test]
    fn observation_messages_match_the_go_side() {
        let r = Observed { id: 0x1122_3344_5566_7788, kind: 1, phase: 0, port: 443, age_ms: 1500, up: 1024, down: 2048, chunks: 3, resent: 1, carriers: 2, deaths: 1, max_wait_ms: 40, ..Observed::default() };
        let mut b = [0xffu8; OBSERVED_LEN];
        assert_eq!(put_observed(&mut b, &r), OBSERVED_LEN);
        assert_eq!(b[..], unhex(OBSERVED_GOLDEN)[..]);
        let mut sid = [0u8; 16];
        sid.iter_mut().enumerate().for_each(|(i, x)| *x = i as u8);
        let mut b = [0u8; LOCAL_LEN];
        assert_eq!(put_local(&mut b, true, 2, 40001, &sid, 7), LOCAL_LEN);
        assert_eq!(b[..], unhex(LOCAL_GOLDEN)[..]);
        let m = unhex(MARK_GOLDEN);
        assert!(matches!(parse(&m), Some(Msg::Mark { kind: 1, session, stream: 9, id: 0x0102_0304_0506_0708 }) if session == [0xaa; 16]));
        assert!(parse(&m[..m.len() - 1]).is_none(), "a mark torn short");
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn messages_match_the_go_side() {
        let wire = unhex(WIRE_GOLDEN);
        match parse(&wire) {
            Some(Msg::Wire { id: 2, form: FORM_UDP, glue_us: 1000, glue_max: 1200, dead_ms: 300, quiet_ms: 30000, keys, cert: b"", key: b"" }) => {
                assert_eq!(keys.len(), 64);
                assert_eq!((keys[0], keys[32]), (0xaa, 0xbb));
            }
            _ => panic!("wire"),
        }
        assert!(parse(&wire[..wire.len() - 1]).is_none(), "a key torn short");
        let h3 = unhex(H3_WIRE_GOLDEN);
        match parse(&h3) {
            Some(Msg::Wire { id: 6, form: FORM_H3DGRAM, glue_us: 1000, keys, cert: b"/c.pem", key: b"/k.pem", .. }) => {
                assert_eq!((keys.len(), keys[0]), (32, 0xcc));
            }
            _ => panic!("h3dgram wire"),
        }
        assert!(parse(&h3[..h3.len() - 1]).is_none(), "a key file's path torn short");
        let ports = [B_PORTS, 2, 0, 0xfb, 0x20, 0x50, 0x00];
        match parse(&ports) {
            Some(Msg::Ports { ports }) => assert_eq!((port_at(ports, 0), port_at(ports, 1)), (8443, 80)),
            _ => panic!("ports"),
        }
        assert!(parse(&[B_HELLO, 1, 0, 9]).is_none(), "a byte too many");
        assert!(matches!(parse(&unhex(POOL_GOLDEN)), Some(Msg::Pool { dead_ms: 300, quiet_ms: 30000 })));
        assert!(matches!(parse(&[B_GEN, 7]), Some(Msg::Gen { gen: 7 })));
        assert!(parse(&[B_GEN]).is_none(), "a gen torn");
        assert!(matches!(parse(&[B_DRAIN]), Some(Msg::Drain)));
        assert!(matches!(parse(&[B_ADOPT]), Some(Msg::Adopt)));
        assert!(matches!(parse(&[B_LINK]), Some(Msg::Link)));
        // exitCopiesGolden: answers held 4 ms on a member of copies.
        assert!(matches!(parse(&[B_COPIES, 0xa0, 0x0f, 0, 0]), Some(Msg::Copies { window_us: 4000 })));
        assert!(parse(&[B_COPIES, 0xa0, 0x0f, 0]).is_none());
        assert!(parse(&[B_LINK, 0]).is_none());
        let mut b = [0u8; 16];
        let n = put_hello(&mut b, 0x0102_0304);
        assert_eq!(&b[..n], &[P_HELLO, 4, 0, 4, 3, 2, 1]);
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
