//! The brain ↔ pipe socket (README.md, «Brain and pipe»): one local
//! SOCK_SEQPACKET socket, one message per datagram, the brain's sockets
//! passed with the message that uses them by SCM_RIGHTS. Integers are
//! little-endian. The Go side is trunk/pipectl (msg.go); both sides hold the
//! same golden bytes in their tests. The socket itself is hikkari_sys::SeqPacket;
//! here are only the messages, so they are tested on any platform.

use crate::route::Route;

pub const VERSION: u16 = 11;

// Brain → pipe.
pub const B_HELLO: u8 = 0x01; // ver u16
pub const B_LISTEN: u8 = 0x02; // id u8, class u8, to u16, copies u8; one fd: a bound UDP socket
pub const B_WIRE: u8 = 0x03; // id u8, form u8, glue_us u32, glue_max u16, dead_ms u16, key [32]; FORM_UDP: one fd per member; FORM_H3DGRAM: see H3
pub const B_UNWIRE: u8 = 0x04; // id u8
pub const B_ROUTE: u8 = 0x05; // voice u8, bulk u8, video u8, n u8 + n × (wire u8, copies u8, after_ms u16), m u8 + m × (wire u8, fate u8): route.rs
pub const B_OPEN: u8 = 0x06; // tag u32, class u8, pin u8, port u16, copies u8
pub const B_DGRAM: u8 = 0x07; // tag u32, payload
pub const B_CLOSE: u8 = 0x08; // tag u32
pub const B_MEMBER: u8 = 0x09; // wire u8, index u8; one fd: the member's new socket
pub const B_DRAIN: u8 = 0x0a; // one fd: the old end of a handoff socket (handoff.rs); the pipe takes no new client
pub const B_ADOPT: u8 = 0x0b; // one fd: the new end of a handoff socket; a pipe draining sends on its other end
pub const B_TCP_LISTEN: u8 = 0x0c; // id u8, to u16; one fd: a listening TCP socket, a client port of streams
pub const B_STATS: u8 = 0x0f; // the counters of the brain's minute line, now (answered by P_STATS)
pub const B_CLIENTS: u8 = 0x0e; // the leg client → entry of the minute, now (answered by P_CLIENTS)
pub const B_COPIES: u8 = 0x10; // members u8, window_us u32: the pool's members of copies and their window (copies.rs); 0 members: none
pub const B_POOL: u8 = 0x0d; // id u8, form u8, members u8, dead_ms u16, lo u16, hi u16, exit ip [4] port u16; Chromium: sni u8+n, key u8+n, cronet u16+n, roots (rest)
pub const B_RECEIVER: u8 = 0x11; // rx u8, ip [4], pool_members u8: a receiver on standby at ip, the active one's ports (0.0.0.0: taken away)
pub const B_ACTIVE: u8 = 0x12; // rx u8: the receiver that carries everything from now (session.rs)
pub const B_DEMAND: u8 = 0x13; // hold_ms u32: the voice class's copies of the other fate on demand, held this long after a loss (hikkari_trunk::demand); 0: always
pub const B_POINTS: u8 = 0x14; // n u8 + n × ip [4]: the active receiver's border points, member i of every wire to point i mod n (spec/trunk.md, "Border points"); n 0: none

// Pipe → brain.
pub const P_HELLO: u8 = 0x81; // ver u16, pid u32
pub const P_TICK: u8 = 0x82; // see put_tick
pub const P_MEMBER: u8 = 0x83; // wire u8, index u8, up u8, why u8
pub const P_DGRAM: u8 = 0x84; // tag u32, payload
pub const P_ERROR: u8 = 0x85; // text
pub const P_DRAINED: u8 = 0x86; // a pipe draining carries nothing more: no client's flow, no stream
pub const P_OBSERVED: u8 = 0x88; // a report of a tester's stream or flow: see put_observed
pub const P_STATS: u8 = 0x89; // see put_stats
pub const P_CLIENTS: u8 = 0x87; // conns u32, closed u32, sending u32, segs u64, retrans u64, rtt_p50_us u32, rtt_p90_us u32 (NONE_MS: none)
pub const P_RECEIVERS: u8 = 0x8a; // active u8, n u8 + n × (rx u8, ip [4], k u8 + k × (wire u8, members u8, up u8, proof_ago_ms u32)): see put_receivers

/// The bare UDP wire (trunk/udpwire): the brain's sockets, sealed frames.
pub const FORM_UDP: u8 = 1;
/// The Chromium QUIC wire (spec/trunk.md, `h3dgram`): the pipe opens its
/// members itself, CONNECT-UDP tunnels over Chromium's QUIC from ports of
/// the wire's book; the message's key is the token (h3dgram::token of the
/// trunk key) and its tail an H3.
pub const FORM_H3DGRAM: u8 = 2;
/// How a QUIC wire's member uses its session (hikkari_cronet::Usage).
pub const USAGE_DESTINATION: u8 = 0;
pub const USAGE_PROXY: u8 = 1;
/// A pool's forms: stream members over plain TCP to the exit's member port
/// (tests, the bench), or Chromium's CONNECT to the exit's relay (the
/// pool's form, trunk/chromium).
pub const POOL_PLAIN: u8 = 1;
pub const POOL_CHROMIUM: u8 = 2;
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
    Wire { id: u8, form: u8, glue_us: u32, glue_max: u16, dead_ms: u16, key: [u8; 32], h3: Option<H3<'a>> },
    Unwire { id: u8 },
    /// Boxed: the fates make it the largest message, and it is a rare one.
    Route(Box<Route>),
    Open { tag: u32, class: u8, pin: u8, port: u16, copies: u8 },
    Dgram { tag: u32, payload: &'a [u8] },
    Close { tag: u32 },
    Member { wire: u8, index: u8 },
    Drain,
    Adopt,
    TcpListen { id: u8, to: u16 },
    Pool(Pool<'a>),
    Copies { members: u8, window_us: u32 },
    Demand { hold_ms: u32 },
    Clients,
    Stats,
    Receiver { rx: u8, ip: std::net::Ipv4Addr, pool_members: u8 },
    Active { rx: u8 },
    /// The border points' addresses, n × ip [4] (points reads them).
    Points(&'a [u8]),
}

/// Most border points a receiver has (B_POINTS).
pub const MAX_POINTS: usize = 8;

/// The addresses of a B_POINTS message's body.
pub fn points(b: &[u8]) -> Vec<std::net::Ipv4Addr> {
    b.chunks_exact(4).map(|a| std::net::Ipv4Addr::new(a[0], a[1], a[2], a[3])).collect()
}

/// A wire of stream members (B_POOL): its members, their stall and source
/// ports, where they go and, for Chromium's form, what the CONNECT carries.
pub struct Pool<'a> {
    pub id: u8,
    pub form: u8,
    pub members: u8,
    pub dead_ms: u16,
    pub ports: (u16, u16),
    pub exit: std::net::SocketAddrV4,
    pub sni: &'a str,
    pub key: &'a str,
    /// libcronet's path; empty: found as the Go entry finds it.
    pub cronet: &'a str,
    /// PEM roots that replace the system's trust; empty: the system's.
    pub roots: &'a str,
}

/// The tail of a QUIC wire's B_WIRE: members u8, usage u8, lo u16, hi u16,
/// exit ip [4] port u16, sni u8+n, cronet u16+n, roots (rest). Its members
/// are tunnels to the exit's QUIC port at `exit`, whose certificate names
/// `sni`, from source ports of [lo, hi].
pub struct H3<'a> {
    pub members: u8,
    pub usage: u8,
    pub ports: (u16, u16),
    pub exit: std::net::SocketAddrV4,
    pub sni: &'a str,
    /// libcronet's path; empty: found as the Go entry finds it.
    pub cronet: &'a str,
    /// PEM roots that replace the system's trust; empty: the system's.
    pub roots: &'a str,
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
        B_WIRE => {
            let (id, form, glue_us, glue_max, dead_ms) = (r.u8()?, r.u8()?, r.u32()?, r.u16()?, r.u16()?);
            let key = r.take(32)?.try_into().ok()?;
            let h3 = match form {
                FORM_H3DGRAM => Some(h3(&mut r)?),
                _ if r.at == r.p.len() => None,
                _ => return None,
            };
            Msg::Wire { id, form, glue_us, glue_max, dead_ms, key, h3 }
        }
        B_UNWIRE => Msg::Unwire { id: r.u8()? },
        B_ROUTE => Msg::Route(Box::new(Route::parse(r.rest())?)),
        B_OPEN => Msg::Open { tag: r.u32()?, class: r.u8()?, pin: r.u8()?, port: r.u16()?, copies: r.u8()? },
        B_DGRAM => Msg::Dgram { tag: r.u32()?, payload: r.rest() },
        B_CLOSE => Msg::Close { tag: r.u32()? },
        B_MEMBER => Msg::Member { wire: r.u8()?, index: r.u8()? },
        B_DRAIN if m.len() == 1 => Msg::Drain,
        B_ADOPT if m.len() == 1 => Msg::Adopt,
        B_TCP_LISTEN => Msg::TcpListen { id: r.u8()?, to: r.u16()? },
        B_POOL => Msg::Pool(pool(&mut r)?),
        B_COPIES if m.len() == 6 => Msg::Copies { members: r.u8()?, window_us: r.u32()? },
        B_DEMAND if m.len() == 5 => Msg::Demand { hold_ms: r.u32()? },
        B_CLIENTS if m.len() == 1 => Msg::Clients,
        B_STATS if m.len() == 1 => Msg::Stats,
        B_RECEIVER if m.len() == 7 => {
            let rx = r.u8()?;
            let ip: [u8; 4] = r.take(4)?.try_into().ok()?;
            Msg::Receiver { rx, ip: ip.into(), pool_members: r.u8()? }
        }
        B_ACTIVE if m.len() == 2 => Msg::Active { rx: r.u8()? },
        B_POINTS if m.len() >= 2 && m[1] as usize <= MAX_POINTS && m.len() == 2 + 4 * m[1] as usize => Msg::Points(&m[2..]),
        _ => return None,
    })
}

fn h3<'a>(r: &mut Rd<'a>) -> Option<H3<'a>> {
    let (members, usage) = (r.u8()?, r.u8()?);
    if usage > USAGE_PROXY {
        return None;
    }
    let ports = (r.u16()?, r.u16()?);
    let ip: [u8; 4] = r.take(4)?.try_into().ok()?;
    let exit = std::net::SocketAddrV4::new(ip.into(), r.u16()?);
    let text = |b: &'a [u8]| std::str::from_utf8(b).ok();
    let n = r.u8()? as usize;
    let sni = text(r.take(n)?)?;
    let n = r.u16()? as usize;
    let cronet = text(r.take(n)?)?;
    let roots = text(r.rest())?;
    Some(H3 { members, usage, ports, exit, sni, cronet, roots })
}

fn pool<'a>(r: &mut Rd<'a>) -> Option<Pool<'a>> {
    let (id, form, members, dead_ms) = (r.u8()?, r.u8()?, r.u8()?, r.u16()?);
    let ports = (r.u16()?, r.u16()?);
    let ip: [u8; 4] = r.take(4)?.try_into().ok()?;
    let exit = std::net::SocketAddrV4::new(ip.into(), r.u16()?);
    let text = |b: &'a [u8]| std::str::from_utf8(b).ok();
    let mut p = Pool { id, form, members, dead_ms, ports, exit, sni: "", key: "", cronet: "", roots: "" };
    match form {
        POOL_PLAIN if r.at == r.p.len() => {}
        POOL_CHROMIUM => {
            let n = r.u8()? as usize;
            p.sni = text(r.take(n)?)?;
            let n = r.u8()? as usize;
            p.key = text(r.take(n)?)?;
            let n = r.u16()? as usize;
            p.cronet = text(r.take(n)?)?;
            p.roots = text(r.rest())?;
        }
        _ => return None,
    }
    Some(p)
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
    /// Sessions retired that still carry something, and whether a session
    /// for the exit's drain is coming up (the pipe's session.rs; trunk
    /// Entry.Retired).
    pub retired: u8,
    pub coming: bool,
    /// Clients' streams open, every session's (trunk Stats.Streams).
    pub streams: u32,
}

pub const TICK_HEAD: usize = 1 + 16 + 32 + 2 + 4 + 1;
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
    out[49] = p.retired;
    out[50] = p.coming as u8;
    out[51..55].copy_from_slice(&p.streams.to_le_bytes());
    out[55] = wires.len() as u8;
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

/// The counters of the brain's minute line that ticks do not carry
/// (P_STATS), in the Go entry's words (trunk Stats, hikkari-control
/// trunkentry statsLine), since the pipe started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Clients' streams opened, reset either way, chunks sent again after
    /// their member died, client bytes up and down.
    pub opened: u64,
    pub reset: u64,
    pub resent: u64,
    pub up: u64,
    pub down: u64,
    /// The pool's book: ports resting dead now, and kills since the start.
    pub dead_ports: u32,
    pub port_kills: u64,
    /// The pipe's own pauses in all (ms).
    pub paused_ms: u64,
    /// The pool's members up: their round trips (each one's latest ping,
    /// as the ticks say a wire's) at p50, p90 and
    /// the most (µs), as the Go entry's rttAt picks them; None: none up.
    pub rtt_us: Option<(u32, u32, u32)>,
}

/// A P_STATS message's length.
pub const STATS_LEN: usize = 73;

pub fn put_stats(out: &mut [u8], s: &Stats) -> usize {
    out[0] = P_STATS;
    for (i, v) in [s.opened, s.reset, s.resent, s.up, s.down].into_iter().enumerate() {
        out[1 + 8 * i..9 + 8 * i].copy_from_slice(&v.to_le_bytes());
    }
    out[41..45].copy_from_slice(&s.dead_ports.to_le_bytes());
    out[45..53].copy_from_slice(&s.port_kills.to_le_bytes());
    out[53..61].copy_from_slice(&s.paused_ms.to_le_bytes());
    let (p50, p90, max) = s.rtt_us.unwrap_or((NONE_MS, NONE_MS, NONE_MS));
    out[61..65].copy_from_slice(&p50.to_le_bytes());
    out[65..69].copy_from_slice(&p90.to_le_bytes());
    out[69..73].copy_from_slice(&max.to_le_bytes());
    STATS_LEN
}

/// A P_OBSERVED message's length.
pub const OBSERVED_LEN: usize = 116;

/// A report of a tester's stream or flow (P_OBSERVED, crate::observe): id
/// u64, kind u8, phase u8, port u16, age_ms u32, up u64, down u64, chunks
/// u64, resent u64, carriers u8, deaths u32, max_wait_ms u32, dgrams_out
/// u64, dgrams_in u64, copies u64, end u8, has_tcp u8, then the client's TCP
/// (zeros without it): rtt_us, rttvar_us, retrans, lost, unacked, cwnd,
/// segs_out, segs_in, each u32.
pub fn put_observed(out: &mut [u8], r: &crate::observe::Report) -> usize {
    out[0] = P_OBSERVED;
    out[1..9].copy_from_slice(&r.id.to_le_bytes());
    out[9] = r.kind;
    out[10] = r.phase;
    out[11..13].copy_from_slice(&r.port.to_le_bytes());
    out[13..17].copy_from_slice(&r.age_ms.to_le_bytes());
    for (i, v) in [r.up, r.down, r.chunks, r.resent].into_iter().enumerate() {
        out[17 + 8 * i..25 + 8 * i].copy_from_slice(&v.to_le_bytes());
    }
    out[49] = r.carriers;
    out[50..54].copy_from_slice(&r.deaths.to_le_bytes());
    out[54..58].copy_from_slice(&r.max_wait_ms.to_le_bytes());
    for (i, v) in [r.dgrams_out, r.dgrams_in, r.copies].into_iter().enumerate() {
        out[58 + 8 * i..66 + 8 * i].copy_from_slice(&v.to_le_bytes());
    }
    out[82] = r.end;
    out[83] = r.tcp.is_some() as u8;
    let t = r.tcp.unwrap_or_default();
    for (i, v) in [t.rtt_us, t.rttvar_us, t.total_retrans, t.lost, t.unacked, t.cwnd, t.segs_out, t.segs_in].into_iter().enumerate() {
        out[84 + 4 * i..88 + 4 * i].copy_from_slice(&v.to_le_bytes());
    }
    OBSERVED_LEN
}

/// The leg client → entry of the minute (P_CLIENTS).
pub fn put_clients(out: &mut [u8], m: &crate::streams::LegMinute) -> usize {
    out[0] = P_CLIENTS;
    let (p50, p90) = m.rtt_us.unwrap_or((NONE_MS, NONE_MS));
    out[1..5].copy_from_slice(&m.conns.to_le_bytes());
    out[5..9].copy_from_slice(&m.closed.to_le_bytes());
    out[9..13].copy_from_slice(&m.sending.to_le_bytes());
    out[13..21].copy_from_slice(&m.segs.to_le_bytes());
    out[21..29].copy_from_slice(&m.retrans.to_le_bytes());
    out[29..33].copy_from_slice(&p50.to_le_bytes());
    out[33..37].copy_from_slice(&p90.to_le_bytes());
    37
}

/// A receiver on standby in a tick (P_RECEIVERS): its wires and pools as
/// (id, members, up, proof_ago_ms); none before its session is open.
pub struct ReceiverTick {
    pub rx: u8,
    pub ip: std::net::Ipv4Addr,
    pub wires: Vec<(u8, u8, u8, u32)>,
}

/// P_RECEIVERS: the active receiver, then each one on standby. out must
/// hold 3 + Σ (6 + 7 × its wires).
pub fn put_receivers(out: &mut [u8], active: u8, rs: &[ReceiverTick]) -> usize {
    out[0] = P_RECEIVERS;
    out[1] = active;
    out[2] = rs.len() as u8;
    let mut at = 3;
    for r in rs {
        out[at] = r.rx;
        out[at + 1..at + 5].copy_from_slice(&r.ip.octets());
        out[at + 5] = r.wires.len() as u8;
        at += 6;
        for &(id, members, up, proof) in &r.wires {
            out[at] = id;
            out[at + 1] = members;
            out[at + 2] = up;
            out[at + 3..at + 7].copy_from_slice(&proof.to_le_bytes());
            at += 7;
        }
    }
    at
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
    const TICK_GOLDEN: &str = "82ffffffff020000003905000007000000080000000000000009000000000000000a000000000000000b0000000000000003010500000001020302fa00000064000000b80b0000010000000000000002000000000000000300000000000000040000000000000005000000000000000600000000000000";

    const POOL_PLAIN_GOLDEN: &str = "0d0001202c01204eff7f7f000001de4f";
    const POOL_CHROMIUM_GOLDEN: &str = "0d0002042c01204eff7f7f000001bb010a686b2e6578616d706c651a676f6c64656e2d746573742d6b65792d3031323334353637383911002f6f70742f6c696263726f6e65742e736f50454d";
    const TCP_LISTEN_GOLDEN: &str = "0c01fb20";
    /// copiesGolden: 4 members of copies, a window of 4 ms.
    const COPIES_GOLDEN: &str = "1004a00f0000";
    /// trunk/pipectl msg_test.go demandGolden: a hold of 5 minutes.
    const DEMAND_GOLDEN: &str = "13e0930400";
    const STATS_GOLDEN: &str = "8901000000000000000200000000000000030000000000000004000000000000000500000000000000060000000700000000000000080000000000000010270000204e000030750000";
    const OBSERVED_GOLDEN: &str = "88efcdab90785634120101fb200f2700000700000000000000080000000000000009000000000000000a000000000000000b0c0000000d000000000000000000000000000000000000000000000000000000010110270000e803000003000000010000000200000040000000c8000000c9000000";
    const CLIENTS_GOLDEN: &str = "870c00000003000000090000005abc000000000000250000000000000060470000e8ee0000";
    /// receiverGolden: receiver 1 at 10.0.0.2, 8 pool members; activeGolden:
    /// receiver 1; receiversGolden: active 0, receiver 1 at 10.0.0.2 with
    /// wire 3 (6 members, 5 up, proof 120 ms ago) and pool 0 (8, 8, none).
    const RECEIVER_GOLDEN: &str = "11010a00000208";
    const ACTIVE_GOLDEN: &str = "1201";
    /// pointsGolden: the border points 10.0.0.1 and 10.0.0.2.
    const POINTS_GOLDEN: &str = "14020a0000010a000002";
    const RECEIVERS_GOLDEN: &str = "8a0001010a0000020203060578000000000808ffffffff";
    const H3_WIRE_GOLDEN: &str = "030602e8030000b0042c01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0400204eff7f7f0000015d110a686b2e6578616d706c6511002f6f70742f6c696263726f6e65742e736f50454d";

    #[test]
    fn speaks_the_brains_receivers() {
        match parse(&unhex(RECEIVER_GOLDEN)) {
            Some(Msg::Receiver { rx, ip, pool_members }) => assert_eq!((rx, ip, pool_members), (1, "10.0.0.2".parse().unwrap(), 8)),
            _ => panic!("not a receiver"),
        }
        assert!(matches!(parse(&unhex(ACTIVE_GOLDEN)), Some(Msg::Active { rx: 1 })));
        match parse(&unhex(POINTS_GOLDEN)) {
            Some(Msg::Points(b)) => assert_eq!(points(b), ["10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap(), "10.0.0.2".parse().unwrap()]),
            _ => panic!("not points"),
        }
        assert!(matches!(parse(&unhex("1400")), Some(Msg::Points(b)) if b.is_empty()), "no points");
        assert!(parse(&unhex("14020a0000010a0000")).is_none(), "torn points");
        assert!(parse(&unhex("11010a000002")).is_none(), "a torn receiver");
        let rs = [ReceiverTick { rx: 1, ip: "10.0.0.2".parse().unwrap(), wires: vec![(3, 6, 5, 120), (0, 8, 8, NONE_MS)] }];
        let mut out = [0u8; 64];
        let n = put_receivers(&mut out, 0, &rs);
        assert_eq!(out[..n], unhex(RECEIVERS_GOLDEN)[..]);
    }

    #[test]
    fn parses_the_brains_pool_and_tcp_port() {
        match parse(&unhex(POOL_PLAIN_GOLDEN)) {
            Some(Msg::Pool(p)) => {
                assert_eq!((p.id, p.form, p.members, p.dead_ms, p.ports), (0, POOL_PLAIN, 32, 300, (20000, 32767)));
                assert_eq!((p.exit, p.sni, p.key), ("127.0.0.1:20446".parse().unwrap(), "", ""));
            }
            _ => panic!("not a pool"),
        }
        let m = unhex(POOL_CHROMIUM_GOLDEN);
        match parse(&m) {
            Some(Msg::Pool(p)) => {
                assert_eq!((p.form, p.members, p.exit.port()), (POOL_CHROMIUM, 4, 443));
                assert_eq!((p.sni, p.key, p.cronet, p.roots), ("hk.example", "golden-test-key-0123456789", "/opt/libcronet.so", "PEM"));
            }
            _ => panic!("not a pool"),
        }
        assert!(parse(&m[..20]).is_none(), "a torn pool");
        let mut plain = unhex(POOL_PLAIN_GOLDEN);
        plain.push(0);
        assert!(parse(&plain).is_none(), "a plain pool carries nothing after its exit");
        assert!(matches!(parse(&unhex(TCP_LISTEN_GOLDEN)), Some(Msg::TcpListen { id: 1, to: 8443 })));
        assert!(matches!(parse(&unhex(COPIES_GOLDEN)), Some(Msg::Copies { members: 4, window_us: 4000 })));
        assert!(parse(&unhex(COPIES_GOLDEN)[..5]).is_none(), "a torn B_COPIES");
        assert!(matches!(parse(&unhex(DEMAND_GOLDEN)), Some(Msg::Demand { hold_ms: 300_000 })));
        assert!(parse(&unhex(DEMAND_GOLDEN)[..4]).is_none(), "a torn B_DEMAND");
    }

    #[test]
    fn parses_the_brains_wire() {
        let m = unhex(WIRE_GOLDEN);
        match parse(&m) {
            Some(Msg::Wire { id, form, glue_us, glue_max, dead_ms, key, h3: None }) => {
                assert_eq!((id, form, glue_us, glue_max, dead_ms), (3, FORM_UDP, 1000, 1200, 300));
                assert_eq!(key[31], 31);
            }
            _ => panic!("not a wire"),
        }
        let mut more = m.clone();
        more.push(0);
        assert!(parse(&more).is_none(), "a bare UDP wire carries nothing after its key");
        assert!(parse(&m[..m.len() - 1]).is_none());
        assert!(parse(&[0x7f]).is_none());
        match parse(&[B_DGRAM, 7, 0, 0, 0, b'h', b'i']) {
            Some(Msg::Dgram { tag: 7, payload }) => assert_eq!(payload, b"hi"),
            _ => panic!("not a dgram"),
        }
    }

    #[test]
    fn parses_the_brains_quic_wire() {
        // The same bytes as trunk/pipectl msg_test.go TestGolden's QUIC wire.
        let m = unhex(H3_WIRE_GOLDEN);
        match parse(&m) {
            Some(Msg::Wire { id: 6, form: FORM_H3DGRAM, glue_us: 1000, glue_max: 1200, dead_ms: 300, key, h3: Some(h) }) => {
                assert_eq!(key[1], 1);
                assert_eq!((h.members, h.usage, h.ports, h.exit), (4, USAGE_DESTINATION, (20000, 32767), "127.0.0.1:4445".parse().unwrap()));
                assert_eq!((h.sni, h.cronet, h.roots), ("hk.example", "/opt/libcronet.so", "PEM"));
            }
            _ => panic!("not a QUIC wire"),
        }
        assert!(parse(&m[..m.len() - 5]).is_none(), "a torn path");
        let mut bad = m.clone();
        bad[44] = 2;
        assert!(parse(&bad).is_none(), "usage 2 is neither destination nor proxy");
    }

    #[test]
    fn parses_the_brains_drain_and_adopt_alone() {
        // The same bytes as trunk/pipectl msg.go bDrain and bAdopt.
        assert!(matches!(parse(&[0x0a]), Some(Msg::Drain)));
        assert!(matches!(parse(&[0x0b]), Some(Msg::Adopt)));
        assert!(parse(&[B_DRAIN, 0]).is_none(), "a drain carries nothing but its socket");
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
            retired: 3,
            coming: true,
            streams: 5,
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

    #[test]
    fn clients_golden() {
        let m = crate::streams::LegMinute { conns: 12, closed: 3, sending: 9, segs: 48218, retrans: 37, rtt_us: Some((18272, 61160)) };
        let mut b = [0u8; 64];
        let n = put_clients(&mut b, &m);
        assert_eq!(b[..n], unhex(CLIENTS_GOLDEN)[..]);
        let none = crate::streams::LegMinute::default();
        let n = put_clients(&mut b, &none);
        assert_eq!(&b[29..n], &[0xff; 8]);
        assert!(matches!(parse(&[B_CLIENTS]), Some(Msg::Clients)));
        assert!(parse(&[B_CLIENTS, 0]).is_none());
    }

    #[test]
    fn observed_golden() {
        let tcp = hikkari_sys::TcpInfo { rtt_us: 10000, rttvar_us: 1000, total_retrans: 3, lost: 1, unacked: 2, cwnd: 64, segs_out: 200, segs_in: 201 };
        let r = crate::observe::Report {
            id: 0x1234567890abcdef,
            kind: 1,
            phase: 1,
            port: 8443,
            age_ms: 9999,
            up: 7,
            down: 8,
            chunks: 9,
            resent: 10,
            carriers: 11,
            deaths: 12,
            max_wait_ms: 13,
            end: 1,
            tcp: Some(tcp),
            ..Default::default()
        };
        let mut b = [0u8; OBSERVED_LEN];
        assert_eq!(put_observed(&mut b, &r), OBSERVED_LEN);
        assert_eq!(b[..], unhex(OBSERVED_GOLDEN)[..]);
    }

    #[test]
    fn stats_golden() {
        let s = Stats { opened: 1, reset: 2, resent: 3, up: 4, down: 5, dead_ports: 6, port_kills: 7, paused_ms: 8, rtt_us: Some((10000, 20000, 30000)) };
        let mut b = [0u8; STATS_LEN];
        assert_eq!(put_stats(&mut b, &s), STATS_LEN);
        assert_eq!(b[..], unhex(STATS_GOLDEN)[..]);
        assert!(matches!(parse(&[B_STATS]), Some(Msg::Stats)));
    }
}
