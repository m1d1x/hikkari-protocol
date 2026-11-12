//! The pipe: everything the entry does with each packet of a client's UDP
//! (README.md). It is blind, as the Go entry: a client's datagram channel is
//! QUIC end to end with the exit's relay, so the pipe reads client datagrams
//! as opaque bytes, gives each client address a flow, and carries every
//! datagram as a dgram frame on a wire to the exit.
//!
//! What to carry it on is the brain's (trunk/pipectl): the brain binds the
//! sockets and hands them over, says which wire each class goes on (route),
//! opens flows of its own (its calls on each wire) and reads a tick a second
//! of every wire: members up, how long they have owed an answer, when one
//! last heard the exit. A route changed moves the next datagram, nothing to
//! migrate: the exit answers a flow on the wire the entry last sent it on
//! (trunk flows.go), so no flow is reset by a change of wire.
//!
//! Without a brain (flags, the bench) the pipe binds its own sockets: one
//! client port, one wire, voice and bulk on it.
//!
//! One thread, no runtime, nothing allocated per packet. Under traffic the
//! loop runs on a tick: it sleeps to the next one and takes everything each
//! socket has with recvmmsg, sends with sendmmsg, and glues the frames of all
//! flows bound for one member into one sealed datagram for the tick.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::io;
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use crate::ctl::{self, Ctl, Msg, PipeTick, WireTick, ANY_WIRE, NONE_MS};
use crate::health::{self, Health, Judge, Verdict};
use crate::sys::{self, now_ns, Poll, RecvBatch, SendBatch, BATCH};
use crate::wire::{self, Frame, Seal, DGRAM_HEAD, OVERHEAD};

/// A wire datagram's slot: a sealed datagram of at most this.
pub const SLOT: usize = 2048;
const MAX_CLIENT: usize = 1500;
/// A member's hello is said again this often until answered.
const HELLO_EVERY: u64 = 250_000_000;
/// The members' clock (trunk's tick): pings are sent and debts judged on
/// it, not on every turn of the loop. A pause of the exit ends with every
/// member's pongs at once, a few datagrams apart; judged between the first
/// and the last of them, the others would be buried by the first one's
/// proof.
const CLOCK: u64 = 25_000_000;
/// Members that die together come back spread over this (trunk's
/// replaceSpread), not as one burst of new peers from one box.
const SPREAD: u64 = 1_000_000_000;
const TICK_EVERY: u64 = 1_000_000_000;
const STATS_EVERY: u64 = 10_000_000_000;

pub const CLASS_BULK: u8 = 0;
pub const CLASS_VOICE: u8 = 1;

#[derive(Default)]
struct Fx(u64);
impl Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = (v ^ (v >> 29)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    fn write_u32(&mut self, v: u32) {
        self.write_u64(v as u64)
    }
}
type FxMap<K> = HashMap<K, u32, BuildHasherDefault<Fx>>;

/// Where a flow's answers go.
enum Dest {
    Client { listen: u16, addr: libc::sockaddr_in },
    Brain { tag: u32 },
    Gone,
}

struct Flow {
    dest: Dest,
    seq: u32,
    class: u8,
    /// A wire the flow is held to (the brain's call on a wire): its
    /// datagrams are dropped while that wire has no member up. ANY_WIRE: none.
    pin: u8,
    port: u16,
    copies: u8,
}

/// One member: a socket of its own to the exit, and its glue.
struct Member {
    sock: Option<UdpSocket>,
    fd: i32,
    /// Up, its pings, its debt: spec/trunk.md, "Members' health".
    h: Health,
    hello_at: u64,
    /// Without a brain: when a member taken down gets its new socket (0:
    /// not waiting for one).
    renew_at: u64,
    /// Sealed datagrams waiting for sendmmsg: BATCH slots.
    out: Vec<u8>,
    out_n: usize,
    send: SendBatch,
    /// The frames being glued, at glue[12..12 + glue_n]; glue_since is when
    /// the first of them came (0: empty).
    glue: Box<[u8; SLOT]>,
    glue_n: usize,
    glue_since: u64,
    seal: Seal,
    dgrams: u64,
}

impl Member {
    fn new(sock: Option<UdpSocket>, key: &[u8; 32]) -> Member {
        let mut prefix = [0u8; 4];
        sys::urandom(&mut prefix);
        let fd = sock.as_ref().map_or(-1, |s| s.as_raw_fd());
        Member {
            sock,
            fd,
            h: Health::new(true),
            hello_at: 0,
            renew_at: 0,
            out: vec![0; SLOT * BATCH],
            out_n: 0,
            send: SendBatch::new(),
            glue: Box::new([0; SLOT]),
            glue_n: 0,
            glue_since: 0,
            seal: Seal::from_key(key, prefix),
            dgrams: 0,
        }
    }

    /// A new socket: the member starts over with its hello.
    fn set_sock(&mut self, sock: Option<UdpSocket>) {
        self.fd = sock.as_ref().map_or(-1, |s| s.as_raw_fd());
        self.sock = sock;
        self.h.down();
        self.hello_at = 0;
        self.renew_at = 0;
        self.glue_n = 0;
        self.glue_since = 0;
        self.out_n = 0;
        self.send.n = 0;
    }

    /// Seals the glued frames into the next out slot; sends the batch when
    /// it is full.
    fn seal_glue(&mut self) {
        if self.glue_n == 0 {
            return;
        }
        if self.out_n == BATCH {
            self.flush_out();
        }
        let slot = &mut self.out[self.out_n * SLOT..(self.out_n + 1) * SLOT];
        slot[12..12 + self.glue_n].copy_from_slice(&self.glue[12..12 + self.glue_n]);
        let n = self.seal.seal(slot, self.glue_n);
        let ptr = slot.as_ptr();
        self.send.push(ptr, n, None);
        self.out_n += 1;
        self.glue_n = 0;
        self.glue_since = 0;
        self.dgrams += 1;
    }

    fn flush_out(&mut self) {
        if self.out_n > 0 {
            self.send.flush(self.fd);
            self.out_n = 0;
        }
    }

    /// Puts one frame (written by `put` into the glue) in, sealing first
    /// when it would not fit; a frame alone over the limit goes alone.
    #[inline]
    fn glue_frame(&mut self, need: usize, max: usize, now: u64, put: impl FnOnce(&mut [u8]) -> usize) {
        if self.glue_n > 0 && OVERHEAD + self.glue_n + need > max {
            self.seal_glue();
        }
        let n = put(&mut self.glue[12 + self.glue_n..]);
        self.glue_n += n;
        if self.glue_since == 0 {
            self.glue_since = now;
        }
    }
}

struct Wire {
    id: u8,
    glue_ns: u64,
    glue_max: usize,
    /// Its members' stall (trunk Config.Stall): the brain's dead_ms.
    stall_ns: u64,
    key: [u8; 32],
    members: Vec<Member>,
    /// Without a brain: where a member's new socket goes.
    exit: Option<SocketAddrV4>,
    /// When one of its members last proved its round trip (0: never).
    proof: u64,
    t: WireTick,
}

impl Wire {
    fn up(&self) -> usize {
        self.members.iter().filter(|m| m.h.up).count()
    }
}

struct Listen {
    id: u8,
    sock: UdpSocket,
    class: u8,
    to: u16,
    copies: u8,
    down: SendBatch,
}

/// What a socket in the poll set is.
#[derive(Clone, Copy)]
enum Slot {
    Ctl,
    Listen(usize),
    Member(usize, usize),
}

/// A member event for the brain, sent after the walk that found it.
#[derive(Clone, Copy)]
struct Event {
    wire: u8,
    index: u8,
    up: bool,
    why: u8,
}

/// Flags of a pipe without a brain (the bench).
pub struct Alone {
    pub listen: SocketAddrV4,
    pub exit: SocketAddrV4,
    pub key: String,
    pub members: usize,
    pub glue_ns: u64,
    pub glue_max: usize,
    pub to: u16,
    pub wire: u8,
}

pub struct Pipe {
    ctl: Option<Ctl>,
    session: [u8; 16],
    gro: bool,
    tick_ns: u64,
    listens: Vec<Listen>,
    wires: Vec<Wire>,
    /// The wire of each class: [bulk, voice].
    route: [u8; 2],
    flows: Vec<Flow>,
    live_flows: u32,
    by_addr: FxMap<u64>,
    by_tag: FxMap<u32>,
    poll: Poll,
    slots: Vec<Slot>,
    dirty: bool,
    crecv: RecvBatch,
    wrecv: RecvBatch,
    msg: Vec<u8>,
    out: Vec<u8>,
    fds: Vec<i32>,
    events: Vec<Event>,
    tok: u64,
    /// The session's proof and the pipe's own pauses.
    judge: Judge,
    clock_at: u64,
    late_max: u64,
    tick_at: u64,
    stats_at: u64,
    moved: u64,
    bad: u64,
}

impl Pipe {
    fn new(ctl: Option<Ctl>, gro: bool, tick_ns: u64) -> Pipe {
        let mut session = [0u8; 16];
        sys::urandom(&mut session);
        let now = now_ns();
        Pipe {
            ctl,
            session,
            gro,
            tick_ns,
            listens: Vec::new(),
            wires: Vec::new(),
            route: [ANY_WIRE, ANY_WIRE],
            flows: Vec::with_capacity(4096),
            live_flows: 0,
            by_addr: HashMap::with_capacity_and_hasher(4096, Default::default()),
            by_tag: HashMap::with_capacity_and_hasher(64, Default::default()),
            poll: Poll::new(),
            slots: Vec::new(),
            dirty: true,
            // With GRO one read may hold many datagrams of one client.
            crecv: RecvBatch::new(if gro { 65536 } else { MAX_CLIENT }),
            wrecv: RecvBatch::new(SLOT),
            msg: vec![0; 65536],
            out: vec![0; 65536],
            fds: Vec::with_capacity(ctl::MAX_FDS),
            events: Vec::with_capacity(64),
            tok: 0,
            judge: Judge::new(health::QUIET),
            clock_at: now,
            late_max: 0,
            tick_at: now + TICK_EVERY,
            stats_at: now,
            moved: 0,
            bad: 0,
        }
    }

    /// A pipe the brain runs over the socket at fd (the pipe's end of the
    /// brain's socketpair). It says hello and waits for the brain's.
    pub fn with_brain(fd: i32, gro: bool, tick_ns: u64) -> Pipe {
        let mut c = Ctl::new(fd);
        let mut b = [0u8; 16];
        let n = ctl::put_hello(&mut b, std::process::id());
        c.send(&b[..n]);
        Pipe::new(Some(c), gro, tick_ns)
    }

    /// A pipe without a brain: its own client port and one wire, voice and
    /// bulk on it (the bench's flags).
    pub fn alone(a: &Alone, tick_ns: u64, gro: bool) -> io::Result<Pipe> {
        let mut p = Pipe::new(None, gro, tick_ns);
        let sock = UdpSocket::bind(a.listen)?;
        sys::tune(&sock, gro)?;
        p.listens.push(Listen { id: 0, sock, class: CLASS_VOICE, to: a.to, copies: 1, down: SendBatch::new() });
        let key = wire::key(&a.key);
        let mut w = Wire {
            id: a.wire,
            glue_ns: a.glue_ns,
            glue_max: a.glue_max,
            stall_ns: health::STALL,
            key,
            members: Vec::new(),
            exit: Some(a.exit),
            proof: 0,
            t: WireTick { id: a.wire, ..Default::default() },
        };
        for _ in 0..a.members {
            w.members.push(Member::new(Some(member_to(a.exit)?), &key));
        }
        p.wires.push(w);
        p.route = [a.wire, a.wire];
        Ok(p)
    }

    /// Runs until the brain is gone (forever without one).
    pub fn run(&mut self) {
        let mut sleep_at = 0u64;
        let mut busy = false;
        let mut prev = 0u64;
        loop {
            let now = now_ns();
            // Before the clock: a member's debt counts from the end of a
            // pause of the pipe's own.
            self.judge.turn(prev, now);
            prev = now;
            let next = self.timers(now);
            if self.dirty {
                self.rebuild_poll();
            }
            // Under traffic the loop runs on a tick: a wakeup is paid once per
            // tick and not once per packet. A tick that moved nothing goes
            // back to waiting for the first packet (an idle pipe sleeps).
            let due = if self.tick_ns > 0 && busy {
                sleep_at = if sleep_at + self.tick_ns > now { sleep_at + self.tick_ns } else { now + self.tick_ns };
                let due = sleep_at.min(next.max(now));
                sys::sleep_until(due);
                self.poll.all();
                due
            } else {
                let due = next.max(now);
                self.poll.wait(due - now);
                sleep_at = now_ns();
                due
            };
            let now = now_ns();
            if now > due {
                let late = now - due;
                self.late_max = self.late_max.max(late);
            }
            let moved0 = self.moved;
            if !self.from_brain() {
                return;
            }
            if self.dirty {
                // The sockets changed under the poll: read every one once.
                self.rebuild_poll();
                self.poll.all();
            }
            self.from_clients();
            self.seal_due();
            self.from_wires();
            busy = self.moved != moved0;
        }
    }

    fn rebuild_poll(&mut self) {
        self.slots.clear();
        if self.ctl.is_some() {
            self.slots.push(Slot::Ctl);
        }
        for i in 0..self.listens.len() {
            self.slots.push(Slot::Listen(i));
        }
        for (wi, w) in self.wires.iter().enumerate() {
            for (mi, m) in w.members.iter().enumerate() {
                if m.fd >= 0 {
                    self.slots.push(Slot::Member(wi, mi));
                }
            }
        }
        let (listens, wires, ctl) = (&self.listens, &self.wires, &self.ctl);
        self.poll.set(self.slots.iter().map(|s| match *s {
            Slot::Ctl => ctl.as_ref().unwrap().fd,
            Slot::Listen(i) => listens[i].sock.as_raw_fd(),
            Slot::Member(w, m) => wires[w].members[m].fd,
        }));
        self.dirty = false;
    }

    /// The members' own talk and health (hello until answered; on the
    /// members' clock a ping every 100 ms and the debts judged, health.rs),
    /// the brain's tick, the stats line; returns when the next of them is
    /// due.
    fn timers(&mut self, now: u64) -> u64 {
        let clock = now >= self.clock_at;
        if clock {
            self.clock_at = if self.clock_at + CLOCK > now { self.clock_at + CLOCK } else { now + CLOCK };
        }
        let mut next = self.clock_at;
        let alone = self.ctl.is_none();
        let Pipe { wires, judge, tok, events, session, dirty, .. } = self;
        for w in wires.iter_mut() {
            for (mi, m) in w.members.iter_mut().enumerate() {
                if m.renew_at != 0 {
                    if now >= m.renew_at {
                        // Alone the pipe dials its own: a new socket is a
                        // new peer to the exit, joined by its hello.
                        let sock = w.exit.and_then(|exit| member_to(exit).ok());
                        m.set_sock(sock);
                        *dirty = true;
                    } else {
                        next = next.min(m.renew_at);
                    }
                }
                if m.fd < 0 {
                    continue;
                }
                if !m.h.up {
                    if now >= m.hello_at {
                        let mut h = [0u8; 64];
                        let n = wire::hello_t2(&mut h[12..], session, w.id);
                        let n = m.seal.seal(&mut h, n);
                        if let Some(s) = &m.sock {
                            let _ = s.send(&h[..n]);
                        }
                        m.hello_at = now + HELLO_EVERY;
                    }
                    next = next.min(m.hello_at);
                } else if clock {
                    match m.h.tick(judge, w.stall_ns, now, tok) {
                        Verdict::Fine => {}
                        Verdict::Ping(t) => {
                            m.glue_frame(9, w.glue_max, now, |b| wire::put_ping(b, wire::F_PING, t));
                            m.seal_glue();
                            m.flush_out();
                        }
                        Verdict::Dead { quiet } => {
                            let why = if quiet { ctl::WHY_QUIET } else { ctl::WHY_SILENT };
                            events.push(Event { wire: w.id, index: mi as u8, up: false, why });
                            // Its socket goes now: what comes on it is no
                            // member's. The brain answers the event with a
                            // new one; alone the pipe dials it within SPREAD.
                            m.set_sock(None);
                            *dirty = true;
                            if alone {
                                let mut r = [0u8; 8];
                                sys::urandom(&mut r);
                                m.renew_at = now + 1 + u64::from_le_bytes(r) % SPREAD;
                                next = next.min(m.renew_at);
                            }
                            continue;
                        }
                    }
                }
                if m.glue_since != 0 {
                    next = next.min(m.glue_since + w.glue_ns);
                }
            }
        }
        self.send_events();
        if now >= self.tick_at {
            self.send_tick(now);
            self.tick_at = if self.tick_at + TICK_EVERY > now { self.tick_at + TICK_EVERY } else { now + TICK_EVERY };
        }
        if now - self.stats_at >= STATS_EVERY {
            self.stats_at = now;
            self.log_stats();
        }
        next.min(self.tick_at)
    }

    /// Member events go to the brain at once, and a tick after them: the
    /// selector reads a wire's members from ticks, and need not wait for the
    /// next second to see one gone.
    fn send_events(&mut self) {
        if self.events.is_empty() {
            return;
        }
        let tick = self.ctl.is_some();
        for e in std::mem::take(&mut self.events) {
            match &mut self.ctl {
                Some(c) => {
                    let mut b = [0u8; 8];
                    let n = ctl::put_member(&mut b, e.wire, e.index, e.up, e.why);
                    c.send(&b[..n]);
                }
                None => eprintln!("hk-pipe: wire {} member {} {} (why {})", e.wire, e.index, if e.up { "up" } else { "down" }, e.why),
            }
        }
        if tick {
            self.send_tick(now_ns());
        }
    }

    fn send_tick(&mut self, now: u64) {
        let p = PipeTick {
            pause_ago_ms: if self.judge.resumed == 0 { NONE_MS } else { ms(now - self.judge.resumed) },
            pauses: self.judge.pauses,
            late_max_us: (self.late_max / 1000).min(u32::MAX as u64) as u32,
            flows: self.live_flows,
        };
        self.late_max = 0;
        let Some(c) = &mut self.ctl else { return };
        let mut ticks = [WireTick::default(); 32];
        let mut n = 0;
        for w in self.wires.iter().take(ticks.len()) {
            let mut t = w.t;
            t.members = w.members.len() as u8;
            t.up = w.up() as u8;
            t.owed_ms = 0;
            t.rtt_us = 0;
            let mut first = true;
            for m in w.members.iter().filter(|m| m.h.up) {
                let owed = ms(m.h.owed(&self.judge, now));
                t.owed_ms = if first { owed } else { t.owed_ms.min(owed) };
                first = false;
                if m.h.rtt > 0 {
                    let us = (m.h.rtt / 1000) as u32;
                    t.rtt_us = if t.rtt_us == 0 { us } else { t.rtt_us.min(us) };
                }
            }
            t.proof_ago_ms = if w.proof == 0 { NONE_MS } else { ms(now - w.proof) };
            t.dgrams = w.members.iter().map(|m| m.dgrams).sum();
            t.dropped += w.members.iter().map(|m| m.send.dropped).sum::<u64>();
            ticks[n] = t;
            n += 1;
        }
        let len = ctl::put_tick(&mut self.out, &p, &ticks[..n]);
        c.send(&self.out[..len]);
    }

    fn log_stats(&self) {
        let mut s = format!("hk-pipe: flows={} route=bulk:{},voice:{} pauses={} bad={}", self.live_flows, self.route[0], self.route[1], self.judge.pauses, self.bad);
        for w in &self.wires {
            s += &format!(
                " | wire {} up={}/{} in={} out={} dgrams={} frames/dgram={:.2}",
                w.id,
                w.up(),
                w.members.len(),
                w.t.up_pkts,
                w.t.down_pkts,
                w.members.iter().map(|m| m.dgrams).sum::<u64>(),
                w.t.up_pkts as f64 / w.members.iter().map(|m| m.dgrams).sum::<u64>().max(1) as f64
            );
        }
        eprintln!("{s}");
    }

    /// The brain's messages, all there are; false once the brain is gone.
    fn from_brain(&mut self) -> bool {
        if self.ctl.is_none() || !self.poll.readable(0) {
            return true;
        }
        loop {
            self.fds.clear();
            let r = self.ctl.as_mut().unwrap().recv(&mut self.msg, &mut self.fds);
            match r {
                Ok(None) => return true,
                Ok(Some(0)) => return false,
                Ok(Some(n)) => {
                    if let Err(e) = self.handle(n) {
                        self.error(&e);
                    }
                    for fd in self.fds.drain(..) {
                        unsafe { libc::close(fd) }; // sockets the message did not take
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => self.error(&e.to_string()),
                Err(_) => return false,
            }
        }
    }

    fn error(&mut self, e: &str) {
        let mut b = Vec::with_capacity(1 + e.len());
        b.push(ctl::P_ERROR);
        b.extend_from_slice(e.as_bytes());
        if let Some(c) = &mut self.ctl {
            c.send(&b);
        }
    }

    /// One message of n bytes in self.msg, its sockets in self.fds (what it
    /// takes it removes from there).
    fn handle(&mut self, n: usize) -> Result<(), String> {
        let Pipe { msg, fds, wires, flows, route, listens, by_tag, live_flows, dirty, gro, moved, .. } = self;
        let Some(m) = ctl::parse(&msg[..n]) else {
            return Err(format!("a message the pipe does not know: type {:#x}, {} bytes", msg[0], n));
        };
        let now = now_ns();
        match m {
            Msg::Hello { ver } => {
                if ver != ctl::VERSION {
                    return Err(format!("brain speaks version {ver}, the pipe {}", ctl::VERSION));
                }
            }
            Msg::Listen { id, class, to, copies } => {
                if fds.len() != 1 {
                    return Err(format!("listen {id}: {} sockets, want 1", fds.len()));
                }
                let sock = sys::udp_from_fd(fds.remove(0)).map_err(|e| e.to_string())?;
                sys::tune(&sock, *gro).map_err(|e| format!("listen {id}: {e}"))?;
                let l = Listen { id, sock, class, to, copies, down: SendBatch::new() };
                match listens.iter_mut().find(|l| l.id == id) {
                    Some(old) => *old = l,
                    None => listens.push(l),
                }
                *dirty = true;
            }
            Msg::Wire { id, form, glue_us, glue_max, dead_ms, key } => {
                if form != ctl::FORM_UDP {
                    return Err(format!("wire {id}: form {form} is not one the pipe carries"));
                }
                if id == ANY_WIRE {
                    return Err("wire 255 is no wire".into());
                }
                let mut socks = Vec::with_capacity(fds.len());
                for fd in fds.drain(..) {
                    let s = sys::udp_from_fd(fd).map_err(|e| e.to_string())?;
                    sys::tune(&s, false).map_err(|e| format!("wire {id}: {e}"))?;
                    socks.push(s);
                }
                let at = match wires.iter().position(|w| w.id == id) {
                    Some(i) => i,
                    None => {
                        wires.push(Wire {
                            id,
                            glue_ns: 0,
                            glue_max: 0,
                            stall_ns: health::STALL,
                            key,
                            members: Vec::new(),
                            exit: None,
                            proof: 0,
                            t: WireTick { id, ..Default::default() },
                        });
                        wires.len() - 1
                    }
                };
                let w = &mut wires[at];
                w.glue_ns = glue_us as u64 * 1000;
                w.glue_max = (glue_max as usize).clamp(64, SLOT - OVERHEAD);
                w.stall_ns = dead_ms.max(1) as u64 * 1_000_000;
                // New sockets (or a new key) start the members over; a member
                // keeps its counters.
                let rekey = w.key != key;
                w.key = key;
                w.members.truncate(socks.len());
                for (i, s) in socks.into_iter().enumerate() {
                    match w.members.get_mut(i) {
                        Some(m) => {
                            m.set_sock(Some(s));
                            if rekey {
                                let mut prefix = [0u8; 4];
                                sys::urandom(&mut prefix);
                                m.seal = Seal::from_key(&key, prefix);
                            }
                        }
                        None => w.members.push(Member::new(Some(s), &key)),
                    }
                }
                *dirty = true;
            }
            Msg::Unwire { id } => {
                wires.retain(|w| w.id != id);
                *dirty = true;
            }
            Msg::Route { voice, bulk } => *route = [bulk, voice],
            Msg::Open { tag, class, pin, port, copies } => {
                if by_tag.contains_key(&tag) {
                    return Err(format!("flow tag {tag} is open already"));
                }
                flows.push(Flow { dest: Dest::Brain { tag }, seq: 0, class, pin, port, copies });
                by_tag.insert(tag, flows.len() as u32);
                *live_flows += 1;
            }
            Msg::Dgram { tag, payload } => {
                let Some(&id) = by_tag.get(&tag) else {
                    return Ok(()); // closed under it
                };
                carry(wires, *route, &mut flows[id as usize - 1], id, payload, now);
                *moved += 1;
            }
            Msg::Close { tag } => {
                if let Some(id) = by_tag.remove(&tag) {
                    flows[id as usize - 1].dest = Dest::Gone;
                    *live_flows -= 1;
                }
            }
            Msg::Member { wire, index } => {
                if fds.len() != 1 {
                    return Err(format!("member {wire}/{index}: {} sockets, want 1", fds.len()));
                }
                let s = sys::udp_from_fd(fds.remove(0)).map_err(|e| e.to_string())?;
                sys::tune(&s, false).map_err(|e| e.to_string())?;
                let Some(m) = wires.iter_mut().find(|w| w.id == wire).and_then(|w| w.members.get_mut(index as usize)) else {
                    return Err(format!("member {wire}/{index}: no such member"));
                };
                m.set_sock(Some(s));
                *dirty = true;
            }
        }
        Ok(())
    }

    /// Clients → wires.
    fn from_clients(&mut self) {
        let Pipe { poll, slots, listens, crecv, flows, by_addr, wires, route, live_flows, moved, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            let Slot::Listen(li) = *s else { continue };
            if !poll.readable(si) {
                continue;
            }
            let l = &listens[li];
            let fd = l.sock.as_raw_fd();
            loop {
                let n = crecv.recv(fd);
                let now = now_ns();
                for i in 0..n {
                    let key = ((li as u64) << 48) | sys::addr_key(&crecv.addr[i]);
                    let id = match by_addr.get(&key) {
                        Some(&id) => id,
                        None => {
                            flows.push(Flow {
                                dest: Dest::Client { listen: li as u16, addr: crecv.addr[i] },
                                seq: 0,
                                class: l.class,
                                pin: ANY_WIRE,
                                port: l.to,
                                copies: l.copies,
                            });
                            *live_flows += 1;
                            let id = flows.len() as u32;
                            by_addr.insert(key, id);
                            id
                        }
                    };
                    let seg = crecv.seg[i];
                    let len = crecv.len[i];
                    let step = if seg == 0 { len } else { seg };
                    let base = i * crecv.slot;
                    let f = &mut flows[id as usize - 1];
                    let mut at = 0;
                    while at < len {
                        let p = &crecv.buf[base + at..base + (at + step).min(len)];
                        carry(wires, *route, f, id, p, now);
                        *moved += 1;
                        at += step;
                    }
                }
                if n < BATCH {
                    break;
                }
            }
        }
    }

    /// Seals what waited its window (on a tick: the tick is the window) and
    /// sends every member's batch.
    fn seal_due(&mut self) {
        let now = now_ns();
        let tick = self.tick_ns > 0;
        for w in self.wires.iter_mut() {
            for m in w.members.iter_mut() {
                if m.glue_since != 0 && (tick || w.glue_ns == 0 || now - m.glue_since >= w.glue_ns) {
                    m.seal_glue();
                }
                m.flush_out();
            }
        }
    }

    /// Wires → clients and the brain.
    fn from_wires(&mut self) {
        let Pipe { poll, slots, wires, wrecv, flows, listens, ctl, out, events, moved, bad, judge, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            let Slot::Member(wi, mi) = *s else { continue };
            if !poll.readable(si) {
                continue;
            }
            let w = &mut wires[wi];
            let (wid, glue_max) = (w.id, w.glue_max);
            let m = &mut w.members[mi];
            if m.fd < 0 {
                continue;
            }
            loop {
                let n = wrecv.recv(m.fd);
                let now = now_ns();
                for i in 0..n {
                    let slot = wrecv.slot;
                    let len = wrecv.len[i];
                    let d = &mut wrecv.buf[i * slot..i * slot + len];
                    let Some(pn) = m.seal.open(d) else {
                        *bad += 1;
                        continue;
                    };
                    let p = &d[12..12 + pn];
                    let mut at = 0;
                    while let Some((fr, nx)) = wire::next_frame(p, at) {
                        match fr {
                            Frame::Dgram { stream, off, len } => {
                                w.t.down_pkts += 1;
                                w.t.down_bytes += len as u64;
                                *moved += 1;
                                match flows.get((stream as usize).wrapping_sub(1)).map(|f| &f.dest) {
                                    Some(Dest::Client { listen, addr }) => {
                                        let l = &mut listens[*listen as usize];
                                        if l.down.full() {
                                            l.down.flush(l.sock.as_raw_fd());
                                        }
                                        l.down.push(p[off..].as_ptr(), len, Some(addr));
                                    }
                                    Some(Dest::Brain { tag }) => {
                                        if let Some(c) = ctl {
                                            let k = ctl::put_dgram(out, *tag, &p[off..off + len]);
                                            c.send(&out[..k]);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Frame::Hello => {
                                if !m.h.up {
                                    m.h.join(now);
                                    events.push(Event { wire: wid, index: mi as u8, up: true, why: ctl::WHY_HELLO });
                                }
                            }
                            Frame::Ping(t) => {
                                m.glue_frame(9, glue_max, now, |b| wire::put_ping(b, wire::F_PONG, t));
                            }
                            Frame::Pong(t) => {
                                if m.h.pong(judge, t, now) {
                                    w.proof = now;
                                }
                            }
                            Frame::Drain | Frame::Other => {}
                        }
                        at = nx;
                    }
                }
                // The answers point into wrecv: send them before reading again.
                for l in listens.iter_mut() {
                    l.down.flush(l.sock.as_raw_fd());
                }
                if n < BATCH {
                    break;
                }
            }
            if m.glue_n > 0 {
                m.seal_glue(); // pongs go at once
                m.flush_out();
            }
        }
        self.send_events();
    }
}

/// Carries one datagram of flow id on its wire: the pin, else its class's
/// route; a wire with no member up is passed over for any member that can
/// carry it (trunk Route), a pinned flow's datagram is dropped instead. A
/// flow keeps to one member of the wire while it is up: its datagrams stay in
/// order.
#[inline]
fn carry(wires: &mut [Wire], route: [u8; 2], f: &mut Flow, id: u32, p: &[u8], now: u64) {
    if matches!(f.dest, Dest::Gone) {
        return;
    }
    let strict = f.pin != ANY_WIRE;
    let want = if strict { f.pin } else { route[(f.class & 1) as usize] };
    let mut wi = wires.iter().position(|w| w.id == want && w.members.iter().any(|m| m.h.up));
    if wi.is_none() {
        if strict {
            if let Some(w) = wires.iter_mut().find(|w| w.id == want) {
                w.t.dropped += 1;
            }
            return;
        }
        let n = wires.iter().filter(|w| w.members.iter().any(|m| m.h.up)).count();
        if n == 0 {
            let at = wires.iter().position(|w| w.id == want).unwrap_or(0);
            if let Some(w) = wires.get_mut(at) {
                w.t.dropped += 1;
            }
            return;
        }
        let k = id as usize % n;
        wi = wires.iter().enumerate().filter(|(_, w)| w.members.iter().any(|m| m.h.up)).map(|(i, _)| i).nth(k);
    }
    let w = &mut wires[wi.unwrap()];
    f.seq = f.seq.wrapping_add(1);
    let (seq, port) = (f.seq, f.port);
    let n = w.members.len();
    let copies = f.copies.max(1) as usize;
    let start = id as usize % n;
    let mut sent = 0;
    for k in 0..n {
        let m = &mut w.members[(start + k) % n];
        if !m.h.up {
            continue;
        }
        m.glue_frame(DGRAM_HEAD + p.len(), w.glue_max, now, |b| wire::put_dgram(b, id, seq, port, p));
        sent += 1;
        if sent == copies {
            break;
        }
    }
    w.t.up_pkts += 1;
    w.t.up_bytes += p.len() as u64;
}

/// A member's socket to the exit, bound by the pipe (no brain).
fn member_to(exit: SocketAddrV4) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect(exit)?;
    sys::tune(&s, false)?;
    Ok(s)
}

fn ms(ns: u64) -> u32 {
    (ns / 1_000_000).min(u32::MAX as u64 - 1) as u32
}
