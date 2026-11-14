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
//!
//! The loop is here; its parts: brain.rs (the brain's messages and the
//! ticks to it), timers.rs (members' hello, pings and deaths), data.rs
//! (clients → wires → clients), tcp.rs and death.rs (streams), session.rs
//! (the exit's drain: sessions), generation.rs (the pipe's own reload),
//! pool.rs (the brain's client ports of streams and pools), h3.rs (the
//! Chromium QUIC wire's members: tunnels from the book's ports).

mod brain;
mod data;
mod death;
mod generation;
mod h3;
mod pool;
mod session;
mod tcp;
mod timers;

use std::collections::BTreeSet;
use std::io;
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use generation::Older;
use session::Sess;
use tcp::{TcpListen, Why};

use hikkari_sys::{self as sys, now_ns, Poll, RecvBatch, SendBatch, SeqPacket};
use hikkari_trunk::flow::FLOW_IDLE_NS;
use hikkari_trunk::health::{self, Judge};
use hikkari_trunk::ports::{self, Book};
use hikkari_trunk::udpwire;

use crate::ctl::{self, WireTick, ANY_WIRE};
use crate::flow::{Flows, FxMap, CLASS_VOICE};
use crate::link::{Reach, StreamWire};
use crate::member::{member_to, Member, Wire, SLOT};
use crate::streams::Streams;

const MAX_CLIENT: usize = 1500;
/// The pool's wire (trunk PoolWire): without a brain, the streams' only one.
const POOL_WIRE: u8 = 0;

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
    /// A client port of streams, a client's stream (its slot), a stream
    /// member (wire, member).
    TcpListen(usize),
    Client(usize),
    Link(usize, usize),
    /// The handoff socket to the newer generation (this pipe drains), to
    /// an older one (this pipe adopted it).
    Newer,
    Older(usize),
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
    /// Members that carry each client datagram (the brain's listen copies).
    pub copies: u8,
    /// A client port of streams (None: none), the exit's port its streams
    /// go to, and the wire of stream members that carries them: the exit's
    /// plain TCP member port, how many members.
    pub tcp_listen: Option<SocketAddrV4>,
    pub tcp_to: u16,
    pub tcp_exit: SocketAddrV4,
    pub tcp_members: usize,
    /// The stream members' source ports: [lo, hi].
    pub ports: (u16, u16),
    /// The stream members by Chromium's CONNECT to the exit's relay at
    /// tcp_exit instead of plain TCP, on this engine (None: plain).
    pub tcp_chromium: Option<hikkari_cronet::Engine>,
    /// The wire is the Chromium QUIC wire to the exit's QUIC port at `exit`
    /// instead of the bare UDP wire: its certificate's domain, the PEM roots
    /// it is checked by (None: the system's), how the members use their
    /// sessions. Their source ports come from `ports`.
    pub h3: Option<(String, Option<String>, hikkari_cronet::Usage)>,
}

pub struct Pipe {
    ctl: Option<SeqPacket>,
    /// The sessions (session.rs) by index, a slot used again once closed:
    /// the current one, the one coming up for the exit's drain, retired
    /// ones; the sessions whose members heard the exit drain this turn, a
    /// bit each; what packet wires of closed sessions counted.
    sessions: Vec<Sess>,
    cur: u8,
    next: Option<u8>,
    drains: u32,
    gone: Vec<WireTick>,
    take_over_ns: u64,
    retire_ns: u64,
    gro: bool,
    tick_ns: u64,
    /// A client's flow unused this long ends (trunk FlowIdle).
    flow_idle_ns: u64,
    listens: Vec<Listen>,
    wires: Vec<Wire>,
    /// The Chromium QUIC wires' engines and books, by wire id (h3.rs).
    h3s: Vec<h3::H3>,
    /// The wire of each class, by class (CLASS_BULK, CLASS_VOICE).
    route: [u8; 2],
    flows: Flows,
    tcp_listens: Vec<TcpListen>,
    swires: Vec<StreamWire>,
    /// The stream members' source ports (spec/trunk.md, "Members' health")
    /// and their range, [lo, hi].
    ports: Book,
    ports_range: (u16, u16),
    streams: Streams,
    /// What acks of one read confirmed: (carrier, bytes), applied after it.
    released: Vec<(u32, u32)>,
    /// Streams with things a dead member carried, waiting to go again, by id
    /// (the order they were opened).
    stranded: BTreeSet<u32>,
    /// Streams to end after the pass that found them done or failed.
    doomed: Vec<(usize, Why)>,
    /// The generations (generation.rs): the newer one this pipe drains to,
    /// the older ones draining to it, the client addresses (owner keys)
    /// whose flows an older one keeps, by its index in older; the keys of
    /// flows the last sweep ended; whether the brain heard it drained.
    newer: Option<SeqPacket>,
    older: Vec<Older>,
    owners: FxMap<u64>,
    freed: Vec<u64>,
    drained: bool,
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
    fn new(ctl: Option<SeqPacket>, gro: bool, tick_ns: u64) -> Pipe {
        let now = now_ns();
        Pipe {
            ctl,
            sessions: vec![Sess::new(now)],
            cur: 0,
            next: None,
            drains: 0,
            gone: Vec::new(),
            take_over_ns: session::TAKE_OVER_NS,
            retire_ns: session::RETIRE_NS,
            gro,
            tick_ns,
            flow_idle_ns: FLOW_IDLE_NS,
            listens: Vec::new(),
            wires: Vec::new(),
            h3s: Vec::new(),
            route: [ANY_WIRE, ANY_WIRE],
            flows: Flows::new(),
            tcp_listens: Vec::new(),
            swires: Vec::new(),
            ports: Book::new(ports::LO, ports::HI, ports::DEAD_FOR_NS).expect("the default range is a valid one"),
            ports_range: (ports::LO, ports::HI),
            streams: Streams::new(),
            released: Vec::with_capacity(256),
            stranded: BTreeSet::new(),
            doomed: Vec::with_capacity(64),
            newer: None,
            older: Vec::new(),
            owners: FxMap::default(),
            freed: Vec::with_capacity(256),
            drained: false,
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
            tick_at: now + timers::TICK_EVERY,
            stats_at: now,
            moved: 0,
            bad: 0,
        }
    }

    /// A pipe the brain runs over the socket at fd (the pipe's end of the
    /// brain's socketpair). It says hello and waits for the brain's.
    pub fn with_brain(fd: i32, gro: bool, tick_ns: u64) -> Pipe {
        let mut c = SeqPacket::new(fd, ctl::MAX_FDS);
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
        p.listens.push(Listen { id: 0, sock, class: CLASS_VOICE, to: a.to, copies: a.copies, down: SendBatch::new() });
        if a.members > 0 {
            let key = match &a.h3 {
                Some(_) => hikkari_trunk::h3dgram::token(&a.key),
                None => udpwire::key(&a.key),
            };
            let mut w = Wire::new(a.wire, key, health::STALL);
            w.glue_ns = a.glue_ns;
            w.glue_max = a.glue_max;
            w.exit = Some(a.exit);
            if let Some((sni, roots, usage)) = &a.h3 {
                let f = h3::Form { exit: a.exit, sni: sni.clone(), roots: roots.clone(), usage: *usage, ports: a.ports, token: key };
                p.h3s.push(h3::H3::new(a.wire, f).map_err(io::Error::other)?);
                w.h3 = true;
                w.glue_max = a.glue_max.min(h3::frames_max(*usage));
            }
            for _ in 0..a.members {
                let fmax = a.h3.as_ref().map_or(0, |h| h3::frames_max(h.2));
                let m = if w.h3 { Member::plain(&key, fmax) } else { Member::new(Some(member_to(a.exit)?), &key) };
                w.members.push(m);
            }
            p.wires.push(w);
            p.route = [a.wire, a.wire];
        } else {
            // No packet members: the datagrams ride the pool's wire.
            p.route = [POOL_WIRE, POOL_WIRE];
        }
        if let Some(addr) = a.tcp_listen {
            p.tcp_listens.push(TcpListen { id: 0, fd: sys::tcp_listen(addr)?, to: a.tcp_to });
            let reach = match &a.tcp_chromium {
                Some(engine) => Reach::Chromium(engine.clone()),
                None => Reach::Plain(a.tcp_exit),
            };
            p.ports = Book::new(a.ports.0, a.ports.1, ports::DEAD_FOR_NS).map_err(io::Error::other)?;
            p.ports_range = a.ports;
            p.swires.push(StreamWire::new(POOL_WIRE, reach, a.tcp_members, health::STALL));
            let now = now_ns();
            for li in 0..a.tcp_members {
                p.redial(0, li, now);
            }
        }
        Ok(p)
    }

    /// A client's flow unused for idle_ns ends; the trunk's is 2 minutes,
    /// tests take less.
    pub fn set_flow_idle(&mut self, idle_ns: u64) {
        self.flow_idle_ns = idle_ns.max(1);
    }

    /// A new session takes over after take_over_ns without a quarter of its
    /// pool, a retired one is cut after retire_ns (the trunk's 10 s and 30
    /// minutes; tests take less).
    pub fn set_session_limits(&mut self, take_over_ns: u64, retire_ns: u64) {
        self.take_over_ns = take_over_ns.max(1);
        self.retire_ns = retire_ns.max(1);
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
            let tcp = self.has_tcp();
            if tcp {
                self.want_tcp();
            }
            let due = if self.tick_ns > 0 && busy {
                sleep_at = if sleep_at + self.tick_ns > now { sleep_at + self.tick_ns } else { now + self.tick_ns };
                let due = sleep_at.min(next.max(now));
                sys::sleep_until(due);
                // Stream sockets are many and mostly idle: read the ones the
                // kernel says are ready, not all of them each tick.
                if tcp {
                    self.poll.wait(0);
                } else {
                    self.poll.all();
                }
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
            if !self.read_brain() {
                return;
            }
            self.read_generations();
            if self.dirty {
                // The sockets changed under the poll: read every one once.
                self.rebuild_poll();
                self.poll.all();
            }
            let now = now_ns();
            self.read_clients();
            self.accept_clients();
            self.open_streams(now);
            self.read_streams(now);
            self.seal_due();
            self.read_wires();
            self.read_links(now);
            self.write_clients();
            self.flush_links(now);
            busy = self.moved != moved0;
        }
    }

    fn rebuild_poll(&mut self) {
        self.slots.clear();
        if self.ctl.is_some() {
            self.slots.push(Slot::Ctl);
        }
        if self.newer.is_some() {
            self.slots.push(Slot::Newer);
        }
        for (i, o) in self.older.iter().enumerate() {
            if o.sock.is_some() {
                self.slots.push(Slot::Older(i));
            }
        }
        if self.reads_clients() {
            for i in 0..self.listens.len() {
                self.slots.push(Slot::Listen(i));
            }
        }
        for (wi, w) in self.wires.iter().enumerate() {
            for (mi, m) in w.members.iter().enumerate() {
                if m.fd >= 0 {
                    self.slots.push(Slot::Member(wi, mi));
                }
            }
        }
        if self.newer.is_none() {
            for i in 0..self.tcp_listens.len() {
                self.slots.push(Slot::TcpListen(i));
            }
        }
        for slot in 0..self.streams.slots() {
            if self.streams.get(slot).is_some() {
                self.slots.push(Slot::Client(slot));
            }
        }
        for (wi, w) in self.swires.iter().enumerate() {
            for (li, l) in w.links.iter().enumerate() {
                if l.sock.is_some() {
                    self.slots.push(Slot::Link(wi, li));
                }
            }
        }
        let (listens, wires, ctl) = (&self.listens, &self.wires, &self.ctl);
        let (tcp_listens, streams, swires) = (&self.tcp_listens, &self.streams, &self.swires);
        let (newer, older) = (&self.newer, &self.older);
        self.poll.set(self.slots.iter().map(|s| match *s {
            Slot::Ctl => ctl.as_ref().unwrap().fd,
            Slot::Listen(i) => listens[i].sock.as_raw_fd(),
            Slot::Member(w, m) => wires[w].members[m].fd,
            Slot::TcpListen(i) => tcp_listens[i].fd.as_raw_fd(),
            Slot::Client(slot) => streams.get(slot).map_or(-1, |st| st.client.fd.as_raw_fd()),
            Slot::Link(w, l) => swires[w].links[l].sock.as_ref().map_or(-1, |s| s.fd()),
            Slot::Newer => newer.as_ref().map_or(-1, |s| s.fd),
            Slot::Older(i) => older[i].sock.as_ref().map_or(-1, |s| s.fd),
        }));
        self.dirty = false;
    }

    /// Seals what waited its window (on a tick: the tick is the window) and
    /// sends every member's batch.
    fn seal_due(&mut self) {
        let now = now_ns();
        let tick = self.tick_ns > 0;
        for w in self.wires.iter_mut() {
            for m in w.members.iter_mut() {
                if m.sched.is_some() {
                    // The QUIC wire's frames wait under its guard: the tick
                    // is their glue (spec/trunk.md, "How each end sends").
                    m.drain(now);
                } else if m.glue_since != 0 && (tick || w.glue_ns == 0 || now - m.glue_since >= w.glue_ns) {
                    m.seal_glue();
                }
                m.flush_out();
            }
        }
    }

    fn log_stats(&self) {
        let mut s = format!(
            "hk-pipe: flows={} idle={} dgrams={}/{} copies={} route=bulk:{},voice:{} pauses={} bad={}",
            self.flows.clients,
            self.flows.n.idle,
            self.flows.n.out,
            self.flows.n.delivered,
            self.flows.n.copies,
            self.route[0],
            self.route[1],
            self.judge.pauses,
            self.bad
        );
        for w in &self.wires {
            let dgrams = w.members.iter().map(|m| m.dgrams).sum::<u64>();
            let dropped = w.t.dropped + w.members.iter().map(|m| m.send.dropped + m.too_big).sum::<u64>();
            s += &format!(
                " | wire {} up={}/{} in={} out={} dgrams={} frames/dgram={:.2} dropped={dropped}",
                w.id,
                w.up(),
                w.members.len(),
                w.t.up_pkts,
                w.t.down_pkts,
                dgrams,
                w.t.up_pkts as f64 / dgrams.max(1) as f64
            );
            if let Some(h) = self.h3s.iter().find(|h| h.id == w.id).filter(|_| w.h3 && w.sess == self.cur) {
                s += &h.stats();
                let now = now_ns();
                let stale: u64 = w.members.iter().filter_map(|m| m.sched.as_ref()).map(|q| q.n.stale).sum();
                let wait_max = w.members.iter().filter_map(|m| m.sched.as_ref()).map(|q| q.n.wait_max_ns).max().unwrap_or(0);
                let limited = w.members.iter().filter(|m| m.guard.rate() > 0.0).count();
                let guard_ms: u64 = w.members.iter().map(|m| m.guard.limited_ns(now) / 1_000_000).sum();
                s += &format!(" stale={stale} wait_max_ms={:.1} guard_ms={guard_ms} limited={limited}", wait_max as f64 / 1e6);
            }
        }
        if self.has_tcp() {
            s += &tcp::stats(&self.streams, &self.swires, &self.ports);
        }
        let retired = self.sessions.iter().filter(|x| x.live && x.retired_at != 0).count();
        if self.next.is_some() || retired > 0 {
            s += &format!(" | sessions cur={} next={} retired={retired}", self.cur, self.next.map_or(-1, |n| n as i32));
        }
        if self.newer.is_some() {
            s += " | draining";
        }
        let older = self.older.iter().filter(|o| o.sock.is_some()).count();
        if older > 0 {
            s += &format!(" | older={} held={}", older, self.owners.len());
        }
        eprintln!("{s}");
    }
}

fn ms(ns: u64) -> u32 {
    (ns / 1_000_000).min(u32::MAX as u64 - 1) as u32
}
