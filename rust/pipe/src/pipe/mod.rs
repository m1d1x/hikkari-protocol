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
//! (clients → wires → clients).

mod brain;
mod data;
mod death;
mod tcp;
mod timers;

use std::collections::BTreeSet;
use std::io;
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use tcp::{TcpListen, Why};

use hikkari_sys::{self as sys, now_ns, Poll, RecvBatch, SendBatch, SeqPacket};
use hikkari_trunk::flow::FLOW_IDLE_NS;
use hikkari_trunk::health::{self, Judge};
use hikkari_trunk::udpwire;

use crate::ctl::{self, ANY_WIRE};
use crate::flow::{Flows, CLASS_VOICE};
use crate::link::StreamWire;
use crate::member::{member_to, Member, Wire, SLOT};
use crate::streams::Streams;

const MAX_CLIENT: usize = 1500;

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
}

pub struct Pipe {
    ctl: Option<SeqPacket>,
    session: [u8; 16],
    gro: bool,
    tick_ns: u64,
    /// A client's flow unused this long ends (trunk FlowIdle).
    flow_idle_ns: u64,
    listens: Vec<Listen>,
    wires: Vec<Wire>,
    /// The wire of each class, by class (CLASS_BULK, CLASS_VOICE).
    route: [u8; 2],
    flows: Flows,
    tcp_listens: Vec<TcpListen>,
    swires: Vec<StreamWire>,
    streams: Streams,
    /// What acks of one read confirmed: (carrier, bytes), applied after it.
    released: Vec<(u32, u32)>,
    /// Streams with things a dead member carried, waiting to go again, by id
    /// (the order they were opened).
    stranded: BTreeSet<u32>,
    /// Streams to end after the pass that found them done or failed.
    doomed: Vec<(usize, Why)>,
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
        let mut session = [0u8; 16];
        sys::urandom(&mut session);
        let now = now_ns();
        Pipe {
            ctl,
            session,
            gro,
            tick_ns,
            flow_idle_ns: FLOW_IDLE_NS,
            listens: Vec::new(),
            wires: Vec::new(),
            route: [ANY_WIRE, ANY_WIRE],
            flows: Flows::new(),
            tcp_listens: Vec::new(),
            swires: Vec::new(),
            streams: Streams::new(),
            released: Vec::with_capacity(256),
            stranded: BTreeSet::new(),
            doomed: Vec::with_capacity(64),
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
        let key = udpwire::key(&a.key);
        let mut w = Wire::new(a.wire, key, health::STALL);
        w.glue_ns = a.glue_ns;
        w.glue_max = a.glue_max;
        w.exit = Some(a.exit);
        for _ in 0..a.members {
            w.members.push(Member::new(Some(member_to(a.exit)?), &key));
        }
        p.wires.push(w);
        p.route = [a.wire, a.wire];
        if let Some(addr) = a.tcp_listen {
            p.tcp_listens.push(TcpListen { fd: sys::tcp_listen(addr)?, to: a.tcp_to });
            // The pool's wire (trunk.PoolWire): the streams' only one here.
            let mut sw = StreamWire::new(0, a.tcp_exit, a.tcp_members, health::STALL);
            let now = now_ns();
            for l in sw.links.iter_mut() {
                l.dial(a.tcp_exit, &p.session, now);
            }
            p.swires.push(sw);
        }
        Ok(p)
    }

    /// A client's flow unused for idle_ns ends; the trunk's is 2 minutes,
    /// tests take less.
    pub fn set_flow_idle(&mut self, idle_ns: u64) {
        self.flow_idle_ns = idle_ns.max(1);
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
        for i in 0..self.tcp_listens.len() {
            self.slots.push(Slot::TcpListen(i));
        }
        for slot in 0..self.streams.slots() {
            if self.streams.get(slot).is_some() {
                self.slots.push(Slot::Client(slot));
            }
        }
        for (wi, w) in self.swires.iter().enumerate() {
            for (li, l) in w.links.iter().enumerate() {
                if l.fd.is_some() {
                    self.slots.push(Slot::Link(wi, li));
                }
            }
        }
        let (listens, wires, ctl) = (&self.listens, &self.wires, &self.ctl);
        let (tcp_listens, streams, swires) = (&self.tcp_listens, &self.streams, &self.swires);
        self.poll.set(self.slots.iter().map(|s| match *s {
            Slot::Ctl => ctl.as_ref().unwrap().fd,
            Slot::Listen(i) => listens[i].sock.as_raw_fd(),
            Slot::Member(w, m) => wires[w].members[m].fd,
            Slot::TcpListen(i) => tcp_listens[i].fd.as_raw_fd(),
            Slot::Client(slot) => streams.get(slot).map_or(-1, |st| st.client.fd.as_raw_fd()),
            Slot::Link(w, l) => swires[w].links[l].fd.as_ref().map_or(-1, |fd| fd.as_raw_fd()),
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
                if m.glue_since != 0 && (tick || w.glue_ns == 0 || now - m.glue_since >= w.glue_ns) {
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
            s += &format!(
                " | wire {} up={}/{} in={} out={} dgrams={} frames/dgram={:.2}",
                w.id,
                w.up(),
                w.members.len(),
                w.t.up_pkts,
                w.t.down_pkts,
                dgrams,
                w.t.up_pkts as f64 / dgrams.max(1) as f64
            );
        }
        if self.has_tcp() {
            s += &tcp::stats(&self.streams, &self.swires);
        }
        eprintln!("{s}");
    }
}

fn ms(ns: u64) -> u32 {
    (ns / 1_000_000).min(u32::MAX as u64 - 1) as u32
}
