//! The exit: everything the exit does with each packet of the entry's
//! members (README.md, «The exit»), as trunk.Exit does it: packet members
//! over udpwire, with the frames bound for one member glued into one
//! datagram for a tick, and stream members over TCP with the streams they
//! carry to the loopback services.
//!
//! What is the brain's (trunk/pipectl): it binds the wire's socket and hands
//! it over with the wire keys (the exit never sees a trunk key), the members'
//! stall and Quiet, the pool's listening socket, and the loopback ports open
//! to the trunk; it reads a tick a second. Without a brain (flags, the
//! bench) the exit binds its own.
//!
//! One thread, no runtime, nothing allocated per packet once a flow is open.
//! Under traffic the loop runs on a tick: it sleeps to the next one, takes
//! everything each wire has with recvmmsg and every relay socket epoll says
//! is ready, and sends with sendmmsg; stream sockets are read and written as
//! their epoll says they can be.
//!
//! Its parts: wire.rs (the entry's datagrams: hellos, pings, a flow's
//! datagrams), h3.rs (the Chromium QUIC wire's connections and requests), relay.rs (flows to and from the loopback services), tcp.rs
//! (stream members and their streams), death.rs (what a dead stream member
//! carried, again), timers.rs (members' health on their clock, idle flows,
//! members and sessions), brain.rs (the brain's messages, the tick).

mod brain;
mod death;
mod h3;
mod relay;
mod stream;
mod tcp;
mod timers;
mod wire;

pub use tcp::Pool;

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddrV4, UdpSocket};

use hikkari_sys::{self as sys, now_ns, Epoll, Poll, RecvBatch, SeqPacket};
use hikkari_trunk::flow::FLOW_IDLE_NS;
use hikkari_trunk::health::Judge;
use hikkari_trunk::udpwire;

use crate::ctl::{self, Tick};
use crate::h3wire::H3Wire;
use crate::flow::{Flows, Seen};
use crate::link::Links;
use crate::peer::{Form, Peer, Wire, NONE, SLOT};
use crate::session::Sessions;
use crate::streams::Streams;

/// The exit's Quiet (trunk ExitQuiet): every member silent at once is the
/// entry paused or the whole path, and the exit, which cannot open members,
/// waits this long for the entry to.
pub const EXIT_QUIET: u64 = 30_000_000_000;
/// Most entry addresses served at once (udpwire MaxPeers).
pub const MAX_PEERS: usize = 1024;
/// Events the stream sockets' epoll reports per call; more are taken by the
/// next call in the same turn.
const TCP_EVENTS: usize = 1024;

/// Flags of an exit without a brain (the bench).
pub struct Alone {
    pub listen: SocketAddrV4,
    pub key: String,
    pub wire: u8,
    pub glue_ns: u64,
    pub glue_max: usize,
    pub stall_ns: u64,
    pub quiet_ns: u64,
    /// The loopback ports open to the trunk; the call's port 0 always is.
    pub ports: Vec<u16>,
    /// The pool's port: plain TCP stream members (None: none).
    pub pool: Option<SocketAddrV4>,
    /// A Chromium QUIC wire beside it, under the same trunk key.
    pub h3: Option<AloneH3>,
}

/// The Chromium QUIC wire of an exit without a brain: its UDP address, its
/// id, the certificate and key (PEM files).
pub struct AloneH3 {
    pub listen: SocketAddrV4,
    pub wire: u8,
    pub cert: String,
    pub key: String,
}

pub struct Exit {
    ctl: Option<SeqPacket>,
    tick_ns: u64,
    flow_idle_ns: u64,
    wires: Vec<Wire>,
    peers: Vec<Peer>,
    peers_free: Vec<usize>,
    by_addr: HashMap<u64, usize>,
    sessions: Sessions,
    flows: Flows,
    pool: Option<Pool>,
    links: Links,
    streams: Streams,
    /// The stream sockets: the pool's, the members', the local ends'.
    tcp: Epoll,
    /// What acks of one read confirmed: (carrier, bytes), applied after it.
    released: Vec<(u32, u32)>,
    /// Streams to end after the pass that found them done or failed (slot,
    /// gen, why).
    doomed: Vec<(usize, u32, stream::Why)>,
    /// The loopback ports open to the trunk, by port.
    ports: Vec<bool>,
    /// The flows' relay sockets, by flow slot and gen.
    relays: Epoll,
    poll: Poll,
    dirty: bool,
    /// Taken out of the exit while a batch is walked (Option: no
    /// allocation for it), as are the relay's buffer and the brain's message.
    wrecv: Option<RecvBatch>,
    relay_buf: Vec<u8>,
    /// A QUIC datagram read (h3.rs), and the members of closed connections.
    dgram_buf: Vec<u8>,
    gone: Vec<(usize, u32)>,
    carriers: [Seen; 2],
    msg: Vec<u8>,
    fds: Vec<i32>,
    tok: u64,
    /// The exit's own pauses (Judge::turn); every session's judge takes the
    /// end of one as its own.
    pause: Judge,
    clock_at: u64,
    late_max: u64,
    tick_at: u64,
    stats_at: u64,
    moved: u64,
    t: Tick,
}

impl Exit {
    fn new(ctl: Option<SeqPacket>, tick_ns: u64) -> io::Result<Exit> {
        let now = now_ns();
        Ok(Exit {
            ctl,
            tick_ns,
            flow_idle_ns: FLOW_IDLE_NS,
            wires: Vec::new(),
            peers: Vec::new(),
            peers_free: Vec::new(),
            by_addr: HashMap::with_capacity(64),
            sessions: Sessions::new(),
            flows: Flows::new(),
            pool: None,
            links: Links::new(),
            streams: Streams::new(),
            tcp: Epoll::new(TCP_EVENTS)?,
            released: Vec::with_capacity(256),
            doomed: Vec::with_capacity(64),
            ports: vec![false; 1 << 16],
            relays: Epoll::new(256)?,
            poll: Poll::new(),
            dirty: true,
            wrecv: Some(RecvBatch::new(SLOT)),
            relay_buf: vec![0; 65535],
            dgram_buf: vec![0; crate::h3wire::DGRAM],
            gone: Vec::with_capacity(16),
            carriers: [(NONE, 0); 2],
            msg: vec![0; 65536],
            fds: Vec::with_capacity(ctl::MAX_FDS),
            tok: 0,
            pause: Judge::new(0),
            clock_at: now,
            late_max: 0,
            tick_at: now + timers::TICK_EVERY,
            stats_at: now,
            moved: 0,
            t: Tick::default(),
        })
    }

    /// An exit the brain runs over the socket at fd. It says hello; the
    /// wire and the ports come in the brain's messages.
    pub fn with_brain(fd: i32, tick_ns: u64) -> io::Result<Exit> {
        let mut c = SeqPacket::new(fd, ctl::MAX_FDS);
        let mut b = [0u8; 16];
        let n = ctl::put_hello(&mut b, std::process::id());
        c.send(&b[..n]);
        Exit::new(Some(c), tick_ns)
    }

    /// An exit without a brain: its own wire socket, one key.
    pub fn alone(a: &Alone, tick_ns: u64) -> io::Result<Exit> {
        let mut x = Exit::new(None, tick_ns)?;
        let sock = UdpSocket::bind(a.listen)?;
        sys::tune(&sock, false)?;
        let keys = vec![udpwire::key(&a.key)];
        x.wires.push(Wire::udp(a.wire, sock, keys, a.stall_ns, a.quiet_ns, a.glue_ns, a.glue_max));
        if let Some(h) = &a.h3 {
            let sock = UdpSocket::bind(h.listen)?;
            sys::tune(&sock, false)?;
            let tokens = vec![hikkari_trunk::h3dgram::token(&a.key)];
            let w = H3Wire::new(sock, &h.cert, &h.key, tokens).map_err(io::Error::other)?;
            x.wires.push(Wire::h3dgram(h.wire, w, a.stall_ns, a.quiet_ns, a.glue_ns, a.glue_max));
        }
        for &p in &a.ports {
            x.ports[p as usize] = true;
        }
        if let Some(addr) = a.pool {
            x.set_pool(Pool { fd: sys::tcp_listen(addr)?, stall_ns: a.stall_ns, quiet_ns: a.quiet_ns })?;
        }
        Ok(x)
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
            if self.pause.turn(prev, now) {
                // Every member's debt counts from the end of the exit's own
                // pause, whatever its session (trunk tick: s.resumed).
                for s in self.sessions.all.iter_mut() {
                    s.judge.resumed = now;
                }
            }
            prev = now;
            let next = self.timers(now);
            if self.dirty {
                self.rebuild_poll();
            }
            // Under traffic the loop runs on a tick: a wakeup is paid once
            // per tick, not once per packet; a tick that moved nothing goes
            // back to waiting for the first packet.
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
                self.late_max = self.late_max.max(now - due);
            }
            let moved0 = self.moved;
            if !self.read_brain() {
                return;
            }
            if self.dirty {
                self.rebuild_poll();
                self.poll.all();
            }
            let now = now_ns();
            self.read_wires(now);
            self.read_relays(now);
            self.tcp_events(now);
            self.read_links(now);
            self.read_locals(now);
            self.write_locals(now);
            self.flush_links(now);
            self.seal_due(now_ns());
            busy = self.moved != moved0;
        }
    }

    /// The poll set: the brain, each wire, the relays' epoll and the stream
    /// sockets' (each readable when any of its sockets has something).
    fn rebuild_poll(&mut self) {
        let mut fds: Vec<i32> = Vec::with_capacity(3 + self.wires.len());
        if let Some(c) = &self.ctl {
            fds.push(c.fd);
        }
        fds.extend(self.wires.iter().map(|w| w.fd()));
        fds.push(self.relays.fd);
        fds.push(self.tcp.fd);
        self.poll.set(fds.into_iter());
        self.dirty = false;
    }

    /// Seals what waited its window (on a tick: the tick is the window) and
    /// sends every wire's batch.
    fn seal_due(&mut self, now: u64) {
        let tick = self.tick_ns > 0;
        let Exit { wires, peers, .. } = self;
        for p in peers.iter_mut() {
            if p.live && p.glue_since != 0 {
                let w = &mut wires[p.wire];
                if tick || w.glue_ns == 0 || now - p.glue_since >= w.glue_ns {
                    w.seal(p);
                }
            }
        }
        for w in wires.iter_mut() {
            w.flush(now);
        }
        self.reap_h3(now);
    }

    /// The peer slot of an entry address, if it has one.
    #[inline]
    fn peer_of(&self, key: u64) -> Option<usize> {
        self.by_addr.get(&key).copied()
    }

    /// A slot for a new entry address of `wire` (`at`: the address's key
    /// on that wire) whose first datagram opened under key k; None when
    /// MAX_PEERS are served.
    fn take_peer(&mut self, addr: sys::sockaddr_in, at: u64, wire: usize, k: usize, now: u64) -> Option<usize> {
        if self.by_addr.len() >= MAX_PEERS {
            return None;
        }
        let i = self.peers_free.pop().unwrap_or_else(|| {
            self.peers.push(Peer::vacant());
            self.peers.len() - 1
        });
        let Form::Udp(u) = &self.wires[wire].form else { return None };
        let key = u.keys[k];
        self.peers[i].take(addr, wire, &key, now);
        self.peers[i].key = at;
        self.by_addr.insert(at, i);
        Some(i)
    }

    /// Forgets peer i: out of its session if it was a member, its address
    /// free for a new one (a datagram from it later is a new member, whose
    /// hello it must say first, as udpwire's peer.Close).
    fn drop_peer(&mut self, i: usize, now: u64) {
        let p = &mut self.peers[i];
        if !p.live {
            return;
        }
        // A member of the QUIC wire ends with its connection (spec/trunk.md,
        // `h3dgram`): the entry opens a new one.
        if p.conn != NONE {
            if let Some(h) = self.wires[p.wire].h3() {
                h.close(p.conn);
            }
            p.conn = NONE;
        }
        if p.session != NONE {
            let s = p.session;
            self.sessions.all[s].leave((i, p.gen), now);
            self.t.members -= 1;
        }
        p.live = false;
        p.session = NONE;
        p.glue_n = 0;
        p.glue_since = 0;
        if self.by_addr.get(&p.key) == Some(&i) {
            self.by_addr.remove(&p.key);
        }
        self.peers_free.push(i);
    }

    fn log_stats(&self) {
        let calls: u64 = self.wires.iter().map(|w| w.socket_counts().1).sum();
        let t = &self.t;
        eprintln!(
            "hk-exit: sessions={} members={} joined={} silent={} quiet={} gone={} flows={} idle={} dgrams={}/{} copies={} refused={} w_in={} w_out={} frames/dgram={:.2} sendmmsg={} pauses={} bad={} dropped={}",
            self.sessions.live(),
            t.members,
            t.joined,
            t.silent,
            t.quiet,
            t.gone,
            self.flows.clients,
            t.flows_idle,
            t.dgrams_out,
            t.dgrams_in,
            t.dgrams_copy,
            t.refused,
            t.w_in,
            t.w_out,
            t.frames_out as f64 / t.w_out.max(1) as f64,
            calls,
            self.pause.pauses,
            t.bad,
            self.wires.iter().map(|w| w.socket_counts().0 + w.dropped).sum::<u64>()
        );
        for w in &self.wires {
            if let Form::H3(h) = &w.form {
                let n = &h.n;
                eprintln!(
                    "hk-exit: h3dgram wire {} conns={} accepted={} refused={} stray={} too_big={} full={}",
                    w.id,
                    h.open(),
                    n.conns,
                    n.refused,
                    n.stray,
                    n.too_big,
                    n.full
                );
            }
        }
        if self.pool.is_some() {
            let n = &self.streams.n;
            eprintln!(
                "hk-exit: links={} streams open={} opened={} fin={} rst_peer={} rst_local={} hit={} resent={} early={}/{} up={}MiB down={}MiB link_dgrams={}",
                t.links,
                self.streams.open,
                n.opened,
                n.fin,
                n.reset_peer,
                n.reset_local,
                n.deaths,
                n.resent,
                n.early,
                n.early_dropped,
                n.up >> 20,
                n.down >> 20,
                t.link_dgrams
            );
        }
    }
}
