//! Clients' streams (spec/trunk.md, "Streams"): a client's TCP connection on
//! a listened port is a stream to the exit's loopback port. The entry opens
//! it, numbers the client's bytes into chunks and writes the exit's in
//! order back to the client (hikkari_trunk::stream). The reference is trunk
//! session.go: Carry, readLocal, writeLocal, maybeFinishLocked,
//! endStreamLocked; the production entry hands each accepted connection to
//! Carry (hikkari-control trunkentry).
//!
//! Stream ids count up and are never used again while the pipe runs: the
//! exit answers a late frame of a stream it ended with a reset for 2 minutes
//! (trunk closedMemory), so an id used again soon would be reset.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd};

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::buf::Behind;
use hikkari_trunk::stream::{Recv, Send};

use crate::flow::FxMap;
use crate::observe::{Report, StreamObs, END_NONE, PHASE_END, PHASE_MARK};

/// A stream's client side: its connection, and what waits for it.
pub struct Client {
    pub fd: OwnedFd,
    /// Received in order and not yet taken by the client.
    down: Behind,
}

impl Client {
    pub fn down_pending(&self) -> bool {
        self.down.pending()
    }

    /// Bytes for the client: written now while nothing waits before them,
    /// the rest kept for when the client takes more. How many were written;
    /// None when the client is gone.
    pub fn give(&mut self, p: &[u8]) -> Option<usize> {
        let mut n = 0;
        if !self.down.pending() {
            match sys::write(&self.fd, p) {
                Io::Done(k) => n = k,
                Io::Again => {}
                Io::Eof | Io::Gone => return None,
            }
        }
        self.down.push(&p[n..]);
        Some(n)
    }

    /// Writes what waits for the client: how many bytes it took; None when
    /// it is gone.
    pub fn flush_down(&mut self) -> Option<usize> {
        if !self.down.pending() {
            return Some(0);
        }
        match sys::write(&self.fd, self.down.bytes()) {
            Io::Done(k) => {
                self.down.took(k);
                Some(k)
            }
            Io::Again => Some(0),
            Io::Eof | Io::Gone => None,
        }
    }
}

pub struct Stream {
    pub client: Client,
    pub id: u32,
    /// The exit's loopback port.
    pub port: u16,
    /// Its open went to the exit; until then the client is not read.
    pub opened: bool,
    pub send: Send,
    pub recv: Recv,
    /// The client ended its side: the FIN went to the exit.
    pub read_done: bool,
    /// The session it goes on (the pipe's session.rs), to its end.
    pub sess: u8,
    /// The exit's FIN is written: the client's side is shut.
    pub write_done: bool,
    /// The client socket's segments out and sent again as last counted in
    /// the leg (Leg).
    leg_seen: (u32, u32),
    /// What it did, for its reports if the exit marks it (observe.rs).
    pub obs: StreamObs,
    /// Handed to a newer generation (pipe/adopt.rs): since when its client
    /// is not read (0: it is), and whether its connection went over.
    pub frozen_at: u64,
    pub handed: bool,
    /// Taken from an older generation and not adopted by the exit yet: its
    /// client is not read.
    pub adopting: bool,
}

impl Stream {
    /// The exit's FIN reaches the client once everything before it did:
    /// shuts the client's side.
    pub fn shut_if_all_in(&mut self) {
        if !self.write_done && self.recv.all_in() && !self.client.down_pending() {
            sys::shutdown_write(&self.client.fd);
            self.write_done = true;
        }
    }

    /// Both directions are over (trunk maybeFinishLocked): its FIN
    /// confirmed, the exit's written.
    pub fn finished(&self) -> bool {
        self.send.fin_done && self.write_done
    }
}

/// How streams ended and what they carried, since the pipe started.
#[derive(Clone, Copy, Default)]
pub struct StreamCounts {
    pub opened: u64,
    /// Both FINs confirmed and written.
    pub fin: u64,
    /// Reset by the exit.
    pub reset_peer: u64,
    /// Reset here: the client failed, or the stream had nothing to go on.
    pub reset_local: u64,
    /// Times a member died carrying a stream's unconfirmed open, chunks or
    /// FIN (once per stream and death), and chunks sent again for it.
    pub deaths: u64,
    pub resent: u64,
    /// Client bytes numbered toward the exit, and written to clients.
    pub up: u64,
    pub down: u64,
}

pub struct Streams {
    list: Vec<Option<Stream>>,
    free: Vec<usize>,
    by_id: FxMap<u32>,
    next_id: u32,
    /// Streams whose open has not gone yet.
    pub unopened: usize,
    pub open: usize,
    pub n: StreamCounts,
    /// The leg client → entry of the minute (Leg).
    pub leg: Leg,
    /// Reports of observed streams for the brain (observe.rs), sent after
    /// the turn that made them.
    pub reports: Vec<Report>,
}

impl Streams {
    pub fn new() -> Streams {
        Streams {
            list: Vec::with_capacity(1024),
            free: Vec::with_capacity(1024),
            by_id: HashMap::with_capacity_and_hasher(1024, Default::default()),
            next_id: 0,
            unopened: 0,
            open: 0,
            n: StreamCounts::default(),
            leg: Leg::default(),
            reports: Vec::new(),
        }
    }

    /// A new client connection to the exit's port, on session `sess`: its
    /// slot.
    pub fn add(&mut self, fd: OwnedFd, port: u16, sess: u8) -> usize {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let st = Stream {
            client: Client { fd, down: Behind::default() },
            id: self.next_id,
            port,
            opened: false,
            send: Send::default(),
            recv: Recv::default(),
            read_done: false,
            sess,
            write_done: false,
            leg_seen: (0, 0),
            obs: StreamObs::new(sys::now_ns()),
            frozen_at: 0,
            handed: false,
            adopting: false,
        };
        self.unopened += 1;
        self.n.opened += 1;
        self.put(st)
    }

    /// A stream an older generation hands over (pipe/adopt.rs): its client's
    /// connection, the exit's port, and `up` bytes read from the client and
    /// `down` written to it there, all confirmed. Opened already (the exit
    /// adopts it, no open goes), on session `sess`, its client not read
    /// until the exit adopts it. Its slot.
    pub fn adopted(&mut self, fd: OwnedFd, port: u16, sess: u8, up: u64, down: u64) -> usize {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let st = Stream {
            client: Client { fd, down: Behind::default() },
            id: self.next_id,
            port,
            opened: true,
            send: Send::at(up),
            recv: Recv::at(down),
            read_done: false,
            sess,
            write_done: false,
            leg_seen: (0, 0),
            obs: StreamObs::new(sys::now_ns()),
            frozen_at: 0,
            handed: false,
            adopting: true,
        };
        self.put(st)
    }

    fn put(&mut self, st: Stream) -> usize {
        let id = st.id;
        let slot = match self.free.pop() {
            Some(s) => {
                self.list[s] = Some(st);
                s
            }
            None => {
                self.list.push(Some(st));
                self.list.len() - 1
            }
        };
        self.by_id.insert(id, slot as u32);
        self.open += 1;
        slot
    }

    /// Gives up the stream in `slot`, ending nothing: another generation
    /// carries it on, or never took it here. Its connection closes here
    /// only (the other generation holds its own).
    pub fn give_up(&mut self, slot: usize) {
        if let Some(st) = self.list[slot].take() {
            self.by_id.remove(&st.id);
            if !st.opened {
                self.unopened -= 1;
            }
            self.open -= 1;
            self.free.push(slot);
        }
    }

    pub fn slots(&self) -> usize {
        self.list.len()
    }

    #[inline]
    pub fn get(&self, slot: usize) -> Option<&Stream> {
        self.list.get(slot)?.as_ref()
    }

    /// The stream in `slot` and the counts, to count what it carries.
    #[inline]
    pub fn with_counts(&mut self, slot: usize) -> Option<(&mut Stream, &mut StreamCounts)> {
        Some((self.list.get_mut(slot)?.as_mut()?, &mut self.n))
    }

    /// Its open went out.
    pub fn opened(&mut self, slot: usize) {
        if let Some(st) = self.list[slot].as_mut() {
            if !st.opened {
                st.opened = true;
                self.unopened -= 1;
            }
        }
    }

    /// The highest id given so far: a lower id not open is a stream ended.
    pub fn last_id(&self) -> u32 {
        self.next_id
    }

    /// The slot of stream `id`, if it is open.
    #[inline]
    pub fn slot_of(&self, id: u32) -> Option<usize> {
        self.by_id.get(&id).map(|&s| s as usize)
    }

    /// The streams session `sess` carries.
    /// The exit marked stream `id` with observation `token` (observe.rs):
    /// its report at the mark; a stream ended or already marked is not
    /// marked again.
    pub fn mark(&mut self, id: u32, token: u64, now: u64) {
        let Some(slot) = self.slot_of(id) else { return };
        let Some(st) = self.list[slot].as_mut() else { return };
        if st.obs.id != 0 || token == 0 {
            return;
        }
        st.obs.id = token;
        let tcp = sys::tcp_info(st.client.fd.as_raw_fd());
        self.reports.push(Report::stream(&st.obs, st.port, PHASE_MARK, END_NONE, tcp, now));
    }

    pub fn on(&self, sess: u8) -> usize {
        self.list.iter().flatten().filter(|st| st.sess == sess).count()
    }

    /// Ends the stream in `slot` (`end`: observe.rs END_*): its client
    /// connection closes, read once more for the leg and, if the exit
    /// marked it, for its last report.
    pub fn end(&mut self, slot: usize, end: u8, now: u64) {
        if let Some(mut st) = self.list[slot].take() {
            let tcp = sys::tcp_info(st.client.fd.as_raw_fd());
            if let Some(i) = tcp {
                self.leg.add(&mut st, i);
            }
            self.leg.closed += 1;
            if st.obs.id != 0 {
                self.reports.push(Report::stream(&st.obs, st.port, PHASE_END, end, tcp, now));
            }
            self.by_id.remove(&st.id);
            if !st.opened {
                self.unopened -= 1;
            }
            self.open -= 1;
            self.free.push(slot);
        }
    }
}

/// Round trips a minute keeps for its percentiles, at most.
const LEG_RTTS: usize = 8192;

/// The leg client → entry over every client's socket (the Go entry's
/// trunkentry clients.go, the same sums): segments the pipe sent its clients
/// and sent again, and the round trip of each socket that sent, since the
/// last minute. No client is named in it.
#[derive(Default)]
pub struct Leg {
    pub segs: u64,
    pub retrans: u64,
    pub closed: u32,
    pub rtts_us: Vec<u32>,
}

/// One minute of the leg, as the brain gets it (ctl::put_clients).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LegMinute {
    pub conns: u32,
    pub closed: u32,
    pub sending: u32,
    pub segs: u64,
    pub retrans: u64,
    /// The sockets' round trips at p50 and p90 in µs; None: no socket sent.
    pub rtt_us: Option<(u32, u32)>,
}

impl Leg {
    /// Counts what a client's socket did since it was last read.
    fn read(&mut self, st: &mut Stream) {
        let Some(i) = sys::tcp_info(st.client.fd.as_raw_fd()) else { return };
        self.add(st, i);
    }

    fn add(&mut self, st: &mut Stream, i: sys::TcpInfo) {
        let segs = i.segs_out.wrapping_sub(st.leg_seen.0);
        let retrans = i.total_retrans.wrapping_sub(st.leg_seen.1);
        st.leg_seen = (i.segs_out, i.total_retrans);
        if segs == 0 {
            return;
        }
        self.segs += segs as u64;
        self.retrans += retrans as u64;
        if i.rtt_us > 0 && self.rtts_us.len() < LEG_RTTS {
            self.rtts_us.push(i.rtt_us);
        }
    }

    /// The minute's sums, with them every live socket read, and the next
    /// minute begun.
    pub fn minute(streams: &mut Streams) -> LegMinute {
        let Streams { list, leg, open, .. } = streams;
        for st in list.iter_mut().flatten() {
            leg.read(st);
        }
        let mut m = LegMinute { conns: *open as u32, closed: leg.closed, sending: leg.rtts_us.len() as u32, segs: leg.segs, retrans: leg.retrans, rtt_us: None };
        if !leg.rtts_us.is_empty() {
            leg.rtts_us.sort_unstable();
            let at = |q: f64| leg.rtts_us[(q * (leg.rtts_us.len() - 1) as f64) as usize];
            m.rtt_us = Some((at(0.5), at(0.9)));
        }
        *leg = Leg { rtts_us: std::mem::take(&mut leg.rtts_us), ..Leg::default() };
        leg.rtts_us.clear();
        m
    }
}
