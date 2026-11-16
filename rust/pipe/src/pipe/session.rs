//! Sessions of the pipe (spec/trunk.md, "Frames": Drain; the Go entry's
//! generations, trunk entry.go: drained, takeOver, Retire, closeRetired):
//! the exit's process replaced without a cut.
//!
//! A session is one session id and the members of every wire that joined
//! under it; each wire has a Wire (or StreamWire) per session, and every
//! flow and stream goes on its session's members alone, to its end. When
//! the exit says it drains, on a member of the current session, the pipe
//! answers once: a new session with a new id and a full pool, whose members
//! reach the exit's new process. The current session goes on taking every
//! new flow and stream, as the exit's old process still serves, and replaces
//! none of its members; once a quarter of the new session's members are up,
//! or after TAKE_OVER_NS, the new one takes over. The old one is retired: it
//! keeps its members, replaces none, takes nothing new, and closes when it
//! carries nothing more or after RETIRE_NS (then what it still carries is
//! cut). The brain's own flows (its calls) move to the new session at the
//! takeover: they never keep a retired one open.
//!
//! A pipe that drains itself (generation.rs: its own process replaced)
//! opens no session for the exit's drain and lets one coming up go: a
//! process that takes no new client has no use for a new pool.
//!
//! The brain sees the current session alone: its ticks and member events
//! are the current session's wires, and its new member sockets go to the
//! current session only while that is the one that replaces its members.
//! The members of a session coming up are the pipe's own, dialed to the
//! address the brain's sockets are connected to.
//!
//! Receivers (hikkari-client plans/2026-11-16-second-receiver.md): the
//! entry holds the trunk to more than one receiver abroad, the same relay
//! for a client (its domain, its keys) at another address, and carries
//! everything on one of them, the active one. Every session belongs to a
//! receiver (rx); the brain's wires and pools are the active receiver's.
//! A receiver on standby (B_RECEIVER) has a session of its own with every
//! wire and pool the current session has, its members the pipe's own and
//! dialed to the receiver's address on the same ports: warm, taking
//! nothing. The brain makes another receiver the active one (B_ACTIVE):
//! its standby session becomes the current one at once, and what the old
//! receiver's sessions carry is cut then and there, not left to time out,
//! so a client dials again within a second and lands on the new receiver;
//! the old receiver goes on standby with a session of its own. Both
//! channels of a client go with it: the move is the whole entry's. A
//! standby session whose exit drains, or whose active wires changed, is
//! opened anew: it carries nothing to keep.

use std::net::{Ipv4Addr, SocketAddrV4};

use hikkari_sys as sys;

use super::Pipe;
use crate::ctl::WireTick;
use crate::link::{Reach, StreamWire, NO_SESSION};
use crate::member::{member_to, Member, Wire};
use crate::observe::{END_EPOCH, END_SESSION};

/// Sessions open at once, at most: a reload of the exit every two minutes
/// for the 30 minutes a retired session may live.
pub(super) const MAX_SESSIONS: usize = 16;
/// A new session takes over after this even without a quarter of its pool
/// (trunk TakeOverLimit).
pub(super) const TAKE_OVER_NS: u64 = 10_000_000_000;
/// A retired session that still carries something is closed after this
/// (trunk RetireLimit): the exit's old process gives up its sessions after
/// as long (edge handoff.go).
pub(super) const RETIRE_NS: u64 = 30 * 60 * 1_000_000_000;

pub(super) struct Sess {
    pub id: [u8; 16],
    /// Its slot is in use.
    pub live: bool,
    /// The exit said it drains on one of its members, and whether the pipe
    /// opened a session for it.
    pub exit_drains: bool,
    pub answered: bool,
    /// When it was opened, and when it was retired (0: not).
    pub opened_at: u64,
    pub retired_at: u64,
    /// The exit's epoch its members' hellos said (spec/trunk.md, "Frames":
    /// hello); none before the first.
    pub epoch: Option<[u8; 8]>,
    /// The receiver it reaches, and whether it is that receiver's warm
    /// session on standby (it takes nothing).
    pub rx: u8,
    pub standby: bool,
}

impl Sess {
    pub fn new(now: u64) -> Sess {
        let mut id = [0u8; 16];
        sys::urandom(&mut id);
        Sess { id, live: true, exit_drains: false, answered: false, opened_at: now, retired_at: 0, epoch: None, rx: 0, standby: false }
    }
}

/// A receiver on standby: its address (the active one's ports), how many
/// members its pools keep (0: as many as the active one's), its session
/// once open, and whether that session must be opened anew.
pub(super) struct Receiver {
    pub rx: u8,
    pub ip: Ipv4Addr,
    pub pool_members: u8,
    pub sess: Option<u8>,
    pub stale: bool,
}

/// reach to the same port of ip: another receiver's pool, on an engine of
/// its own.
fn reach_at(reach: &Reach, ip: Ipv4Addr) -> Reach {
    match reach {
        Reach::Plain(a) => Reach::Plain(SocketAddrV4::new(ip, a.port())),
        Reach::Chromium(e) => {
            let f = e.form();
            let exit = SocketAddrV4::new(ip, f.exit.port());
            match hikkari_cronet::Form::new(exit, &f.sni, &f.key, f.roots.clone()) {
                Ok(form) => Reach::Chromium(hikkari_cronet::Engine::new(form)),
                // The active pool's form passed the same check.
                Err(e) => unreachable!("the active pool's form: {e}"),
            }
        }
    }
}

/// What a wire counted, its members' sealed datagrams and drops with it.
pub(super) fn counted(w: &Wire) -> WireTick {
    let mut t = w.t;
    t.dgrams = w.members.iter().map(|m| m.dgrams).sum();
    t.dropped += w.members.iter().map(|m| m.send.dropped + m.too_big).sum::<u64>();
    t
}

/// o's counters added to t's.
pub(super) fn add_counts(t: &mut WireTick, o: &WireTick) {
    t.up_pkts += o.up_pkts;
    t.up_bytes += o.up_bytes;
    t.down_pkts += o.down_pkts;
    t.down_bytes += o.down_bytes;
    t.dgrams += o.dgrams;
    t.dropped += o.dropped;
}

impl Pipe {
    /// The session whose dead members come back: the one coming up, else
    /// the current one; none while the pipe drains itself.
    pub(super) fn taker(&self) -> Option<u8> {
        if self.newer.is_some() {
            return None;
        }
        Some(self.next.unwrap_or(self.cur))
    }

    /// The sessions that replace their dead members, a bit each: the taker
    /// and the receivers' on standby; none while the pipe drains itself.
    pub(super) fn renew_mask(&self) -> u32 {
        let Some(t) = self.taker() else { return 0 };
        let mut m = 1u32 << t;
        for r in &self.receivers {
            if let Some(s) = r.sess {
                m |= 1 << s;
            }
        }
        m
    }

    /// The receivers on standby take the active one's wires anew (its
    /// wires or pools changed).
    pub(super) fn receivers_stale(&mut self) {
        for r in &mut self.receivers {
            r.stale = true;
        }
    }

    /// The sessions' part of the loop, each turn: the exit's drains heard,
    /// a session opened for the current one's, the one coming up taking
    /// over. Returns when the takeover is due at the latest.
    pub(super) fn step_sessions(&mut self, now: u64) -> u64 {
        let mut heard = std::mem::take(&mut self.drains);
        while heard != 0 {
            let s = heard.trailing_zeros() as usize;
            heard &= heard - 1;
            if let Some(ss) = self.sessions.get_mut(s).filter(|ss| ss.live) {
                ss.exit_drains = true;
            }
        }
        self.step_standbys(now);
        let c = self.cur as usize;
        if self.newer.is_none() && self.next.is_none() && self.sessions[c].exit_drains && !self.sessions[c].answered {
            self.sessions[c].answered = true;
            self.open_next(now);
        }
        let Some(n) = self.next else { return u64::MAX };
        let (up, all) = self.members_of(n);
        let since = self.sessions[n as usize].opened_at;
        if up >= all.div_ceil(4) || now - since >= self.take_over_ns {
            self.take_over(n, up, all);
            return u64::MAX;
        }
        since + self.take_over_ns
    }

    /// Members up and members in all of session s, over every wire.
    fn members_of(&self, s: u8) -> (usize, usize) {
        let (mut up, mut all) = (0, 0);
        for w in self.wires.iter().filter(|w| w.sess == s) {
            up += w.up();
            all += w.members.len();
        }
        for w in self.swires.iter().filter(|w| w.sess == s) {
            up += w.up();
            all += w.links.len();
        }
        (up, all)
    }

    /// The exit drains: a new session with a full pool of every wire the
    /// current one has, coming up (trunk Entry.drained).
    fn open_next(&mut self, now: u64) {
        let Some(n) = self.open_like_cur(None, now) else {
            eprintln!("hk-pipe: the exit drains, no new session: {MAX_SESSIONS} sessions open already");
            return;
        };
        self.next = Some(n);
        let (_, all) = self.members_of(n);
        eprintln!("hk-pipe: the exit drains: a new session of {all} member(s) comes up");
    }

    /// A new session with every wire and pool the current one has, its
    /// members the pipe's own: to the current receiver, or to receiver `to`
    /// (rx, address, pool members: 0 as many as the current one's) on the
    /// same ports. None when MAX_SESSIONS are open.
    fn open_like_cur(&mut self, to: Option<(u8, Ipv4Addr, u8)>, now: u64) -> Option<u8> {
        let n = (0..MAX_SESSIONS).find(|&i| self.sessions.get(i).is_none_or(|s| !s.live))?;
        let cur = self.cur;
        let cur_rx = self.sessions[cur as usize].rx;
        let mut ss = Sess::new(now);
        ss.rx = to.map_or(cur_rx, |t| t.0);
        let rx = ss.rx;
        match self.sessions.get_mut(n) {
            Some(s) => *s = ss,
            None => self.sessions.push(ss),
        }
        let n = n as u8;
        let at = |e: SocketAddrV4| match to {
            Some((_, ip, _)) => SocketAddrV4::new(ip, e.port()),
            None => e,
        };
        let mut add = Vec::new();
        for w in self.wires.iter().filter(|w| w.sess == cur) {
            let mut nw = Wire::new(w.id, w.key, w.stall_ns);
            nw.sess = n;
            nw.rx = rx;
            nw.glue_ns = w.glue_ns;
            nw.glue_max = w.glue_max;
            nw.exit = w.exit.map(at);
            nw.h3 = w.h3;
            for _ in 0..w.members.len() {
                // The QUIC wire's members open their tunnels (h3.rs).
                let m = if w.h3 { Member::plain(&w.key, w.members.first().map_or(0, |m| m.frames_max)) } else { Member::new(nw.exit.and_then(|e| member_to(e).ok()), &w.key) };
                nw.members.push(m);
            }
            add.push(nw);
        }
        self.wires.extend(add);
        // Another receiver's QUIC wires open their tunnels on engines of
        // their own, to its address.
        if to.is_some() {
            let forms: Vec<_> = self.h3s.iter().filter(|h| h.rx == cur_rx).map(|h| (h.id, h.form.clone())).collect();
            for (id, mut f) in forms {
                f.exit = at(f.exit);
                if self.h3s.iter().any(|h| h.id == id && h.rx == rx && h.form == f) {
                    continue;
                }
                self.h3s.retain(|h| !(h.id == id && h.rx == rx));
                match super::h3::H3::new(id, rx, f) {
                    Ok(h) => self.h3s.push(h),
                    Err(e) => eprintln!("hk-pipe: receiver {rx}: wire {id}: {e}"),
                }
            }
        }
        let pools: Vec<_> = self.swires.iter().filter(|w| w.sess == cur).map(|w| (w.id, w.reach.clone(), w.links.len(), w.stall_ns)).collect();
        for (id, reach, links, stall_ns) in pools {
            let (reach, links) = match to {
                None => (reach, links),
                Some((_, ip, 0)) => (reach_at(&reach, ip), links),
                Some((_, ip, members)) => (reach_at(&reach, ip), members as usize),
            };
            let mut sw = StreamWire::new(id, reach, links, stall_ns);
            if to.is_some() {
                // A receiver's pool carries the voice's copies once active.
                sw.set_copies(self.pool_copies.0, self.pool_copies.1);
            }
            sw.sess = n;
            let wi = match self.swires.iter().position(|w| w.sess == NO_SESSION) {
                Some(i) => {
                    self.swires[i] = sw;
                    i
                }
                None => {
                    self.swires.push(sw);
                    self.swires.len() - 1
                }
            };
            for li in 0..links {
                self.redial(wi, li, now);
            }
        }
        self.dirty = true;
        Some(n)
    }

    /// The brain's receiver on standby (B_RECEIVER): rx at ip, on the active
    /// receiver's ports, its pools keeping pool_members (0: as many as the
    /// active one's); ip 0.0.0.0 takes it away. A receiver given again as it
    /// is keeps its session.
    pub(super) fn set_receiver(&mut self, rx: u8, ip: Ipv4Addr, pool_members: u8) -> Result<(), String> {
        if rx == self.sessions[self.cur as usize].rx {
            return Err(format!("receiver {rx} is the active one"));
        }
        let at = self.receivers.iter().position(|r| r.rx == rx);
        if ip.is_unspecified() {
            if let Some(i) = at {
                let r = self.receivers.remove(i);
                if let Some(s) = r.sess {
                    self.close_session(s);
                }
                eprintln!("hk-pipe: receiver {rx} taken away");
            }
            return Ok(());
        }
        match at {
            Some(i) if self.receivers[i].ip == ip && self.receivers[i].pool_members == pool_members => {}
            Some(i) => {
                let r = &mut self.receivers[i];
                (r.ip, r.pool_members, r.stale) = (ip, pool_members, true);
            }
            None => self.receivers.push(Receiver { rx, ip, pool_members, sess: None, stale: true }),
        }
        Ok(())
    }

    /// Each turn: a receiver on standby without a session, or whose session
    /// is stale or heard its exit drain, gets a session anew (none while
    /// the pipe drains itself).
    fn step_standbys(&mut self, now: u64) {
        if self.newer.is_some() {
            return;
        }
        for i in 0..self.receivers.len() {
            let r = &self.receivers[i];
            let drains = r.sess.is_some_and(|s| self.sessions[s as usize].exit_drains);
            if r.sess.is_some() && !r.stale && !drains {
                continue;
            }
            let (rx, ip, members, old) = (r.rx, r.ip, r.pool_members, r.sess);
            if let Some(s) = old {
                self.close_session(s);
            }
            let n = self.open_like_cur(Some((rx, ip, members)), now);
            if let Some(s) = n {
                self.sessions[s as usize].standby = true;
            }
            let r = &mut self.receivers[i];
            (r.sess, r.stale) = (n, false);
            match n {
                Some(s) => {
                    let (_, all) = self.members_of(s);
                    let why = if drains {
                        "its exit drains"
                    } else if old.is_some() {
                        "the active one's wires changed"
                    } else {
                        "new"
                    };
                    eprintln!("hk-pipe: receiver {rx} at {ip}: a standby session of {all} member(s) ({why})");
                }
                None => eprintln!("hk-pipe: receiver {rx}: no standby session, {MAX_SESSIONS} sessions open already"),
            }
        }
    }

    /// A pipe that begins to drain itself lets the receivers' standby
    /// sessions go: they carry nothing, and the newer pipe is given the
    /// receivers by the brain.
    pub(super) fn drop_standbys(&mut self) {
        let sessions: Vec<u8> = self.receivers.iter_mut().filter_map(|r| r.sess.take()).collect();
        for s in sessions {
            self.close_session(s);
        }
    }

    /// The brain's B_ACTIVE: receiver rx carries everything from now. Its
    /// standby session becomes the current one; the old receiver's sessions
    /// (the current one, a retired one, one coming up for its drain) are cut
    /// and closed, their clients' streams and flows ended now; the old
    /// receiver goes on standby at its address, its pools keeping as many
    /// members as rx's did.
    pub(super) fn set_active(&mut self, rx: u8) -> Result<(), String> {
        let old = self.cur;
        let old_rx = self.sessions[old as usize].rx;
        if rx == old_rx {
            return Ok(());
        }
        if self.newer.is_some() {
            return Err(format!("receiver {rx}: the pipe drains, it moves nothing"));
        }
        let Some(i) = self.receivers.iter().position(|r| r.rx == rx) else {
            return Err(format!("receiver {rx}: no such receiver on standby"));
        };
        let Some(n) = self.receivers[i].sess else {
            return Err(format!("receiver {rx}: its standby session is not open yet"));
        };
        let old_ip = self.cur_ip();
        let members = self.receivers[i].pool_members;
        self.receivers.remove(i);
        let now = sys::now_ns();
        self.sessions[n as usize].standby = false;
        self.flows.move_brains(old, n);
        self.cur = n;
        self.next = None;
        let (mut streams, mut flows) = (0, 0);
        let gone: Vec<u8> = (0..self.sessions.len() as u8).filter(|&s| self.sessions[s as usize].live && self.sessions[s as usize].rx == old_rx).collect();
        for s in gone {
            flows += self.flows.end_session(s, END_SESSION, &mut self.freed);
            streams += self.cut_streams(s, super::Why::Session);
            self.close_session(s);
        }
        eprintln!("hk-pipe: trunk: receiver {rx} is the active one; receiver {old_rx} cut: {streams} stream(s) and {flows} flow(s) ended");
        if let Some(ip) = old_ip {
            self.receivers.push(Receiver { rx: old_rx, ip, pool_members: members, sess: None, stale: true });
        }
        self.step_standbys(now);
        if self.ctl.is_some() {
            self.send_tick(now);
        }
        Ok(())
    }

    /// The current receiver's address: its wires' or its pools' exit.
    fn cur_ip(&self) -> Option<Ipv4Addr> {
        let cur = self.cur;
        let wire = self.wires.iter().filter(|w| w.sess == cur).find_map(|w| w.exit.map(|e| *e.ip()));
        wire.or_else(|| {
            self.swires.iter().find(|w| w.sess == cur).map(|w| match &w.reach {
                Reach::Plain(a) => *a.ip(),
                Reach::Chromium(e) => *e.form().exit.ip(),
            })
        })
    }

    /// The receivers on standby for the brain's tick (P_RECEIVERS): each
    /// one's wires and pools, members up of all and its latest proof.
    pub(super) fn standby_ticks(&self, now: u64) -> Vec<crate::ctl::ReceiverTick> {
        let mut out = Vec::with_capacity(self.receivers.len());
        for r in &self.receivers {
            let mut t = crate::ctl::ReceiverTick { rx: r.rx, ip: r.ip, wires: Vec::new() };
            if let Some(s) = r.sess {
                let ago = |p: u64| if p == 0 { crate::ctl::NONE_MS } else { super::ms(now - p) };
                for w in self.wires.iter().filter(|w| w.sess == s) {
                    t.wires.push((w.id, w.members.len() as u8, w.up() as u8, ago(w.proof)));
                }
                for w in self.swires.iter().filter(|w| w.sess == s) {
                    t.wires.push((w.id, w.links.len() as u8, w.up() as u8, ago(w.proof)));
                }
            }
            out.push(t);
        }
        out
    }

    /// Session n takes everything new, the brain's flows with it; the
    /// current one retires (trunk Entry.takeOver).
    fn take_over(&mut self, n: u8, up: usize, all: usize) {
        let old = self.cur;
        let now = sys::now_ns();
        self.sessions[old as usize].retired_at = now.max(1);
        self.flows.move_brains(old, n);
        self.cur = n;
        self.next = None;
        if up < all.div_ceil(4) {
            eprintln!("hk-pipe: trunk: exit drains: the new session has {up} of {all} member(s) after {}s, it takes over anyway", self.take_over_ns / 1_000_000_000);
        }
        let (streams, flows) = (self.streams.on(old), self.flows.on(old));
        eprintln!("hk-pipe: trunk: exit drains: new session, the old one keeps {streams} stream(s) and {flows} flow(s)");
        // The brain's view is the current session's wires: it hears the new
        // one's at once, not on the next second.
        if self.ctl.is_some() {
            self.send_tick(now);
        }
    }

    /// The retired sessions that carry nothing, or have outlived RETIRE_NS
    /// with what they still carry cut (once a second; trunk closeRetired).
    /// The keys of the clients' flows cut go to `freed`.
    pub(super) fn close_retired(&mut self, now: u64) {
        for s in 0..self.sessions.len() {
            let ss = &self.sessions[s];
            if !ss.live || ss.retired_at == 0 {
                continue;
            }
            let s = s as u8;
            let busy = self.flows.on(s) > 0 || self.streams.on(s) > 0;
            let old = now - self.sessions[s as usize].retired_at > self.retire_ns;
            if busy && !old {
                continue;
            }
            if busy {
                let flows = self.flows.end_session(s, END_SESSION, &mut self.freed);
                let streams = self.cut_streams(s, super::Why::Session);
                eprintln!("hk-pipe: trunk: retired session closed after {}s with {streams} stream(s) and {flows} flow(s)", self.retire_ns / 1_000_000_000);
            }
            self.close_session(s);
        }
    }

    /// Session s's members close and its wires go; what its packet wires
    /// counted goes on in `gone`. A StreamWire's slot is kept for the next
    /// session: streams owe by its index.
    pub(super) fn close_session(&mut self, s: u8) {
        let (gone, h3s) = (&mut self.gone, &mut self.h3s);
        let now = sys::now_ns();
        self.wires.retain(|w| {
            if w.sess != s {
                return true;
            }
            // Its tunnels go with its members (member.rs, Drop); their
            // ports go back to the book.
            if let Some(h) = h3s.iter_mut().find(|h| h.id == w.id && h.rx == w.rx && w.h3) {
                for m in &w.members {
                    h.give_back(m.port, false, now);
                }
            }
            let t = counted(w);
            match gone.iter_mut().find(|g| g.id == w.id) {
                Some(g) => add_counts(g, &t),
                None => gone.push(WireTick { id: w.id, ..t }),
            }
            false
        });
        for w in self.swires.iter_mut().filter(|w| w.sess == s) {
            match gone.iter_mut().find(|g| g.id == w.id) {
                Some(g) => add_counts(g, &w.t),
                None => gone.push(w.t),
            }
            for l in w.links.iter_mut() {
                l.drop_sock(&mut self.ports);
                l.renew_at = 0;
            }
            w.sess = NO_SESSION;
        }
        self.sessions[s as usize].live = false;
        self.dirty = true;
    }

    /// A pipe that begins to drain itself lets a session coming up go: it
    /// carries nothing yet. The exit's drain is answered again if the pipe
    /// takes its clients back (its newer generation gone).
    pub(super) fn drop_next(&mut self) {
        if let Some(n) = self.next.take() {
            self.close_session(n);
            self.sessions[self.cur as usize].answered = false;
            eprintln!("hk-pipe: drains itself: the new session for the exit's drain goes");
        }
    }

    /// The exits' epochs the members' hellos said since the last call
    /// (trunk entry.go, the hello's epoch): a session's first is said; a
    /// later one that differs means the exit restarted under the session
    /// and lost what it held of it (trunk Session.Reset). The session's
    /// clients' streams are cut and their flows end (a client's next
    /// datagram opens a new one), and the brain's flows forget the answers
    /// they saw: the exit's new process numbers its answers anew. The
    /// members stay.
    pub(super) fn saw_epochs(&mut self) {
        while let Some((s, epoch)) = self.epochs.pop() {
            let ss = &mut self.sessions[s as usize];
            if !ss.live {
                continue;
            }
            match ss.epoch {
                Some(e) if e == epoch => {}
                None => {
                    ss.epoch = Some(epoch);
                    eprintln!("hk-pipe: trunk: exit epoch {}", hex(&epoch));
                }
                Some(old) => {
                    ss.epoch = Some(epoch);
                    eprintln!("hk-pipe: trunk: exit epoch {} after {}: streams reset", hex(&epoch), hex(&old));
                    let flows = self.flows.end_session(s, END_EPOCH, &mut self.freed);
                    self.flows.forget_answers(s);
                    let streams = self.cut_streams(s, super::Why::Epoch);
                    eprintln!("hk-pipe: the exit lost the session: {streams} stream(s) and {flows} flow(s) ended");
                }
            }
        }
    }

    /// The streams of session s cut: their clients' connections close.
    fn cut_streams(&mut self, s: u8, why: super::Why) -> usize {
        let mut n = 0;
        for slot in 0..self.streams.slots() {
            if self.streams.get(slot).is_some_and(|st| st.sess == s) {
                self.doomed.push((slot, why));
                n += 1;
            }
        }
        self.end_doomed();
        n
    }
}

/// Bytes in lower-case hex, as Go's %x.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
