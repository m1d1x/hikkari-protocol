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

use hikkari_sys as sys;

use super::Pipe;
use crate::ctl::WireTick;
use crate::link::{StreamWire, NO_SESSION};
use crate::member::{member_to, Member, Wire};

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
}

impl Sess {
    pub fn new(now: u64) -> Sess {
        let mut id = [0u8; 16];
        sys::urandom(&mut id);
        Sess { id, live: true, exit_drains: false, answered: false, opened_at: now, retired_at: 0 }
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
        let Some(n) = (0..MAX_SESSIONS).find(|&i| self.sessions.get(i).is_none_or(|s| !s.live)) else {
            eprintln!("hk-pipe: the exit drains, no new session: {MAX_SESSIONS} sessions open already");
            return;
        };
        let ss = Sess::new(now);
        match self.sessions.get_mut(n) {
            Some(s) => *s = ss,
            None => self.sessions.push(ss),
        }
        let (n, cur) = (n as u8, self.cur);
        let mut add = Vec::new();
        for w in self.wires.iter().filter(|w| w.sess == cur) {
            let mut nw = Wire::new(w.id, w.key, w.stall_ns);
            nw.sess = n;
            nw.glue_ns = w.glue_ns;
            nw.glue_max = w.glue_max;
            nw.exit = w.exit;
            nw.h3 = w.h3;
            for _ in 0..w.members.len() {
                // The QUIC wire's members open their tunnels (h3.rs).
                let m = if w.h3 { Member::plain(&w.key, w.members.first().map_or(0, |m| m.frames_max)) } else { Member::new(w.exit.and_then(|e| member_to(e).ok()), &w.key) };
                nw.members.push(m);
            }
            add.push(nw);
        }
        self.wires.extend(add);
        let pools: Vec<_> = self.swires.iter().filter(|w| w.sess == cur).map(|w| (w.id, w.reach.clone(), w.links.len(), w.stall_ns)).collect();
        for (id, reach, links, stall_ns) in pools {
            let mut sw = StreamWire::new(id, reach, links, stall_ns);
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
        self.next = Some(n);
        self.dirty = true;
        let (_, all) = self.members_of(n);
        eprintln!("hk-pipe: the exit drains: a new session of {all} member(s) comes up");
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
            eprintln!("hk-pipe: the exit drains: the new session has {up} of {all} member(s) after {} s, it takes over anyway", self.take_over_ns / 1_000_000_000);
        }
        let (streams, flows) = (self.streams.on(old), self.flows.on(old));
        eprintln!("hk-pipe: the exit drains: new session, the old one keeps {streams} stream(s) and {flows} flow(s)");
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
                let flows = self.flows.end_session(s, &mut self.freed);
                let streams = self.cut_streams(s);
                eprintln!("hk-pipe: retired session closed after {} s with {streams} stream(s) and {flows} flow(s)", self.retire_ns / 1_000_000_000);
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
            if let Some(h) = h3s.iter_mut().find(|h| h.id == w.id && w.h3) {
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

    /// The streams of session s cut: their clients' connections close.
    fn cut_streams(&mut self, s: u8) -> usize {
        let mut n = 0;
        for slot in 0..self.streams.slots() {
            if self.streams.get(slot).is_some_and(|st| st.sess == s) {
                self.doomed.push((slot, super::Why::Local));
                n += 1;
            }
        }
        self.end_doomed();
        n
    }
}
