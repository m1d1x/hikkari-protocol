//! The exit's sessions (trunk exit.go): one per entry session id, its
//! members joining it by the id in their hello, its epoch random per session
//! (an entry that sees it change knows the exit lost its flows), its
//! members' proof and Quiet (hikkari_trunk::health::Judge: the exit's Quiet
//! is 30 s, it cannot open members and waits for the entry to), its flows by
//! stream id. A session left without members for SESSION_IDLE ends with its
//! flows: the entry is gone, and so are its clients.

use std::collections::HashMap;

use hikkari_sys as sys;
use hikkari_trunk::health::Judge;

use crate::flow::Seen;

/// trunk SessionIdle.
pub const SESSION_IDLE: u64 = 120_000_000_000;

pub struct Session {
    pub live: bool,
    pub id: [u8; 16],
    pub epoch: [u8; 8],
    pub judge: Judge,
    /// Its members (peer slots and their gens), up ones only.
    pub members: Vec<Seen>,
    /// The members of each wire, by wire id: what an answer of a flow
    /// whose own members are gone goes on (flow::Flow::carriers).
    pub by_wire: Vec<(u8, Vec<Seen>)>,
    /// Since when it has had no member (0 while it has one).
    pub empty_since: u64,
    pub flows: HashMap<u32, usize>,
}

impl Session {
    fn new(id: [u8; 16], quiet_ns: u64) -> Session {
        let mut epoch = [0u8; 8];
        sys::urandom(&mut epoch);
        Session {
            live: true,
            id,
            epoch,
            judge: Judge::new(quiet_ns),
            members: Vec::new(),
            by_wire: Vec::new(),
            empty_since: 0,
            flows: HashMap::with_capacity(256),
        }
    }

    pub fn join(&mut self, m: Seen, wire: u8) {
        self.members.push(m);
        match self.by_wire.iter_mut().find(|(w, _)| *w == wire) {
            Some((_, ms)) => ms.push(m),
            None => self.by_wire.push((wire, vec![m])),
        }
        self.empty_since = 0;
    }

    pub fn leave(&mut self, m: Seen, now: u64) {
        self.members.retain(|&x| x != m);
        for (_, ms) in self.by_wire.iter_mut() {
            ms.retain(|&x| x != m);
        }
        if self.members.is_empty() {
            self.empty_since = now;
        }
    }

    /// Its members up on `wire`.
    pub fn of_wire(&self, wire: u8) -> &[Seen] {
        self.by_wire.iter().find(|(w, _)| *w == wire).map_or(&[], |(_, ms)| ms)
    }
}

pub struct Sessions {
    pub all: Vec<Session>,
    by_id: HashMap<[u8; 16], usize>,
}

impl Default for Sessions {
    fn default() -> Sessions {
        Sessions::new()
    }
}

impl Sessions {
    pub fn new() -> Sessions {
        Sessions { all: Vec::new(), by_id: HashMap::new() }
    }

    /// The session of `id`, made on the first hello that names it.
    pub fn of(&mut self, id: [u8; 16], quiet_ns: u64, now: u64) -> usize {
        if let Some(&s) = self.by_id.get(&id) {
            return s;
        }
        let s = match self.all.iter().position(|x| !x.live) {
            Some(i) => {
                self.all[i] = Session::new(id, quiet_ns);
                i
            }
            None => {
                self.all.push(Session::new(id, quiet_ns));
                self.all.len() - 1
            }
        };
        self.all[s].empty_since = now;
        self.by_id.insert(id, s);
        s
    }

    /// Ends session s: the caller has ended its flows.
    pub fn end(&mut self, s: usize) {
        let x = &mut self.all[s];
        x.live = false;
        self.by_id.remove(&x.id);
    }

    pub fn live(&self) -> u32 {
        self.by_id.len() as u32
    }
}
