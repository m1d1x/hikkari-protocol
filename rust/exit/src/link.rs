//! The entry's stream members on the exit (spec/trunk.md, "Member": a t1
//! hello, or a t2 one with the streams flag, then frames one after another
//! on the byte stream, both ways), each over a TCP connection of its own
//! that the exit accepted. Here the connection is plain TCP, as the bench's
//! Go exit takes its pool; Chromium's TLS goes under it in R2. The
//! reference is trunk exit.go ServeMember and session.go serve: the first
//! frame is the hello, answered in kind with the session's epoch, within
//! helloTimeout of the connection.
//!
//! Nothing is allocated per frame: a member's buffers (hikkari_trunk::buf)
//! are allocated with its slot and kept for the next member in it.

use std::os::fd::OwnedFd;

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::buf::{Out, IN};
use hikkari_trunk::health::Health;
use hikkari_trunk::stream::{CHUNK, INFLIGHT};

use crate::peer::NONE;

/// Most stream members at once: a carrier names a member by a slot of 16
/// bits (carrier()).
pub const MAX_LINKS: usize = 4096;

pub struct Link {
    /// A slot in use; gen counts its uses, so what a stream owes names the
    /// member that carried it and not one that came after it in the slot.
    pub live: bool,
    pub gen: u16,
    pub fd: Option<OwnedFd>,
    /// The member's session (NONE until its hello) and its wire as its
    /// hello says it (trunk.PoolWire for a t1 hello).
    pub session: usize,
    pub wire: u8,
    /// Its t2 hello's flags, None for a t1 one: the answer is in kind.
    pub t2: Option<u8>,
    pub h: Health,
    pub out: Out,
    pub inb: Box<[u8]>,
    /// Bytes read and not yet a whole frame, at inb[..in_n].
    pub in_n: usize,
    /// Unconfirmed chunk bytes it carries (trunk member.inflight).
    pub inflight: usize,
    /// Chunks and FINs it carries that are not confirmed yet (trunk
    /// member.segs): it owes progress while there is one.
    pub owing: u32,
    /// When the exit took its connection: its hello is due within
    /// HELLO_WAIT of it.
    pub accepted_at: u64,
    /// What the socket's epoll said and nothing since undid: it has bytes,
    /// it takes bytes (edge-triggered: told once, until it would block).
    pub can_read: bool,
    pub can_write: bool,
}

impl Link {
    fn vacant() -> Link {
        Link {
            live: false,
            gen: 0,
            fd: None,
            session: NONE,
            wire: 0,
            t2: None,
            h: Health::new(false),
            out: Out::new(),
            inb: vec![0; IN].into_boxed_slice(),
            in_n: 0,
            inflight: 0,
            owing: 0,
            accepted_at: 0,
            can_read: false,
            can_write: false,
        }
    }

    /// A member: its hello answered, in a session.
    #[inline]
    pub fn joined(&self) -> bool {
        self.live && self.session != NONE
    }

    /// Whether it takes a chunk now (trunk pickLocked with room): it is up,
    /// and owes nothing or has room under INFLIGHT for a whole chunk.
    pub fn takes_chunk(&self) -> bool {
        self.h.up && (self.inflight == 0 || self.inflight + CHUNK <= INFLIGHT)
    }

    /// It carries one more thing to be confirmed: from owing nothing, its
    /// debt begins now.
    pub fn owe(&mut self, bytes: usize, now: u64) {
        if self.owing == 0 {
            self.h.busy_since = now;
        }
        self.owing += 1;
        self.inflight += bytes;
    }

    /// Something it carried is off its debt: confirmed (the member's proof)
    /// or dropped with its stream.
    pub fn release(&mut self, bytes: usize) {
        self.inflight -= bytes;
        self.owing -= 1;
        if self.owing == 0 {
            self.h.busy_since = 0;
        }
    }

    /// Writes what waits, as much as the socket takes: false when it failed.
    pub fn flush(&mut self) -> bool {
        let Some(fd) = &self.fd else { return true };
        while self.can_write && self.out.pending() {
            match sys::write(fd, self.out.bytes()) {
                Io::Done(n) => self.out.wrote(n),
                Io::Again => self.can_write = false,
                Io::Eof | Io::Gone => return false,
            }
        }
        true
    }
}

/// Every stream member in one slab.
pub struct Links {
    pub all: Vec<Link>,
    free: Vec<usize>,
}

impl Default for Links {
    fn default() -> Links {
        Links::new()
    }
}

impl Links {
    pub fn new() -> Links {
        Links { all: Vec::new(), free: Vec::new() }
    }

    /// A slot for a connection the exit took; None when MAX_LINKS are open.
    pub fn take(&mut self, fd: OwnedFd, now: u64) -> Option<usize> {
        let i = match self.free.pop() {
            Some(i) => i,
            None if self.all.len() < MAX_LINKS => {
                self.all.push(Link::vacant());
                self.all.len() - 1
            }
            None => return None,
        };
        let l = &mut self.all[i];
        l.live = true;
        l.gen = l.gen.wrapping_add(1);
        l.fd = Some(fd);
        l.session = NONE;
        l.wire = 0;
        l.t2 = None;
        l.h = Health::new(false);
        l.out.clear();
        l.in_n = 0;
        l.inflight = 0;
        l.owing = 0;
        l.accepted_at = now;
        // A socket just taken may hold its hello already: read it at once.
        l.can_read = true;
        l.can_write = true;
        Some(i)
    }

    /// Closes the member in slot i; the slot is free for the next one.
    pub fn close(&mut self, i: usize) {
        let l = &mut self.all[i];
        if !l.live {
            return;
        }
        l.live = false;
        l.fd = None;
        l.h.down();
        l.session = NONE;
        l.out.clear();
        l.in_n = 0;
        self.free.push(i);
    }

    /// The member a carrier names, if it is still that one and up.
    #[inline]
    pub fn of_carrier(&mut self, c: u32) -> Option<&mut Link> {
        let (i, gen) = carrier_of(c);
        self.all.get_mut(i).filter(|l| l.live && l.gen == gen)
    }
}

/// What a stream owes names its member: the slot and its use.
#[inline]
pub fn carrier(slot: usize, gen: u16) -> u32 {
    (slot as u32) << 16 | gen as u32
}

#[inline]
pub fn carrier_of(c: u32) -> (usize, u16) {
    ((c >> 16) as usize, c as u16)
}
