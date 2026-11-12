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
use std::os::fd::OwnedFd;

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::stream::{Recv, Send};

use crate::flow::FxMap;

/// A stream's client side: its connection, and what waits for it.
pub struct Client {
    pub fd: OwnedFd,
    /// Received in order and not yet taken by the client, at down[down_at..].
    down: Vec<u8>,
    down_at: usize,
}

impl Client {
    pub fn down_pending(&self) -> bool {
        self.down_at < self.down.len()
    }

    /// Bytes for the client: written now while nothing waits before them,
    /// the rest kept for when the client takes more. How many were written;
    /// None when the client is gone.
    pub fn give(&mut self, p: &[u8]) -> Option<usize> {
        let mut n = 0;
        if !self.down_pending() {
            match sys::write(&self.fd, p) {
                Io::Done(k) => n = k,
                Io::Again => {}
                Io::Eof | Io::Gone => return None,
            }
            self.down.clear();
            self.down_at = 0;
        }
        self.down.extend_from_slice(&p[n..]);
        Some(n)
    }

    /// Writes what waits for the client: how many bytes it took; None when
    /// it is gone.
    pub fn flush_down(&mut self) -> Option<usize> {
        if !self.down_pending() {
            return Some(0);
        }
        match sys::write(&self.fd, &self.down[self.down_at..]) {
            Io::Done(k) => {
                self.down_at += k;
                // A client always behind would grow the buffer by all it was
                // ever sent: what it took goes once it is the larger half.
                if self.down_at > self.down.len() / 2 {
                    self.down.drain(..self.down_at);
                    self.down_at = 0;
                }
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
    /// The exit's FIN is written: the client's side is shut.
    pub write_done: bool,
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
    /// Reset because a member carrying its unconfirmed bytes died (R1.3
    /// sends nothing again; R1.4 moves them to another member).
    pub cut: u64,
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
        }
    }

    /// A new client connection to the exit's port: its slot.
    pub fn add(&mut self, fd: OwnedFd, port: u16) -> usize {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let st = Stream {
            client: Client { fd, down: Vec::new(), down_at: 0 },
            id: self.next_id,
            port,
            opened: false,
            send: Send::default(),
            recv: Recv::default(),
            read_done: false,
            write_done: false,
        };
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
        self.by_id.insert(self.next_id, slot as u32);
        self.unopened += 1;
        self.open += 1;
        self.n.opened += 1;
        slot
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

    /// Ends the stream in `slot`: its client connection closes.
    pub fn end(&mut self, slot: usize) {
        if let Some(st) = self.list[slot].take() {
            self.by_id.remove(&st.id);
            if !st.opened {
                self.unopened -= 1;
            }
            self.open -= 1;
            self.free.push(slot);
        }
    }
}
