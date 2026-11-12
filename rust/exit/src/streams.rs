//! The exit's streams (spec/trunk.md, "Streams"; trunk session.go on the
//! exit: openLocked, dataLocked, finLocked, writeLocal, readLocal,
//! endStreamLocked, holdEarlyLocked): the entry's open names a stream id of
//! its session and a loopback port, and the exit connects to it, the
//! entry's chunks are put in order and written to that connection, its
//! bytes are numbered into chunks back (hikkari_trunk::stream). Port 0 is
//! the trunk's own download (trunk sourceConn): the 8 bytes the entry writes
//! ask for n bytes, sent back and then the end.
//!
//! A stream's id lives in its session (session.rs: streams, closed, early);
//! here are the streams themselves, in one slab, and what the exit holds of
//! a stream whose open has not come yet.

use std::os::fd::OwnedFd;

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::buf::Behind;
use hikkari_trunk::stream::{Recv, Send, CHUNK, WINDOW};

use crate::peer::NONE;

/// Most bytes the trunk's own download gives (trunk MaxDownload).
pub const MAX_DOWNLOAD: u64 = 64 << 20;
/// What the exit holds for streams whose open has not come (trunk
/// earlyStreams, earlyTotal, earlyFor): a stream's window, in all as much as
/// a full pool carries, for 30 s.
pub const EARLY_STREAMS: usize = 1024;
pub const EARLY_TOTAL: usize = 64 << 20;
pub const EARLY_FOR: u64 = 30_000_000_000;
/// A finished stream's id is remembered this long (trunk closedMemory), so
/// its late frames are answered and do not open it again.
pub const CLOSED_MEMORY: u64 = 120_000_000_000;

/// The stream's end on the exit's box.
pub enum Local {
    /// A TCP connection to the loopback port; `up` once the connect is done
    /// (or failed: the next read or write says so).
    Tcp { fd: OwnedFd, up: bool },
    /// The trunk's own download: the request's bytes as they come, then n
    /// zero bytes to send.
    Source { req: [u8; 8], have: usize, left: u64 },
}

/// What reading the local end gave.
pub enum Read {
    Bytes(usize),
    Again,
    End,
    Gone,
}

impl Local {
    /// Reads into buf (a member's out buffer, behind a chunk's head).
    pub fn read(&mut self, buf: &mut [u8]) -> Read {
        match self {
            Local::Tcp { up: false, .. } => Read::Again,
            Local::Tcp { fd, .. } => match sys::read(fd, buf) {
                Io::Done(n) => Read::Bytes(n),
                Io::Again => Read::Again,
                Io::Eof => Read::End,
                Io::Gone => Read::Gone,
            },
            Local::Source { have, left, .. } => {
                if *have < 8 {
                    return Read::Again;
                }
                if *left == 0 {
                    return Read::End;
                }
                let n = (*left).min(buf.len() as u64) as usize;
                buf[..n].fill(0);
                *left -= n as u64;
                Read::Bytes(n)
            }
        }
    }

    /// Writes p now as far as the end takes it: how many bytes, None when
    /// it is gone. A source takes its request and drops the rest, as the Go
    /// source reads nothing past it.
    pub fn write(&mut self, p: &[u8]) -> Option<usize> {
        match self {
            Local::Tcp { up: false, .. } => Some(0),
            Local::Tcp { fd, .. } => match sys::write(fd, p) {
                Io::Done(n) => Some(n),
                Io::Again => Some(0),
                Io::Eof | Io::Gone => None,
            },
            Local::Source { req, have, left } => {
                let k = (8 - *have).min(p.len());
                req[*have..*have + k].copy_from_slice(&p[..k]);
                *have += k;
                if *have == 8 && k > 0 {
                    let n = u64::from_be_bytes(*req);
                    if n > MAX_DOWNLOAD {
                        return None;
                    }
                    *left = n;
                }
                Some(p.len())
            }
        }
    }

    /// Whether it is up: a connection whose connect is done (or failed), or
    /// a source.
    pub fn up(&self) -> bool {
        !matches!(self, Local::Tcp { up: false, .. })
    }

    /// A source never waits for its socket: it has none.
    pub fn is_source(&self) -> bool {
        matches!(self, Local::Source { .. })
    }

    /// Ends the writing side: the local end reads its end (CloseWrite).
    pub fn shut(&self) {
        if let Local::Tcp { fd, .. } = self {
            sys::shutdown_write(fd);
        }
    }

    /// Its descriptor, if it has one.
    pub fn fd(&self) -> Option<&OwnedFd> {
        match self {
            Local::Tcp { fd, .. } => Some(fd),
            Local::Source { .. } => None,
        }
    }
}

pub struct Stream {
    pub live: bool,
    /// Counts the slot's uses: a socket's readiness names a stream by slot
    /// and gen, so a late one for a stream that ended finds nothing.
    pub gen: u32,
    pub session: usize,
    pub id: u32,
    pub local: Option<Local>,
    pub can_read: bool,
    pub can_write: bool,
    pub send: Send,
    pub recv: Recv,
    /// Received in order and not yet taken by the local end.
    pub behind: Behind,
    /// The wire the entry last sent it on (trunk followLocked): its chunks
    /// and acks go back on it while it has a member up.
    pub wire: u8,
    /// The local end ended its side: the FIN went to the entry.
    pub read_done: bool,
    /// The entry's FIN reached the local end.
    pub write_done: bool,
}

impl Stream {
    fn vacant() -> Stream {
        Stream {
            live: false,
            gen: 0,
            session: NONE,
            id: 0,
            local: None,
            can_read: false,
            can_write: false,
            send: Send::default(),
            recv: Recv::default(),
            behind: Behind::default(),
            wire: ANY_WIRE,
            read_done: false,
            write_done: false,
        }
    }

    /// Writes what waits for the local end: how many bytes it took; None
    /// when it is gone.
    pub fn flush_behind(&mut self) -> Option<usize> {
        if !self.behind.pending() || !self.can_write {
            return Some(0);
        }
        let Some(l) = self.local.as_mut() else { return Some(0) };
        let n = l.write(self.behind.bytes())?;
        if n < self.behind.bytes().len() {
            self.can_write = false;
        }
        self.behind.took(n);
        Some(n)
    }

    /// The entry's FIN reaches the local end once everything before it did
    /// and the local end is up.
    pub fn shut_if_all_in(&mut self) {
        let up = self.local.as_ref().is_some_and(|l| l.up());
        if !self.write_done && up && self.recv.all_in() && !self.behind.pending() {
            if let Some(l) = &self.local {
                l.shut();
            }
            self.write_done = true;
        }
    }

    /// Both directions are over (trunk maybeFinishLocked): its FIN
    /// confirmed, the entry's written.
    pub fn finished(&self) -> bool {
        self.send.fin_done && self.write_done
    }
}

/// Bytes for a stream's local end: written now while nothing waits before
/// them, the rest kept behind for when it takes more (a local end not up
/// yet takes none). How many were written; None when it is gone.
pub fn give(local: &mut Option<Local>, behind: &mut Behind, p: &[u8]) -> Option<usize> {
    let mut n = 0;
    if !behind.pending() {
        if let Some(l) = local.as_mut() {
            n = l.write(p)?;
        }
    }
    behind.push(&p[n..]);
    Some(n)
}

/// trunk AnyWire: no wire yet.
pub const ANY_WIRE: u8 = 255;

/// How streams ended and what they carried, since the exit started.
#[derive(Clone, Copy, Default)]
pub struct StreamCounts {
    pub opened: u64,
    /// Both FINs confirmed and written.
    pub fin: u64,
    /// Reset by the entry.
    pub reset_peer: u64,
    /// Reset here: the local end failed or could not be reached, its port
    /// not open to the trunk, or the session ended under it.
    pub reset_local: u64,
    /// Times a member died carrying a stream's unconfirmed chunks or FIN
    /// (once per stream and death), and chunks sent again for it.
    pub deaths: u64,
    pub resent: u64,
    /// Bytes read from local ends and written to them (trunk Stats.Up,
    /// Stats.Down).
    pub up: u64,
    pub down: u64,
    /// Chunks and FINs of a stream not open yet: held, and dropped past the
    /// bounds.
    pub early: u64,
    pub early_dropped: u64,
}

pub struct Streams {
    pub all: Vec<Stream>,
    free: Vec<usize>,
    pub open: u32,
    pub n: StreamCounts,
}

impl Default for Streams {
    fn default() -> Streams {
        Streams::new()
    }
}

impl Streams {
    pub fn new() -> Streams {
        Streams { all: Vec::with_capacity(256), free: Vec::new(), open: 0, n: StreamCounts::default() }
    }

    /// A new stream `id` of session s: its slot.
    pub fn open(&mut self, s: usize, id: u32) -> usize {
        let i = self.free.pop().unwrap_or_else(|| {
            self.all.push(Stream::vacant());
            self.all.len() - 1
        });
        let gen = self.all[i].gen.wrapping_add(1);
        self.all[i] = Stream { live: true, gen, session: s, id, ..Stream::vacant() };
        self.open += 1;
        self.n.opened += 1;
        i
    }

    /// Frees slot i (the caller took its socket off the poll first).
    pub fn end(&mut self, i: usize) {
        let st = &mut self.all[i];
        if !st.live {
            return;
        }
        st.live = false;
        st.local = None;
        // A long stream's buffers are not kept for the next one.
        st.send = Send::default();
        st.recv = Recv::default();
        st.behind = Behind::default();
        self.open -= 1;
        self.free.push(i);
    }

    /// Stream i if it is still the use `gen` names.
    #[inline]
    pub fn at(&mut self, i: usize, gen: u32) -> Option<&mut Stream> {
        self.all.get_mut(i).filter(|st| st.live && st.gen == gen)
    }
}

/// A chunk or FIN that came before its stream's open: its offset, and for a
/// chunk its bytes.
pub struct EarlyFrame {
    pub fin: bool,
    pub off: u64,
    pub bytes: Vec<u8>,
}

/// What the exit holds of one stream whose open has not come.
pub struct Early {
    pub frames: Vec<EarlyFrame>,
    pub bytes: usize,
    pub since: u64,
}

impl Early {
    /// Whether a chunk of n more bytes fits a stream's bound (its window
    /// and a chunk), given what every early stream holds already.
    pub fn fits(&self, n: usize, all: usize) -> bool {
        self.bytes + n <= WINDOW as usize + CHUNK && all + n <= EARLY_TOTAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// trunk sourceConn: the 8 bytes of the request, in any cut, ask for n
    /// bytes; then the end. Past MaxDownload, nothing.
    #[test]
    fn the_source_gives_what_its_request_asks() {
        let mut l = Local::Source { req: [0; 8], have: 0, left: 0 };
        let mut buf = [9u8; 64];
        assert!(matches!(l.read(&mut buf), Read::Again), "nothing before the request");
        let req = 100u64.to_be_bytes();
        assert_eq!(l.write(&req[..3]), Some(3));
        assert!(matches!(l.read(&mut buf), Read::Again));
        assert_eq!(l.write(&[&req[3..], b"more"].concat()), Some(9), "what follows the request is dropped");
        let (mut got, mut end) = (0, false);
        while !end {
            match l.read(&mut buf) {
                Read::Bytes(n) => {
                    assert!(buf[..n].iter().all(|&b| b == 0));
                    got += n;
                }
                Read::End => end = true,
                _ => panic!("a source neither gives nor ends"),
            }
        }
        assert_eq!(got, 100);
        let mut l = Local::Source { req: [0; 8], have: 0, left: 0 };
        assert_eq!(l.write(&(MAX_DOWNLOAD + 1).to_be_bytes()), None);
    }

    #[test]
    fn a_slot_used_again_is_a_new_stream() {
        let mut s = Streams::new();
        let i = s.open(0, 7);
        let g = s.all[i].gen;
        s.end(i);
        let j = s.open(0, 8);
        assert_eq!((i, s.open), (j, 1));
        assert!(s.at(i, g).is_none(), "the old stream's readiness finds nothing");
        assert_eq!(s.n.opened, 2);
    }
}
