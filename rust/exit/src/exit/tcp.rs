//! The entry's stream members in the loop (spec/trunk.md, "Member"; link.rs),
//! as the Go exit's session serves them: taken on the pool's port, joined by
//! their hello, their frames read and handed to the streams (stream.rs),
//! their out buffers written, pings and deaths on the members' clock. A
//! member's death and what it carried going again: death.rs.
//!
//! Stream sockets (the pool's listening socket, members, local ends) are
//! watched by one epoll, edge-triggered: each turn takes what it reports,
//! and each socket is read and written until it would block or nothing can
//! go (no credit, no member with room), keeping what it was told.

use std::os::fd::{AsRawFd, OwnedFd};

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::frame::{self, Frame, F_HELLO, F_OBSERVE, KIND_PACKET, KIND_STREAMS, NO_GOT};
use hikkari_trunk::health::{Health, Verdict};

use super::stream::{ack_on, Why};
use super::Exit;
use crate::link::Links;
use crate::streams::{Local, ANY_WIRE};

/// A stream member's hello must come within this of its connection (trunk
/// helloTimeout).
const HELLO_WAIT: u64 = 5_000_000_000;
/// Reads of one member's socket in one turn, at most.
const LINK_READS: usize = 8;
/// The wire of a t1 member (trunk.PoolWire).
const POOL_WIRE: u8 = 0;

/// What an epoll event names: the pool's socket, a member, a local end.
const TAG_POOL: u64 = 0;
const TAG_LINK: u64 = 1 << 62;
pub(super) const TAG_STREAM: u64 = 2 << 62;
const TAG_KIND: u64 = 3 << 62;

#[inline]
pub(super) fn tag(kind: u64, slot: usize, gen: u32) -> u64 {
    kind | (slot as u64) << 32 | gen as u64
}

/// The pool's port: the listening socket stream members connect to, their
/// stall and the session's Quiet.
pub struct Pool {
    pub fd: OwnedFd,
    pub stall_ns: u64,
    pub quiet_ns: u64,
}

/// The member of a session a stream's next frame goes on (trunk pickLocked
/// on the exit): of the wire the entry last sent the stream on while it has
/// a member up, else of any wire; the one owing least; for a chunk, only one
/// with room under INFLIGHT.
pub(super) fn pick(links: &Links, of: &[(usize, u8)], wire: u8, chunk: bool) -> Option<usize> {
    let only = wire != ANY_WIRE && of.iter().any(|&(_, w)| w == wire);
    let mut best: Option<(usize, usize)> = None;
    for &(i, w) in of {
        let l = &links.all[i];
        if only && w != wire || !l.h.up || chunk && !l.takes_chunk() {
            continue;
        }
        if best.is_none_or(|b| l.inflight < b.1) {
            best = Some((i, l.inflight));
        }
    }
    best.map(|b| b.0)
}

impl Exit {
    /// The pool's port, its listening socket watched with the stream sockets.
    pub(super) fn set_pool(&mut self, p: Pool) -> std::io::Result<()> {
        self.tcp.add_io(p.fd.as_raw_fd(), TAG_POOL)?;
        self.pool = Some(p);
        Ok(())
    }

    /// What the stream sockets' epoll says, kept on each socket.
    pub(super) fn tcp_events(&mut self, now: u64) {
        loop {
            let n = self.tcp.ready();
            for i in 0..n {
                let (d, (r, w)) = (self.tcp.data(i), self.tcp.ways(i));
                let (slot, gen) = (((d >> 32) & 0xff_ffff) as usize, d as u32);
                match d & TAG_KIND {
                    TAG_POOL => self.accept_links(now),
                    TAG_LINK => {
                        if let Some(l) = self.links.all.get_mut(slot).filter(|l| l.live && l.gen as u32 == gen) {
                            l.can_read |= r;
                            l.can_write |= w;
                        }
                    }
                    _ => {
                        if let Some(st) = self.streams.at(slot, gen) {
                            st.can_read |= r;
                            st.can_write |= w;
                            // A connect done or failed: the next read or
                            // write says which.
                            if let Some(Local::Tcp { up, .. }) = &mut st.local {
                                *up = true;
                            }
                        }
                    }
                }
            }
            if n < super::TCP_EVENTS {
                return;
            }
        }
    }

    /// New connections on the pool's port: each a member once its hello
    /// comes (trunk Exit.ServeMember).
    fn accept_links(&mut self, now: u64) {
        let Some(pool) = &self.pool else { return };
        let lfd = pool.fd.as_raw_fd();
        while let Some(fd) = sys::accept(lfd) {
            let raw = fd.as_raw_fd();
            let Some(i) = self.links.take(fd, now) else { continue };
            if self.tcp.add_io(raw, tag(TAG_LINK, i, self.links.all[i].gen as u32)).is_err() {
                self.links.close(i);
                continue;
            }
            self.moved += 1;
        }
    }

    /// Every member's frames, as far as its socket has them.
    pub(super) fn read_links(&mut self, now: u64) {
        for li in 0..self.links.all.len() {
            for _ in 0..LINK_READS {
                let l = &mut self.links.all[li];
                if !l.live || !l.can_read {
                    break;
                }
                let Some(fd) = &l.fd else { break };
                match sys::read(fd, &mut l.inb[l.in_n..]) {
                    Io::Done(k) => {
                        l.in_n += k;
                        self.moved += 1;
                        if !self.link_frames(li, now) {
                            self.link_down(li, Down::Gone, now);
                            break;
                        }
                    }
                    Io::Again => {
                        l.can_read = false;
                        break;
                    }
                    Io::Eof | Io::Gone => {
                        self.link_down(li, Down::Gone, now);
                        break;
                    }
                }
            }
        }
        self.end_doomed(now);
    }

    /// The whole frames read on member li (trunk session.go handle); false
    /// for bytes that are no frame, or a first frame that is no hello (the
    /// member is not the entry's).
    fn link_frames(&mut self, li: usize, now: u64) -> bool {
        let inb = std::mem::take(&mut self.links.all[li].inb);
        let n = self.links.all[li].in_n;
        let mut at = 0;
        let mut ok = true;
        while at < n {
            let Some((fr, next)) = frame::next_frame(&inb[..n], at) else {
                ok = (F_HELLO..=F_OBSERVE).contains(&inb[at]); // else: the rest is to come
                break;
            };
            if !self.links.all[li].joined() && !matches!(fr, Frame::Hello) {
                ok = false;
                break;
            }
            match fr {
                Frame::Hello => {
                    if !self.link_hello(li, &inb[..n], at, now) {
                        ok = false;
                        break;
                    }
                }
                Frame::Ping(t) => {
                    self.links.all[li].out.frame(9, |b| frame::put_ping(b, frame::F_PONG, t));
                }
                Frame::Pong(t) => {
                    let l = &mut self.links.all[li];
                    l.h.pong(&mut self.sessions.all[l.session].judge, t, now);
                }
                Frame::Open { stream, port } => self.open_stream(li, stream, port, now),
                Frame::Data { stream, off, at: p, len } => self.stream_data(li, stream, off, &inb[p..p + len], now),
                Frame::Fin { stream, off } => self.stream_fin(li, stream, off, now),
                Frame::Ack { stream, received, credit, flags, got } => self.stream_ack(li, stream, received, credit, flags, got, now),
                Frame::Rst { stream } => {
                    let s = self.links.all[li].session;
                    if let Some(&slot) = self.sessions.all[s].streams.get(&stream) {
                        self.doom(slot, Why::Peer);
                    }
                }
                // Datagrams ride the packet wires (the Rust entry sends them
                // there); a pool member's are R2's.
                Frame::Dgram { .. } => self.t.link_dgrams += 1,
                Frame::Drain | Frame::Other => {}
            }
            at = next;
        }
        let l = &mut self.links.all[li];
        let mut inb = inb;
        inb.copy_within(at..n, 0);
        l.in_n = n - at;
        l.inb = inb;
        self.confirm(now);
        ok
    }

    /// The hello on member li (trunk ServeMember, serve): a t1 hello (the
    /// pool's) or a t2 one of streams joins the session it names, made on
    /// its first hello, and is answered in kind with the session's epoch;
    /// what waits to go again goes, and every stream says how far it is (the
    /// acks a dead member carried may be lost). A copy of the hello changes
    /// nothing. False for a hello of no stream member.
    fn link_hello(&mut self, li: usize, p: &[u8], at: usize, now: u64) -> bool {
        let Some(h) = frame::read_hello(p, at) else { return false };
        if self.links.all[li].joined() {
            return true;
        }
        let (wire, t2) = match h.t2 {
            None => (POOL_WIRE, None),
            Some((w, f)) if f & KIND_STREAMS != 0 && f & KIND_PACKET == 0 => (w, Some(f)),
            Some(_) => return false,
        };
        let Some(pool) = &self.pool else { return false };
        let s = self.sessions.of(h.session, pool.quiet_ns, now);
        let Exit { links, sessions, streams, pause, t, .. } = self;
        let sess = &mut sessions.all[s];
        sess.judge.resumed = sess.judge.resumed.max(pause.resumed);
        let l = &mut links.all[li];
        l.session = s;
        l.wire = wire;
        l.t2 = t2;
        l.h = Health::new(false);
        l.h.join(now);
        sess.link_join(li, wire);
        t.links += 1;
        t.joined += 1;
        let (id, epoch) = (sess.id, sess.epoch);
        l.out.frame(31, |b| frame::put_hello(b, &id, &epoch, t2.map(|f| (wire, f))));
        for &slot in sess.streams.values() {
            ack_on(&mut l.out, &mut streams.all[slot], NO_GOT);
        }
        self.resend(s, now);
        true
    }

    /// Every member's waiting frames, as much as its socket takes.
    pub(super) fn flush_links(&mut self, now: u64) {
        for li in 0..self.links.all.len() {
            let l = &mut self.links.all[li];
            if l.live && l.out.pending() && !l.flush() {
                self.link_down(li, Down::Gone, now);
            }
        }
        self.end_doomed(now);
    }

    /// Stream members on the members' clock: a hello not come within
    /// HELLO_WAIT closes the connection, pings and deaths as any member's
    /// (hikkari_trunk::health), judged by the member's session.
    pub(super) fn link_clock(&mut self, now: u64) {
        let Some(stall) = self.pool.as_ref().map(|p| p.stall_ns) else { return };
        for li in 0..self.links.all.len() {
            let Exit { links, sessions, tok, .. } = self;
            let l = &mut links.all[li];
            if !l.live {
                continue;
            }
            if !l.joined() {
                if now.saturating_sub(l.accepted_at) > HELLO_WAIT {
                    links.close(li);
                }
                continue;
            }
            match l.h.tick(&sessions.all[l.session].judge, stall, now, tok) {
                Verdict::Fine => {}
                Verdict::Ping(k) => {
                    l.out.frame(9, |b| frame::put_ping(b, frame::F_PING, k));
                }
                Verdict::Dead { quiet } => self.link_down(li, if quiet { Down::Quiet } else { Down::Silent }, now),
            }
        }
    }
}

/// Why a stream member is down.
#[derive(Clone, Copy)]
pub(super) enum Down {
    /// Past its stall while another member proved the entry alive.
    Silent,
    /// Every member silent past Quiet.
    Quiet,
    /// Its connection failed or ended, or spoke no trunk.
    Gone,
}
