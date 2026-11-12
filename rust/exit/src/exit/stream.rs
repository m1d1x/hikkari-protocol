//! The entry's streams in the loop (spec/trunk.md, "Streams"; streams.rs),
//! as the Go exit's session carries them (trunk session.go: openLocked,
//! dataLocked, finLocked, ackedLocked, holdEarlyLocked, endStreamLocked,
//! readLocal, writeLocal): the entry's opens connected to their loopback
//! ports, its chunks put in order, written to the local end and acked on
//! the member they came on, the local end's bytes read straight into
//! members' out buffers as chunks back, FINs both ways, resets, chunks and
//! FINs that came before their open held. Frames come from the members
//! (tcp.rs).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;

use hikkari_sys as sys;
use hikkari_trunk::frame::{self, ACK_FIN, ACK_LEN, NO_GOT};
use hikkari_trunk::stream::{CHUNK, NO_CARRIER};

use super::tcp::{pick, tag, TAG_STREAM};
use super::Exit;
use crate::link::{carrier, Links};
use crate::streams::{give, Early, EarlyFrame, Local, Read, EARLY_STREAMS};

/// Chunks read from one local end in one turn, at most: one busy stream
/// does not hold up the others.
const READS_PER_TURN: usize = 64;
/// A reset goes on this many members (trunk endStreamLocked: Copies).
const RST_COPIES: usize = 2;

/// Why a stream ends.
#[derive(Clone, Copy)]
pub(super) enum Why {
    /// The entry reset it: nothing to tell it.
    Peer,
    /// Its local end failed or could not be reached.
    Local,
    /// Both directions are over: no reset, it ends.
    Done,
}

/// What a stream owed and no longer does, without a confirmation: the
/// member it went on carries it no more.
pub(super) fn forget(links: &mut Links, c: u32, len: u32) {
    if c == NO_CARRIER {
        return;
    }
    if let Some(l) = links.of_carrier(c) {
        l.release(len as usize);
    }
}

impl Exit {
    /// The entry's open of stream `id` to `port` on member li (trunk
    /// openLocked): a copy is acked again, a stream that ended is reset; a
    /// new one takes what came before it, is acked, and connects to its
    /// loopback port (port 0: the trunk's own download). A port not open to
    /// the trunk, or one that refuses, resets it.
    pub(super) fn open_stream(&mut self, li: usize, id: u32, port: u16, now: u64) {
        let (s, wire) = (self.links.all[li].session, self.links.all[li].wire);
        let sess = &mut self.sessions.all[s];
        if let Some(&slot) = sess.streams.get(&id) {
            self.streams.all[slot].wire = wire;
            ack_on(&mut self.links.all[li].out, &mut self.streams.all[slot], NO_GOT);
            return;
        }
        if sess.closed.contains_key(&id) {
            self.links.all[li].out.frame(5, |b| frame::put_rst(b, id));
            return;
        }
        let slot = self.streams.open(s, id);
        sess.streams.insert(id, slot);
        self.streams.all[slot].wire = wire;
        if let Some(e) = sess.early.remove(&id) {
            sess.early_bytes -= e.bytes;
            for f in e.frames {
                if f.fin {
                    self.stream_fin(li, id, f.off, now);
                } else {
                    self.stream_data(li, id, f.off, &f.bytes, now);
                }
            }
        }
        if !self.streams.all[slot].live {
            return;
        }
        ack_on(&mut self.links.all[li].out, &mut self.streams.all[slot], NO_GOT);
        let gen = self.streams.all[slot].gen;
        if port == hikkari_trunk::flow::ECHO_PORT {
            let st = &mut self.streams.all[slot];
            st.local = Some(Local::Source { req: [0; 8], have: 0, left: 0 });
            st.can_read = true;
            st.can_write = true;
            return;
        }
        if !self.ports[port as usize] {
            self.t.refused_streams += 1;
            self.doom(slot, Why::Local);
            return;
        }
        match sys::tcp_connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
            Ok(fd) if self.tcp.add_io(fd.as_raw_fd(), tag(TAG_STREAM, slot, gen)).is_ok() => {
                self.streams.all[slot].local = Some(Local::Tcp { fd, up: false });
            }
            _ => {
                self.t.refused_streams += 1;
                self.doom(slot, Why::Local);
            }
        }
    }

    /// A chunk of stream `id` at `off` on member li (trunk dataLocked): put
    /// in order, written on to the local end, acked on li naming it. A chunk
    /// of a stream that ended is reset; of one not open yet, held.
    pub(super) fn stream_data(&mut self, li: usize, id: u32, off: u64, p: &[u8], now: u64) {
        let (s, wire) = (self.links.all[li].session, self.links.all[li].wire);
        let Some(&slot) = self.sessions.all[s].streams.get(&id) else {
            if self.sessions.all[s].closed.contains_key(&id) {
                self.links.all[li].out.frame(5, |b| frame::put_rst(b, id));
            } else {
                self.hold_early(s, id, false, off, p, now);
            }
            return;
        };
        let st = &mut self.streams.all[slot];
        st.wire = wire;
        let (mut wrote, mut gone) = (0, false);
        let got = {
            let (recv, local, behind) = (&mut st.recv, &mut st.local, &mut st.behind);
            recv.chunk(off, p, |q| match give(local, behind, q) {
                Some(k) => wrote += k,
                None => gone = true,
            })
        };
        if st.local.as_ref().is_some_and(|l| l.is_source()) {
            st.can_read = true;
        }
        self.streams.n.down += wrote as u64;
        st.recv.wrote(wrote);
        ack_on(&mut self.links.all[li].out, st, got);
        if gone {
            self.doom(slot, Why::Local);
            return;
        }
        st.shut_if_all_in();
        if st.finished() {
            self.doom(slot, Why::Done);
        }
    }

    /// The entry's FIN of stream `id` at `off` (trunk finLocked): acked, and
    /// once everything before it is written, the local end's side is shut.
    /// The FIN of a stream that ended was the exit's to confirm.
    pub(super) fn stream_fin(&mut self, li: usize, id: u32, off: u64, now: u64) {
        let (s, wire) = (self.links.all[li].session, self.links.all[li].wire);
        let Some(&slot) = self.sessions.all[s].streams.get(&id) else {
            if self.sessions.all[s].closed.contains_key(&id) {
                self.links.all[li].out.frame(ACK_LEN, |b| frame::put_ack(b, id, off, off, ACK_FIN, NO_GOT));
            } else {
                self.hold_early(s, id, true, off, &[], now);
            }
            return;
        };
        let st = &mut self.streams.all[slot];
        st.wire = wire;
        st.recv.fin(off);
        ack_on(&mut self.links.all[li].out, st, NO_GOT);
        st.shut_if_all_in();
        if st.finished() {
            self.doom(slot, Why::Done);
        }
    }

    /// The entry's ack of stream `id` (trunk ackedLocked): what it confirms
    /// is off its members' debts (confirm), and what waits to go again goes.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn stream_ack(&mut self, li: usize, id: u32, received: u64, credit: u64, flags: u8, got: u64, now: u64) {
        let s = self.links.all[li].session;
        let Some(&slot) = self.sessions.all[s].streams.get(&id) else { return };
        let Exit { streams, released, .. } = self;
        let st = &mut streams.all[slot];
        st.send.acked(received, credit, flags, got, |o| released.push((o.carrier, o.len)));
        self.confirm(now);
        self.resend(s, now);
        if self.streams.all[slot].finished() {
            self.doom(slot, Why::Done);
        }
    }

    /// A chunk or FIN of a stream whose open has not come (trunk
    /// holdEarlyLocked): kept, within the bounds, for when it comes.
    fn hold_early(&mut self, s: usize, id: u32, fin: bool, off: u64, p: &[u8], now: u64) {
        let sess = &mut self.sessions.all[s];
        if !sess.early.contains_key(&id) && sess.early.len() >= EARLY_STREAMS {
            self.streams.n.early_dropped += 1;
            return;
        }
        let all = sess.early_bytes;
        let e = sess.early.entry(id).or_insert_with(|| Early { frames: Vec::new(), bytes: 0, since: now });
        if !e.fits(p.len(), all) {
            self.streams.n.early_dropped += 1;
            return;
        }
        e.frames.push(EarlyFrame { fin, off, bytes: p.to_vec() });
        e.bytes += p.len();
        sess.early_bytes += p.len();
        self.streams.n.early += 1;
    }

    /// What acks confirmed: each member that carried it has it off its debt,
    /// and that is its proof and the session's.
    pub(super) fn confirm(&mut self, now: u64) {
        let Exit { links, sessions, released, .. } = self;
        for (c, len) in released.drain(..) {
            let Some(l) = links.of_carrier(c) else { continue };
            if !l.joined() {
                continue;
            }
            l.inflight -= len as usize;
            l.owing -= 1;
            l.h.confirmed(&mut sessions.all[l.session].judge, now, l.owing > 0);
        }
    }

    /// Stream slot ends after the pass that found it done or failed.
    pub(super) fn doom(&mut self, slot: usize, why: Why) {
        self.doomed.push((slot, self.streams.all[slot].gen, why));
    }

    /// Ends the streams found done or failed: reset to the entry unless it
    /// reset them or they finished, what they owed off their members, the id
    /// remembered (trunk endStreamLocked).
    pub(super) fn end_doomed(&mut self, now: u64) {
        while let Some((slot, gen, why)) = self.doomed.pop() {
            let Exit { streams, sessions, links, .. } = self;
            let Some(st) = streams.all.get_mut(slot).filter(|st| st.live && st.gen == gen) else { continue };
            let sess = &mut sessions.all[st.session];
            match (st.finished(), why) {
                (true, _) | (_, Why::Done) => streams.n.fin += 1,
                (false, Why::Peer) => streams.n.reset_peer += 1,
                (false, Why::Local) => {
                    streams.n.reset_local += 1;
                    for &(li, _) in sess.links.iter().take(RST_COPIES) {
                        let id = st.id;
                        links.all[li].out.frame(5, |b| frame::put_rst(b, id));
                    }
                }
            }
            for o in st.send.owed.drain(..) {
                forget(links, o.carrier, o.len);
            }
            sess.streams.remove(&st.id);
            sess.stranded.remove(&st.id);
            sess.closed.insert(st.id, now);
            streams.end(slot);
        }
    }

    /// Local ends → members: each readable local end's bytes, as far as its
    /// credit and the members' room go, read straight into a member's out
    /// buffer as chunks; its end is its FIN (trunk readLocal).
    pub(super) fn read_locals(&mut self, now: u64) {
        for slot in 0..self.streams.all.len() {
            let st = &self.streams.all[slot];
            if !st.live || !st.can_read || st.read_done || st.local.is_none() {
                continue;
            }
            // What is owed again goes before what is new (trunk queueLocked).
            let s = st.session;
            if !self.sessions.all[s].stranded.is_empty() && !self.resend(s, now) {
                continue;
            }
            if let Some(why) = self.read_local(slot, now) {
                self.doom(slot, why);
            }
        }
        self.end_doomed(now);
    }

    /// One local end's bytes into chunks; Some(why) when it failed.
    fn read_local(&mut self, slot: usize, now: u64) -> Option<Why> {
        let Exit { streams, sessions, links, moved, .. } = self;
        let st = &mut streams.all[slot];
        let of = &sessions.all[st.session].links;
        let local = st.local.as_mut()?;
        for _ in 0..READS_PER_TURN {
            let room = (st.send.room() as usize).min(CHUNK);
            if room == 0 {
                break;
            }
            let li = pick(links, of, st.wire, true)?;
            let l = &mut links.all[li];
            let k = l.out.chunk_room(room);
            if k == 0 {
                break;
            }
            match local.read(l.out.chunk_buf(k)) {
                Read::Bytes(k) => {
                    let off = st.send.chunk(&l.out.chunk_buf(k)[..k], carrier(li, l.gen));
                    l.out.chunk_done(st.id, off, k);
                    l.owe(k, now);
                    streams.n.up += k as u64;
                    *moved += 1;
                }
                Read::Again => {
                    // A source asks again once its request is in.
                    st.can_read = local.is_source();
                    break;
                }
                Read::End => {
                    let li = pick(links, of, st.wire, false)?;
                    let l = &mut links.all[li];
                    let (id, off) = (st.id, st.send.sent);
                    if !l.out.frame(13, |b| frame::put_fin(b, id, off)) {
                        break;
                    }
                    st.send.fin(carrier(li, l.gen));
                    l.owe(0, now);
                    st.read_done = true;
                    *moved += 1;
                    break;
                }
                Read::Gone => return Some(Why::Local),
            }
        }
        None
    }

    /// Local ends that take more: what waits for them, written; the freed
    /// window told by a quarter (trunk writeLocal); the entry's FIN passed on
    /// once all before it is written.
    pub(super) fn write_locals(&mut self, now: u64) {
        for slot in 0..self.streams.all.len() {
            let Exit { streams, sessions, links, moved, doomed, .. } = self;
            let st = &mut streams.all[slot];
            if !st.live || !st.can_write || (!st.behind.pending() && (st.write_done || !st.recv.all_in())) {
                continue;
            }
            let Some(k) = st.flush_behind() else {
                doomed.push((slot, st.gen, Why::Local));
                continue;
            };
            if k > 0 {
                streams.n.down += k as u64;
                *moved += 1;
                if st.recv.wrote(k) {
                    if let Some(li) = pick(links, &sessions.all[st.session].links, st.wire, false) {
                        ack_on(&mut links.all[li].out, st, NO_GOT);
                    }
                }
            }
            st.shut_if_all_in();
            if st.finished() {
                doomed.push((slot, st.gen, Why::Done));
            }
        }
        self.end_doomed(now);
    }
}

/// An ack of how far stream st has the entry's bytes, answering the chunk at
/// got (NO_GOT: none), into a member's out buffer (trunk ackGotLocked).
pub(super) fn ack_on(out: &mut hikkari_trunk::buf::Out, st: &mut crate::streams::Stream, got: u64) {
    let (r, c, f) = st.recv.ack();
    let id = st.id;
    out.frame(ACK_LEN, |b| frame::put_ack(b, id, r, c, f, got));
}
