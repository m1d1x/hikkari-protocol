//! Clients' streams in the loop (spec/trunk.md, "Streams"; streams.rs):
//! client connections accepted and opened to the exit, their bytes read
//! into chunks on stream members (link.rs), the exit's chunks written back
//! in order and acked, FINs both ways, resets, and the stream members' own
//! talk. A member's death and what it carried going again: death.rs.

use std::os::fd::{AsRawFd, OwnedFd};

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::buf::Out;
use hikkari_trunk::frame::{self, Frame, ACK_FIN, ACK_LEN, NO_GOT};
use hikkari_trunk::health::Verdict;
use hikkari_trunk::stream::{CHUNK, NO_CARRIER};

use super::{Event, Pipe, Slot};
use crate::ctl;
use crate::link::{self, carrier, carrier_of, Link, StreamWire};
use crate::streams::{Stream, StreamCounts, Streams};

/// A client port of streams: its listening socket and the exit's port.
pub(super) struct TcpListen {
    pub fd: OwnedFd,
    pub to: u16,
}

/// A stream member's hello must be answered within this of its dial
/// (trunk helloTimeout, the exit's side of the same wait).
const HELLO_WAIT: u64 = 5_000_000_000;
/// Chunks read from one client in one turn, at most: one busy client does
/// not hold the others' turn.
const READS_PER_TURN: usize = 64;
/// Reads of one member's socket in one turn, at most.
const LINK_READS: usize = 8;
/// A reset goes on this many members (trunk endStreamLocked: Copies).
const RST_COPIES: usize = 2;

/// Why a stream is reset.
#[derive(Clone, Copy)]
pub(super) enum Why {
    /// The exit reset it: nothing to tell it.
    Peer,
    /// The client failed.
    Local,
    /// Both directions are over: no reset, it ends.
    Done,
}

/// The member a stream's next frame goes on (trunk pickLocked): of the bulk
/// route's wire while it has a member up, else of any wire; the one owing
/// least; for a chunk, only one with room under INFLIGHT.
pub(super) fn pick(wires: &[StreamWire], bulk: u8, chunk: bool) -> Option<(usize, usize)> {
    let only = wires.iter().any(|w| w.id == bulk && w.up() > 0);
    let mut best: Option<(usize, usize, usize)> = None;
    for (wi, w) in wires.iter().enumerate() {
        if only && w.id != bulk {
            continue;
        }
        for (li, l) in w.links.iter().enumerate() {
            if !l.h.up || chunk && !l.takes_chunk() {
                continue;
            }
            if best.is_none_or(|b| l.inflight < b.2) {
                best = Some((wi, li, l.inflight));
            }
        }
    }
    best.map(|b| (b.0, b.1))
}

/// What a stream owed and no longer does, without a confirmation: the
/// member it went on carries it no more.
fn forget(wires: &mut [StreamWire], c: u32, len: u32) {
    if c == NO_CARRIER {
        return;
    }
    let (wi, li, gen) = carrier_of(c);
    let Some(l) = wires.get_mut(wi).and_then(|w| w.links.get_mut(li)) else { return };
    if l.gen != gen || l.sock.is_none() {
        return;
    }
    l.inflight -= len as usize;
    l.owing -= 1;
    if l.owing == 0 {
        l.h.busy_since = 0;
    }
}

impl Pipe {
    /// Whether the loop has stream sockets to poll for real readiness.
    pub(super) fn has_tcp(&self) -> bool {
        !self.tcp_listens.is_empty()
    }

    /// New client connections: a stream each, opened when a member is up.
    pub(super) fn accept_clients(&mut self) {
        let Pipe { poll, slots, tcp_listens, streams, dirty, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            let Slot::TcpListen(li) = *s else { continue };
            if !poll.readable(si) {
                continue;
            }
            let l = &tcp_listens[li];
            while let Some(fd) = sys::accept(l.fd.as_raw_fd()) {
                streams.add(fd, l.to);
                *dirty = true;
            }
        }
    }

    /// Opens the streams not opened yet, on the members up.
    pub(super) fn open_streams(&mut self, now: u64) {
        if self.streams.unopened == 0 {
            return;
        }
        let Pipe { streams, swires, route, .. } = self;
        for slot in 0..streams.slots() {
            let Some((st, _)) = streams.with_counts(slot) else { continue };
            if st.opened {
                continue;
            }
            let Some((wi, li)) = pick(swires, route[0], false) else { return };
            let l = &mut swires[wi].links[li];
            if !l.out.frame(7, |b| frame::put_open(b, st.id, st.port)) {
                return;
            }
            st.send.open(carrier(wi, li, l.gen));
            l.owe(0, now);
            streams.opened(slot);
        }
    }

    /// Clients → members: each readable client's bytes, as far as its
    /// credit and the members' room go, read straight into a member's out
    /// buffer as chunks; a client's end is its FIN.
    pub(super) fn read_streams(&mut self, now: u64) {
        // What is owed again goes before what is new (trunk queueLocked).
        if !self.resend(now) {
            return;
        }
        let Pipe { poll, slots, streams, swires, route, moved, doomed, .. } = self;
        let bulk = route[0];
        for (si, s) in slots.iter().enumerate() {
            let Slot::Client(slot) = *s else { continue };
            if !poll.readable(si) {
                continue;
            }
            let Some((st, n)) = streams.with_counts(slot) else { continue };
            if !st.opened || st.read_done {
                continue;
            }
            for _ in 0..READS_PER_TURN {
                let room = (st.send.room() as usize).min(CHUNK);
                if room == 0 {
                    break;
                }
                let Some((wi, li)) = pick(swires, bulk, true) else { break };
                let w = &mut swires[wi];
                let l = &mut w.links[li];
                let k = l.out.chunk_room(room);
                if k == 0 {
                    break;
                }
                match sys::read(&st.client.fd, l.out.chunk_buf(k)) {
                    Io::Done(k) => {
                        let off = st.send.chunk(&l.out.chunk_buf(k)[..k], carrier(wi, li, l.gen));
                        l.out.chunk_done(st.id, off, k);
                        l.owe(k, now);
                        w.t.up_pkts += 1;
                        w.t.up_bytes += k as u64;
                        n.up += k as u64;
                        *moved += 1;
                    }
                    Io::Again => break,
                    Io::Eof => {
                        let Some((wi, li)) = pick(swires, bulk, false) else { break };
                        let l = &mut swires[wi].links[li];
                        let off = st.send.sent;
                        if !l.out.frame(13, |b| frame::put_fin(b, st.id, off)) {
                            break;
                        }
                        st.send.fin(carrier(wi, li, l.gen));
                        l.owe(0, now);
                        st.read_done = true;
                        break;
                    }
                    Io::Gone => {
                        doomed.push((slot, Why::Local));
                        break;
                    }
                }
            }
        }
        self.end_doomed();
    }

    /// Members → clients: every readable member's frames.
    pub(super) fn read_links(&mut self, now: u64) {
        for si in 0..self.slots.len() {
            let Slot::Link(wi, li) = self.slots[si] else { continue };
            if !self.poll.readable(si) {
                continue;
            }
            for _ in 0..LINK_READS {
                let l = &mut self.swires[wi].links[li];
                let Some(sock) = &mut l.sock else { break };
                match sock.read(&mut l.inb[l.in_n..]) {
                    Io::Done(k) => {
                        l.in_n += k;
                        if !self.link_frames(wi, li, now) {
                            self.link_down(wi, li, ctl::WHY_GONE, now);
                            break;
                        }
                    }
                    Io::Again => break,
                    Io::Eof | Io::Gone => {
                        self.link_down(wi, li, ctl::WHY_GONE, now);
                        break;
                    }
                }
            }
        }
        self.send_events();
    }

    /// The whole frames read on member li of wire wi; false for bytes that
    /// are no frame (the member is not the exit's).
    fn link_frames(&mut self, wi: usize, li: usize, now: u64) -> bool {
        let Pipe { swires, streams, judge, events, released, doomed, moved, .. } = self;
        let StreamWire { links, t, proof, id: wid, .. } = &mut swires[wi];
        let Link { inb, in_n, out, h, .. } = &mut links[li];
        let mut joined = false;
        let mut at = 0;
        while at < *in_n {
            let Some((fr, next)) = frame::next_frame(&inb[..*in_n], at) else {
                if !(frame::F_HELLO..=frame::F_OBSERVE).contains(&inb[at]) {
                    return false;
                }
                break; // the rest of the frame is still to come
            };
            match fr {
                Frame::Hello => {
                    if !h.up {
                        h.join(now);
                        joined = true;
                        events.push(Event { wire: *wid, index: li as u8, up: true, why: ctl::WHY_HELLO });
                    }
                }
                Frame::Ping(tok) => {
                    out.frame(9, |b| frame::put_ping(b, frame::F_PONG, tok));
                }
                Frame::Pong(tok) => {
                    if h.pong(judge, tok, now) {
                        *proof = now;
                    }
                }
                Frame::Data { len, .. } => {
                    t.down_pkts += 1;
                    t.down_bytes += len as u64;
                    *moved += 1;
                    stream_frame(fr, inb, out, streams, doomed, released);
                }
                Frame::Fin { .. } | Frame::Ack { .. } | Frame::Rst { .. } => stream_frame(fr, inb, out, streams, doomed, released),
                // Datagrams ride the packet wires (carry.rs): the exit answers
                // a flow on the wire it came on.
                Frame::Open { .. } | Frame::Dgram { .. } | Frame::Drain | Frame::Other => {}
            }
            at = next;
        }
        inb.copy_within(at..*in_n, 0);
        *in_n -= at;
        if joined {
            // Every stream says again how far it is: acks sent on a member
            // that died are lost (trunk serve).
            for slot in 0..streams.slots() {
                if let Some((st, _)) = streams.with_counts(slot) {
                    if st.opened {
                        ack(out, st, NO_GOT);
                    }
                }
            }
        }
        self.confirm(now);
        self.end_doomed();
        true
    }

    /// What acks confirmed: each member that carried it has it off its debt,
    /// and that is its proof and the session's.
    fn confirm(&mut self, now: u64) {
        let Pipe { swires, released, judge, .. } = self;
        for (c, len) in released.drain(..) {
            let (wi, li, gen) = carrier_of(c);
            let Some(w) = swires.get_mut(wi) else { continue };
            let Some(l) = w.links.get_mut(li) else { continue };
            if l.gen != gen || l.sock.is_none() {
                continue;
            }
            l.inflight -= len as usize;
            l.owing -= 1;
            l.h.confirmed(judge, now, l.owing > 0);
            w.proof = now;
        }
    }

    /// Ends the streams found done or failed in this pass.
    fn end_doomed(&mut self) {
        while let Some((slot, why)) = self.doomed.pop() {
            let Pipe { streams, swires, route, dirty, .. } = self;
            let Some((st, n)) = streams.with_counts(slot) else { continue };
            if !st.finished() {
                count(n, why);
                if !matches!(why, Why::Peer) && st.opened {
                    for _ in 0..RST_COPIES {
                        let Some((wi, li)) = pick(swires, route[0], false) else { break };
                        swires[wi].links[li].out.frame(5, |b| frame::put_rst(b, st.id));
                    }
                }
            } else {
                n.fin += 1;
            }
            for o in st.send.owed.drain(..) {
                forget(swires, o.carrier, o.len);
            }
            streams.end(slot);
            *dirty = true;
        }
    }

    /// Clients that take more: what waits for them, written; the freed
    /// window told by a quarter (trunk writeLocal).
    pub(super) fn write_clients(&mut self) {
        let Pipe { poll, slots, streams, swires, route, doomed, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            let Slot::Client(slot) = *s else { continue };
            if !poll.writable(si) {
                continue;
            }
            let Some((st, n)) = streams.with_counts(slot) else { continue };
            if !st.client.down_pending() {
                continue;
            }
            let Some(k) = st.client.flush_down() else {
                doomed.push((slot, Why::Local));
                continue;
            };
            n.down += k as u64;
            if st.recv.wrote(k) {
                if let Some((wi, li)) = pick(swires, route[0], false) {
                    ack(&mut swires[wi].links[li].out, st, NO_GOT);
                }
            }
            st.shut_if_all_in();
            if st.finished() {
                doomed.push((slot, Why::Done));
            }
        }
        self.end_doomed();
    }

    /// Every member's waiting frames, as much as its socket takes.
    pub(super) fn flush_links(&mut self, now: u64) {
        for wi in 0..self.swires.len() {
            for li in 0..self.swires[wi].links.len() {
                let l = &mut self.swires[wi].links[li];
                let Some(sock) = &mut l.sock else { continue };
                if let Io::Gone = link::flush(&mut l.out, sock) {
                    self.link_down(wi, li, ctl::WHY_GONE, now);
                }
            }
        }
        self.send_events();
    }

    /// What each stream socket is waited for in the next poll.
    pub(super) fn want_tcp(&mut self) {
        let chunk = self.stranded.is_empty() && pick(&self.swires, self.route[0], true).is_some();
        let Pipe { poll, slots, streams, swires, .. } = self;
        for (si, s) in slots.iter().enumerate() {
            match *s {
                Slot::Client(slot) => {
                    let Some(st) = streams.get(slot) else { continue };
                    let read = st.opened && !st.read_done && chunk && st.send.room() > 0;
                    poll.want(si, read, st.client.down_pending());
                }
                Slot::Link(wi, li) => {
                    let l = &swires[wi].links[li];
                    let write = l.out.pending() && l.sock.as_ref().is_some_and(|s| s.polls_writes());
                    poll.want(si, l.sock.is_some(), write);
                }
                _ => {}
            }
        }
    }

    /// Stream members on the members' clock: dialed anew when due, a hello
    /// unanswered too long is a failed member, pings and deaths as any
    /// member's (hikkari_trunk::health). Returns when the next is due.
    pub(super) fn link_timers(&mut self, now: u64, clock: bool, mut next: u64) -> u64 {
        for wi in 0..self.swires.len() {
            for li in 0..self.swires[wi].links.len() {
                let Pipe { swires, judge, tok, session, dirty, .. } = self;
                let w = &mut swires[wi];
                let l = &mut w.links[li];
                if l.renew_at != 0 {
                    if now >= l.renew_at {
                        l.dial(&w.reach, session, now);
                        *dirty = true;
                    } else {
                        next = next.min(l.renew_at);
                    }
                }
                if l.sock.is_none() {
                    continue;
                }
                if !l.h.up {
                    if now.saturating_sub(l.dialed_at) > HELLO_WAIT {
                        self.link_down(wi, li, ctl::WHY_GONE, now);
                    }
                    continue;
                }
                if !clock {
                    continue;
                }
                match l.h.tick(judge, w.stall_ns, now, tok) {
                    Verdict::Fine => {}
                    Verdict::Ping(t) => {
                        l.out.frame(9, |b| frame::put_ping(b, frame::F_PING, t));
                    }
                    Verdict::Dead { quiet } => {
                        let why = if quiet { ctl::WHY_QUIET } else { ctl::WHY_SILENT };
                        self.link_down(wi, li, why, now);
                    }
                }
            }
        }
        next
    }

}

/// A stream's frame from the exit (trunk session.go: dataLocked, finLocked,
/// ackedLocked, the reset in handle), answered on the member it came on:
/// a chunk is written on to the client and acked, a FIN acked, an ack
/// confirms what the stream owed (`released`, applied by confirm). A stream
/// done or failed is left in `doomed`.
fn stream_frame(fr: Frame, inb: &[u8], out: &mut Out, streams: &mut Streams, doomed: &mut Vec<(usize, Why)>, released: &mut Vec<(u32, u32)>) {
    let id = match fr {
        Frame::Data { stream, .. } | Frame::Fin { stream, .. } | Frame::Ack { stream, .. } | Frame::Rst { stream } => stream,
        _ => return,
    };
    let Some(slot) = streams.slot_of(id) else {
        match fr {
            // Late chunks of a stream that ended get a reset.
            Frame::Data { .. } => {
                out.frame(5, |b| frame::put_rst(b, id));
            }
            // It ended here already: the FIN was ours to confirm.
            Frame::Fin { off, .. } if id <= streams.last_id() => {
                out.frame(ACK_LEN, |b| frame::put_ack(b, id, off, off, ACK_FIN, NO_GOT));
            }
            _ => {}
        }
        return;
    };
    let (st, n) = streams.with_counts(slot).unwrap();
    match fr {
        Frame::Data { off, at, len, .. } => {
            let (mut wrote, mut gone) = (0, false);
            let got = st.recv.chunk(off, &inb[at..at + len], |q| match st.client.give(q) {
                Some(k) => wrote += k,
                None => gone = true,
            });
            n.down += wrote as u64;
            st.recv.wrote(wrote);
            ack(out, st, got);
            if gone {
                doomed.push((slot, Why::Local));
                return;
            }
            st.shut_if_all_in();
        }
        Frame::Fin { off, .. } => {
            st.recv.fin(off);
            ack(out, st, NO_GOT);
            st.shut_if_all_in();
        }
        Frame::Ack { received, credit, flags, got, .. } => {
            st.send.acked(received, credit, flags, got, |o| released.push((o.carrier, o.len)));
        }
        _ => {
            doomed.push((slot, Why::Peer));
            return;
        }
    }
    if st.finished() {
        doomed.push((slot, Why::Done));
    }
}

/// An ack of how far the stream has the exit's bytes, answering the chunk
/// at got (NO_GOT: none).
pub(super) fn ack(out: &mut Out, st: &mut Stream, got: u64) {
    let (r, c, f) = st.recv.ack();
    out.frame(ACK_LEN, |b| frame::put_ack(b, st.id, r, c, f, got));
}

fn count(n: &mut StreamCounts, why: Why) {
    match why {
        Why::Peer => n.reset_peer += 1,
        Why::Local => n.reset_local += 1,
        Why::Done => {}
    }
}

/// The streams' part of the stats line.
pub(super) fn stats(streams: &Streams, wires: &[StreamWire]) -> String {
    let n = &streams.n;
    let mut s = format!(
        " | streams open={} opened={} fin={} rst_peer={} rst_local={} hit={} resent={} up={}MiB down={}MiB",
        streams.open,
        n.opened,
        n.fin,
        n.reset_peer,
        n.reset_local,
        n.deaths,
        n.resent,
        n.up >> 20,
        n.down >> 20
    );
    for w in wires {
        s += &format!(" | swire {} up={}/{} chunks={}/{}", w.id, w.up(), w.links.len(), w.t.up_pkts, w.t.down_pkts);
    }
    s
}
