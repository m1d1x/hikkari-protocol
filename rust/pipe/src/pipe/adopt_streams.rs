//! Streams handed over between generations (spec/trunk.md, "An entry's own
//! process replaced"; adopt.rs does the flows). A stream goes with its
//! client's connection itself, so the client sees no end of it.
//!
//! On the newer generation's `ready` the old pipe freezes every stream it
//! can hand (opened, no FIN either way): it reads its client no more, and
//! takes no new chunk from the exit but one that fills a hole under chunks
//! kept past it (those the exit counts as confirmed). Once every byte it
//! sent is confirmed and everything it got is written to the client, it
//! sends `smove` with the connection (SCM_RIGHTS), `up` (bytes read from the
//! client) and `down` (bytes written to it). One not ready in FREEZE_NS, or
//! that met a FIN, goes on here as before. The new pipe opens the stream
//! under an id of its own, already open, its client not read, and sends
//! `adopt`; the exit's ack gives it its credit and the exit sends again
//! what the client did not get. On `adopted` it reads the client and says
//! `staken`: the old pipe lets the stream go without an end. Refused or
//! unanswered: `skept`, and the old pipe goes on with it.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use hikkari_sys as sys;
use hikkari_trunk::frame::{self, OBS_STREAM};
use hikkari_trunk::handoff::{self, StreamMoving};

use super::adopt::{ADOPT_AGAIN_NS, ADOPT_TRIES};
use super::tcp::pick;
use super::Pipe;
use crate::ctl::ANY_WIRE;

/// A frozen stream not ready to go over in this long stays here: its
/// client waited for it, and waits no more.
const FREEZE_NS: u64 = 5_000_000_000;

/// A stream an older generation hands over, while the exit answers: its
/// slot and id here, the older one's index, what `smove` said, when the
/// adopt last went and how many times.
pub(super) struct AdoptingStream {
    slot: usize,
    id: u32,
    older: usize,
    m: StreamMoving,
    sent_at: u64,
    tries: u8,
}

impl Pipe {
    /// The newer generation's `ready`: every stream that can go over is
    /// frozen; how many.
    pub(super) fn freeze_streams(&mut self, now: u64) -> usize {
        let mut n = 0;
        for slot in 0..self.streams.slots() {
            let Some((st, _)) = self.streams.with_counts(slot) else { continue };
            let sess = &self.sessions[st.sess as usize];
            if !st.opened || st.read_done || st.send.fin_sent || st.recv.fin_at.is_some() || st.adopting || st.frozen_at != 0 || !sess.live || sess.standby {
                continue;
            }
            st.frozen_at = now;
            n += 1;
        }
        self.freezing += n;
        n
    }

    /// The frozen streams: each one ready goes over, one that met a FIN or
    /// waited past FREEZE_NS goes on here. Cheap with none frozen.
    pub(super) fn hand_streams(&mut self, now: u64) {
        if self.freezing == 0 {
            return;
        }
        for slot in 0..self.streams.slots() {
            let Some((st, _)) = self.streams.with_counts(slot) else { continue };
            if st.frozen_at == 0 || st.handed {
                continue;
            }
            if st.read_done || st.recv.fin_at.is_some() || now.saturating_sub(st.frozen_at) > FREEZE_NS || self.newer.is_none() {
                st.frozen_at = 0;
                self.freezing -= 1;
                continue;
            }
            if !st.send.all_confirmed() || !st.recv.none_ahead() || st.client.down_pending() {
                continue;
            }
            let m = StreamMoving { session: self.sessions[st.sess as usize].id, stream: st.id, port: st.port, up: st.send.sent, down: st.recv.written };
            let k = handoff::put_smove(&mut self.out, &m);
            let Some(s) = &mut self.newer else { continue };
            if s.send_fds(&self.out[..k], &[st.client.fd.as_raw_fd()]) {
                st.handed = true;
            }
        }
    }

    /// The newer generation's `staken` or `skept` of stream `id`.
    pub(super) fn stream_answered(&mut self, id: u32, taken: bool) {
        let Some(slot) = self.streams.slot_of(id) else { return };
        let Some((st, _)) = self.streams.with_counts(slot) else { return };
        if st.frozen_at == 0 {
            return;
        }
        st.frozen_at = 0;
        st.handed = false;
        self.freezing -= 1;
        if taken {
            self.streams.give_up(slot);
            self.handed_out += 1;
            self.dirty = true;
        }
    }

    /// An older generation's `smove` with the client's connection `fd`:
    /// the stream opens here and the exit is asked to adopt it.
    pub(super) fn stream_moving(&mut self, older: usize, m: StreamMoving, fd: i32, now: u64) {
        // SAFETY: the descriptor came with the message and is this pipe's.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let slot = self.streams.adopted(fd, m.port, self.cur, m.up, m.down);
        let id = self.streams.get(slot).map_or(0, |st| st.id);
        self.dirty = true;
        self.adopting_streams.push(AdoptingStream { slot, id, older, m, sent_at: now, tries: 0 });
        let i = self.adopting_streams.len() - 1;
        self.send_stream_adopt(i, now);
    }

    /// The exit's adopted of stream `id` (adopt.rs take_adopted).
    pub(super) fn stream_adopted(&mut self, id: u32, ok: bool) {
        let Some(i) = self.adopting_streams.iter().position(|a| a.id == id) else { return };
        let a = self.adopting_streams.swap_remove(i);
        if ok {
            if let Some((st, _)) = self.streams.with_counts(a.slot) {
                st.adopting = false;
            }
            self.handed_in += 1;
            self.tell_older(a.older, handoff::STAKEN, a.m.stream);
            eprintln!("hk-pipe: adopted a stream of an older generation ({} so far)", self.handed_in);
        } else {
            self.leave_stream(a);
        }
    }

    /// Once a second: adopts unanswered go again or give up, frozen streams
    /// that waited too long go on with their generation.
    pub(super) fn streams_clock(&mut self, now: u64) {
        self.hand_streams(now);
        let mut i = 0;
        while i < self.adopting_streams.len() {
            let a = &self.adopting_streams[i];
            if now.saturating_sub(a.sent_at) < ADOPT_AGAIN_NS {
                i += 1;
            } else if a.tries >= ADOPT_TRIES {
                let a = self.adopting_streams.swap_remove(i);
                self.leave_stream(a);
            } else {
                self.send_stream_adopt(i, now);
                i += 1;
            }
        }
    }

    fn send_stream_adopt(&mut self, i: usize, now: u64) {
        let a = &mut self.adopting_streams[i];
        a.sent_at = now;
        a.tries += 1;
        let Some((wi, li)) = pick(&self.swires, self.cur, ANY_WIRE, false) else { return };
        let (m, id) = (a.m, a.id);
        self.swires[wi].links[li].out.frame(frame::ADOPT_LEN, |b| frame::put_adopt(b, OBS_STREAM, &m.session, m.stream, id, m.up, m.down));
    }

    /// The exit did not adopt the stream: the older generation goes on with
    /// it, and this pipe's copy of its connection closes.
    fn leave_stream(&mut self, a: AdoptingStream) {
        self.streams.give_up(a.slot);
        self.dirty = true;
        self.tell_older(a.older, handoff::SKEPT, a.m.stream);
    }

    fn tell_older(&mut self, older: usize, kind: u8, stream: u32) {
        if let Some(s) = self.older.get_mut(older).and_then(|o| o.sock.as_mut()) {
            let k = handoff::put_stream_answer(&mut self.out, kind, stream);
            s.send(&self.out[..k]);
        }
    }
}

/// A descriptor that came with a message nobody took.
pub(super) fn close_stray(fds: &mut Vec<i32>) {
    for fd in fds.drain(..) {
        sys::close_fd(fd);
    }
}
