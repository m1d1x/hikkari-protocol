//! Flows handed over between generations (spec/trunk.md, "An entry's own
//! process replaced"; owner's decision of 18.11: a rollout of the entry
//! cuts no live flow). generation.rs keeps a flow with the generation that
//! opened it; this hands it to the newest one instead, and the exit moves
//! it under the new session with its socket to the relay.
//!
//! The new pipe says `ready` to every older one once its current session's
//! exit said it adopts (frame::ADOPT_EXIT). The old one answers with a
//! `move` per client flow it carries. The new one opens the flow under an
//! id of its own on its current session and sends `adopt` on a member of
//! the pool; until the exit answers, the flow's datagrams still go to the
//! old pipe (the owners) and its answers come to whichever session the exit
//! holds it on. On `adopted` the new pipe says `taken`; the old one forgets
//! the flow without ending it and says `moved` with the seq it got to; the
//! new one takes the address and carries the flow from that seq on. An
//! adopt refused, or unanswered after ADOPT_TRIES tries, leaves the flow
//! with the old pipe as before.

use std::net::SocketAddrV4;

use hikkari_sys as sys;
use hikkari_trunk::frame::{self, ADOPT_EXIT, OBS_FLOW};
use hikkari_trunk::handoff::{self, Moving};

use super::data::client_key;
use super::generation::{owner_key, split};
use super::tcp::pick;
use super::Pipe;
use crate::ctl::ANY_WIRE;
use crate::flow::{Dest, Flow};

/// An adopt unanswered this long goes again on another member.
const ADOPT_AGAIN_NS: u64 = 2_000_000_000;
/// Tries of one adopt before the flow is left with the old pipe.
const ADOPT_TRIES: u8 = 3;

/// A flow an older generation hands over, while the exit and that
/// generation answer: its id here, its key, the older one's index, what
/// `move` said, when the adopt last went and how many times, and whether
/// the exit adopted it (then the older one's `moved` is awaited).
pub(super) struct Adopting {
    id: u32,
    key: u64,
    pub older: usize,
    m: Moving,
    sent_at: u64,
    tries: u8,
    pub taken: bool,
}

impl Pipe {
    /// The exit's adopted frames of this read (tcp.rs): `ADOPT_EXIT` says
    /// the session's exit adopts at all, a flow's says how its adopt went.
    pub(super) fn take_adopted(&mut self, now: u64) {
        for (sess, kind, stream, ok) in std::mem::take(&mut self.adopted) {
            if kind == ADOPT_EXIT {
                self.sessions[sess as usize].adopts |= ok;
                continue;
            }
            if kind != OBS_FLOW || sess != self.cur {
                continue;
            }
            let Some(i) = self.adopting.iter().position(|a| a.id == stream && !a.taken) else { continue };
            if !ok {
                self.leave_with_older(i);
                continue;
            }
            let a = &mut self.adopting[i];
            a.taken = true;
            a.sent_at = now;
            let (listen, addr) = (a.m.listen, a.m.addr);
            if let Some(s) = &mut self.older[a.older].sock {
                let n = handoff::put_head(&mut self.out, handoff::TAKEN, listen, addr);
                s.send(&self.out[..n]);
            }
        }
    }

    /// Once a second: `ready` to every older generation whose list of
    /// addresses is whole, once this pipe's exit adopts; adopts unanswered
    /// go again or give up.
    pub(super) fn adopt_clock(&mut self, now: u64) {
        if self.newer.is_none() && self.sessions[self.cur as usize].adopts {
            for o in self.older.iter_mut().filter(|o| o.all && !o.ready) {
                if let Some(s) = &mut o.sock {
                    s.send(&[handoff::READY]);
                }
                o.ready = true;
            }
        }
        let mut i = 0;
        while i < self.adopting.len() {
            let a = &self.adopting[i];
            if a.taken || now.saturating_sub(a.sent_at) < ADOPT_AGAIN_NS {
                i += 1;
            } else if a.tries >= ADOPT_TRIES {
                self.leave_with_older(i);
            } else {
                self.send_adopt(i, now);
                i += 1;
            }
        }
    }

    /// An older generation's `move`: the flow opens here, under an id of
    /// its own, and the exit is asked to adopt it.
    pub(super) fn moving(&mut self, older: usize, m: Moving, now: u64) {
        let Some(li) = self.listens.iter().position(|l| l.id == m.listen) else { return };
        let key = client_key(li, &sys::sockaddr(m.addr));
        if self.flows.find(key).is_some() {
            return;
        }
        let mut f = Flow::new(Dest::Client { listen: li as u16, addr: sys::sockaddr(m.addr) }, m.class, ANY_WIRE, m.port, m.copies, now);
        f.sess = self.cur;
        f.seq = m.seq;
        let Some(id) = self.flows.client(key, || f) else { return };
        self.adopting.push(Adopting { id, key, older, m, sent_at: now, tries: 0, taken: false });
        let i = self.adopting.len() - 1;
        self.send_adopt(i, now);
    }

    /// The older generation's `moved`: the flow is this pipe's, from the
    /// seq the older one got to on.
    pub(super) fn moved(&mut self, older: usize, listen: u8, addr: SocketAddrV4, seq: u32) {
        let sa = sys::sockaddr(addr);
        let Some(i) = self.adopting.iter().position(|a| a.older == older && a.m.listen == listen && a.m.addr == addr) else { return };
        let a = self.adopting.swap_remove(i);
        let ok = owner_key(listen, &sa);
        if self.owners.get(&ok) == Some(&(older as u32)) {
            self.owners.remove(&ok);
        }
        if let Some((f, _)) = self.flows.with_counts(a.id) {
            if seq != 0 && seq.wrapping_sub(f.seq) < u32::MAX / 2 {
                f.seq = seq;
            }
        }
        self.handed_in += 1;
        eprintln!("hk-pipe: adopted a flow of an older generation ({} so far)", self.handed_in);
    }

    /// The adopt of `adopting[i]` on a member of the pool of this pipe's
    /// current session.
    fn send_adopt(&mut self, i: usize, now: u64) {
        let a = &mut self.adopting[i];
        a.sent_at = now;
        a.tries += 1;
        let Some((wi, li)) = pick(&self.swires, self.cur, ANY_WIRE, false) else { return };
        let (from, old, new) = (a.m.session, a.m.stream, a.id);
        self.swires[wi].links[li].out.frame(frame::ADOPT_LEN, |b| frame::put_adopt(b, OBS_FLOW, &from, old, new, 0, 0));
    }

    /// The exit did not adopt `adopting[i]`: the older generation carries
    /// it as before, and the flow opened here for it is given up.
    fn leave_with_older(&mut self, i: usize) {
        let a = self.adopting.swap_remove(i);
        self.flows.give_up(a.key);
    }

    /// The newer generation's `ready`: every client flow this pipe carries
    /// on a session of its own goes to it, the older generations' that
    /// drain through this one stay theirs.
    pub(super) fn hand_over(&mut self) {
        let Some(s) = &mut self.newer else { return };
        let mut n = 0;
        for (key, f) in self.flows.clients_open() {
            let sess = &self.sessions[f.sess as usize];
            if !sess.live || sess.standby {
                continue;
            }
            let (li, addr) = split(key);
            let m = Moving { listen: self.listens[li].id, addr, session: sess.id, stream: f.id(), port: f.port, class: f.class, copies: f.copies, seq: f.seq };
            let k = handoff::put_move(&mut self.out, &m);
            s.send(&self.out[..k]);
            n += 1;
        }
        eprintln!("hk-pipe: hands {n} flow(s) to the newer generation");
    }

    /// The newer generation's `taken`: the exit adopted the flow; it is
    /// forgotten here without an end, and the seq it got to goes over.
    pub(super) fn taken(&mut self, listen: u8, addr: SocketAddrV4) {
        let Some(li) = self.listens.iter().position(|l| l.id == listen) else { return };
        let seq = self.flows.give_up(client_key(li, &sys::sockaddr(addr))).unwrap_or(0);
        if seq != 0 {
            self.handed_out += 1;
        }
        if let Some(s) = &mut self.newer {
            let k = handoff::put_moved(&mut self.out, listen, addr, seq);
            s.send(&self.out[..k]);
        }
    }
}
