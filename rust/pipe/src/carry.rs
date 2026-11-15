//! Which wires and members carry a flow's datagram (trunk fates.go:
//! carriesLocked, voiceSetLocked, resolveLocked, sendDgramLocked,
//! sendOnLocked; spec/trunk.md, "Datagrams" and "Wires").
//!
//! A datagram goes on every wire of its flow's set at once, as one dgram
//! frame of the flow's seq: the exit takes the first copy, whichever wire
//! brought it. The set is the route's (route.rs): for voice, the main wire
//! with the flow's copies and one copy on the best wire of the other fate
//! that is up, or the route's whole set; for video and bulk one wire; for a
//! pinned flow (the brain's call on a wire) its pin alone. A wire of the set
//! with no member up gives its place to the best wire of its fate that is up
//! and not in the set yet (lowest id), else is left out; TCP never carries
//! voice alone while a wire of fate udp is up. A set that carried nothing
//! goes on any member up; a pinned flow's datagram is dropped instead,
//! counted on its wire.
//!
//! The members of a wire go round: each copy on the member after the last
//! one the wire used, so that a stream member's retransmit holds up one
//! datagram in N, not every one (trunk sendOnLocked takes the member that
//! sent the longest ago). A datagram is never owed, so a stream member
//! carrying it is not held to account for it; one whose out buffer is full
//! drops it. The members are those of the flow's session (the pipe's
//! session.rs): the session of a draining exit's old process reaches only
//! that process.
//!
//! A carry with a delay (after_ns) puts the copy in Later, sent by the loop
//! when its time comes (trunk laterLocked): no thread, nothing allocated.
//!
//! A pool with members of copies (copies.rs) takes a datagram on its
//! window's member first, then on the next members of copies, each held
//! for the window; with none of them up, on its members in turn as before.

use std::collections::VecDeque;

use hikkari_trunk::flow::COPIES;
use hikkari_trunk::frame::{self, DGRAM_HEAD};
use hikkari_trunk::sched::Class;

use crate::ctl::ANY_WIRE;
use crate::flow::{Flow, CLASS_VIDEO, CLASS_VOICE};
use crate::link::StreamWire;
use crate::member::Wire;
use crate::route::{Carry, Route, Set, FATE_NONE, FATE_TCP, FATE_UDP};

/// The wires of one session as a set sees them: which are up, their fates.
struct View<'a> {
    wires: &'a [Wire],
    swires: &'a [StreamWire],
    sess: u8,
    fates: &'a [u8; 256],
}

impl View<'_> {
    fn up(&self, id: u8) -> bool {
        self.wires.iter().any(|w| w.id == id && w.sess == self.sess && w.any_up())
            || self.swires.iter().any(|w| w.id == id && w.sess == self.sess && w.up() > 0)
    }

    /// Wire id's fate: the route's, or a stream wire's tcp and a packet
    /// wire's udp (trunk fateOr).
    fn fate(&self, id: u8) -> u8 {
        match self.fates[id as usize] {
            FATE_NONE if self.swires.iter().any(|w| w.id == id && w.sess == self.sess) => FATE_TCP,
            FATE_NONE => FATE_UDP,
            f => f,
        }
    }

    /// The wire of fate f with a member up that set does not hold yet,
    /// lowest id first; ANY_WIRE for none (trunk bestUpLocked).
    fn best_up(&self, f: u8, set: &Set) -> u8 {
        let packets = self.wires.iter().filter(|w| w.sess == self.sess && w.any_up()).map(|w| w.id);
        let streams = self.swires.iter().filter(|w| w.sess == self.sess && w.up() > 0).map(|w| w.id);
        packets.chain(streams).filter(|&id| id != ANY_WIRE && !set.has(id) && self.fate(id) == f).min().unwrap_or(ANY_WIRE)
    }

    /// A set's wires with no member up taken off it: each goes to the best
    /// wire of its fate up and not in the set yet, or is left out (trunk
    /// resolveLocked).
    fn resolve(&self, set: Set) -> Set {
        let mut out = Set::default();
        for &c in set.carries() {
            let mut c = c;
            if c.wire != ANY_WIRE && !self.up(c.wire) {
                c.wire = self.best_up(self.fate(c.wire), &out);
                if c.wire == ANY_WIRE {
                    continue;
                }
            }
            out.add(c);
        }
        out
    }

    /// The voice class's set (trunk voiceSetLocked).
    fn voice(&self, r: &Route) -> Set {
        let mut set = r.voice_set;
        if set.is_empty() {
            let mut main = r.voice;
            if main == ANY_WIRE || !self.up(main) {
                main = self.best_up(FATE_UDP, &set);
            }
            if main == ANY_WIRE {
                return set; // no wire of fate udp up: the pool alone, as any member
            }
            set.add(Carry { wire: main, copies: 0, after_ns: 0 });
            let other = if self.fate(main) == FATE_TCP { FATE_UDP } else { FATE_TCP };
            let w = self.best_up(other, &set);
            if w != ANY_WIRE {
                set.add(Carry { wire: w, copies: 1, after_ns: 0 });
            }
        }
        let set = self.resolve(set);
        if set.carries().iter().any(|c| c.wire == ANY_WIRE || self.fate(c.wire) != FATE_TCP) {
            return set;
        }
        let mut set = set;
        let w = self.best_up(FATE_UDP, &set);
        if w != ANY_WIRE {
            set.add(Carry { wire: w, copies: 1, after_ns: 0 });
        }
        set
    }

    /// The set a flow's next datagram goes on, and whether it is held to it
    /// (trunk carriesLocked).
    fn carries(&self, r: &Route, f: &Flow) -> (Set, bool) {
        if f.pin != ANY_WIRE {
            return (Set::of(&[Carry { wire: f.pin, copies: 0, after_ns: 0 }]), true);
        }
        let set = match f.class {
            CLASS_VOICE => self.voice(r),
            CLASS_VIDEO => {
                let mut w = r.video();
                if w == ANY_WIRE {
                    w = self.best_up(FATE_UDP, &Set::default());
                }
                self.resolve(Set::of(&[Carry { wire: w, copies: 0, after_ns: 0 }]))
            }
            _ => self.resolve(Set::of(&[Carry { wire: r.bulk, copies: 0, after_ns: 0 }])),
        };
        if set.is_empty() {
            return (Set::of(&[Carry { wire: ANY_WIRE, copies: 0, after_ns: 0 }]), false);
        }
        (set, false)
    }
}

/// A datagram's copy waiting for its carry's delay.
struct Pending {
    due: u64,
    wire: u8,
    copies: u8,
    sess: u8,
    id: u32,
    seq: u32,
    port: u16,
    len: u16,
    buf: [u8; LATER_MAX],
}

/// The most a later copy holds: a client datagram (the pipe's MAX_CLIENT).
pub const LATER_MAX: usize = 1500;
/// Later copies waiting at once, at most: a call is 50 a second, a delay
/// 10 ms; past this they are dropped, counted.
const LATER_CAP: usize = 512;

/// The copies that leave after their carry's delay, in order of it.
pub struct Later {
    q: VecDeque<Pending>,
    /// Copies dropped: too big for a later copy, or the queue full.
    pub dropped: u64,
}

impl Default for Later {
    fn default() -> Later {
        Later::new()
    }
}

impl Later {
    pub fn new() -> Later {
        Later { q: VecDeque::with_capacity(LATER_CAP), dropped: 0 }
    }

    /// When the next copy is due; u64::MAX for none.
    pub fn next_due(&self) -> u64 {
        self.q.front().map_or(u64::MAX, |p| p.due)
    }

    #[allow(clippy::too_many_arguments)]
    fn put(&mut self, due: u64, wire: u8, copies: u8, f: &Flow, id: u32, p: &[u8]) {
        if p.len() > LATER_MAX || self.q.len() == LATER_CAP {
            self.dropped += 1;
            return;
        }
        let mut i = self.q.len();
        while i > 0 && self.q[i - 1].due > due {
            i -= 1;
        }
        let mut d = Pending { due, wire, copies, sess: f.sess, id, seq: f.seq, port: f.port, len: p.len() as u16, buf: [0; LATER_MAX] };
        d.buf[..p.len()].copy_from_slice(p);
        self.q.insert(i, d);
    }

    /// Sends the copies whose time has come (trunk sendLater).
    pub fn send_due(&mut self, wires: &mut [Wire], swires: &mut [StreamWire], now: u64) {
        while self.q.front().is_some_and(|d| d.due <= now) {
            let d = self.q.pop_front().expect("a front");
            let p = &d.buf[..d.len as usize];
            send_on(wires, swires, d.sess, d.wire, d.copies as usize, d.id, d.seq, d.port, p, now);
        }
    }
}

/// Carries one datagram of flow `id` on every wire of its set, never sent
/// again.
#[allow(clippy::too_many_arguments)]
pub fn carry(wires: &mut [Wire], swires: &mut [StreamWire], route: &Route, later: &mut Later, f: &mut Flow, id: u32, p: &[u8], now: u64) {
    f.used = now;
    f.seq = f.seq.wrapping_add(1);
    let (set, strict) = View { wires, swires, sess: f.sess, fates: &route.fates }.carries(route, f);
    // 0 is the trunk's default, as a Go flow opened with Copies 0.
    let own = if f.copies == 0 { COPIES } else { f.copies };
    let (mut sent, mut queued) = (0, false);
    for c in set.carries() {
        let copies = if c.copies == 0 { own } else { c.copies };
        if c.after_ns > 0 {
            later.put(now + c.after_ns, c.wire, copies, f, id, p);
            queued = true;
            continue;
        }
        sent += send_on(wires, swires, f.sess, c.wire, copies as usize, id, f.seq, f.port, p, now);
    }
    if sent > 0 || queued {
        return;
    }
    // The set's wires all went down since: any member up.
    if !strict && send_on(wires, swires, f.sess, ANY_WIRE, own as usize, id, f.seq, f.port, p, now) > 0 {
        return;
    }
    // Nothing can carry it: dropped, counted on the wire it wanted: its pin
    // or its class's route (with none, on the session's first).
    let want = match f.class {
        _ if strict => f.pin,
        CLASS_VOICE => route.voice,
        CLASS_VIDEO => route.video(),
        _ => route.bulk,
    };
    if let Some(w) = wires.iter_mut().find(|w| w.id == want && w.sess == f.sess) {
        w.t.dropped += 1;
    } else if let Some(w) = swires.iter_mut().find(|w| w.id == want && w.sess == f.sess) {
        w.t.dropped += 1;
    } else if !strict {
        if let Some(w) = wires.iter_mut().find(|w| w.sess == f.sess) {
            w.t.dropped += 1;
        } else if let Some(w) = swires.iter_mut().find(|w| w.sess == f.sess) {
            w.t.dropped += 1;
        }
    }
}

/// Sends the dgram frame on `copies` members of wire `wire` of session
/// `sess` (of any of its wires for ANY_WIRE, packet wires first), each wire's
/// members in turn; says on how many (trunk sendOnLocked).
#[allow(clippy::too_many_arguments)]
fn send_on(wires: &mut [Wire], swires: &mut [StreamWire], sess: u8, wire: u8, copies: usize, id: u32, seq: u32, port: u16, p: &[u8], now: u64) -> usize {
    let takes = |wid: u8, ws: u8| ws == sess && (wire == ANY_WIRE || wid == wire);
    let mut n = 0;
    for w in wires.iter_mut().filter(|w| takes(w.id, w.sess)) {
        n += on_packets(w, copies - n, id, seq, port, p, now);
        if n == copies {
            return n;
        }
    }
    for w in swires.iter_mut().filter(|w| takes(w.id, w.sess)) {
        n += on_streams(w, copies - n, id, seq, port, p, now);
        if n == copies {
            break;
        }
    }
    n
}

/// The next `want` packet members up after the wire's last one.
fn on_packets(w: &mut Wire, want: usize, id: u32, seq: u32, port: u16, p: &[u8], now: u64) -> usize {
    let (len, glue_max, start) = (w.members.len(), w.glue_max, w.rr);
    let mut n = 0;
    for k in 1..=len {
        if n == want {
            break;
        }
        let mi = (start + k) % len;
        let m = &mut w.members[mi];
        if !m.h.up {
            continue;
        }
        m.frame(Class::Flow(id), DGRAM_HEAD + p.len(), glue_max, now, |b| frame::put_dgram(b, id, seq, port, p));
        w.rr = mi;
        n += 1;
    }
    if n > 0 {
        w.t.up_pkts += 1;
        w.t.up_bytes += p.len() as u64;
    }
    n
}

/// The next `want` stream members up after the wire's last one, or its
/// window's member of copies and the ones after it (copies.rs); a member
/// whose out buffer is full drops it.
#[allow(clippy::too_many_arguments)]
fn on_streams(w: &mut StreamWire, want: usize, id: u32, seq: u32, port: u16, p: &[u8], now: u64) -> usize {
    if let Some(first) = w.window_member(now) {
        return on_copies(w, first, want, id, seq, port, p, now);
    }
    let (len, start) = (w.links.len(), w.rr);
    let (mut n, mut put) = (0, false);
    for k in 1..=len {
        if n == want {
            break;
        }
        let li = (start + k) % len;
        let l = &mut w.links[li];
        if !l.h.up {
            continue;
        }
        if l.out.frame(DGRAM_HEAD + p.len(), |b| frame::put_dgram(b, id, seq, port, p)) {
            put = true;
        } else {
            w.t.dropped += 1;
        }
        w.rr = li;
        n += 1;
    }
    if put {
        w.t.up_pkts += 1;
        w.t.up_bytes += p.len() as u64;
    }
    n
}

/// `want` members of copies up from the window's, each frame held for the
/// window.
#[allow(clippy::too_many_arguments)]
fn on_copies(w: &mut StreamWire, first: usize, want: usize, id: u32, seq: u32, port: u16, p: &[u8], now: u64) -> usize {
    let (len, window) = (w.links.len(), w.copies.window_ns);
    let (mut n, mut put) = (0, false);
    for k in 0..len {
        if n == want {
            break;
        }
        let li = (first + k) % len;
        if !w.is_copy(li) || !w.links[li].h.up {
            continue;
        }
        if w.links[li].out.frame_held(DGRAM_HEAD + p.len(), now, window, |b| frame::put_dgram(b, id, seq, port, p)) {
            put = true;
        } else {
            w.t.dropped += 1;
        }
        n += 1;
    }
    if put {
        w.copies.frames += 1;
        w.t.up_pkts += 1;
        w.t.up_bytes += p.len() as u64;
    }
    n
}

#[cfg(test)]
mod tests;
