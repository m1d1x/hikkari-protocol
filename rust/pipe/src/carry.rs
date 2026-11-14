//! Which wire and members carry a flow's datagram (trunk flows.go:
//! sendDgramLocked, dgramWireLocked; wires.go: Route).

use hikkari_trunk::flow::COPIES;
use hikkari_trunk::frame::{self, DGRAM_HEAD};
use hikkari_trunk::sched::Class;

use crate::ctl::ANY_WIRE;
use crate::flow::Flow;
use crate::link::StreamWire;
use crate::member::Wire;

/// Carries one datagram of flow `id` on `copies` members at once, never
/// sent again (spec/trunk.md, "Datagrams"). The members are those of the
/// flow's session (the pipe's session.rs: the session of a draining exit's
/// old process reaches only that process), and of its wire, of packet
/// members or of stream members: its pin, else its class's
/// route. A route's wire with no member up is passed over for any member
/// up, of any wire (trunk Route); a pinned flow's datagram is dropped
/// instead, counted on its wire. ANY_WIRE is any member up.
///
/// Go takes the members carrying least (trunk sendDgramLocked): a stream
/// member by its unconfirmed chunk bytes, a packet member carries none. Of
/// members carrying the same, a flow takes the same ones while they are up,
/// spread over flows by id: its datagrams stay in order. A datagram is never
/// owed, so a stream member carrying it is not held to account for it; one
/// whose out buffer is full drops it.
#[inline]
pub fn carry(wires: &mut [Wire], swires: &mut [StreamWire], route: [u8; 2], f: &mut Flow, id: u32, p: &[u8], now: u64) {
    f.used = now;
    f.seq = f.seq.wrapping_add(1);
    let strict = f.pin != ANY_WIRE;
    let want = if strict { f.pin } else { route[(f.class & 1) as usize] };
    let sess = f.sess;
    let has = |id: u8| wires.iter().any(|w| w.id == id && w.sess == sess && w.any_up()) || swires.iter().any(|w| w.id == id && w.sess == sess && w.up() > 0);
    let only = if want != ANY_WIRE && (strict || has(want)) { Some(want) } else { None };
    let takes = |wid: u8, ws: u8| ws == sess && only.is_none_or(|o| wid == o);
    let up: usize = wires.iter().filter(|w| takes(w.id, w.sess)).map(|w| w.up()).sum();
    let sup: usize = swires.iter().filter(|w| takes(w.id, w.sess)).map(|w| w.up()).sum();
    if up + sup == 0 {
        // Nothing can carry it: dropped, counted on the wire it wanted (a
        // flow with no pin and no route: on the first).
        if let Some(w) = wires.iter_mut().find(|w| w.id == want && w.sess == sess) {
            w.t.dropped += 1;
        } else if let Some(w) = swires.iter_mut().find(|w| w.id == want && w.sess == sess) {
            w.t.dropped += 1;
        } else if !strict {
            if let Some(w) = wires.iter_mut().find(|w| w.sess == sess) {
                w.t.dropped += 1;
            } else if let Some(w) = swires.iter_mut().find(|w| w.sess == sess) {
                w.t.dropped += 1;
            }
        }
        return;
    }
    // 0 is the trunk's default, as a Go flow opened with Copies 0.
    let copies = (if f.copies == 0 { COPIES } else { f.copies } as usize).min(up + sup);
    if sup == 0 {
        on_packets(wires, only, up, copies, f, id, p, now);
    } else {
        on_least(wires, swires, only, up + sup, copies, f, id, p, now);
    }
}

/// Packet members only, all carrying nothing: the k-th member up from the
/// flow's start, for k < copies.
#[allow(clippy::too_many_arguments)]
#[inline]
fn on_packets(wires: &mut [Wire], only: Option<u8>, up: usize, copies: usize, f: &Flow, id: u32, p: &[u8], now: u64) {
    let start = id as usize % up;
    let (seq, port) = (f.seq, f.port);
    let mut k = 0;
    for w in wires.iter_mut() {
        if w.sess != f.sess || only.is_some_and(|o| w.id != o) {
            continue;
        }
        let glue_max = w.glue_max;
        let mut on_wire = false;
        for m in w.members.iter_mut().filter(|m| m.h.up) {
            let rank = (k + up - start) % up;
            k += 1;
            if rank >= copies {
                continue;
            }
            m.frame(Class::Flow(id), DGRAM_HEAD + p.len(), glue_max, now, |b| frame::put_dgram(b, id, seq, port, p));
            on_wire = true;
        }
        if on_wire {
            w.t.up_pkts += 1;
            w.t.up_bytes += p.len() as u64;
        }
    }
}

/// A member up the datagram may go on: packet member (wire, index) or
/// stream member (wire, index).
#[derive(Clone, Copy)]
enum On {
    Packet(usize, usize),
    Stream(usize, usize),
}

/// With stream members among them: `copies` times the member carrying
/// least not taken yet, ties by its rank from the flow's start. Keys are
/// (bytes carried, rank) and ranks differ, so each pass takes the least key
/// above the last one taken: no list of members taken.
#[allow(clippy::too_many_arguments)]
fn on_least(wires: &mut [Wire], swires: &mut [StreamWire], only: Option<u8>, up: usize, copies: usize, f: &Flow, id: u32, p: &[u8], now: u64) {
    let start = id as usize % up;
    let (seq, port) = (f.seq, f.port);
    let mut last: Option<(usize, usize)> = None;
    // Wires counted for this datagram: bit wi for packet wires, 32 + wi
    // for stream wires.
    let mut counted = 0u64;
    for _ in 0..copies {
        let mut best: Option<((usize, usize), On)> = None;
        let mut consider = |key: (usize, usize), on: On| {
            if last.is_none_or(|l| key > l) && best.is_none_or(|b| key < b.0) {
                best = Some((key, on));
            }
        };
        let mut k = 0;
        for (wi, w) in wires.iter().enumerate() {
            if w.sess != f.sess || only.is_some_and(|o| w.id != o) {
                continue;
            }
            for (mi, _) in w.members.iter().enumerate().filter(|(_, m)| m.h.up) {
                consider((0, (k + up - start) % up), On::Packet(wi, mi));
                k += 1;
            }
        }
        for (wi, w) in swires.iter().enumerate() {
            if w.sess != f.sess || only.is_some_and(|o| w.id != o) {
                continue;
            }
            for (li, l) in w.links.iter().enumerate().filter(|(_, l)| l.h.up) {
                consider((l.inflight, (k + up - start) % up), On::Stream(wi, li));
                k += 1;
            }
        }
        let Some((key, on)) = best else { break };
        last = Some(key);
        match on {
            On::Packet(wi, mi) => {
                let w = &mut wires[wi];
                let glue_max = w.glue_max;
                w.members[mi].frame(Class::Flow(id), DGRAM_HEAD + p.len(), glue_max, now, |b| frame::put_dgram(b, id, seq, port, p));
                if counted & (1 << (wi & 31)) == 0 {
                    counted |= 1 << (wi & 31);
                    w.t.up_pkts += 1;
                    w.t.up_bytes += p.len() as u64;
                }
            }
            On::Stream(wi, li) => {
                let w = &mut swires[wi];
                if !w.links[li].out.frame(DGRAM_HEAD + p.len(), |b| frame::put_dgram(b, id, seq, port, p)) {
                    w.t.dropped += 1;
                } else if counted & (1 << (32 + (wi & 31))) == 0 {
                    counted |= 1 << (32 + (wi & 31));
                    w.t.up_pkts += 1;
                    w.t.up_bytes += p.len() as u64;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Dest, CLASS_BULK, CLASS_VOICE};
    use crate::member::Member;

    const KEY: [u8; 32] = [7; 32];

    /// Wires by id, each of `n` members, the ones in `down` not up.
    fn wires(spec: &[(u8, usize)], down: &[(u8, usize)]) -> Vec<Wire> {
        spec.iter()
            .map(|&(id, n)| {
                let mut w = Wire::new(id, KEY, 300_000_000);
                w.glue_max = 1200;
                for i in 0..n {
                    let mut m = Member::new(None, &KEY);
                    if !down.contains(&(id, i)) {
                        m.h.join(1);
                    }
                    w.members.push(m);
                }
                w
            })
            .collect()
    }

    fn flow(class: u8, pin: u8, copies: u8) -> Flow {
        Flow::new(Dest::Brain { tag: 1 }, class, pin, 443, copies, 0)
    }

    /// Which members got a frame, as "wire/index".
    fn carried(ws: &[Wire]) -> Vec<String> {
        let mut out = vec![];
        for w in ws {
            for (i, m) in w.members.iter().enumerate() {
                if m.glue_n > 0 {
                    out.push(format!("{}/{i}", w.id));
                }
            }
        }
        out
    }

    #[test]
    fn two_copies_go_on_two_members_of_the_routes_wire_one_copy_on_one() {
        let mut ws = wires(&[(1, 3), (2, 3)], &[]);
        let mut f = flow(CLASS_VOICE, ANY_WIRE, 2);
        carry(&mut ws, &mut [], [1, 2], &mut f, 4, b"hi", 10);
        assert_eq!(carried(&ws), ["2/1", "2/2"], "voice on wire 2, flow 4 from member 4 % 3");
        assert_eq!((f.seq, f.used, ws[1].t.up_pkts, ws[0].t.up_pkts), (1, 10, 1, 0));
        let mut ws = wires(&[(1, 3)], &[]);
        let mut f = flow(CLASS_BULK, ANY_WIRE, 1);
        carry(&mut ws, &mut [], [1, 2], &mut f, 5, b"hi", 10);
        assert_eq!(carried(&ws), ["1/2"]);
        let mut ws = wires(&[(1, 3)], &[]);
        carry(&mut ws, &mut [], [1, 2], &mut flow(CLASS_BULK, ANY_WIRE, 0), 0, b"hi", 10);
        assert_eq!(carried(&ws).len(), 2, "copies 0 is the trunk's 2");
    }

    #[test]
    fn a_flow_keeps_to_its_members_while_they_are_up() {
        let mut ws = wires(&[(1, 4)], &[]);
        let mut f = flow(CLASS_BULK, ANY_WIRE, 1);
        for _ in 0..3 {
            carry(&mut ws, &mut [], [1, 1], &mut f, 6, b"x", 10);
        }
        assert_eq!(carried(&ws), ["1/2"]);
        assert_eq!(f.seq, 3, "each datagram its own seq");
    }

    #[test]
    fn a_route_wire_with_none_up_is_passed_over_for_any_member_of_any_wire() {
        // As trunk sendDgramLocked: no member on the route's wire, so the
        // copies go on any member, here across the other two wires.
        let mut ws = wires(&[(1, 1), (2, 2), (3, 1)], &[(2, 0), (2, 1)]);
        carry(&mut ws, &mut [], [2, 2], &mut flow(CLASS_BULK, ANY_WIRE, 2), 0, b"x", 10);
        assert_eq!(carried(&ws), ["1/0", "3/0"]);
        assert_eq!((ws[0].t.up_pkts, ws[1].t.dropped, ws[2].t.up_pkts), (1, 0, 1));
    }

    #[test]
    fn a_pinned_flow_is_dropped_while_its_wire_has_none_up() {
        let mut ws = wires(&[(1, 2), (2, 2)], &[(2, 0), (2, 1)]);
        let mut f = flow(CLASS_VOICE, 2, 1);
        carry(&mut ws, &mut [], [1, 1], &mut f, 0, b"x", 10);
        assert!(carried(&ws).is_empty(), "not on wire 1, whatever the route");
        assert_eq!((ws[1].t.dropped, ws[0].t.dropped), (1, 0));
        let mut ws = wires(&[(1, 2), (2, 2)], &[(2, 0)]);
        carry(&mut ws, &mut [], [1, 1], &mut flow(CLASS_VOICE, 2, 2), 0, b"x", 10);
        assert_eq!(carried(&ws), ["2/1"], "two copies, one member up: one copy");
    }

    #[test]
    fn a_flow_goes_only_on_its_sessions_members() {
        // Session 1 is the exit's new process, 0 its old one: a flow of each
        // reaches only its own (spec/trunk.md, Drain).
        let mut ws = wires(&[(1, 2), (1, 2)], &[]);
        ws[1].sess = 1;
        let mut f = flow(CLASS_VOICE, ANY_WIRE, 2);
        f.sess = 1;
        carry(&mut ws, &mut [], [1, 1], &mut f, 0, b"x", 10);
        assert!(ws[0].members.iter().all(|m| m.glue_n == 0), "nothing on session 0's members");
        assert!(ws[1].members.iter().all(|m| m.glue_n > 0), "two copies on session 1's two");
        let mut ws = wires(&[(1, 2), (2, 1)], &[]);
        ws[1].sess = 1;
        let mut ps = [pool(0, &[0])];
        ps[0].sess = 1;
        let mut f = flow(CLASS_VOICE, 1, 2);
        f.sess = 1;
        carry(&mut ws, &mut ps, [1, 1], &mut f, 0, b"x", 10);
        assert!(carried(&ws).is_empty() && on_pool(&ps).is_empty(), "pinned to wire 1, which session 1 lacks: dropped");
        assert_eq!((ws[0].t.dropped, ws[1].t.dropped), (0, 0), "counted on no other session's wire");
    }

    #[test]
    fn nothing_up_drops_on_the_wire_it_wanted() {
        let mut ws = wires(&[(1, 1), (2, 1)], &[(1, 0), (2, 0)]);
        carry(&mut ws, &mut [], [2, 2], &mut flow(CLASS_BULK, ANY_WIRE, 2), 0, b"x", 10);
        assert_eq!((ws[0].t.dropped, ws[1].t.dropped), (0, 1));
        carry(&mut ws, &mut [], [ANY_WIRE, ANY_WIRE], &mut flow(CLASS_BULK, ANY_WIRE, 2), 0, b"x", 10);
        assert_eq!(ws[0].t.dropped, 1, "no route: on the first wire");
    }

    /// A stream wire of `n` members up, member i carrying inflight[i].
    fn pool(id: u8, inflight: &[usize]) -> StreamWire {
        let reach = crate::link::Reach::Plain("127.0.0.1:1".parse().unwrap());
        let mut w = StreamWire::new(id, reach, inflight.len(), 300_000_000);
        for (l, &b) in w.links.iter_mut().zip(inflight) {
            l.h.join(1);
            l.inflight = b;
        }
        w
    }

    /// Which stream members got a frame, as "wire/index".
    fn on_pool(ws: &[StreamWire]) -> Vec<String> {
        let mut out = vec![];
        for w in ws {
            for (i, l) in w.links.iter().enumerate() {
                if l.out.pending() {
                    out.push(format!("{}/{i}", w.id));
                }
            }
        }
        out
    }

    #[test]
    fn a_datagram_on_the_pool_goes_on_the_members_carrying_least() {
        // trunk sendDgramLocked: the Copies members of least inflight.
        let mut ps = [pool(0, &[65536, 0, 16384, 0])];
        carry(&mut [], &mut ps, [0, 0], &mut flow(CLASS_VOICE, ANY_WIRE, 2), 7, b"hi", 10);
        assert_eq!(on_pool(&ps), ["0/1", "0/3"]);
        assert_eq!((ps[0].t.up_pkts, ps[0].t.up_bytes), (1, 2), "one datagram on the wire, two copies");
        let mut ps = [pool(0, &[65536, 0, 16384, 0])];
        carry(&mut [], &mut ps, [0, 0], &mut flow(CLASS_VOICE, ANY_WIRE, 3), 7, b"hi", 10);
        assert_eq!(on_pool(&ps), ["0/1", "0/2", "0/3"]);
        // The same load: a flow keeps to the same members, spread by id.
        let mut ps = [pool(0, &[0, 0, 0, 0])];
        let mut f = flow(CLASS_BULK, ANY_WIRE, 1);
        for _ in 0..3 {
            carry(&mut [], &mut ps, [0, 0], &mut f, 6, b"x", 10);
        }
        assert_eq!(on_pool(&ps), ["0/2"]);
    }

    #[test]
    fn a_frame_on_a_stream_member_is_the_dgram_the_exit_reads() {
        let mut ps = [pool(0, &[0])];
        carry(&mut [], &mut ps, [0, 0], &mut flow(CLASS_VOICE, 0, 1), 9, b"voice", 10);
        let b = ps[0].links[0].out.bytes();
        match frame::next_frame(b, 0) {
            Some((frame::Frame::Dgram { stream: 9, seq: 1, port: 443, off, len }, n)) => {
                assert_eq!((&b[off..off + len], n), (&b"voice"[..], b.len()));
            }
            other => panic!("not one dgram frame: {:?}", other.map(|x| x.1)),
        }
    }

    #[test]
    fn the_pool_with_none_up_passes_a_flow_to_packet_members_and_back() {
        let mut ws = wires(&[(2, 2)], &[]);
        let mut ps = [pool(0, &[0, 0])];
        for l in ps[0].links.iter_mut() {
            l.h.down();
        }
        carry(&mut ws, &mut ps, [0, 0], &mut flow(CLASS_VOICE, ANY_WIRE, 1), 0, b"x", 10);
        assert_eq!((carried(&ws), on_pool(&ps)), (vec!["2/0".to_string()], vec![]));
        let mut ws = wires(&[(2, 2)], &[(2, 0), (2, 1)]);
        let mut ps = [pool(0, &[0, 0])];
        carry(&mut ws, &mut ps, [2, 2], &mut flow(CLASS_VOICE, ANY_WIRE, 1), 0, b"x", 10);
        assert_eq!(on_pool(&ps).len(), 1, "the route's wire has none up: the pool carries it");
        let mut ps = [pool(0, &[0, 0])];
        for l in ps[0].links.iter_mut() {
            l.h.down();
        }
        let mut f = flow(CLASS_VOICE, 0, 1);
        carry(&mut [], &mut ps, [0, 0], &mut f, 0, b"x", 10);
        assert_eq!(ps[0].t.dropped, 1, "pinned to the pool with none up: dropped on it");
    }
}
