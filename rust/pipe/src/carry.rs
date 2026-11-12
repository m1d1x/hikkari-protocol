//! Which wire and members carry a flow's datagram (trunk flows.go:
//! sendDgramLocked, dgramWireLocked; wires.go: Route).

use hikkari_trunk::flow::COPIES;
use hikkari_trunk::frame::{self, DGRAM_HEAD};

use crate::ctl::ANY_WIRE;
use crate::flow::Flow;
use crate::member::Wire;

/// Carries one datagram of flow `id` on `copies` members at once, never
/// sent again (spec/trunk.md, "Datagrams"). The members are those of its
/// wire: its pin, else its class's route. A route's wire with no member up
/// is passed over for any member up, of any wire (trunk Route); a pinned
/// flow's datagram is dropped instead, counted on its wire. ANY_WIRE is any
/// member up. Of the members it may go on, a flow takes the same ones while
/// they are up, spread over flows by id: its datagrams stay in order. Go
/// takes the members carrying least, which for packet members (no chunks
/// in flight) is any; the pipe has packet members only.
#[inline]
pub fn carry(wires: &mut [Wire], route: [u8; 2], f: &mut Flow, id: u32, p: &[u8], now: u64) {
    f.used = now;
    f.seq = f.seq.wrapping_add(1);
    let strict = f.pin != ANY_WIRE;
    let want = if strict { f.pin } else { route[(f.class & 1) as usize] };
    let only = if want != ANY_WIRE && (strict || wires.iter().any(|w| w.id == want && w.any_up())) {
        Some(want)
    } else {
        None
    };
    let up: usize = wires.iter().filter(|w| only.is_none_or(|o| w.id == o)).map(|w| w.up()).sum();
    if up == 0 {
        // Nothing can carry it: dropped, counted on the wire it wanted (a
        // flow with no pin and no route: on the first).
        let at = wires.iter().position(|w| w.id == want).or_else(|| (!strict && !wires.is_empty()).then_some(0));
        if let Some(i) = at {
            wires[i].t.dropped += 1;
        }
        return;
    }
    // 0 is the trunk's default, as a Go flow opened with Copies 0.
    let copies = (if f.copies == 0 { COPIES } else { f.copies } as usize).min(up);
    let start = id as usize % up;
    let (seq, port) = (f.seq, f.port);
    // The k-th member up of those it may go on, from start, for k < copies.
    let mut k = 0;
    for w in wires.iter_mut() {
        if only.is_some_and(|o| w.id != o) {
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
            m.glue_frame(DGRAM_HEAD + p.len(), glue_max, now, |b| frame::put_dgram(b, id, seq, port, p));
            on_wire = true;
        }
        if on_wire {
            w.t.up_pkts += 1;
            w.t.up_bytes += p.len() as u64;
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
        carry(&mut ws, [1, 2], &mut f, 4, b"hi", 10);
        assert_eq!(carried(&ws), ["2/1", "2/2"], "voice on wire 2, flow 4 from member 4 % 3");
        assert_eq!((f.seq, f.used, ws[1].t.up_pkts, ws[0].t.up_pkts), (1, 10, 1, 0));
        let mut ws = wires(&[(1, 3)], &[]);
        let mut f = flow(CLASS_BULK, ANY_WIRE, 1);
        carry(&mut ws, [1, 2], &mut f, 5, b"hi", 10);
        assert_eq!(carried(&ws), ["1/2"]);
        let mut ws = wires(&[(1, 3)], &[]);
        carry(&mut ws, [1, 2], &mut flow(CLASS_BULK, ANY_WIRE, 0), 0, b"hi", 10);
        assert_eq!(carried(&ws).len(), 2, "copies 0 is the trunk's 2");
    }

    #[test]
    fn a_flow_keeps_to_its_members_while_they_are_up() {
        let mut ws = wires(&[(1, 4)], &[]);
        let mut f = flow(CLASS_BULK, ANY_WIRE, 1);
        for _ in 0..3 {
            carry(&mut ws, [1, 1], &mut f, 6, b"x", 10);
        }
        assert_eq!(carried(&ws), ["1/2"]);
        assert_eq!(f.seq, 3, "each datagram its own seq");
    }

    #[test]
    fn a_route_wire_with_none_up_is_passed_over_for_any_member_of_any_wire() {
        // As trunk sendDgramLocked: no member on the route's wire, so the
        // copies go on any member, here across the other two wires.
        let mut ws = wires(&[(1, 1), (2, 2), (3, 1)], &[(2, 0), (2, 1)]);
        carry(&mut ws, [2, 2], &mut flow(CLASS_BULK, ANY_WIRE, 2), 0, b"x", 10);
        assert_eq!(carried(&ws), ["1/0", "3/0"]);
        assert_eq!((ws[0].t.up_pkts, ws[1].t.dropped, ws[2].t.up_pkts), (1, 0, 1));
    }

    #[test]
    fn a_pinned_flow_is_dropped_while_its_wire_has_none_up() {
        let mut ws = wires(&[(1, 2), (2, 2)], &[(2, 0), (2, 1)]);
        let mut f = flow(CLASS_VOICE, 2, 1);
        carry(&mut ws, [1, 1], &mut f, 0, b"x", 10);
        assert!(carried(&ws).is_empty(), "not on wire 1, whatever the route");
        assert_eq!((ws[1].t.dropped, ws[0].t.dropped), (1, 0));
        let mut ws = wires(&[(1, 2), (2, 2)], &[(2, 0)]);
        carry(&mut ws, [1, 1], &mut flow(CLASS_VOICE, 2, 2), 0, b"x", 10);
        assert_eq!(carried(&ws), ["2/1"], "two copies, one member up: one copy");
    }

    #[test]
    fn nothing_up_drops_on_the_wire_it_wanted() {
        let mut ws = wires(&[(1, 1), (2, 1)], &[(1, 0), (2, 0)]);
        carry(&mut ws, [2, 2], &mut flow(CLASS_BULK, ANY_WIRE, 2), 0, b"x", 10);
        assert_eq!((ws[0].t.dropped, ws[1].t.dropped), (0, 1));
        carry(&mut ws, [ANY_WIRE, ANY_WIRE], &mut flow(CLASS_BULK, ANY_WIRE, 2), 0, b"x", 10);
        assert_eq!(ws[0].t.dropped, 1, "no route: on the first wire");
    }
}
