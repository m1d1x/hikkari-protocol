//! carry.rs against the rules of trunk fates.go, each test named after the
//! Go test of the same rule where there is one.

use super::*;
use crate::flow::Dest;
use crate::member::Member;

const KEY: [u8; 32] = [7; 32];
const POOL: u8 = 0;
const CLASS_BULK: u8 = 0;

/// Packet wires by id, each of `n` members, the ones in `down` not up.
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

/// A stream wire of `n` members, all up but the ones in `down`.
fn pool(id: u8, n: usize, down: &[usize]) -> StreamWire {
    let reach = crate::link::Reach::Plain("127.0.0.1:1".parse().unwrap());
    let mut w = StreamWire::new(id, reach, n, 300_000_000);
    for (i, l) in w.links.iter_mut().enumerate() {
        if !down.contains(&i) {
            l.h.join(1);
        }
    }
    w
}

fn flow(class: u8, pin: u8, copies: u8) -> Flow {
    Flow::new(Dest::Brain { tag: 1 }, class, pin, 443, copies, 0)
}

/// Frames each packet member and stream member holds, as "wire/index×n".
fn carried(ws: &[Wire], ps: &[StreamWire]) -> Vec<String> {
    let mut out = vec![];
    for w in ws {
        for (i, m) in w.members.iter().enumerate() {
            if m.glue_n > 0 {
                out.push(format!("{}/{i}×{}", w.id, m.glue_n / (DGRAM_HEAD + 2)));
            }
        }
    }
    for w in ps {
        for (i, l) in w.links.iter().enumerate() {
            let mut n = 0;
            let b = l.out.bytes();
            let mut at = 0;
            while let Some((_, k)) = frame::next_frame(&b[at..], 0) {
                n += 1;
                at += k;
            }
            if n > 0 {
                out.push(format!("{}/{i}×{n}", w.id));
            }
        }
    }
    out
}

/// A route of voice on `voice`, bulk on `bulk`, no fates said.
fn route(voice: u8, bulk: u8) -> Route {
    Route { voice, bulk, ..Route::one(ANY_WIRE) }
}

fn send(ws: &mut [Wire], ps: &mut [StreamWire], r: &Route, f: &mut Flow, n: usize) -> Later {
    let mut later = Later::new();
    for _ in 0..n {
        carry(ws, ps, r, &mut later, f, 4, b"hi", 10);
    }
    later
}

/// TestVoiceRidesTwoFates: a voice datagram goes on its main wire with the
/// flow's copies and once on the pool, the other fate; bulk on its one wire.
#[test]
fn voice_rides_two_fates() {
    let (mut ws, mut ps) = (wires(&[(1, 3)], &[]), [pool(POOL, 4, &[])]);
    let mut f = flow(CLASS_VOICE, ANY_WIRE, 2);
    send(&mut ws, &mut ps, &route(1, POOL), &mut f, 1);
    assert_eq!(carried(&ws, &ps), ["1/1×1", "1/2×1", "0/1×1"], "two copies on wire 1, one on the pool");
    assert_eq!((ws[0].t.up_pkts, ps[0].t.up_pkts, f.seq), (1, 1, 1), "one datagram on each wire, one seq");
    let (mut ws, mut ps) = (wires(&[(1, 3)], &[]), [pool(POOL, 4, &[])]);
    send(&mut ws, &mut ps, &route(1, POOL), &mut flow(CLASS_BULK, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["0/1×1"], "bulk on its one wire");
}

/// The members of a wire go round: a stream member's retransmit holds up
/// one datagram in N (trunk sendOnLocked).
#[test]
fn a_wires_members_go_round() {
    let (mut ws, mut ps) = (wires(&[(1, 2)], &[]), [pool(POOL, 4, &[2])]);
    send(&mut ws, &mut ps, &route(1, POOL), &mut flow(CLASS_VOICE, ANY_WIRE, 1), 6);
    assert_eq!(carried(&ws, &ps), ["1/0×3", "1/1×3", "0/0×2", "0/1×2", "0/3×2"], "the down member passed over");
}

/// TestTCPNeverCarriesVoiceAlone: voice routed on the pool still gets a
/// copy on the best wire of fate udp; with none up, the pool alone.
#[test]
fn tcp_never_carries_voice_alone() {
    let (mut ws, mut ps) = (wires(&[(2, 1), (1, 1)], &[]), [pool(POOL, 2, &[])]);
    send(&mut ws, &mut ps, &route(POOL, POOL), &mut flow(CLASS_VOICE, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["1/0×1", "0/1×1"], "the lowest id of fate udp");
    let set = Set::of(&[Carry { wire: POOL, copies: 2, after_ns: 0 }]);
    let (mut ws, mut ps) = (wires(&[(1, 1)], &[]), [pool(POOL, 2, &[])]);
    let r = Route { voice_set: set, ..route(POOL, POOL) };
    send(&mut ws, &mut ps, &r, &mut flow(CLASS_VOICE, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["1/0×1", "0/0×1", "0/1×1"], "the route's own set of the pool alone too");
    let (mut ws, mut ps) = (wires(&[(1, 1)], &[(1, 0)]), [pool(POOL, 2, &[])]);
    send(&mut ws, &mut ps, &route(1, POOL), &mut flow(CLASS_VOICE, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["0/1×1"], "no wire of fate udp up: the pool alone");
}

/// The fates are the route's: a packet wire the brain says is tcp is the
/// other fate of a packet wire of fate udp (a third fate is a value, trunk
/// Wire.Fate).
#[test]
fn a_wires_fate_is_the_routes() {
    let mut ws = wires(&[(1, 1), (2, 1), (3, 1)], &[]);
    let mut r = route(1, 1);
    r.fates[3] = FATE_TCP;
    send(&mut ws, &mut [], &r, &mut flow(CLASS_VOICE, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &[]), ["1/0×1", "3/0×1"], "wire 2 is udp as wire 1: not the second fate");
}

/// A wire of the set with no member up gives its place to the best wire of
/// its fate up (trunk resolveLocked), and the set goes on.
#[test]
fn a_wire_down_gives_its_place_to_one_of_its_fate() {
    let (mut ws, mut ps) = (wires(&[(1, 1), (2, 1)], &[(1, 0)]), [pool(POOL, 1, &[])]);
    send(&mut ws, &mut ps, &route(1, POOL), &mut flow(CLASS_VOICE, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["2/0×1", "0/0×1"]);
    let (mut ws, mut ps) = (wires(&[(2, 2)], &[]), [pool(POOL, 1, &[0])]);
    send(&mut ws, &mut ps, &route(POOL, POOL), &mut flow(CLASS_BULK, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["2/1×1"], "bulk's pool down, no other of its fate: any member up");
}

/// TestVideoGoesOnOneWire: video on its own wire, else voice's main wire;
/// one wire, no copy on the other fate.
#[test]
fn video_goes_on_one_wire() {
    let (mut ws, mut ps) = (wires(&[(1, 1), (2, 1)], &[]), [pool(POOL, 1, &[])]);
    send(&mut ws, &mut ps, &route(1, POOL), &mut flow(CLASS_VIDEO, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["1/0×1"], "voice's main wire");
    let (mut ws, mut ps) = (wires(&[(1, 1), (2, 1)], &[]), [pool(POOL, 1, &[])]);
    let r = Route { video: 2, ..route(1, POOL) };
    send(&mut ws, &mut ps, &r, &mut flow(CLASS_VIDEO, ANY_WIRE, 1), 1);
    assert_eq!(carried(&ws, &ps), ["2/0×1"], "its own wire");
}

/// TestALaterCopyLeavesAfterItsDelay: a carry with a delay waits in Later
/// and leaves when its time comes, with the datagram's seq.
#[test]
fn a_later_copy_leaves_after_its_delay() {
    let set = Set::of(&[Carry { wire: 1, copies: 1, after_ns: 0 }, Carry { wire: 1, copies: 1, after_ns: 10_000_000 }]);
    let mut ws = wires(&[(1, 2)], &[]);
    let r = Route { voice_set: set, ..route(1, 1) };
    let mut f = flow(CLASS_VOICE, ANY_WIRE, 1);
    let mut later = send(&mut ws, &mut [], &r, &mut f, 1);
    assert_eq!(carried(&ws, &[]), ["1/1×1"], "the first copy now");
    assert_eq!(later.next_due(), 10 + 10_000_000);
    later.send_due(&mut ws, &mut [], 10_000_009);
    assert_eq!(carried(&ws, &[]).len(), 1, "not yet");
    later.send_due(&mut ws, &mut [], 10_000_010);
    assert_eq!(carried(&ws, &[]), ["1/0×1", "1/1×1"], "the later one on the next member");
    assert_eq!(later.next_due(), u64::MAX);
}

/// TestPinnedCallHoldsToItsWire: a pinned flow goes on its pin alone, and
/// is dropped while it has none up, counted on it.
#[test]
fn a_pinned_flow_holds_to_its_wire() {
    let (mut ws, mut ps) = (wires(&[(1, 2), (2, 2)], &[]), [pool(POOL, 1, &[])]);
    send(&mut ws, &mut ps, &route(1, POOL), &mut flow(CLASS_VOICE, 2, 1), 1);
    assert_eq!(carried(&ws, &ps), ["2/1×1"], "no second fate for a pin");
    let mut ws = wires(&[(1, 2), (2, 2)], &[(2, 0), (2, 1)]);
    send(&mut ws, &mut [], &route(1, 1), &mut flow(CLASS_VOICE, 2, 1), 1);
    assert!(carried(&ws, &[]).is_empty(), "not on wire 1, whatever the route");
    assert_eq!((ws[1].t.dropped, ws[0].t.dropped), (1, 0));
}

#[test]
fn a_flow_goes_only_on_its_sessions_members() {
    // Session 1 is the exit's new process, 0 its old one: a flow of each
    // reaches only its own (spec/trunk.md, Drain).
    let mut ws = wires(&[(1, 2), (1, 2)], &[]);
    ws[1].sess = 1;
    let mut ps = [pool(POOL, 1, &[]), pool(POOL, 1, &[])];
    ps[1].sess = 1;
    let mut f = flow(CLASS_VOICE, ANY_WIRE, 2);
    f.sess = 1;
    send(&mut ws, &mut ps, &route(1, POOL), &mut f, 1);
    assert!(ws[0].members.iter().all(|m| m.glue_n == 0) && !ps[0].links[0].out.pending(), "nothing on session 0's");
    assert!(ws[1].members.iter().all(|m| m.glue_n > 0) && ps[1].links[0].out.pending(), "on session 1's both fates");
}

#[test]
fn nothing_up_drops_on_the_wire_it_wanted() {
    let mut ws = wires(&[(1, 1), (2, 1)], &[(1, 0), (2, 0)]);
    send(&mut ws, &mut [], &route(2, 2), &mut flow(CLASS_BULK, ANY_WIRE, 2), 1);
    assert_eq!((ws[0].t.dropped, ws[1].t.dropped), (0, 1));
    send(&mut ws, &mut [], &Route::one(ANY_WIRE), &mut flow(CLASS_BULK, ANY_WIRE, 2), 1);
    assert_eq!(ws[0].t.dropped, 1, "no route: on the first wire");
}

#[test]
fn a_frame_on_a_stream_member_is_the_dgram_the_exit_reads() {
    let mut ps = [pool(POOL, 1, &[])];
    let mut later = Later::new();
    carry(&mut [], &mut ps, &route(POOL, POOL), &mut later, &mut flow(CLASS_VOICE, POOL, 1), 9, b"voice", 10);
    let b = ps[0].links[0].out.bytes();
    match frame::next_frame(b, 0) {
        Some((frame::Frame::Dgram { stream: 9, seq: 1, port: 443, off, len }, n)) => {
            assert_eq!((&b[off..off + len], n), (&b"voice"[..], b.len()));
        }
        other => panic!("not one dgram frame: {:?}", other.map(|x| x.1)),
    }
}
