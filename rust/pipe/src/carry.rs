//! Which wire and member carry a flow's datagram (trunk Route).

use hikkari_trunk::frame::{self, DGRAM_HEAD};

use crate::ctl::ANY_WIRE;
use crate::flow::{Dest, Flow};
use crate::member::Wire;

/// Carries one datagram of flow id on its wire: the pin, else its class's
/// route; a wire with no member up is passed over for any member that can
/// carry it (trunk Route), a pinned flow's datagram is dropped instead. A
/// flow keeps to one member of the wire while it is up: its datagrams stay in
/// order.
#[inline]
pub fn carry(wires: &mut [Wire], route: [u8; 2], f: &mut Flow, id: u32, p: &[u8], now: u64) {
    if matches!(f.dest, Dest::Gone) {
        return;
    }
    let strict = f.pin != ANY_WIRE;
    let want = if strict { f.pin } else { route[(f.class & 1) as usize] };
    let Some(wi) = pick_wire(wires, want, strict, id) else { return };
    let w = &mut wires[wi];
    f.seq = f.seq.wrapping_add(1);
    let (seq, port) = (f.seq, f.port);
    let n = w.members.len();
    let copies = f.copies.max(1) as usize;
    let start = id as usize % n;
    let mut sent = 0;
    for k in 0..n {
        let m = &mut w.members[(start + k) % n];
        if !m.h.up {
            continue;
        }
        m.glue_frame(DGRAM_HEAD + p.len(), w.glue_max, now, |b| frame::put_dgram(b, id, seq, port, p));
        sent += 1;
        if sent == copies {
            break;
        }
    }
    w.t.up_pkts += 1;
    w.t.up_bytes += p.len() as u64;
}

/// The wire `want` if a member of it is up; else (not strict) one of the
/// wires that have, spread by flow id. None, counted as dropped on `want`,
/// when nothing can carry it.
#[inline]
fn pick_wire(wires: &mut [Wire], want: u8, strict: bool, id: u32) -> Option<usize> {
    if let Some(i) = wires.iter().position(|w| w.id == want && w.any_up()) {
        return Some(i);
    }
    let up = if strict { 0 } else { wires.iter().filter(|w| w.any_up()).count() };
    if up == 0 {
        let at = if strict { wires.iter().position(|w| w.id == want) } else { Some(wires.iter().position(|w| w.id == want).unwrap_or(0)) };
        if let Some(w) = at.and_then(|i| wires.get_mut(i)) {
            w.t.dropped += 1;
        }
        return None;
    }
    wires.iter().enumerate().filter(|(_, w)| w.any_up()).map(|(i, _)| i).nth(id as usize % up)
}
