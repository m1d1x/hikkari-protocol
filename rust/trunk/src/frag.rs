//! A frame cut into pieces and put together again (spec/trunk.md, "Wires":
//! `h3dgram`, a frame over the room): the members of the Chromium QUIC wire
//! hold 1194 B of frames a datagram, a client's own QUIC packet does not fit,
//! and it stays on its wire in frag frames rather than going on another.
//! Both ends cut (the entry up, the exit down) and both put together.

use crate::frame::F_FRAG;
use crate::sched::STALE_NS;

/// A frag frame's head: type, id u16, index u8, count u8, n u16.
pub const HEAD: usize = 7;
/// The most pieces a frame is cut into.
pub const PIECES_MAX: usize = 4;
/// The largest piece a receiver keeps (a QUIC DATAGRAM frame's worth, as
/// sched::FRAME).
pub const PIECE_MAX: usize = crate::sched::FRAME - HEAD;
/// The largest frame a cut carries.
pub const WHOLE_MAX: usize = PIECES_MAX * PIECE_MAX;
/// Frames a member keeps being put together.
const SLOTS: usize = 8;

/// How a frame of `len` bytes is cut for datagrams holding `room` bytes of
/// frames: the count of pieces and the size of each but the last, as even
/// as they go; None when PIECES_MAX pieces do not hold it.
pub fn cut(len: usize, room: usize) -> Option<(usize, usize)> {
    let most = room.checked_sub(HEAD)?.min(PIECE_MAX);
    if most == 0 {
        return None;
    }
    let count = len.div_ceil(most).max(2);
    if count > PIECES_MAX {
        return None;
    }
    Some((count, len.div_ceil(count)))
}

/// Writes piece `index` of `count` of cut frame `id`, its bytes `piece`;
/// the frame's length.
#[inline]
pub fn put_piece(out: &mut [u8], id: u16, index: u8, count: u8, piece: &[u8]) -> usize {
    out[0] = F_FRAG;
    out[1..3].copy_from_slice(&id.to_be_bytes());
    out[3] = index;
    out[4] = count;
    out[5..7].copy_from_slice(&(piece.len() as u16).to_be_bytes());
    out[HEAD..HEAD + piece.len()].copy_from_slice(piece);
    HEAD + piece.len()
}

/// What a member's putting together counts.
#[derive(Default, Clone, Copy, Debug)]
pub struct Counts {
    /// Frames put together whole.
    pub whole: u64,
    /// Frames lost: not whole in time, pushed out, or a piece that does not
    /// fit the frame it names.
    pub lost: u64,
}

struct Slot {
    /// Being put together; `done`: whole, its bytes lent out until release.
    used: bool,
    done: bool,
    id: u16,
    count: u8,
    have: u8,
    at: u64,
    len: [u16; PIECES_MAX],
    b: [u8; WHOLE_MAX],
}

/// One member's frames being put together, SLOTS at a time. A frame made
/// whole stays where it was put together until `release`, so that a
/// receiver may send it out of there in its batch, as it sends any frame out
/// of its receive buffer; a slot is allocated with the first frame cut on
/// the member, and kept.
pub struct Reasm {
    s: Box<[Slot; SLOTS]>,
    pub n: Counts,
}

impl Default for Reasm {
    fn default() -> Reasm {
        Reasm::new()
    }
}

impl Reasm {
    pub fn new() -> Reasm {
        let slot = || Slot { used: false, done: false, id: 0, count: 0, have: 0, at: 0, len: [0; PIECES_MAX], b: [0; WHOLE_MAX] };
        Reasm { s: Box::new(std::array::from_fn(|_| slot())), n: Counts::default() }
    }

    /// Piece `index` of `count` of frame `id`, at `now`: the whole frame
    /// once its last piece came (lent until release), else None.
    pub fn piece(&mut self, now: u64, id: u16, index: u8, count: u8, p: &[u8]) -> Option<&[u8]> {
        let (i, c) = (index as usize, count as usize);
        if !(2..=PIECES_MAX).contains(&c) || i >= c || p.len() > PIECE_MAX {
            self.n.lost += 1;
            return None;
        }
        self.age(now);
        let Some(k) = self.slot_of(id, count, now) else {
            self.n.lost += 1;
            return None;
        };
        let s = &mut self.s[k];
        if s.have & (1 << i) != 0 {
            return None;
        }
        s.have |= 1 << i;
        s.len[i] = p.len() as u16;
        s.b[i * PIECE_MAX..i * PIECE_MAX + p.len()].copy_from_slice(p);
        if s.have.count_ones() as usize != c {
            return None;
        }
        let mut n = 0;
        for j in 0..c {
            let l = s.len[j] as usize;
            s.b.copy_within(j * PIECE_MAX..j * PIECE_MAX + l, n);
            n += l;
        }
        s.done = true;
        self.n.whole += 1;
        Some(&self.s[k].b[..n])
    }

    /// Forgets every frame: the member's connection is new, and the other
    /// end's cut ids start over.
    pub fn clear(&mut self) {
        for s in self.s.iter_mut() {
            s.used = false;
            s.done = false;
        }
    }

    /// Frees the frames made whole: their bytes are sent.
    pub fn release(&mut self) {
        for s in self.s.iter_mut().filter(|s| s.done) {
            s.used = false;
            s.done = false;
        }
    }

    /// Whether every slot holds a whole frame not released: the next piece
    /// of a new frame finds no room until release.
    pub fn full(&self) -> bool {
        self.s.iter().all(|s| s.done)
    }

    /// Frames not whole STALE_NS after their first piece are lost.
    fn age(&mut self, now: u64) {
        for s in self.s.iter_mut().filter(|s| s.used && !s.done && now.saturating_sub(s.at) > STALE_NS) {
            s.used = false;
            self.n.lost += 1;
        }
    }

    /// The slot of frame `id`: its own, else a free one, else the oldest one
    /// being put together, whose frame is lost. None while every slot holds
    /// a whole frame not released (the piece is lost).
    fn slot_of(&mut self, id: u16, count: u8, now: u64) -> Option<usize> {
        if let Some(k) = self.s.iter().position(|s| s.used && !s.done && s.id == id) {
            if self.s[k].count == count {
                return Some(k);
            }
            self.s[k].used = false;
            self.n.lost += 1;
        }
        let k = match self.s.iter().position(|s| !s.used) {
            Some(k) => k,
            None => {
                let (k, _) = self.s.iter().enumerate().filter(|(_, s)| !s.done).min_by_key(|(_, s)| s.at)?;
                self.n.lost += 1;
                k
            }
        };
        let s = &mut self.s[k];
        (s.used, s.done, s.id, s.count, s.have, s.at) = (true, false, id, count, 0, now);
        Some(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{self, Frame};
    use crate::guard::Guard;
    use crate::sched::{Class, Sched};

    const MS: u64 = 1_000_000;

    /// The datagrams a scheduler makes of what waits, `room` bytes of
    /// frames each.
    fn datagrams(s: &mut Sched, now: u64, room: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 2000];
        s.drain(now, room, &mut buf, 0, &mut Guard::default(), 0, |b, at, len| {
            out.push(b[at..at + len].to_vec());
            true
        });
        out
    }

    /// The frames of datagrams as the receiver reads them, a cut frame put
    /// together first: each dgram's payload.
    fn receive(r: &mut Reasm, ds: &[Vec<u8>], now: u64) -> Vec<Vec<u8>> {
        let mut got = Vec::new();
        for d in ds {
            let mut at = 0;
            while let Some((f, next)) = frame::next_frame(d, at) {
                let whole = match f {
                    Frame::Frag { id, index, count, off, len } => r.piece(now, id, index, count, &d[off..off + len]).map(<[u8]>::to_vec),
                    Frame::Dgram { .. } => Some(d[at..next].to_vec()),
                    _ => None,
                };
                if let Some(w) = whole {
                    match frame::next_frame(&w, 0) {
                        Some((Frame::Dgram { off, len, .. }, n)) if n == w.len() => got.push(w[off..off + len].to_vec()),
                        _ => panic!("a whole frame is one dgram"),
                    }
                }
                at = next;
            }
            r.release();
        }
        got
    }

    fn dgram(stream: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; frame::DGRAM_HEAD + payload.len()];
        frame::put_dgram(&mut b, stream, seq, 443, payload);
        b
    }

    /// The cuts of the sizes R6.3 measured: a member of 1250 B packets holds
    /// 1194 B of frames; a client's QUIC packet of 1200–1500 B is two pieces,
    /// as even as they go.
    #[test]
    fn a_frame_over_the_room_is_cut_in_even_pieces() {
        assert_eq!(cut(1213, 1194), Some((2, 607)));
        assert_eq!(cut(1513, 1194), Some((2, 757)));
        assert_eq!(cut(1513, 400), Some((4, 379)));
        assert_eq!(cut(1513, 300), None, "four pieces of 293 B do not hold it");
        assert_eq!(cut(100, HEAD), None, "no room for a piece's bytes");
        assert!(cut(WHOLE_MAX, 1400).is_some());
        assert!(cut(WHOLE_MAX + 1, 1400).is_none());
    }

    /// Client datagrams of 1200, 1250, 1350 and 1500 B over a member that
    /// holds 1194 B: each reaches the other end whole, byte for byte, with a
    /// call's datagram between them as it was.
    #[test]
    fn a_clients_quic_packet_reaches_the_other_end_whole() {
        let mut s = Sched::new();
        let mut want = Vec::new();
        for (id, size) in [1200usize, 1250, 1350, 1500].into_iter().enumerate() {
            let p: Vec<u8> = (0..size).map(|i| (i * 7 + size) as u8).collect();
            assert!(s.put_cut(Class::Flow(1), &dgram(1, id as u32, &p), 1194, id as u16, 0));
            want.push(p);
            s.put(Class::Flow(2), frame::DGRAM_HEAD + 160, 0, |b| frame::put_dgram(b, 2, id as u32, 443, &[9; 160]));
            want.push(vec![9; 160]);
        }
        let ds = datagrams(&mut s, MS, 1194);
        assert!(ds.iter().all(|d| d.len() <= 1194), "no datagram over the room");
        let mut got = receive(&mut Reasm::new(), &ds, MS);
        got.sort();
        want.sort();
        assert_eq!(got, want);
    }

    /// A piece lost: its frame is not made of the others, and is counted
    /// lost once 150 ms passed; a piece seen twice is dropped; pieces out of
    /// order still make the frame.
    #[test]
    fn a_frame_missing_a_piece_is_lost_and_counted() {
        let mut r = Reasm::new();
        assert!(r.piece(0, 5, 0, 2, b"ab").is_none());
        assert!(r.piece(0, 5, 0, 2, b"ab").is_none(), "a copy of a piece");
        assert!(r.piece(MS, 6, 1, 2, b"YZ").is_none());
        assert_eq!(r.piece(MS, 6, 0, 2, b"WX"), Some(&b"WXYZ"[..]), "out of order");
        r.release();
        assert!(r.piece(200 * MS, 7, 0, 3, b"q").is_none());
        assert_eq!((r.n.whole, r.n.lost), (1, 1), "frame 5 waited 200 ms");
        assert!(r.piece(200 * MS, 8, 2, 2, b"x").is_none());
        assert!(r.piece(200 * MS, 8, 0, 5, b"x").is_none());
        assert_eq!(r.n.lost, 3, "an index past the count, a count past four");
    }

    /// Eight frames being put together at most: a ninth pushes out the
    /// oldest; a whole frame stays lent until release, and while every slot
    /// holds one a new frame's piece is lost.
    #[test]
    fn a_member_puts_eight_frames_together_at_most() {
        let mut r = Reasm::new();
        for id in 0..9u16 {
            r.piece(id as u64, id, 0, 2, b"a");
        }
        assert_eq!(r.n.lost, 1, "frame 0 pushed out by frame 8");
        for id in 1..9u16 {
            assert_eq!(r.piece(20, id, 1, 2, b"b"), Some(&b"ab"[..]));
        }
        assert!(r.full());
        assert!(r.piece(30, 100, 0, 2, b"c").is_none());
        assert_eq!(r.n.lost, 2, "no slot while all are lent");
        r.release();
        assert!(!r.full());
        assert!(r.piece(31, 100, 0, 2, b"c").is_none());
        assert_eq!(r.piece(31, 100, 1, 2, b"d"), Some(&b"cd"[..]));
        assert_eq!(r.n.whole, 9);
    }
}
