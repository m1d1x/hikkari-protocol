//! A stream's rules (spec/trunk.md, "Streams"), the same at both ends: the
//! bytes it sends are numbered by offset and owed until the other end
//! confirms them, the bytes it receives are put in order and acked, and the
//! window says how far the other end may send. The reference is trunk
//! session.go: ackedLocked (what an ack confirms), dataLocked and takeLocked
//! (chunks in order, the ones past a hole kept), ackGotLocked and writeLocal
//! (what an ack says, when the freed window is told), dropMemberLocked (what
//! a dead member carried goes again, oldest first). No sockets: what carries
//! the bytes and where they are written is the caller's.

use std::collections::{BTreeMap, VecDeque};

use crate::frame::{ACK_FIN, F_DATA, F_FIN, F_OPEN, NO_GOT};

/// A data frame's bytes, at most (trunk DefaultChunk).
pub const CHUNK: usize = 16 << 10;
/// How far past what it wrote a receiver lets the sender go (trunk
/// DefaultWindow).
pub const WINDOW: u64 = 2 << 20;
/// Unconfirmed chunk bytes one member carries, at most (trunk
/// DefaultInflight); a member owing nothing takes a chunk whatever its size.
pub const INFLIGHT: usize = 256 << 10;
/// The carrier of something owed that no member carries now: its member
/// died, and it waits to be sent again.
pub const NO_CARRIER: u32 = u32::MAX;

/// Something a stream sent that the other end must confirm: its open (F_OPEN),
/// a chunk (F_DATA, `len` bytes at `off`) or its end (F_FIN at `off`), and
/// the member carrying it, in the caller's own numbering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owed {
    pub kind: u8,
    pub off: u64,
    pub len: u32,
    pub carrier: u32,
}

/// The bytes of a stream's unconfirmed chunks, from the lowest one owed to
/// what was numbered last, so a chunk can go again when its member dies.
/// They span at most the window: an ack that gives credit up to received +
/// WINDOW confirms everything below received. One buffer that grows to what
/// the stream keeps and is moved down once the bytes dropped from its front
/// are the larger half, so each byte is moved at most once on average.
#[derive(Default)]
pub struct Kept {
    buf: Vec<u8>,
    /// The stream offset of buf[at].
    base: u64,
    at: usize,
}

impl Kept {
    fn push(&mut self, p: &[u8]) {
        self.buf.extend_from_slice(p);
    }

    /// Bytes below `off` are confirmed: they are not kept any more.
    fn drop_below(&mut self, off: u64) {
        if off <= self.base {
            return;
        }
        let n = ((off - self.base) as usize).min(self.buf.len() - self.at);
        self.at += n;
        self.base += n as u64;
        if self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        } else if self.at > self.buf.len() / 2 {
            self.buf.drain(..self.at);
            self.at = 0;
        }
    }

    /// The kept bytes of [off, off+len).
    pub fn get(&self, off: u64, len: usize) -> &[u8] {
        let i = self.at + (off - self.base) as usize;
        &self.buf[i..i + len]
    }

    /// Bytes kept now.
    pub fn len(&self) -> usize {
        self.buf.len() - self.at
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The sending half: what was numbered, how far the other end lets it go,
/// what it still owes, and the bytes of what it owes.
pub struct Send {
    /// Bytes numbered so far: the next chunk's offset.
    pub sent: u64,
    /// The other end takes bytes below this.
    pub credit: u64,
    /// In the order it was sent: the open, chunks by offset, the FIN.
    pub owed: VecDeque<Owed>,
    pub kept: Kept,
    /// Owed things no member carries (NO_CARRIER): they wait to go again.
    pub stranded: u32,
    /// The FIN is sent, and confirmed.
    pub fin_sent: bool,
    pub fin_done: bool,
}

impl Default for Send {
    fn default() -> Send {
        Send {
            sent: 0,
            credit: WINDOW,
            owed: VecDeque::with_capacity(16),
            kept: Kept::default(),
            stranded: 0,
            fin_sent: false,
            fin_done: false,
        }
    }
}

impl Send {
    /// How many bytes the credit lets it number now.
    pub fn room(&self) -> u64 {
        self.credit.saturating_sub(self.sent)
    }

    /// Numbers the chunk `p` on `carrier`, keeping its bytes until they are
    /// confirmed: its offset.
    pub fn chunk(&mut self, p: &[u8], carrier: u32) -> u64 {
        let off = self.sent;
        self.owed.push_back(Owed { kind: F_DATA, off, len: p.len() as u32, carrier });
        self.kept.push(p);
        self.sent += p.len() as u64;
        off
    }

    pub fn open(&mut self, carrier: u32) {
        self.owed.push_back(Owed { kind: F_OPEN, off: 0, len: 0, carrier });
    }

    /// Its end at the offset reached.
    pub fn fin(&mut self, carrier: u32) -> u64 {
        self.fin_sent = true;
        self.owed.push_back(Owed { kind: F_FIN, off: self.sent, len: 0, carrier });
        self.sent
    }

    /// An ack of the other end (trunk ackedLocked): the credit moves on, and
    /// `confirmed` is told of each thing it owed that the ack confirms. Any
    /// ack confirms the open, the ack's FIN flag the FIN; a chunk is
    /// confirmed by `got` naming it or by `received` passing its end.
    pub fn acked(&mut self, received: u64, credit: u64, flags: u8, got: u64, mut confirmed: impl FnMut(&Owed)) {
        if credit > self.credit {
            self.credit = credit;
        }
        let fin = flags & ACK_FIN != 0;
        let mut fin_done = false;
        self.owed.retain(|o| {
            let done = match o.kind {
                F_OPEN => true,
                F_DATA => o.off + o.len as u64 <= received || o.off == got,
                _ => fin,
            };
            if done {
                fin_done |= o.kind == F_FIN;
                confirmed(o);
            }
            !done
        });
        self.fin_done |= fin_done;
        if self.stranded > 0 {
            self.stranded = self.owed.iter().filter(|o| o.carrier == NO_CARRIER).count() as u32;
        }
        let low = self.owed.iter().find(|o| o.kind == F_DATA).map_or(self.sent, |o| o.off);
        self.kept.drop_below(low);
    }

    /// The member `carrier` died (trunk dropMemberLocked): what it carried
    /// waits to go again. Whether it carried anything of this stream.
    pub fn strand(&mut self, carrier: u32) -> bool {
        let mut any = false;
        for o in self.owed.iter_mut().filter(|o| o.carrier == carrier) {
            o.carrier = NO_CARRIER;
            self.stranded += 1;
            any = true;
        }
        any
    }

    /// The first owed thing waiting to go again, oldest first: its index.
    pub fn next_stranded(&self) -> Option<usize> {
        if self.stranded == 0 {
            return None;
        }
        self.owed.iter().position(|o| o.carrier == NO_CARRIER)
    }

    /// Owed thing i goes again on `carrier`.
    pub fn resent(&mut self, i: usize, carrier: u32) {
        self.owed[i].carrier = carrier;
        self.stranded -= 1;
    }
}

/// The receiving half: what arrived in order, what was written on, the
/// other end's FIN, and the chunks past a hole.
pub struct Recv {
    /// Contiguous bytes received.
    pub received: u64,
    /// Bytes written to the local connection.
    pub written: u64,
    /// The offset of the other end's FIN, once known.
    pub fin_at: Option<u64>,
    /// The credit last told.
    pub advertise: u64,
    ahead: BTreeMap<u64, Vec<u8>>,
}

impl Default for Recv {
    fn default() -> Recv {
        Recv { received: 0, written: 0, fin_at: None, advertise: WINDOW, ahead: BTreeMap::new() }
    }
}

impl Recv {
    /// A chunk of `p` at `off` (trunk dataLocked): the bytes that are next in
    /// order go to `take`, those of the chunk and then of the ones kept past
    /// the hole it fills; a chunk past a hole is kept while it is inside the
    /// window. Returns the ack's got: the chunk's offset, or NO_GOT for one
    /// past the window (not kept, so not confirmed: it comes again).
    pub fn chunk(&mut self, off: u64, p: &[u8], mut take: impl FnMut(&[u8])) -> u64 {
        let end = off + p.len() as u64;
        if end <= self.received {
            return off; // a copy of what is here
        }
        if off > self.received {
            if off < self.written + WINDOW + CHUNK as u64 {
                self.ahead.insert(off, p.to_vec());
                return off;
            }
            return NO_GOT;
        }
        take(&p[(self.received - off) as usize..]);
        self.received = end;
        // The kept chunks that start inside what is here now, lowest first;
        // one sent again cut differently still counts for its tail.
        while let Some((&o, _)) = self.ahead.range(..=self.received).next() {
            let q = self.ahead.remove(&o).unwrap_or_default();
            let qend = o + q.len() as u64;
            if qend > self.received {
                take(&q[(self.received - o) as usize..]);
                self.received = qend;
            }
        }
        off
    }

    /// The other end's FIN at `off`.
    pub fn fin(&mut self, off: u64) {
        if self.fin_at.is_none() {
            self.fin_at = Some(off);
        }
    }

    /// Everything up to the other end's FIN is here.
    pub fn all_in(&self) -> bool {
        self.fin_at == Some(self.received)
    }

    /// What an ack says now (trunk ackGotLocked): received, the credit (and
    /// the credit is then told), the flags.
    pub fn ack(&mut self) -> (u64, u64, u8) {
        self.advertise = self.written + WINDOW;
        (self.received, self.advertise, if self.all_in() { ACK_FIN } else { 0 })
    }

    /// n more bytes written on (trunk writeLocal): whether the window freed
    /// by a quarter since it was last told, so an ack must tell it.
    pub fn wrote(&mut self, n: usize) -> bool {
        self.written += n as u64;
        self.written + WINDOW >= self.advertise + WINDOW / 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ack_confirms_the_open_chunks_by_got_or_received_and_the_fin_by_its_flag() {
        let mut s = Send::default();
        s.open(1);
        let a = s.chunk(&[1; 100], 1);
        let b = s.chunk(&[2; 100], 2);
        let c = s.chunk(&[3; 100], 3);
        assert_eq!((a, b, c, s.room()), (0, 100, 200, WINDOW - 300));
        s.fin(3);
        let mut seen = vec![];
        s.acked(0, 0, 0, 200, |o| seen.push((o.kind, o.off)));
        assert_eq!(seen, [(F_OPEN, 0), (F_DATA, 200)], "any ack confirms the open, got the chunk it names");
        seen.clear();
        s.acked(100, WINDOW + 100, 0, NO_GOT, |o| seen.push((o.kind, o.off)));
        assert_eq!(seen, [(F_DATA, 0)], "received passing a chunk's end confirms it");
        assert_eq!(s.credit, WINDOW + 100);
        s.acked(50, 10, 0, NO_GOT, |_| {});
        assert_eq!(s.credit, WINDOW + 100, "credit never goes back");
        assert!(!s.fin_done);
        seen.clear();
        s.acked(300, 0, ACK_FIN, NO_GOT, |o| seen.push((o.kind, o.off)));
        assert_eq!(seen, [(F_DATA, 100), (F_FIN, 300)]);
        assert!(s.fin_done && s.owed.is_empty());
    }

    #[test]
    fn a_dead_members_things_go_again_oldest_first_with_their_bytes() {
        let mut s = Send::default();
        s.open(1);
        s.chunk(b"aaaa", 1);
        s.chunk(b"bbbb", 2);
        s.chunk(b"cccc", 1);
        s.fin(1);
        assert!(s.strand(1) && !s.strand(9));
        assert_eq!(s.stranded, 4);
        let i = s.next_stranded().unwrap();
        assert_eq!((s.owed[i].kind, i), (F_OPEN, 0), "the open goes first");
        s.resent(i, 3);
        let i = s.next_stranded().unwrap();
        let o = s.owed[i];
        assert_eq!((o.kind, o.off, s.kept.get(o.off, o.len as usize)), (F_DATA, 0, &b"aaaa"[..]));
        // An ack on another member confirms the first two chunks meanwhile.
        s.acked(8, WINDOW, 0, NO_GOT, |_| {});
        assert_eq!(s.stranded, 2, "a confirmed chunk waits no more");
        let i = s.next_stranded().unwrap();
        let o = s.owed[i];
        assert_eq!((o.kind, o.off, s.kept.get(o.off, o.len as usize)), (F_DATA, 8, &b"cccc"[..]));
        assert_eq!(s.kept.len(), 4, "the confirmed bytes are not kept");
        s.resent(i, 3);
        let i = s.next_stranded().unwrap();
        assert_eq!(s.owed[i].kind, F_FIN);
        s.resent(i, 3);
        assert_eq!(s.next_stranded(), None);
        s.acked(12, WINDOW, ACK_FIN, NO_GOT, |_| {});
        assert!(s.fin_done && s.kept.is_empty());
    }

    #[test]
    fn kept_bytes_follow_out_of_order_confirmations() {
        let mut s = Send::default();
        for i in 0..8u8 {
            s.chunk(&[i; 1000], 1);
        }
        s.acked(0, WINDOW, 0, 1000, |_| {});
        assert_eq!(s.kept.len(), 8000, "the lowest chunk is still owed: nothing goes");
        s.acked(0, WINDOW, 0, 0, |_| {});
        assert_eq!(s.kept.len(), 6000, "the two lowest confirmed by got");
        assert_eq!(s.kept.get(5000, 1000), &[5; 1000][..]);
        s.acked(7000, WINDOW, 0, NO_GOT, |_| {});
        assert_eq!(s.kept.get(7000, 1000), &[7; 1000][..]);
        s.chunk(&[8; 10], 1);
        assert_eq!(s.kept.get(7000, 1010)[1000..], [8; 10]);
    }

    fn take_all(r: &mut Recv, off: u64, p: &[u8], out: &mut Vec<u8>) -> u64 {
        r.chunk(off, p, |q| out.extend_from_slice(q))
    }

    #[test]
    fn chunks_past_a_hole_wait_for_it_and_copies_count_for_their_tail() {
        let mut r = Recv::default();
        let mut out = vec![];
        assert_eq!(take_all(&mut r, 4, b"ef", &mut out), 4);
        assert_eq!(take_all(&mut r, 8, b"ij", &mut out), 8);
        assert!(out.is_empty() && r.received == 0);
        assert_eq!(take_all(&mut r, 0, b"abcd", &mut out), 0);
        assert_eq!((out.as_slice(), r.received), (&b"abcdef"[..], 6), "the hole at 6 holds ij back");
        // Sent again cut differently: 5..8 overlaps what is here.
        take_all(&mut r, 5, b"fgh", &mut out);
        assert_eq!((out.as_slice(), r.received), (&b"abcdefghij"[..], 10));
        assert_eq!(take_all(&mut r, 2, b"cd", &mut out), 2, "a copy of what is here is confirmed again");
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn a_chunk_past_the_window_is_not_kept_nor_confirmed() {
        let mut r = Recv::default();
        let far = WINDOW + CHUNK as u64;
        assert_eq!(r.chunk(far, b"x", |_| unreachable!()), NO_GOT);
        assert_eq!(r.chunk(far - 1, b"x", |_| unreachable!()), far - 1);
    }

    #[test]
    fn the_freed_window_is_told_by_the_quarter_and_the_fin_once_all_is_in() {
        let mut r = Recv::default();
        r.chunk(0, &[0; 100], |_| {});
        r.fin(100);
        assert!(r.all_in());
        assert_eq!(r.ack(), (100, WINDOW, ACK_FIN));
        assert!(!r.wrote(WINDOW as usize / 4 - 1));
        assert!(r.wrote(1), "a quarter of the window freed since it was told");
        assert_eq!(r.ack().1, WINDOW + WINDOW / 4);
        let mut r = Recv::default();
        r.fin(10);
        assert_eq!(r.ack().2, 0, "the FIN is not confirmed before the bytes before it");
    }
}
