//! A stream member's buffers and a local connection's waiting bytes, the
//! same at both ends of the trunk (spec/trunk.md, "Member": frames one after
//! another on a byte stream). No sockets: the caller writes `Out::bytes()`
//! to its socket and says how much went (`Out::wrote`), as it writes
//! `Behind::bytes()` to a local connection. The reference is trunk
//! session.go: a member's writeLoop (frames in order, one write for all that
//! wait) and writeLocal (what arrived waits for the local connection).
//!
//! Nothing is allocated per frame: an Out is allocated once, and a chunk of
//! a local connection's bytes is read straight into it behind its frame's
//! head (chunk_room, chunk_buf, chunk_done).

use crate::frame::{self, DATA_HEAD};
use crate::stream::INFLIGHT;

/// A member's out buffer: four times its chunks in flight, so the kernel's
/// buffer can take what the window lets out while the frames that are not
/// chunks keep their room.
pub const OUT: usize = 4 * INFLIGHT;
/// Room in the out buffer chunks leave to the other frames (acks, pings,
/// opens, FINs, resets): a member whose buffer fills even this is not taking
/// writes, and dies by its stall.
pub const SPARE: usize = 64 << 10;
/// A member's in buffer: room for several frames of the largest chunk a
/// frame can carry (n is u16).
pub const IN: usize = 256 << 10;

/// Frames waiting for the member's socket, at buf[head..tail].
pub struct Out {
    buf: Box<[u8]>,
    head: usize,
    tail: usize,
}

impl Default for Out {
    fn default() -> Out {
        Out::new()
    }
}

impl Out {
    pub fn new() -> Out {
        Out { buf: vec![0; OUT].into_boxed_slice(), head: 0, tail: 0 }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }

    pub fn pending(&self) -> bool {
        self.tail > self.head
    }

    /// Makes `need` bytes free after the tail, moving what waits to the
    /// front when it must; whether they are. What waits is moved only when
    /// it is no more than the room the move frees, so a byte is moved at
    /// most once on average: a slow socket with most of the buffer waiting
    /// would otherwise have it all moved for every chunk.
    fn room(&mut self, need: usize) -> bool {
        if self.head == self.tail {
            self.clear();
        }
        if OUT - self.tail < need && self.head >= self.tail - self.head {
            self.buf.copy_within(self.head..self.tail, 0);
            self.tail -= self.head;
            self.head = 0;
        }
        OUT - self.tail >= need
    }

    /// One frame of at most `need` bytes, written by `put`; false when the
    /// buffer has no room for it.
    #[inline]
    pub fn frame(&mut self, need: usize, put: impl FnOnce(&mut [u8]) -> usize) -> bool {
        if !self.room(need) {
            return false;
        }
        self.tail += put(&mut self.buf[self.tail..]);
        true
    }

    /// Room for a chunk of up to `n` bytes, leaving SPARE: the bytes a chunk
    /// may have now (0: none).
    pub fn chunk_room(&mut self, n: usize) -> usize {
        self.room(DATA_HEAD + n + SPARE);
        (OUT - self.tail).saturating_sub(SPARE + DATA_HEAD).min(n)
    }

    /// Where a chunk's bytes go: after its head, at the tail.
    pub fn chunk_buf(&mut self, n: usize) -> &mut [u8] {
        let at = self.tail + DATA_HEAD;
        &mut self.buf[at..at + n]
    }

    /// The chunk of n bytes read into chunk_buf is a frame now.
    pub fn chunk_done(&mut self, stream: u32, off: u64, n: usize) {
        frame::put_data_head(&mut self.buf[self.tail..], stream, off, n as u16);
        self.tail += DATA_HEAD + n;
    }

    /// What waits for the socket, in order.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.buf[self.head..self.tail]
    }

    /// The socket took n bytes of bytes().
    #[inline]
    pub fn wrote(&mut self, n: usize) {
        self.head += n;
    }
}

/// Bytes that arrived in order for a local connection and wait for it to
/// take them (trunk writeLocal's queue), at buf[at..]. One buffer that grows
/// to what waits; what was taken goes once it is the larger half, so a
/// connection always behind does not grow it by all it was ever sent.
#[derive(Default)]
pub struct Behind {
    buf: Vec<u8>,
    at: usize,
}

impl Behind {
    pub fn pending(&self) -> bool {
        self.at < self.buf.len()
    }

    /// What waits, in order.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.buf[self.at..]
    }

    /// Bytes behind what waits.
    pub fn push(&mut self, p: &[u8]) {
        if !self.pending() {
            self.buf.clear();
            self.at = 0;
        }
        self.buf.extend_from_slice(p);
    }

    /// The connection took n bytes of bytes().
    pub fn took(&mut self, n: usize) {
        self.at += n;
        if self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        } else if self.at > self.buf.len() / 2 {
            self.buf.drain(..self.at);
            self.at = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{next_frame, Frame};

    #[test]
    fn a_chunk_read_behind_its_head_is_a_frame_and_leaves_the_spare() {
        let mut o = Out::new();
        assert!(o.frame(9, |b| frame::put_ping(b, frame::F_PING, 7)));
        let k = o.chunk_room(100);
        assert_eq!(k, 100);
        o.chunk_buf(k).fill(5);
        o.chunk_done(3, 40, k);
        let p = o.bytes();
        let (f, next) = next_frame(p, 0).unwrap();
        assert!(matches!(f, Frame::Ping(7)));
        let Some((Frame::Data { stream: 3, off: 40, at, len: 100 }, end)) = next_frame(p, next) else { panic!("data") };
        assert!(p[at..at + 100].iter().all(|&b| b == 5) && end == p.len());
        o.wrote(p.len());
        assert!(!o.pending());
        // The buffer full of chunks still leaves SPARE to other frames.
        while o.chunk_room(16 << 10) > 0 {
            let k = o.chunk_room(16 << 10);
            o.chunk_done(1, 0, k);
        }
        assert!(o.frame(30, |b| frame::put_ack(b, 1, 0, 0, 0, 0)), "an ack fits in the spare");
    }

    #[test]
    fn behind_keeps_what_was_not_taken_in_order() {
        let mut b = Behind::default();
        b.push(b"abcd");
        b.took(1);
        b.push(b"ef");
        assert_eq!(b.bytes(), b"bcdef");
        b.took(3);
        assert_eq!(b.bytes(), b"ef");
        b.took(2);
        assert!(!b.pending());
        b.push(b"g");
        assert_eq!(b.bytes(), b"g");
    }
}
