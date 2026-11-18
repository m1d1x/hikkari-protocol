//! The trunk's frames (spec/trunk.md, "Frames"): written into and read out
//! of a caller's buffer, nothing allocated.

pub const F_HELLO: u8 = 1;
pub const F_OPEN: u8 = 2;
pub const F_DATA: u8 = 3;
pub const F_ACK: u8 = 4;
pub const F_FIN: u8 = 5;
pub const F_RST: u8 = 6;
pub const F_DGRAM: u8 = 7;
pub const F_PING: u8 = 8;
pub const F_PONG: u8 = 9;
pub const F_DRAIN: u8 = 10;
pub const F_OBSERVE: u8 = 11;
/// A piece of a frame cut for a datagram that does not hold it (frag.rs).
pub const F_FRAG: u8 = 12;
/// The entry's new process claims a flow or stream of its old one's session
/// (spec/trunk.md, "An entry's own process replaced"); the exit answers.
pub const F_ADOPT: u8 = 13;
pub const F_ADOPTED: u8 = 14;

/// The entry's capabilities, the first byte of the epoch its hello sends
/// (spec/trunk.md, "Frames": hello; trunk capObserve): it reads observe
/// frames, so the exit sends it the marks of testers' streams and flows.
pub const CAP_OBSERVE: u8 = 1;
/// The entry may send adopt: an exit that adopts says so with an adopted of
/// ADOPT_EXIT right after its answer to the hello (an older exit drops a
/// member on a frame it does not know).
pub const CAP_ADOPT: u8 = 2;
/// An adopt's kinds: the flow or stream it claims (OBS_STREAM, OBS_FLOW),
/// and the adopted that says the exit adopts at all.
pub const ADOPT_EXIT: u8 = 0;
/// An adopt frame: type, kind u8, session [16], old u32, new u32, up u64, down u64.
pub const ADOPT_LEN: usize = 42;
/// An adopted frame: type, kind u8, stream u32, ok u8.
pub const ADOPTED_LEN: usize = 7;
/// An observe frame's kinds (trunk ObsStream, ObsFlow).
pub const OBS_STREAM: u8 = 1;
pub const OBS_FLOW: u8 = 2;

/// A dgram frame's head: type, stream u32, seq u32, port u16, n u16.
pub const DGRAM_HEAD: usize = 13;
/// A data frame's head: type, stream u32, offset u64, n u16.
pub const DATA_HEAD: usize = 15;
/// An ack frame: type, stream u32, received u64, credit u64, flags u8, got u64.
pub const ACK_LEN: usize = 30;
/// An ack's flag: the FIN is received.
pub const ACK_FIN: u8 = 1;
/// An ack's got for no chunk in particular (trunk noGot).
pub const NO_GOT: u64 = u64::MAX;

/// A t1 hello (a pool member's: it carries everything), the entry's: its
/// session id and a zero epoch whose first byte is its capabilities: it
/// reads observe frames.
pub fn hello_t1(out: &mut [u8], session: &[u8; 16]) -> usize {
    out[0] = F_HELLO;
    out[1..5].copy_from_slice(b"HKT1");
    out[5..21].copy_from_slice(session);
    out[21..29].fill(0);
    out[21] = CAP_OBSERVE | CAP_ADOPT;
    29
}

pub fn put_open(out: &mut [u8], stream: u32, port: u16) -> usize {
    out[0] = F_OPEN;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..7].copy_from_slice(&port.to_be_bytes());
    7
}

/// A data frame's head for n bytes of `stream` at `off`; the n bytes follow
/// it at out[DATA_HEAD..], written there by the caller (read straight from
/// the client's socket).
#[inline]
pub fn put_data_head(out: &mut [u8], stream: u32, off: u64, n: u16) -> usize {
    out[0] = F_DATA;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..13].copy_from_slice(&off.to_be_bytes());
    out[13..15].copy_from_slice(&n.to_be_bytes());
    DATA_HEAD
}

#[inline]
pub fn put_ack(out: &mut [u8], stream: u32, received: u64, credit: u64, flags: u8, got: u64) -> usize {
    out[0] = F_ACK;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..13].copy_from_slice(&received.to_be_bytes());
    out[13..21].copy_from_slice(&credit.to_be_bytes());
    out[21] = flags;
    out[22..30].copy_from_slice(&got.to_be_bytes());
    ACK_LEN
}

pub fn put_fin(out: &mut [u8], stream: u32, off: u64) -> usize {
    out[0] = F_FIN;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..13].copy_from_slice(&off.to_be_bytes());
    13
}

pub fn put_rst(out: &mut [u8], stream: u32) -> usize {
    out[0] = F_RST;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    5
}
/// A t2 hello of a packet member of `wire` (flags: packet, no streams).
pub fn hello_t2(out: &mut [u8], session: &[u8; 16], wire: u8) -> usize {
    out[0] = F_HELLO;
    out[1..5].copy_from_slice(b"HKT2");
    out[5..21].copy_from_slice(session);
    out[21..29].fill(0); // the entry has no epoch; byte 0 is its capabilities
    out[21] = CAP_OBSERVE | CAP_ADOPT;
    out[29] = wire;
    out[30] = KIND_PACKET;
    31
}

/// A hello as read from the other end: its session id, the epoch it
/// carries (the exit's; from the entry, its capabilities and zeros), and for
/// a t2 hello its wire and flags (spec/trunk.md, "Wires").
pub struct Hello {
    pub session: [u8; 16],
    pub epoch: [u8; 8],
    /// None for t1: a pool member, carrying everything.
    pub t2: Option<(u8, u8)>,
}

/// A t2 hello's flag: the member carries streams (trunk kindStreams).
pub const KIND_STREAMS: u8 = 1;
/// A t2 hello's flag: each frame in a datagram of its own (trunk kindPacket).
pub const KIND_PACKET: u8 = 2;

/// Reads the hello frame at `p[at..]` (next_frame said it is one).
pub fn read_hello(p: &[u8], at: usize) -> Option<Hello> {
    let b = at + 1;
    let t2 = match p.get(b..b + 4)? {
        b"HKT1" => None,
        b"HKT2" => Some((*p.get(b + 28)?, *p.get(b + 29)?)),
        _ => return None,
    };
    Some(Hello { session: p.get(b + 4..b + 20)?.try_into().ok()?, epoch: p[b + 20..b + 28].try_into().ok()?, t2 })
}

/// The exit's answer to a hello: the same session id, the exit's epoch, in
/// kind (trunk appendHelloFor: t1 for a pool member, t2 with the same wire
/// and flags for any other).
pub fn put_hello(out: &mut [u8], session: &[u8; 16], epoch: &[u8; 8], t2: Option<(u8, u8)>) -> usize {
    out[0] = F_HELLO;
    out[1..5].copy_from_slice(if t2.is_some() { b"HKT2" } else { b"HKT1" });
    out[5..21].copy_from_slice(session);
    out[21..29].copy_from_slice(epoch);
    match t2 {
        Some((wire, flags)) => {
            out[29] = wire;
            out[30] = flags;
            31
        }
        None => 29,
    }
}

#[inline]
pub fn put_dgram(out: &mut [u8], stream: u32, seq: u32, port: u16, payload: &[u8]) -> usize {
    out[0] = F_DGRAM;
    out[1..5].copy_from_slice(&stream.to_be_bytes());
    out[5..9].copy_from_slice(&seq.to_be_bytes());
    out[9..11].copy_from_slice(&port.to_be_bytes());
    out[11..13].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    out[13..13 + payload.len()].copy_from_slice(payload);
    13 + payload.len()
}

#[inline]
pub fn put_ping(out: &mut [u8], typ: u8, token: u64) -> usize {
    out[0] = typ;
    out[1..9].copy_from_slice(&token.to_be_bytes());
    9
}

/// The exit's observe (spec/trunk.md, "Observation"): stream or flow
/// `stream` (kind OBS_STREAM or OBS_FLOW) is a tester's, its observation
/// `id`.
#[inline]
pub fn put_observe(out: &mut [u8], kind: u8, stream: u32, id: u64) -> usize {
    out[0] = F_OBSERVE;
    out[1] = kind;
    out[2..6].copy_from_slice(&stream.to_be_bytes());
    out[6..14].copy_from_slice(&id.to_be_bytes());
    14
}

/// The entry's adopt: flow or stream `old` of the session `session` (its
/// old process's) is now `new` of the session this member is of; a stream's
/// `up` (bytes the exit received) and `down` (bytes the client got).
pub fn put_adopt(out: &mut [u8], kind: u8, session: &[u8; 16], old: u32, new: u32, up: u64, down: u64) -> usize {
    out[0] = F_ADOPT;
    out[1] = kind;
    out[2..18].copy_from_slice(session);
    out[18..22].copy_from_slice(&old.to_be_bytes());
    out[22..26].copy_from_slice(&new.to_be_bytes());
    out[26..34].copy_from_slice(&up.to_be_bytes());
    out[34..42].copy_from_slice(&down.to_be_bytes());
    ADOPT_LEN
}

/// The exit's answer to an adopt of `stream` (its new id), or with
/// ADOPT_EXIT, stream 0 and ok, that it adopts at all.
pub fn put_adopted(out: &mut [u8], kind: u8, stream: u32, ok: bool) -> usize {
    out[0] = F_ADOPTED;
    out[1] = kind;
    out[2..6].copy_from_slice(&stream.to_be_bytes());
    out[6] = ok as u8;
    ADOPTED_LEN
}

/// The exit's drain (spec/trunk.md, "Drain"): its process is being replaced.
#[inline]
pub fn put_drain(out: &mut [u8]) -> usize {
    out[0] = F_DRAIN;
    1
}

/// One frame read from a datagram's plaintext.
pub enum Frame {
    Hello,
    /// A dgram: its flow (stream), its sender's seq (the receiver drops
    /// copies by it, flow::Replay), the exit's port, and the payload at
    /// `off..off + len`.
    Dgram { stream: u32, seq: u32, port: u16, off: usize, len: usize },
    Ping(u64),
    Pong(u64),
    Drain,
    Open { stream: u32, port: u16 },
    /// A chunk of a stream at `off`, its bytes at `at..at + len` of the
    /// datagram or the read buffer.
    Data { stream: u32, off: u64, at: usize, len: usize },
    Ack { stream: u32, received: u64, credit: u64, flags: u8, got: u64 },
    Fin { stream: u32, off: u64 },
    Rst { stream: u32 },
    /// The exit marked a stream or flow of the entry's (OBS_STREAM,
    /// OBS_FLOW) for both ends to report under observation id `token`.
    Observe { kind: u8, stream: u32, token: u64 },
    /// Piece `index` of `count` of the sender's cut frame `id`, its bytes at
    /// `off..off + len` (frag.rs).
    Frag { id: u16, index: u8, count: u8, off: usize, len: usize },
    /// The entry claims `old` of its old session `session` as `new` here.
    Adopt { kind: u8, session: [u8; 16], old: u32, new: u32, up: u64, down: u64 },
    /// The exit's answer to an adopt of `stream`, or with ADOPT_EXIT that it
    /// adopts.
    Adopted { kind: u8, stream: u32, ok: bool },
    Other,
}

/// Reads the frame at `p[at..]`: the frame and where the next one starts,
/// or None for a torn or unknown frame (the rest of the datagram is dropped).
#[inline]
pub fn next_frame(p: &[u8], at: usize) -> Option<(Frame, usize)> {
    let typ = *p.get(at)?;
    let rest = p.len() - at - 1;
    let b = at + 1;
    let be32 = |i: usize| u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
    let be64 = |i: usize| u64::from_be_bytes(p[i..i + 8].try_into().unwrap());
    let fixed = |n: usize| if rest >= n { Some(b + n) } else { None };
    match typ {
        F_HELLO => {
            if rest < 28 {
                return None;
            }
            let n = if &p[b..b + 4] == b"HKT2" { 30 } else { 28 };
            Some((Frame::Hello, fixed(n)?))
        }
        F_DGRAM => {
            if rest < 12 {
                return None;
            }
            let n = u16::from_be_bytes([p[b + 10], p[b + 11]]) as usize;
            if rest < 12 + n {
                return None;
            }
            let port = u16::from_be_bytes([p[b + 8], p[b + 9]]);
            Some((Frame::Dgram { stream: be32(b), seq: be32(b + 4), port, off: b + 12, len: n }, b + 12 + n))
        }
        F_PING => Some((Frame::Ping(be64(fixed(8)? - 8)), b + 8)),
        F_PONG => Some((Frame::Pong(be64(fixed(8)? - 8)), b + 8)),
        F_DRAIN => Some((Frame::Drain, b)),
        F_OPEN => {
            let next = fixed(6)?;
            Some((Frame::Open { stream: be32(b), port: u16::from_be_bytes([p[b + 4], p[b + 5]]) }, next))
        }
        F_ACK => {
            let next = fixed(29)?;
            let f = Frame::Ack { stream: be32(b), received: be64(b + 4), credit: be64(b + 12), flags: p[b + 20], got: be64(b + 21) };
            Some((f, next))
        }
        F_FIN => {
            let next = fixed(12)?;
            Some((Frame::Fin { stream: be32(b), off: be64(b + 4) }, next))
        }
        F_RST => {
            let next = fixed(4)?;
            Some((Frame::Rst { stream: be32(b) }, next))
        }
        F_OBSERVE => {
            let next = fixed(13)?;
            Some((Frame::Observe { kind: p[b], stream: be32(b + 1), token: be64(b + 5) }, next))
        }
        F_FRAG => {
            if rest < 6 {
                return None;
            }
            let n = u16::from_be_bytes([p[b + 4], p[b + 5]]) as usize;
            let next = fixed(6 + n)?;
            let id = u16::from_be_bytes([p[b], p[b + 1]]);
            Some((Frame::Frag { id, index: p[b + 2], count: p[b + 3], off: b + 6, len: n }, next))
        }
        F_ADOPT => {
            let next = fixed(ADOPT_LEN - 1)?;
            let session = p[b + 1..b + 17].try_into().ok()?;
            Some((Frame::Adopt { kind: p[b], session, old: be32(b + 17), new: be32(b + 21), up: be64(b + 25), down: be64(b + 33) }, next))
        }
        F_ADOPTED => {
            let next = fixed(ADOPTED_LEN - 1)?;
            Some((Frame::Adopted { kind: p[b], stream: be32(b + 1), ok: p[b + 5] != 0 }, next))
        }
        F_DATA => {
            if rest < 14 {
                return None;
            }
            let n = u16::from_be_bytes([p[b + 12], p[b + 13]]) as usize;
            let next = fixed(14 + n)?;
            Some((Frame::Data { stream: be32(b), off: be64(b + 4), at: b + 14, len: n }, next))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_in_sequence() {
        let mut b = [0u8; 200];
        let mut n = put_dgram(&mut b, 7, 1, 443, b"abc");
        n += put_ping(&mut b[n..], F_PING, 42);
        n += put_dgram(&mut b[n..], 8, 0x0102_0304, 0, b"");
        let mut at = 0;
        let mut seen = vec![];
        while at < n {
            let (f, next) = next_frame(&b[..n], at).unwrap();
            seen.push(match f {
                Frame::Dgram { stream, seq, port, off, len } => format!("d{stream}/{seq}/{port}/{}", String::from_utf8_lossy(&b[off..off + len])),
                Frame::Ping(t) => format!("p{t}"),
                _ => "?".into(),
            });
            at = next;
        }
        assert_eq!(seen, ["d7/1/443/abc", "p42", "d8/16909060/0/"]);
        assert!(next_frame(&b[..5], 0).is_none());
    }

    /// A hello read back as trunk wire.go's readFrame reads it, and the
    /// exit's answer in kind as appendHelloFor writes it.
    #[test]
    fn hellos_read_and_answered_in_kind() {
        let mut b = [0u8; 64];
        let n = hello_t2(&mut b, &[7; 16], 2);
        let (f, next) = next_frame(&b[..n], 0).unwrap();
        assert!(matches!(f, Frame::Hello) && next == n);
        let h = read_hello(&b[..n], 0).unwrap();
        assert_eq!((h.session, h.epoch, h.t2), ([7; 16], [CAP_OBSERVE | CAP_ADOPT, 0, 0, 0, 0, 0, 0, 0], Some((2, KIND_PACKET))), "the entry reads observe frames and may adopt");
        let m = put_hello(&mut b, &h.session, &[9; 8], h.t2);
        let go = [&[1u8][..], b"HKT2", &[7; 16], &[9; 8], &[2, 2]].concat();
        assert_eq!(&b[..m], &go[..]);
        let n = hello_t1(&mut b, &[5; 16]);
        let h = read_hello(&b[..n], 0).unwrap();
        assert!(h.t2.is_none());
        assert_eq!(put_hello(&mut b, &h.session, &[1; 8], None), 29);
        assert_eq!(&b[1..5], b"HKT1");
        b[1] = b'X';
        assert!(read_hello(&b[..29], 0).is_none(), "a hello of no trunk");
    }

    /// The bytes of trunk wire.go's appendOpen, appendData, appendAck,
    /// appendFin, appendRst and a t1 hello, read back as frames.
    #[test]
    fn stream_frames_as_go_writes_them() {
        let mut b = [0u8; 256];
        let mut n = hello_t1(&mut b, &[0xab; 16]);
        assert_eq!(&b[..5], b"\x01HKT1");
        n += put_open(&mut b[n..], 5, 9000);
        let h = n;
        n += put_data_head(&mut b[n..], 5, 1 << 40, 3);
        b[n..n + 3].copy_from_slice(b"xyz");
        n += 3;
        n += put_ack(&mut b[n..], 5, 7, 2 << 20, ACK_FIN, NO_GOT);
        n += put_fin(&mut b[n..], 5, 7);
        n += put_rst(&mut b[n..], 5);
        let go_data = [3u8, 0, 0, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'x', b'y', b'z'];
        assert_eq!(&b[h..h + go_data.len()], &go_data);
        let mut at = 0;
        let mut seen = vec![];
        while at < n {
            let (f, next) = next_frame(&b[..n], at).unwrap();
            seen.push(match f {
                Frame::Hello => "hello".into(),
                Frame::Open { stream, port } => format!("open {stream} {port}"),
                Frame::Data { stream, off, at, len } => format!("data {stream} {off} {}", String::from_utf8_lossy(&b[at..at + len])),
                Frame::Ack { stream, received, credit, flags, got } => format!("ack {stream} {received} {credit} {flags} {}", got == NO_GOT),
                Frame::Fin { stream, off } => format!("fin {stream} {off}"),
                Frame::Rst { stream } => format!("rst {stream}"),
                _ => "?".into(),
            });
            at = next;
        }
        assert_eq!(seen, ["hello", "open 5 9000", "data 5 1099511627776 xyz", "ack 5 7 2097152 1 true", "fin 5 7", "rst 5"]);
        assert!(next_frame(&b[h..h + DATA_HEAD + 2], 0).is_none(), "a chunk torn short is no frame");
    }

    /// adopt and adopted byte for byte as spec/trunk.md lays them out. The Go
    /// exit does not adopt (it never says so): the Rust exit replaced it on
    /// the cascade (R6.4), so the bytes have no Go side.
    #[test]
    fn adopt_golden() {
        let mut b = [0u8; 64];
        let n = put_adopt(&mut b, OBS_STREAM, &[0xaa; 16], 7, 0x0102_0304, 1 << 40, 5);
        let hex: String = b[..n].iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(hex, "0d01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000070102030400000100000000000000000000000005");
        let Some((Frame::Adopt { kind, session, old, new, up, down }, next)) = next_frame(&b[..n], 0) else { panic!("not an adopt") };
        assert_eq!((kind, session, old, new, up, down, next), (OBS_STREAM, [0xaa; 16], 7, 0x0102_0304, 1 << 40, 5, n));
        assert!(next_frame(&b[..n - 1], 0).is_none(), "an adopt torn");
        let n = put_adopted(&mut b, OBS_FLOW, 9, true);
        assert_eq!(&b[..n], &[F_ADOPTED, OBS_FLOW, 0, 0, 0, 9, 1]);
        let Some((Frame::Adopted { kind, stream, ok }, _)) = next_frame(&b[..n], 0) else { panic!("not an adopted") };
        assert_eq!((kind, stream, ok), (OBS_FLOW, 9, true));
    }
}
