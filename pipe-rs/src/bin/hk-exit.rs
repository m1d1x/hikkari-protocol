//! hk-exit: the cascade exit's UDP half, prototype (pipe-rs/README.md).
//!
//! The exit end of the bare UDP wire (trunk/udpwire, trunk.Exit): one socket,
//! a peer per entry member address. It opens each sealed datagram, answers a
//! hello with the session's epoch, pongs the entry's pings, and for every
//! dgram frame either echoes it (port 0, trunk.EchoPort: the trunk's own call
//! and the bench's users, sent straight back) or relays it to a loopback
//! socket of the flow's own and carries the relay's answers back.
//!
//! Unlike the Go exit (writePackets: every frame in a datagram of its own) it
//! glues the frames bound for one peer into one sealed datagram for a tick
//! (1 ms) or about 1200 bytes, exactly as the entry glues the way up. That is
//! R1: the way down becomes as batched as the way up, so the entry pays one
//! recvmmsg and one AES open for several datagrams instead of one each, and
//! its u16 cost per packet drops toward the u64 cost (research
//! 2026-11-12-rust-pipe-prototype.md, finding 3). Copies are dropped by the
//! sender's sequence (spec/trunk.md), as the Go exit's replay does.
//!
//! One thread, no runtime, nothing allocated per packet. What the brain
//! decides (sessions, drains, generations, observation) is left out, as in
//! hk-pipe; this is the pipe half the entry's exit would run.

use std::collections::HashMap;
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use hikkari_pipe::sys::{self, now_ns, Epoll, RecvBatch, SendBatch, BATCH};
use hikkari_pipe::wire::{self, Frame, Replay, Seal, DGRAM_HEAD, OVERHEAD};

/// A sealed datagram's slot, and the cap on a relay's answer.
const SLOT: usize = 2048;
const MAX_RELAY: usize = 1500;

struct Opts {
    listen: SocketAddrV4,
    key: String,
    glue_ns: u64,
    glue_max: usize,
    tick_ns: u64,
}

fn opts() -> Opts {
    let mut o = Opts {
        listen: "127.0.0.1:20447".parse().unwrap(),
        key: "bench-trunk-key-0123456789abcdef".into(),
        glue_ns: 1_000_000,
        glue_max: 1200,
        tick_ns: 1_000_000,
    };
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < a.len() {
        let v = a.get(i + 1).cloned().unwrap_or_default();
        match a[i].as_str() {
            "--listen" => o.listen = v.parse().expect("--listen ip:port"),
            "--key" => o.key = v,
            "--glue-us" => o.glue_ns = v.parse::<u64>().expect("--glue-us") * 1000,
            "--glue-max" => o.glue_max = v.parse().expect("--glue-max"),
            "--tick-us" => o.tick_ns = v.parse::<u64>().expect("--tick-us") * 1000,
            x => panic!("unknown flag {x}"),
        }
        i += 2;
    }
    o
}

/// One entry member address: the peer whose sealed datagrams this exit opens
/// and whose answers it glues and seals back.
struct Peer {
    addr: libc::sockaddr_in,
    up: bool,
    session: [u8; 16],
    epoch: [u8; 8],
    sealer: Seal,
    /// Sealed datagrams waiting for sendmmsg: BATCH slots.
    out: Vec<u8>,
    out_n: usize,
    send: SendBatch,
    /// The frames being glued, at glue[12..12 + glue_n]; glue_since is when
    /// the first of them came (0: empty).
    glue: [u8; SLOT],
    glue_n: usize,
    glue_since: u64,
}

impl Peer {
    fn new(addr: libc::sockaddr_in, sealer: Seal) -> Peer {
        Peer {
            addr,
            up: false,
            session: [0; 16],
            epoch: [0; 8],
            sealer,
            out: vec![0; SLOT * BATCH],
            out_n: 0,
            send: SendBatch::new(),
            glue: [0; SLOT],
            glue_n: 0,
            glue_since: 0,
        }
    }

    /// Seals the glued frames into the next out slot, to this peer's address;
    /// sends the batch when it is full.
    fn seal_glue(&mut self, fd: i32, st: &mut Stats) {
        if self.glue_n == 0 {
            return;
        }
        if self.out_n == BATCH {
            self.flush_out(fd);
        }
        let slot = &mut self.out[self.out_n * SLOT..(self.out_n + 1) * SLOT];
        slot[12..12 + self.glue_n].copy_from_slice(&self.glue[12..12 + self.glue_n]);
        let n = self.sealer.seal(slot, self.glue_n);
        let ptr = slot.as_ptr();
        self.send.push(ptr, n, Some(&self.addr));
        self.out_n += 1;
        self.glue_n = 0;
        self.glue_since = 0;
        st.w_out += 1;
    }

    fn flush_out(&mut self, fd: i32) {
        if self.out_n > 0 {
            self.send.flush(fd);
            self.out_n = 0;
        }
    }

    /// Puts one frame (written by `put` into the glue) in, sealing first when
    /// it would not fit; a frame alone over the limit goes alone.
    #[inline]
    fn glue_frame(&mut self, need: usize, max: usize, now: u64, fd: i32, st: &mut Stats, put: impl FnOnce(&mut [u8]) -> usize) {
        if self.glue_n > 0 && OVERHEAD + self.glue_n + need > max {
            self.seal_glue(fd, st);
        }
        let n = put(&mut self.glue[12 + self.glue_n..]);
        self.glue_n += n;
        if self.glue_since == 0 {
            self.glue_since = now;
        }
    }
}

/// One flow (a client UDP association, or the trunk's own call): its stream,
/// the copies' replay window, the exit's own downward sequence, and the peer
/// its answers follow. A relayed flow (port != 0) also holds a socket to the
/// loopback relay.
#[derive(Default)]
struct Flow {
    active: bool,
    seq: u32,
    peer: usize,
    port: u16,
    replay: Replay,
    sock: Option<UdpSocket>,
    fd: i32,
}

#[derive(Default)]
struct Stats {
    w_in: u64,     // sealed datagrams opened from entry members
    w_out: u64,    // sealed datagrams sealed back down
    echoed: u64,   // echo dgrams sent down
    relay_up: u64, // dgrams written to a relay
    relay_dn: u64, // dgrams carried back from a relay
    copied: u64,   // copies dropped by sequence
    bad: u64,      // datagrams that did not open or framed wrong
    flows: u64,
}

/// Grows the flow table to hold `stream` (ids are dense from 1) and returns
/// its index, or None for the invalid stream 0.
fn flow_at(flows: &mut Vec<Flow>, stream: u32) -> Option<usize> {
    if stream == 0 {
        return None;
    }
    let idx = stream as usize - 1;
    if idx >= flows.len() {
        flows.resize_with(idx + 1, Flow::default);
    }
    Some(idx)
}

fn main() {
    let o = opts();
    let listen = UdpSocket::bind(o.listen).expect("bind wire");
    sys::tune(&listen, false).expect("wire socket");
    let lfd = listen.as_raw_fd();
    let aead = Seal::aead(&o.key);
    // One opener for every incoming datagram (open uses the shared key, not a
    // nonce stream); each peer seals its own way out.
    let opener = Seal::with_aead(aead.clone(), [0; 12]);
    let mut epoll = Epoll::new().expect("epoll");
    let fds = [lfd, epoll.fd];

    let mut peers: Vec<Peer> = Vec::with_capacity(8);
    let mut by_addr: HashMap<u64, usize> = HashMap::with_capacity(8);
    let mut sessions: HashMap<[u8; 16], [u8; 8]> = HashMap::new();
    let mut flows: Vec<Flow> = Vec::with_capacity(4096);

    let mut wrecv = RecvBatch::new(SLOT);
    let mut relay_buf = [0u8; MAX_RELAY];
    let mut st = Stats::default();
    let mut stats_at = now_ns();
    let mut busy = false;
    let mut tick_at = 0u64;
    eprintln!(
        "hk-exit: wire {}, glue {} us / {} B, tick {} us",
        o.listen,
        o.glue_ns / 1000,
        o.glue_max,
        o.tick_ns / 1000
    );

    loop {
        let now = now_ns();
        let mut next = now + 100_000_000;
        for p in &peers {
            if p.glue_since != 0 {
                next = next.min(p.glue_since + o.glue_ns);
            }
        }
        // Under traffic the loop runs on a tick (hk-pipe): sleep to the next
        // one, then take everything every socket has; idle, wait in ppoll for
        // the first packet.
        let ready = if o.tick_ns > 0 && busy {
            tick_at = if tick_at + o.tick_ns > now { tick_at + o.tick_ns } else { now + o.tick_ns };
            sys::sleep_until(tick_at.min(next.max(now)));
            u64::MAX
        } else {
            let r = sys::wait(&fds, next.saturating_sub(now));
            tick_at = now_ns();
            r
        };
        let moved0 = st.w_in + st.w_out;

        // Entry members → echo or relay.
        if ready & 1 != 0 {
            loop {
                let n = wrecv.recv(lfd);
                for i in 0..n {
                    let from = wrecv.addr[i];
                    let base = i * wrecv.slot;
                    let dlen = wrecv.len[i];
                    let Some(pn) = opener.open(&mut wrecv.buf[base..base + dlen]) else {
                        st.bad += 1;
                        continue;
                    };
                    st.w_in += 1;
                    let pi = peer_of(&mut peers, &mut by_addr, &aead, from);
                    let pstart = base + 12;
                    let mut at = 0;
                    while let Some((fr, nx)) = wire::next_frame(&wrecv.buf[pstart..pstart + pn], at) {
                        match fr {
                            Frame::Hello { at: hat, t2 } => {
                                let p = &wrecv.buf[pstart..];
                                let mut sid = [0u8; 16];
                                sid.copy_from_slice(&p[hat..hat + 16]);
                                let epoch = *sessions.entry(sid).or_insert_with(|| {
                                    let mut e = [0u8; 8];
                                    sys::urandom(&mut e);
                                    e
                                });
                                let t2opt = if t2 { Some((p[hat + 24], p[hat + 25])) } else { None };
                                let peer = &mut peers[pi];
                                peer.session = sid;
                                peer.epoch = epoch;
                                peer.up = true;
                                let mut h = [0u8; 64];
                                let hn = wire::put_hello(&mut h[12..], &sid, &epoch, t2opt);
                                let hn = peer.sealer.seal(&mut h, hn);
                                let addr = peer.addr;
                                sys::send_to(lfd, &h[..hn], &addr);
                            }
                            Frame::Dgram { stream, seq, port, off, len } => {
                                let Some(idx) = flow_at(&mut flows, stream) else {
                                    at = nx;
                                    continue;
                                };
                                if !flows[idx].active {
                                    flows[idx].active = true;
                                    flows[idx].port = port;
                                    st.flows += 1;
                                }
                                flows[idx].peer = pi;
                                if flows[idx].replay.seen(seq) {
                                    st.copied += 1;
                                    at = nx;
                                    continue;
                                }
                                if port == wire::ECHO_PORT {
                                    flows[idx].seq = flows[idx].seq.wrapping_add(1);
                                    let dseq = flows[idx].seq;
                                    // The payload is still in wrecv (opened in place);
                                    // glue_frame copies it into the peer's glue.
                                    let pr = pstart;
                                    let (lo, hi) = (pr + off, pr + off + len);
                                    let peer = &mut peers[pi];
                                    glue_dgram(peer, &wrecv.buf, lo, hi, stream, dseq, wire::ECHO_PORT, o.glue_max, now, lfd, &mut st);
                                    st.echoed += 1;
                                } else {
                                    relay_up(&mut flows[idx], &mut epoll, &wrecv.buf[pstart + off..pstart + off + len], stream, &mut st);
                                }
                            }
                            Frame::Ping(t) => {
                                let peer = &mut peers[pi];
                                peer.glue_frame(9, o.glue_max, now, lfd, &mut st, |b| wire::put_ping(b, wire::F_PONG, t));
                            }
                            Frame::Pong(_) | Frame::Drain | Frame::Other => {}
                        }
                        at = nx;
                    }
                }
                if n < BATCH {
                    break;
                }
            }
        }

        // Relays → entry members. Each readable flow socket's answers glue
        // down to the peer the flow last came on.
        let ready_streams: Vec<u32> = epoll.ready().map(|d| d as u32).collect();
        for stream in ready_streams {
            let Some(idx) = flow_at(&mut flows, stream) else { continue };
            loop {
                let Some(sock) = flows[idx].sock.as_ref() else { break };
                let Ok(rn) = sock.recv(&mut relay_buf) else { break };
                let now = now_ns();
                flows[idx].seq = flows[idx].seq.wrapping_add(1);
                let (dseq, port, pi) = (flows[idx].seq, flows[idx].port, flows[idx].peer);
                let peer = &mut peers[pi];
                glue_dgram(peer, &relay_buf, 0, rn, stream, dseq, port, o.glue_max, now, lfd, &mut st);
                st.relay_dn += 1;
            }
        }

        // Seal what waited its window (on a tick: the tick is the window),
        // send every peer's batch.
        let now = now_ns();
        for p in peers.iter_mut() {
            if p.glue_since != 0 && (o.tick_ns > 0 || o.glue_ns == 0 || now - p.glue_since >= o.glue_ns) {
                p.seal_glue(lfd, &mut st);
            }
            p.flush_out(lfd);
        }

        busy = st.w_in + st.w_out != moved0;

        if now - stats_at >= 10_000_000_000 {
            stats_at = now;
            let calls: u64 = peers.iter().map(|p| p.send.calls).sum();
            eprintln!(
                "hk-exit: peers={} flows={} w_in={} w_out={} echoed={} relay={}/{} frames/dgram={:.2} sendmmsg={} copied={} bad={} dropped={}",
                peers.len(),
                st.flows,
                st.w_in,
                st.w_out,
                st.echoed,
                st.relay_up,
                st.relay_dn,
                (st.echoed + st.relay_dn) as f64 / st.w_out.max(1) as f64,
                calls,
                st.copied,
                st.bad,
                peers.iter().map(|p| p.send.dropped).sum::<u64>()
            );
        }
    }
}

/// The peer of an entry address, made on its first datagram with a nonce
/// stream of its own.
fn peer_of(peers: &mut Vec<Peer>, by_addr: &mut HashMap<u64, usize>, aead: &aes_gcm::Aes256Gcm, from: libc::sockaddr_in) -> usize {
    let key = sys::addr_key(&from);
    if let Some(&pi) = by_addr.get(&key) {
        return pi;
    }
    let mut seed = [0u8; 12];
    sys::urandom(&mut seed);
    peers.push(Peer::new(from, Seal::with_aead(aead.clone(), seed)));
    let pi = peers.len() - 1;
    by_addr.insert(key, pi);
    pi
}

/// Glues one dgram frame of `src[lo..hi]` to a peer.
#[inline]
fn glue_dgram(peer: &mut Peer, src: &[u8], lo: usize, hi: usize, stream: u32, seq: u32, port: u16, max: usize, now: u64, fd: i32, st: &mut Stats) {
    let payload = &src[lo..hi];
    peer.glue_frame(DGRAM_HEAD + payload.len(), max, now, fd, st, |b| wire::put_dgram(b, stream, seq, port, payload));
}

/// Opens a flow's socket to the loopback relay on its first datagram and
/// writes the datagram to it.
fn relay_up(f: &mut Flow, epoll: &mut Epoll, payload: &[u8], stream: u32, st: &mut Stats) {
    if f.sock.is_none() {
        let Ok(s) = sys::udp_to_loopback(f.port) else { return };
        f.fd = s.as_raw_fd();
        let _ = epoll.add(f.fd, stream as u64);
        f.sock = Some(s);
    }
    if let Some(s) = f.sock.as_ref() {
        let _ = s.send(payload);
        st.relay_up += 1;
    }
}
