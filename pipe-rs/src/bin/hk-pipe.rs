//! hk-pipe: the cascade entry's pipe, prototype (pipe-rs/README.md).
//!
//! Blind as the Go entry (spec/trunk.md, hikkari-control trunkentry): a
//! client's datagram channel is QUIC end to end with the exit's relay, so the
//! entry reads client UDP datagrams as opaque bytes, gives each client address
//! a flow, and carries every datagram as a dgram frame over the bare UDP wire
//! (trunk/udpwire) to the exit. Unlike the Go entry it glues the frames of all
//! clients for one member into one sealed datagram for up to `--glue-us`
//! (default 1 ms) or about 1200 bytes, reads and writes with recvmmsg and
//! sendmmsg, and allocates nothing per packet. One thread, no runtime.
//!
//! What the brain (selector, synthetic calls, knobs from the hub) would
//! decide is fixed here by flags: one wire, its members, the glue window.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use hikkari_pipe::sys::{self, now_ns, RecvBatch, SendBatch, BATCH};
use hikkari_pipe::wire::{self, Frame, Seal, DGRAM_HEAD, OVERHEAD};

/// A wire datagram's slot: a sealed datagram of at most this.
const SLOT: usize = 2048;
const MAX_CLIENT: usize = 1500;

struct Opts {
    listen: SocketAddrV4,
    exit: SocketAddrV4,
    key: String,
    members: usize,
    glue_ns: u64,
    glue_max: usize,
    to: u16,
    gro: bool,
    wire: u8,
    tick_ns: u64,
}

fn opts() -> Opts {
    let mut o = Opts {
        listen: "127.0.0.1:8443".parse().unwrap(),
        exit: "127.0.0.1:20447".parse().unwrap(),
        key: "bench-trunk-key-0123456789abcdef".into(),
        members: 2,
        glue_ns: 1_000_000,
        glue_max: 1200,
        to: 0,
        gro: true,
        wire: 2,
        tick_ns: 1_000_000,
    };
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < a.len() {
        let v = a.get(i + 1).cloned().unwrap_or_default();
        match a[i].as_str() {
            "--listen" => o.listen = v.parse().expect("--listen ip:port"),
            "--wire" => o.exit = v.parse().expect("--wire ip:port"),
            "--key" => o.key = v,
            "--members" => o.members = v.parse().expect("--members"),
            "--glue-us" => o.glue_ns = v.parse::<u64>().expect("--glue-us") * 1000,
            "--glue-max" => o.glue_max = v.parse().expect("--glue-max"),
            "--to" => o.to = v.parse().expect("--to"),
            "--gro" => o.gro = v == "1",
            "--wire-id" => o.wire = v.parse().expect("--wire-id"),
            "--tick-us" => o.tick_ns = v.parse::<u64>().expect("--tick-us") * 1000,
            x => panic!("unknown flag {x}"),
        }
        i += 2;
    }
    o
}

#[derive(Default)]
struct Fx(u64);
impl Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = (v ^ (v >> 29)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

struct Flow {
    addr: libc::sockaddr_in,
    seq: u32,
}

/// One member: a socket of its own to the exit, and its glue.
struct Member {
    sock: UdpSocket,
    fd: i32,
    up: bool,
    hello_at: u64,
    ping_at: u64,
    token: u64,
    /// Sealed datagrams waiting for sendmmsg: BATCH slots.
    out: Vec<u8>,
    out_n: usize,
    send: SendBatch,
    /// The frames being glued, at glue[12..12 + glue_n]; glue_since is when
    /// the first of them came (0: empty).
    glue: [u8; SLOT],
    glue_n: usize,
    glue_since: u64,
    seal: Seal,
}

#[derive(Default)]
struct Stats {
    c_in: u64,
    c_out: u64,
    w_out: u64,
    w_in: u64,
    frames_up: u64,
    bad: u64,
    gro_segs: u64,
}

impl Member {
    /// Seals the glued frames into the next out slot; sends the batch when
    /// it is full.
    fn seal_glue(&mut self, st: &mut Stats) {
        if self.glue_n == 0 {
            return;
        }
        if self.out_n == BATCH {
            self.flush_out();
        }
        let slot = &mut self.out[self.out_n * SLOT..(self.out_n + 1) * SLOT];
        slot[12..12 + self.glue_n].copy_from_slice(&self.glue[12..12 + self.glue_n]);
        let n = self.seal.seal(slot, self.glue_n);
        let ptr = slot.as_ptr();
        self.send.push(ptr, n, None);
        self.out_n += 1;
        self.glue_n = 0;
        self.glue_since = 0;
        st.w_out += 1;
    }

    fn flush_out(&mut self) {
        if self.out_n > 0 {
            self.send.flush(self.fd);
            self.out_n = 0;
        }
    }

    /// Puts one frame (written by `put` into the glue) in, sealing first
    /// when it would not fit; a frame alone over the limit goes alone.
    #[inline]
    fn glue_frame(&mut self, need: usize, max: usize, now: u64, st: &mut Stats, put: impl FnOnce(&mut [u8]) -> usize) {
        if self.glue_n > 0 && OVERHEAD + self.glue_n + need > max {
            self.seal_glue(st);
        }
        let n = put(&mut self.glue[12 + self.glue_n..]);
        self.glue_n += n;
        if self.glue_since == 0 {
            self.glue_since = now;
        }
    }
}

fn main() {
    let o = opts();
    let client = UdpSocket::bind(o.listen).expect("bind clients");
    sys::tune(&client, o.gro).expect("client socket");
    let cfd = client.as_raw_fd();

    let mut session = [0u8; 16];
    sys::urandom(&mut session);
    let mut members: Vec<Member> = (0..o.members)
        .map(|_| {
            let s = UdpSocket::bind("0.0.0.0:0").expect("bind member");
            s.connect(o.exit).expect("connect exit");
            sys::tune(&s, false).expect("member socket");
            let mut seed = [0u8; 12];
            sys::urandom(&mut seed);
            let fd = s.as_raw_fd();
            Member {
                sock: s,
                fd,
                up: false,
                hello_at: 0,
                ping_at: 0,
                token: 0,
                out: vec![0; SLOT * BATCH],
                out_n: 0,
                send: SendBatch::new(),
                glue: [0; SLOT],
                glue_n: 0,
                glue_since: 0,
                seal: Seal::new(&o.key, seed),
            }
        })
        .collect();
    let mut fds = vec![cfd];
    fds.extend(members.iter().map(|m| m.fd));

    let mut flows: Vec<Flow> = Vec::with_capacity(4096);
    let mut by_addr: HashMap<u64, u32, BuildHasherDefault<Fx>> = HashMap::with_capacity_and_hasher(4096, Default::default());
    // With GRO one read may hold many datagrams of one client.
    let mut crecv = RecvBatch::new(if o.gro { 65536 } else { MAX_CLIENT });
    let mut wrecv = RecvBatch::new(SLOT);
    let mut down = SendBatch::new();
    let mut st = Stats::default();
    let mut tok = 0u64;
    let mut stats_at = now_ns();
    let mut busy = false;
    let mut tick_at = 0u64;
    eprintln!(
        "hk-pipe: clients {} → wire {} x{}, glue {} us / {} B, gro {}, tick {} us",
        o.listen,
        o.exit,
        o.members,
        o.glue_ns / 1000,
        o.glue_max,
        o.gro,
        o.tick_ns / 1000
    );

    loop {
        let now = now_ns();
        // The member's own talk: hello until answered, a ping every 100 ms
        // (the exit judges a packet member by its pings).
        let mut next = now + 100_000_000;
        for m in members.iter_mut() {
            if !m.up && now >= m.hello_at {
                let mut h = [0u8; 64];
                let n = wire::hello_t2(&mut h[12..], &session, o.wire);
                let n = m.seal.seal(&mut h, n);
                let _ = m.sock.send(&h[..n]);
                m.hello_at = now + 250_000_000;
            }
            if m.up && now >= m.ping_at {
                tok += 1;
                m.token = tok;
                m.glue_frame(9, o.glue_max, now, &mut st, |b| wire::put_ping(b, wire::F_PING, tok));
                m.seal_glue(&mut st);
                m.flush_out();
                m.ping_at = now + 100_000_000;
            }
            next = next.min(if m.up { m.ping_at } else { m.hello_at });
            if m.glue_since != 0 {
                next = next.min(m.glue_since + o.glue_ns);
            }
        }
        // Under traffic the loop runs on a tick: it sleeps to the next one and
        // then takes everything every socket has, so a wakeup is paid once
        // per tick and not once per packet. A tick that moved nothing goes
        // back to waiting for the first packet (an idle entry sleeps).
        let ready = if o.tick_ns > 0 && busy {
            tick_at = if tick_at + o.tick_ns > now { tick_at + o.tick_ns } else { now + o.tick_ns };
            sys::sleep_until(tick_at.min(next.max(now)));
            u64::MAX
        } else {
            let r = sys::wait(&fds, next.saturating_sub(now));
            tick_at = now_ns();
            r
        };
        let moved0 = st.c_in + st.c_out;
        let now = now_ns();

        // Clients → wire.
        if ready & 1 != 0 {
            loop {
                let n = crecv.recv(cfd);
                for i in 0..n {
                    let key = sys::addr_key(&crecv.addr[i]);
                    let id = match by_addr.get(&key) {
                        Some(&id) => id,
                        None => {
                            flows.push(Flow { addr: crecv.addr[i], seq: 0 });
                            let id = flows.len() as u32;
                            by_addr.insert(key, id);
                            id
                        }
                    };
                    let seg = crecv.seg[i];
                    let len = crecv.len[i];
                    let step = if seg == 0 { len } else { seg };
                    if seg != 0 {
                        st.gro_segs += 1;
                    }
                    let f = &mut flows[id as usize - 1];
                    // A flow keeps to one member: its datagrams stay in order.
                    let m = &mut members[(id as usize) % o.members];
                    let base = i * crecv.slot;
                    let mut at = 0;
                    while at < len {
                        let p = &crecv.buf[base + at..base + (at + step).min(len)];
                        f.seq = f.seq.wrapping_add(1);
                        let seq = f.seq;
                        m.glue_frame(DGRAM_HEAD + p.len(), o.glue_max, now, &mut st, |b| {
                            wire::put_dgram(b, id, seq, o.to, p)
                        });
                        st.c_in += 1;
                        st.frames_up += 1;
                        at += step;
                    }
                }
                if n < BATCH {
                    break;
                }
            }
        }
        // Seal what waited its window (on a tick: the tick is the window),
        // send every member's batch.
        let now = now_ns();
        for m in members.iter_mut() {
            if m.glue_since != 0 && (o.tick_ns > 0 || o.glue_ns == 0 || now - m.glue_since >= o.glue_ns) {
                m.seal_glue(&mut st);
            }
            m.flush_out();
        }

        // Wire → clients.
        for (mi, m) in members.iter_mut().enumerate() {
            if ready & (1 << (mi + 1)) == 0 {
                continue;
            }
            loop {
                let n = wrecv.recv(m.fd);
                for i in 0..n {
                    st.w_in += 1;
                    let slot = wrecv.slot;
                    let len = wrecv.len[i];
                    let d = &mut wrecv.buf[i * slot..i * slot + len];
                    let Some(pn) = m.seal.open(d) else {
                        st.bad += 1;
                        continue;
                    };
                    let p = &d[12..12 + pn];
                    let mut at = 0;
                    while let Some((fr, nx)) = wire::next_frame(p, at) {
                        match fr {
                            Frame::Dgram { stream, off, len, .. } => {
                                if let Some(f) = flows.get((stream as usize).wrapping_sub(1)) {
                                    if down.full() {
                                        down.flush(cfd);
                                        // wrecv's buffers are still ours: nothing is read before the next recv.
                                    }
                                    down.push(p[off..].as_ptr(), len, Some(&f.addr));
                                    st.c_out += 1;
                                }
                            }
                            Frame::Hello { .. } => m.up = true,
                            Frame::Ping(t) => {
                                let now = now_ns();
                                m.glue_frame(9, o.glue_max, now, &mut st, |b| wire::put_ping(b, wire::F_PONG, t));
                            }
                            Frame::Pong(_) | Frame::Drain | Frame::Other => {}
                        }
                        at = nx;
                    }
                }
                // The answers point into wrecv: send them before reading again.
                down.flush(cfd);
                if n < BATCH {
                    break;
                }
            }
            if m.glue_n > 0 {
                m.seal_glue(&mut st); // pongs go at once
                m.flush_out();
            }
        }

        busy = st.c_in + st.c_out != moved0;

        if now - stats_at >= 10_000_000_000 {
            stats_at = now;
            let calls: u64 = members.iter().map(|m| m.send.calls).sum();
            eprintln!(
                "hk-pipe: flows={} c_in={} c_out={} w_out={} w_in={} frames/dgram={:.2} sendmmsg_up={} sendmmsg_down={} gro_segs={} bad={} dropped={}",
                flows.len(),
                st.c_in,
                st.c_out,
                st.w_out,
                st.w_in,
                st.frames_up as f64 / st.w_out.max(1) as f64,
                calls,
                down.calls,
                st.gro_segs,
                st.bad,
                down.dropped + members.iter().map(|m| m.send.dropped).sum::<u64>()
            );
        }
    }
}
