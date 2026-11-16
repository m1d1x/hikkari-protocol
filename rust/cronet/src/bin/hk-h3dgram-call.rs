//! hk-h3dgram-call: one member of the trunk's Chromium QUIC wire
//! (spec/trunk.md, `h3dgram`) opened through Chromium's own QUIC
//! (hikkari_cronet::Tunnel, CONNECT-UDP) to the exit's pipe, and the trunk's
//! call on it: a t2 hello until the exit answers, pongs to the exit's pings,
//! then a datagram to port 0 every `--every-us` that the exit sends straight
//! back. The check of the exit's QUIC wire (hot path plan, R6.2: the echo
//! 30 s without a loss on loopback).
//!
//! Prints one line: sent, back, lost, rtt p50/p99/max in microseconds, the
//! longest gap between answers, the exit's pings answered, and exits 1 if a
//! datagram was lost. `--usage destination|proxy` is how Chromium uses the
//! member's QUIC session (hikkari_cronet::Usage; destination by default).

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = call::run() {
        eprintln!("hk-h3dgram-call: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hk-h3dgram-call: Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod call {
    use std::net::SocketAddrV4;
    use std::time::Duration;

    use hikkari_cronet::{Proxy, State, Tunnel, TunnelEngine, Usage};
    use hikkari_sys as sys;
    use hikkari_trunk::flow::ECHO_PORT;
    use hikkari_trunk::frame::{self, Frame, F_PONG};
    use hikkari_trunk::h3dgram;

    struct Args {
        cronet: Option<String>,
        sni: String,
        exit: SocketAddrV4,
        roots: Option<String>,
        key: String,
        wire: u8,
        count: u64,
        every_us: u64,
        size: usize,
        usage: Usage,
    }

    fn args() -> Result<Args, String> {
        let mut a = Args {
            cronet: None,
            sni: "hk.example".into(),
            exit: "127.0.0.1:4433".parse().expect("a literal address"),
            roots: None,
            key: "bench-trunk-key-0123456789abcdef".into(),
            wire: 6,
            count: 1500,
            every_us: 20_000,
            size: 160,
            usage: Usage::Destination,
        };
        let mut it = std::env::args().skip(1);
        while let Some(k) = it.next() {
            let mut v = || it.next().ok_or(format!("{k} needs a value"));
            match k.as_str() {
                "--cronet" => a.cronet = Some(v()?),
                "--sni" => a.sni = v()?,
                "--exit" => a.exit = v()?.parse().map_err(|e| format!("--exit: {e}"))?,
                "--roots" => {
                    let p = v()?;
                    a.roots = Some(std::fs::read_to_string(&p).map_err(|e| format!("--roots {p}: {e}"))?);
                }
                "--key" => a.key = v()?,
                "--wire-id" => a.wire = v()?.parse().map_err(|e| format!("--wire-id: {e}"))?,
                "--count" => a.count = v()?.parse().map_err(|e| format!("--count: {e}"))?,
                "--every-us" => a.every_us = v()?.parse().map_err(|e| format!("--every-us: {e}"))?,
                "--size" => a.size = v()?.parse().map_err(|e| format!("--size: {e}"))?,
                "--usage" => a.usage = Usage::parse(&v()?)?,
                _ => return Err(format!("unknown flag {k}")),
            }
        }
        if a.size < 16 || a.size > 1100 {
            return Err("--size is 16..1100 (seq and send time, then filler)".into());
        }
        Ok(a)
    }

    /// What the call heard.
    #[derive(Default)]
    struct Heard {
        rtts: Vec<u64>,
        seen: Vec<bool>,
        bad: u64,
        pings: u64,
        answered_at: u64,
        gap_max: u64,
        hello: bool,
    }

    pub fn run() -> Result<(), String> {
        let a = args()?;
        hikkari_cronet::load(a.cronet.as_deref())?;
        let engine = TunnelEngine::start(Proxy { sni: a.sni.clone(), addr: a.exit, roots: a.roots.clone() }, false)?;
        let auth = h3dgram::authorization(&h3dgram::token(&a.key));
        let t0 = sys::now_ns();
        let tunnel = Tunnel::open(&engine, ("trunk.hikkari.arpa", 443), &[("proxy-authorization", &auth)], None, a.usage)?;
        loop {
            match tunnel.state() {
                State::Up => break,
                State::Closed(e) => return Err(format!("the tunnel did not come up: net error {e}")),
                State::Opening if sys::now_ns() - t0 > 10_000_000_000 => return Err("no tunnel in 10 s".into()),
                State::Opening => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        let up_ms = (sys::now_ns() - t0) / 1_000_000;
        let fd = tunnel.fd();
        let mut h = Heard { seen: vec![false; a.count as usize], ..Heard::default() };
        let mut buf = vec![0u8; 2048];
        let mut out = vec![0u8; 2048];
        hello(fd, t0, &mut buf, &mut out, &a, &mut h)?;
        let hello_ms = (sys::now_ns() - t0) / 1_000_000;

        let every = a.every_us * 1000;
        // Under a load (the cost's bench) the loop wakes often enough to
        // keep the schedule; a call's own pace needs no more.
        let nap = Duration::from_micros((a.every_us / 4).clamp(20, 200));
        let start = sys::now_ns();
        h.answered_at = start;
        let mut sent = 0u64;
        let mut refused = 0u64;
        let mut payload = vec![0x5au8; a.size];
        let end = start + a.count * every + 1_000_000_000;
        while sys::now_ns() < end {
            let now = sys::now_ns();
            if sent < a.count && now >= start + sent * every {
                payload[..8].copy_from_slice(&sent.to_be_bytes());
                payload[8..16].copy_from_slice(&now.to_be_bytes());
                let n = frame::put_dgram(&mut out, 1, sent as u32 + 1, ECHO_PORT, &payload);
                if !sys::send_nowait(fd, &out[..n]) {
                    refused += 1;
                }
                sent += 1;
            }
            read(fd, &mut buf, &mut out, &a, &mut h)?;
            if let State::Closed(e) = tunnel.state() {
                return Err(format!("the tunnel closed under the call: net error {e}"));
            }
            std::thread::sleep(nap);
        }
        let st = tunnel.stats();
        h.rtts.sort_unstable();
        let pct = |p: usize| h.rtts.get((h.rtts.len() * p / 100).min(h.rtts.len().saturating_sub(1))).copied().unwrap_or(0);
        let back = h.rtts.len() as u64;
        println!(
            "hk-h3dgram-call up_ms={up_ms} hello_ms={hello_ms} sent={sent} refused={refused} back={back} lost={} bad={} rtt_us p50={} p99={} max={} gap_max_ms={} pings={} tunnel up_sent={} up_dropped={} down_received={} down_dropped={}",
            sent - back,
            h.bad,
            pct(50),
            pct(99),
            h.rtts.last().copied().unwrap_or(0),
            h.gap_max / 1_000_000,
            h.pings,
            st.up_sent,
            st.up_dropped,
            st.down_received,
            st.down_dropped
        );
        drop(tunnel);
        drop(engine);
        if back < sent || h.bad > 0 {
            std::process::exit(1);
        }
        Ok(())
    }

    /// The member's t2 hello every 250 ms until the exit answers
    /// (spec/trunk.md, "Wires"), in a session of its own.
    fn hello(fd: i32, t0: u64, buf: &mut [u8], out: &mut [u8], a: &Args, h: &mut Heard) -> Result<(), String> {
        let mut session = [0u8; 16];
        sys::urandom(&mut session);
        let mut hello_at = 0u64;
        while !h.hello {
            let now = sys::now_ns();
            if now - t0 > 10_000_000_000 {
                return Err("no answer to the hello in 10 s".into());
            }
            if now >= hello_at {
                let n = frame::hello_t2(out, &session, a.wire);
                sys::send_nowait(fd, &out[..n]);
                hello_at = now + 250_000_000;
            }
            read(fd, buf, out, a, h)?;
            std::thread::sleep(Duration::from_micros(200));
        }
        Ok(())
    }

    /// Every datagram the tunnel has: the hello's answer, the exit's pings
    /// (answered), the call's answers (checked against what was sent).
    fn read(fd: i32, buf: &mut [u8], out: &mut [u8], a: &Args, h: &mut Heard) -> Result<(), String> {
        while let Some(n) = sys::recv_dgram(fd, buf).map_err(|e| format!("the tunnel's end: {e}"))? {
            let p = &buf[..n];
            let mut at = 0;
            while at < p.len() {
                let Some((f, next)) = frame::next_frame(p, at) else {
                    h.bad += 1;
                    break;
                };
                match f {
                    Frame::Hello => h.hello = true,
                    Frame::Ping(t) => {
                        let m = frame::put_ping(out, F_PONG, t);
                        sys::send_nowait(fd, &out[..m]);
                        h.pings += 1;
                    }
                    Frame::Dgram { port: ECHO_PORT, off, len, .. } => answer(&p[off..off + len], a, h),
                    _ => {}
                }
                at = next;
            }
        }
        Ok(())
    }

    fn answer(d: &[u8], a: &Args, h: &mut Heard) {
        if d.len() != a.size || d[16..].iter().any(|&b| b != 0x5a) {
            h.bad += 1;
            return;
        }
        let seq = u64::from_be_bytes(d[..8].try_into().expect("8 bytes"));
        let at = u64::from_be_bytes(d[8..16].try_into().expect("8 bytes"));
        if seq >= a.count || h.seen[seq as usize] {
            h.bad += 1;
            return;
        }
        h.seen[seq as usize] = true;
        let now = sys::now_ns();
        h.rtts.push((now - at) / 1000);
        h.gap_max = h.gap_max.max(now - h.answered_at);
        h.answered_at = now;
    }
}
