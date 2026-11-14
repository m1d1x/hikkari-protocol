//! hk-udp-tunnel: opens one CONNECT-UDP tunnel through Chromium's QUIC
//! (hikkari_cronet::Tunnel) to an HTTP/3 proxy that echoes, sends a call's
//! datagrams (one every `--every-ms`) and counts what comes back: the check
//! of the cronet patch (hot path plan, R6.1: a datagram goes out of Chromium
//! to the test server and back). The bench's proxy is
//! rust/bench/go/connectudp.
//!
//! Prints one line: sent, back, lost, rtt p50/p99/max in microseconds, the
//! tunnel's counts, and exits 1 if a datagram was lost.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = probe::run() {
        eprintln!("hk-udp-tunnel: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hk-udp-tunnel: Linux only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod probe {
    use std::net::SocketAddrV4;
    use std::time::Duration;

    use hikkari_cronet::{Proxy, State, Tunnel, TunnelEngine, Usage};
    use hikkari_sys as sys;

    struct Args {
        cronet: Option<String>,
        sni: String,
        proxy: SocketAddrV4,
        roots: Option<String>,
        auth: String,
        target: (String, u16),
        count: u64,
        every_ms: u64,
        size: usize,
        usage: Usage,
    }

    fn args() -> Result<Args, String> {
        let mut a = Args {
            cronet: None,
            sni: "hk.example".into(),
            proxy: "127.0.0.1:4433".parse().expect("a literal address"),
            roots: None,
            auth: "basic aGs6YmVuY2g=".into(),
            target: ("echo.hikkari.arpa".into(), 7),
            count: 1500,
            every_ms: 20,
            size: 160,
            usage: Usage::Destination,
        };
        let mut it = std::env::args().skip(1);
        while let Some(k) = it.next() {
            let mut v = || it.next().ok_or(format!("{k} needs a value"));
            match k.as_str() {
                "--cronet" => a.cronet = Some(v()?),
                "--sni" => a.sni = v()?,
                "--proxy" => a.proxy = v()?.parse().map_err(|e| format!("--proxy: {e}"))?,
                "--roots" => {
                    let p = v()?;
                    a.roots = Some(std::fs::read_to_string(&p).map_err(|e| format!("--roots {p}: {e}"))?);
                }
                "--auth" => a.auth = v()?,
                "--target" => {
                    let t = v()?;
                    let (h, p) = t.rsplit_once(':').ok_or("--target is host:port")?;
                    a.target = (h.into(), p.parse().map_err(|e| format!("--target port: {e}"))?);
                }
                "--count" => a.count = v()?.parse().map_err(|e| format!("--count: {e}"))?,
                "--every-ms" => a.every_ms = v()?.parse().map_err(|e| format!("--every-ms: {e}"))?,
                "--size" => a.size = v()?.parse().map_err(|e| format!("--size: {e}"))?,
                "--usage" => a.usage = Usage::parse(&v()?)?,
                _ => return Err(format!("unknown flag {k}")),
            }
        }
        if a.size < 16 || a.size > 1200 {
            return Err("--size is 16..1200 (seq and send time, then filler)".into());
        }
        Ok(a)
    }

    pub fn run() -> Result<(), String> {
        let a = args()?;
        hikkari_cronet::load(a.cronet.as_deref())?;
        let engine = TunnelEngine::start(Proxy { sni: a.sni.clone(), addr: a.proxy, roots: a.roots.clone() }, false)?;
        let t0 = sys::now_ns();
        let tunnel = Tunnel::open(&engine, (&a.target.0, a.target.1), &[("proxy-authorization", &a.auth)], None, a.usage)?;
        loop {
            match tunnel.state() {
                State::Up => break,
                State::Closed(e) => return Err(format!("the tunnel did not come up: net error {e}")),
                State::Opening if sys::now_ns() - t0 > 10_000_000_000 => return Err("no tunnel in 10 s".into()),
                State::Opening => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        let up_ms = (sys::now_ns() - t0) / 1_000_000;

        let mut rtts: Vec<u64> = Vec::with_capacity(a.count as usize);
        let mut seen = vec![false; a.count as usize];
        let mut buf = vec![0u8; 2048];
        let mut out = vec![0u8; a.size];
        let start = sys::now_ns();
        let every = a.every_ms * 1_000_000;
        let mut sent = 0u64;
        let mut refused = 0u64;
        let mut bad = 0u64;
        // Sends on schedule, then waits a second for the stragglers.
        let end = start + a.count * every + 1_000_000_000;
        while sys::now_ns() < end {
            let now = sys::now_ns();
            if sent < a.count && now >= start + sent * every {
                out[..8].copy_from_slice(&sent.to_be_bytes());
                out[8..16].copy_from_slice(&now.to_be_bytes());
                if !sys::send_nowait(tunnel.fd(), &out) {
                    refused += 1;
                }
                sent += 1;
            }
            while let Some(n) = sys::recv_dgram(tunnel.fd(), &mut buf).map_err(|e| format!("the tunnel's end: {e}"))? {
                // The proxy echoes the HTTP Datagram's payload: context ID 0
                // stripped by Chromium, so this is what was sent.
                if n != a.size {
                    bad += 1;
                    continue;
                }
                let seq = u64::from_be_bytes(buf[..8].try_into().expect("8 bytes"));
                let at = u64::from_be_bytes(buf[8..16].try_into().expect("8 bytes"));
                if seq >= a.count || seen[seq as usize] || buf[..n] != out_for(seq, at, &out)[..n] {
                    bad += 1;
                    continue;
                }
                seen[seq as usize] = true;
                rtts.push((sys::now_ns() - at) / 1000);
            }
            if let State::Closed(e) = tunnel.state() {
                return Err(format!("the tunnel closed under the call: net error {e}"));
            }
            std::thread::sleep(Duration::from_micros(200));
        }
        let st = tunnel.stats();
        rtts.sort_unstable();
        let pct = |p: usize| rtts.get((rtts.len() * p / 100).min(rtts.len().saturating_sub(1))).copied().unwrap_or(0);
        let back = rtts.len() as u64;
        println!(
            "hk-udp-tunnel up_ms={up_ms} sent={sent} refused={refused} back={back} lost={} bad={bad} rtt_us p50={} p99={} max={} tunnel up_sent={} up_dropped={} down_received={} down_dropped={}",
            sent - back,
            pct(50),
            pct(99),
            rtts.last().copied().unwrap_or(0),
            st.up_sent,
            st.up_dropped,
            st.down_received,
            st.down_dropped
        );
        drop(tunnel);
        drop(engine);
        if back < sent || bad > 0 {
            std::process::exit(1);
        }
        Ok(())
    }

    /// The datagram `seq` sent at `at`: what an echo must equal.
    fn out_for(seq: u64, at: u64, filler: &[u8]) -> Vec<u8> {
        let mut d = filler.to_vec();
        d[..8].copy_from_slice(&seq.to_be_bytes());
        d[8..16].copy_from_slice(&at.to_be_bytes());
        d
    }
}
