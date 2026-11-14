//! The exit's sending down a Chromium QUIC member on a narrow line
//! (spec/trunk.md, `h3dgram`, "How the exit sends down"): a call beside a
//! deaf flood over the line's rate, both the trunk's echo, as Go's
//! TestLiveTrafficOnABloatedLine puts a call beside a deaf bulk. The line
//! here is a thread between the client and hk-exit: up as it comes, down at
//! a fixed rate behind a queue that drops its tail. The guard has to bring
//! the flood under the line, and the scheduler has to keep the call's frames
//! out of the flood's queue.
#![cfg(target_os = "linux")]

mod common;

use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::*};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{exit, has, Client, KEY, WIRE};
use hikkari_trunk::flow::ECHO_PORT;
use hikkari_trunk::frame::{self, Frame};
use hikkari_trunk::h3dgram;

/// The line down: bytes a second (2 Mbit/s) and the queue's bytes (256 ms
/// of it).
const RATE: f64 = 250_000.0;
const QUEUE: usize = 64 << 10;
/// The call: 160 bytes every 20 ms, on stream 2. The flood: 1000 bytes at
/// FLOOD a second on stream 1, about 1.6 times the line once answered.
const CALL_EVERY: Duration = Duration::from_millis(20);
const FLOOD: u32 = 400;
const RUN: Duration = Duration::from_secs(12);
/// The call is judged after the guard had this long to find the line.
const SETTLE: Duration = Duration::from_secs(3);

/// The line: a client-side socket, the thread, what it dropped.
struct Line {
    at: SocketAddr,
    stop: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    /// Each second's mean queue down, in ms of the line, after SETTLE.
    queue_ms: Arc<std::sync::Mutex<Vec<f64>>>,
    t: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Line {
    fn drop(&mut self) {
        self.stop.store(true, Relaxed);
        if let Some(t) = self.t.take() {
            let _ = t.join();
        }
    }
}

fn line(to: SocketAddr) -> Line {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    b.connect(to).unwrap();
    a.set_nonblocking(true).unwrap();
    b.set_nonblocking(true).unwrap();
    let at = a.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicU64::new(0));
    let queue_ms = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (s, d, qm) = (stop.clone(), dropped.clone(), queue_ms.clone());
    let t = std::thread::spawn(move || {
        let (t0, mut sec, mut sum, mut k) = (Instant::now(), 0u64, 0f64, 0u64);
        let mut client = None;
        let mut q: VecDeque<Vec<u8>> = VecDeque::new();
        let mut q_bytes = 0;
        let mut free_at = Instant::now();
        let mut buf = [0u8; 2048];
        while !s.load(Relaxed) {
            let mut moved = false;
            while let Ok((n, from)) = a.recv_from(&mut buf) {
                client = Some(from);
                let _ = b.send(&buf[..n]);
                moved = true;
            }
            while let Ok(n) = b.recv(&mut buf) {
                if q_bytes + n > QUEUE {
                    d.fetch_add(1, Relaxed);
                } else {
                    q_bytes += n;
                    q.push_back(buf[..n].to_vec());
                }
                moved = true;
            }
            let now = Instant::now();
            while let (Some(c), true) = (client, now >= free_at) {
                let Some(p) = q.pop_front() else { break };
                q_bytes -= p.len();
                let _ = a.send_to(&p, c);
                sum += q_bytes as f64 / RATE * 1000.0;
                k += 1;
                if t0.elapsed().as_secs() > sec {
                    sec = t0.elapsed().as_secs();
                    qm.lock().unwrap().push(sum / k.max(1) as f64);
                    (sum, k) = (0.0, 0);
                }
                free_at = free_at.max(now - Duration::from_millis(1)) + Duration::from_secs_f64(p.len() as f64 / RATE);
                moved = true;
            }
            if !moved {
                std::thread::sleep(Duration::from_micros(50));
            }
        }
    });
    Line { at, stop, dropped, queue_ms, t: Some(t) }
}

/// What the call heard.
#[derive(Debug, Default)]
struct Heard {
    sent: u32,
    back: u32,
    late: u32,
    rtt_p50_ms: f64,
    rtt_p95_ms: f64,
    flood_back: u32,
}

fn payload(kind: u8, seq: u32, t0: Instant, n: usize) -> Vec<u8> {
    let mut p = vec![0u8; n];
    p[0] = kind;
    p[1..5].copy_from_slice(&seq.to_be_bytes());
    p[5..13].copy_from_slice(&(t0.elapsed().as_nanos() as u64).to_be_bytes());
    p
}

fn call_beside_a_flood() -> Heard {
    let (_x, at) = exit();
    let l = line(at);
    let mut c = Client::connect(l.at);
    let (stream, status) = c.connect_udp(&h3dgram::authorization(&h3dgram::token(KEY)));
    assert_eq!(status, b"200");
    let mut b = [0u8; 64];
    let n = frame::hello_t2(&mut b, &[5u8; 16], WIRE);
    c.send(stream, &b[..n]);
    let until = Instant::now() + Duration::from_secs(5);
    while !has(&c.recv(stream), |f, _| matches!(f, Frame::Hello)) {
        assert!(Instant::now() < until, "no answer to the hello");
    }

    // From here the client reads what came and goes on: a read that waits
    // would hold its sends back behind a steady stream down.
    c.sock.set_nonblocking(true).unwrap();
    let t0 = Instant::now();
    let (mut call_seq, mut flood_seq) = (0u32, 0u32);
    let (mut next_call, mut next_flood) = (t0, t0);
    let flood_every = Duration::from_secs(1) / FLOOD;
    let mut rtts = Vec::new();
    let mut h = Heard::default();
    let mut b = vec![0u8; 1100];
    while t0.elapsed() < RUN + Duration::from_millis(500) {
        let now = Instant::now();
        while now >= next_call && t0.elapsed() < RUN {
            call_seq += 1;
            let n = frame::put_dgram(&mut b, 2, call_seq, ECHO_PORT, &payload(2, call_seq, t0, 160));
            if c.q.dgram_send(&with_head(stream, &b[..n])).is_ok() && next_call - t0 >= SETTLE {
                h.sent += 1;
            }
            next_call += CALL_EVERY;
        }
        while now >= next_flood && t0.elapsed() < RUN {
            flood_seq += 1;
            let n = frame::put_dgram(&mut b, 1, flood_seq, ECHO_PORT, &payload(1, flood_seq, t0, 1000));
            let _ = c.q.dgram_send(&with_head(stream, &b[..n]));
            next_flood += flood_every;
        }
        let got = c.recv(stream);
        if got.is_empty() {
            std::thread::sleep(Duration::from_micros(200));
        }
        for g in got {
            let mut at = 0;
            while let Some((f, next)) = frame::next_frame(&g, at) {
                if let Frame::Dgram { port: ECHO_PORT, off, len, .. } = f {
                    let p = &g[off..off + len];
                    let sent_ns = u64::from_be_bytes(p[5..13].try_into().unwrap());
                    let rtt_ms = (t0.elapsed().as_nanos() as u64 - sent_ns) as f64 / 1e6;
                    let settled = Duration::from_nanos(sent_ns) >= SETTLE;
                    match p[0] {
                        2 if settled => {
                            h.back += 1;
                            rtts.push(rtt_ms);
                            if rtt_ms > 150.0 {
                                h.late += 1;
                            }
                        }
                        1 => h.flood_back += 1,
                        _ => {}
                    }
                }
                at = next;
            }
        }
    }
    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| rtts.get(((rtts.len() as f64 - 1.0) * p) as usize).copied().unwrap_or(f64::NAN);
    h.rtt_p50_ms = pct(0.5);
    h.rtt_p95_ms = pct(0.95);
    let q: Vec<String> = l.queue_ms.lock().unwrap().iter().map(|m| format!("{m:.0}")).collect();
    eprintln!("line dropped {} packets down; its queue each second, ms: {}", l.dropped.load(Relaxed), q.join(" "));
    h
}

/// The frames of one write as an HTTP Datagram of `stream`.
fn with_head(stream: u64, frames: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; h3dgram::HEAD_MAX + frames.len()];
    let at = h3dgram::put_head(&mut d, h3dgram::HEAD_MAX, stream);
    d[h3dgram::HEAD_MAX..].copy_from_slice(frames);
    d[at..].to_vec()
}

/// Before the guard and the scheduler (quiche's CUBIC, frames in QUIC's own
/// queue), 2026-11-14: the call got 198 to 206 of 450, the median 3.6 s
/// late, the line's queue full all along. Now nearly all of it comes on
/// time; what comes late is the guard's own probe, as in Go's: after the
/// hold the limit grows 3 % a half second until the line's queue fills, and
/// only loss over a tenth cuts it again (spec/v1.md, "The sender: a
/// guard": a call beside a deaf bulk got 93 to 95 % of its packets).
#[test]
fn a_call_beside_a_deaf_flood_keeps_its_time_on_a_narrow_line() {
    let h = call_beside_a_flood();
    eprintln!("{h:?}");
    assert!(h.flood_back > 0, "the flood came down");
    assert!(h.back * 100 >= h.sent * 95, "the call got {} of {} after the guard settled", h.back, h.sent);
    assert!(h.rtt_p50_ms < 50.0, "the call's median round trip {} ms", h.rtt_p50_ms);
    assert!(h.late * 100 <= h.sent * 10, "{} of the call's {} answers over 150 ms", h.late, h.sent);
}
