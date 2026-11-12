//! hk-loadgen: synthetic users for the entry bench (rust/README.md, bench/run.sh).
//!
//! Each user is one UDP socket, as a client's datagram channel is one QUIC
//! connection, and sends what cascade-load-v1 sends per user (hikkari-client
//! plans/research/2026-11-11-cascade-synthetic-users.md) in the sizes a
//! capture of the entry's 8443 saw (research/2026-11-12-h3-wire-chromium-quic-cost.md):
//! voice 50/s of 220 B (160 B of audio and QUIC and Hikkari heads), a game
//! 200/s of 140 B (80 B), and 125/s of 45 B, the QUIC acks a user's
//! datagrams draw. Whatever comes back is the exit's echo.
//!
//! It reads the entry process's CPU at the start and the end of the window
//! and prints one line: the CPU per packet of the entry and per user
//! datagram, the call's pauses over 60 and 150 ms, losses, round trips.

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hk-loadgen runs on Linux only (recvmmsg, sendmmsg, SCM_RIGHTS)");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{SocketAddrV4, UdpSocket};
    use std::os::fd::AsRawFd;

    use hikkari_sys::{self as sys, now_ns};

    const VOICE: u8 = 1;
    const GAME: u8 = 2;
    const ACK: u8 = 3;
    const KINDS: [(u8, u64, usize); 3] = [(VOICE, 20_000_000, 220), (GAME, 5_000_000, 140), (ACK, 8_000_000, 45)];

    struct User {
        sock: UdpSocket,
        fd: i32,
        next: [u64; 3],
        seq: [u32; 3],
        sent: [u64; 3],
        got: [u64; 3],
        last_voice: u64,
        gaps60: u64,
        gaps150: u64,
        gap_max: u64,
    }

    pub fn main() {
        let a: Vec<String> = std::env::args().skip(1).collect();
        let mut target: SocketAddrV4 = "127.0.0.1:8443".parse().unwrap();
        let mut users = 1usize;
        let mut warm = 5u64;
        let mut secs = 30u64;
        let mut pid = 0u32;
        let mut label = String::from("-");
        let mut i = 0;
        while i < a.len() {
            let v = a.get(i + 1).cloned().unwrap_or_default();
            match a[i].as_str() {
                "--to" => target = v.parse().expect("--to ip:port"),
                "--users" => users = v.parse().expect("--users"),
                "--warm" => warm = v.parse().expect("--warm"),
                "--secs" => secs = v.parse().expect("--secs"),
                "--pid" => pid = v.parse().expect("--pid"),
                "--label" => label = v,
                x => panic!("unknown flag {x}"),
            }
            i += 2;
        }

        let start = now_ns();
        let mut rnd = [0u8; 8];
        let mut us: Vec<User> = (0..users)
            .map(|_| {
                let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
                s.connect(target).expect("connect");
                sys::tune(&s, false).expect("tune");
                let fd = s.as_raw_fd();
                // Each user's phase apart, as real users are.
                let mut next = [0u64; 3];
                for (k, (_, every, _)) in KINDS.iter().enumerate() {
                    sys::urandom(&mut rnd);
                    next[k] = start + u64::from_le_bytes(rnd) % every;
                }
                User { sock: s, fd, next, seq: [0; 3], sent: [0; 3], got: [0; 3], last_voice: 0, gaps60: 0, gaps150: 0, gap_max: 0 }
            })
            .collect();

        let w0 = start + warm * 1_000_000_000;
        let w1 = w0 + secs * 1_000_000_000;
        let end = w1 + 1_000_000_000; // a second more for the window's last answers
        let mut cpu0 = None;
        let mut cpu1 = None;
        let mut rtts: Vec<u32> = Vec::with_capacity((users as u64 * 50 * secs) as usize + 16);
        let mut pkt = [0u8; 1500];
        let mut buf = [0u8; 2048];
        let mut late_sends = 0u64;

        loop {
            let now = now_ns();
            if cpu0.is_none() && now >= w0 {
                cpu0 = Some((now, if pid != 0 { sys::cpu_ns(pid) } else { None }));
                for u in us.iter_mut() {
                    u.last_voice = 0;
                }
            }
            if cpu1.is_none() && now >= w1 {
                cpu1 = Some((now, if pid != 0 { sys::cpu_ns(pid) } else { None }));
            }
            if now >= end {
                break;
            }
            let mut soonest = now + 1_000_000;
            for (ui, u) in us.iter_mut().enumerate() {
                for (k, &(kind, every, size)) in KINDS.iter().enumerate() {
                    while u.next[k] <= now {
                        let at = u.next[k];
                        if now - at > 5_000_000 {
                            late_sends += 1;
                        }
                        u.next[k] += every;
                        if at >= w1 {
                            continue; // nothing new after the window
                        }
                        u.seq[k] += 1;
                        pkt[0] = kind;
                        pkt[1..3].copy_from_slice(&(ui as u16).to_be_bytes());
                        pkt[3..7].copy_from_slice(&u.seq[k].to_be_bytes());
                        pkt[7..15].copy_from_slice(&now.to_be_bytes());
                        let _ = u.sock.send(&pkt[..size]);
                        if at >= w0 {
                            u.sent[k] += 1;
                        }
                    }
                    soonest = soonest.min(u.next[k]);
                }
                loop {
                    let r = sys::recv_nowait(u.fd, &mut buf);
                    if r < 15 {
                        break;
                    }
                    let t = u64::from_be_bytes(buf[7..15].try_into().unwrap());
                    if t < w0 || t >= w1 {
                        continue;
                    }
                    let k = (buf[0] as usize).wrapping_sub(1);
                    if k > 2 {
                        continue;
                    }
                    let got = now_ns();
                    u.got[k] += 1;
                    if buf[0] == VOICE {
                        rtts.push(((got - t) / 1000) as u32);
                        if u.last_voice != 0 && got < w1 {
                            let gap = got - u.last_voice;
                            if gap > 60_000_000 {
                                u.gaps60 += 1;
                            }
                            if gap > 150_000_000 {
                                u.gaps150 += 1;
                            }
                            u.gap_max = u.gap_max.max(gap);
                        }
                        u.last_voice = got;
                    }
                }
            }
            let wait = soonest.saturating_sub(now_ns()).min(1_000_000);
            if wait > 50_000 {
                sys::sleep_until(now_ns() + wait);
            }
        }

        let (t0, c0) = cpu0.unwrap();
        let (t1, c1) = cpu1.unwrap();
        let wall = (t1 - t0) as f64 / 1e9;
        let sum = |f: &dyn Fn(&User) -> u64| us.iter().map(f).sum::<u64>();
        let sent: [u64; 3] = [sum(&|u| u.sent[0]), sum(&|u| u.sent[1]), sum(&|u| u.sent[2])];
        let got: [u64; 3] = [sum(&|u| u.got[0]), sum(&|u| u.got[1]), sum(&|u| u.got[2])];
        let pkts = sent.iter().sum::<u64>() + got.iter().sum::<u64>();
        let user_dgrams = sent[0] + sent[1] + got[0] + got[1];
        let minutes = wall / 60.0 * users as f64;
        rtts.sort_unstable();
        let pct = |q: f64| if rtts.is_empty() { 0.0 } else { rtts[((rtts.len() - 1) as f64 * q) as usize] as f64 / 1000.0 };
        let (cpu_ms, user_ms, sys_ms, per_pkt, per_dgram) = match (c0, c1) {
            (Some((u0, s0)), Some((u1, s1))) => {
                let cpu = (u1 + s1 - u0 - s0) as f64;
                (cpu / 1e6, (u1 - u0) as f64 / 1e6, (s1 - s0) as f64 / 1e6, cpu / 1e3 / pkts as f64, cpu / 1e3 / user_dgrams as f64)
            }
            _ => (0.0, 0.0, 0.0, 0.0, 0.0),
        };
        println!(
            "label={label} users={users} secs={wall:.1} pkts_per_s={:.0} cpu_pct={:.1} user_ms={user_ms:.0} sys_ms={sys_ms:.0} us_per_pkt={per_pkt:.2} us_per_user_dgram={per_dgram:.2} \
    voice={}/{} game={}/{} ack={}/{} gaps60_per_min={:.2} gaps150_per_min={:.2} gap_max_ms={:.1} rtt_p50_ms={:.2} rtt_p99_ms={:.2} rtt_max_ms={:.2} late_sends={late_sends}",
            pkts as f64 / wall,
            cpu_ms / 10.0 / wall,
            got[0],
            sent[0],
            got[1],
            sent[1],
            got[2],
            sent[2],
            sum(&|u| u.gaps60) as f64 / minutes,
            sum(&|u| u.gaps150) as f64 / minutes,
            us.iter().map(|u| u.gap_max).max().unwrap_or(0) as f64 / 1e6,
            pct(0.5),
            pct(0.99),
            pct(1.0),
        );
    }
}
