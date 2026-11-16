//! hk-exit: the cascade exit's pipe (rust/README.md, exit/src/exit/mod.rs).
//!
//! With `--ctl-fd N` the brain runs it: fd N is the exit's end of the
//! brain's SOCK_SEQPACKET socketpair, and the wire (its socket, its keys,
//! the members' stall and Quiet) and the loopback ports open to the trunk
//! come over it. The exit ends when the brain does.
//!
//! Without it (the bench) the flags fix what the brain would decide: one
//! wire on `--listen` under `--key` (or the key in `--key-file`, so that it
//! is in no process table), the pool's port of plain TCP stream
//! members on `--pool`, the ports in `--ports` (the call's port 0 always),
//! the glue window, the stall and Quiet. `--h3 ip:port` adds the Chromium
//! QUIC wire (`h3dgram`, id `--h3-wire-id`) under the same key, with the
//! certificate and key in `--cert` and `--cert-key` (PEM).
//!
//! `--flow-idle-ms` (either way): a flow unused this long ends; the trunk's
//! 2 minutes without it.

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hk-exit runs on Linux only (recvmmsg, sendmmsg, epoll, SCM_RIGHTS)");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use hikkari_exit::exit::{Alone, AloneH3, Exit, EXIT_QUIET};
    use hikkari_trunk::health::STALL;

    pub fn main() {
        let mut a = Alone {
            listen: "127.0.0.1:20447".parse().unwrap(),
            key: "bench-trunk-key-0123456789abcdef".into(),
            wire: 2,
            glue_ns: 1_000_000,
            glue_max: 1200,
            stall_ns: STALL,
            quiet_ns: EXIT_QUIET,
            ports: Vec::new(),
            pool: None,
            h3: None,
        };
        let mut h3 = AloneH3 { listen: "127.0.0.1:4433".parse().unwrap(), wire: 6, cert: String::new(), key: String::new() };
        let mut with_h3 = false;
        let mut flow_idle_ms: Option<u64> = None;
        let mut tick_ns = 1_000_000u64;
        let mut ctl: Option<i32> = None;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < args.len() {
            let v = args.get(i + 1).cloned().unwrap_or_default();
            match args[i].as_str() {
                "--ctl-fd" => ctl = Some(v.parse().expect("--ctl-fd N")),
                "--listen" => a.listen = v.parse().expect("--listen ip:port"),
                "--key" => a.key = v,
                "--key-file" => a.key = std::fs::read_to_string(&v).expect("--key-file").trim().to_string(),
                "--wire-id" => a.wire = v.parse().expect("--wire-id"),
                "--glue-us" => a.glue_ns = v.parse::<u64>().expect("--glue-us") * 1000,
                "--glue-max" => a.glue_max = v.parse().expect("--glue-max"),
                "--dead-ms" => a.stall_ns = v.parse::<u64>().expect("--dead-ms") * 1_000_000,
                "--quiet-ms" => a.quiet_ns = v.parse::<u64>().expect("--quiet-ms") * 1_000_000,
                "--pool" => a.pool = Some(v.parse().expect("--pool ip:port")),
                "--ports" => a.ports = v.split(',').filter(|s| !s.is_empty()).map(|s| s.parse().expect("--ports p,q")).collect(),
                "--flow-idle-ms" => flow_idle_ms = Some(v.parse().expect("--flow-idle-ms")),
                "--h3" => {
                    h3.listen = v.parse().expect("--h3 ip:port");
                    with_h3 = true;
                }
                "--h3-wire-id" => h3.wire = v.parse().expect("--h3-wire-id"),
                "--cert" => h3.cert = v,
                "--cert-key" => h3.key = v,
                "--tick-us" => tick_ns = v.parse::<u64>().expect("--tick-us") * 1000,
                x => panic!("unknown flag {x}"),
            }
            i += 2;
        }
        if with_h3 {
            a.h3 = Some(h3);
        }
        let mut x = match ctl {
            Some(fd) => {
                eprintln!("hk-exit: under the brain on fd {fd}, tick {} us", tick_ns / 1000);
                Exit::with_brain(fd, tick_ns).expect("epoll")
            }
            None => {
                eprintln!(
                    "hk-exit: wire {} (id {}), pool {:?}, glue {} us / {} B, ports {:?}, tick {} us",
                    a.listen,
                    a.wire,
                    a.pool,
                    a.glue_ns / 1000,
                    a.glue_max,
                    a.ports,
                    tick_ns / 1000
                );
                Exit::alone(&a, tick_ns).expect("sockets")
            }
        };
        if let Some(ms) = flow_idle_ms {
            x.set_flow_idle(ms * 1_000_000);
        }
        x.run();
        eprintln!("hk-exit: the brain is gone");
    }
}
