//! hk-exit: the cascade exit's pipe (rust/README.md, exit/src/exit/mod.rs).
//!
//! With `--ctl-fd N` the brain runs it: fd N is the exit's end of the
//! brain's SOCK_SEQPACKET socketpair, and the wire (its socket, its keys,
//! the members' stall and Quiet) and the loopback ports open to the trunk
//! come over it. The exit ends when the brain does.
//!
//! Without it (the bench) the flags fix what the brain would decide: one
//! wire on `--listen` under `--key`, the ports in `--ports` (the call's port
//! 0 always), the glue window, the stall and Quiet.
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
    use hikkari_exit::exit::{Alone, Exit, EXIT_QUIET};
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
        };
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
                "--wire-id" => a.wire = v.parse().expect("--wire-id"),
                "--glue-us" => a.glue_ns = v.parse::<u64>().expect("--glue-us") * 1000,
                "--glue-max" => a.glue_max = v.parse().expect("--glue-max"),
                "--dead-ms" => a.stall_ns = v.parse::<u64>().expect("--dead-ms") * 1_000_000,
                "--quiet-ms" => a.quiet_ns = v.parse::<u64>().expect("--quiet-ms") * 1_000_000,
                "--ports" => a.ports = v.split(',').filter(|s| !s.is_empty()).map(|s| s.parse().expect("--ports p,q")).collect(),
                "--flow-idle-ms" => flow_idle_ms = Some(v.parse().expect("--flow-idle-ms")),
                "--tick-us" => tick_ns = v.parse::<u64>().expect("--tick-us") * 1000,
                x => panic!("unknown flag {x}"),
            }
            i += 2;
        }
        let mut x = match ctl {
            Some(fd) => {
                eprintln!("hk-exit: under the brain on fd {fd}, tick {} us", tick_ns / 1000);
                Exit::with_brain(fd, tick_ns).expect("epoll")
            }
            None => {
                eprintln!(
                    "hk-exit: wire {} (id {}), glue {} us / {} B, ports {:?}, tick {} us",
                    a.listen,
                    a.wire,
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
