//! hk-pipe: the cascade entry's pipe (rust/README.md, pipe/src/pipe/mod.rs).
//!
//! With `--ctl-fd N` the brain runs it: fd N is the pipe's end of the
//! brain's SOCK_SEQPACKET socketpair, and everything else (client ports,
//! wires and their members, the route, the brain's own flows) comes over it.
//! The pipe ends when the brain does.
//!
//! Without it (the bench) the flags fix what the brain would decide: one
//! client port, one wire, its members, the glue window, the copies; with
//! `--tcp-listen` also a client port of streams to the exit's `--tcp-to`,
//! carried on `--tcp-members` plain TCP members to `--tcp-wire`; with
//! `--tcp-chromium <domain>` the members are Chromium's CONNECT to the
//! exit's relay at `--tcp-wire` instead (the pool's form), under the trunk
//! key `--key`, trusting the PEM roots in `--tcp-roots` (tests) or the
//! system's, libcronet from `--cronet` or found as the Go entry finds it.
//! The stream members' source ports come from the book of `--ports lo-hi`
//! (trunk's 20000-32767 without it). With `--members 0` there is no wire of
//! packet members, and clients' datagrams ride the stream members (the
//! pool's wire 0, as the Go entry's voice on its pool).
//!
//! `--flow-idle-ms` (either way): a client's flow unused this long ends;
//! the trunk's 2 minutes without it.

#[cfg(target_os = "linux")]
fn main() {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hk-pipe runs on Linux only (recvmmsg, sendmmsg, SCM_RIGHTS)");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
mod linux {
    use hikkari_pipe::pipe::{Alone, Pipe};

    pub fn main() {
        let mut a = Alone {
            listen: "127.0.0.1:8443".parse().unwrap(),
            exit: "127.0.0.1:20447".parse().unwrap(),
            key: "bench-trunk-key-0123456789abcdef".into(),
            members: 2,
            glue_ns: 1_000_000,
            glue_max: 1200,
            to: 0,
            wire: 2,
            copies: 1,
            tcp_listen: None,
            tcp_to: 0,
            tcp_exit: "127.0.0.1:20446".parse().unwrap(),
            tcp_members: 4,
            tcp_chromium: None,
            ports: (hikkari_trunk::ports::LO, hikkari_trunk::ports::HI),
        };
        let (mut chromium, mut roots, mut cronet): (Option<String>, Option<String>, Option<String>) = (None, None, None);
        let mut flow_idle_ms: Option<u64> = None;
        let mut gro = true;
        let mut tick_ns = 1_000_000u64;
        let mut ctl: Option<i32> = None;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < args.len() {
            let v = args.get(i + 1).cloned().unwrap_or_default();
            match args[i].as_str() {
                "--ctl-fd" => ctl = Some(v.parse().expect("--ctl-fd N")),
                "--listen" => a.listen = v.parse().expect("--listen ip:port"),
                "--wire" => a.exit = v.parse().expect("--wire ip:port"),
                "--key" => a.key = v,
                "--members" => a.members = v.parse().expect("--members"),
                "--glue-us" => a.glue_ns = v.parse::<u64>().expect("--glue-us") * 1000,
                "--glue-max" => a.glue_max = v.parse().expect("--glue-max"),
                "--to" => a.to = v.parse().expect("--to"),
                "--gro" => gro = v == "1",
                "--wire-id" => a.wire = v.parse().expect("--wire-id"),
                "--copies" => a.copies = v.parse().expect("--copies"),
                "--flow-idle-ms" => flow_idle_ms = Some(v.parse().expect("--flow-idle-ms")),
                "--tick-us" => tick_ns = v.parse::<u64>().expect("--tick-us") * 1000,
                "--tcp-listen" => a.tcp_listen = Some(v.parse().expect("--tcp-listen ip:port")),
                "--tcp-to" => a.tcp_to = v.parse().expect("--tcp-to"),
                "--tcp-wire" => a.tcp_exit = v.parse().expect("--tcp-wire ip:port"),
                "--tcp-members" => a.tcp_members = v.parse().expect("--tcp-members"),
                "--tcp-chromium" => chromium = Some(v),
                "--tcp-roots" => roots = Some(std::fs::read_to_string(&v).expect("--tcp-roots file")),
                "--cronet" => cronet = Some(v),
                "--ports" => {
                    let (lo, hi) = v.split_once('-').expect("--ports lo-hi");
                    a.ports = (lo.parse().expect("--ports lo"), hi.parse().expect("--ports hi"));
                }
                x => panic!("unknown flag {x}"),
            }
            i += 2;
        }
        if let Some(sni) = chromium {
            hikkari_cronet::load(cronet.as_deref()).expect("libcronet");
            let form = hikkari_cronet::Form::new(a.tcp_exit, &sni, &a.key, roots).expect("--tcp-chromium");
            a.tcp_chromium = Some(hikkari_cronet::Engine::new(form));
            eprintln!("hk-pipe: stream members by Chromium {}", hikkari_cronet::version().unwrap_or_default());
        }
        let mut p = match ctl {
            Some(fd) => {
                eprintln!("hk-pipe: under the brain on fd {fd}, gro {gro}, tick {} us", tick_ns / 1000);
                Pipe::with_brain(fd, gro, tick_ns)
            }
            None => {
                eprintln!(
                    "hk-pipe: clients {} → wire {} x{}, glue {} us / {} B, gro {}, tick {} us",
                    a.listen,
                    a.exit,
                    a.members,
                    a.glue_ns / 1000,
                    a.glue_max,
                    gro,
                    tick_ns / 1000
                );
                Pipe::alone(&a, tick_ns, gro).expect("sockets")
            }
        };
        if let Some(ms) = flow_idle_ms {
            p.set_flow_idle(ms * 1_000_000);
        }
        p.run();
        eprintln!("hk-pipe: the brain is gone");
    }
}
