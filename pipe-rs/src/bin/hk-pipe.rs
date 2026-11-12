//! hk-pipe: the cascade entry's pipe (pipe-rs/README.md, src/pipe.rs).
//!
//! With `--ctl-fd N` the brain runs it: fd N is the pipe's end of the
//! brain's SOCK_SEQPACKET socketpair, and everything else (client ports,
//! wires and their members, the route, the brain's own flows) comes over it.
//! The pipe ends when the brain does.
//!
//! Without it (the bench) the flags fix what the brain would decide: one
//! client port, one wire, its members, the glue window.

use hikkari_pipe::pipe::{Alone, Pipe};

fn main() {
    let mut a = Alone {
        listen: "127.0.0.1:8443".parse().unwrap(),
        exit: "127.0.0.1:20447".parse().unwrap(),
        key: "bench-trunk-key-0123456789abcdef".into(),
        members: 2,
        glue_ns: 1_000_000,
        glue_max: 1200,
        to: 0,
        wire: 2,
    };
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
            "--tick-us" => tick_ns = v.parse::<u64>().expect("--tick-us") * 1000,
            x => panic!("unknown flag {x}"),
        }
        i += 2;
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
    p.run();
    eprintln!("hk-pipe: the brain is gone");
}
