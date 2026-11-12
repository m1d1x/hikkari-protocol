# pipe-rs: the entry's pipe in Rust (prototype)

Status: prototype on branch `rust-pipe-proto`, bench only. Not deployed, not for `main`. The question and the numbers:
hikkari-client `plans/research/2026-11-12-rust-pipe-prototype.md`; why: `plans/2026-11-11-entry-hot-path-and-unit-economics.md`,
«Труба на Rust».

## What it is

`hk-pipe` is the UDP half of the cascade entry (spec/trunk.md), one thread, no runtime:

- It is blind, as the Go entry: a client's datagram channel is QUIC end to end with the exit's relay. The pipe reads client
  UDP datagrams on the listened port as opaque bytes, gives each client address a flow (stream id, seq), and carries every
  datagram as a `dgram` frame (one copy, as the entry carries a one-copy port) over the bare UDP wire (`trunk/udpwire`:
  AES-256-GCM under HKDF-SHA256(trunk key, "hikkari trunk udp wire")) to an unchanged Go exit.
- It glues the frames of all clients bound for one member into one sealed datagram, for one tick (1 ms) or up to about
  1200 bytes. The wire already allows it: a packet member reads one frame sequence per datagram.
- Under traffic it runs on a tick: it sleeps to the next millisecond, then takes everything each socket has with
  `recvmmsg` and sends with `sendmmsg`; an idle pipe waits in `ppoll` for the first packet. `--tick-us 0` wakes per packet.
- Nothing is allocated per packet: receive slots, send slots and the glue buffer are allocated once; answers to clients
  are sent straight out of the receive buffer. UDP GRO is on for the client socket.
- A member speaks the t2 hello of a packet member (wire 2, flags packet), says it again every 250 ms until answered, pings
  every 100 ms and answers the exit's pings.

Left out on purpose: streams (TCP) and the pool, other wires, the selector, the trunk's calls, drains and generations,
observation, flow idle ends, IPv6, GSO on send (the glued datagrams differ in size; answers go to different clients).

`hk-loadgen` is the bench's users (cascade-load-v1 per user: voice 50/s, game 200/s, acks 125/s, in the sizes the entry's
capture saw). `bench/go` holds the Go side: `goentry` (the production entry's UDP path over `trunk` and `udpwire`) and
`goexit` (`trunk.Exit` with the wire, echo on port 0).

## Build and bench

```bash
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
cp target/aarch64-unknown-linux-musl/release/hk-pipe target/aarch64-unknown-linux-musl/release/hk-loadgen bench/out/
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/goentry ./goentry && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/goexit ./goexit)
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/run.sh 3 30 "1 4 16 64" "go rust rustev"
```

The entry runs on CPUs 0–1 (`taskset`), the users and the exit on CPUs of their own; `hk-loadgen` reads the entry's CPU
from `/proc/<pid>/stat` at the start and the end of its window.

## Brain and pipe (interface, not built)

The brain is the Go entry as it is (selector, the trunk's calls and downloads, knobs from the hub, minute lines,
generations); the pipe carries every packet. One local `SOCK_SEQPACKET` socket between them, one message per datagram,
and the brain owns the sockets.

Brain → pipe:

| Message | What |
| --- | --- |
| `sockets` | the listened client ports and the wires' member sockets, by `SCM_RIGHTS`: the brain binds them, so a reload hands the same sockets to the next generation as today |
| `wires` | each wire: id, form (`udp`, later `quic`, `h3`), members, the exit, the key's derived cipher key, glue window and size |
| `route` | the wire of each class (voice, bulk) and the one kept warm; the pipe moves the next datagram, nothing to migrate |
| `pin` | a flow held to one wire (the brain's own call on a wire) |
| `ceiling` | later: a limit per flow or per client address |
| `drain` | stop taking new client addresses, hand them over (the generations of 2.2б) |

Pipe → brain:

| Message | What |
| --- | --- |
| `tick` | once a second per wire and member: up, owed since, last proof, round trip of pings, packets and bytes each way, frames per datagram, drops; and the pipe's own late ticks (`entry_paused` comes from here) |
| `member` | a member up or dead, and why |
| `observe` | an exit's `observe` frame, passed up as it came; the pipe counts a marked flow and reports it at its end |
| `flow` | a flow opened or ended (count only; no address leaves the pipe, as no address leaves the entry today) |

The trunk's call stays in the brain: 50 datagrams a second over the socket are nothing, and the call then hears the pipe
the way a client does. What the brain decides a second at a time never sits in the path of a packet.
