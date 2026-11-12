# rust: Hikkari in Rust

The trunk's protocol and the cascade entry's pipe. The Go side (`trunk`, `trunk/pipectl`) is the reference and the
brain; how to write code here: [../STYLE.md](../STYLE.md).

Status: branch `rust-r1.2-dgrams` on `rust-pipe-r1` (R1.1 members' health, R1.2 datagrams whole, R3 the brain's socket);
bench and tests only, not deployed. The
plan and its steps: hikkari-client `plans/2026-11-11-entry-hot-path-and-unit-economics.md`, «Труба на Rust»; numbers:
`plans/research/2026-11-12-rust-pipe-*.md`.

## Layout

| Crate | What | Who may depend on it |
| --- | --- | --- |
| `sys` (`hikkari-sys`) | Linux syscalls: batched UDP, poll, time, SOCK_SEQPACKET with SCM_RIGHTS. Every `unsafe` of the workspace | any |
| `trunk` (`hikkari-trunk`) | the trunk's protocol (spec/trunk.md): frames, members' health, a flow's rules (copies dropped by seq, idle end), the `udp` wire's seal. No sockets, no clock, no threads | the entry, an exit, the messenger |
| `pipe` (`hikkari-pipe`) | the entry's pipe: client ports, flows, wires, the route, the loop; binary `hk-pipe` | nothing |
| `bench` (`hikkari-bench`) | the bench's users (`hk-loadgen`), `run.sh`, the Go entry and exit it measures against | nothing |

`trunk` depends on no other crate here, `sys` on none, `pipe` on both. Inside `pipe`: `ctl` (the brain's messages),
`flow`, `member` (wires, members, glue), `carry` (which wire carries a datagram), `pipe/` (the loop: `brain`, `timers`,
`data`).

## What it is

`hk-pipe` is the UDP half of the cascade entry (spec/trunk.md), one thread, no runtime:

- It is blind, as the Go entry: a client's datagram channel is QUIC end to end with the exit's relay. The pipe reads client
  UDP datagrams on the listened port as opaque bytes, gives each client address a flow (stream id, seq), and carries every
  datagram as a `dgram` frame over the bare UDP wire (`trunk/udpwire`: AES-256-GCM under HKDF-SHA256(trunk key, "hikkari
  trunk udp wire")) to an unchanged Go exit.
- Datagrams are spec/trunk.md, "Datagrams", as the Go session carries them (trunk flows.go): each on as many members as
  its port's copies (1 for a port whose sender copies itself, 2 otherwise, 0 is the trunk's 2), never sent again; the
  answers' copies dropped by seq in a window of 1024 (`trunk/src/flow.rs`, `Replay`); a client's flow ended after 2
  minutes unused, and the address's next datagram opens a new one (`--flow-idle-ms` for tests). A flow takes the
  members of its pin, else of its class's route; a route's wire with no member up is passed over for any member up of
  any wire, a pinned flow's datagram is dropped. A flow keeps to the same members while they are up. Stream ids are a
  slot and its generation: an ended flow's slot is used again under a new id, so the exit's late answers to it find
  nothing. The brain's flows end when it closes them. Like trunk Stats, the counts leave out the trunk's own call
  (port 0).
- It glues the frames of all clients bound for one member into one sealed datagram, for one tick (1 ms) or up to about
  1200 bytes. The wire already allows it: a packet member reads one frame sequence per datagram.
- Under traffic it runs on a tick: it sleeps to the next millisecond, then takes everything each socket has with
  `recvmmsg` and sends with `sendmmsg`; an idle pipe waits in `ppoll` for the first packet. `--tick-us 0` wakes per packet.
- Nothing is allocated per packet: receive slots, send slots and the glue buffer are allocated once; answers to clients
  are sent straight out of the receive buffer. UDP GRO is on for the client socket.
- A member speaks the t2 hello of a packet member (wire 2, flags packet), says it again every 250 ms until answered, pings
  every 100 ms and answers the exit's pings.
- Members' health is `spec/trunk.md` as the Go session judges it (`trunk/src/health.rs`, any wire's members, on the members'
  clock of 25 ms as Go's tick): a member owing a pong past max(Stall, 4 × smoothed RTT) + 100 ms dies only while another
  member, of any wire, proved the exit alive after its debt began (`why` silent); every member silent at once dies only
  after Quiet, 1 s (`why` quiet); a turn of the loop more than 100 ms after the one before is the pipe's own pause, and
  every debt counts from its end. A pong of any ping still owed is the proof; frames that merely arrive prove nothing.
  Members taken down get new sockets spread over a second (the brain, or the pipe alone). Judging on every turn of the
  loop instead of the clock would bury the others by the first pong after the exit's pause: its pongs come a few
  datagrams apart.

Left out on purpose: streams (TCP) and the pool, wires other than `udp`, drains and generations, observation, IPv6, GSO
on send (the glued datagrams differ in size; answers go to different clients).

`hk-loadgen` is the bench's users (cascade-load-v1 per user: voice 50/s, game 200/s, acks 125/s, in the sizes the entry's
capture saw). `bench/go` holds the Go side: `goentry` (the production entry's UDP path over `trunk` and `udpwire`) and
`goexit` (`trunk.Exit` with the wire, echo on port 0).

## Build and bench

```bash
cargo clippy --all-targets && cargo test          # on the mac: trunk and ctl; the rest builds to a stub
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
cp target/aarch64-unknown-linux-musl/release/hk-pipe target/aarch64-unknown-linux-musl/release/hk-loadgen bench/out/
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/goentry ./goentry && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/goexit ./goexit)
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/run.sh 3 30 "1 4 16 64" "go rust rustev"
```

The entry runs on CPUs 0–1 (`taskset`), the users and the exit on CPUs of their own; `hk-loadgen` reads the entry's CPU
from `/proc/<pid>/stat` at the start and the end of its window.

## Brain and pipe (R3)

The brain is the Go entry (selector, the trunk's calls and downloads, knobs from the hub, minute lines, generations);
the pipe carries every packet. One local `SOCK_SEQPACKET` socket between them, one message per datagram, and the brain
owns the sockets: it binds them and passes them with the message that uses them by `SCM_RIGHTS`, so a reload can hand
the same sockets to the next pipe (R3). The brain's side is `trunk/pipectl`: it starts `hk-pipe --ctl-fd 3` on its end
of a socketpair, and its `Pipe` is a `trunk.Steered` (the selector reads the wires from the pipe's ticks and sets the
route, `trunk.SteerOn`) and a `trunk.CallCarrier` (the trunk's call on each wire runs through the pipe as a client's
datagrams do, `trunk.RunCallOn`). The messages are `pipe/src/ctl.rs`; integers little-endian; both sides test the same golden
bytes.

Brain → pipe:

| Message | What |
| --- | --- |
| `hello` | version |
| `listen` | a client port (one socket): id, class (bulk, voice), the exit's loopback port, copies |
| `wire` | a wire and its members (one connected socket each): id, form (`udp`; later `quic`, `h3`), glue window and size, its members' stall (dead_ms: Stall, the pipe adds the rest of the rule), the wire's own key (udpwire.Key of the trunk key: the pipe never sees the trunk key) |
| `unwire` | a wire taken away; its flows go on by the route |
| `route` | the wire of each class; the pipe moves the next datagram, nothing to migrate: the exit answers a flow on the wire the entry last sent it on |
| `open`, `dgram`, `close` | a flow of the brain's own (its call on a wire, pinned: dropped while the wire has no member up) and its datagrams |
| `member` | a member's new socket (one), after the pipe took it down: as a Go member is dialed anew, the exit sees a new peer |

Pipe → brain:

| Message | What |
| --- | --- |
| `hello` | version, pid |
| `tick` | once a second, and at once after a member event: the pipe's latest pause (a turn of its loop more than 100 ms after the one before), pauses, the latest turn in the second, clients' flows open; since the start, as trunk Stats (the trunk's call left out), datagrams out, delivered, copies dropped, and flows ended unused; per wire members, up, owed (the least debt of its up members), when one last heard the exit, round trip, packets and bytes each way, sealed datagrams, drops |
| `member` | a member up (hello answered) or down: `silent` (past its stall while another member proved the exit alive), `quiet` (every member silent past Quiet), `gone` (its socket failed) |
| `dgram` | an answer on a brain's flow |
| `error` | a message the pipe could not take |

Left for later: `drain` and generations (R3), `ceiling`, `observe` (the exit's marks of a tester's flow), IPv6, the forms other than `udp` (R4) and streams with the pool (R5). The pipe passes over a wire with no member
up for any wire that has one, as `trunk.Route` does, before the selector moves the route.

The test of the whole loop (a Go exit, two `udp` wires to it through cutters, the selector over the pipe's ticks, four
clients calling): `trunk/pipectl` `TestTheSelectorMovesVoiceOffACutWire`. Members' health against the Go exit
(`health_linux_test.go`, trunk's TestOtherEndPaused, TestPathCut and TestOwnPause on the pipe, and a member that dies
alone): `TestAMemberAloneSilentDiesByItsStall`, `TestTheExitPausedBuriesNoMember`, `TestAPathCutEndsMembersByQuiet`,
`TestThePipesOwnPauseBuriesNoMember`; the same rules on a clock of their own: `cargo test --lib`. Datagrams against the
Go exit, each scenario through the Go entry too, which must count the same (`dgram_linux_test.go`):
`TestCopiesAreCountedAndDroppedAsByTheGoEntry`, `TestAClientsFlowUnusedEndsAndItsNextDatagramOpensANewOne`; which
members carry a datagram: `carry.rs` tests. Run on Linux with the
pipe built:

```bash
cargo build --release --target aarch64-unknown-linux-musl && cp target/aarch64-unknown-linux-musl/release/hk-pipe bench/out/
(cd ../trunk && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o ../rust/bench/out/pipectl.test ./pipectl)
docker run --rm -v "$PWD/bench:/bench" -e HK_PIPE=/bench/out/hk-pipe debian:bookworm-slim /bench/out/pipectl.test -test.v
```
