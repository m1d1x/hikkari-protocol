# rust: Hikkari in Rust

The trunk's protocol, the cascade entry's pipe and the exit's. The Go side (`trunk`, `trunk/pipectl`) is the reference
and the brain; how to write code here: [../STYLE.md](../STYLE.md).

Status: branch `rust-r4-generations` on `rust-r2.3-ports` (R4 generations: a reload hands the client ports to a new pipe, the old one carries its flows to their end; R2.3 the members' port book, deaths and their wait, datagrams on stream members; R2.2 a wire's members on one engine; R2.1 stream members by Chromium's CONNECT; R1.7 the exit's streams; R1.6 the exit's pipe, UDP; R1.5 both paths benched at once; R1.1
members' health, R1.2 datagrams whole, R1.3 clients' TCP streams, R1.4 what a dead member carried sent again, R3 the
brain's socket); bench and tests only, not deployed. The
plan and its steps: hikkari-client `plans/2026-11-11-entry-hot-path-and-unit-economics.md`, «Труба на Rust»; numbers:
`plans/research/2026-11-12-rust-pipe-*.md`.

## Layout

| Crate | What | Who may depend on it |
| --- | --- | --- |
| `sys` (`hikkari-sys`) | Linux syscalls: batched UDP, poll, time, SOCK_SEQPACKET with SCM_RIGHTS. Every `unsafe` of the workspace | any |
| `trunk` (`hikkari-trunk`) | the trunk's protocol (spec/trunk.md): frames, members' health, a flow's rules (copies dropped by seq, idle end), a stream's rules (what an ack confirms, chunks in order, the window), the `udp` wire's seal, a pool member's Naive padding and CONNECT headers (`naive`), the book of members' source ports (`ports`). No sockets, no clock, no threads | the entry, an exit, the messenger |
| `cronet` (`hikkari-cronet`) | a pool member over Chromium's network stack: libcronet loaded at run time, the member's own TCP socket by cronet's dialer, the CONNECT tunnel read and written like a non-blocking socket; its `unsafe` is the C API's | the entry |
| `pipe` (`hikkari-pipe`) | the entry's pipe: client ports, flows, wires, the route, the loop; binary `hk-pipe` | nothing |
| `exit` (`hikkari-exit`) | the exit's pipe: the entry's packet members and stream members, their sessions, flows and streams to the loopback services, answers glued down; binary `hk-exit` | nothing |
| `bench` (`hikkari-bench`) | the bench's users (`hk-loadgen`), `run.sh`, the Go entry and exit it measures against | nothing |

`trunk` depends on no other crate here, `sys` on none, `cronet` on both, `pipe` on all three, `exit` on `sys` and `trunk`. Inside `pipe`: `ctl` (the brain's messages),
`flow`, `member` (wires, members, glue), `carry` (which wire carries a datagram), `link` (stream members over TCP),
`streams` (clients' connections as streams), `pipe/` (the loop: `brain`, `timers`, `data`, `tcp`).

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

Streams (R1.3; spec/trunk.md, "Streams", as the Go session carries them: Carry, readLocal, writeLocal):

- A client's TCP connection on a client port of streams is a stream to the exit's loopback port. Its open goes on a
  stream member as soon as one is up; until then the client is not read. Stream ids count up and are never used again
  while the pipe runs: the exit resets a late frame of a stream it ended for 2 minutes.
- The client's bytes are read straight into a member's out buffer behind a data frame's head, in chunks of up to 16 KiB,
  as far as the exit's credit (2 MiB past what it wrote) and the member's room go: a member takes a chunk while its
  unconfirmed chunks stay under 256 KiB, or owes nothing. A chunk goes on the stream member owing least, of the bulk
  route's wire while it has one up. The client's end is the FIN.
- The exit's chunks are put in order (`hikkari_trunk::stream::Recv`: chunks past a hole kept inside the window) and
  written to the client at once; what the client does not take waits for it. Each chunk is acked on the member it came
  on (`got` names it), and the freed window is told by a quarter. The exit's FIN shuts the client's side once everything
  before it is written. A stream ends when both FINs are confirmed and written; a reset either way ends it at once.
- Stream members (`link.rs`) are the pool's form: a t1 hello, frames one after another on a TCP connection of their own,
  pings when idle a second, deaths by the same rules as any member's (`trunk/src/health.rs`: a member owes while it
  carries an unconfirmed open, chunk or FIN). A member's connection is plain TCP to the exit's member port, as the bench's
  Go entry dials its pool, or Chromium's CONNECT tunnel to the exit's relay (R2.1, below).
- A member that dies (`pipe/death.rs`, trunk dropMemberLocked) resets no stream: the opens, chunks and FINs it carried
  unconfirmed wait in their streams and go again on the other members, oldest first (by stream id, then as each was
  sent) and ahead of any new chunk, a chunk only on a member under 256 KiB unconfirmed. A stream keeps the bytes of its
  unconfirmed chunks for this (`hikkari_trunk::stream::Kept`, at most the window). Every stream acks again elsewhere,
  since the acks the member carried may be lost, and again on each member that comes up. The stats line counts
  `hit` (a stream's things on a member that died) and `resent` (chunks sent again). Chunks that reach the exit before
  their open are the exit's to hold (the Go exit does, trunk holdEarlyLocked).
- Nothing is allocated per chunk: members' buffers are allocated once (out 1 MiB, in 256 KiB), a client's waiting bytes
  and a stream's unconfirmed bytes in one buffer each that grows to what it holds; chunks past a hole are the only
  copies made per chunk.

Left out on purpose: the port book and replacing members spread over a second (R2.3), the brain's messages for client ports of streams and stream wires (the bench runs them by flags), datagrams on stream members (they
ride the packet wires), wires other than `udp` and the plain TCP members, drains and generations, observation, IPv6, GSO
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
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags with_purego -o ../out/goentry ./goentry && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/goexit ./goexit)
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/run.sh 3 30 "1 4 16 64" "go rust rustev"
```

The entry runs on CPUs 0–1 (`taskset`), the users and the exit on CPUs of their own; `hk-loadgen` reads the entry's CPU
from `/proc/<pid>/stat` at the start and the end of its window.

Streams (R1.3): `bench/tcp.sh` runs `tcpcheck` clients through the Go entry (`goentry -tcp-listen`: each connection
carried by `Session().Carry`, as hikkari-control trunkentry does) and through `hk-pipe --tcp-listen`, both over 4 plain
TCP members to the same Go exit, whose streams reach an echo (`tcpcheck -serve`). Each stream sends its own PRNG bytes
and reads the echo back, every byte compared; the line has the entry's CPU per MiB sent (each MiB crosses the entry
twice, up and echoed down).

```bash
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/tcpcheck ./tcpcheck)
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/tcp.sh 3 "go rust" 1073741824 1 4
```

Members cut under the streams (R1.4): with `CUT=rst` (the member's socket fails) or `CUT=freeze` (it goes silent and
dies by its stall) the members go through `tcpcheck -proxy`, which cuts the busiest member every `CUT_EVERY` (3 s).
`PIPE=/bench/out/<build>` runs another `hk-pipe` build as `rust`.

```bash
docker run --rm -e CUT=rst -v "$PWD/bench:/bench" debian:bookworm-slim /bench/tcp.sh 3 "rust go" 1073741824 1 4
```

Both paths at once (R1.5): `bench/mixed.sh` runs the UDP users through an entry while clients' streams download through
the same entry (`tcpcheck -for`, at `-rate` bytes a second per stream or as fast as they go), the Go entry against
`hk-pipe`, to the same Go exit. Each load on CPUs of its own outside the entry. `bench/mixed_summary.py` gives per load
the price of a user's packet (runs without a download) and the CPU a download adds per MiB, with the voice gaps.

```bash
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/mixed.sh 3 30 "16 64" "go rust" "none rate flood"
python3 bench/mixed_summary.py bench/out/results-mixed.txt
```

## The exit (R1.6, R1.7)

`hk-exit` is the cascade exit, as `trunk.Exit` over `trunk/udpwire` and the pool's port is, one thread, no runtime, on the
same loop as `hk-pipe` (a tick of 1 ms under traffic, `recvmmsg`/`sendmmsg`, nothing allocated per packet once a flow is
open):

- One socket per wire, a member per entry address (udpwire Listener). An address's first datagram that opens under one
  of the wire's keys (the brain hands udpwire.Key of each trunk key, never the trunk key) makes it a peer; anything else
  is dropped unanswered. A packet member's t2 hello joins it to the session its id names (made on the first such hello,
  its epoch random), and is answered in kind with the session's epoch in a datagram of its own, every copy again. A
  hello on a wire without the packet flag, or with the streams flag, gets no answer: stream members come on the pool's
  port.
- Members' health is the entry's (`trunk/src/health.rs`, judged per session): a ping every 100 ms on the members' clock of
  25 ms, a member owing past its stall dies while another member of its session proved the entry alive, every member
  silent dies only after Quiet (30 s, `trunk.ExitQuiet`: the exit cannot open members and waits for the entry to), and
  the exit's own pause (a turn more than 100 ms late) restarts every debt. A dead member is forgotten: a datagram from
  its address later is a new peer, which must say its hello first (udpwire peer.Close). An address silent 2 minutes is
  forgotten (udpwire PeerIdle), a session without members for 2 minutes ends with its flows (trunk SessionIdle).
- A flow is a stream id of a session (trunk flows.go on the exit): its first datagram opens a UDP socket of its own to
  127.0.0.1:port, if the brain opened the port to the trunk (the edge's trunkLocal.DialFlow), watched by epoll; port 0
  is the trunk's call, answered straight back with no socket. Copies are dropped by the entry's seq in a window of 1024
  (`trunk/src/flow.rs`). The answers go as the entry sends: on one member until a copy arrives, then on 2, on the
  members the flow last came on while they are up, else on the session's members of the flow's wire, else any. A socket
  that fails ends its flow; a flow unused 2 minutes ends.
- Every frame bound for one member in a tick (answers, pongs, pings) is glued into one sealed datagram of up to about
  1200 bytes, as the entry glues its way up; the Go exit sends a datagram per frame (`writePackets`). The entry's packet
  members read a frame sequence per datagram, so nothing changes for them but the count of datagrams.

Streams (R1.7; spec/trunk.md, "Streams", as the Go exit's session carries them: openLocked, dataLocked, finLocked,
ackedLocked, holdEarlyLocked, endStreamLocked, readLocal, writeLocal; the exit's mirror of the entry's R1.3 and R1.4):

- Stream members connect to the pool's port (plain TCP here, as the bench's Go exit takes its pool; Chromium's TLS under
  them is R2). The first frame is the hello, within 5 s of the connection (trunk helloTimeout): a t1 hello (the pool's,
  wire 0) or a t2 one with the streams flag joins the session its id names, the same sessions as the packet members, and
  is answered in kind with the session's epoch. Members of either kind prove the entry alive for each other. Their health
  is any member's (`trunk/src/health.rs`, on the members' clock; Quiet 30 s); a connection that fails or ends is `gone`.
- The entry's open names a stream id and a loopback port: the exit connects to 127.0.0.1:port if the brain opened the port
  to the trunk (port 0 is the trunk's own download, `trunk sourceConn`: 8 bytes ask for n, n zero bytes back, then the
  end), else the stream is reset; a connect that fails resets it too. A copy of an open is acked again, an open of a
  stream that ended in the last 2 minutes is reset. Chunks and FINs that come before their open are held (1024 streams,
  a stream's window, 64 MiB in all, 30 s) and given to the stream at its open.
- The entry's chunks are put in order (`hikkari_trunk::stream::Recv`), written to the local end at once, the rest kept
  for when it takes more (`hikkari_trunk::buf::Behind`); each chunk is acked on the member it came on (`got` names it),
  the freed window told by a quarter, the entry's FIN passed on once everything before it is written.
- The local end's bytes are read straight into a member's out buffer behind a chunk's head (`hikkari_trunk::buf::Out`,
  the same buffer as the entry's), as far as the entry's credit and the member's room go, on the member owing least of
  the wire the entry last sent the stream on; the local end's end is the FIN. A member that dies with unconfirmed chunks
  or a FIN: they go again on the others, oldest stream first, ahead of anything new, and every stream acks again
  elsewhere. A stream ends when both FINs are confirmed and written; a local end that fails resets it on 2 members.
- Stream sockets (the pool's, members', local ends') are one epoll, edge-triggered: what it reports is kept on each socket
  and the loop reads and writes it until it would block or nothing can go (no credit, no member with room). Nothing is
  allocated per chunk: a member's buffers are allocated with its slot (out 1 MiB, in 256 KiB) and kept for the next.

The brain is the edge process (keys from the hub, the ports open to the trunk; later observation and generations); its
side is `trunk/pipectl` `StartExit`, `Exit.SetWire` (the wire's socket by `SCM_RIGHTS`, its keys, stall, Quiet, glue),
`Exit.SetPool` (the pool's listening socket, stream members' stall and Quiet), `Exit.SetPorts`, `Exit.Tick`. The messages
are `exit/src/ctl.rs` (version 2), both sides hold the same golden bytes:

| Message | What |
| --- | --- |
| brain `hello` | version |
| brain `wire` | id, form (`udp`), glue window and size, members' stall (dead_ms), Quiet (quiet_ms), the wire keys; one socket |
| brain `ports` | the loopback ports open to the trunk (flows and streams); replaces the set before |
| brain `pool` | members' stall (dead_ms), Quiet (quiet_ms); one socket: the pool's listening TCP socket |
| exit `hello` | version, pid |
| exit `tick` | once a second: its latest pause, pauses, the latest turn past due, sessions, packet members up, clients' flows, stream members up, streams open; since the start members joined, buried by their stall, by Quiet, gone (a packet member's address idle, a stream member's connection), the clients' datagrams sent, delivered, copies dropped, flows ended idle, datagrams refused (a port not open, a relay that refused), sealed datagrams in and out, frames out, bad, dropped; streams opened, ended by FINs, reset by the entry and here, member deaths that hit a stream, chunks sent again, bytes up and down, early frames held and dropped, opens refused, datagrams that came on stream members |
| exit `error` | a message it could not take |

Left out on purpose: datagrams on stream members (the Go entry's pool may carry them; they are counted in the tick as
`link_dgrams` and dropped, R2 carries them), drain and generations (R4), `observe` (the relay's marks of a tester's flow,
and the edge's tracking of each flow's and stream's connection), IPv6, the pool's Chromium wire (R2), the edge's own use
of it (R5).

Tests against the Go side, on the Go exit and the Rust exit alike (`trunk/pipectl`): the health scenarios with the pipe as
the entry (`health_linux_test.go`) and with the Go entry (`exit_health_linux_test.go`: a member cut alone buried once at
each end, a path held 700 ms buries nothing, a path cut ends the entry's members by Quiet while the exit keeps them, the
exit's own pause buries nothing), datagrams counted as by the Go exit (`dgram_linux_test.go`), a port not open to the
trunk answered nothing (`TestAPortNotOpenToTheTrunkGetsNothing`); streams through either entry (`stream_exit_linux_test.go`:
4 streams of 8 MiB byte for byte, a stream of 32 MiB while the busiest member dies twice by rst or freeze) and frame by
frame (`stream_raw_linux_test.go`: a chunk and FIN before their open held, an open to a shut port reset). `HK_EXIT` names the exit's binary as `HK_PIPE` names
the entry's:

```bash
cargo build --release --target aarch64-unknown-linux-musl
cp target/aarch64-unknown-linux-musl/release/hk-pipe target/aarch64-unknown-linux-musl/release/hk-exit bench/out/
(cd ../trunk && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o ../rust/bench/out/pipectl.test ./pipectl)
docker run --rm -v "$PWD/bench:/bench" -e HK_PIPE=/bench/out/hk-pipe -e HK_EXIT=/bench/out/hk-exit debian:bookworm-slim /bench/out/pipectl.test -test.v
```

The bench with the Rust exit: `EXIT=rust bench/run.sh ...` (the line adds the exit's CPU, `exit_cpu_pct`); streams:
`EXIT=rust bench/tcp.sh ...` (`hk-exit --pool 127.0.0.1:20446 --ports 9000`; the line adds the exit's CPU per MiB,
`exit_us_per_MiB`, for either exit). `HK_EXIT=/bench/out/<build>` runs another `hk-exit` build.

```bash
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/tcpcheck ./tcpcheck)
docker run --rm -e EXIT=rust -v "$PWD/bench:/bench" debian:bookworm-slim /bench/tcp.sh 3 "go rust" 1073741824 1 4
docker run --rm -e EXIT=rust -e CUT=rst -v "$PWD/bench:/bench" debian:bookworm-slim /bench/tcp.sh 3 "rust go" 1073741824 1 4
```

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
| `drain` | the old end of a reload's handoff socket (one): the pipe takes no new client (below, «Generations») |
| `adopt` | the new end of a handoff socket (one): an older pipe drains to this one; it comes before the client ports |

Pipe → brain:

| Message | What |
| --- | --- |
| `hello` | version, pid |
| `tick` | once a second, and at once after a member event: the pipe's latest pause (a turn of its loop more than 100 ms after the one before), pauses, the latest turn in the second, clients' flows open; since the start, as trunk Stats (the trunk's call left out), datagrams out, delivered, copies dropped, and flows ended unused; per wire members, up, owed (the least debt of its up members), when one last heard the exit, round trip, packets and bytes each way, sealed datagrams, drops |
| `member` | a member up (hello answered) or down: `silent` (past its stall while another member proved the exit alive), `quiet` (every member silent past Quiet), `gone` (its socket failed) |
| `dgram` | an answer on a brain's flow |
| `error` | a message the pipe could not take |
| `drained` | a pipe draining carries nothing more: no client's flow, no stream |

Left for later: `ceiling`, `observe` (the exit's marks of a tester's flow), IPv6, the forms other than `udp` (R4) and streams with the pool (R5). The pipe passes over a wire with no member
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

## Chromium members (R2.1)

`hikkari-cronet` puts a stream member on Chromium's network stack, as `trunk/chromium` does for the Go entry: the same
cronet build (sagernet's, Chromium 150 here), loaded at run time from `libcronet.so` (`--cronet`, else the executable's
directory, else the dynamic linker's paths). A wire's members share one engine and its one network thread (`Engine`,
R2.2), as cronet-go `NaiveClient` with `concurrency` on a single engine: each member's CONNECT carries an isolation key
of its own (`-network-isolation-key`), so Chromium gives it a TCP connection and an HTTP/2 session of its own, never
pools two members on one and never resumes one member's TLS session in another's hello. The engine is set up as
`NaiveClient.startEngine` sets it (HTTP/2 without QUIC, its windows and socket pools), its exit's domain mapped to the
exit's address (`HostResolverRules`) and its DNS client pointed at loopback, so no name is looked up. The stream is the
CONNECT of `trunk/chromium`: `-connect-authority trunk.hikkari.arpa:443`, the `padding` header, `proxy-authorization` of
the trunk key; the first 8 writes and reads each way carry Naive padding (`hikkari_trunk::naive`).

A member's TCP socket is the pipe's: the loop connects it to the exit from the member's port without waiting
(`sys::member_connect`: Nagle off, Go's keepalive), polls it for writing like any socket, and once it is up hands it to
the engine (`link::Link::promote`). The engine's dialer (`Cronet_Engine_SetDialer`) only takes that socket from a
hand-over slot and refuses anything else; the keeper thread starts one member's stream at a time and waits until the
dialer has taken its socket, so a socket always goes to its own member's stream, and a stream that asks for no socket
(it found a connection to reuse) fails the member. A path that does not answer holds no thread: the member is still
connecting when its hello wait ends. A member that goes down has its stream canceled and its connection shut down
under Chromium (the member keeps a duplicate of the descriptor), so its session ends with it.

The pipe's loop never waits on the library. A member's bytes cross in two buffers, one read and one write outstanding
as the stream API allows; cronet's network thread rings the member's eventfd when a read or a write is done or the
tunnel came up or failed, and the loop polls that eventfd as it polls a socket (`link::Sock`). The engine is started
and shut down, and the streams begun and ended, on one thread of their own (`keeper`), since an engine's start and
shutdown block. A relay that answers other than 200 (a wrong key gets its site) is a failed member.

libcronet is a glibc library, so the pipe that loads it is built for `aarch64-unknown-linux-gnu`, in docker on the mac;
the bench's box is Debian. The Go exit's `-naive` is the relay's stream channel for pool members (as the Go
`trunk/chromium` test's exit: TLS for `hk.example`, HTTP/2 CONNECT behind the key, padding, `trunk.Exit.ServeMember`);
it writes its certificate to `bench/out/naive-roots.pem` and logs each tunnel with how many hellos carried GREASE
(Chromium's do, Go's TLS never).

```bash
docker run --rm -v "$PWD/..:/src" -v "$HOME/.cargo/registry:/usr/local/cargo/registry" -e CARGO_TARGET_DIR=/src/rust/target/gnu \
  -w /src/rust rust:1.97.1-bookworm cargo build --release -p hikkari-pipe
cp target/gnu/release/hk-pipe bench/out/hk-pipe-gnu
cp "$(go env GOMODCACHE)"/github.com/sagernet/cronet-go/lib/linux_arm64@*/libcronet.so bench/out/
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/goexit ./goexit)
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/tcp.sh 3 "rust chromium" 1073741824 1 4
```

R2.2, a wire's members on one engine (`bench/members.sh`): the Go exit with `-naive-hellos` writes every member's
ClientHello whole; `gomember` (the Go entry's `trunk/chromium`, an engine each) gives the reference hellos, then
`hk-pipe` brings up 32 members, carries the bytes, and `hellocheck` names both sets by the client release test's hk and
ja4 (`bench/go/hello`, a copy of the client's parser, hk h1) and fails unless every member's hello is the reference's.
`CUT=rst` or `CUT=freeze` with `tcp.sh` cuts Chromium's members too (the proxy in front of the relay channel).

```bash
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags with_purego -o ../out/gomember ./gomember \
  && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../out/hellocheck ./hellocheck)
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/members.sh 32 1073741824 1
docker run --rm -e CUT=rst -e CUT_EVERY=1s -v "$PWD/bench:/bench" debian:bookworm-slim /bench/tcp.sh 1 chromium 1073741824 16 32
```

## The members' ports, their deaths, datagrams on the pool (R2.3)

A stream member's connection goes from a source port of the pipe's book (`hikkari_trunk::ports::Book`, trunk
`PortBook`; `--ports lo-hi`, 20000-32767 without it): the free ports are a list, a take one random index into it, a dead
port comes back an hour after its last kill from the head of a queue, and a book with nothing free answers at once
(the member waits as on a failed dial). A port whose bind finds it busy (a connection of ours still in `TIME_WAIT`) goes
back and another is tried at once. A member's port is killed when the member stalls (hikkari_trunk::health) or its
connection or hello gets no answer within 5 s; it goes back to the book when its connection closes, still dead if
killed. The wait before a member is dialed anew is trunk `Entry.slot`'s: a stall dials again at once (after 3 in a row
the wait grows), a dial or hello that failed and a member that lived under 5 s grow it from 200 ms to about 6 s, a
member that lived longer dials again at once; every redial is spread over a second on top (`replaceSpread`).

A datagram may ride stream members (spec/trunk.md, "Datagrams": the members carrying least): the route or pin names the
pool's wire, or the wire it named has no member up. Of the members it may go on, it takes the Copies carrying the
fewest unconfirmed bytes (a packet member carries none), ties by the flow's rank, so a flow keeps to its members while
the load is even (`carry::on_least`); a member whose out buffer is full drops it. The exit's answers on a stream member
go to the client as any wire's. With `--members 0` the pipe has no packet wire and its datagrams ride the pool.

`bench/pool.sh` puts the bench's users on the pool alone, the Go entry (`goentry -members 0 -pool-chromium`, an engine
per member, its ports from trunk's book) against `hk-pipe-gnu --members 0 --tcp-chromium`, to the Go exit's relay
channel; with `CUT=rst` or `CUT=freeze` the members die under the users and come back on new ports.

```bash
(cd bench/go && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags with_purego -o ../out/goentry ./goentry)
docker run --rm -v "$PWD/bench:/bench" debian:bookworm-slim /bench/pool.sh 3 30 "4 16 64" "go rust" 32
docker run --rm -e CUT=freeze -e CUT_EVERY=2s -v "$PWD/bench:/bench" debian:bookworm-slim /bench/pool.sh 3 40 16 "go rust" 32
```

## Generations (R4)

A reload of the entry replaces its pipe without a cut (spec/trunk.md, "An entry's own process replaced"; the Go entry's
generations, hikkari-control trunkentry `handoff.go`, are the reference). The brain starts the new pipe, gives it its
wires and waits for its members, then makes one `SOCK_SEQPACKET` socket for the reload (`pipectl.HandoffLink`): its new
end goes to the new pipe with `adopt`, the client ports (the same sockets) after it, its old end to the old pipe with
`drain` (`Pipe.Handoff` does all three in one brain; across two brain processes the ends travel as inherited files). The
messages between the pipes are `pipe/src/handoff.rs`, the loop's part `pipe/src/pipe/generation.rs`:

- The old pipe stops reading the client ports and stops accepting, and sends `own` (every address its flows are for, many
  to a message), then `all`. The new pipe reads no client port before every older pipe it adopted said `all`; the datagrams
  wait in the shared socket meanwhile.
- The new pipe sends a datagram of an address an older pipe owns to that pipe (`dgram`), a message per segment; the old
  pipe carries it on its own session and members, and answers out of the shared socket. A flow stays with its pipe until
  it ends unused; then the old pipe sends `free`, and a datagram it was handed for a flow it no longer has goes back in
  the `free`, which the new pipe carries itself. A stream stays with the pipe that accepted it.
- An old pipe with no client's flow and no stream says `drained` to its brain once (on its second's tick); the brain ends
  it then, or at its limit. An older pipe gone (its socket closed) gives every address it held to the new one: the next
  datagram opens a flow there. A newer pipe gone makes the old one read its clients again.
- The ownership check costs the new pipe one lookup per client datagram while an older pipe owns any address, nothing
  otherwise; the handed datagrams are one message each way, only for the old pipe's flows and only while it drains.

Tests against both exits (`generation_linux_test.go`): `TestAReloadUnderACallPausesItNoMoreThan150ms` (a call through the
reload: no pause over 150 ms, nothing lost; a call after it is the new pipe's; the old one drains once the first hangs up,
whose next call is the new pipe's), `TestAnOldPipeGoneGivesItsAddressesToTheNewOne`.

Left for later: the brain's messages for TCP client ports (under the brain the pipe has UDP client ports only: TCP is the
bench's flags, so a reload of streams is not tested), the exit's drain (`drain` frame 10: the pipe ignores it, so a reload of
the exit's relay keeps the old session until the exit's old process leaves), and the Rust exit's own generations.
