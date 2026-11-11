# Hikkari trunk wire (t1)

Status: written 2026-11-09, first deploy pending (hikkari-control `entry-box trunk-exit`, `entry-box trunk-entry`).

The trunk carries clients between our two boxes of the Russian cascade: an entry in Russia and a Hikkari relay abroad.
No client speaks it. A client talks Hikkari v1 to the entry's address as to any relay; the entry ends the client's TCP only
and carries its bytes, still the client's own TLS, to the exit, which hands them to its relay on loopback. What crosses the
border is the trunk's TLS, never the client's.

```
client ─TCP/UDP─► entry (RU) ═ pool of members ═► exit relay :443 ─► 127.0.0.1:<port>
```

## Member

One long tunnel over its own TCP connection and source port, as the stream channel's wire:

- TLS by Chromium's network stack (cronet, the build the client core links: package `trunk/chromium`), so the ClientHello,
  HTTP/2 and padding are the Hikkari client's own, not an imitation. One Chromium engine per member, its TCP socket dialled by
  the trunk from the source port the pool chose. The relay's certificate is checked against its domain.
- HTTP/2 `CONNECT trunk.hikkari.arpa:443`, `proxy-authorization: Basic base64("trunk:<trunk key>")`, the `padding` header,
  and Naive padding of the first 8 writes each way (`u16 length, u8 padding, bytes, zeros`).
- The relay serves a member only for a trunk key on `trunk.hikkari.arpa`. A trunk key on any other host, or a subscriber key
  on that host, is a stranger and gets what strangers get. A member reaches only the relay box's loopback ports the hub opened.

An entry keeps N members (default 32) to one exit; they form one session.

## Frames

Both ways, big-endian:

| Frame | Fields |
| --- | --- |
| hello 1 | `"HKT1"`, session id [16], epoch [8] |
| open 2 | stream u32, port u16 |
| data 3 | stream u32, offset u64, n u16, n bytes |
| ack 4 | stream u32, received u64, credit u64, flags u8 (1: FIN received), got u64 |
| fin 5 | stream u32, offset u64 |
| rst 6 | stream u32 |
| dgram 7 | stream u32, seq u32, port u16, n u16, n bytes |
| ping 8, pong 9 | token u64 |
| drain 10 | (exit to entry) |
| observe 11 | kind u8 (1 stream, 2 flow), stream u32, id u64 (exit to entry) |

The entry's first frame on a member is hello with its session id (random per entry run) and a zero epoch; the exit answers
hello with the same id and the epoch of its session (random per exit session). The entry has no epoch: the first byte of
the one it sends carries its capabilities (bit 1: it reads observe frames), the rest is zero. An epoch that changes under a session means the
exit lost its streams: the entry resets its own.

Drain is the exit's process being replaced without a cut. The entry answers it once per session: a new session with a new
id and a full pool, which reaches the exit's new process, takes every new stream and flow once a quarter of its pool is up
(or after 10 seconds); until then the old session takes them, as the exit's old process still serves, and replaces none of
its members. Nothing new waits for a pool that is not there: the trunk's call goes on through the old session. Then the old
one is retired: it keeps its members, replaces none, and closes when it carries nothing more or after 30 minutes. An entry whose own process is being
replaced retires its current session the same way and opens no session after it, so a drain that reaches the old entry
process changes nothing: a process that takes no new clients has no use for a new pool. What an entry cuts when it stops
counts every session it has, the retired ones too.

## Streams

A stream is one client TCP connection to an exit loopback port, opened by the entry. Its bytes are numbered by offset; data
frames are chunks of up to 16 KiB on any member. The receiver answers every chunk with an ack on the member it came on:
`received` is how far it has every byte, `credit` how far the sender may send (bytes written to the local connection plus
the window, 2 MiB), `got` the offset of the chunk this ack answers (all ones for none). A chunk is confirmed by `got` or by
`received` passing its end. `fin` carries the final offset; the ack flag confirms it. A stream ends when both FINs are
confirmed and written; `rst` ends it at once.

The exit holds chunks and FINs of a stream whose open has not arrived (it left on a member that died) and takes them when it
comes. Late frames of an ended stream get `rst`.

## Members' health

A member owes progress while it carries unconfirmed chunks or an unanswered ping. It proves progress only by the confirmation
of its own chunks or the pong of its own ping: frames that merely arrive on it prove nothing about its way out. A member that
owes progress and proves none for max(300 ms, 4 × smoothed RTT) while another member proved progress after its debt began is
dead: closed, its chunks sent again on the other members oldest first as they have room (256 KiB unconfirmed per member), its
source port kept out of use for an hour, and a member on a new port opened within a second (replacements are spread over that
second, so members that die together do not come back as one burst). An idle member is pinged every second.

When every member is silent at once, no member is to blame: the other end paused (a box starved of CPU by its neighbours) or
the whole path did. Then members die only after Quiet: 1 s on the entry, 30 s on the exit, which cannot open members and waits
for the entry to. A clock tick more than 100 ms late is the side's own pause: every member's debt counts from the end of it,
and the entry logs `trunk: paused <duration>`.

## Datagrams

A flow is one client UDP association (entry: one client address on one listened port; exit: one socket to the loopback port).
Every datagram goes as a dgram frame on the 2 members carrying least; no ack, no resend. The receiver drops copies by `seq`
in a window of 1024. A flow ends after 2 minutes unused.

A flow whose sender already copies its datagrams goes on one member: Hikkari v1.02 sends a call over both its channels, and a
second copy on the trunk would make four of every packet. The entry chooses per listened port (the hub sets one copy on ports
that reach the exit's Hikkari relay). The exit answers a flow as the entry sends it: on one member until a copy of the flow's
datagrams arrives, then on 2.

A flow to port 0 is the trunk's own call (`call.go`): the exit sends every datagram straight back, with no socket, as it
came (one copy, or 2 once a copy arrives). The entry keeps one call with one copy and one with 2, a datagram every 20 ms, and
reports each minute of the wall clock: sent, answered within 2 s, round trips, and the pauses between answers a call hears
(over 60 ms and over 150 ms, the longest, the silence in all, the 5 longest with their time). Neither end counts the call
among its clients' flows and datagrams, and it never keeps a retired session open. An exit older than this answers nothing on
port 0: the call reports every datagram lost.

## Observation

Testers are observed in full, other users not at all (owner's decision 10.11; hikkari-client
`plans/2026-11-10-hikkari-observability-plan.md`, этап 1б). Neither end knows whose a stream or flow is: the client's TLS
crosses the entry. The exit's relay knows the key. For a tester's key it marks the stream or flow its connection came by:
the exit draws a random observation id, reports the stream itself and sends `observe` on two members, only to an entry
whose hello said it reads them. Each end reports a marked stream or flow at the mark (what it did so far) and at its end:
bytes each way, chunks, chunks sent again, members that carried and that died owing it, the longest wait for a chunk's
confirmation, datagrams each way and copies dropped, how it ended. The entry adds its client's TCP numbers. The hub joins
the ends by the id. Every stream keeps these counters in memory for its own sake; one never marked is reported by neither
end.

## Wires (t2, draft)

Status: written 2026-11-11 on branch `stage4-wires`, not deployed; the set of wires waits for the owner's choice after the
stand (hikkari-client `plans/2026-11-11-trunk-wires-stage4.md`, step 1). Code: `wires.go`, `selector.go`.

A wire is a kind of member, not a session of its own: the pool is one wire, and members of other forms (QUIC streams, an
encrypted UDP socket, a tunnel) join the same session. A stream moves from wire to wire as it moves from a dead member to a
live one: its unconfirmed chunks go again on the other wire, with no new open.

A member of any wire but the pool says it in a t2 hello: `"HKT2"`, session id [16], epoch [8], wire u8, flags u8. Flags:
bit 1, the member carries streams; bit 2, it is a packet member. The exit answers in kind (the same wire and flags). The
pool's members keep the t1 hello, so an exit that predates t2 still serves them and refuses the rest as strangers.

A member without the streams flag carries datagrams and pings only: no open, data, ack, fin or rst goes on it, and one that
arrives there is dropped. A packet member sends every frame in a datagram of its own and reads one frame sequence per
datagram, both ways; its hello is said again every 250 ms until answered, and the exit answers every copy. It pings every
100 ms whether or not the last ping came back, owes progress from its oldest unanswered ping, a pong of any ping since
then is its proof, and its stall limit is the member's limit plus 100 ms: datagrams lost one by one do not kill it.

The entry routes two classes of traffic, each on a wire of its choice: voice (calls and other small live datagrams; by the
port, as one copy is chosen today) and bulk (streams and every other datagram). A wire with no member that can carry the
class is passed over for any member that can. The exit has no route: it answers a stream or a flow on the wire the entry
last sent it on. The trunk's call can be pinned to one wire: then its datagrams go on that wire only, and are lost while it
has no member, so the call hears the wire alone.

The entry chooses the route every second (the selector). A wire is red when it has no member up, or when every member has
owed progress for 500 ms while another wire proved the path alive in that time; a red wire is left at once. Every wire
owing together is a pause of the entry or a cut of the whole path: nothing is red for it and nothing moves. Otherwise the
rank is slow: voice by its call over 10 minutes (red minutes plus pauses over 60 ms, then the round trip at p99), bulk by
its 1 MiB downloads over an hour (failures, then the median speed, then CPU), and a wire takes a class from the one that
carries it only when it is better by a margin (5 heard pauses; a quarter faster) for 5 minutes. Bulk goes only on wires
that carry streams. For each class the chosen wire and the best other wire of another shape are kept warm.

The numbers are from the stand's night (11.11, 01:00–05:46 UTC, nekko-spb → unl1, the four candidate wires and the pool's
own call side by side), to be checked against the stand's full day and the peak:

- Red after 500 ms. A wire's own silence of 500 ms while another wire heard came 30 times on the pool (members dying)
  and 3 times on QUIC (820–840 ms, alone), never on the random-byte wires (none even of 300 ms). The entry's own pauses
  (the box not run on :x0) silenced every wire at once for 157–320 ms: nobody red. 1000 ms would miss the QUIC stalls
  and 22 of the pool's. A voice wire's death costs the call at most this long only if its other copy is lost too: the
  client's stream copy of a voice packet rides the bulk wire, of another shape.
- Voice margin 5, hold 5 minutes. Replayed over the night's minutes: with the bare UDP wire present, margin 3 moved
  voice twice in 4.6 h (to salamander for 9 minutes and back), margin 5 never, red minutes under voice 0 either way.
  Between QUIC and salamander alone, margin 3 and a 3-minute hold moved it 9 times, margin 5 and 5 minutes 3 times, and
  the minutes voice spent on a red minute were 7 and 6: moving between wires as good as each other buys nothing.
- Bulk margin a quarter. A 1 MiB download takes one or two round trips of slow start (QUIC 59–68 or 101–118 ms); the
  hourly medians were QUIC 127 and salamander 113 Mbit/s, while 12 MiB ranked them the other way (264 and 271). Within a
  quarter they are the same wire; no move over the night at 10, 25 or 50%.

The trunk's own download: a stream to port 0, held to one wire, carries 8 bytes (u64, the length asked, at most 64 MiB);
the exit answers it from the trunk itself, with no socket, with that many zero bytes and its end. The entry resets the
stream once it has them, or when it gives up: its last frames may wait for a wire that is gone. Neither the download nor
its reset counts among clients' resets. An exit older than this has no port 0 and resets the stream: the download fails.

The entry's wires can change while it runs: a wire taken away has its members closed (what they carried goes again on the
others), a new one comes up, a changed one (members, shape, form, or the knobs its dial is made from) is closed and comes up
anew. Only the current session and the one coming up open members.

The bare UDP wire (`trunk/udpwire`): packet members, a UDP socket of its own per member on the entry and one socket for all
on the exit, a member per entry address. A datagram is a 12-byte random nonce and the frames of one write sealed with
AES-256-GCM under HKDF-SHA256(trunk key, "hikkari trunk udp wire"). A datagram that opens under no trunk key is dropped
without an answer.
