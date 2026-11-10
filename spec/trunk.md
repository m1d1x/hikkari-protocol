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
