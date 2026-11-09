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

The entry's first frame on a member is hello with its session id (random per entry run) and a zero epoch; the exit answers
hello with the same id and the epoch of its session (random per exit session). An epoch that changes under a session means the
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
owes progress and proves none for max(300 ms, 4 × smoothed RTT) is dead: closed, its chunks sent again on the other members
oldest first as they have room (256 KiB unconfirmed per member), its source port kept out of use for an hour, and a member
on a new port opened at once. An idle member is pinged every second.

## Datagrams

A flow is one client UDP association (entry: one client address on one listened port; exit: one socket to the loopback port).
Every datagram goes as a dgram frame on the 2 members carrying least; no ack, no resend. The receiver drops copies by `seq`
in a window of 1024. A flow ends after 2 minutes unused.

A flow whose sender already copies its datagrams goes on one member: Hikkari v1.02 sends a call over both its channels, and a
second copy on the trunk would make four of every packet. The entry chooses per listened port (the hub sets one copy on ports
that reach the exit's Hikkari relay). The exit answers a flow as the entry sends it: on one member until a copy of the flow's
datagrams arrives, then on 2.
