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
| frag 12 | id u16, index u8, count u8, n u16, n bytes (packet members of the `h3dgram` wire only, "Wires") |
| copies 13 | (exit to entry; experiment, "Copies on demand") |
| adopt 14, adopted 15 | a flow or stream the entry's new process takes from its old one ("An entry's own process replaced") |

The entry's first frame on a member is hello with its session id (random per entry run) and a zero epoch; the exit answers
hello with the same id and the epoch of its session (random per exit session). The entry has no epoch: the first byte of
the one it sends carries its capabilities (bit 1: it reads observe frames; bit 2: it reads copies frames; bit 4: it may adopt, "An entry's own process replaced"), the rest is zero. An epoch that changes under a session means the
exit lost its streams: the entry resets its own.

Drain is the exit's process being replaced without a cut. The entry answers it once per session: a new session with a new
id and a full pool, which reaches the exit's new process, takes every new stream and flow once a quarter of its pool is up
(or after 10 seconds); until then the old session takes them, as the exit's old process still serves, and replaces none of
its members. Nothing new waits for a pool that is not there: the trunk's call goes on through the old session, and moves to
the new one when it takes over; the exit's new process numbers its answers anew, so an entry counts a flow's answers only
from members of its own session. Then the old
one is retired: it keeps its members, replaces none, and closes when it carries nothing more or after 30 minutes. An entry whose own process is being
replaced retires its current session the same way and opens no session after it, so a drain that reaches the old entry
process changes nothing: a process that takes no new clients has no use for a new pool. What an entry cuts when it stops
counts every session it has, the retired ones too.

An entry's own process replaced (a generation of its unit, trunkentry `handoff.go`; the Rust pipe's `drain` and `adopt`)
cuts nothing either. The new process gets the same client sockets and opens a session of its own. The old one stops
accepting and stops reading the shared UDP sockets, and first tells the new one every client address its flows are for; the
new one reads no client datagram before that list is whole. A datagram from such an address the new process hands to the
old one, which carries it on its own session; the answers go out of the shared socket from the process that holds the flow.
A flow the old process ends (2 minutes unused) it lets go: it lets the address go, and a datagram it was handed for a flow
it no longer has goes back to the new one with it, which opens the flow itself. An old process that carries nothing more
says so and leaves, at the latest after 30 minutes; one that is gone gives every address it held to the new one.

What the old process carries it hands over (owner's decision of 18.11: a rollout of the entry cuts no live flow; a
call begun before it was cut 30 minutes later, 17.11 20:40:52). A flow moves to the new process's session and keeps its
end at the exit: the same socket to the relay, which sees nothing. Once the new process's current session's exit said it
adopts (below), the new process says so to the old one, and the old one hands it every client flow it carries on a session
of its own (an older process's that drains through it stays that one's): the flow's client address, its session's id,
its stream id there, its port, class and copies, and the seq it got to. The new process opens the flow under a stream id
of its own on its current session and sends `adopt` for it on a member of its pool. Until the exit answers, the flow's
datagrams still go to the old process, and its answers come on whichever session the exit holds it on. On `adopted` the
new process tells the old one, which forgets the flow without ending it and says the seq it got to; the new process takes
the address and carries the flow from that seq on. A flow the exit does not adopt, or whose `adopt` has no answer after
3 tries 2 seconds apart, stays with the old process.

A stream goes over with its client's connection itself (the descriptor passed between the processes), so the client
sees no end of it. The old process freezes every stream with no FIN either way: it reads its client no more, and takes no
new chunk from the exit but one that fills a hole under chunks kept past it (the exit counts those as confirmed, so none
may stay behind). Once the exit confirmed every byte it sent and everything it got is written to the client, it hands
over the connection, its session's id, its stream id, its port, `up` (bytes read from the client) and `down` (bytes
written to it). One not ready within 5 seconds, or that met a FIN, stays with the old process. The new process opens the
stream under an id of its own, already open, its client not read, and sends `adopt`; on `adopted` it reads the client,
and the old process lets the stream go without an end. Refused or unanswered, it goes back: the old process goes on with
it, and the new one closes its copy of the connection.

| Frame | Fields |
| --- | --- |
| adopt 14 | kind u8 (1 stream, 2 flow), session id [16], stream u32 (its id there), stream u32 (its id here), up u64, down u64 (entry to exit; 0 and 0 for a flow) |
| adopted 15 | kind u8, stream u32 (its id here), ok u8 (exit to entry) |

The exit adopts a flow or stream only of a session of its own process, and the old session's id is the proof: only the entry that
opened that session knows it. It moves the flow or stream under the new id into the session `adopt` came on, and sends
on that session's members from then on; a flow's old id goes on reaching it until the old session ends, so what the old process sent
on it before it learned of the move is not lost. The flow's `seq` numbering and its answers' go on: the window of copies
at each end takes the next ones as it took the ones before. A stream's `up` must be what the exit received, in order and
with nothing kept past a hole, and it has no FIN from the entry; what it sent at `down` and after (the old process never
wrote it to the client) is owed again and goes on the new session, and an ack on the member `adopt` came on gives the new
process its credit. The old id of a stream ends with the move: the old process sent nothing on it once it waited for its
bytes to be confirmed. The answer is `ok` 0 for a kind it does not adopt, a session it does not have (the exit's process
was replaced since: the old session is an older process's), an id the old session does not have, or a stream whose `up`
does not hold. Adopting twice is adopting once. Neither end counts a flow or stream it handed over or adopted as cut.

An exit that predates adopt takes it for a torn frame and drops the member. So an entry that may send it sets bit 4 in its
hello's capabilities, and an exit that adopts answers the hello of such a member of the pool (or of another wire of
streams), right after it, with `adopted` of kind 0 (stream 0, ok 1). The entry sends `adopt` only on a session whose exit
said so; with an exit that never said it, the old process carries what it has as before.

An exit's own process replaced (the Rust exit's `drain` and `adopt`, R6.4; the relay's generations, edge `handoff.go`)
cuts nothing either, and is what sends the drain above. Every process of the exit holds the same sockets: each packet
wire's UDP socket and the pool's port. The old process sends drain on every member of every session it holds, and on
any member that joins it later; it stops reading the shared UDP sockets and stops accepting on the pool's port, and
first tells the new one every entry address its members of the bare UDP wire come from (an address it holds is its
own from the first datagram that opened, before the hello is answered). The new one reads no packet wire before every
older process said that list is whole. From then on a datagram of the bare UDP wire from an address an older process
holds, and a QUIC packet of the `h3dgram` wire whose destination connection id an older process issued, the new one
hands to that process, which takes it as one it read and answers out of the shared socket. Every connection id an exit
process issues names its generation, as the relay's do (the first byte is the second's XOR the generation, so the
first byte on the wire is as random as the rest); a packet of a connection id that is no exit's, or of the newest
generation, is the newest process's. A stream member stays with the process that accepted it. The old process lets an
address go when it forgets its member (dead, or silent past PeerIdle); a datagram it was handed for an address it no
longer holds goes back to the new one with it, which takes it as its own (a hello there makes a member of the new
process). The old process says when it carries nothing more (no client's flow, no stream; the trunk's call is no
client's); the one that started it closes it then, or after 30 minutes. One that is gone leaves every address it held
to the new one: a member there that says no hello carries nothing, dies by its health on the entry and is replaced.

## Streams

A stream is one client TCP connection to an exit loopback port, opened by the entry. Its bytes are numbered by offset; data
frames are chunks of up to 16 KiB on any member. The receiver answers every chunk with an ack on the member it came on:
`received` is how far it has every byte, `credit` how far the sender may send (bytes written to the local connection plus
the window, 2 MiB), `got` the offset of the chunk this ack answers (all ones for none). A chunk is confirmed by `got` or by
`received` passing its end. `fin` carries the final offset; the ack flag confirms it. A stream ends when both FINs are
confirmed and written; `rst` ends it at once.

The exit holds chunks and FINs of a stream whose open has not arrived (it left on a member that died) and takes them when it
comes. Late frames of an ended stream get `rst`. The entry opens every stream, so a chunk or FIN of a stream it does not
have is always late, however long ago it ended: it answers `rst` (an exit left holding a stream the entry reset, as at a
flip of epochs, would otherwise send its chunks again on every member and bury each for owing them).

## Members' health

A member owes progress while it carries unconfirmed chunks or an unanswered ping. It proves progress only by the confirmation
of its own chunks or the pong of its own ping: frames that merely arrive on it prove nothing about its way out. A member that
owes progress and proves none for max(300 ms, 4 × smoothed RTT) while another member proved progress after its debt began is
dead: closed, its chunks sent again on the other members oldest first as they have room (256 KiB unconfirmed per member), its
source port kept out of use for an hour, and a member on a new port opened within a second (replacements are spread over that
second, so members that die together do not come back as one burst). An idle member is pinged every second. The pipe also
keeps each pool's proof fresh at rest: when none of its members proved progress for 250 ms, and none owes a ping, carries a
chunk unconfirmed, has frames waiting to go or heard the exit in that time, the idle member that sent least lately pings at
once, so a pool at rest is told from a pool cut within a couple of seconds (the brain moves off a receiver whose pool alone
went unheard for 2 s) for a ping every 250 ms per pool, whatever its members. A pool carrying anything is proved by its
confirmations; a ping into its queue would only wait past its member's stall and bury the member.

When every member is silent at once, no member is to blame: the other end paused (a box starved of CPU by its neighbours) or
the whole path did. Then members die only after Quiet: 1 s on the entry, 30 s on the exit, which cannot open members and waits
for the entry to. A clock tick more than 100 ms late is the side's own pause: every member's debt counts from the end of it,
and the entry logs `trunk: paused <duration>`.

## Border points

An exit (the core: `hk-exit`, the relay, the keys) may be reached through border points, boxes that only forward the trunk's
ports to it (hikkari-client plans/2026-11-19-border-forwarders.md: nft DNAT and SNAT, no process, no key, no state of
anyone's). The core's own address, the exit its wires and pools are given with, may be one of the points or none of them: the
core may be out of the entry's reach (the egress that holds everyone's sessions, reached from Russia through the points
alone), and with points given no member dials it. The entry spreads the members of each wire over the points: member `i` of a wire goes
to point `i mod n` on the wire's port, pool and packet wires alike, under one session id. The exit joins every member to its
session by its hello, whatever address it comes from (a packet wire's member is an entry address and port, a pool's member a
connection), so nothing changes on the exit. A point that freezes or dies takes down its own members alone, by their health
as above; the others carry the session and every stream and flow on it, and a member down dials its own point again, as any
member does. A datagram's copies ("Datagrams") go to members at points it did not reach yet first, over every wire it goes
on, then to the others: a point that freezes holds one copy of it at most while another point is up, so a call with two
copies is not heard to pause. Nothing moves: there is no point to choose and no threshold. A Chromium member's TLS and QUIC are the core's
  (its certificate): the entry's socket goes to the point, and the engine uses that point's TLS name
  for SNI, certificate verification and the proxy origin. An unnamed point uses the core's name.
  TCP CONNECT and CONNECT-UDP still target the trunk, with the same trunk credentials.

The brain gives the points before the wires, so that no member dials the core's own address first; points given later move
every member to them. Points are the active receiver's (the pipe's receivers, rust/pipe/src/pipe/session.rs): a move to
another receiver drops them, a receiver on standby is reached at its own address alone, and a receiver that was reached
through points does not go on standby at its own address once another is active. Points given anew move only the members
whose point changed: each is closed (what it carried goes again on the others) and dialed to its new point after the spread
  alone, as is a member that was waiting to dial again: the backoff was its old address's.
  Changing a point's TLS name reconnects its TCP and H3 members under the same session id.
  Bare UDP members depend only on the point's address.

  The brain sends named points as local message 0x15 (count u8, then IPv4, name length u8, and DNS name
  per point). A zero-length name uses the core name. The address-only message 0x14 remains valid.
  A core configured for named points accepts each name only from that forwarding point, and its own name only
  from addresses that are not points (the hub's direct checks); from a point it may accept its own name during
  the transition. For H3 the exit wire's local message carries the original name,
  the transition flag and each point's address, name and certificate paths.

## Datagrams

A flow is one client UDP association (entry: one client address on one listened port; exit: one socket to the loopback port).
Every datagram goes as a dgram frame on every wire of its flow's set (Wires): on each wire on as many of its members as the
set says, no ack, no resend. All copies carry the flow's one `seq`; the receiver takes the first and drops the others by
`seq` in a window of 1024, whichever wire brought it. On a wire the members go round: each copy goes on the member of that
wire that sent last the longest ago, so a TCP member's resend holds up one datagram in N, not every one. A flow ends after 2
minutes unused.

One end may end a flow the other still keeps: when the way to it loses the flow's datagrams for 2 minutes while the other
end goes on sending (the entry's own call never stops, nor does a client in a call). Its next datagram opens the flow again
under the same id, and its count starts at 1. The receiver whose window stands a whole window (1024) past a `seq` below 1024
takes it as that new count and starts its window anew: without this every datagram of the new count is too old to tell and
dropped, for as long as the flow lives (aezamsk1 18.11: 126 s with nothing down, every call of the people's entry silent
after).

The copies on a flow's main wire are its own: 2 by default, one for a flow whose sender already copies its datagrams
(Hikkari v1.02 sends a call over both its channels, and a second copy on the trunk would make four of every packet). The
entry chooses per listened port (the hub sets one copy on ports that reach the exit's Hikkari relay). Such a port still gets
the set of two fates: the client's own copy goes inside its stream channel, TCP to the entry, and under a cut of UDP it
comes 95–166 ms late; it guards the client's leg, not the trunk's.

The exit answers a flow on every wire its datagrams came on in the last second; with none in that second, on the wire of the
latest. On each wire it answers on one member, and on 2 once a copy comes on that wire of a datagram that wire already
brought (the entry's copies there, not another wire's).

A member of the pool that carries dgram frames has Nagle off (`TCP_NODELAY`) at both ends: a voice copy is a small frame
every 20 ms, and with Nagle the kernel holds it until the last one is acknowledged. Each end sets it on a member that is a
TCP socket of its own; the entry's Chromium sets it on the pool's sockets, and the relay that hands the exit its members
accepts them on Go's TCP, which sets it on every socket.

### Copies on the pool

A write into a pool's member costs much the same for one frame as for many: on the entry each is an HTTP/2 DATA frame, a
TLS record, a `sendmsg` and a hand-over to Chromium's thread; on the exit the relay seals each write it is handed. So the
pool may carry the datagrams' copies on members of their own, written a window at a time (hikkari-client
`plans/2026-11-15-pool-copy-coalescing.md`). The wire's bytes do not change: a window is dgram frames one after another on
the member's stream, as any frames are, each with its stream, `seq` and port.

The entry sets K members of copies (the brain's `copies`, 4 of the pool's 32 by default; 0 is none, and copies go round
every member as above). A member of copies carries datagrams and its own pings and pongs, and a stream's frame only when no
other member is up. The copies of one window, W from the first of them (4 ms by default), all go on one member of copies
and leave in one write once the window is over, or sooner once they hold 16 KiB; the next window goes on the next member
of copies up. A member of copies that goes down leaves at the next window, and the member up that owes least takes its
place, so a copy never waits for a new connection. Any other frame on a member ends its window: what waits goes at once.

The exit holds its answers the same way, for its own window (the brain's `copy window`, 4 ms by default, 0 none), on a
member the entry never sent a stream's frame on (an open, a chunk, a FIN, an ack): the answers go where the flow's
datagrams came, so on the entry's members of copies.

A flow to port 0 is the trunk's own call (`call.go`): the exit sends every datagram straight back, with no socket, as it
came (one copy, or 2 once a copy arrives). The entry keeps one call with one copy and one with 2, both of the voice class on
its set (Wires), and one held to each wire, a datagram every 20 ms, and reports each minute of the wall clock: sent, answered within 2 s, round trips,
and the pauses between answers a call hears (over 60 ms and over 150 ms, the longest, the silence in all, the 5 longest with
their time). Neither end counts the call among its clients' flows and datagrams, and it never keeps a retired session open.
An exit older than this answers nothing on port 0: the call reports every datagram lost.

A call's datagram is its frame number (u64, big endian), then 8 bytes of the exit's stamp and 8 of its map, sent as zeros,
then padding to 64 bytes. Before it answers (`echo.go`), the exit writes into them its wall clock when the datagram arrived
(unix ns, u64) and which of the flow's last 64 frame numbers it has had (u64: bit i is frame n-i, n this datagram's; a frame
64 or more older than the newest one had is had alone). A datagram on port 0 shorter than 24 bytes, or whose stamp and map
are not zeros (another user of the echo), goes back as it came. The calls the entry keeps side by side tick together and number
their frames as one: frame n leaves on every wire at the same moment. An exit older than the stamp answers the zeros back,
and the entry hears no direction from it.

### Copies on demand (experiment)

hikkari-client `plans/2026-11-18-copies-on-demand.md`; off unless the brain turns it on (`B_DEMAND`, rust/README.md). The
voice class's copy of the other fate (the pool's) goes only while an end lost datagrams of a packet wire lately, not on
every datagram.

Each end judges a flow's holes among the datagrams that came on its packet wires (`hikkari_trunk::demand`): a seq under one
that came 20 ms ago that never came on a packet wire is lost, whatever the pool brought. The members of a wire go round and an
end reads their sockets a batch at a time, so a datagram may come after the next ones; 20 ms is past a turn of the loop.
The wire is losing when, over the last one to two spans of 200 ms, at least 2 datagrams due on packet wires were lost and at
least 1% of those due: a share, not a count, as the wire's own trickle (0.1%) over many people is many datagrams a second.
A loss that finds the wire losing starts the copies, or holds them, for the entry's hold (5 minutes, owner 18.11:
`demand::HOLD_NS`) from then; a cut comes in waves, and a pause in a wave shorter than the hold starts nothing anew.

The entry turns the copies on for its own losses (down): its copy on the pool makes the exit answer there too, as the exit
answers on every wire the flow's datagrams came on in the last second. For its losses (up) the exit asks with a copies frame,
at most every 100 ms, on the packet member that lost and on one stream member of the session; the entry holds the copies as
for a loss of its own. An entry that does not know the frame drops the rest of the datagram, so the exit sends it only to
an entry whose hello said it reads copies frames (bit 2). The hold is the entry's: the brain gives it (`B_DEMAND`, 0 is
copies always, as before the experiment); the exit only asks, and an entry holding copies always takes no notice.

### What a listener hears

The entry hears each minute as a listener with a jitter buffer would (`hearing.go`, hikkari-client
`plans/2026-11-15-live-udp-two-fates.md`, раздел 4). A listener plays frame n at the best one-way delay of the minute plus
its buffer; a frame that came later, or never, is a hole. Up is a listener at the exit: the delay is the exit's stamp less
the entry's send, a frame the exit's map says it had but whose answer was lost counts in time (its delay is not known), a
frame no answer told of is lost. Down is a listener at the entry, over the frames the exit had: the delay is the answer's
arrival less the exit's stamp. The two clocks are apart: taking the minute's best delay off every frame's takes their offset
with it. Each direction is heard with three buffers at once, 40, 60 and 100 ms (an application's own is not known and moves
by itself): holes (their share of the frames judged), runs of 2 holes or more (a syllable swallowed: one frame of 20 ms is
hidden by the codec), and bad seconds (3 holes or more and at least 6% of the second's frames: a robot voice).

A set of wires (the voice class over two fates) is heard from the calls held to its wires, with no datagram more: a frame is
in time if it came in time on one of them, against the best delay of the set. The set is the one at the moment each frame
left. For each other wire of the set the entry also reports how much later its copy came than the copy on the set's first
(the pool's behind the datagrams'), up and down, at p50, p95 and the most, over the frames both brought.

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

Every wire has a fate: what must break on the path for it to lose a frame (hikkari-client
`plans/2026-11-15-live-udp-two-fates.md`). `udp` is datagrams of IP on the path (the bare UDP wire, `h3dgram`, QUIC,
salamander), `tcp` is streams TCP sends again (the pool). The hub sets it in the wire's knobs as it sets the shape; a wire
that says none is `tcp` for the pool and `udp` for any other. The shape answers another question: which wires one rule
against one form takes together. On the night of 14.11 the path lost 15–20% of every UDP datagram and almost no TCP segment;
two copies on two members of one wire were lost together (5%), a copy on each fate lost almost nothing (0.3–0.8% heard
holes at a 60 ms buffer, hikkari-client `plans/research/2026-11-15-voice-night-lab.md`).

The entry routes three classes of traffic, by the listened port:

- voice (calls and other small live datagrams): a set of wires of different fates at once. The route names the main wire,
  where the flow's own copies go, and the entry adds one copy on the best wire of the other fate that has a member up; or
  the route gives the whole set: up to 4 carries, each a wire, its copies (0 for the flow's) and how long after the
  datagram they leave (a later copy on one wire misses the burst that took the first). TCP never carries voice alone while
  a wire of fate `udp` has a member up: a set of the pool alone gets one copy on the best such wire. With no such wire up
  the set is the pool alone, as any member.
- video (a client's video and screen, too big to copy): one wire, the route's, or voice's main wire when the route names
  none.
- bulk (streams and every other datagram): one wire.

A wire of a set, or the one wire of video or bulk, with no member up is passed over for the best wire of its fate that has
one and is not in the set yet, else left out; a flow with no wire left goes on any member that can carry it. Between wires
of one fate the best is the lowest id (owner's choice of 2026-11-15). The exit has no route: it answers a stream on the
wire the entry last sent it on, a flow on its set as it hears it (Datagrams). The trunk's call can be pinned to one wire:
then its datagrams go on that wire only, and are lost while it has no member, so the call hears the wire alone.

The entry chooses the route every second (the selector). A wire is red when it has no member up, or when every member has
owed progress for 500 ms while another wire proved the path alive in that time; a red wire is left at once. Every wire
owing together is a pause of the entry or a cut of the whole path: nothing is red for it and nothing moves. Nor is a wire
left while every wire is red, or within 10 s of a pause of the entry's own (its session's clock or the selector's tick ran
late): a box that was not run buries and owes on every wire, and which one comes back last is luck, not the wire. Such a
wire is held; while it has no member up, its traffic goes on any member that can carry it. Otherwise the
rank is slow. Bulk goes by its 1 MiB downloads over an hour (failures, then the median speed, then CPU), only on wires that
carry streams, and a wire takes it from the one that carries it only when it is a quarter faster at as few failures for 5
minutes.

Voice goes on a set of two fates (hikkari-client `plans/2026-11-15-live-udp-two-fates.md`, раздел 5): the route gives the
whole set, the best wire of fate `udp` as its main wire with the flow's copies, and the best wire of another fate with one
copy. A wire is ranked for voice by what a listener heard of its own call (the call pinned to it) in its latest minute, up
and down together at the 60 ms buffer (What a listener hears): fewer bad seconds, then fewer runs of 2 holes or more, then
fewer holes, then the shorter round trip at p50, two round trips within 50 ms of each other being equal. A wire whose exit
stamps nothing is ranked by what its call has: lost datagrams as holes, pauses over 60 ms as runs, over 150 ms as bad
seconds. A wire not heard yet ranks below every wire heard. A wire better than the one in its place takes it once it has
stayed better for 5 minutes; a red one is left at once for the next best wire of its fate. With no wire of fate `udp` to be
had, the main wire is the best of the others, and a wire of fate `udp` takes it back as soon as it is not red: one fate is
the fallback, not a rank.

The set grows at once and shrinks slowly. Each second, 1 s after it ends, the entry hears the voice set's calls as one
listener over that second's frames, against the best delays of every frame its calls still keep (the open minute and the
one in its grace), at the 60 ms buffer; a second is bad as in What a listener hears. After 2 bad seconds of the last 5,
voice gets one more copy on its main wire 10 ms after the first; it goes after 5 minutes with no bad second. A copy moves no
traffic, so there is nothing to hold it against. The set heard is the two fates' calls, not the copies: the third copy does
not hide the seconds that brought it.

Video goes on one wire. Its rank is the bad seconds its call heard at a 200 ms buffer over the last minute, judged second by
second as the set's, then the voice rank. It leaves its wire after 3 bad seconds of the last 5, for the best wire of another
fate (of any fate when there is none), the next frame on the new wire; a better wire takes it after 5 minutes. Video has no
copies: its frames left on the old wire may be lost.

For each class the chosen wire and the best other wire of another shape are kept warm, and every wire of voice's set.

The numbers are from the stand's night (11.11, 01:00–05:46 UTC, nekko-spb → unl1, the four candidate wires and the pool's
own call side by side), to be checked against the stand's full day and the peak:

- Red after 500 ms. A wire's own silence of 500 ms while another wire heard came 30 times on the pool (members dying)
  and 3 times on QUIC (820–840 ms, alone), never on the random-byte wires (none even of 300 ms). The entry's own pauses
  (the box not run on :x0) silenced every wire at once for 157–320 ms: nobody red. 1000 ms would miss the QUIC stalls
  and 22 of the pool's. A voice wire's death costs the call at most this long only if its other copy is lost too: the
  client's stream copy of a voice packet rides the bulk wire, of another shape.
- Voice margin 5, hold 5 minutes (voice was one wire until 15.11; the set keeps the hold, the margin went with the
  minutes ranked by pauses). Replayed over the night's minutes: with the bare UDP wire present, margin 3 moved
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

The Chromium QUIC wire (`h3dgram`, draft 2026-11-13, R6.2; hikkari-client `plans/2026-11-11-entry-hot-path-and-unit-economics.md`,
"Труба на Rust"): packet members whose datagrams are HTTP Datagrams (RFC 9297) of a CONNECT-UDP request (RFC 9298) over
HTTP/3, sent by Chromium's own QUIC stack on the entry, so the border sees what Chrome sends. Chromium uses the member's
QUIC session as its session to a site (`SessionUsage::kDestination`: packets of 1250 B, Chrome's to any site since early
2023), not as its session to an IP Protection proxy (`kProxy`: 1350 B, which a Chrome with ML-KEM sends to no one but
Google's proxies): owner's choice of 2026-11-14 (hikkari-client `plans/research/2026-11-14-h3dgram-wire-shape-research.md`).
The usage is a knob of the entry's wire (`destination` by default, `proxy`); nothing else on the wire differs, and the exit
takes both. A member is
one QUIC connection (TLS 1.3, ALPN `h3`, the exit's UDP port) carrying one CONNECT-UDP request: `:method CONNECT`,
`:protocol connect-udp`, `:scheme https`, `:path /.well-known/masque/udp/{host}/{port}/` (any target: the exit is the
trunk's end and opens nothing to it), and `proxy-authorization: Bearer <token>`, where the token is HKDF-SHA256(trunk key,
"hikkari trunk h3dgram wire"), 32 bytes in lower-case hex. Datagrams must be on in both QUIC (RFC 9221) and HTTP/3
(`SETTINGS_H3_DATAGRAM` 1). The exit answers a request with a known token `200` with `capsule-protocol: ?1`; any other
request on the connection is answered `404` as a site would, and a connection that never asks a CONNECT-UDP with a known
token carries nothing of the trunk. Capsules on the request stream are read and dropped.

An HTTP Datagram is the request stream's quarter stream id (varint), context id 0 (varint) and the frames of one write as
they are, not sealed: QUIC's TLS already keeps them, and the token proved the trunk key. A datagram with another context id,
or one for a stream that is no member, is dropped. The frames of one datagram are at most what Chromium guarantees one HTTP
Datagram of the member holds, whatever its packet number's length (R6.3): 1194 B in packets of 1250 B (`destination`),
1294 B in packets of 1350 B (`proxy`), that is the packet less a long header with the version, the exit's 16-byte and
Chromium's 8-byte connection ids, a 2-byte length and a 4-byte packet number, the 16-byte tag, the DATAGRAM frame's type
and the HTTP Datagram's 2-byte head. Chromium resets the request stream (and with it the member) on a datagram over the
room it has now, so neither end writes one over that limit. Live datagrams of clients (voice, games) fit; a client's own
QUIC packets do not: QUIC's Initial is 1200 B at least (RFC 9000, 14.1), Chrome's packets are 1250–1350 B.

A frame over the room is cut, not carried by another wire (owner's choice of 2026-11-14: what crosses the border is one
shape, Chromium's to a site, and a flow stays on its member's wire). The sender cuts the frame's bytes into `count`
pieces (2 to 4, as even as they go), each a frag frame: `id` the sender's count of cut frames on this member (u16,
wrapping), `index` from 0, and the piece. All pieces of a frame go on the same member, in order, each in a datagram that
holds it, glued with other frames like any frame; they wait and age in the member's scheduler as any frame does, so one
dropped there loses the frame. The receiver puts a frame together per member by `id` from its `count` pieces, and reads
it as the one frame it must be (a dgram frame; anything else is dropped as a torn frame would be). A member keeps at most
8 frames being put together; a frame not whole 150 ms after its first piece, or pushed out by a ninth, is lost and
counted. A piece seen twice is dropped. A frame that 4 pieces do not hold is dropped and counted, as udpwire drops a write
over its datagram. Only this wire's members cut frames: every other wire's datagram holds any client's.

The entry opens its members itself, not the brain (R6.3): one Chromium engine per wire, a CONNECT-UDP tunnel per member,
each in a network partition of its own, so no two members share a QUIC connection. A member's UDP socket is the entry's,
as a pool member's TCP socket is: bound from a port of the wire's book of source ports, connected to the exit and given
to the engine's UDP dialer, which refuses every other socket Chromium asks for; a dead member's port rests in the book
as a stream member's does. A tunnel closed under the member is its death (gone), as a closed socket is; a member dead by
its health closes its tunnel. Either way the entry opens a new member within the spread.

The member's end is its connection's: the request stream ending, the connection closing or the member dying by its health
closes both, and the entry opens a new member with a new connection. The exit's QUIC connection ids are random, 16 bytes.

How each end sends on a member's connection (the exit down, R6.2b; the entry up, R6.3): as the datagram channel of v1.05 (spec/v1.md, "the datagram channel
is a pipe"), since the wire carries only live datagrams whose senders run congestion control of their own. QUIC's window is
fixed by memory (64 MiB in flight, no pacing); the guard of v1.05 with its thresholds judges each half second of the
connection's sending from QUIC's own counts (bytes sent, lost and acknowledged, packets sent; the smoothed round trip for
the line's queue) and holds the connection to a rate only on real loss. The frames wait in the connection's scheduler, not
in QUIC's queue: the member's own frames (pings, pongs, the hello's answer, which goes in a datagram of its own) first,
then the flows' frames by deficit round robin, 1500 B a turn, over 32 buckets by stream id (a flow shares its bucket with
the flows of the same stream id modulo 32). Right before a datagram is made, a frame that waited over 150 ms is dropped,
the oldest first, and so is the oldest of a bucket holding 64 frames; each is counted stale. Up the entry does the same
above Chromium's own sender, which it cannot replace: the member's frames wait in the entry's scheduler of the same rules,
the guard judges each half second from the counts Chromium's network thread copies for it (bytes and packets sent,
packets lost, the smoothed round trip; lost bytes are the lost packets at the connection's mean packet), and a datagram
goes into the tunnel only while the guard lets it. The guard is the same at both ends, with the same thresholds, but for
one rule of the entry's alone: a half second of at least 100 packets whose smoothed round trip is 50 ms over the least
the connection has seen turns the limit on as loss does. Chromium's sender under the entry's guard keeps loss under the
tenth while the line's queue stays full, and that queue is the trunk's own; on a line a user shares with others, as the
client's and the relay's, the queue is often another's, and limiting by it starves live traffic (owner's choice of
2026-11-14).
