# Hikkari protocol

One protocol, one credential, one host and port, two channels:

```
TCP ─► stream channel: tcp/443, HTTP/2 CONNECT through Chromium (Naive), Naive padding
UDP ─► datagram channel: udp/443, QUIC + HTTP/3 auth, UDP as QUIC DATAGRAM
    └► when the datagram channel does not connect: UDP-over-TCP inside the stream channel
```

Wire description: [spec/v1.md](spec/v1.md).

## Layout

| Package | What |
| --- | --- |
| `client` | the choice between channels (fallback, retry, network change) and the datagram client |
| `server` | the datagram channel, UDP-over-TCP, the exit policy and admission interfaces a relay implements |
| `server/naive` | the stream channel's server: a Caddy handler (own module, so the client side never pulls Caddy) |
| `wire/datagram` | the datagram wire (Hysteria2 framing), carried from sing-quic |
| `connect` | the hand-off between the CONNECT front and handlers before it |
| `trunk` | the cascade's trunk between our entry in Russia and a relay abroad, both ends ([spec/trunk.md](spec/trunk.md)); own module (utls, x/net), no client uses it |

Users: the relay (`hikkari-control/edge`) imports `server`, `server/naive` and `trunk`; the client engine (`m1d1x/sing-box-lx`, outbound `hikkari`) imports `client` and builds the stream channel from sing-box's Naive outbound (cronet).

## Tests

```
go test -race ./...                  # datagram channel loopback, client fallback
cd server/naive && go test ./...     # Naive proxy; needs Linux loopback aliases (127.0.64.51 …)
cd trunk && go test -race ./...      # trunk: pool, killed members, one-way death, datagrams
```

The end-to-end test with the real Chromium client lives in `hikkari-control/edge` (`HIKKARI_TEST_CORE`).

Sources carried in and changes: [NOTICE.md](NOTICE.md). License: GPL-3.0-or-later.
