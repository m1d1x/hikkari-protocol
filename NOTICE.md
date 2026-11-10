# Sources carried into this repository

| Path | Source | Revision | License |
| --- | --- | --- | --- |
| `wire/datagram/` | [sagernet/sing-quic](https://github.com/SagerNet/sing-quic) `hysteria2/` | `v0.7.2-0.20261002084117-75c3ac4fa12b` | GPL-3.0-or-later, [LICENSE.sing-quic](wire/datagram/LICENSE.sing-quic) |
| `server/naive/` | [m1d1x/forwardproxy](https://github.com/m1d1x/forwardproxy) branch `hikkari` (klzgrad's Naive fork of caddyserver/forwardproxy) | `30cd3e5` | Apache-2.0, [LICENSE.forwardproxy](server/naive/LICENSE.forwardproxy) |

Changes against the sources:

- `wire/datagram`: realm (NAT punching), gecko obfuscation, port hopping and Brutal congestion control removed; BBR always; the server roster is swapped atomically (`UpdateUsers` raced with authentication). `OnAuth` on both sides hands the admitted QUIC connection to v1.04 observability.
- `server/naive`: Caddyfile support removed (JSON config only); the Caddy module is `http.handlers.hikkari_proxy`; `ContextKeyDial` moved to `connect/`.

Libraries, not carried: Chromium's network stack (`sagernet/cronet-go`, used by the client engine), QUIC (`sagernet/quic-go`, `sagernet/sing-quic` for TLS glue and BBR), Caddy (`m1d1x/caddy`).
