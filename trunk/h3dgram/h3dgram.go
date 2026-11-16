// Package h3dgram is the form of the trunk's Chromium QUIC wire
// (spec/trunk.md, "Wires": h3dgram): a member is one QUIC connection with
// one CONNECT-UDP (RFC 9298) whose proxy-authorization carries the token of
// a trunk key, and its datagrams are HTTP Datagrams (RFC 9297) of the frames
// of one write. The wire's ends are Rust (rust/exit h3wire.rs, the entry's
// pipe over Chromium's QUIC); here is what the Go brain gives them: the
// token of each trunk key, and the header it goes in. The Rust side is
// hikkari_trunk::h3dgram, which holds the same golden bytes.
package h3dgram

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
)

// TokenSize is a token's size, raw; it goes in hex.
const TokenSize = 32

// PathPrefix is RFC 9298's default template, before {host}/{port}/.
const PathPrefix = "/.well-known/masque/udp/"

// Token is the wire's token for a trunk key: HKDF-SHA256(trunk key,
// "hikkari trunk h3dgram wire").
func Token(trunkKey string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(trunkKey), nil, "hikkari trunk h3dgram wire", TokenSize)
}

// Authorization is the proxy-authorization value that carries token t.
func Authorization(t []byte) string {
	return "Bearer " + hex.EncodeToString(t)
}
