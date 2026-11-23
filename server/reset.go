package server

// The datagram channel's stateless reset key shared by a group's relays
// (spec/v1.md, relay behaviour, 2026-11-24).

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/sagernet/quic-go"
)

// GroupResetKey derives the stateless reset key from the private key of the
// group's certificate: every relay the hub gave that certificate, and every
// generation of each, resets the others' connections. The hash keeps the
// private key out of the reset tokens.
func GroupResetKey(private crypto.PrivateKey) (*quic.StatelessResetKey, error) {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("stateless reset key: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("hikkari-stateless-reset/v1:"))
	h.Write(der)
	key := new(quic.StatelessResetKey)
	copy(key[:], h.Sum(nil))
	return key, nil
}
