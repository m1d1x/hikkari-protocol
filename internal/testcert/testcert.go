// Package testcert makes throwaway TLS material for tests.
package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"time"

	aTLS "github.com/sagernet/sing/common/tls"
)

// New returns a self-signed certificate for host and a pool that trusts it.
func New(host string) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{host}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// Client adapts a crypto/tls client config to sing's Config; QUIC reads only
// STDConfig.
type Client struct{ Config *tls.Config }

func (c *Client) ServerName() string                  { return c.Config.ServerName }
func (c *Client) SetServerName(name string)           { c.Config.ServerName = name }
func (c *Client) NextProtos() []string                { return c.Config.NextProtos }
func (c *Client) SetNextProtos(protos []string)       { c.Config.NextProtos = protos }
func (c *Client) HandshakeTimeout() time.Duration     { return 0 }
func (c *Client) SetHandshakeTimeout(time.Duration)   {}
func (c *Client) STDConfig() (*aTLS.STDConfig, error) { return c.Config, nil }
func (c *Client) Client(net.Conn) (aTLS.Conn, error)  { return nil, net.ErrClosed }
func (c *Client) Clone() aTLS.Config                  { return &Client{Config: c.Config.Clone()} }
