// Package quicwire is the trunk's QUIC wire (hikkari-client
// plans/2026-11-11-trunk-wires-stage4.md): stream members over Hikkari's own
// datagram channel, the stand's `quic` and `salamander` (hikkari-control
// edge/wirestand.go). In the bench hour of 11.11 they took 12 MiB at 264 and
// 271 Mbit/s against the pool's 162, and held 100 Mbit/s for 90 s: the
// wires for bulk.
//
// A member is one QUIC connection of its own (Chrome's Initial, HTTP/3
// auth, its own source port and congestion control) with one stream to
// Host in it: a member that dies takes one connection, not the wire. The
// exit's channel hands that stream to the trunk (trunk.Exit.ServeMember);
// any other destination, and every datagram, is refused.
//
// Every secret is derived from the trunk key both ends hold: the channel's
// access key, the salamander password, and the exit's certificate key, which
// the entry pins instead of trusting a CA (the exit's certificate is its
// own, self-signed for the SNI). A path that answers with any other
// certificate learns nothing: the entry closes before it says its key.
package quicwire

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"

	hkclient "github.com/m1d1x/hikkari-protocol/client"
	hkserver "github.com/m1d1x/hikkari-protocol/server"
	"github.com/m1d1x/hikkari-protocol/trunk"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Host is the destination a member's stream asks for in the channel.
const Host = "trunk.hikkari.arpa"

func derive(trunkKey, info string, n int) []byte {
	k, err := hkdf.Key(sha256.New, []byte(trunkKey), nil, "hikkari trunk quic wire "+info, n)
	if err != nil {
		panic(err)
	}
	return k
}

// AccessKey is the channel's access key for a trunk key.
func AccessKey(trunkKey string) string { return hex.EncodeToString(derive(trunkKey, "key", 16)) }

// SalamanderPassword is the salamander password for a trunk key.
func SalamanderPassword(trunkKey string) string {
	return hex.EncodeToString(derive(trunkKey, "salamander", 16))
}

// certKey is the exit's certificate key for a trunk key.
func certKey(trunkKey string) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), derive(trunkKey, "certificate", 32))
}

// Certificate is the exit's certificate for sni under a trunk key.
func Certificate(trunkKey, sni string) (tls.Certificate, error) {
	key, err := certKey(trunkKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(2, 0, 0),
		DNSNames: []string{sni}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// errPin is a certificate that is not the exit's.
var errPin = errors.New("quicwire: the exit's certificate is not the trunk key's")

// pinned checks the leaf against the trunk key's certificate key.
func pinned(trunkKey string) (func([][]byte, [][]*x509.Certificate) error, error) {
	key, err := certKey(trunkKey)
	if err != nil {
		return nil, err
	}
	want, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errPin
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, want) {
			return errPin
		}
		return nil
	}, nil
}

// Dialer opens the entry's members of the wire.
type Dialer struct {
	Exit netip.AddrPort
	Key  string // the trunk key
	SNI  string // the server name the members say
	// Salamander obfuscates every packet (the Hysteria2 shape).
	Salamander bool
}

// Dial opens one member from localPort (0: any): a QUIC connection of its
// own, and the stream to Host in it.
func (d Dialer) Dial(ctx context.Context, localPort int) (io.ReadWriteCloser, error) {
	verify, err := pinned(d.Key)
	if err != nil {
		return nil, err
	}
	salamander := ""
	if d.Salamander {
		salamander = SalamanderPassword(d.Key)
	}
	life, cancel := context.WithCancel(context.Background())
	dc, err := hkclient.NewDatagram(hkclient.DatagramOptions{
		Context: life, Dialer: portDialer(localPort), Server: M.SocksaddrFromNetIP(d.Exit),
		Password: AccessKey(d.Key), Salamander: salamander,
		TLS: &clientTLS{config: &tls.Config{ServerName: d.SNI, InsecureSkipVerify: true, VerifyPeerCertificate: verify}},
	})
	if err != nil {
		cancel()
		return nil, err
	}
	c, err := dc.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddrHostPort(Host, 443))
	if err != nil {
		_ = dc.Close()
		cancel()
		return nil, err
	}
	return &member{Conn: c, close: func() { _ = dc.Close(); cancel() }}, nil
}

type member struct {
	net.Conn
	once  sync.Once
	close func()
}

func (m *member) Close() error {
	err := m.Conn.Close()
	m.once.Do(m.close)
	return err
}

// portDialer opens the channel's UDP socket from one source port.
type portDialer int

func (p portDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkUDP {
		return nil, errors.New("quicwire: only UDP")
	}
	return net.DialUDP("udp", &net.UDPAddr{Port: int(p)}, net.UDPAddrFromAddrPort(dest.AddrPort()))
}

func (p portDialer) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{Port: int(p)})
}

// clientTLS adapts a crypto/tls config to sing's Config; QUIC reads only
// STDConfig.
type clientTLS struct{ config *tls.Config }

func (c *clientTLS) ServerName() string                  { return c.config.ServerName }
func (c *clientTLS) SetServerName(name string)           { c.config.ServerName = name }
func (c *clientTLS) NextProtos() []string                { return c.config.NextProtos }
func (c *clientTLS) SetNextProtos(protos []string)       { c.config.NextProtos = protos }
func (c *clientTLS) HandshakeTimeout() time.Duration     { return 0 }
func (c *clientTLS) SetHandshakeTimeout(time.Duration)   {}
func (c *clientTLS) STDConfig() (*aTLS.STDConfig, error) { return c.config, nil }
func (c *clientTLS) Client(net.Conn) (aTLS.Conn, error)  { return nil, errors.ErrUnsupported }
func (c *clientTLS) Clone() aTLS.Config                  { return &clientTLS{config: c.config.Clone()} }

// ListenOptions are the exit's end of the wire.
type ListenOptions struct {
	Listen string // the UDP address
	// Conn, when set, is the socket to serve instead of binding Listen; the
	// listener closes it on Close.
	Conn net.PacketConn
	Keys []string // trunk keys; the certificate is the first one's
	SNI  string
	// Salamander, as the entry's: an exit of one wire serves one shape.
	Salamander bool
	// Serve gets every member (trunk.Exit.ServeMember), on a goroutine of
	// its own.
	Serve func(io.ReadWriteCloser)
}

// Listen serves the wire until ctx ends or Close.
func Listen(ctx context.Context, o ListenOptions) (*hkserver.Datagram, error) {
	if len(o.Keys) == 0 || o.Serve == nil {
		return nil, errors.New("quicwire: a trunk key and a member's Serve are required")
	}
	cert, err := Certificate(o.Keys[0], o.SNI)
	if err != nil {
		return nil, err
	}
	salamander := ""
	if o.Salamander {
		// One password for the socket: the first key's, like the
		// certificate. An entry on another key reaches the pool only.
		salamander = SalamanderPassword(o.Keys[0])
	}
	keys := make([]string, 0, len(o.Keys))
	for _, k := range o.Keys {
		keys = append(keys, AccessKey(k))
	}
	d, err := hkserver.ListenDatagram(ctx, hkserver.DatagramOptions{
		Listen:      o.Listen,
		Conn:        o.Conn,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Salamander:  salamander,
		Admitter:    admitter{},
		Exit:        exit{serve: o.Serve},
	})
	if err != nil {
		return nil, err
	}
	d.SetKeys(keys)
	return d, nil
}

// admitter admits the roster's keys (SetKeys holds only the trunk's), not
// the probe credential: the wire has no probe.
type admitter struct{}

func (admitter) Admit(ctx context.Context, key string) (context.Context, func(), func(int, int), bool) {
	if key == "" {
		return nil, nil, nil, false
	}
	return ctx, func() {}, func(int, int) {}, true
}

// exit gives a stream to Host to the trunk and refuses everything else.
type exit struct{ serve func(io.ReadWriteCloser) }

func (exit) Resolve(context.Context, M.Socksaddr) (netip.AddrPort, error) {
	return netip.AddrPort{}, hkserver.ErrRefused
}

func (e exit) DialTCP(ctx context.Context, dest M.Socksaddr) (net.Conn, error) {
	if dest.Fqdn != Host {
		return nil, hkserver.ErrRefused
	}
	channel, member := net.Pipe()
	go func() {
		defer member.Close()
		e.serve(member)
	}()
	return channel, nil
}

var _ trunk.Dial = Dialer{}.Dial
