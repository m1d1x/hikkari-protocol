// Package chromium dials trunk members (package trunk) the way the Hikkari
// client dials its stream channel: Chromium's network stack (cronet, the same
// build the client core links), so what crosses the border is Chromium's own
// ClientHello, HTTP/2 and Naive padding, byte for byte the client's, not an
// imitation.
//
// One Chromium engine per member, so a member is one TCP connection the
// trunk can account for: the engine takes its socket from this package's
// dialer, from the source port the pool chose, and the member's end closes
// the engine and with it the socket. A member the pool finds dead is a dead
// TCP flow and a port not to use again; Chromium's own pooling would hide
// both.
//
// Own module: cronet stays out of the relay's build (the exit end imports
// package trunk only).
//
// Linking: cgo with the static libcronet on macOS (tests); on Linux the entry
// is built with -tags with_purego and loads libcronet.so at run time
// (cronet.LoadLibrary, or from the executable's directory).
package chromium

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	mDNS "github.com/miekg/dns"
	"github.com/sagernet/cronet-go"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Dialer opens members to one exit.
type Dialer struct {
	// Exit is the relay's address, ip:port.
	Exit string
	// SNI is the relay's domain: Chromium checks the certificate against it.
	SNI string
	// Key is the trunk key the exit's relay admits.
	Key string
	// Roots, PEM, replaces the system's trust (tests); empty is the system's.
	Roots string
	// Timeout bounds TCP, TLS and the CONNECT answer together.
	Timeout time.Duration
}

// DefaultTimeout bounds one member's dial.
const DefaultTimeout = 5 * time.Second

// Dial implements trunk.Dial. A path that does not answer within Timeout is
// trunk.ErrSilent: the port it came from is suspect.
func (d Dialer) Dial(ctx context.Context, localPort int) (io.ReadWriteCloser, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	server := M.ParseSocksaddr(d.Exit)
	if !server.IsIP() || server.Port == 0 {
		return nil, fmt.Errorf("chromium: exit %q is not ip:port", d.Exit)
	}
	tcp := &portDialer{exit: server, port: localPort, timeout: timeout}
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		ServerAddress:           server,
		ServerName:              d.SNI,
		Username:                trunk.User,
		Password:                d.Key,
		TrustedRootCertificates: d.Roots,
		DNSResolver:             refuseDNS,
		Dialer:                  tcp,
	})
	if err != nil {
		return nil, err
	}
	if err := client.Start(); err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := client.DialContext(dctx, N.NetworkTCP, M.ParseSocksaddr(trunk.Host))
	if err != nil {
		_ = client.Close()
		if tcp.silent.Load() || dctx.Err() != nil {
			return nil, fmt.Errorf("%w: %v", trunk.ErrSilent, err)
		}
		return nil, err
	}
	return &member{Conn: conn, client: client}, nil
}

// member is one CONNECT tunnel on its own engine.
type member struct {
	net.Conn
	client *cronet.NaiveClient
	once   sync.Once
}

func (m *member) Close() error {
	m.once.Do(func() {
		_ = m.Conn.Close()
		_ = m.client.Close()
	})
	return nil
}

// portDialer gives the engine its TCP socket: to the exit only, from the
// chosen source port.
type portDialer struct {
	exit    M.Socksaddr
	port    int
	timeout time.Duration
	// silent: the connect timed out (no answer from the path).
	silent atomic.Bool
}

var errNotExit = errors.New("chromium: the engine dialled something other than the exit")

func (p *portDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP || destination.Addr != p.exit.Addr || destination.Port != p.exit.Port {
		return nil, errNotExit
	}
	d := net.Dialer{Timeout: p.timeout, LocalAddr: &net.TCPAddr{Port: p.port}, KeepAlive: 15 * time.Second}
	c, err := d.DialContext(ctx, "tcp", p.exit.String())
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			p.silent.Store(true)
		}
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return c, nil
}

func (p *portDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("chromium: a trunk member carries no UDP of its own")
}

// refuseDNS answers every name the engine asks for but the exit's own domain
// (which cronet answers itself with the exit's address): a member talks to
// one address only.
func refuseDNS(_ context.Context, request *mDNS.Msg) *mDNS.Msg {
	resp := new(mDNS.Msg)
	resp.SetRcode(request, mDNS.RcodeRefused)
	return resp
}

// Version is the Chromium build the members speak.
func Version() string { return strings.TrimSpace(chromiumVersion) }
