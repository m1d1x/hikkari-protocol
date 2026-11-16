package chromium

// h3.go is Naive over HTTP/3: one Chromium engine with QUIC forced, CONNECT
// streams over one QUIC connection to one exit. It is the candidate wire h3
// of the trunk's stand (hikkari-client plans/2026-11-11-entry-hot-path-and-
// unit-economics.md, variant A): Chromium's own QUIC on the wire, streams only,
// no datagrams (the cronet API has none).
//
// Chromium gets its UDP socket straight from this package (cronet-go hands a
// *net.UDPConn's descriptor to the engine, dupSocketFD), so no packet of the
// wire passes through Go. H3 counts how each socket was handed over: a socket
// cronet had to relay through a socket pair (createPacketSocketPair, a copy
// in Go per packet) is a broken bench, and Sockets says so.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/cronet-go"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// H3Congestion names Chromium's congestion controller for QUIC: "" is
// Chromium's own default, else bbr, bbr2, cubic or reno.
func h3Congestion(name string) (cronet.QUICCongestionControl, error) {
	switch name {
	case "":
		return cronet.QUICCongestionControlDefault, nil
	case "bbr":
		return cronet.QUICCongestionControlBBR, nil
	case "bbr2":
		return cronet.QUICCongestionControlBBRv2, nil
	case "cubic":
		return cronet.QUICCongestionControlCubic, nil
	case "reno":
		return cronet.QUICCongestionControlReno, nil
	}
	return "", fmt.Errorf("chromium: congestion %q is not bbr, bbr2, cubic or reno", name)
}

// H3 is one Chromium engine speaking Naive over HTTP/3 to one exit.
type H3 struct {
	// Exit is the exit's address, ip:port (UDP).
	Exit string
	// SNI is the exit's name: Chromium checks the certificate against it.
	SNI string
	// User and Key are the exit's Naive credential.
	User, Key string
	// Roots, PEM, replaces the system's trust; empty is the system's.
	Roots string
	// Congestion is Chromium's controller ("" its default).
	Congestion string

	client *cronet.NaiveClient
	socks  *h3Sockets
}

// H3Sockets says how the engine got its sockets.
type H3Sockets struct {
	// Direct UDP sockets handed to Chromium as they are.
	Direct int64
	// Relayed UDP sockets Chromium got through a socket pair, every packet
	// copied in Go: must stay 0.
	Relayed int64
	// TCP connections the engine asked for (refused: the wire is QUIC only).
	TCP int64
}

type h3Sockets struct {
	exit    M.Socksaddr
	direct  atomic.Int64
	relayed atomic.Int64
	tcp     atomic.Int64
}

// Start brings the engine up.
func (h *H3) Start(ctx context.Context) error {
	server := M.ParseSocksaddr(h.Exit)
	if !server.IsIP() || server.Port == 0 {
		return fmt.Errorf("chromium: exit %q is not ip:port", h.Exit)
	}
	cc, err := h3Congestion(h.Congestion)
	if err != nil {
		return err
	}
	h.socks = &h3Sockets{exit: server}
	client, err := cronet.NewNaiveClient(cronet.NaiveClientOptions{
		Context:                 ctx,
		ServerAddress:           server,
		ServerName:              h.SNI,
		Username:                h.User,
		Password:                h.Key,
		TrustedRootCertificates: h.Roots,
		DNSResolver:             refuseDNS,
		Dialer:                  h.socks,
		Logger:                  &h3Logger{socks: h.socks},
		QUIC:                    true,
		QUICCongestionControl:   cc,
	})
	if err != nil {
		return err
	}
	if err := client.Start(); err != nil {
		return err
	}
	h.client = client
	return nil
}

// Open opens a CONNECT stream to destination (host:port, as the exit's proxy
// dials it).
func (h *H3) Open(ctx context.Context, destination string, timeout time.Duration) (net.Conn, error) {
	if h.client == nil {
		return nil, errors.New("chromium: h3 not started")
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return h.client.DialContext(dctx, N.NetworkTCP, M.ParseSocksaddr(destination))
}

// Sockets says how the engine got its sockets so far.
func (h *H3) Sockets() H3Sockets {
	if h.socks == nil {
		return H3Sockets{}
	}
	return H3Sockets{Direct: h.socks.direct.Load(), Relayed: h.socks.relayed.Load(), TCP: h.socks.tcp.Load()}
}

// Close takes the engine down.
func (h *H3) Close() error {
	if h.client == nil {
		return nil
	}
	return h.client.Close()
}

var errH3NotExit = errors.New("chromium: h3 dialled something other than the exit's UDP")

// DialContext gives the engine a plain *net.UDPConn to the exit, which cronet
// hands to Chromium by descriptor. TCP is refused: the wire is QUIC only.
func (s *h3Sockets) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkTCP {
		s.tcp.Add(1)
		return nil, errH3NotExit
	}
	if destination.Addr != s.exit.Addr || destination.Port != s.exit.Port {
		return nil, errH3NotExit
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", s.exit.String())
	if err != nil {
		return nil, err
	}
	u := c.(*net.UDPConn)
	// Chromium's own socket buffers are small for a trunk.
	_ = u.SetReadBuffer(4 << 20)
	_ = u.SetWriteBuffer(4 << 20)
	s.direct.Add(1)
	return u, nil
}

func (s *h3Sockets) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errH3NotExit
}

// h3Logger counts cronet's word that it relayed a UDP socket (it says so at
// debug level only, "relaying UDP connection to ...").
type h3Logger struct{ socks *h3Sockets }

var _ logger.ContextLogger = (*h3Logger)(nil)

func (l *h3Logger) heard(args []any) {
	if strings.HasPrefix(fmt.Sprint(args...), "relaying UDP connection") {
		l.socks.relayed.Add(1)
		l.socks.direct.Add(-1)
	}
}

func (l *h3Logger) Trace(args ...any)                             {}
func (l *h3Logger) Debug(args ...any)                             { l.heard(args) }
func (l *h3Logger) Info(args ...any)                              {}
func (l *h3Logger) Warn(args ...any)                              {}
func (l *h3Logger) Error(args ...any)                             {}
func (l *h3Logger) Fatal(args ...any)                             {}
func (l *h3Logger) Panic(args ...any)                             {}
func (l *h3Logger) TraceContext(ctx context.Context, args ...any) {}
func (l *h3Logger) DebugContext(ctx context.Context, args ...any) { l.heard(args) }
func (l *h3Logger) InfoContext(ctx context.Context, args ...any)  {}
func (l *h3Logger) WarnContext(ctx context.Context, args ...any)  {}
func (l *h3Logger) ErrorContext(ctx context.Context, args ...any) {}
func (l *h3Logger) FatalContext(ctx context.Context, args ...any) {}
func (l *h3Logger) PanicContext(ctx context.Context, args ...any) {}
