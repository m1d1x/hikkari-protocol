package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/m1d1x/hikkari-protocol/wire/datagram"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/common/uot"
)

// Admitter decides who may use a channel and counts what they carry. The relay
// owns the key roster; both channels of a Hikkari relay ask the same Admitter,
// so a key is admitted, counted and revoked once for both.
type Admitter interface {
	// Admit opens a session for key; the empty key is the relay's own probe
	// credential. The session context ends when the key is revoked; done
	// closes the session; count receives bytes up and down. ok=false refuses.
	Admit(ctx context.Context, key string) (session context.Context, done func(), count func(up, down int), ok bool)
}

// DatagramOptions configure the datagram channel of one relay.
type DatagramOptions struct {
	// Listen is the UDP address, normally the Naive channel's host:port.
	Listen string
	// Certificate serves the TLS certificate (the relay domain's, the same the
	// Naive channel shows).
	Certificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// Masquerade answers unauthenticated HTTP/3, normally the relay's site.
	Masquerade http.Handler
	// ProbePassword admits the relay's probe under the empty key.
	ProbePassword string
	// Salamander, when set, obfuscates every packet with this password.
	Salamander string
	// Idle ends a UDP flow without packets; UDPIdle when zero.
	Idle     time.Duration
	Admitter Admitter
	Exit     Exit
	// Dup, when set, serves duplicated associations (v1.02): a UDP
	// association addressed to dup.Host is a carrier of a session the stream
	// channel may carry too. Share one hub with the stream channel (WithDup).
	Dup *DupHub
	// Book, when set, counts the channel's QUIC connections by access key
	// (v1.04 observability); the probe credential's under the empty key.
	Book *observe.Book
}

// Datagram is the datagram channel: QUIC with HTTP/3 auth, UDP as QUIC
// DATAGRAM frames (the Hysteria2 wire in wire/datagram), streams allowed too.
type Datagram struct {
	opts    DatagramOptions
	service *datagram.Service[string]
	conn    net.PacketConn
	flows   atomic.Int64
	closing atomic.Bool
}

// ListenDatagram opens the channel; SetKeys gives it the roster.
func ListenDatagram(ctx context.Context, opts DatagramOptions) (*Datagram, error) {
	if opts.Certificate == nil || opts.Admitter == nil || opts.Exit == nil {
		return nil, errors.New("hikkari datagram: certificate, admitter and exit are required")
	}
	if opts.Idle <= 0 {
		opts.Idle = UDPIdle
	}
	if opts.Masquerade == nil {
		opts.Masquerade = http.NotFoundHandler()
	}
	d := &Datagram{opts: opts}
	service, err := datagram.NewService[string](datagram.ServiceOptions{
		Context:            ctx,
		Logger:             quietLogger{},
		SalamanderPassword: opts.Salamander,
		TLSConfig:          &serverTLS{config: &tls.Config{GetCertificate: opts.Certificate, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}},
		UDPTimeout:         opts.Idle,
		Handler:            d,
		MasqueradeHandler:  opts.Masquerade,
		OnAuth: func(user any, conn *quic.Conn) {
			key, _ := user.(string)
			observe.WatchQUIC(opts.Book, key, "datagram", conn, d.closing.Load)
		},
	})
	if err != nil {
		return nil, err
	}
	d.service = service
	d.SetKeys(nil)
	if d.conn, err = net.ListenPacket("udp", opts.Listen); err != nil {
		return nil, err
	}
	if err = service.Start(d.conn); err != nil {
		_ = d.conn.Close()
		return nil, err
	}
	return d, nil
}

// SetKeys replaces the roster: user = password = access key, plus the probe
// credential under the empty key.
func (d *Datagram) SetKeys(keys []string) {
	users := append([]string{""}, keys...)
	passwords := append([]string{d.opts.ProbePassword}, keys...)
	d.service.UpdateUsers(users, passwords)
}

// Flows is how many UDP associations the channel has carried.
func (d *Datagram) Flows() int64 { return d.flows.Load() }

// Close stops the channel.
func (d *Datagram) Close() error {
	d.closing.Store(true)
	err := d.service.Close()
	if d.conn != nil {
		_ = d.conn.Close()
	}
	return err
}

// NewConnectionEx serves a stream on the datagram channel: the same grant as
// a datagram, so it is allowed.
func (d *Datagram) NewConnectionEx(ctx context.Context, conn net.Conn, _ M.Socksaddr, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	key, _ := auth.UserFromContext[string](ctx)
	go func() {
		defer closeWith(onClose)
		defer conn.Close()
		ctx, done, count, ok := d.opts.Admitter.Admit(ctx, key)
		if !ok {
			return
		}
		defer done()
		target, err := d.opts.Exit.DialTCP(ctx, dest)
		if err != nil {
			return
		}
		defer target.Close()
		context.AfterFunc(ctx, func() { _ = conn.Close(); _ = target.Close() })
		go func() {
			nr, _ := io.Copy(target, conn)
			count(int(nr), 0)
			_ = target.Close()
		}()
		nr, _ := io.Copy(conn, target)
		count(0, int(nr))
	}()
}

// NewPacketConnectionEx serves one UDP association.
func (d *Datagram) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _ M.Socksaddr, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	key, _ := auth.UserFromContext[string](ctx)
	go func() {
		defer closeWith(onClose)
		ctx, done, count, ok := d.opts.Admitter.Admit(ctx, key)
		if !ok {
			_ = conn.Close()
			return
		}
		defer done()
		d.flows.Add(1)
		if d.opts.Dup != nil && dup.IsHost(dest.AddrString()) {
			_ = d.opts.Dup.ServePacket(ctx, key, conn, count)
			return
		}
		_ = RelayPackets(ctx, conn, uot.Request{}, d.opts.Exit, d.opts.Idle, count)
	}()
}

func closeWith(onClose N.CloseHandlerFunc) {
	if onClose != nil {
		onClose(nil)
	}
}

// serverTLS adapts a crypto/tls config to sing's ServerConfig; QUIC reads only
// STDConfig.
type serverTLS struct{ config *tls.Config }

func (s *serverTLS) ServerName() string                  { return s.config.ServerName }
func (s *serverTLS) SetServerName(name string)           { s.config.ServerName = name }
func (s *serverTLS) NextProtos() []string                { return s.config.NextProtos }
func (s *serverTLS) SetNextProtos(protos []string)       { s.config.NextProtos = protos }
func (s *serverTLS) HandshakeTimeout() time.Duration     { return 0 }
func (s *serverTLS) SetHandshakeTimeout(time.Duration)   {}
func (s *serverTLS) STDConfig() (*aTLS.STDConfig, error) { return s.config, nil }
func (s *serverTLS) Client(net.Conn) (aTLS.Conn, error)  { return nil, errors.ErrUnsupported }
func (s *serverTLS) Server(net.Conn) (aTLS.Conn, error)  { return nil, errors.ErrUnsupported }
func (s *serverTLS) Clone() aTLS.Config                  { return &serverTLS{config: s.config.Clone()} }
func (s *serverTLS) Start() error                        { return nil }
func (s *serverTLS) Close() error                        { return nil }

// quietLogger drops per-connection chatter: it would name destinations, and a
// relay logs none.
type quietLogger struct{}

func (quietLogger) Trace(...any) {}
func (quietLogger) Debug(...any) {}
func (quietLogger) Info(...any)  {}
func (quietLogger) Warn(...any)  {}
func (quietLogger) Error(...any) {}
func (quietLogger) Fatal(...any) {}
func (quietLogger) Panic(...any) {}
