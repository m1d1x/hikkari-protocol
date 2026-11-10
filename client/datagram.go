package client

import (
	"context"
	"net"
	"os"

	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/m1d1x/hikkari-protocol/wire/datagram"
	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type DatagramOptions struct {
	// Context owns the QUIC connection's lifetime.
	Context context.Context
	// Dialer opens the UDP socket to Server.
	Dialer N.Dialer
	Server M.Socksaddr
	// Password is the access key, the same as the stream channel's.
	Password string
	// TLS is the client TLS config (server name and trust of the relay
	// domain); ALPN is set to h3.
	TLS        aTLS.Config
	Salamander string
	// QUIC tunes the QUIC connection; zero values keep the defaults.
	QUIC qtls.QUICOptions
	// NoChromeParrot sends the plain QUIC Initial instead of Chrome's.
	NoChromeParrot bool
	Logger         logger.Logger
	// Book, when set, counts the channel's QUIC connections under Name
	// ("datagram", or "voice" for the voice connection of v1.03) in the
	// client's group (v1.04 observability).
	Book *observe.Book
	Name string
}

// Datagram is the client of the datagram channel. It is a Channel: UDP rides
// QUIC DATAGRAM frames, TCP a QUIC stream.
type Datagram struct {
	client *datagram.Client
}

func NewDatagram(opts DatagramOptions) (*Datagram, error) {
	if opts.Logger == nil {
		opts.Logger = logger.NOP()
	}
	opts.TLS.SetNextProtos(nil)
	c, err := datagram.NewClient(datagram.ClientOptions{
		Context:            opts.Context,
		Dialer:             opts.Dialer,
		Logger:             opts.Logger,
		ServerAddress:      opts.Server,
		SalamanderPassword: opts.Salamander,
		Password:           opts.Password,
		TLSConfig:          opts.TLS,
		QUICOptions:        opts.QUIC,
		ChromeParrot:       !opts.NoChromeParrot,
		OnAuth: func(conn *quic.Conn) {
			name := opts.Name
			if name == "" {
				name = "datagram"
			}
			observe.WatchQUIC(opts.Book, Group, name, conn, nil)
		},
	})
	if err != nil {
		return nil, err
	}
	return &Datagram{client: c}, nil
}

func (d *Datagram) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return d.client.DialConn(ctx, destination)
	case N.NetworkUDP:
		conn, err := d.client.ListenPacket(ctx)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(conn, destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (d *Datagram) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	return d.client.ListenPacket(ctx)
}

// NetworkChanged drops the QUIC connection; the next packet makes a new one.
func (d *Datagram) NetworkChanged() { _ = d.client.CloseWithError(E.New("network changed")) }

// Close ends the QUIC connection.
func (d *Datagram) Close() error { return d.client.CloseWithError(os.ErrClosed) }
