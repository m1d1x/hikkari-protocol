package server

import (
	"context"
	"net"

	"github.com/m1d1x/hikkari-protocol/connect"
	"github.com/sagernet/sing/common/uot"
)

// IsUoTHost reports whether a CONNECT asks for the UDP-over-TCP fallback.
func IsUoTHost(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	return host == uot.MagicAddress || host == uot.LegacyMagicAddress
}

// WithUoT puts the UDP-over-TCP server on a CONNECT request's context: the
// Naive proxy answers the CONNECT behind its own auth and padding and hands
// the bytes to one end of a pipe; RelayPackets serves the other end. onFlow,
// when set, is called once per association. Bytes are counted around the
// tunnel by whoever counts the CONNECT.
func WithUoT(ctx context.Context, hostPort string, exit Exit, onFlow func()) context.Context {
	host, _, _ := net.SplitHostPort(hostPort)
	version := uot.Version
	if host == uot.LegacyMagicAddress {
		version = uot.LegacyVersion
	}
	return context.WithValue(ctx, connect.ContextKeyDial{}, func(ctx context.Context) (net.Conn, error) {
		proxySide, relaySide := net.Pipe()
		go func() {
			defer relaySide.Close()
			stop := context.AfterFunc(ctx, func() { _ = relaySide.Close() })
			defer stop()
			var request uot.Request
			if version == uot.Version {
				r, err := uot.ReadRequest(relaySide)
				if err != nil {
					return
				}
				request = *r
			}
			if onFlow != nil {
				onFlow()
			}
			_ = RelayPackets(ctx, uot.NewConn(relaySide, request), request, exit, 0, nil)
		}()
		return proxySide, nil
	})
}
