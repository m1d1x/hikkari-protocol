package naive

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/m1d1x/hikkari-protocol/connect"
)

// sourceDial is the proxy's dial to a destination dialContextCheckACL has
// resolved: a session that carries a source (connect.Source, its egress and
// country) dials from it, any other as the dialer does.
func sourceDial(dialer *net.Dialer) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if _, ok := connect.SourceFrom(ctx); !ok {
			return dialer.DialContext(ctx, network, address)
		}
		dest, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, fmt.Errorf("dial from the session's source: %w", err)
		}
		return connect.DialTCP(ctx, *dialer, dest)
	}
}
