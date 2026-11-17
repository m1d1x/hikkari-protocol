package connect

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// Source is where a session's traffic leaves a relay: the local addresses its
// sockets toward the internet bind to. A relay box routes each source into
// the tunnel of one egress (ip rule from <source> lookup <egress table>), so
// the source is the session's exit and, by the hub's map, its country. It
// lives on the session context because a relay serves every country from one
// process: the handler that knows the key (admission, the CONNECT gate) puts
// it there, and every dial and socket the session opens binds to it.
// Binding a local address needs no privilege, unlike a socket mark.
type Source struct {
	V4, V6 netip.Addr
}

// ErrNoSourceFamily is a destination of a family the session's source has no
// address of: such a session cannot reach it without leaving another way.
var ErrNoSourceFamily = errors.New("hikkari: the session's exit has no address of this family")

type sourceKey struct{}

// WithSource puts a session's source on its context. A zero source leaves
// the context as it is: the session leaves by the relay's default route.
func WithSource(ctx context.Context, s Source) context.Context {
	if !s.V4.IsValid() && !s.V6.IsValid() {
		return ctx
	}
	return context.WithValue(ctx, sourceKey{}, s)
}

// SourceFrom returns the session's source, ok false when it has none.
func SourceFrom(ctx context.Context) (Source, bool) {
	s, ok := ctx.Value(sourceKey{}).(Source)
	return s, ok
}

// Local returns the address a socket to dest binds to: invalid when the
// context has no source (bind nothing), ErrNoSourceFamily when the source has
// no address of dest's family.
func Local(ctx context.Context, dest netip.Addr) (netip.Addr, error) {
	s, ok := SourceFrom(ctx)
	if !ok {
		return netip.Addr{}, nil
	}
	if dest.Unmap().Is4() {
		if s.V4.IsValid() {
			return s.V4, nil
		}
	} else if s.V6.IsValid() {
		return s.V6, nil
	}
	return netip.Addr{}, ErrNoSourceFamily
}

// DialTCP dials dest from the session's source.
func DialTCP(ctx context.Context, d net.Dialer, dest netip.AddrPort) (net.Conn, error) {
	local, err := Local(ctx, dest.Addr())
	if err != nil {
		return nil, err
	}
	if local.IsValid() {
		d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, 0))
	}
	return d.DialContext(ctx, "tcp", dest.String())
}
