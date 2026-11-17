package naive

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/m1d1x/hikkari-protocol/connect"
)

// A CONNECT of a session with a source leaves from that source, so the box
// routes it into its egress; one without a source dials as before; one whose
// source lacks the destination's family is refused rather than sent out by
// the default route.
func TestAConnectLeavesFromItsSessionsSource(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan netip.Addr, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			seen <- c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
			_ = c.Close()
		}
	}()
	dial := sourceDial(&net.Dialer{})
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want netip.Addr
	}{
		{"no source", context.Background(), netip.MustParseAddr("127.0.0.1")},
		{"egress A", connect.WithSource(context.Background(), connect.Source{V4: netip.MustParseAddr("127.0.0.2")}), netip.MustParseAddr("127.0.0.2")},
		{"egress B", connect.WithSource(context.Background(), connect.Source{V4: netip.MustParseAddr("127.0.0.3")}), netip.MustParseAddr("127.0.0.3")},
	} {
		c, err := dial(tc.ctx, "tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = c.Close()
		if got := <-seen; got != tc.want {
			t.Fatalf("%s: far end saw %v, want %v", tc.name, got, tc.want)
		}
	}
	v6only := connect.WithSource(context.Background(), connect.Source{V6: netip.MustParseAddr("::1")})
	if _, err := dial(v6only, "tcp", ln.Addr().String()); !errors.Is(err, connect.ErrNoSourceFamily) {
		t.Fatalf("an IPv4 destination from an IPv6-only source: %v", err)
	}
}
