package naive

import (
	"context"
	"net"
	"testing"
)

func TestContextDialOwnsDestination(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	called := false
	ctx := context.WithValue(context.Background(), ContextKeyDial{}, func(context.Context) (net.Conn, error) {
		called = true
		return a, nil
	})
	// No ACL, no resolver: a name that does not resolve still dials.
	conn, err := Handler{}.dialContextCheckACL(ctx, "tcp", "sp.v2.udp-over-tcp.arpa:0")
	if err != nil || conn != a || !called {
		t.Fatalf("conn=%v err=%v called=%v", conn, err, called)
	}
	if _, err := (Handler{}).dialContextCheckACL(ctx, "udp", "x:1"); err == nil {
		t.Fatal("udp network accepted")
	}
}
