package udpwire

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

const key = "test-trunk-key-0123456789abcdef"

type nolocal struct{}

func (nolocal) DialStream(context.Context, uint16) (net.Conn, error) { return nil, net.ErrClosed }
func (nolocal) DialFlow(context.Context, uint16) (net.Conn, error)   { return nil, net.ErrClosed }

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestCallOverTheWire: an entry with a pool on pipes and this wire on real
// loopback UDP; the trunk's call pinned to the wire comes back whole, and a
// stranger's key opens no member.
func TestCallOverTheWire(t *testing.T) {
	x := trunk.NewExit(trunk.Config{}, nolocal{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go x.Run(ctx)
	l, err := Listen("127.0.0.1:0", []string{"another-trunk-key-000000000", key}, func(c io.ReadWriteCloser) { _ = x.ServeMember(c) })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ports, _ := trunk.NewPortBook(40000, 41000, time.Minute)
	pool := func(ctx context.Context, _ int) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() { _ = x.ServeMember(b) }()
		return a, nil
	}
	e, err := trunk.NewEntry(trunk.Config{}, 1, pool, ports, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	const udp trunk.WireID = 2
	if err := e.AddWire(trunk.Wire{ID: udp, Name: "udp", Shape: "random", Members: 2, Packet: true, Dial: Dialer{Exit: l.Addr(), Key: key}.Dial}); err != nil {
		t.Fatal(err)
	}
	go e.Run(ctx)
	waitFor(t, func() bool { return e.Wires()[udp].Members == 2 })
	var got atomic.Int64
	f := e.Session().OpenFlowWith(trunk.EchoPort, trunk.FlowOptions{Copies: 1, Pin: udp}, func([]byte) { got.Add(1) }, nil)
	for i := 0; i < 100; i++ {
		f.Send(make([]byte, 64))
		time.Sleep(time.Millisecond)
	}
	waitFor(t, func() bool { return got.Load() == 100 })
	if l.Peers() != 2 {
		t.Fatalf("%d peers for 2 members", l.Peers())
	}

	// A stranger: its datagrams open under no key.
	bad, err := Dialer{Exit: l.Addr(), Key: "a-stranger-key-0000000000000"}.Dial(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	_, _ = bad.Write([]byte("hello?"))
	time.Sleep(100 * time.Millisecond)
	if l.Peers() != 2 {
		t.Fatalf("a stranger became a peer: %d", l.Peers())
	}
}
