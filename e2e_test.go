package hikkari_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// loopbackExit allows loopback: the default exit policy of a relay refuses it.
type loopbackExit struct{}

func (loopbackExit) Resolve(ctx context.Context, dest M.Socksaddr) (netip.AddrPort, error) {
	return dest.AddrPort(), nil
}
func (loopbackExit) DialTCP(ctx context.Context, dest M.Socksaddr) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", dest.String())
}

type roster struct {
	mu    sync.Mutex
	keys  map[string]bool
	up    atomic.Int64
	down  atomic.Int64
	slots map[int]context.CancelFunc
	next  int
}

func (r *roster) Admit(ctx context.Context, key string) (context.Context, func(), func(up, down int), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if key != "" && !r.keys[key] {
		return nil, nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	r.next++
	id := r.next
	r.slots[id] = cancel
	return ctx, func() { cancel(); r.mu.Lock(); delete(r.slots, id); r.mu.Unlock() },
		func(up, down int) { r.up.Add(int64(up)); r.down.Add(int64(down)) }, true
}

func (r *roster) revoke() {
	r.mu.Lock()
	r.keys = map[string]bool{}
	for _, c := range r.slots {
		c()
	}
	r.mu.Unlock()
}

func echoUDP(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP(b[:n], from)
		}
	}()
	return c
}

func freeUDP(t *testing.T) string {
	c, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer c.Close()
	return c.LocalAddr().String()
}

// call sends n datagrams of 160 bytes every 20 ms and counts the echoes.
func call(t *testing.T, conn net.Conn, n int) int {
	got := 0
	buf := make([]byte, 2048)
	for i := 0; i < n; i++ {
		_, _ = conn.Write(make([]byte, 160))
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := conn.Read(buf); err == nil {
			got++
		}
		time.Sleep(20 * time.Millisecond)
	}
	return got
}

func TestDatagramChannel(t *testing.T) {
	const key = "subscriber-key-0123456789abcdef"
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, salamander := range []string{"", "mask-password"} {
		t.Run("salamander="+salamander, func(t *testing.T) {
			keys.keys = map[string]bool{key: true}
			d, err := server.ListenDatagram(ctx, server.DatagramOptions{
				Listen:      listen,
				Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
				Salamander:  salamander,
				Admitter:    keys,
				Exit:        loopbackExit{},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.SetKeys([]string{key})
			echo := echoUDP(t)
			defer echo.Close()

			dc, err := client.NewDatagram(client.DatagramOptions{
				Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(listen), Password: key, Salamander: salamander,
				TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer dc.Close()
			conn, err := dc.DialContext(ctx, "udp", M.SocksaddrFromNet(echo.LocalAddr()))
			if err != nil {
				t.Fatal(err)
			}
			if got := call(t, conn, 50); got < 48 {
				t.Fatalf("echoed %d of 50", got)
			}
			if d.Flows() != 1 || keys.up.Load() < 48*160 || keys.down.Load() < 48*160 {
				t.Fatalf("flows %d, counted %d/%d", d.Flows(), keys.up.Load(), keys.down.Load())
			}
			// Revoking the key ends the live flow and refuses a new one.
			keys.revoke()
			d.SetKeys(nil)
			if got := call(t, conn, 5); got != 0 {
				t.Fatalf("revoked flow echoed %d", got)
			}
			conn.Close()
			conn, err = dc.DialContext(ctx, "udp", M.SocksaddrFromNet(echo.LocalAddr()))
			if err == nil {
				if got := call(t, conn, 5); got != 0 {
					t.Fatalf("revoked key opened a flow that echoed %d", got)
				}
				conn.Close()
			}
		})
	}
}

// fakeStream records what went over the stream channel.
type fakeStream struct{ udp, tcp atomic.Int64 }

func (f *fakeStream) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	if network == "tcp" {
		f.tcp.Add(1)
	} else {
		f.udp.Add(1)
	}
	a, _ := net.Pipe()
	return a, nil
}
func (f *fakeStream) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	f.udp.Add(1)
	return nil, errors.New("fake")
}

type deadDatagram struct{ tries atomic.Int64 }

func (d *deadDatagram) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	d.tries.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (d *deadDatagram) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("dead")
}

func TestClientFallsBackAndRetries(t *testing.T) {
	stream, dead := &fakeStream{}, &deadDatagram{}
	c := client.New(client.Options{Stream: stream, Datagram: dead, ConnectTimeout: 50 * time.Millisecond, RetryAfter: 300 * time.Millisecond})
	dest := M.ParseSocksaddr("1.1.1.1:3478")
	ctx := context.Background()
	if _, err := c.DialContext(ctx, "tcp", dest); err != nil || stream.tcp.Load() != 1 || dead.tries.Load() != 0 {
		t.Fatal("tcp must go over the stream channel only")
	}
	start := time.Now()
	if _, err := c.DialContext(ctx, "udp", dest); err != nil || stream.udp.Load() != 1 || dead.tries.Load() != 1 {
		t.Fatalf("udp: stream %d, datagram tries %d", stream.udp.Load(), dead.tries.Load())
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("fallback waited past connect_timeout")
	}
	// Within retry_after the datagram channel is not tried again.
	_, _ = c.DialContext(ctx, "udp", dest)
	if dead.tries.Load() != 1 || stream.udp.Load() != 2 {
		t.Fatal("datagram channel retried before retry_after")
	}
	time.Sleep(350 * time.Millisecond)
	_, _ = c.DialContext(ctx, "udp", dest)
	if dead.tries.Load() != 2 {
		t.Fatal("datagram channel not retried after retry_after")
	}
	c.NetworkChanged()
	if !c.DatagramUp() {
		t.Fatal("a network change must forget the failure")
	}
	// The caller's own cancellation is not the channel's fault.
	c2 := client.New(client.Options{Stream: stream, Datagram: dead, ConnectTimeout: time.Second})
	cctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, _ = c2.DialContext(cctx, "udp", dest)
	if !c2.DatagramUp() {
		t.Fatal("caller cancellation marked the datagram channel failed")
	}
}
