package quicwire

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

const key = "test-trunk-key-0123456789abcdef"

// echoLocal is the exit's relay in the test: a TCP echo.
type echoLocal struct{ addr string }

func (l echoLocal) DialStream(ctx context.Context, _ uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", l.addr)
}
func (echoLocal) DialFlow(context.Context, uint16) (net.Conn, error) { return nil, net.ErrClosed }

func freePort(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStreamsOverQUIC(t *testing.T) {
	for _, salamander := range []bool{false, true} {
		t.Run(map[bool]string{false: "quic", true: "salamander"}[salamander], func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			x := trunk.NewExit(trunk.Config{}, echoLocal{ln.Addr().String()})
			go x.Run(ctx)
			at := freePort(t)
			srv, err := Listen(ctx, ListenOptions{Listen: at.String(), Keys: []string{key}, SNI: "www.example.com", Salamander: salamander,
				Serve: func(c io.ReadWriteCloser) { _ = x.ServeMember(c) }})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()

			ports, _ := trunk.NewPortBook(42000, 43000, time.Minute)
			pool := func(ctx context.Context, _ int) (io.ReadWriteCloser, error) {
				a, b := net.Pipe()
				go func() { _ = x.ServeMember(b) }()
				return a, nil
			}
			e, err := trunk.NewEntry(trunk.Config{}, 1, pool, ports, t.Logf)
			if err != nil {
				t.Fatal(err)
			}
			const quic trunk.WireID = 1
			d := Dialer{Exit: at, Key: key, SNI: "www.example.com", Salamander: salamander}
			if err := e.AddWire(trunk.Wire{ID: quic, Name: "quic", Shape: "browser", Members: 2, Streams: true, Dial: d.Dial}); err != nil {
				t.Fatal(err)
			}
			e.SetRoute(trunk.Route{Voice: trunk.AnyWire, Bulk: quic})
			go e.Run(ctx)
			waitFor(t, func() bool { return e.Wires()[quic].Members == 2 })

			client, edge := net.Pipe()
			defer client.Close()
			go e.Session().Carry(edge, 443)
			data := make([]byte, 4<<20)
			_, _ = rand.Read(data)
			go func() { _, _ = client.Write(data) }()
			got := make([]byte, len(data))
			_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, data) {
				t.Fatalf("echo over the wire: %v", err)
			}
			if r := e.Download(ctx, quic, 1<<20); r.End != "ok" {
				t.Fatalf("download %+v", r)
			}
		})
	}
}

// TestPinnedCertificate: an exit whose certificate is another trunk key's
// is not the exit: the member never comes up.
func TestPinnedCertificate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	at := freePort(t)
	srv, err := Listen(ctx, ListenOptions{Listen: at.String(), Keys: []string{"another-trunk-key-0000000000000"}, SNI: "www.example.com",
		Serve: func(c io.ReadWriteCloser) { c.Close() }})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	if c, err := (Dialer{Exit: at, Key: key, SNI: "www.example.com"}).Dial(dctx, 0); err == nil {
		c.Close()
		t.Fatal("a member came up to an exit with another key's certificate")
	} else {
		t.Logf("refused: %v", err)
	}
}
