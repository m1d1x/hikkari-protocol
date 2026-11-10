package hikkari_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestObserveCall runs a duplicated call through a relay and a client that
// both keep a book (v1.04) and checks what each end saw: which channel
// brought each copy, the copies the stream channel saved while the datagram
// channel was silent, the QUIC connections, and the call itself.
func TestObserveCall(t *testing.T) {
	const key = "subscriber-key-0123456789abcdef"
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relayBook, clientBook := observe.NewBook(), observe.NewBook()
	hub := server.NewDupHub(loopbackExit{}, 0)
	hub.Observe(relayBook)
	d, err := server.ListenDatagram(ctx, server.DatagramOptions{
		Listen:      listen,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Admitter:    keys,
		Exit:        loopbackExit{},
		Dup:         hub,
		Book:        relayBook,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.SetKeys([]string{key})
	dc, err := client.NewDatagram(client.DatagramOptions{
		Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(listen), Password: key,
		TLS:  &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
		Book: clientBook,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dc.Close()
	stream := &hubStream{hub: hub, key: key}
	lossy := &lossyDatagram{inner: dc}
	c := client.New(client.Options{Stream: stream, Datagram: lossy, Dup: true, Book: clientBook})

	echo := newSourceEcho(t)
	defer echo.Close()
	conn, err := c.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	// 3 s of a call on both channels, then 2 s with the datagram channel
	// silent: the stream copy alone carries those 100 packets each way.
	if got, _, _ := callStats(conn, echo.LocalAddr(), 150, 160, 20*time.Millisecond); got < 148 {
		t.Fatalf("call: %d/150", got)
	}
	lossy.drop.Store(true)
	if got, _, _ := callStats(conn, echo.LocalAddr(), 100, 160, 20*time.Millisecond); got < 98 {
		t.Fatalf("datagram silent: %d/100", got)
	}
	lossy.drop.Store(false)
	_ = conn.Close()

	relay := relayBook.Take()[key]
	if relay == nil || relay.Dup == nil {
		t.Fatalf("relay book has no dup for the key: %v", relayBook)
	}
	up := relay.Dup
	if up.Fresh < 245 || up.Fresh > 250 || up.Opened != 1 {
		t.Fatalf("relay up: %+v", up)
	}
	// While the datagram channel was silent every packet came first by the
	// stream channel; before, the stream copy (on from the call's second
	// second) also came, as a second copy or a first.
	if up.FirstStream < 95 || up.LeadDatagram.N()+up.LeadStream.N() < 50 {
		t.Fatalf("relay first copies: %+v", up)
	}
	if q := relay.QUIC["datagram"]; q == nil || q.Conns != 1 || q.Opened != 1 || q.RTT.N() != 1 || q.PktsOut == 0 {
		t.Fatalf("relay quic: %+v", q)
	}

	own := clientBook.Take()[client.Group]
	if own == nil || own.Dup == nil || own.Calls == nil {
		t.Fatalf("client book: %+v", own)
	}
	down := own.Dup
	// Closed, so every number is settled: the 100 answers of the silent
	// datagram channel came by the stream copy alone.
	if down.Fresh < 245 || down.OnlyStream < 95 || down.Both < 50 || down.Ends[observe.EndEOF] != 1 {
		t.Fatalf("client down: %+v", down)
	}
	if down.OnlyStream+down.OnlyDatagram+down.Both != down.Fresh {
		t.Fatalf("settled %d of %d", down.OnlyStream+down.OnlyDatagram+down.Both, down.Fresh)
	}
	calls := own.Calls
	if calls.N != 1 || calls.Short != 1 || calls.OneSided != 0 || calls.PPSDown.Summary().Max < calls.PPSUp.Summary().Max*0.9 {
		t.Fatalf("calls: %+v", calls)
	}
	// 250 packets in about 6 s: the test's own pause between its two parts
	// is part of the call.
	if s := calls.PPSUp.Summary(); s.Max < 30 || s.Max > 60 || calls.BytesUp.Summary().Max > 160 {
		t.Fatalf("call pps up %+v", s)
	}
	if q := own.QUIC["datagram"]; q == nil || q.Conns != 1 || q.RTT.N() != 1 {
		t.Fatalf("client quic: %+v", q)
	}
	raw, _ := json.Marshal(own)
	t.Logf("client period: %s", raw)
	raw, _ = json.Marshal(relay)
	t.Logf("relay period: %s", raw)
}
