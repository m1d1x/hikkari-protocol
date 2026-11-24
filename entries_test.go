package hikkari_test

// Several entries (v1.07, spec/v1.md): a client reaches one relay through two
// L4 forwards, as a cascade's client reaches the core through two entries,
// and one of them goes silent for 8 s the way aezamsk1 does.

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/dup"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// entryForward is an entry of the cascade as the relay's side sees it: an L4
// forward of a TCP port and a UDP port to the relay's. While cut, both ways
// freeze as a silent entry does: TCP bytes wait in the forward, UDP packets
// are lost.
type entryForward struct {
	tcp, udp string
	cut      atomic.Bool
	conns    atomic.Int64 // TCP connections forwarded
}

func newEntryForward(t *testing.T, ctx context.Context, listen, tcpTo, udpTo string) *entryForward {
	e := &entryForward{}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { _ = ln.Close() })
	e.tcp = ln.Addr().String()
	go func() {
		for {
			down, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", tcpTo)
			if err != nil {
				_ = down.Close()
				continue
			}
			e.conns.Add(1)
			context.AfterFunc(ctx, func() { _ = down.Close(); _ = up.Close() })
			go e.pump(up, down)
			go e.pump(down, up)
		}
	}()
	udpAddr, _ := net.ResolveUDPAddr("udp", listen)
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { _ = pc.Close() })
	e.udp = pc.LocalAddr().String()
	go e.forwardUDP(ctx, pc, udpTo)
	return e
}

// pump copies src to dst, holding what it read while the entry is cut.
func (e *entryForward) pump(dst, src net.Conn) {
	defer dst.Close()
	b := make([]byte, 32<<10)
	for {
		n, err := src.Read(b)
		for e.cut.Load() {
			time.Sleep(2 * time.Millisecond)
		}
		if n > 0 {
			if _, werr := dst.Write(b[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// forwardUDP gives every client address a socket of its own to the relay, as
// a NAT does, and drops packets both ways while the entry is cut.
func (e *entryForward) forwardUDP(ctx context.Context, pc *net.UDPConn, to string) {
	relay, _ := net.ResolveUDPAddr("udp", to)
	var mu sync.Mutex
	flows := map[string]*net.UDPConn{}
	b := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDP(b)
		if err != nil {
			return
		}
		if e.cut.Load() {
			continue
		}
		mu.Lock()
		up := flows[from.String()]
		if up == nil {
			up, err = net.DialUDP("udp", nil, relay)
			if err != nil {
				mu.Unlock()
				continue
			}
			flows[from.String()] = up
			context.AfterFunc(ctx, func() { _ = up.Close() })
			go func(up *net.UDPConn, from *net.UDPAddr) {
				rb := make([]byte, 65535)
				for {
					k, err := up.Read(rb)
					if err != nil {
						return
					}
					if !e.cut.Load() {
						_, _ = pc.WriteToUDP(rb[:k], from)
					}
				}
			}(up, from)
		}
		mu.Unlock()
		_, _ = up.Write(b[:n])
	}
}

// lineFront stands in for the relay's Naive front, which needs Chromium on
// the client: a TCP connection names its destination in its first line, then
// carries the stream. A CONNECT to dup.Host goes to the dup hub, as the Naive
// front's WithDup does; any other destination is dialed through the exit.
func lineFront(t *testing.T, ctx context.Context, hub *server.DupHub, key string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				dest := strings.TrimSpace(line)
				stream := &bufferedConn{Conn: conn, r: r}
				if server.IsDupHost(dest) {
					_ = hub.ServeStream(ctx, key, stream)
					return
				}
				out, err := loopbackExit{}.DialTCP(ctx, M.ParseSocksaddr(dest))
				if err != nil {
					return
				}
				defer out.Close()
				go func() { _, _ = io.Copy(out, stream); _ = out.Close() }()
				_, _ = io.Copy(conn, out)
			}()
		}
	}()
	return ln.Addr().String()
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// lineStream is the client's side of lineFront through one entry.
type lineStream struct{ addr string }

func (s lineStream) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	if network != "tcp" {
		return nil, errors.New("line stream: tcp only")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, dest.String()+"\n"); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (lineStream) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("line stream: no UoT")
}

func echoTCP(t *testing.T, ctx context.Context) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// pattern is the byte at offset i of the long stream.
func pattern(i int64) byte { return byte(i*7 + i>>13) }

// longStream writes size bytes over conn at about 6 MiB/s and reads them
// back from the echo; it reports the bytes read back and the first offset
// that differed (-1 when none), and keeps the longest wait for a read in
// stall.
func longStream(conn net.Conn, size int64, progress, stall *atomic.Int64) (got, bad int64) {
	go func() {
		chunk := make([]byte, 64<<10)
		for off := int64(0); off < size; off += int64(len(chunk)) {
			for i := range chunk {
				chunk[i] = pattern(off + int64(i))
			}
			if _, err := conn.Write(chunk); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	bad = -1
	b := make([]byte, 64<<10)
	for got < size {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		start := time.Now()
		n, err := conn.Read(b)
		if wait := int64(time.Since(start)); wait > stall.Load() {
			stall.Store(wait)
		}
		for i := 0; i < n; i++ {
			if bad < 0 && b[i] != pattern(got+int64(i)) {
				bad = got + int64(i)
			}
		}
		got += int64(n)
		progress.Store(got)
		if err != nil {
			return
		}
	}
	return
}

type entriesStand struct {
	entries [2]*entryForward
	client  *client.Client
	book    *observe.Book
	log     *diary
	tcpEcho string
	udpEcho *sourceEcho
}

// newEntriesStand is one relay (dup hub, datagram channel, a stand-in for the
// Naive front) behind two entries, and a client that knows both.
func newEntriesStand(t *testing.T, ctx context.Context, listens [2]string) *entriesStand {
	const key = "subscriber-key-0123456789abcdef"
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	hub := server.NewDupHub(loopbackExit{}, 0)
	d, err := server.ListenDatagram(ctx, server.DatagramOptions{
		Listen:      listen,
		Certificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil },
		Admitter:    keys,
		Exit:        loopbackExit{},
		Dup:         hub,
	})
	if err != nil {
		t.Fatal(err)
	}
	context.AfterFunc(ctx, func() { _ = d.Close() })
	d.SetKeys([]string{key})
	front := lineFront(t, ctx, hub, key)
	s := &entriesStand{book: observe.NewBook(), log: &diary{start: time.Now()}, tcpEcho: echoTCP(t, ctx), udpEcho: newSourceEcho(t)}
	context.AfterFunc(ctx, func() { _ = s.udpEcho.Close() })
	var paths [2]client.Path
	for i := range s.entries {
		s.entries[i] = newEntryForward(t, ctx, listens[i], front, listen)
		channel := func(name string) *client.Datagram {
			dc, err := client.NewDatagram(client.DatagramOptions{
				Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(s.entries[i].udp), Password: key,
				TLS:  &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
				Book: s.book, Name: name,
			})
			if err != nil {
				t.Fatal(err)
			}
			context.AfterFunc(ctx, func() { _ = dc.Close() })
			return dc
		}
		paths[i] = client.Path{Stream: lineStream{s.entries[i].tcp}, Datagram: channel("datagram"), VoiceDatagram: channel("voice")}
	}
	s.client = client.New(client.Options{
		Stream: paths[0].Stream, Datagram: paths[0].Datagram, VoiceDatagram: paths[0].VoiceDatagram,
		Paths: paths[1:], Context: ctx, Dup: true, Logger: s.log, Book: s.book,
	})
	return s
}

// waitActive polls until the client's active entry is want; it returns how
// long that took, or false after limit.
func waitActive(c *client.Client, want int, limit time.Duration) (time.Duration, bool) {
	start := time.Now()
	for time.Since(start) < limit {
		if c.Active() == want {
			return time.Since(start), true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return limit, false
}

// TestAnEntryGoesSilentUnderACallAndAStream is aezamsk1 going silent for
// 8 s under a call and a 64 MiB download through it: the call goes on by the
// other entry with no pause over 60 ms, new TCP goes by the other entry
// within 2 s, and the download on the silent entry lives on when it comes
// back, not a byte lost.
func TestAnEntryGoesSilentUnderACallAndAStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newEntriesStand(t, ctx, [2]string{"127.0.0.1:0", "127.0.0.1:0"})
	runEntryCut(t, ctx, s, func(on bool) { s.entries[0].cut.Store(on) }, 8*time.Second)
}

// runEntryCut runs a call and a 64 MiB stream through entry 0 of s, cuts it
// for cutFor with cut, and holds the client to v1.07: the call without a
// pause over 60 ms, new TCP by entry 1 within 2 s, the stream whole.
func runEntryCut(t *testing.T, ctx context.Context, s *entriesStand, cut func(on bool), cutFor time.Duration) {
	t.Helper()
	defer func() {
		if t.Failed() {
			s.log.dump(t)
		}
	}()
	time.Sleep(time.Second) // both entries answer their first pings
	if s.client.Active() != 0 {
		t.Fatalf("active entry %d before the cut, want 0", s.client.Active())
	}

	const size = 64 << 20
	stream, err := s.client.DialContext(ctx, "tcp", M.ParseSocksaddr(s.tcpEcho))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var streamGot, streamBad, streamStall atomic.Int64
	streamDone := make(chan struct{})
	go func() {
		got, bad := longStream(stream, size, &streamGot, &streamStall)
		streamGot.Store(got)
		streamBad.Store(bad)
		close(streamDone)
	}()

	conn, err := s.client.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	type callResult struct {
		got, dups int
		worst     time.Duration
	}
	callDone := make(chan callResult, 1)
	go func() {
		// A call 1 s to be told a call, the cut at 3 s, 3 s after it.
		got, dups, worst := callStats(conn, s.udpEcho.LocalAddr(), callPackets(cutFor), 160, 20*time.Millisecond)
		callDone <- callResult{got, dups, worst}
	}()

	time.Sleep(3 * time.Second)
	cutAt := time.Now()
	cut(true)
	atCut := streamGot.Load()
	switched, ok := waitActive(s.client, 1, 3*time.Second)
	if !ok {
		t.Fatalf("the client stayed on entry 0 for %v after its cut", switched)
	}
	time.Sleep(time.Until(cutAt.Add(2 * time.Second)))
	before := s.entries[1].conns.Load()
	newStart := time.Now()
	fresh, err := s.client.DialContext(ctx, "tcp", M.ParseSocksaddr(s.tcpEcho))
	if err != nil {
		t.Fatalf("new TCP 2 s into the cut: %v", err)
	}
	_ = fresh.SetDeadline(time.Now().Add(2 * time.Second))
	echo := make([]byte, 1024)
	if _, err := fresh.Write(echo); err != nil {
		t.Fatalf("new TCP write: %v", err)
	}
	if _, err := io.ReadFull(fresh, echo); err != nil {
		t.Fatalf("new TCP 2 s into the cut got no echo: %v", err)
	}
	newTook := time.Since(newStart)
	fresh.Close()
	if s.entries[1].conns.Load() <= before {
		t.Fatalf("new TCP did not go by entry 1")
	}

	time.Sleep(time.Until(cutAt.Add(cutFor)))
	cut(false)
	// Entry 0 answers again when its TCP retransmits, which backs off over
	// a long silence: seconds after the entry came back, not at once.
	back, ok := waitActive(s.client, 0, 20*time.Second)
	if !ok {
		t.Fatalf("entry 0 not active %v after it came back", back)
	}

	select {
	case <-streamDone:
	case <-time.After(90 * time.Second):
		t.Fatalf("the stream did not end; %d bytes back", streamGot.Load())
	}
	call := <-callDone
	sources, _ := s.udpEcho.seen()
	t.Logf("switch to entry 1 %v after the cut; new TCP echoed in %v; back on entry 0 %v after it answered",
		switched.Round(time.Millisecond), newTook.Round(time.Millisecond), back.Round(time.Millisecond))
	t.Logf("call: %d/%d echoed, %d duplicates, longest pause %v; stream: %d MiB back at the cut, %d of %d bytes, first bad %d, longest wait %v",
		call.got, callPackets(cutFor), call.dups, call.worst.Round(time.Millisecond), atCut>>20, streamGot.Load(), int64(size), streamBad.Load(),
		time.Duration(streamStall.Load()).Round(time.Millisecond))
	if switched > 2*time.Second || newTook > 2*time.Second {
		t.Errorf("new TCP left the silent entry in %v (+%v), want under 2 s", switched, newTook)
	}
	if call.worst > 60*time.Millisecond || call.got < callPackets(cutFor)-2 || call.dups != 0 {
		t.Errorf("call: %d echoed, %d duplicates, longest pause %v; want no pause over 60 ms", call.got, call.dups, call.worst)
	}
	if sources != 1 {
		t.Errorf("the far end saw the call from %d sources, want one exit socket", sources)
	}
	if atCut == 0 || atCut >= size {
		t.Errorf("the stream had %d of %d bytes back at the cut, want it running", atCut, int64(size))
	}
	if streamGot.Load() != size || streamBad.Load() >= 0 {
		t.Errorf("stream: %d of %d bytes, first bad at %d", streamGot.Load(), int64(size), streamBad.Load())
	}

	p := s.book.Take()[client.Group]
	if p == nil || p.Entries["0"] == nil || p.Entries["1"] == nil {
		t.Fatalf("no entries in the period: %+v", p)
	}
	e0, e1 := p.Entries["0"], p.Entries["1"]
	t.Logf("period: entry 0 silences %d, silent %.1f s, active %.1f s; entry 1 active %.1f s, ping p50 %.1f ms",
		e0.Silences, e0.SilentS, e0.ActiveS, e1.ActiveS, e1.PingMS.Quantile(0.5))
	if e0.Silences != 1 || e0.SilentS < cutFor.Seconds()-3 || e1.ActiveS < cutFor.Seconds()-3 || e0.Now != 1 {
		t.Errorf("period: entry 0 %+v, entry 1 %+v", *e0, *e1)
	}
}

// deafStream is a stream channel to a relay before v1.07: a CONNECT to
// dup.Host whose first frame is a ping is closed.
type deafStream struct{}

func (deafStream) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	a, b := net.Pipe()
	go func() {
		buf := make([]byte, dup.MaxFrame)
		_, _ = dup.ReadStream(b, buf)
		_ = b.Close()
	}()
	return a, nil
}

func (deafStream) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("deaf")
}

// TestEntriesOfARelayWithoutPingsStayOnTheFirst: a relay that never answers a
// ping leaves the client where a v1.06 client is, on entry 0.
func TestEntriesOfARelayWithoutPingsStayOnTheFirst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := client.New(client.Options{Stream: deafStream{}, Paths: []client.Path{{Stream: deafStream{}}}, Context: ctx})
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if c.Active() != 0 {
			t.Fatalf("active entry %d with a relay that knows no pings", c.Active())
		}
	}
}

// TestTheRelayAnswersPingsWithoutASession: a probe carrier's pings come back
// unchanged and open no exit socket; a ping inside a session's carrier comes
// back too.
func TestTheRelayAnswersPingsWithoutASession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hub := server.NewDupHub(loopbackExit{}, 0)
	exchange := func(conn net.Conn, f dup.Frame) dup.Frame {
		t.Helper()
		frame, _ := dup.Append(nil, f)
		if err := dup.WriteStream(conn, frame); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		data, err := dup.ReadStream(conn, make([]byte, dup.MaxFrame))
		if err != nil {
			t.Fatal(err)
		}
		back, err := dup.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		return back
	}
	probe, relaySide := net.Pipe()
	go func() { _ = hub.ServeStream(ctx, "k", relaySide) }()
	id := dup.Session{1, 2, 3}
	for seq := uint64(1); seq <= 3; seq++ {
		back := exchange(probe, dup.Frame{Kind: dup.KindPing, Session: id, Seq: seq})
		if back.Kind != dup.KindPing || back.Session != id || back.Seq != seq {
			t.Fatalf("ping %d came back as %+v", seq, back)
		}
	}
	if hub.Sessions() != 0 {
		t.Fatalf("pings opened %d sessions", hub.Sessions())
	}
	probe.Close()

	carrier, relaySide := net.Pipe()
	defer carrier.Close()
	go func() { _ = hub.ServeStream(ctx, "k", relaySide) }()
	session := dup.Session{9}
	if back := exchange(carrier, dup.Frame{Kind: dup.KindAttach, Session: session, Lane: dup.LaneVoice}); back.Kind != dup.KindAttach {
		t.Fatalf("attach came back as %+v", back)
	}
	if back := exchange(carrier, dup.Frame{Kind: dup.KindPing, Session: id, Seq: 7}); back.Kind != dup.KindPing || back.Seq != 7 {
		t.Fatalf("a ping in a session came back as %+v", back)
	}
	if hub.Sessions() != 1 {
		t.Fatalf("sessions %d, want the one attached", hub.Sessions())
	}
}

// callPackets is a call of 20 ms packets long enough for a cut of cutFor at
// 3 s and 3 s after it.
func callPackets(cutFor time.Duration) int {
	return int((6*time.Second + cutFor) / (20 * time.Millisecond))
}
