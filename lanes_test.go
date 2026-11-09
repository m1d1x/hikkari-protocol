package hikkari_test

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/internal/testcert"
	"github.com/m1d1x/hikkari-protocol/server"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// narrowLink is one QUIC connection's send side on a narrow path: one FIFO of
// 32 frames, as quic-go queues DATAGRAM frames, drained at rate bytes per
// second. A full queue makes the writer wait, as SendDatagram does. Every
// association opened through it shares the queue, as they share the
// connection.
type narrowLink struct {
	inner client.Channel
	rate  int
	once  sync.Once
	queue chan func()
}

func (l *narrowLink) start() {
	l.queue = make(chan func(), 32)
	go func() {
		for send := range l.queue {
			send()
		}
	}()
}

func (l *narrowLink) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	return l.inner.DialContext(ctx, network, dest)
}

func (l *narrowLink) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	l.once.Do(l.start)
	p, err := l.inner.ListenPacket(ctx, dest)
	if err != nil {
		return nil, err
	}
	return &narrowConn{PacketConn: p, link: l}, nil
}

type narrowConn struct {
	net.PacketConn
	link *narrowLink
}

func (c *narrowConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	frame := append([]byte(nil), p...)
	wire := time.Duration(len(frame)) * time.Second / time.Duration(c.link.rate)
	c.link.queue <- func() {
		start := time.Now()
		_, _ = c.PacketConn.WriteTo(frame, addr)
		if rest := wire - time.Since(start); rest > 0 {
			time.Sleep(rest)
		}
	}
	return len(p), nil
}

// callWithVideo sends, through one socket for 6 s, a call's voice (160 B
// every 20 ms) and its video (6 × 1200 B every 33 ms and a 40-packet key
// frame every second, about 2.1 Mbit/s), and reports the voice's round trips
// and the longest silence between voice answers, and the share of video
// answered.
func callWithVideo(conn net.PacketConn, to net.Addr) (p95, worstRTT, worstGap time.Duration, voiceGot, voiceSent, videoGot, videoSent int) {
	const run = 6 * time.Second
	var mu sync.Mutex
	sentAt := map[uint16]time.Time{}
	var rtts []time.Duration
	var last time.Time
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 2048)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			now := time.Now()
			mu.Lock()
			if n == 160 {
				seq := uint16(b[0])<<8 | uint16(b[1])
				if at, ok := sentAt[seq]; ok {
					delete(sentAt, seq)
					rtts = append(rtts, now.Sub(at))
					voiceGot++
					if !last.IsZero() && now.Sub(last) > worstGap {
						worstGap = now.Sub(last)
					}
					last = now
				}
			} else {
				videoGot++
			}
			mu.Unlock()
		}
	}()
	stop := time.Now().Add(run)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for seq := uint16(0); time.Now().Before(stop); seq++ {
			p := make([]byte, 160)
			p[0], p[1] = byte(seq>>8), byte(seq)
			mu.Lock()
			sentAt[seq] = time.Now()
			voiceSent++
			mu.Unlock()
			_, _ = conn.WriteTo(p, to)
			time.Sleep(20 * time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		frame := 0
		for time.Now().Before(stop) {
			burst := 6
			if frame%30 == 0 {
				burst = 40
			}
			for i := 0; i < burst; i++ {
				_, _ = conn.WriteTo(make([]byte, 1200), to)
			}
			mu.Lock()
			videoSent += burst
			mu.Unlock()
			frame++
			time.Sleep(33 * time.Millisecond)
		}
	}()
	wg.Wait()
	<-done
	mu.Lock()
	defer mu.Unlock()
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	if len(rtts) > 0 {
		p95 = rtts[len(rtts)*95/100]
		worstRTT = rtts[len(rtts)-1]
	}
	return
}

// TestCallWithVideoNarrowLink is tester tamila-001 on 2026-11-09: a Discord
// call with her stream in one socket, on a path narrower than call plus video.
// Voice must keep its pace though the datagram channel's queue is full of
// video and the stream channel stalls.
func TestCallWithVideoNarrowLink(t *testing.T) {
	const key = "subscriber-key-0123456789abcdef"
	const rate = 250_000 // 2 Mbit/s
	cert, pool := testcert.New("hk.example")
	keys := &roster{keys: map[string]bool{key: true}, slots: map[int]context.CancelFunc{}}
	listen := freeUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	defer d.Close()
	d.SetKeys([]string{key})
	newDatagram := func() *client.Datagram {
		dc, err := client.NewDatagram(client.DatagramOptions{
			Context: ctx, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(listen), Password: key,
			TLS: &testcert.Client{Config: &tls.Config{ServerName: "hk.example", RootCAs: pool}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = dc.Close() })
		return dc
	}
	stream := &hubStream{hub: hub, key: key}
	c := client.New(client.Options{
		Stream:        stream,
		Datagram:      &narrowLink{inner: newDatagram(), rate: rate},
		VoiceDatagram: &narrowLink{inner: newDatagram(), rate: rate},
		Dup:           true,
	})
	echo := newSourceEcho(t)
	defer echo.Close()
	conn, err := c.ListenPacket(ctx, M.Socksaddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The relay's attach answer arrives and the call is seen before the
	// stream channel stalls.
	_, _, _ = callStats(conn, echo.LocalAddr(), 100, 160, 20*time.Millisecond)
	stream.stall.Store(true)
	defer stream.stall.Store(false)

	p95, worstRTT, worstGap, voiceGot, voiceSent, videoGot, videoSent := callWithVideo(conn, echo.LocalAddr())
	t.Logf("voice %d/%d, rtt p95 %v, max %v, worst gap %v; video %d/%d", voiceGot, voiceSent, p95, worstRTT, worstGap, videoGot, videoSent)
	if voiceGot < voiceSent*98/100 || p95 > 40*time.Millisecond || worstGap > 80*time.Millisecond {
		t.Fatalf("voice behind video: %d/%d answered, rtt p95 %v, worst gap %v", voiceGot, voiceSent, p95, worstGap)
	}
	if videoGot < videoSent/2 {
		t.Fatalf("video starved: %d/%d", videoGot, videoSent)
	}
	if sources, _ := echo.seen(); sources != 1 {
		t.Fatalf("far end saw %d sources", sources)
	}
}
