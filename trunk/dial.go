package trunk

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// A member's wire is a Naive tunnel: TLS to the exit's relay with a browser's
// ClientHello and the relay's real certificate, then an HTTP/2 CONNECT to
// Host, padded as Naive pads the first frames each way. On the exit the
// Hikkari relay answers it behind its own auth (hikkari-control edge/trunk_exit.go) and hands the
// tunnel to Exit.ServeMember; anyone else gets the relay's site.

// Host is the CONNECT authority of a trunk member.
const Host = "trunk.hikkari.arpa:443"

// User is the Proxy-Authorization user of a trunk member; the password is
// the trunk key.
const User = "trunk"

// Hellos are the ClientHellos a member can send, by the name the hub gives
// (EDGE_TRUNK_FP). There is no default: the hub chooses by measurement
// (опыт 0 found chrome133 cut at the border, chrome131 and firefox not).
var Hellos = map[string]utls.ClientHelloID{
	"chrome_131":  utls.HelloChrome_131,
	"chrome_133":  utls.HelloChrome_133,
	"chrome_120":  utls.HelloChrome_120,
	"firefox_120": utls.HelloFirefox_120,
	"firefox_148": utls.HelloFirefox_148,
	"safari_26":   utls.HelloSafari_26_3,
	"edge_106":    utls.HelloEdge_106,
}

// HelloNames lists Hellos' keys, sorted.
func HelloNames() []string {
	names := make([]string, 0, len(Hellos))
	for n := range Hellos {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Dialer opens members to one exit.
type Dialer struct {
	// Exit is the relay's address, ip:port.
	Exit string
	// SNI is the relay's domain: the certificate is checked against it.
	SNI string
	// Hello is the ClientHello preset.
	Hello utls.ClientHelloID
	// Key is the trunk key the exit's relay admits.
	Key string
	// Timeout bounds TCP, TLS and the CONNECT answer together.
	Timeout time.Duration
	// Roots verifies the certificate; nil is the system's (tests set it).
	Roots *x509.CertPool
}

// Dial implements Dial. A path that does not answer within Timeout is
// ErrSilent: the port it came from is suspect.
func (d Dialer) Dial(ctx context.Context, localPort int) (io.ReadWriteCloser, error) {
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = helloTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	nd := net.Dialer{LocalAddr: &net.TCPAddr{Port: localPort}, KeepAlive: 15 * time.Second}
	raw, err := nd.DialContext(ctx, "tcp", d.Exit)
	if err != nil {
		return nil, silent(ctx, err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	tlsConn := utls.UClient(raw, &utls.Config{ServerName: d.SNI, RootCAs: d.Roots, MinVersion: utls.VersionTLS12}, d.Hello)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, silent(ctx, fmt.Errorf("tls: %w", err))
	}
	if p := tlsConn.ConnectionState().NegotiatedProtocol; p != "h2" {
		raw.Close()
		return nil, fmt.Errorf("tls: the relay chose %q, not h2", p)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tlsConn)
	if err != nil {
		raw.Close()
		return nil, err
	}
	body, feed := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: Host},
		Host:   Host,
		Header: http.Header{
			"Proxy-Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(User+":"+d.Key))},
			"Padding":             {padHeader()},
		},
		Body:          body,
		ContentLength: -1,
	}
	type answer struct {
		resp *http.Response
		err  error
	}
	got := make(chan answer, 1)
	// The tunnel lives past this call: its request is not bound to ctx.
	go func() { r, err := cc.RoundTrip(req); got <- answer{r, err} }()
	var a answer
	select {
	case a = <-got:
	case <-ctx.Done():
		cc.Close()
		raw.Close()
		return nil, ErrSilent
	}
	if a.err != nil {
		raw.Close()
		return nil, fmt.Errorf("connect: %w", a.err)
	}
	if a.resp.StatusCode != http.StatusOK {
		a.resp.Body.Close()
		raw.Close()
		return nil, fmt.Errorf("connect: %s", a.resp.Status)
	}
	padded := a.resp.Header.Get("Padding") != ""
	t := &tunnel{body: a.resp.Body, feed: feed, cc: cc, raw: raw}
	if padded {
		t.r = &unpadReader{r: a.resp.Body}
		t.w = &padWriter{w: feed}
	} else {
		// The relay did not agree to pad: our first frames would carry
		// padding it would not strip.
		t.Close()
		return nil, errors.New("connect: the relay does not pad")
	}
	return t, nil
}

func silent(ctx context.Context, err error) error {
	var ne net.Error
	if ctx.Err() != nil || (errors.As(err, &ne) && ne.Timeout()) || errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w: %v", ErrSilent, err)
	}
	return err
}

type tunnel struct {
	r    io.Reader
	w    io.Writer
	body io.ReadCloser
	feed *io.PipeWriter
	cc   *http2.ClientConn
	raw  net.Conn
	once sync.Once
}

func (t *tunnel) Read(p []byte) (int, error)  { return t.r.Read(p) }
func (t *tunnel) Write(p []byte) (int, error) { return t.w.Write(p) }
func (t *tunnel) Close() error {
	t.once.Do(func() {
		_ = t.feed.Close()
		_ = t.body.Close()
		_ = t.cc.Close()
		_ = t.raw.Close()
	})
	return nil
}

// Naive padding (hikkari-protocol server/naive, dualStream): the first
// padFrames writes each way carry a 3-byte header (length u16, padding u8),
// the bytes and that many zeros; then the bytes go as they are.
const padFrames = 8

func padHeader() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(32))
	b := make([]byte, 30+n.Int64())
	for i := range b {
		if i < 16 {
			k, _ := rand.Int(rand.Reader, big.NewInt(16))
			b[i] = "!#$()+<>?@[]^`{}"[k.Int64()]
		} else {
			b[i] = '~'
		}
	}
	return string(b)
}

type padWriter struct {
	w    io.Writer
	sent int
}

func (p *padWriter) Write(b []byte) (int, error) {
	if p.sent >= padFrames {
		return p.w.Write(b)
	}
	written := 0
	for len(b) > 0 && p.sent < padFrames {
		k, _ := rand.Int(rand.Reader, big.NewInt(256))
		pad := int(k.Int64())
		n := len(b)
		if max := 65535 - 3 - 255; n > max {
			n = max
		}
		frame := make([]byte, 3+n+pad)
		frame[0], frame[1], frame[2] = byte(n>>8), byte(n), byte(pad)
		copy(frame[3:], b[:n])
		if _, err := p.w.Write(frame); err != nil {
			return written, err
		}
		p.sent++
		written += n
		b = b[n:]
	}
	if len(b) > 0 {
		n, err := p.w.Write(b)
		return written + n, err
	}
	return written, nil
}

type unpadReader struct {
	r    io.Reader
	got  int
	left int // bytes of the current padded frame not yet read
	pad  int
}

func (u *unpadReader) Read(b []byte) (int, error) {
	for u.got < padFrames || u.left > 0 {
		if u.left == 0 {
			var h [3]byte
			if _, err := io.ReadFull(u.r, h[:]); err != nil {
				return 0, err
			}
			u.left, u.pad = int(h[0])<<8|int(h[1]), int(h[2])
			u.got++
			if u.left == 0 {
				if err := u.skip(); err != nil {
					return 0, err
				}
				continue
			}
		}
		if len(b) > u.left {
			b = b[:u.left]
		}
		n, err := u.r.Read(b)
		u.left -= n
		if u.left == 0 && n > 0 {
			if err := u.skip(); err != nil {
				return n, err
			}
		}
		return n, err
	}
	return u.r.Read(b)
}

func (u *unpadReader) skip() error {
	if u.pad == 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, u.r, int64(u.pad))
	u.pad = 0
	return err
}

// ParseKey checks a trunk key: printable, no separators, at least 24 bytes.
func ParseKey(key string) error {
	if len(key) < 24 || strings.ContainsAny(key, ":,\r\n\t ") {
		return errors.New("trunk: a key is 24+ characters without ':', ',' or spaces")
	}
	return nil
}
