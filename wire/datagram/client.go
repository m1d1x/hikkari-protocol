package datagram

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/wire/datagram/internal/protocol"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const defaultHandshakeTimeout = 15 * time.Second

type ClientOptions struct {
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	ServerAddress      M.Socksaddr
	SalamanderPassword string
	Password           string
	TLSConfig          aTLS.Config
	QUICOptions        qtls.QUICOptions
	BBRProfile         string
	ChromeParrot       bool
	// OnAuth, when set, is told of every connection the relay admits (v1.04
	// observability).
	OnAuth func(conn *quic.Conn)
}

type Client struct {
	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	serverAddr         M.Socksaddr
	salamanderPassword string
	password           string
	tlsConfig          aTLS.Config
	quicConfig         *quic.Config
	bbrProfile         congestion_meta2.Profile
	onAuth             func(conn *quic.Conn)

	connAccess sync.Mutex
	conn       *clientQUICConnection
	closeIdle  atomic.Bool
	pending    *clientOffer
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
		ChromeParrot:                   options.ChromeParrot,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		serverAddr:         options.ServerAddress,
		salamanderPassword: options.SalamanderPassword,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		bbrProfile:         bbrProfile,
		onAuth:             options.OnAuth,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := context.WithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	go c.completeOffer(pending, offerCtx)

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) offerWithStream(ctx context.Context) (*clientQUICConnection, error) {
	for {
		conn, err := c.offer(ctx)
		if err != nil {
			return nil, err
		}
		if conn.acquireStream() {
			return conn, nil
		}
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	rawConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	if c.salamanderPassword != "" {
		rawConn = NewSalamanderClientConn(rawConn, []byte(c.salamanderPassword))
		qtls.SetDesiredBufferSizes(rawConn)
	}
	return c.authenticateAndWrap(ctx, rawConn, func(quicConnPtr **quic.Conn) (http.RoundTripper, error) {
		return qtls.CreateTransport(rawConn, quicConnPtr, c.tlsConfig, c.quicConfig)
	})
}

func (c *Client) authenticateAndWrap(ctx context.Context, rawConn io.Closer, createTransport func(quicConnPtr **quic.Conn) (http.RoundTripper, error)) (*clientQUICConnection, error) {
	var quicConn *quic.Conn
	http3Transport, err := createTransport(&quicConn)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password})
	handshakeTimeout := c.tlsConfig.HandshakeTimeout()
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	authCtx, authCancel := context.WithTimeout(ctx, handshakeTimeout)
	defer authCancel()
	response, err := http3Transport.RoundTrip(request.WithContext(authCtx))
	if err != nil {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		rawConn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != protocol.StatusAuthOK {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		rawConn.Close()
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	// BBR always: Brutal's fixed rate makes no bandwidth and costs latency.
	quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
		quicConn.InitialPacketSize(),
		c.bbrProfile,
	))
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     rawConn,
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
		udpConnMap:  make(map[uint32]*udpPacketConn),
		closeIdle:   &c.closeIdle,
	}
	if c.onAuth != nil {
		c.onAuth(quicConn)
	}
	go c.loopMessages(conn)
	go func() {
		<-quicConn.Context().Done()
		conn.closeWithError(context.Cause(quicConn.Context()))
	}()
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offerWithStream(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		conn.releaseStream(false)
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		parent:      conn,
		destination: destination,
		keepSession: qtls.KeepSessionFromContext(ctx),
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.releaseUDPSession(sessionID)
	})
	conn.access.Lock()
	select {
	case <-conn.connDone:
		conn.access.Unlock()
		return nil, E.Errors(conn.connErr, os.ErrClosed)
	default:
	}
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.access.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.connAccess.Lock()
	conn := c.conn
	c.connAccess.Unlock()
	if conn == nil {
		return
	}
	conn.access.Lock()
	closed := conn.streams == 0 && len(conn.udpConnMap) == 0 && conn.markClosedLocked(os.ErrClosed)
	conn.access.Unlock()
	if closed {
		conn.closeTransport()
	}
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn     *quic.Conn
	rawConn      io.Closer
	connDone     chan struct{}
	connErr      error
	udpDisabled  bool
	access       sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
	streams      int
	closeIdle    *atomic.Bool
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) acquireStream() bool {
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.connDone:
		return false
	default:
	}
	c.streams++
	return true
}

func (c *clientQUICConnection) releaseStream(keepSession bool) {
	c.access.Lock()
	c.streams--
	closed := c.closeIdle.Load() && !keepSession && c.streams == 0 && len(c.udpConnMap) == 0 && c.markClosedLocked(os.ErrClosed)
	c.access.Unlock()
	if closed {
		c.closeTransport()
	}
}

func (c *clientQUICConnection) releaseUDPSession(sessionID uint32) {
	c.access.Lock()
	delete(c.udpConnMap, sessionID)
	closed := c.closeIdle.Load() && c.streams == 0 && len(c.udpConnMap) == 0 && c.markClosedLocked(os.ErrClosed)
	c.access.Unlock()
	if closed {
		c.closeTransport()
	}
}

func (c *clientQUICConnection) markClosedLocked(err error) bool {
	select {
	case <-c.connDone:
		return false
	default:
	}
	c.connErr = err
	close(c.connDone)
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.access.Lock()
	if !c.markClosedLocked(err) {
		c.access.Unlock()
		return
	}
	udpConnMap := c.udpConnMap
	c.udpConnMap = make(map[uint32]*udpPacketConn)
	c.access.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	c.closeTransport()
}

func (c *clientQUICConnection) closeTransport() {
	_ = c.quicConn.CloseWithError(0, "")
	_ = c.rawConn.Close()
}

type clientConn struct {
	*quic.Stream
	parent         *clientQUICConnection
	destination    M.Socksaddr
	keepSession    bool
	requestWritten bool
	responseRead   bool
	closeOnce      sync.Once
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, qtls.WrapError(err)
	}
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, qtls.WrapError(err)
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	c.closeOnce.Do(func() { c.parent.releaseStream(c.keepSession) })
	return err
}
