package datagram

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/m1d1x/hikkari-protocol/wire/datagram/internal/protocol"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ServiceOptions struct {
	Context            context.Context
	Logger             logger.Logger
	SalamanderPassword string
	TLSConfig          aTLS.ServerConfig
	QUICOptions        qtls.QUICOptions
	UDPTimeout         time.Duration
	Handler            ServerHandler
	MasqueradeHandler  http.Handler
	BBRProfile         string
	// OnAuth, when set, is told of every connection that authenticates, as
	// it does (v1.04 observability).
	OnAuth func(user any, conn *quic.Conn)
}

type ServerHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx                context.Context
	logger             logger.Logger
	salamanderPassword string
	tlsConfig          aTLS.ServerConfig
	quicConfig         *quic.Config
	userMap            atomic.Pointer[map[string]U]
	udpTimeout         time.Duration
	handler            ServerHandler
	masqueradeHandler  http.Handler
	quicListener       io.Closer
	bbrProfile         congestion_meta2.Profile
	onAuth             func(user any, conn *quic.Conn)
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		MaxIncomingStreams:             1 << 60,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
		DisablePathManager:             true,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	service := &Service[U]{
		ctx:                options.Context,
		logger:             options.Logger,
		salamanderPassword: options.SalamanderPassword,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpTimeout:         options.UDPTimeout,
		handler:            options.Handler,
		masqueradeHandler:  options.MasqueradeHandler,
		onAuth:             options.OnAuth,
		bbrProfile:         bbrProfile,
	}
	service.userMap.Store(&map[string]U{})
	return service, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U)
	for i, user := range userList {
		userMap[passwordList[i]] = user
	}
	// Swapped whole: sessions authenticating now read one roster or the other.
	s.userMap.Store(&userMap)
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if s.salamanderPassword != "" {
		conn = NewSalamanderConn(conn, []byte(s.salamanderPassword))
	}
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	obfsEnabled := s.salamanderPassword != ""
	listener, err := qtls.ListenWithOptions(conn, s.tlsConfig, s.quicConfig, qtls.ListenOptions{
		DisableVersionNegotiationPackets: obfsEnabled,
		StatelessReset:                   !obfsEnabled,
	})
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(s.quicListener)
}

func (s *Service[U]) loopConnections(listener qtls.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	httpServer := http3.Server{
		Handler:          session,
		StreamDispatcher: session.dispatchStream,
	}
	_ = httpServer.ServeQUICConn(connection)
	_ = connection.CloseWithError(0, "")
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx           context.Context
	quicConn      *quic.Conn
	connAccess    sync.Mutex
	connDone      chan struct{}
	connErr       error
	authenticated bool
	authUser      U
	udpAccess     sync.RWMutex
	udpConnMap    map[uint32]*udpPacketConn
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		if s.authenticated {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{UDPEnabled: true, RxAuto: true})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		request := protocol.AuthRequestFromHeader(r.Header)
		user, loaded := (*s.userMap.Load())[request.Auth]
		if !loaded {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		s.authUser = user
		s.authenticated = true
		if s.onAuth != nil {
			s.onAuth(user, s.quicConn)
		}
		// BBR always, whatever bandwidth the client claims: Brutal's fixed
		// rate makes no bandwidth and costs latency.
		s.quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
			s.quicConn.InitialPacketSize(),
			s.bbrProfile,
		))
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{UDPEnabled: true, RxAuto: true})
		w.WriteHeader(protocol.StatusAuthOK)
		if s.ctx.Done() != nil {
			go func() {
				select {
				case <-s.ctx.Done():
					s.closeWithError(s.ctx.Err())
				case <-s.connDone:
				}
			}()
		}
		go s.loopMessages()
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *serverSession[U]) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if !s.authenticated || err != nil {
		return false, nil
	}
	if frameType != protocol.FrameTypeTCPRequest {
		return false, nil
	}
	_, err = quicvarint.Read(quicvarint.NewReader(stream))
	if err != nil {
		s.logger.Error(E.Cause(err, "seek frame type"))
		return true, nil
	}
	go func() {
		hErr := s.handleStream(stream)
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	destinationString, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	destination := M.ParseSocksaddr(destinationString).Unwrap()
	if len(destination.Fqdn) > 255 {
		return E.New("fqdn too long")
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, s.authUser), &serverConn{Stream: stream}, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), destination, nil)
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint32]*udpPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type serverConn struct {
	*quic.Stream
	responseWritten bool
}

func (c *serverConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrInvalid
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(false, err.Error(), nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(true, "", nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer := protocol.WriteTCPResponse(true, "", p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, qtls.WrapError(err)
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
