package naive

import (
	"context"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHikkariCancellationClosesConnectTarget(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialed := make(chan struct{})
	h := &Handler{logger: zap.NewNop(), aclRules: []aclRule{&aclAllRule{allow: true}}, dialContext: func(context.Context, string, string) (net.Conn, error) { close(dialed); return client, nil }}
	r := httptest.NewRequest(http.MethodConnect, "https://1.1.1.1:443", nil).WithContext(context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer()))
	r.URL = &url.URL{Host: "1.1.1.1:443"}
	r.Host = "1.1.1.1:443"
	r.ProtoMajor = 2
	r.Body = io.NopCloser(strings.NewReader(""))
	done := make(chan error, 1)
	go func() { done <- h.ServeHTTP(httptest.NewRecorder(), r, nil) }()
	select {
	case err := <-done:
		t.Fatalf("CONNECT returned before dial: %v", err)
	case <-dialed:
	case <-time.After(time.Second):
		t.Fatal("CONNECT did not dial target")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled CONNECT retained its target socket")
	}
}
