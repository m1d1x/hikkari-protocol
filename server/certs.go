package server

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CaddyCertificate serves the certificate Caddy keeps for host in its file
// storage (certificates/<issuer>/<host>/<host>.crt and .key), the newest
// issuer's, reloading when Caddy renews it. Until the first one is issued it
// returns an error, and a handshake fails rather than shows another name.
func CaddyCertificate(storage, host string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := &caddyCerts{storage: storage, host: host}
	return c.get
}

type caddyCerts struct {
	storage, host string
	mu            sync.Mutex
	path          string
	mtime         time.Time
	cert          *tls.Certificate
}

func (c *caddyCerts) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	matches, _ := filepath.Glob(filepath.Join(c.storage, "certificates", "*", c.host, c.host+".crt"))
	var newest string
	var newestTime time.Time
	for _, m := range matches {
		if st, err := os.Stat(m); err == nil && st.ModTime().After(newestTime) {
			newest, newestTime = m, st.ModTime()
		}
	}
	if newest == "" {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, errors.New("hikkari: no certificate yet for " + c.host)
	}
	if newest == c.path && newestTime.Equal(c.mtime) && c.cert != nil {
		return c.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(newest, strings.TrimSuffix(newest, ".crt")+".key")
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	c.path, c.mtime, c.cert = newest, newestTime, &cert
	return c.cert, nil
}
