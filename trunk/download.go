package trunk

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// The trunk's own download: a stream to EchoPort, held to one wire, asks the
// exit for n bytes and takes them (hikkari-client
// plans/2026-11-11-trunk-wires-stage4.md, раздел 5: 1 MiB every 10 minutes
// on every wire). The exit answers it from the trunk itself, with no socket
// and nothing of a client's: 8 bytes of the length asked, then that many
// zeros, then its end. An exit older than this has no port 0 open and resets
// the stream: the download fails.

// MaxDownload bounds what one download may ask for.
const MaxDownload = 64 << 20

// sourceConn is the exit's end of a download: it reads the length and
// writes that many zeros back.
func sourceConn() net.Conn {
	trunkEnd, source := net.Pipe()
	go func() {
		defer source.Close()
		var req [8]byte
		if _, err := io.ReadFull(source, req[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint64(req[:])
		if n > MaxDownload {
			return
		}
		buf := make([]byte, 32<<10)
		for n > 0 {
			k := uint64(len(buf))
			if k > n {
				k = n
			}
			if _, err := source.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	}()
	return trunkEnd
}

// DownloadResult is one download.
type DownloadResult struct {
	Want, Got int
	Took      time.Duration // until the last byte, or until it gave up
	// End is ok (every byte came), timeout (ctx ended first), closed (the
	// stream ended short: reset, or an exit that has no download).
	End string
}

// Download takes n bytes from the exit over wire alone, on the current
// session, until ctx ends.
func (e *Entry) Download(ctx context.Context, wire WireID, n int) DownloadResult {
	r := DownloadResult{Want: n, End: "closed"}
	if n <= 0 || n > MaxDownload {
		return r
	}
	client, edge := net.Pipe()
	defer client.Close()
	s := e.Session()
	st := s.open(edge, EchoPort, wire)
	if st == nil {
		return r
	}
	go s.readLocal(st)
	start := time.Now()
	// A download that did not finish leaves nothing waiting: its chunks may
	// sit for a wire that is not there.
	defer s.abort(st)
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	var req [8]byte
	binary.BigEndian.PutUint64(req[:], uint64(n))
	if _, err := client.Write(req[:]); err != nil {
		r.Took = time.Since(start)
		if ctx.Err() != nil {
			r.End = "timeout"
		}
		return r
	}
	got, err := io.CopyN(io.Discard, client, int64(n))
	r.Got, r.Took = int(got), time.Since(start)
	switch {
	case err == nil:
		r.End = "ok"
	case ctx.Err() != nil:
		r.End = "timeout"
	case errors.Is(err, io.EOF):
		r.End = "closed"
	}
	return r
}
