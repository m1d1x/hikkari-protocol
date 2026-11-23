package pipectl

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
)

// ExitConfig starts an exit's pipe.
type ExitConfig struct {
	Bin    string   // hk-exit
	Args   []string // its other flags (--tick-us, --flow-idle-ms)
	Stderr io.Writer
	Logf   func(format string, a ...any)
	// Local hears of each connection the exit opens to its relay and closes
	// (Mark names the stream or flow behind one); Observe gets the exit's
	// reports of the testers' streams and flows the brain marked, their Tag
	// the one Mark was given. Both are called on the brain's reading
	// goroutine: neither may block.
	Local   func(ExitLocal)
	Observe func(trunk.Report)
}

// ExitWire is a wire the exit's pipe serves, as the brain configures it.
type ExitWire struct {
	ID trunk.WireID
	// Conn is the wire's socket, bound by the brain; the pipe gets a copy of
	// it and the brain keeps it (a reload hands it to the next pipe).
	Conn *net.UDPConn
	// Form is the wire's form: FormUDP (when 0) or FormH3Dgram.
	Form byte
	// Keys are the trunk keys a member may open under (the pipe gets
	// udpwire.Key of each, or h3dgram.Token on the QUIC wire).
	Keys []string
	// CertFile and KeyFile are the QUIC wire's TLS certificate chain and
	// key (PEM), which the exit reads; the UDP wire has none.
	CertFile, KeyFile string
	// PointTLS restricts H3 names to their forwarding addresses.
	PointTLS *ExitPointTLS
	// Stall is how long a member may owe an answer while another member of
	// its session proves the entry alive (the pipe adds the ping interval
	// and raises it to 4 × the member's smoothed RTT); Quiet how long every
	// member of a session may be silent at once. trunk.DefaultStall and
	// trunk.ExitQuiet when 0.
	Stall, Quiet time.Duration
	Glue         time.Duration // how long frames wait to share a datagram; 1 ms when 0
	GlueMax      int           // the most a glued datagram holds; 1200 when 0
}

// Exit is a running exit's pipe.
type Exit struct {
	cfg  ExitConfig
	cmd  *exec.Cmd
	conn *net.UnixConn
	done chan struct{}
	err  error

	wmu sync.Mutex

	mu    sync.Mutex
	pid   int
	wires map[trunk.WireID]ExitWire
	pool  *exitPool
	ports []uint16
	// copyWindow is the window answers wait on a member of copies
	// (SetCopyWindow), for a reload.
	copyWindow time.Duration
	tick       ExitTick
	tickAt     time.Time

	hello chan struct{}
	// tags are what the streams and flows the brain marked were marked
	// with, by observation id, until their end is reported.
	tags map[uint64]string
	// drained is closed once the exit, draining, says it carries nothing
	// more.
	drained     chan struct{}
	drainedOnce sync.Once
}

// exitPool is the pool's port as the brain gave it.
type exitPool struct {
	l            *net.TCPListener
	stall, quiet time.Duration
}

// StartExit runs the exit's pipe under this brain, as Start runs the
// entry's.
func StartExit(cfg ExitConfig) (*Exit, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	cmd, conn, err := spawn(cfg.Bin, append([]string{"--ctl-fd", "3"}, cfg.Args...), cfg.Stderr)
	if err != nil {
		return nil, err
	}
	x := &Exit{cfg: cfg, cmd: cmd, conn: conn, done: make(chan struct{}), wires: map[trunk.WireID]ExitWire{}, hello: make(chan struct{}), drained: make(chan struct{}),
		tags: map[uint64]string{}}
	go func() {
		x.err = cmd.Wait()
		close(x.done)
		conn.Close()
	}()
	go x.read()
	if err := x.send(binary.LittleEndian.AppendUint16([]byte{xHello}, ExitVersion)); err != nil {
		x.Close()
		return nil, err
	}
	select {
	case <-x.hello:
	case <-x.done:
		return nil, fmt.Errorf("pipectl: the exit ended before its hello: %v", x.err)
	case <-time.After(5 * time.Second):
		x.Close()
		return nil, errors.New("pipectl: no hello from the exit in 5 s")
	}
	return x, nil
}

func (x *Exit) send(msg []byte, conns ...syscall.Conn) error {
	return sendWith(x.conn, &x.wmu, msg, conns...)
}

// SetWire gives the exit a wire: its socket, its keys, its members' stall
// and Quiet. A wire is given once.
func (x *Exit) SetWire(w ExitWire) error {
	if w.Glue == 0 {
		w.Glue = time.Millisecond
	}
	if w.GlueMax == 0 {
		w.GlueMax = 1200
	}
	if w.Stall == 0 {
		w.Stall = trunk.DefaultStall
	}
	if w.Quiet == 0 {
		w.Quiet = trunk.ExitQuiet
	}
	if w.Form == 0 {
		w.Form = FormUDP
	}
	m, err := putExitWire(w)
	if err != nil {
		return err
	}
	if err := x.send(m, w.Conn); err != nil {
		return err
	}
	x.mu.Lock()
	x.wires[w.ID] = w
	x.mu.Unlock()
	return nil
}

// SetPool gives the exit the pool's port: stream members (plain TCP here;
// Chromium's TLS under them is R2) connect to l, bound by the brain, which
// keeps it; with l nil the exit listens on nothing and its members come by
// Link. Their stall and the session's Quiet as in ExitWire
// (trunk.DefaultStall, trunk.ExitQuiet when 0). Given once.
func (x *Exit) SetPool(l *net.TCPListener, stall, quiet time.Duration) error {
	if stall == 0 {
		stall = trunk.DefaultStall
	}
	if quiet == 0 {
		quiet = trunk.ExitQuiet
	}
	var err error
	if l != nil {
		err = x.send(putExitPool(stall, quiet), l)
	} else {
		err = x.send(putExitPool(stall, quiet))
	}
	if err != nil {
		return err
	}
	x.mu.Lock()
	x.pool = &exitPool{l: l, stall: stall, quiet: quiet}
	x.mu.Unlock()
	return nil
}

// SetPorts says which loopback ports are open to the trunk (trunk
// Local.DialFlow and DialStream refuse the others); the set replaces the one
// before. The trunk's call and download, port 0, are always answered.
func (x *Exit) SetPorts(ports []uint16) error {
	if err := x.send(putExitPorts(ports)); err != nil {
		return err
	}
	x.mu.Lock()
	x.ports = append([]uint16(nil), ports...)
	x.mu.Unlock()
	return nil
}

// SetCopyWindow is how long the exit holds answers on a stream member that
// carried no stream, a pool's member of copies (spec/trunk.md, "Copies on
// the pool"): the answers of a window go down in one write. 0 holds none.
func (x *Exit) SetCopyWindow(window time.Duration) error {
	if window < 0 || window > time.Second {
		return fmt.Errorf("pipectl: a window of copies %v, want 0 to 1s", window)
	}
	if err := x.send(putExitCopies(window)); err != nil {
		return err
	}
	x.mu.Lock()
	x.copyWindow = window
	x.mu.Unlock()
	return nil
}

// Tick is the latest tick and when it came.
func (x *Exit) Tick() (ExitTick, time.Time) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.tick, x.tickAt
}

// Pid is the pipe's process.
func (x *Exit) Pid() int { return x.cmd.Process.Pid }

// Done is closed once the pipe has ended.
func (x *Exit) Done() <-chan struct{} { return x.done }

// Close ends the pipe and closes the brain's sockets.
func (x *Exit) Close() error {
	_ = x.cmd.Process.Kill()
	<-x.done
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, w := range x.wires {
		w.Conn.Close()
	}
	if x.pool != nil && x.pool.l != nil {
		x.pool.l.Close()
	}
	return nil
}

// Link gives the exit a stream member's connected socket, as if accepted on
// the pool's port: the relay's brain takes a member's CONNECT itself and
// hands its own end of a socket pair over (edge trunk_pipe.go). It needs
// SetPool first, with or without a listening socket. The exit has its own
// descriptor: the caller closes c's.
func (x *Exit) Link(c *os.File) error {
	x.mu.Lock()
	pool := x.pool
	x.mu.Unlock()
	if pool == nil {
		return errors.New("pipectl: a member before the pool: SetPool first")
	}
	return x.send([]byte{xLink}, c)
}

func (x *Exit) read() {
	buf := make([]byte, 4096)
	helloed := false
	for {
		n, _, flags, _, err := x.conn.ReadMsgUnix(buf, nil)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if flags&syscall.MSG_TRUNC != 0 {
			x.cfg.Logf("pipectl: a message from the exit torn by the buffer")
			continue
		}
		m := buf[:n]
		switch m[0] {
		case xpHello:
			if n < 7 || binary.LittleEndian.Uint16(m[1:]) != ExitVersion {
				x.cfg.Logf("pipectl: the exit's hello % x is not version %d", m, ExitVersion)
				_ = x.cmd.Process.Kill()
				return
			}
			x.mu.Lock()
			x.pid = int(binary.LittleEndian.Uint32(m[3:]))
			x.mu.Unlock()
			if !helloed {
				helloed = true
				close(x.hello)
			}
		case xpTick:
			t, err := parseExitTick(m)
			if err != nil {
				x.cfg.Logf("%v", err)
				continue
			}
			x.mu.Lock()
			x.tick, x.tickAt = t, time.Now()
			x.mu.Unlock()
		case xpLocal:
			l, err := parseExitLocal(m)
			if err != nil {
				x.cfg.Logf("%v", err)
				continue
			}
			if x.cfg.Local != nil {
				x.cfg.Local(l)
			}
		case xpObserved:
			o, err := parseObserved(m)
			if err != nil {
				x.cfg.Logf("%v", err)
				continue
			}
			r := o.Report
			x.mu.Lock()
			r.Tag = x.tags[r.ID]
			if r.Phase == trunk.PhaseEnd {
				delete(x.tags, r.ID)
			}
			x.mu.Unlock()
			if x.cfg.Observe != nil {
				x.cfg.Observe(r)
			}
		case xpDrained:
			x.cfg.Logf("pipectl: the exit drained")
			x.drainedOnce.Do(func() { close(x.drained) })
		case xpError:
			x.cfg.Logf("pipectl: the exit: %s", m[1:])
		default:
			x.cfg.Logf("pipectl: a message from the exit the brain does not know: type %#x", m[0])
		}
	}
}

// Mark marks the stream or flow `stream` of the session for both ends to
// report (spec/trunk.md, "Observation"; trunk Session.Observe): the relay
// admitted a tester's key on its connection, whose local port the exit told
// Local. The brain draws the observation's id; tag goes into the exit's
// reports of it (Observe), never across the trunk. A stream or flow already
// ended or marked is not marked again: the exit reports nothing for it.
func (x *Exit) Mark(kind trunk.ObsKind, session trunk.SessionID, stream uint32, tag string) (uint64, error) {
	id := obsID()
	x.mu.Lock()
	// A mark that reached the exit after its stream ended is never
	// reported, and its tag never asked for: past maxTags one is forgotten.
	if len(x.tags) >= maxTags {
		for k := range x.tags {
			delete(x.tags, k)
			break
		}
	}
	x.tags[id] = tag
	x.mu.Unlock()
	if err := x.send(putExitMark(kind, session, stream, id)); err != nil {
		x.mu.Lock()
		delete(x.tags, id)
		x.mu.Unlock()
		return 0, err
	}
	return id, nil
}

// maxTags bounds the marks waiting for their end.
const maxTags = 4096

// obsID is a random observation id, never 0 (trunk newObsID).
func obsID() uint64 {
	var b [8]byte
	for {
		_, _ = rand.Read(b[:])
		if id := binary.LittleEndian.Uint64(b[:]); id != 0 {
			return id
		}
	}
}
