package pipectl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
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
}

// ExitWire is a wire the exit's pipe serves, as the brain configures it.
type ExitWire struct {
	ID trunk.WireID
	// Conn is the wire's socket, bound by the brain; the pipe gets a copy of
	// it and the brain keeps it (a reload hands it to the next pipe).
	Conn *net.UDPConn
	// Keys are the trunk keys a member may open under (the pipe gets
	// udpwire.Key of each).
	Keys []string
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

	mu     sync.Mutex
	pid    int
	wires  map[trunk.WireID]*net.UDPConn
	pool   *net.TCPListener
	tick   ExitTick
	tickAt time.Time

	hello chan struct{}
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
	x := &Exit{cfg: cfg, cmd: cmd, conn: conn, done: make(chan struct{}), wires: map[trunk.WireID]*net.UDPConn{}, hello: make(chan struct{})}
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
	m, err := putExitWire(w.ID, w.Glue, w.GlueMax, w.Stall, w.Quiet, w.Keys)
	if err != nil {
		return err
	}
	if err := x.send(m, w.Conn); err != nil {
		return err
	}
	x.mu.Lock()
	x.wires[w.ID] = w.Conn
	x.mu.Unlock()
	return nil
}

// SetPool gives the exit the pool's port: stream members (plain TCP here;
// Chromium's TLS under them is R2) connect to l, bound by the brain, which
// keeps it. Their stall and the session's Quiet as in ExitWire
// (trunk.DefaultStall, trunk.ExitQuiet when 0). Given once.
func (x *Exit) SetPool(l *net.TCPListener, stall, quiet time.Duration) error {
	if stall == 0 {
		stall = trunk.DefaultStall
	}
	if quiet == 0 {
		quiet = trunk.ExitQuiet
	}
	if err := x.send(putExitPool(stall, quiet), l); err != nil {
		return err
	}
	x.mu.Lock()
	x.pool = l
	x.mu.Unlock()
	return nil
}

// SetPorts says which loopback ports are open to the trunk (trunk
// Local.DialFlow and DialStream refuse the others); the set replaces the one
// before. The trunk's call and download, port 0, are always answered.
func (x *Exit) SetPorts(ports []uint16) error { return x.send(putExitPorts(ports)) }

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
	for _, c := range x.wires {
		c.Close()
	}
	if x.pool != nil {
		x.pool.Close()
	}
	return nil
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
		case xpError:
			x.cfg.Logf("pipectl: the exit: %s", m[1:])
		default:
			x.cfg.Logf("pipectl: a message from the exit the brain does not know: type %#x", m[0])
		}
	}
}
