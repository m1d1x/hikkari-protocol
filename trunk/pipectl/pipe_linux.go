package pipectl

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/m1d1x/hikkari-protocol/trunk"
	"github.com/m1d1x/hikkari-protocol/trunk/udpwire"
)

// Config starts a pipe.
type Config struct {
	Bin    string   // hk-pipe
	Args   []string // its other flags (--tick-us, --gro)
	Stderr io.Writer
	Logf   func(format string, a ...any)
}

// Wire is a wire the pipe carries, as the brain configures it.
type Wire struct {
	ID      trunk.WireID
	Name    string
	Exit    netip.AddrPort
	Key     string // the trunk key; the pipe gets udpwire.Key of it
	Members int
	Glue    time.Duration // how long frames wait to share a datagram; 1 ms when 0
	GlueMax int           // the most a glued datagram holds; 1200 when 0
	Dead    time.Duration // a member owing an answer this long is down; 1 s when 0
}

// staleTick is how old the latest tick may be before the brain takes the
// pipe as not running: its wires say nothing then.
const staleTick = 3 * time.Second

// Pipe is a running pipe. It is a trunk.Steered (the selector reads its
// wires and sets its route) and a trunk.CallCarrier (the trunk's calls run
// through it as a client's datagrams do).
type Pipe struct {
	cfg  Config
	cmd  *exec.Cmd
	conn *net.UnixConn
	done chan struct{}
	err  error // the process's end, once done is closed

	wmu sync.Mutex // one writer at a time: a message and its sockets go together

	mu      sync.Mutex
	pid     int
	wires   map[trunk.WireID]*wireConf
	listens map[byte]*net.UDPConn
	route   trunk.Route
	tick    Tick
	tickAt  time.Time
	resumed time.Time
	flows   map[uint32]func([]byte)

	nextTag atomic.Uint32
	hello   chan struct{}
}

type wireConf struct {
	w       Wire
	members []*net.UDPConn
}

// Start runs the pipe under this brain: a socketpair, the pipe's end as its
// fd 3, the hellos. The pipe ends when Close does, or when this process
// does.
func Start(cfg Config) (*Pipe, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("pipectl: socketpair: %w", err)
	}
	mine := os.NewFile(uintptr(fds[0]), "pipectl-brain")
	theirs := os.NewFile(uintptr(fds[1]), "pipectl-pipe")
	defer theirs.Close()
	fc, err := net.FileConn(mine)
	mine.Close()
	if err != nil {
		return nil, fmt.Errorf("pipectl: %w", err)
	}
	conn := fc.(*net.UnixConn)
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	cmd := exec.Command(cfg.Bin, append([]string{"--ctl-fd", "3"}, cfg.Args...)...)
	cmd.ExtraFiles = []*os.File{theirs}
	cmd.Stderr = cfg.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("pipectl: %w", err)
	}
	p := &Pipe{cfg: cfg, cmd: cmd, conn: conn, done: make(chan struct{}), wires: map[trunk.WireID]*wireConf{},
		listens: map[byte]*net.UDPConn{}, route: trunk.AnyRoute, flows: map[uint32]func([]byte){}, hello: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
		conn.Close()
	}()
	go p.read()
	if err := p.send(binary.LittleEndian.AppendUint16([]byte{bHello}, Version)); err != nil {
		p.Close()
		return nil, err
	}
	select {
	case <-p.hello:
	case <-p.done:
		return nil, fmt.Errorf("pipectl: the pipe ended before its hello: %v", p.err)
	case <-time.After(5 * time.Second):
		p.Close()
		return nil, errors.New("pipectl: no hello from the pipe in 5 s")
	}
	return p, nil
}

// Close ends the pipe and closes the brain's sockets.
func (p *Pipe) Close() error {
	_ = p.cmd.Process.Kill()
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.listens {
		c.Close()
	}
	for _, w := range p.wires {
		for _, c := range w.members {
			if c != nil {
				c.Close()
			}
		}
	}
	return nil
}

// Done is closed once the pipe has ended.
func (p *Pipe) Done() <-chan struct{} { return p.done }

// send writes one message with the sockets of conns.
func (p *Pipe) send(msg []byte, conns ...*net.UDPConn) error {
	var fds []int
	var raws []syscall.RawConn
	for _, c := range conns {
		rc, err := c.SyscallConn()
		if err != nil {
			return err
		}
		raws = append(raws, rc)
	}
	// The descriptors stay the brain's: the kernel copies them into the
	// message, and the pipe gets descriptors of its own.
	var werr error
	var hold func(i int)
	hold = func(i int) {
		if i == len(raws) {
			p.wmu.Lock()
			defer p.wmu.Unlock()
			var oob []byte
			if len(fds) > 0 {
				oob = syscall.UnixRights(fds...)
			}
			_, _, werr = p.conn.WriteMsgUnix(msg, oob, nil)
			return
		}
		if err := raws[i].Control(func(fd uintptr) {
			fds = append(fds, int(fd))
			hold(i + 1)
		}); err != nil {
			werr = err
		}
	}
	hold(0)
	if werr != nil {
		return fmt.Errorf("pipectl: %w", werr)
	}
	return nil
}

// Listen gives the pipe a client port: its datagrams are flows of class,
// to port `to` at the exit, each datagram on copies members.
func (p *Pipe) Listen(id byte, c *net.UDPConn, class trunk.Class, to uint16, copies int) error {
	if copies <= 0 {
		copies = 1
	}
	if err := p.send(putListen(id, class, to, copies), c); err != nil {
		return err
	}
	p.mu.Lock()
	if old := p.listens[id]; old != nil && old != c {
		old.Close()
	}
	p.listens[id] = c
	p.mu.Unlock()
	return nil
}

// SetWire gives the pipe a wire, or new members and settings of one it has:
// the brain dials the members (connected UDP sockets to w.Exit). A flow on
// the wire is not reset: its next datagram goes on the new members.
func (p *Pipe) SetWire(w Wire) error {
	if w.Glue == 0 {
		w.Glue = time.Millisecond
	}
	if w.GlueMax == 0 {
		w.GlueMax = 1200
	}
	if w.Dead == 0 {
		w.Dead = time.Second
	}
	key, err := udpwire.Key(w.Key)
	if err != nil {
		return err
	}
	msg, err := putWire(w.ID, FormUDP, w.Glue, w.GlueMax, w.Dead, key)
	if err != nil {
		return err
	}
	members := make([]*net.UDPConn, 0, w.Members)
	for i := 0; i < w.Members; i++ {
		c, err := dialMember(w.Exit)
		if err != nil {
			closeAll(members)
			return err
		}
		members = append(members, c)
	}
	if err := p.send(msg, members...); err != nil {
		closeAll(members)
		return err
	}
	p.mu.Lock()
	if old := p.wires[w.ID]; old != nil {
		closeAll(old.members)
	}
	p.wires[w.ID] = &wireConf{w: w, members: members}
	p.mu.Unlock()
	return nil
}

// RemoveWire takes a wire away; its flows go on by the route.
func (p *Pipe) RemoveWire(id trunk.WireID) error {
	if err := p.send([]byte{bUnwire, byte(id)}); err != nil {
		return err
	}
	p.mu.Lock()
	if old := p.wires[id]; old != nil {
		closeAll(old.members)
		delete(p.wires, id)
	}
	p.mu.Unlock()
	return nil
}

func dialMember(exit netip.AddrPort) (*net.UDPConn, error) {
	return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(exit))
}

func closeAll(cs []*net.UDPConn) {
	for _, c := range cs {
		if c != nil {
			c.Close()
		}
	}
}

// Wires is what the pipe's latest tick said of each wire (trunk.Steered).
// A tick older than staleTick says nothing: a pipe not running proves no
// wire, and every wire silent at once moves no route.
func (p *Pipe) Wires() map[trunk.WireID]trunk.WireState {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[trunk.WireID]trunk.WireState{}
	if time.Since(p.tickAt) > staleTick {
		return out
	}
	for _, w := range p.tick.Wires {
		s := trunk.WireState{ID: w.ID, Members: w.Up, Owed: w.Owed}
		if w.ProofAgo >= 0 {
			s.Proof = p.tickAt.Add(-w.ProofAgo)
		}
		out[w.ID] = s
	}
	return out
}

// LastPause is when the pipe last came back from a pause of its own, as its
// ticks say, or as the gap between them does (trunk.Steered).
func (p *Pipe) LastPause() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.resumed
}

// Route is the route the brain last gave the pipe.
func (p *Pipe) Route() trunk.Route {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.route
}

// SetRoute gives the pipe the wire of each class: its next datagram of each
// class goes on it (trunk.Steered).
func (p *Pipe) SetRoute(r trunk.Route) {
	if err := p.send(putRoute(r)); err != nil {
		p.cfg.Logf("pipectl: route: %v", err)
		return
	}
	p.mu.Lock()
	p.route = r
	p.mu.Unlock()
}

// Tick is the pipe's latest tick and when it came.
func (p *Pipe) Tick() (Tick, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tick, p.tickAt
}

// OpenCallFlow opens a flow of the brain's own to the exit's echo through
// the pipe (trunk.CallCarrier): the trunk's call hears the pipe as a client
// does.
func (p *Pipe) OpenCallFlow(o trunk.FlowOptions, deliver func([]byte)) trunk.CallFlow {
	tag := p.nextTag.Add(1)
	p.mu.Lock()
	p.flows[tag] = deliver
	p.mu.Unlock()
	f := &callFlow{p: p, tag: tag}
	if err := p.send(putOpen(tag, o, trunk.EchoPort)); err != nil {
		f.Close()
	}
	return f
}

type callFlow struct {
	p      *Pipe
	tag    uint32
	closed atomic.Bool
}

func (f *callFlow) Send(b []byte) bool {
	if f.closed.Load() {
		return false
	}
	msg := append(putTag(bDgram, f.tag), b...)
	if err := f.p.send(msg); err != nil {
		f.Close()
		return false
	}
	return true
}

func (f *callFlow) Close() {
	if f.closed.Swap(true) {
		return
	}
	_ = f.p.send(putTag(bClose, f.tag))
	f.p.mu.Lock()
	delete(f.p.flows, f.tag)
	f.p.mu.Unlock()
}

// read takes the pipe's messages until it ends.
func (p *Pipe) read() {
	buf := make([]byte, 65536)
	helloed := false
	for {
		n, _, flags, _, err := p.conn.ReadMsgUnix(buf, nil)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if flags&syscall.MSG_TRUNC != 0 {
			p.cfg.Logf("pipectl: a message from the pipe torn by the buffer")
			continue
		}
		m := buf[:n]
		switch m[0] {
		case pHello:
			if n < 7 || binary.LittleEndian.Uint16(m[1:]) != Version {
				p.cfg.Logf("pipectl: the pipe's hello % x is not version %d", m, Version)
				_ = p.cmd.Process.Kill()
				return
			}
			p.mu.Lock()
			p.pid = int(binary.LittleEndian.Uint32(m[3:]))
			p.mu.Unlock()
			if !helloed {
				helloed = true
				close(p.hello)
			}
		case pTick:
			t, err := parseTick(m)
			if err != nil {
				p.cfg.Logf("%v", err)
				continue
			}
			now := time.Now()
			p.mu.Lock()
			// A gap between ticks is the pipe not run (or this brain not):
			// the selector holds what it sees red then.
			if !p.tickAt.IsZero() && now.Sub(p.tickAt) > 2*time.Second+500*time.Millisecond {
				p.resumed = now
			}
			if t.PauseAgo >= 0 {
				if at := now.Add(-t.PauseAgo); at.After(p.resumed) {
					p.resumed = at
				}
			}
			p.tick, p.tickAt = t, now
			p.mu.Unlock()
		case pMember:
			if n < 5 {
				continue
			}
			id, index, up, why := trunk.WireID(m[1]), int(m[2]), m[3] == 1, m[4]
			p.cfg.Logf("pipectl: wire %d member %d up=%v why=%d", id, index, up, why)
			if !up {
				go p.renew(id, index)
			}
		case pDgram:
			if n < 5 {
				continue
			}
			tag := binary.LittleEndian.Uint32(m[1:])
			p.mu.Lock()
			deliver := p.flows[tag]
			p.mu.Unlock()
			if deliver != nil {
				deliver(m[5:])
			}
		case pError:
			p.cfg.Logf("pipectl: the pipe: %s", m[1:])
		default:
			p.cfg.Logf("pipectl: a message the brain does not know: type %#x", m[0])
		}
	}
}

// renew dials a member the pipe took down anew, as a Go member is: the exit
// sees a new peer and joins it to the session by its hello.
func (p *Pipe) renew(id trunk.WireID, index int) {
	p.mu.Lock()
	wc := p.wires[id]
	p.mu.Unlock()
	if wc == nil || index >= len(wc.members) {
		return
	}
	c, err := dialMember(wc.w.Exit)
	if err != nil {
		p.cfg.Logf("pipectl: wire %d member %d: %v", id, index, err)
		return
	}
	if err := p.send([]byte{bMember, byte(id), byte(index)}, c); err != nil {
		c.Close()
		p.cfg.Logf("pipectl: wire %d member %d: %v", id, index, err)
		return
	}
	p.mu.Lock()
	if p.wires[id] == wc && index < len(wc.members) {
		if old := wc.members[index]; old != nil {
			old.Close()
		}
		wc.members[index] = c
	} else {
		c.Close()
	}
	p.mu.Unlock()
}

// Run steers the pipe with sel and runs a call on each of wires through it,
// until ctx ends: the brain's whole loop over a pipe, as trunkentry's
// measure is over the entry's session.
func (p *Pipe) Run(ctx context.Context, sel *trunk.Selector, wires []trunk.WireID, call func(trunk.WireID, trunk.CallWindow), logf func(string, ...any)) {
	for _, id := range wires {
		go trunk.RunCallOn(ctx, func() trunk.CallCarrier { return p }, trunk.CallConfig{Copies: 1, OnWire: true, Wire: id}, func(cw trunk.CallWindow) {
			sel.Call(id, cw)
			if call != nil {
				call(id, cw)
			}
		})
	}
	trunk.SteerOn(ctx, p, sel, logf)
}
