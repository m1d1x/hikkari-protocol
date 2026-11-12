package pipectl

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// spawn starts bin with args under this brain: a SOCK_SEQPACKET socketpair,
// the child's end its fd 3 (args say --ctl-fd 3), the brain's end returned.
// The child ends when this process does. The entry's pipe and the exit's
// run the same way.
func spawn(bin string, args []string, stderr io.Writer) (*exec.Cmd, *net.UnixConn, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("pipectl: socketpair: %w", err)
	}
	mine := os.NewFile(uintptr(fds[0]), "pipectl-brain")
	theirs := os.NewFile(uintptr(fds[1]), "pipectl-pipe")
	defer theirs.Close()
	fc, err := net.FileConn(mine)
	mine.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("pipectl: %w", err)
	}
	conn := fc.(*net.UnixConn)
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	cmd := exec.Command(bin, args...)
	cmd.ExtraFiles = []*os.File{theirs}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("pipectl: %w", err)
	}
	return cmd, conn, nil
}

// sendWith writes one message on conn with the sockets of conns (UDP
// sockets, a listening TCP socket), one writer at a time (wmu): a message
// and its sockets go together.
func sendWith(conn *net.UnixConn, wmu *sync.Mutex, msg []byte, conns ...syscall.Conn) error {
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
	// message, and the child gets descriptors of its own.
	var werr error
	var hold func(i int)
	hold = func(i int) {
		if i == len(raws) {
			wmu.Lock()
			defer wmu.Unlock()
			var oob []byte
			if len(fds) > 0 {
				oob = syscall.UnixRights(fds...)
			}
			_, _, werr = conn.WriteMsgUnix(msg, oob, nil)
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
