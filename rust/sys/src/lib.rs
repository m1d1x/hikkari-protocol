//! Batched UDP on Linux: recvmmsg and sendmmsg over buffers allocated once,
//! UDP GRO on receive. IPv4 only (the prototype's bench). Every unsafe call
//! of the workspace lives here, behind a safe function.
#![cfg(target_os = "linux")]

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

mod tcp;
pub use tcp::{accept, read, shutdown_write, tcp_connect, tcp_from_fd, tcp_listen, write, Io};

/// An IPv4 address as the kernel keeps it: what a batch reads a datagram
/// from and sends an answer to.
pub use libc::sockaddr_in;

pub const BATCH: usize = 64;
const CMSG: usize = 64;

pub fn now_ns() -> u64 {
    let mut ts: libc::timespec = unsafe { zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn sockaddr(a: SocketAddrV4) -> libc::sockaddr_in {
    let mut s: libc::sockaddr_in = unsafe { zeroed() };
    s.sin_family = libc::AF_INET as libc::sa_family_t;
    s.sin_port = a.port().to_be();
    s.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
    s
}

/// The key of a client address: IPv4 and port in one integer.
#[inline]
pub fn addr_key(s: &libc::sockaddr_in) -> u64 {
    ((u32::from_be(s.sin_addr.s_addr) as u64) << 16) | u16::from_be(s.sin_port) as u64
}

pub fn tune(sock: &UdpSocket, gro: bool) -> io::Result<()> {
    sock.set_nonblocking(true)?;
    let fd = sock.as_raw_fd();
    let big: libc::c_int = 8 << 20;
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &big as *const _ as *const _, 4);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &big as *const _ as *const _, 4);
        if gro {
            let one: libc::c_int = 1;
            if libc::setsockopt(fd, libc::SOL_UDP, libc::UDP_GRO, &one as *const _ as *const _, 4) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Receive side: BATCH slots of `slot` bytes each, read by one recvmmsg.
pub struct RecvBatch {
    pub slot: usize,
    pub buf: Vec<u8>,
    iov: Vec<libc::iovec>,
    hdr: Vec<libc::mmsghdr>,
    pub addr: Vec<libc::sockaddr_in>,
    cmsg: Vec<[u8; CMSG]>,
    pub len: Vec<usize>,
    /// The GRO segment size of each slot (0: one datagram).
    pub seg: Vec<usize>,
}

impl RecvBatch {
    pub fn new(slot: usize) -> RecvBatch {
        RecvBatch {
            slot,
            buf: vec![0; slot * BATCH],
            iov: vec![unsafe { zeroed() }; BATCH],
            hdr: vec![unsafe { zeroed() }; BATCH],
            addr: vec![unsafe { zeroed() }; BATCH],
            cmsg: vec![[0; CMSG]; BATCH],
            len: vec![0; BATCH],
            seg: vec![0; BATCH],
        }
    }

    /// One recvmmsg without waiting: how many slots it filled (0 for none).
    pub fn recv(&mut self, fd: i32) -> usize {
        for i in 0..BATCH {
            self.iov[i].iov_base = unsafe { self.buf.as_mut_ptr().add(i * self.slot) } as *mut _;
            self.iov[i].iov_len = self.slot;
            let h = &mut self.hdr[i].msg_hdr;
            h.msg_iov = &mut self.iov[i];
            h.msg_iovlen = 1;
            h.msg_name = &mut self.addr[i] as *mut _ as *mut _;
            h.msg_namelen = size_of::<libc::sockaddr_in>() as u32;
            h.msg_control = self.cmsg[i].as_mut_ptr() as *mut _;
            h.msg_controllen = CMSG as _;
            h.msg_flags = 0;
        }
        let n = unsafe {
            libc::recvmmsg(fd, self.hdr.as_mut_ptr(), BATCH as _, libc::MSG_DONTWAIT as _, std::ptr::null_mut())
        };
        if n <= 0 {
            return 0;
        }
        let n = n as usize;
        for i in 0..n {
            self.len[i] = self.hdr[i].msg_len as usize;
            self.seg[i] = gro_size(&self.hdr[i].msg_hdr);
        }
        n
    }

    #[inline]
    pub fn slot_mut(&mut self, i: usize) -> &mut [u8] {
        let s = self.slot;
        &mut self.buf[i * s..i * s + self.len[i]]
    }
}

fn gro_size(h: &libc::msghdr) -> usize {
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(h);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_UDP && (*c).cmsg_type == libc::UDP_GRO {
                let mut v: u16 = 0;
                std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut v as *mut u16 as *mut u8, 2);
                return v as usize;
            }
            c = libc::CMSG_NXTHDR(h, c);
        }
    }
    0
}

/// Send side: up to BATCH messages, each a pointer into a buffer the caller
/// keeps alive until flush, with or without a destination.
pub struct SendBatch {
    iov: Vec<libc::iovec>,
    hdr: Vec<libc::mmsghdr>,
    addr: Vec<libc::sockaddr_in>,
    pub n: usize,
    pub sent: u64,
    pub dropped: u64,
    pub calls: u64,
}

impl Default for SendBatch {
    fn default() -> SendBatch {
        SendBatch::new()
    }
}

impl SendBatch {
    pub fn new() -> SendBatch {
        SendBatch {
            iov: vec![unsafe { zeroed() }; BATCH],
            hdr: vec![unsafe { zeroed() }; BATCH],
            addr: vec![unsafe { zeroed() }; BATCH],
            n: 0,
            sent: 0,
            dropped: 0,
            calls: 0,
        }
    }

    #[inline]
    pub fn full(&self) -> bool {
        self.n == BATCH
    }

    /// Queues `len` bytes at `ptr` (to `to`, or the connected peer for None).
    /// The bytes must stay put until the next flush.
    #[inline]
    pub fn push(&mut self, ptr: *const u8, len: usize, to: Option<&libc::sockaddr_in>) {
        let i = self.n;
        self.iov[i].iov_base = ptr as *mut _;
        self.iov[i].iov_len = len;
        let h = &mut self.hdr[i].msg_hdr;
        h.msg_iov = &mut self.iov[i];
        h.msg_iovlen = 1;
        match to {
            Some(a) => {
                self.addr[i] = *a;
                h.msg_name = &mut self.addr[i] as *mut _ as *mut _;
                h.msg_namelen = size_of::<libc::sockaddr_in>() as u32;
            }
            None => {
                h.msg_name = std::ptr::null_mut();
                h.msg_namelen = 0;
            }
        }
        h.msg_control = std::ptr::null_mut();
        h.msg_controllen = 0;
        self.n += 1;
    }

    /// Sends everything queued; what the socket refuses is dropped, as a
    /// full socket buffer drops.
    pub fn flush(&mut self, fd: i32) {
        let mut at = 0;
        while at < self.n {
            self.calls += 1;
            let r = unsafe { libc::sendmmsg(fd, self.hdr[at..].as_mut_ptr(), (self.n - at) as _, 0) };
            if r <= 0 {
                let e = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if e == libc::EINTR {
                    continue;
                }
                // EAGAIN or a refused peer: drop this one, try the rest.
                self.dropped += 1;
                at += 1;
                continue;
            }
            at += r as usize;
            self.sent += r as u64;
        }
        self.n = 0;
    }
}

/// Readiness of a set of sockets by ppoll: the set is rebuilt when the
/// sockets change, not per wait.
pub struct Poll {
    pub fds: Vec<libc::pollfd>,
}

impl Default for Poll {
    fn default() -> Poll {
        Poll::new()
    }
}

impl Poll {
    pub fn new() -> Poll {
        Poll { fds: Vec::new() }
    }

    pub fn set(&mut self, fds: impl Iterator<Item = i32>) {
        self.fds.clear();
        self.fds.extend(fds.map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 }));
    }

    /// What socket i is waited for: readable, writable, or both (neither:
    /// only its failure).
    #[inline]
    pub fn want(&mut self, i: usize, read: bool, write: bool) {
        self.fds[i].events = if read { libc::POLLIN } else { 0 } | if write { libc::POLLOUT } else { 0 };
    }

    /// Waits for any of the set to be readable, at most `timeout_ns`;
    /// whether one is (readable(i) says which).
    pub fn wait(&mut self, timeout_ns: u64) -> bool {
        for p in self.fds.iter_mut() {
            p.revents = 0;
        }
        let ts = libc::timespec { tv_sec: (timeout_ns / 1_000_000_000) as _, tv_nsec: (timeout_ns % 1_000_000_000) as _ };
        let r = unsafe { libc::ppoll(self.fds.as_mut_ptr(), self.fds.len() as _, &ts, std::ptr::null()) };
        r > 0
    }

    /// Marks every socket readable: on a tick the pipe reads them all.
    pub fn all(&mut self) {
        for p in self.fds.iter_mut() {
            p.revents = libc::POLLIN;
        }
    }

    #[inline]
    pub fn readable(&self, i: usize) -> bool {
        self.fds[i].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
    }

    #[inline]
    pub fn writable(&self, i: usize) -> bool {
        self.fds[i].revents & (libc::POLLOUT | libc::POLLHUP | libc::POLLERR) != 0
    }
}

/// A UDP socket from a descriptor the brain passed, non-blocking.
pub fn udp_from_fd(fd: i32) -> io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    let s = unsafe { UdpSocket::from_raw_fd(fd) };
    s.set_nonblocking(true)?;
    Ok(s)
}

/// The CPU time a process has had, all its threads, in ns: user and
/// system (/proc/<pid>/stat utime, stime; clock ticks).
pub fn cpu_ns(pid: u32) -> Option<(u64, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After the comm: state is field 3, utime 14, stime 15 (1-based).
    let tick = 1_000_000_000 / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    Some((f.get(11)?.parse::<u64>().ok()? * tick, f.get(12)?.parse::<u64>().ok()? * tick))
}

pub fn urandom(b: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(b)).expect("urandom");
}

/// One datagram from fd without waiting: its size, or below 0 for none
/// (or an error).
pub fn recv_nowait(fd: i32, buf: &mut [u8]) -> isize {
    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), libc::MSG_DONTWAIT) }
}

/// Sleeps until the monotonic clock reads `at` (ns).
pub fn sleep_until(at: u64) {
    let ts = libc::timespec { tv_sec: (at / 1_000_000_000) as _, tv_nsec: (at % 1_000_000_000) as _ };
    unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &ts, std::ptr::null_mut()) };
}

/// Closes a descriptor no one took (a socket passed with a message that
/// did not use it).
pub fn close_fd(fd: i32) {
    unsafe { libc::close(fd) };
}

/// A local SOCK_SEQPACKET socket: one message per datagram, descriptors
/// passed with a message by SCM_RIGHTS (the brain ↔ pipe socket).
pub struct SeqPacket {
    pub fd: i32,
    cmsg: Vec<u8>,
    /// Messages the socket refused (its buffer full).
    pub dropped: u64,
}

impl SeqPacket {
    /// The socket at fd, with buffers of 4 MiB each way and room for up to
    /// max_fds descriptors in one message.
    pub fn new(fd: i32, max_fds: usize) -> SeqPacket {
        let big: libc::c_int = 4 << 20;
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, &big as *const _ as *const _, 4);
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &big as *const _ as *const _, 4);
        }
        let space = unsafe { libc::CMSG_SPACE((max_fds * 4) as u32) } as usize;
        SeqPacket { fd, cmsg: vec![0; space], dropped: 0 }
    }

    /// One message without waiting, its descriptors appended to fds:
    /// Ok(None) for none now, Ok(Some(0)) once the other end is gone. A
    /// message torn by the buffer is an error, its descriptors closed.
    pub fn recv(&mut self, buf: &mut [u8], fds: &mut Vec<i32>) -> io::Result<Option<usize>> {
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
        let mut h: libc::msghdr = unsafe { zeroed() };
        h.msg_iov = &mut iov;
        h.msg_iovlen = 1;
        h.msg_control = self.cmsg.as_mut_ptr() as *mut _;
        h.msg_controllen = self.cmsg.len() as _;
        let n = unsafe { libc::recvmsg(self.fd, &mut h, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => Ok(None),
                _ => Err(e),
            };
        }
        let first = fds.len();
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&h);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let len = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let p = libc::CMSG_DATA(c) as *const i32;
                    for i in 0..len / 4 {
                        fds.push(std::ptr::read_unaligned(p.add(i)));
                    }
                }
                c = libc::CMSG_NXTHDR(&h, c);
            }
        }
        if h.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            for fd in fds.drain(first..) {
                close_fd(fd);
            }
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a message torn by the buffer"));
        }
        Ok(Some(n as usize))
    }

    /// Sends one message without waiting; false (and counted) when the
    /// socket refuses it.
    pub fn send(&mut self, msg: &[u8]) -> bool {
        let n = unsafe { libc::send(self.fd, msg.as_ptr() as *const _, msg.len(), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
        if n < 0 {
            self.dropped += 1;
            return false;
        }
        true
    }
}

/// Readiness of many sockets by epoll, read without waiting: what a loop on
/// a tick asks once per turn, when the sockets are too many to read each
/// one (the exit's sockets to its relay, one per flow). Level-triggered: a
/// socket not read to its end is ready again on the next turn.
pub struct Epoll {
    pub fd: i32,
    ev: Vec<libc::epoll_event>,
}

impl Epoll {
    /// An epoll set that reports up to `max` ready sockets per wait.
    pub fn new(max: usize) -> io::Result<Epoll> {
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Epoll { fd, ev: vec![libc::epoll_event { events: 0, u64: 0 }; max.max(1)] })
    }

    /// Watches fd for reading; `data` comes back with it when it is ready.
    pub fn add(&self, fd: i32, data: u64) -> io::Result<()> {
        let mut e = libc::epoll_event { events: libc::EPOLLIN as u32, u64: data };
        if unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, fd, &mut e) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Watches a stream socket for both ways, edge-triggered: `data` comes
    /// back once each time it turns readable or writable, or fails. The loop
    /// keeps what it was told (a TCP socket's flags) and reads or writes
    /// until the socket would block; it is told again only after that.
    pub fn add_io(&self, fd: i32, data: u64) -> io::Result<()> {
        let events = (libc::EPOLLIN | libc::EPOLLOUT | libc::EPOLLRDHUP | libc::EPOLLET) as u32;
        let mut e = libc::epoll_event { events, u64: data };
        if unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, fd, &mut e) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Stops watching fd (before it is closed).
    pub fn del(&self, fd: i32) {
        unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
    }

    /// The sockets ready now, without waiting: how many; data(i) says which.
    pub fn ready(&mut self) -> usize {
        let n = unsafe { libc::epoll_wait(self.fd, self.ev.as_mut_ptr(), self.ev.len() as _, 0) };
        n.max(0) as usize
    }

    #[inline]
    pub fn data(&self, i: usize) -> u64 {
        self.ev[i].u64
    }

    /// What ready socket i is: readable (data, its end, or its failure),
    /// writable (room, or its failure).
    #[inline]
    pub fn ways(&self, i: usize) -> (bool, bool) {
        let e = self.ev[i].events as i32;
        let gone = e & (libc::EPOLLERR | libc::EPOLLHUP) != 0;
        (gone || e & (libc::EPOLLIN | libc::EPOLLRDHUP) != 0, gone || e & libc::EPOLLOUT != 0)
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        close_fd(self.fd);
    }
}

/// A UDP socket of its own to 127.0.0.1:port, non-blocking: a flow's way to
/// a loopback service (trunk Local.DialFlow), the service seeing one source
/// port per flow as from the Go exit.
pub fn udp_to_loopback(port: u16) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind("127.0.0.1:0")?;
    s.connect(("127.0.0.1", port))?;
    s.set_nonblocking(true)?;
    let buf: libc::c_int = 1 << 20;
    unsafe {
        libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &buf as *const _ as *const _, 4);
    }
    Ok(s)
}

/// One datagram on a connected socket without waiting; false when the
/// socket refused it (its buffer full, or the service gone).
pub fn send_nowait(fd: i32, b: &[u8]) -> bool {
    unsafe { libc::send(fd, b.as_ptr() as *const _, b.len(), libc::MSG_DONTWAIT) >= 0 }
}

/// One datagram from fd without waiting: Ok(Some(n)), Ok(None) for none
/// now, Err when the socket failed (on a connected socket: the service
/// behind it is gone, as an ICMP port unreachable tells).
pub fn recv_dgram(fd: i32, buf: &mut [u8]) -> io::Result<Option<usize>> {
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), libc::MSG_DONTWAIT) };
    if n >= 0 {
        return Ok(Some(n as usize));
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EAGAIN) | Some(libc::EINTR) => Ok(None),
        _ => Err(e),
    }
}
