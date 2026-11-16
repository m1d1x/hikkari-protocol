//! TCP without waiting: the clients' connections and the stream members'
//! sockets of the entry's pipe, each a descriptor the pipe polls. Every call
//! returns at once; what would block is `Io::Again`. IPv4 only.

use std::io;
use std::mem::size_of;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::sockaddr;

/// What a read or a write did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Io {
    /// This many bytes.
    Done(usize),
    /// Nothing now: the socket would block.
    Again,
    /// The other end ended its side (a read only).
    Eof,
    /// The connection failed (reset, refused, timed out).
    Gone,
}

fn last() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_int(fd: i32, level: i32, opt: i32, v: libc::c_int) {
    unsafe { libc::setsockopt(fd, level, opt, &v as *const _ as *const _, size_of::<libc::c_int>() as _) };
}

/// A listening TCP socket on addr, non-blocking.
pub fn tcp_listen(addr: SocketAddrV4) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    set_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1);
    let sa = sockaddr(addr);
    if unsafe { libc::bind(fd, &sa as *const _ as *const _, size_of::<libc::sockaddr_in>() as _) } != 0
        || unsafe { libc::listen(fd, 1024) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// The next connection waiting on a listening socket, non-blocking, with
/// Nagle off (as Go's net does for every TCP connection); None for none now.
pub fn accept(listener: i32) -> Option<OwnedFd> {
    loop {
        let fd = unsafe { libc::accept4(listener, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) };
        if fd >= 0 {
            set_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
            return Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        match last() {
            libc::EINTR => continue,
            // A connection that failed before it was taken: the next one.
            libc::ECONNABORTED | libc::EPROTO => continue,
            _ => return None,
        }
    }
}

/// A TCP connection to addr, begun and not waited for, Nagle off: its first
/// writes are Again until it is up, and a read or write says Gone if it
/// fails.
pub fn tcp_connect(addr: SocketAddrV4) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    let sa = sockaddr(addr);
    let r = unsafe { libc::connect(fd, &sa as *const _ as *const _, size_of::<libc::sockaddr_in>() as _) };
    if r != 0 && last() != libc::EINPROGRESS {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

fn io_of(n: isize, read: bool) -> Io {
    if n > 0 {
        return Io::Done(n as usize);
    }
    if n == 0 {
        return if read { Io::Eof } else { Io::Done(0) };
    }
    match last() {
        libc::EAGAIN | libc::EINTR => Io::Again,
        // A write on a connection still coming up.
        libc::ENOTCONN if !read => Io::Again,
        _ => Io::Gone,
    }
}

/// Reads what is there into buf.
#[inline]
pub fn read(fd: &OwnedFd, buf: &mut [u8]) -> Io {
    let n = unsafe { libc::recv(fd.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len(), libc::MSG_DONTWAIT) };
    io_of(n, true)
}

/// Writes as much of buf as the socket takes now; a closed peer is Gone,
/// never a SIGPIPE.
#[inline]
pub fn write(fd: &OwnedFd, buf: &[u8]) -> Io {
    let n = unsafe { libc::send(fd.as_raw_fd(), buf.as_ptr() as *const _, buf.len(), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
    io_of(n, false)
}

/// Ends this side of the connection (the other end reads EOF), keeping the
/// other side open.
pub fn shutdown_write(fd: &OwnedFd) {
    unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_WR) };
}

/// A TCP socket from a descriptor the brain passed (a listening socket it
/// bound), made non-blocking.
pub fn tcp_from_fd(fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if !crate::inet4(fd) {
        return Err(crate::not_inet4());
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// A connected stream socket from a descriptor the brain passed (a member
/// the relay took the CONNECT of: its end of a socket pair, or a TCP
/// connection), non-blocking. One that is no stream socket is refused.
pub fn stream_from_fd(fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut ty: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // Safe: ty is a c_int the kernel fills up to len.
    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE, &mut ty as *mut _ as *mut _, &mut len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if ty != libc::SOCK_STREAM {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a stream socket"));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// A pool member's TCP connection to addr from local port `from` (0: the
/// kernel's choice), begun and not waited for: Nagle off and the keepalive
/// of Go's net.Dialer (15 s idle, 15 s apart, 9 probes), as the Go entry's
/// chromium portDialer opens it. The loop polls it for writing and asks
/// `connected` when it is.
pub fn member_connect(addr: SocketAddrV4, from: u16) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
    set_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, 15);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, 15);
    set_int(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, 9);
    if from != 0 {
        let local = sockaddr(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, from));
        if unsafe { libc::bind(fd, &local as *const _ as *const _, size_of::<libc::sockaddr_in>() as _) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let sa = sockaddr(addr);
    let r = unsafe { libc::connect(fd, &sa as *const _ as *const _, size_of::<libc::sockaddr_in>() as _) };
    if r != 0 && last() != libc::EINPROGRESS {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Whether a connection begun by `member_connect` is up: Done(0) when it
/// is, Again while it is coming up, Gone when it failed (refused,
/// unreachable, timed out).
pub fn connected(fd: &OwnedFd) -> Io {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    if unsafe { libc::getpeername(fd.as_raw_fd(), &mut sa as *mut _ as *mut _, &mut len) } == 0 {
        return Io::Done(0);
    }
    let mut err: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    unsafe { libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut _, &mut len) };
    if err == 0 {
        Io::Again
    } else {
        Io::Gone
    }
}

/// Ends both sides of a connection whose descriptor someone else holds (a
/// duplicate of a socket handed to a library): the holder's next read or
/// write fails and it closes its own.
pub fn shutdown_both(fd: &OwnedFd) {
    unsafe { libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR) };
}

/// Hands the descriptor over: the caller closes it (a library that adopts
/// a socket, as cronet's dialer does).
pub fn into_raw(fd: OwnedFd) -> i32 {
    std::os::fd::IntoRawFd::into_raw_fd(fd)
}

/// What the kernel says of a TCP socket (struct tcp_info, Linux uapi
/// linux/tcp.h; the Go entry reads the same through unix.GetsockoptTCPInfo,
/// trunkentry tcpinfo_linux.go): its smoothed round trip and its variance,
/// the segments it sent again since it opened, the ones it holds lost and
/// unacknowledged now, its congestion window, the segments it sent and got.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpInfo {
    pub rtt_us: u32,
    pub rttvar_us: u32,
    pub total_retrans: u32,
    pub lost: u32,
    pub unacked: u32,
    pub cwnd: u32,
    pub segs_out: u32,
    pub segs_in: u32,
}

/// The kernel's tcp_info of fd; None when it is no TCP socket or the kernel
/// is older than tcpi_segs_out (4.2).
pub fn tcp_info(fd: i32) -> Option<TcpInfo> {
    // The struct's layout is the kernel's ABI: u32 fields at these offsets.
    const UNACKED: usize = 24;
    const LOST: usize = 32;
    const RTT: usize = 68;
    const RTTVAR: usize = 72;
    const SND_CWND: usize = 80;
    const TOTAL_RETRANS: usize = 100;
    const SEGS_OUT: usize = 136;
    const SEGS_IN: usize = 140;
    let mut b = [0u8; 256];
    let mut len = b.len() as libc::socklen_t;
    // SAFETY: the kernel writes at most len bytes into b and says how many.
    let r = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, b.as_mut_ptr() as *mut _, &mut len) };
    if r != 0 || (len as usize) < SEGS_IN + 4 {
        return None;
    }
    let u = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    Some(TcpInfo {
        rtt_us: u(RTT),
        rttvar_us: u(RTTVAR),
        total_retrans: u(TOTAL_RETRANS),
        lost: u(LOST),
        unacked: u(UNACKED),
        cwnd: u(SND_CWND),
        segs_out: u(SEGS_OUT),
        segs_in: u(SEGS_IN),
    })
}
