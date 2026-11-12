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
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Why a dial got no connection.
#[derive(Debug)]
pub enum DialErr {
    /// Nothing answered within the timeout: the path, or the port it came
    /// from, is suspect (trunk ErrSilent).
    Silent,
    /// Refused, unreachable, or the port taken.
    Failed(io::Error),
}

/// A TCP connection to addr from local port `from` (0: the kernel's
/// choice), waited for up to timeout_ns: a pool member's own socket, as the
/// Go entry's chromium portDialer opens it (Nagle off, keepalive of Go's
/// net.Dialer: 15 s idle, 15 s apart, 9 probes). It blocks the calling
/// thread; the socket it returns is non-blocking.
pub fn tcp_dial(addr: SocketAddrV4, from: u16, timeout_ns: u64) -> Result<OwnedFd, DialErr> {
    let fail = |_| DialErr::Failed(io::Error::last_os_error());
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(fail(()));
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
            return Err(fail(()));
        }
    }
    let sa = sockaddr(addr);
    if unsafe { libc::connect(fd, &sa as *const _ as *const _, size_of::<libc::sockaddr_in>() as _) } == 0 {
        return Ok(owned);
    }
    if last() != libc::EINPROGRESS {
        return Err(fail(()));
    }
    let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
    let ms = (timeout_ns / 1_000_000).min(i32::MAX as u64) as i32;
    let r = loop {
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r < 0 && last() == libc::EINTR {
            continue;
        }
        break r;
    };
    if r == 0 {
        return Err(DialErr::Silent);
    }
    let mut err: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut _, &mut len) };
    match err {
        0 => Ok(owned),
        libc::ETIMEDOUT => Err(DialErr::Silent),
        e => Err(DialErr::Failed(io::Error::from_raw_os_error(e))),
    }
}

/// Hands the descriptor over: the caller closes it (a library that adopts
/// a socket, as cronet's dialer does).
pub fn into_raw(fd: OwnedFd) -> i32 {
    std::os::fd::IntoRawFd::into_raw_fd(fd)
}
