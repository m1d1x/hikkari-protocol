//! Batched UDP on Linux: recvmmsg and sendmmsg over buffers allocated once,
//! UDP GRO on receive. IPv4 only (the prototype's bench).

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

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

/// Waits for any of fds to be readable, at most `timeout_ns`; returns the
/// revents bits (bit i: fds[i] readable).
pub fn wait(fds: &[i32], timeout_ns: u64) -> u64 {
    let mut p = [libc::pollfd { fd: -1, events: 0, revents: 0 }; 8];
    for (i, &fd) in fds.iter().enumerate() {
        p[i] = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    }
    let ts = libc::timespec { tv_sec: (timeout_ns / 1_000_000_000) as _, tv_nsec: (timeout_ns % 1_000_000_000) as _ };
    let r = unsafe { libc::ppoll(p.as_mut_ptr(), fds.len() as _, &ts, std::ptr::null()) };
    if r <= 0 {
        return 0;
    }
    let mut bits = 0;
    for i in 0..fds.len() {
        if p[i].revents & libc::POLLIN != 0 {
            bits |= 1 << i;
        }
    }
    bits
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

/// Sleeps until the monotonic clock reads `at` (ns).
pub fn sleep_until(at: u64) {
    let ts = libc::timespec { tv_sec: (at / 1_000_000_000) as _, tv_nsec: (at % 1_000_000_000) as _ };
    unsafe { libc::clock_nanosleep(libc::CLOCK_MONOTONIC, libc::TIMER_ABSTIME, &ts, std::ptr::null_mut()) };
}
