//! Stream members: the members of a wire that carries streams, each over a
//! TCP connection of its own to the exit, in the pool's form (spec/trunk.md,
//! "Member": a t1 hello, then frames one after another on the byte stream,
//! both ways). A member's connection is either Chromium's CONNECT tunnel to
//! the exit's relay (hikkari_cronet, the pool's form: trunk/chromium) or
//! plain TCP to the exit's member port, as the bench's Go entry dials its
//! pool. The reference is trunk session.go: a member's writeLoop (frames in
//! order, one write for all that wait) and serve (frames read one by one).
//!
//! Nothing is allocated per frame: a member writes into its out buffer and
//! reads into its in buffer, both allocated once (hikkari_trunk::buf). A
//! chunk of a client's bytes is read straight into the out buffer behind its
//! frame's head.

use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use hikkari_cronet::{Conn, Form};

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::buf::{Out, IN};
use hikkari_trunk::frame;
use hikkari_trunk::health::Health;
use hikkari_trunk::stream::{CHUNK, INFLIGHT};

use crate::ctl::WireTick;

/// A member's connection.
pub enum Sock {
    Tcp(OwnedFd),
    Chromium(Conn),
}

impl Sock {
    /// What the loop polls: the socket, or the tunnel's wake-up.
    pub fn fd(&self) -> i32 {
        match self {
            Sock::Tcp(fd) => fd.as_raw_fd(),
            Sock::Chromium(c) => c.fd(),
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Io {
        match self {
            Sock::Tcp(fd) => sys::read(fd, buf),
            Sock::Chromium(c) => c.read(buf),
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Io {
        match self {
            Sock::Tcp(fd) => sys::write(fd, buf),
            Sock::Chromium(c) => c.write(buf),
        }
    }

    /// Whether to poll it for writing while bytes wait: a tunnel's finished
    /// write rings its wake-up, which is polled for reading.
    pub fn polls_writes(&self) -> bool {
        matches!(self, Sock::Tcp(_))
    }
}

/// Writes what waits in a member's out buffer, as much as its connection
/// takes.
pub fn flush(out: &mut Out, sock: &mut Sock) -> Io {
    if !out.pending() {
        return Io::Done(0);
    }
    let r = sock.write(out.bytes());
    if let Io::Done(n) = r {
        out.wrote(n);
    }
    r
}

/// How a wire's members reach the exit.
#[derive(Clone)]
pub enum Reach {
    /// Plain TCP to the exit's member port (the bench's pool).
    Plain(SocketAddrV4),
    /// Chromium's CONNECT to the exit's relay (the pool's form).
    Chromium(Arc<Form>),
}

pub struct Link {
    pub sock: Option<Sock>,
    /// Up, its pings, its debt: spec/trunk.md, "Members' health".
    pub h: Health,
    pub out: Out,
    pub inb: Box<[u8]>,
    /// Bytes read and not yet a whole frame, at inb[..in_n].
    pub in_n: usize,
    /// Unconfirmed chunk bytes it carries (trunk member.inflight).
    pub inflight: usize,
    /// Opens, chunks and FINs it carries that are not confirmed yet (trunk
    /// member.segs): it owes progress while there is one.
    pub owing: u32,
    /// Counts its sockets: what a stream owes names the member and the
    /// socket it went on, so a confirmation that comes after the member was
    /// dialed anew is not counted on the new socket.
    pub gen: u16,
    /// When its connection was begun: the exit's hello is due within
    /// HELLO_WAIT of it.
    pub dialed_at: u64,
    /// Without a brain: when a member taken down is dialed anew (0: not
    /// waiting for it).
    pub renew_at: u64,
}

impl Link {
    pub fn new() -> Link {
        Link {
            sock: None,
            h: Health::new(false),
            out: Out::new(),
            inb: vec![0; IN].into_boxed_slice(),
            in_n: 0,
            inflight: 0,
            owing: 0,
            gen: 0,
            dialed_at: 0,
            renew_at: 0,
        }
    }

    /// A new connection to the exit, its t1 hello waiting in the out buffer:
    /// a new member to the exit, up once the exit answers. A tunnel takes
    /// the hello once the relay has answered its CONNECT.
    pub fn dial(&mut self, reach: &Reach, session: &[u8; 16], now: u64) {
        self.drop_sock();
        self.gen = self.gen.wrapping_add(1);
        self.dialed_at = now;
        self.renew_at = 0;
        self.sock = match reach {
            Reach::Plain(exit) => sys::tcp_connect(*exit).ok().map(Sock::Tcp),
            Reach::Chromium(form) => Conn::open(form, 0).ok().map(Sock::Chromium),
        };
        if self.sock.is_some() {
            self.out.frame(29, |b| frame::hello_t1(b, session));
        }
    }

    /// Its socket closed and what it held forgotten.
    pub fn drop_sock(&mut self) {
        self.sock = None;
        self.h.down();
        self.out.clear();
        self.in_n = 0;
        self.inflight = 0;
        self.owing = 0;
    }

    /// Whether it takes a chunk now (trunk pickLocked with room): it is up,
    /// and owes nothing or has room under INFLIGHT for a whole chunk.
    pub fn takes_chunk(&self) -> bool {
        self.h.up && (self.inflight == 0 || self.inflight + CHUNK <= INFLIGHT)
    }

    /// It carries one more thing to be confirmed: from owing nothing, its
    /// debt begins now.
    pub fn owe(&mut self, bytes: usize, now: u64) {
        if self.owing == 0 {
            self.h.busy_since = now;
        }
        self.owing += 1;
        self.inflight += bytes;
    }
}

/// A wire of stream members: the pool's form (spec/trunk.md, "Wires").
pub struct StreamWire {
    pub id: u8,
    /// Its members' stall (trunk Config.Stall).
    pub stall_ns: u64,
    pub links: Vec<Link>,
    /// How a member's new connection reaches the exit.
    pub reach: Reach,
    /// When one of its members last proved its round trip (0: never).
    pub proof: u64,
    pub t: WireTick,
}

impl StreamWire {
    pub fn new(id: u8, reach: Reach, members: usize, stall_ns: u64) -> StreamWire {
        StreamWire {
            id,
            stall_ns,
            links: (0..members).map(|_| Link::new()).collect(),
            reach,
            proof: 0,
            t: WireTick { id, ..Default::default() },
        }
    }

    pub fn up(&self) -> usize {
        self.links.iter().filter(|l| l.h.up).count()
    }
}

/// What a stream owes names its member: the wire's index, the member's, and
/// its socket's generation.
#[inline]
pub fn carrier(wi: usize, li: usize, gen: u16) -> u32 {
    ((wi as u32) << 24) | ((li as u32) << 16) | gen as u32
}

#[inline]
pub fn carrier_of(c: u32) -> (usize, usize, u16) {
    ((c >> 24) as usize, ((c >> 16) & 0xff) as usize, c as u16)
}
