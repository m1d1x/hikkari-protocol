//! Stream members: the members of a wire that carries streams, each over a
//! TCP connection of its own to the exit, in the pool's form (spec/trunk.md,
//! "Member": a t1 hello, then frames one after another on the byte stream,
//! both ways). A member's connection is either Chromium's CONNECT tunnel to
//! the exit's relay (hikkari_cronet, the pool's form: trunk/chromium) or
//! plain TCP to the exit's member port, as the bench's Go entry dials its
//! pool. A tunnel's TCP connection is the loop's: connected without waiting
//! and handed to the wire's engine once up, so no thread ever waits on a
//! path that does not answer. The reference is trunk session.go: a member's writeLoop (frames in
//! order, one write for all that wait) and serve (frames read one by one).
//!
//! Nothing is allocated per frame: a member writes into its out buffer and
//! reads into its in buffer, both allocated once (hikkari_trunk::buf). A
//! chunk of a client's bytes is read straight into the out buffer behind its
//! frame's head.

use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd};

use hikkari_cronet::{Conn, Engine};

use hikkari_sys::{self as sys, Io};
use hikkari_trunk::buf::{Out, IN};
use hikkari_trunk::frame;
use hikkari_trunk::health::Health;
use hikkari_trunk::ports::Book;
use hikkari_trunk::stream::{CHUNK, INFLIGHT};

use crate::ctl::WireTick;

/// A member's connection.
pub enum Sock {
    Tcp(OwnedFd),
    /// A tunnel's TCP connection coming up, not yet Chromium's.
    Dialing(OwnedFd, Engine),
    Chromium(Conn),
}

impl Sock {
    /// What the loop polls: the socket, or the tunnel's wake-up.
    pub fn fd(&self) -> i32 {
        match self {
            Sock::Tcp(fd) | Sock::Dialing(fd, _) => fd.as_raw_fd(),
            Sock::Chromium(c) => c.fd(),
        }
    }

    /// A connection coming up reads nothing, or Gone once it failed.
    pub fn read(&mut self, buf: &mut [u8]) -> Io {
        match self {
            Sock::Tcp(fd) | Sock::Dialing(fd, _) => sys::read(fd, buf),
            Sock::Chromium(c) => c.read(buf),
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Io {
        match self {
            Sock::Tcp(fd) => sys::write(fd, buf),
            Sock::Dialing(..) => Io::Again,
            Sock::Chromium(c) => c.write(buf),
        }
    }

    /// Whether to poll it for writing while bytes wait: a tunnel's finished
    /// write rings its wake-up, which is polled for reading; a connection
    /// coming up is writable once up.
    pub fn polls_writes(&self) -> bool {
        !matches!(self, Sock::Chromium(_))
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
    /// Chromium's CONNECT to the exit's relay (the pool's form), on the
    /// wire's engine.
    Chromium(Engine),
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
    /// When a member taken down is dialed anew (0: not waiting for it).
    pub renew_at: u64,
    /// Its connection's source port, taken from the pipe's book (0: none).
    pub port: u16,
    /// When the exit's hello came on its connection (0: not yet).
    pub up_at: u64,
    /// The wait before its next dial beyond the spread, and its stalls in a
    /// row (trunk Entry.slot: backoff, stalls).
    pub backoff_ns: u64,
    pub stalls: u32,
}

/// How a dial went.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dialed {
    /// A connection is coming up, its hello waiting.
    Begun,
    /// Every source port of the book is dead or in use.
    NoPort,
    /// The connection could not be begun.
    Failed,
}

/// Ports tried in one dial whose bind finds the port someone else's (the
/// book's ports are not the kernel's alone: a connection of ours still in
/// TIME_WAIT holds its port too).
const BUSY_TRIES: usize = 8;

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
            port: 0,
            up_at: 0,
            backoff_ns: 0,
            stalls: 0,
        }
    }

    /// A new connection to the exit from a port of the book, its t1 hello
    /// waiting in the out buffer: a new member to the exit, up once the exit
    /// answers. A tunnel takes the hello once the relay has answered its
    /// CONNECT. A port whose bind finds it busy goes back to the book and
    /// another is tried at once (trunk Entry.slot on EADDRINUSE).
    pub fn dial(&mut self, reach: &Reach, session: &[u8; 16], book: &mut Book, now: u64) -> Dialed {
        self.drop_sock(book);
        self.gen = self.gen.wrapping_add(1);
        self.dialed_at = now;
        self.renew_at = 0;
        let exit = match reach {
            Reach::Plain(exit) => *exit,
            Reach::Chromium(engine) => engine.form().exit,
        };
        for _ in 0..BUSY_TRIES {
            let mut r = [0u8; 8];
            sys::urandom(&mut r);
            let Some(port) = book.take(now, u64::from_le_bytes(r)) else { return Dialed::NoPort };
            match sys::member_connect(exit, port) {
                Ok(fd) => {
                    self.port = port;
                    self.sock = Some(match reach {
                        Reach::Plain(_) => Sock::Tcp(fd),
                        Reach::Chromium(engine) => Sock::Dialing(fd, engine.clone()),
                    });
                    self.out.frame(29, |b| frame::hello_t1(b, session));
                    return Dialed::Begun;
                }
                Err(e) => {
                    book.release(port);
                    if e.kind() != io::ErrorKind::AddrInUse {
                        return Dialed::Failed;
                    }
                }
            }
        }
        Dialed::Failed
    }

    /// Its wait before the next dial grows: 200 ms, then twice as long up
    /// to about 5 s (trunk Entry.slot: grow).
    pub fn grow(&mut self) {
        if self.backoff_ns == 0 {
            self.backoff_ns = 200_000_000;
        } else if self.backoff_ns < 5_000_000_000 {
            self.backoff_ns *= 2;
        }
    }

    /// A tunnel's connection that came up becomes the tunnel: Done(0) when
    /// it did (the descriptor to poll changed), Again while it is coming up
    /// or for any other socket, Gone when it failed.
    pub fn promote(&mut self) -> Io {
        match &self.sock {
            Some(Sock::Dialing(fd, _)) => match sys::connected(fd) {
                Io::Done(_) => {}
                r => return r,
            },
            _ => return Io::Again,
        }
        let Some(Sock::Dialing(fd, engine)) = self.sock.take() else { unreachable!("matched above") };
        match Conn::open(&engine, fd) {
            Ok(c) => {
                self.sock = Some(Sock::Chromium(c));
                Io::Done(0)
            }
            Err(e) => {
                eprintln!("hk-pipe: a member's tunnel: {e}");
                Io::Gone
            }
        }
    }

    /// Its socket closed, its port back to the book (still dead if the path
    /// killed it) and what it held forgotten.
    pub fn drop_sock(&mut self, book: &mut Book) {
        self.sock = None;
        if self.port != 0 {
            book.release(self.port);
            self.port = 0;
        }
        self.up_at = 0;
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
