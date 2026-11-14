//! The Chromium QUIC wire's members (spec/trunk.md, `h3dgram`; hikkari-client
//! plans/2026-11-11-entry-hot-path-and-unit-economics.md, R6.3): each member
//! is a CONNECT-UDP tunnel (hikkari_cronet::Tunnel) on a QUIC connection of
//! its own, opened by the pipe itself, not by the brain. Its frames go as
//! one HTTP Datagram per glued write through the tunnel's end of a datagram
//! pair, so the tick's glue is paid once per datagram in Chromium, not once
//! per frame (the R5 box's lesson: a write per frame was two thirds of the
//! pool's cost).
//!
//! A member's QUIC socket is the pipe's, as a pool member's TCP socket is
//! (link.rs): bound from a port of the wire's book (spec/trunk.md, "Members'
//! health": a port whose member died rests for an hour), connected to the
//! exit, and handed to the engine's UDP dialer (hikkari_cronet::UdpHand).
//! One tunnel opens at a time per wire, the next once Chromium took the
//! socket, so the port the book gave is the one the connection has.
//!
//! The engine of a wire starts off the loop and every tunnel and engine ends
//! off it (both wait for cronet's network thread); members of all sessions
//! of a wire share its engine and book. A tunnel closed by Chromium is the
//! member's death (WHY_GONE); one dead by its health is closed: either way
//! its port rests, and the member opens a new tunnel within SPREAD.

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::OwnedFd;
use std::sync::Arc;

use hikkari_cronet::{Proxy, Starting, State, Tunnel, TunnelEngine, Usage};
use hikkari_sys as sys;
use hikkari_trunk::h3dgram;
use hikkari_trunk::ports::{self, Book};

use super::{timers, Event, Pipe};
use crate::ctl;
use crate::member::Wire;

/// How long a tunnel's socket may wait in the hand. Chromium dials when the
/// tunnel asks the pool for a session, within a turn of its network thread;
/// one not taken after this found a session to reuse, which a member must
/// never have.
const DIAL_WAIT_NS: u64 = 1_000_000_000;
/// The most frames one HTTP Datagram of a member holds, by how its session
/// is used (spec/trunk.md, `h3dgram`): Chromium's guaranteed largest
/// datagram payload (quiche QuicPacketCreator::GetGuaranteedLargestDatagram-
/// Payload: a long header with the version, the exit's 16-byte and its own
/// 8-byte connection ids, a 2-byte length and a 4-byte packet number, the
/// 16-byte tag, the frame's type) less the HTTP Datagram's head of stream
/// 0, 2 bytes. Its current room is up to 16 bytes more (a short header,
/// R6.3's measure: 1213 B passed at 1250), but changes with the packet
/// number's length, and a datagram over it resets the member.
pub(super) fn frames_max(u: Usage) -> usize {
    match u {
        Usage::Destination => 1250 - 16 - 37 - 1 - 2,
        Usage::Proxy => 1350 - 16 - 37 - 1 - 2,
    }
}
/// The CONNECT-UDP target every member asks for: the exit is the trunk's
/// end and opens nothing to it (spec/trunk.md, `h3dgram`).
const TARGET: (&str, u16) = ("trunk.hikkari.arpa", 443);

/// What a QUIC wire's members are opened with; a wire given another one by
/// the brain comes up anew.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Form {
    pub exit: SocketAddrV4,
    pub sni: String,
    pub roots: Option<String>,
    pub usage: Usage,
    pub ports: (u16, u16),
    pub token: [u8; h3dgram::TOKEN],
}

/// One QUIC wire's engine, book and opening member.
pub(super) struct H3 {
    pub id: u8,
    pub form: Form,
    auth: String,
    starting: Option<Starting>,
    engine: Option<Arc<TunnelEngine>>,
    book: Book,
    /// The member whose socket waits in the hand: its session, its index,
    /// since when.
    dialing: Option<(u8, usize, u64)>,
    /// Numbers the members' isolation keys: every tunnel a QUIC session of
    /// its own, never one shared with another member.
    keys: u64,
    /// Tunnels opened, closed by Chromium, and opens that failed.
    pub opened: u64,
    pub closed: u64,
    pub failed: u64,
}

impl H3 {
    /// A wire's engine starting (off the loop) for form f.
    pub fn new(id: u8, f: Form) -> Result<H3, String> {
        let book = Book::new(f.ports.0, f.ports.1, ports::DEAD_FOR_NS).map_err(|e| format!("wire {id}: {e}"))?;
        let proxy = Proxy { sni: f.sni.clone(), addr: f.exit, roots: f.roots.clone() };
        Ok(H3 {
            id,
            auth: h3dgram::authorization(&f.token),
            starting: Some(TunnelEngine::start_off_loop(proxy, true)),
            engine: None,
            book,
            dialing: None,
            keys: 0,
            opened: 0,
            closed: 0,
            failed: 0,
            form: f,
        })
    }

    /// The engine once up; a start that failed is said once, and the wire
    /// carries nothing.
    fn engine(&mut self) -> Option<Arc<TunnelEngine>> {
        if let Some(s) = &self.starting {
            match s.ready() {
                None => return None,
                Some(Ok(e)) => self.engine = Some(e),
                Some(Err(e)) => eprintln!("hk-pipe: wire {}: {e}", self.id),
            }
            self.starting = None;
        }
        self.engine.clone()
    }

    /// The port of a member gone back to the book: resting if it died,
    /// free if it was let go.
    pub fn give_back(&mut self, port: u16, died: bool, now: u64) {
        if port == 0 {
            return;
        }
        if died {
            self.book.dead(port, now);
        } else {
            self.book.release(port);
        }
    }

    /// Opens a tunnel from the next port of the book: its socket in the
    /// engine's hand first. Returns the tunnel and its port.
    fn open(&mut self, e: &Arc<TunnelEngine>, now: u64) -> Result<(Tunnel, u16), String> {
        let hand = e.hand().expect("a wire's engine is started with own sockets");
        let mut r = [0u8; 8];
        sys::urandom(&mut r);
        let port = self.book.take(now, u64::from_le_bytes(r)).ok_or("no free source port in the book")?;
        let fd = match bind_to(port, self.form.exit) {
            Ok(x) => x,
            Err(e) => {
                // Held by someone else (a session Chromium still keeps):
                // the port rests as a dead member's would.
                self.book.dead(port, now);
                return Err(format!("port {port}: {e}"));
            }
        };
        hand.put(fd.0, fd.1);
        let key = format!("https://member-{}:443", self.keys);
        self.keys += 1;
        let t = Tunnel::open(e, TARGET, &[("proxy-authorization", &self.auth)], Some(&key), self.form.usage);
        match t {
            Ok(t) => {
                self.opened += 1;
                Ok((t, port))
            }
            Err(err) => {
                hand.take_back();
                self.book.release(port);
                Err(err)
            }
        }
    }

    /// The book's line for the stats: free ports, resting ones, tunnels.
    pub fn stats(&self) -> String {
        let (dead, _) = self.book.dead_now();
        format!(" ports free={} dead={dead} tunnels opened={} closed={} failed={}", self.book.free(), self.opened, self.closed, self.failed)
    }
}

impl Drop for H3 {
    fn drop(&mut self) {
        if let Some(e) = self.engine.take() {
            hikkari_cronet::let_go(e);
        }
    }
}

/// A UDP socket from `port`, connected to the exit, with its local address.
fn bind_to(port: u16, exit: SocketAddrV4) -> std::io::Result<(OwnedFd, SocketAddrV4)> {
    let s = UdpSocket::bind(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port))?;
    s.connect(exit)?;
    sys::tune(&s, false)?;
    let SocketAddr::V4(local) = s.local_addr()? else {
        return Err(std::io::Error::other("an IPv4 socket with no IPv4 address"));
    };
    Ok((OwnedFd::from(s), local))
}

impl Pipe {
    /// The QUIC wires' members, each turn: tunnels Chromium closed are the
    /// members' deaths, the opening member's socket taken or taken back, and
    /// one member without a tunnel opens one. Returns when it is next due.
    pub(super) fn h3_members(&mut self, now: u64) -> u64 {
        if self.h3s.is_empty() {
            return u64::MAX;
        }
        let (cur, taker, brains) = (self.cur, self.taker(), self.ctl.is_some());
        let Pipe { h3s, wires, events, dirty, .. } = self;
        let mut next = u64::MAX;
        for h in h3s.iter_mut() {
            let engine = h.engine();
            if let Some((s, mi, since)) = h.dialing {
                let hand = engine.as_ref().and_then(|e| e.hand());
                if hand.is_none_or(|x| x.taken()) {
                    h.dialing = None;
                } else if now - since >= DIAL_WAIT_NS {
                    if let Some(x) = hand {
                        x.take_back();
                    }
                    h.dialing = None;
                    h.failed += 1;
                    eprintln!("hk-pipe: wire {}: Chromium took no socket for a member's tunnel in 1 s", h.id);
                    if let Some(m) = wires.iter_mut().find(|w| w.id == h.id && w.sess == s && w.h3).and_then(|w| w.members.get_mut(mi)) {
                        h.book.release(m.port);
                        m.set_tunnel(None, 0);
                        m.renew_at = now + spread();
                        *dirty = true;
                    }
                }
            }
            let id = h.id;
            for w in wires.iter_mut().filter(|w| w.id == id && w.h3) {
                next = next.min(closed_tunnels(h, w, cur, brains, events, dirty, now));
                if h.dialing.is_some() || taker != Some(w.sess) {
                    continue;
                }
                let Some(e) = &engine else { continue };
                let Some(mi) = w.members.iter().position(|m| m.tun.is_none() && m.renew_at == 0) else { continue };
                match h.open(e, now) {
                    Ok((t, port)) => {
                        w.members[mi].set_tunnel(Some(t), port);
                        h.dialing = Some((w.sess, mi, now));
                        *dirty = true;
                    }
                    Err(err) => {
                        h.failed += 1;
                        eprintln!("hk-pipe: wire {} member {mi}: {err}", h.id);
                        w.members[mi].renew_at = now + spread();
                    }
                }
            }
            if h.dialing.is_some() || h.starting.is_some() {
                next = next.min(now + timers::CLOCK);
            }
        }
        next
    }
}

/// The members of w whose tunnel Chromium closed: dead, their ports resting,
/// a new tunnel within SPREAD (the members of the current session told to
/// the brain).
fn closed_tunnels(h: &mut H3, w: &mut Wire, cur: u8, brains: bool, events: &mut Vec<Event>, dirty: &mut bool, now: u64) -> u64 {
    let mut next = u64::MAX;
    for (mi, m) in w.members.iter_mut().enumerate() {
        if m.renew_at != 0 {
            next = next.min(m.renew_at);
        }
        let Some(t) = &m.tun else { continue };
        let State::Closed(err) = t.state() else { continue };
        h.closed += 1;
        if m.h.up && brains && w.sess == cur {
            events.push(Event { wire: w.id, index: mi as u8, up: false, why: ctl::WHY_GONE });
        }
        eprintln!("hk-pipe: wire {} member {mi}: the tunnel closed (net error {err})", w.id);
        if h.dialing.is_some_and(|(s, i, _)| s == w.sess && i == mi) {
            h.dialing = None;
        }
        h.give_back(m.port, true, now);
        m.set_tunnel(None, 0);
        m.renew_at = now + spread();
        next = next.min(m.renew_at);
        *dirty = true;
    }
    next
}

/// A random wait under SPREAD: members that die together come back one by
/// one (trunk's replaceSpread).
pub(super) fn spread() -> u64 {
    let mut r = [0u8; 8];
    sys::urandom(&mut r);
    1 + u64::from_le_bytes(r) % timers::SPREAD
}

impl Pipe {
    /// The brain's QUIC wire (B_WIRE, FORM_H3DGRAM): a new form (exit,
    /// domain, roots, usage, ports, token) brings the wire up anew on a new
    /// engine; the same one sent again changes only the glue, the stall and
    /// how many members the session that takes new ones has.
    pub(super) fn set_h3(&mut self, id: u8, glue_us: u32, glue_max: u16, dead_ms: u16, key: [u8; 32], m: &ctl::H3) -> Result<(), String> {
        if id == ctl::ANY_WIRE {
            return Err("wire 255 is no wire".into());
        }
        let Some(sess) = self.taker() else {
            return Err(format!("wire {id}: the pipe drains, it takes no new member"));
        };
        hikkari_cronet::load((!m.cronet.is_empty()).then_some(m.cronet))?;
        let usage = if m.usage == ctl::USAGE_PROXY { Usage::Proxy } else { Usage::Destination };
        let roots = (!m.roots.is_empty()).then(|| m.roots.to_string());
        let f = Form { exit: m.exit, sni: m.sni.to_string(), roots, usage, ports: m.ports, token: key };
        let now = sys::now_ns();
        if !self.h3s.iter().any(|h| h.id == id && h.form == f) {
            let h = H3::new(id, f)?;
            self.h3s.retain(|h| h.id != id);
            for w in self.wires.iter_mut().filter(|w| w.id == id && w.h3) {
                for m in w.members.iter_mut() {
                    m.set_tunnel(None, 0);
                    m.renew_at = 0;
                }
            }
            self.h3s.push(h);
        }
        // A bare UDP wire of the same id in this session goes: the id is
        // the QUIC wire's now.
        self.wires.retain(|w| !(w.id == id && w.sess == sess && !w.h3));
        let at = match self.wires.iter().position(|w| w.id == id && w.sess == sess) {
            Some(i) => i,
            None => {
                let mut w = Wire::new(id, key, dead_ms.max(1) as u64 * 1_000_000);
                w.sess = sess;
                w.h3 = true;
                w.exit = Some(m.exit);
                self.wires.push(w);
                self.wires.len() - 1
            }
        };
        let (wires, h3s) = (&mut self.wires, &mut self.h3s);
        let w = &mut wires[at];
        let h = h3s.iter_mut().find(|h| h.id == id).expect("pushed above");
        w.glue_ns = glue_us as u64 * 1000;
        let fmax = frames_max(usage);
        w.glue_max = (glue_max as usize).clamp(64, fmax);
        w.stall_ns = dead_ms.max(1) as u64 * 1_000_000;
        w.key = key;
        w.exit = Some(m.exit);
        for gone in w.members.drain((m.members as usize).min(w.members.len())..) {
            h.give_back(gone.port, false, now);
        }
        for m in w.members.iter_mut() {
            m.frames_max = fmax;
        }
        while w.members.len() < m.members as usize {
            w.members.push(crate::member::Member::plain(&key, fmax));
        }
        self.dirty = true;
        Ok(())
    }
}
