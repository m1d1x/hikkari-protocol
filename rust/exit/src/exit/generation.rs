//! Generations of the exit (spec/trunk.md, "An exit's own process replaced";
//! the relay's generations, server/generation.go; the entry pipe's,
//! hk-pipe generation.rs): a reload starts a new exit on the same sockets,
//! and the old one carries what it has until it ends.
//!
//! The brain makes one SOCK_SEQPACKET socket per reload and gives its ends
//! with `drain` to the old exit and with `adopt` to the new one
//! (hikkari_trunk::handoff the messages). The old exit tells every entry it
//! drains (a drain frame on each member, and on each member that joins it
//! later), stops reading the packet wires' sockets and stops accepting on
//! the pool's port, and tells the new one its generation, every entry
//! address of its bare UDP wire's members, then `all`. The new exit reads no
//! packet wire before every older one said `all`; from then on a datagram
//! of an address an older exit holds, and a QUIC packet of a connection id
//! an older exit issued (h3wire.rs owner), go to that exit, which takes them
//! as read and answers out of the shared socket. An address the old exit
//! forgets it lets go (`free`), with a datagram it was handed for it if
//! any, which the new exit then takes itself. The old exit tells the brain
//! once it carries nothing more (`drained`); an older exit gone leaves
//! every address it held to the new one.

use std::collections::HashMap;
use std::net::SocketAddrV4;

use hikkari_sys::{self as sys, SeqPacket};
use hikkari_trunk::frame;
use hikkari_trunk::handoff::{self, Msg, ADDR, HEAD, OWN_MAX};

use super::Exit;
use crate::ctl;
use crate::peer::{Class, Form};

/// Older generations draining to one exit at once, at most: a reload a
/// minute for an hour.
const MAX_OLDER: usize = 64;

/// An older generation this exit adopted: its end of the handoff socket
/// (None once it is gone), whether its list of addresses is whole, and the
/// generations its connection ids name: its own and those of the older
/// ones that still drain through it.
pub(super) struct Older {
    sock: Option<SeqPacket>,
    all: bool,
    gens: Vec<u8>,
}

/// The exit's place among its generations.
pub(super) struct Gens {
    /// Its own generation (the brain's `gen`): its connection ids name it.
    pub gen: u8,
    /// The newer generation it drains to (this exit is the old one).
    pub newer: Option<SeqPacket>,
    pub older: Vec<Older>,
    /// The bare UDP wire's entry addresses an older generation keeps, by
    /// owner_key: the older one's index.
    owners: HashMap<u64, u32>,
    /// The entries were told this exit drains: a member that joins is told
    /// too (trunk Exit.Drain: a session made while draining drains).
    pub told: bool,
    /// It told the brain it carries nothing more.
    drained: bool,
    /// A message being made.
    out: Vec<u8>,
}

impl Gens {
    pub fn new() -> Gens {
        Gens { gen: 0, newer: None, older: Vec::new(), owners: HashMap::new(), told: false, drained: false, out: vec![0; HEAD + 65536] }
    }

    /// The sockets of the other generations to poll: the newer one, then
    /// each older one still there (slot() names them back).
    pub fn fds(&self) -> impl Iterator<Item = i32> + '_ {
        self.newer.iter().map(|s| s.fd).chain(self.older.iter().filter_map(|o| o.sock.as_ref().map(|s| s.fd)))
    }

    /// The older generation keeping an address of the bare UDP wire, if
    /// one does.
    #[inline]
    pub fn owner_of(&self, wire: u8, addr: &sys::sockaddr_in) -> Option<usize> {
        if self.owners.is_empty() {
            return None;
        }
        self.owners.get(&owner_key(wire, addr)).map(|&o| o as usize)
    }

    /// The older generation whose connection ids name gen (its own, or an
    /// older one's that drains through it), if it is still there.
    pub fn older_of_gen(&self, gen: u8) -> Option<usize> {
        self.older.iter().position(|o| o.sock.is_some() && o.gens.contains(&gen))
    }

    /// A datagram (or QUIC packet) from addr on wire `wire` to the older
    /// generation o; one its socket refuses (its buffer full) is dropped,
    /// as a full socket drops it.
    pub fn forward(&mut self, o: usize, wire: u8, addr: &sys::sockaddr_in, p: &[u8]) {
        let Some(s) = &mut self.older[o].sock else { return };
        let head = handoff::put_head(&mut self.out, handoff::DGRAM, wire, v4(addr));
        self.out[head..head + p.len()].copy_from_slice(p);
        s.send(&self.out[..head + p.len()]);
    }

    /// Lets an address go to the newer generation (this exit forgot its
    /// member), with the datagram it was handed for it, if any.
    pub fn free(&mut self, wire: u8, addr: &sys::sockaddr_in, p: &[u8]) {
        let Some(s) = &mut self.newer else { return };
        let head = handoff::put_head(&mut self.out, handoff::FREE, wire, v4(addr));
        self.out[head..head + p.len()].copy_from_slice(p);
        s.send(&self.out[..head + p.len()]);
    }
}

/// An address's key among the owners: the wire by its id (the brain's, the
/// same in both exits) and the address.
#[inline]
fn owner_key(wire: u8, addr: &sys::sockaddr_in) -> u64 {
    ((wire as u64) << 48) | sys::addr_key(addr)
}

/// The wire and the address of an owner_key.
fn owner_addr(k: u64) -> (u8, SocketAddrV4) {
    ((k >> 48) as u8, SocketAddrV4::new(((k >> 16) as u32).into(), k as u16))
}

pub(super) fn v4(s: &sys::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(u32::from_be(s.sin_addr.s_addr).into(), u16::from_be(s.sin_port))
}

/// Which socket of the other generations a poll slot is.
#[derive(Clone, Copy)]
pub(super) enum GenSlot {
    Newer,
    Older(usize),
}

impl Exit {
    /// Whether the exit reads its packet wires' sockets: not while it
    /// drains, nor before every older generation said whose addresses it
    /// keeps.
    pub(super) fn reads_wires(&self) -> bool {
        self.gens.newer.is_none() && self.gens.older.iter().all(|o| o.all)
    }

    /// The poll slots of the other generations, in the order Gens::fds
    /// gives their sockets.
    pub(super) fn gen_slots(&self) -> Vec<GenSlot> {
        let older = self.gens.older.iter().enumerate().filter(|(_, o)| o.sock.is_some()).map(|(i, _)| GenSlot::Older(i));
        self.gens.newer.iter().map(|_| GenSlot::Newer).chain(older).collect()
    }

    /// The brain's `gen`: the exit's connection ids name it from now on.
    pub(super) fn set_gen(&mut self, gen: u8) {
        self.gens.gen = gen;
        for w in self.wires.iter_mut() {
            if let Some(h) = w.h3() {
                h.set_gen(gen);
            }
        }
    }

    /// The brain's `drain`, its one socket the old end of a handoff: every
    /// entry is told, the exit takes no new member and tells the new exit
    /// its generation and its bare UDP wire's addresses.
    pub(super) fn drain(&mut self, fds: &mut Vec<i32>) -> Result<(), String> {
        if fds.len() != 1 {
            return Err(format!("exit: drain: {} sockets, want 1", fds.len()));
        }
        if self.gens.newer.is_some() {
            return Err("exit: drain: the exit drains already".into());
        }
        let mut s = SeqPacket::new(fds.remove(0), 0);
        let now = sys::now_ns();
        self.tell_drain(now);
        if let Some(fd) = self.pool.as_ref().and_then(|p| p.fd.as_ref()) {
            self.tcp.del(std::os::fd::AsRawFd::as_raw_fd(fd));
        }
        // The generations and the addresses of the older exits that still
        // drain through this one go to the newer with its own: their
        // datagrams and packets come here, which hands them on (handed).
        let mut sent = s.send(&[handoff::GEN, self.gens.gen]);
        for o in self.gens.older.iter().filter(|o| o.sock.is_some()) {
            for &g in &o.gens {
                sent &= s.send(&[handoff::GEN, g]);
            }
        }
        let mut addrs: Vec<(u8, SocketAddrV4)> = self
            .peers
            .iter()
            .filter(|p| p.live && matches!(self.wires[p.wire].form, Form::Udp(_)))
            .map(|p| (self.wires[p.wire].id, v4(&p.addr)))
            .collect();
        addrs.extend(self.gens.owners.keys().map(|&k| owner_addr(k)));
        for chunk in addrs.chunks(OWN_MAX) {
            let out = &mut self.gens.out;
            out[0] = handoff::OWN;
            let mut at = 1;
            for &(wire, a) in chunk {
                at += handoff::put_addr(&mut out[at..at + ADDR], wire, a);
            }
            sent &= s.send(&out[..at]);
        }
        sent &= s.send(&[handoff::ALL]);
        self.gens.newer = Some(s);
        self.dirty = true;
        eprintln!("hk-exit: drains with {} session(s), {} UDP member(s), {} flow(s), {} stream(s)", self.sessions.live(), addrs.len(), self.flows.clients, self.streams.open);
        if !sent {
            return Err("exit: drain: the handoff socket refused the list of addresses".into());
        }
        Ok(())
    }

    /// A drain frame on every member up, and from now on on every member
    /// that joins (trunk Session.Drain).
    fn tell_drain(&mut self, now: u64) {
        self.gens.told = true;
        let Exit { wires, peers, links, .. } = self;
        for p in peers.iter_mut().filter(|p| p.joined()) {
            wires[p.wire].glue(p, Class::Own, 1, now, frame::put_drain);
        }
        for l in links.all.iter_mut().filter(|l| l.joined()) {
            l.out.frame(1, frame::put_drain);
        }
    }

    /// The brain's `adopt`, its one socket the new end of a handoff: an
    /// older generation drains to this exit.
    pub(super) fn adopt(&mut self, fds: &mut Vec<i32>) -> Result<(), String> {
        if fds.len() != 1 {
            return Err(format!("exit: adopt: {} sockets, want 1", fds.len()));
        }
        let o = Older { sock: Some(SeqPacket::new(fds.remove(0), 0)), all: false, gens: Vec::new() };
        let owners = &self.gens.owners;
        // A slot of an older exit gone and owning nothing is used again.
        match (0..self.gens.older.len()).find(|&i| self.gens.older[i].sock.is_none() && !owners.values().any(|&v| v as usize == i)) {
            Some(i) => self.gens.older[i] = o,
            None if self.gens.older.len() < MAX_OLDER => self.gens.older.push(o),
            None => return Err(format!("exit: adopt: {MAX_OLDER} older generations drain to this exit already")),
        }
        self.dirty = true;
        Ok(())
    }

    /// The other generations' messages, all there are.
    pub(super) fn read_generations(&mut self, now: u64) {
        for k in 0..self.gslots.len() {
            if !self.poll.readable(self.gen_at + k) {
                continue;
            }
            match self.gslots[k] {
                GenSlot::Newer => self.read_newer(now),
                GenSlot::Older(i) => self.read_older(i, now),
            }
        }
    }

    /// The newer generation's datagrams for this exit's members.
    fn read_newer(&mut self, now: u64) {
        let mut msg = std::mem::take(&mut self.msg);
        while let Some(s) = &mut self.gens.newer {
            self.fds.clear();
            let n = match s.recv(&mut msg, &mut self.fds) {
                Ok(None) => break,
                Ok(Some(n)) if n > 0 => n,
                _ => {
                    // The new exit is gone: nothing reads the wires but
                    // this exit, which takes them again.
                    self.gens.newer = None;
                    self.gens.drained = false;
                    self.dirty = true;
                    if let Some(fd) = self.pool.as_ref().and_then(|p| p.fd.as_ref()) {
                        let _ = self.tcp.add_io(std::os::fd::AsRawFd::as_raw_fd(fd), 0);
                    }
                    self.error("exit: the newer generation is gone: the exit reads its wires again");
                    break;
                }
            };
            let Some(Msg::Dgram { listen: wire, addr, .. }) = handoff::parse(&msg[..n]) else { continue };
            let from = sys::sockaddr(addr);
            self.handed(wire, from, &mut msg[HEAD..n], now);
        }
        self.msg = msg;
    }

    /// A datagram the newer generation read for this exit: one of an older
    /// generation that drains through this exit goes on to it; on the bare
    /// UDP wire one of an address no exit here holds goes back with it.
    fn handed(&mut self, wire: u8, from: sys::sockaddr_in, d: &mut [u8], now: u64) {
        let Some(wi) = self.wires.iter().position(|w| w.id == wire) else { return };
        if let Some(h) = self.wires[wi].h3() {
            if let Some(o) = h.owner(d).and_then(|g| self.gens.older_of_gen(g)) {
                self.gens.forward(o, wire, &from, d);
                return;
            }
            self.h3_packet(wi, from, d, now);
            return;
        }
        if let Some(o) = self.gens.owner_of(wire, &from) {
            self.gens.forward(o, wire, &from, d);
            return;
        }
        if self.peer_of(super::wire::peer_key(wi, &from)).is_none() {
            self.gens.free(wire, &from, d);
            return;
        }
        self.datagram(wi, from, d, now);
    }

    /// An older generation's generation, its list of addresses, its `all`,
    /// the addresses it lets go and the datagrams it gives back.
    fn read_older(&mut self, i: usize, now: u64) {
        let mut msg = std::mem::take(&mut self.msg);
        while let Some(s) = &mut self.gens.older[i].sock {
            self.fds.clear();
            let n = match s.recv(&mut msg, &mut self.fds) {
                Ok(None) => break,
                Ok(Some(n)) if n > 0 => n,
                _ => {
                    // Gone: every address it held is this exit's.
                    self.gens.older[i] = Older { sock: None, all: true, gens: Vec::new() };
                    self.gens.owners.retain(|_, o| *o as usize != i);
                    self.dirty = true;
                    break;
                }
            };
            match handoff::parse(&msg[..n]) {
                Some(Msg::Gen { gen }) => {
                    if !self.gens.older[i].gens.contains(&gen) {
                        self.gens.older[i].gens.push(gen);
                    }
                }
                Some(Msg::Own { addrs }) => {
                    for (wire, a) in handoff::addrs(addrs) {
                        self.gens.owners.insert(owner_key(wire, &sys::sockaddr(a)), i as u32);
                    }
                }
                Some(Msg::All) => {
                    self.gens.older[i].all = true;
                    self.dirty = true;
                }
                Some(Msg::Free { listen: wire, addr, payload }) => {
                    let from = sys::sockaddr(addr);
                    let k = owner_key(wire, &from);
                    if self.gens.owners.get(&k) == Some(&(i as u32)) {
                        self.gens.owners.remove(&k);
                    }
                    // A draining exit takes no address: the newer one does,
                    // which this exit told it the older one kept.
                    if self.gens.newer.is_some() {
                        let p = msg[HEAD..n].to_vec();
                        self.gens.free(wire, &from, &p);
                        continue;
                    }
                    if payload.is_empty() {
                        continue;
                    }
                    let Some(wi) = self.wires.iter().position(|w| w.id == wire) else { continue };
                    if self.wires[wi].h3().is_none() {
                        self.datagram(wi, from, &mut msg[HEAD..n], now);
                    }
                }
                Some(Msg::Dgram { .. } | Msg::Ready | Msg::Move(_) | Msg::Taken { .. } | Msg::Moved { .. } | Msg::StreamMove(_) | Msg::StreamTaken { .. } | Msg::StreamKept { .. }) | None => {}
            }
        }
        self.msg = msg;
    }

    /// Peer pi is forgotten while the exit drains: its address of the bare
    /// UDP wire is the newer generation's from now on.
    pub(super) fn let_go(&mut self, pi: usize) {
        if self.gens.newer.is_none() {
            return;
        }
        let p = &self.peers[pi];
        if matches!(self.wires[p.wire].form, Form::Udp(_)) {
            let (wire, addr) = (self.wires[p.wire].id, p.addr);
            self.gens.free(wire, &addr, &[]);
        }
    }

    /// Once a second: a draining exit that carries nothing more (no
    /// client's flow, no stream, no older generation draining through it)
    /// tells the brain, once. An older one still there reads the wires
    /// through this exit (it forwards that one's datagrams and lets its
    /// addresses go on to the newer): were this exit to end under it, the
    /// older one's end of the handoff socket would close, and it would take
    /// the wires back beside the newest (read_newer). It ends first: its
    /// relay's drain limit runs out before this one's.
    pub(super) fn check_drained(&mut self) {
        if self.gens.newer.is_none() || self.gens.drained || self.flows.clients != 0 || self.streams.open != 0 {
            return;
        }
        if self.gens.older.iter().any(|o| o.sock.is_some()) {
            return;
        }
        self.gens.drained = true;
        eprintln!("hk-exit: drained: no flow, no stream, no older generation");
        if let Some(c) = &mut self.ctl {
            c.send(&[ctl::P_DRAINED]);
        }
    }
}
