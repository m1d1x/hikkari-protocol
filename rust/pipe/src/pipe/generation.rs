//! Generations of the pipe (spec/trunk.md, "An entry's own process
//! replaced"; the Go entry's generations, trunkentry handoff.go): a reload
//! starts a new pipe on the same client sockets, and the old one carries
//! what it has until it ends.
//!
//! The brain makes one SOCK_SEQPACKET socket per reload and gives its ends
//! with `drain` to the old pipe and with `adopt` to the new one (handoff.rs
//! the messages). The old pipe stops reading the clients' sockets and stops
//! accepting, and tells the new one every client address its flows are for,
//! then `all`. The new pipe reads no client datagram before every older pipe
//! said `all`; from then on a datagram of an address an older pipe keeps
//! goes to that pipe, which carries it on its own session and answers out
//! of the shared socket. A flow the old pipe ends it lets go (`free`, with
//! the datagram it was handed for it, if any), and the new pipe opens the
//! address's flow itself. The old pipe tells the brain once it carries
//! nothing more (`drained`); an older pipe gone gives every address it held
//! to the new one.

use std::net::{Ipv4Addr, SocketAddrV4};

use hikkari_sys::{self as sys, SeqPacket};

use super::data::{client_key, take_client};
use super::Pipe;
use crate::ctl;
use crate::handoff::{self, Msg, ADDR, OWN_MAX};

/// Older generations draining to one pipe at once, at most: a reload a
/// minute for an hour.
const MAX_OLDER: usize = 64;

/// An older generation this pipe adopted: its end of the handoff socket
/// (None once it is gone), and whether it said its list of addresses is
/// whole.
pub(super) struct Older {
    pub sock: Option<SeqPacket>,
    pub all: bool,
}

/// An address's key among the owners: the listen by its id (the brain's,
/// the same in both pipes: the new pipe may hear an older one's list
/// before the brain's listens) and the address.
#[inline]
pub(super) fn owner_key(listen: u8, addr: &sys::sockaddr_in) -> u64 {
    ((listen as u64) << 48) | sys::addr_key(addr)
}

/// The listen part and the address of a key (client_key, owner_key).
fn split(key: u64) -> (usize, SocketAddrV4) {
    ((key >> 48) as usize, SocketAddrV4::new(Ipv4Addr::from(((key >> 16) & 0xffff_ffff) as u32), key as u16))
}

/// A client datagram (segments of `step` bytes in p) to the older
/// generation that keeps its flow, a message per segment; one its socket
/// refuses (its buffer full) is dropped, as a full socket drops it.
pub(super) fn forward(o: &mut Older, buf: &mut [u8], listen: u8, addr: &sys::sockaddr_in, p: &[u8], step: usize) {
    let Some(s) = &mut o.sock else { return };
    let (_, a) = split(sys::addr_key(addr));
    let head = handoff::put_head(buf, handoff::DGRAM, listen, a);
    let mut at = 0;
    while at < p.len() {
        let seg = &p[at..(at + step).min(p.len())];
        buf[head..head + seg.len()].copy_from_slice(seg);
        s.send(&buf[..head + seg.len()]);
        at += step;
    }
}

impl Pipe {
    /// Whether the pipe reads the clients' sockets: not while it drains,
    /// nor before every older generation said whose flows it keeps.
    pub(super) fn reads_clients(&self) -> bool {
        self.newer.is_none() && self.older.iter().all(|o| o.all)
    }

    /// The brain's `drain`, its one socket the old end of a handoff: this
    /// pipe takes no new client and tells the new one its flows' addresses.
    pub(super) fn drain(&mut self) -> Result<(), String> {
        if self.fds.len() != 1 {
            return Err(format!("drain: {} sockets, want 1", self.fds.len()));
        }
        if self.newer.is_some() {
            return Err("drain: the pipe drains already".into());
        }
        self.drop_next();
        let mut s = SeqPacket::new(self.fds.remove(0), 0);
        let mut sent = true;
        let keys: Vec<u64> = self.flows.client_keys().collect();
        for chunk in keys.chunks(OWN_MAX) {
            self.out[0] = handoff::OWN;
            let mut at = 1;
            for &key in chunk {
                let (li, a) = split(key);
                at += handoff::put_addr(&mut self.out[at..at + ADDR], self.listens[li].id, a);
            }
            sent &= s.send(&self.out[..at]);
        }
        sent &= s.send(&[handoff::ALL]);
        self.newer = Some(s);
        self.dirty = true;
        eprintln!("hk-pipe: drains with {} flow(s) and {} stream(s)", keys.len(), self.streams.open);
        if !sent {
            return Err("drain: the handoff socket refused the list of flows".into());
        }
        Ok(())
    }

    /// The brain's `adopt`, its one socket the new end of a handoff: an
    /// older generation drains to this pipe.
    pub(super) fn adopt(&mut self) -> Result<(), String> {
        if self.fds.len() != 1 {
            return Err(format!("adopt: {} sockets, want 1", self.fds.len()));
        }
        let o = Older { sock: Some(SeqPacket::new(self.fds.remove(0), 0)), all: false };
        let owners = &self.owners;
        // A slot of an older pipe gone and owning nothing is used again.
        match (0..self.older.len()).find(|&i| self.older[i].sock.is_none() && !owners.values().any(|&v| v as usize == i)) {
            Some(i) => self.older[i] = o,
            None if self.older.len() < MAX_OLDER => self.older.push(o),
            None => return Err(format!("adopt: {MAX_OLDER} older generations drain to this pipe already")),
        }
        self.dirty = true;
        Ok(())
    }

    /// The other generations' messages, all there are: from the newer one
    /// (this pipe drains), from each older one (this pipe adopted them).
    pub(super) fn read_generations(&mut self) {
        let (newer, older) = self.generation_slots();
        if newer {
            self.read_newer();
        }
        for i in 0..self.older.len() {
            if older & (1 << i) != 0 {
                self.read_older(i);
            }
        }
    }

    /// Which generation sockets the poll says are readable: the newer one,
    /// and a bit per older one.
    fn generation_slots(&self) -> (bool, u64) {
        let (mut newer, mut older) = (false, 0u64);
        for (si, s) in self.slots.iter().enumerate() {
            match *s {
                super::Slot::Newer if self.poll.readable(si) => newer = true,
                super::Slot::Older(i) if self.poll.readable(si) => older |= 1 << i,
                _ => {}
            }
        }
        (newer, older)
    }

    /// The newer generation's datagrams for this pipe's flows.
    fn read_newer(&mut self) {
        loop {
            let Some(s) = &mut self.newer else { return };
            self.fds.clear();
            let n = match s.recv(&mut self.msg, &mut self.fds) {
                Ok(None) => return,
                Ok(Some(n)) if n > 0 => n,
                _ => {
                    // The new pipe is gone: nothing reads the clients but
                    // this pipe, which takes them again.
                    self.newer = None;
                    self.dirty = true;
                    self.drained = false;
                    self.error("the newer generation is gone: the pipe reads its clients again");
                    return;
                }
            };
            let Some(Msg::Dgram { listen, addr, payload }) = handoff::parse(&self.msg[..n]) else { continue };
            let Some(li) = self.listens.iter().position(|l| l.id == listen) else { continue };
            let sa = sys::sockaddr(addr);
            let key = client_key(li, &sa);
            if self.flows.find(key).is_none() {
                // Ended here: the address is the new pipe's, with this
                // datagram.
                let head = handoff::put_head(&mut self.out, handoff::FREE, listen, addr);
                self.out[head..head + payload.len()].copy_from_slice(payload);
                s.send(&self.out[..head + payload.len()]);
                continue;
            }
            let Pipe { flows, wires, swires, route, listens, moved, cur, .. } = self;
            let now = sys::now_ns();
            take_client(flows, wires, swires, *route, &listens[li], li, sa, key, payload, payload.len(), now, moved, *cur);
        }
    }

    /// An older generation's list of addresses, its `all`, the addresses it
    /// lets go and the datagrams it gives back.
    fn read_older(&mut self, i: usize) {
        loop {
            let Some(s) = &mut self.older[i].sock else { return };
            self.fds.clear();
            let n = match s.recv(&mut self.msg, &mut self.fds) {
                Ok(None) => return,
                Ok(Some(n)) if n > 0 => n,
                _ => {
                    // Gone: every address it held is this pipe's.
                    self.older[i] = Older { sock: None, all: true };
                    self.owners.retain(|_, o| *o as usize != i);
                    self.dirty = true;
                    return;
                }
            };
            match handoff::parse(&self.msg[..n]) {
                Some(Msg::Own { addrs }) => {
                    for (listen, a) in handoff::addrs(addrs) {
                        self.owners.insert(owner_key(listen, &sys::sockaddr(a)), i as u32);
                    }
                }
                Some(Msg::All) => {
                    self.older[i].all = true;
                    self.dirty = true;
                }
                Some(Msg::Free { listen, addr, payload }) => {
                    let sa = sys::sockaddr(addr);
                    let ok = owner_key(listen, &sa);
                    if self.owners.get(&ok) == Some(&(i as u32)) {
                        self.owners.remove(&ok);
                    }
                    let Some(li) = self.listens.iter().position(|l| l.id == listen) else { continue };
                    if payload.is_empty() {
                        continue;
                    }
                    let Pipe { flows, wires, swires, route, listens, moved, cur, .. } = self;
                    let now = sys::now_ns();
                    let key = client_key(li, &sa);
                    take_client(flows, wires, swires, *route, &listens[li], li, sa, key, payload, payload.len(), now, moved, *cur);
                }
                Some(Msg::Dgram { .. }) | None => {}
            }
        }
    }

    /// Flows unused past idle end (once a second). A pipe draining lets
    /// their addresses go to the newer generation, and tells the brain once
    /// it carries nothing more.
    pub(super) fn sweep_flows(&mut self, now: u64) {
        self.flows.sweep(now, self.flow_idle_ns, &mut self.freed);
        self.close_retired(now);
        if let Some(s) = &mut self.newer {
            for &key in &self.freed {
                let (li, a) = split(key);
                let n = handoff::put_head(&mut self.out, handoff::FREE, self.listens[li].id, a);
                s.send(&self.out[..n]);
            }
            if !self.drained && self.flows.clients == 0 && self.streams.open == 0 {
                self.drained = true;
                eprintln!("hk-pipe: drained: no flow, no stream");
                if let Some(c) = &mut self.ctl {
                    c.send(&[ctl::P_DRAINED]);
                }
            }
        }
        self.freed.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_splits_into_its_listen_and_address() {
        let a: SocketAddrV4 = "10.1.2.3:50443".parse().unwrap();
        let sa = sys::sockaddr(a);
        assert_eq!(split(client_key(5, &sa)), (5, a));
        assert_eq!(split(owner_key(9, &sa)), (9, a));
    }
}
