//! Flows (spec/trunk.md, "Datagrams"; trunk flows.go): a client's address on
//! a listened port, or a flow the brain opened (its calls on each wire). A
//! flow is a stream id on the trunk, its datagrams numbered by seq; answers
//! come back on it, copies dropped by seq (hikkari_trunk::flow::Replay). A
//! client's flow ends after 2 minutes unused and its next datagram opens a
//! new one, as the Go entry's udpPort opens a flow per client address and
//! forgets it at its end. The brain's flows end when the brain closes them.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

use hikkari_sys::sockaddr_in;
use hikkari_trunk::flow::{Replay, ECHO_PORT};

pub const CLASS_BULK: u8 = 0;
pub const CLASS_VOICE: u8 = 1;

/// A stream id is a slot and its generation: the low SLOT_BITS are the
/// slot plus one (an id is never 0), the rest count the slot's reuses. An
/// ended flow's slot is used again, but under a new id: the exit forgets a
/// flow 2 minutes after it was last used, and what it still answers on the
/// old id finds no flow here. A slot comes round to the same id after 4096
/// reuses, each at least an idle end apart: days, not minutes.
const SLOT_BITS: u32 = 20;
const SLOT_MASK: u32 = (1 << SLOT_BITS) - 1;
/// Flows open at once, at most.
pub const MAX_FLOWS: usize = SLOT_MASK as usize;

/// Where a flow's answers go.
pub enum Dest {
    Client { listen: u16, addr: sockaddr_in },
    Brain { tag: u32 },
    Gone,
}

pub struct Flow {
    pub dest: Dest,
    pub seq: u32,
    pub class: u8,
    /// A wire the flow is held to (the brain's call on a wire): its
    /// datagrams are dropped while that wire has no member up. ANY_WIRE: none.
    pub pin: u8,
    pub port: u16,
    pub copies: u8,
    /// The copies of its answers already seen.
    pub replay: Replay,
    /// When it last sent a datagram or got one that was not a copy.
    pub used: u64,
    id: u32,
    /// A client's key in by_addr, to forget it at the end.
    key: u64,
}

impl Flow {
    pub fn new(dest: Dest, class: u8, pin: u8, port: u16, copies: u8, now: u64) -> Flow {
        Flow { dest, seq: 0, class, pin, port, copies, replay: Replay::default(), used: now, id: 0, key: 0 }
    }

    /// The trunk's own call, not a client's: neither end counts it among its
    /// clients' flows and datagrams (trunk flow.echo).
    #[inline]
    pub fn echo(&self) -> bool {
        self.port == ECHO_PORT
    }
}

/// The clients' datagrams, as trunk Stats counts them (the trunk's own
/// call left out), and the flows that ended unused.
#[derive(Clone, Copy, Default)]
pub struct Counts {
    /// Datagrams read from clients (trunk DgramsOut).
    pub out: u64,
    /// Datagrams delivered to clients (trunk DgramsIn).
    pub delivered: u64,
    /// Copies dropped as already seen (trunk DgramsCopy).
    pub copies: u64,
    /// Clients' flows ended unused (trunk EndIdle).
    pub idle: u64,
}

/// Every flow the pipe has open, by stream id, client address and the
/// brain's tag.
pub struct Flows {
    list: Vec<Flow>,
    free: Vec<u32>,
    by_addr: FxMap<u64>,
    by_tag: FxMap<u32>,
    /// Flows open, the trunk's own calls left out (trunk Stats.Flows).
    pub clients: u32,
    pub n: Counts,
}

impl Flows {
    pub fn new() -> Flows {
        Flows {
            list: Vec::with_capacity(4096),
            free: Vec::with_capacity(4096),
            by_addr: HashMap::with_capacity_and_hasher(4096, Default::default()),
            by_tag: HashMap::with_capacity_and_hasher(64, Default::default()),
            clients: 0,
            n: Counts::default(),
        }
    }

    /// The id of a client's flow by its key (listen and address), opened
    /// with `new` on its first datagram; None when MAX_FLOWS are open.
    #[inline]
    pub fn client(&mut self, key: u64, new: impl FnOnce() -> Flow) -> Option<u32> {
        if let Some(&id) = self.by_addr.get(&key) {
            return Some(id);
        }
        let mut f = new();
        f.key = key;
        let id = self.push(f)?;
        self.by_addr.insert(key, id);
        Some(id)
    }

    /// Opens the brain's flow `tag`.
    pub fn open(&mut self, tag: u32, f: Flow) -> Result<(), String> {
        if self.by_tag.contains_key(&tag) {
            return Err(format!("flow tag {tag} is open already"));
        }
        let id = self.push(f).ok_or_else(|| format!("flow tag {tag}: {MAX_FLOWS} flows are open already"))?;
        self.by_tag.insert(tag, id);
        Ok(())
    }

    /// The id of the brain's flow `tag`, if it is open.
    pub fn tagged(&self, tag: u32) -> Option<u32> {
        self.by_tag.get(&tag).copied()
    }

    /// Ends the brain's flow `tag`.
    pub fn close(&mut self, tag: u32) {
        if let Some(id) = self.by_tag.remove(&tag) {
            self.end(id);
        }
    }

    /// The open flow of trunk stream `id` and the counts, to count its
    /// datagrams; None for a flow ended (or never opened here).
    #[inline]
    pub fn with_counts(&mut self, id: u32) -> Option<(&mut Flow, &mut Counts)> {
        let f = self.list.get_mut(((id & SLOT_MASK) as usize).wrapping_sub(1))?;
        if f.id != id || matches!(f.dest, Dest::Gone) {
            return None;
        }
        Some((f, &mut self.n))
    }

    /// Ends every client's flow unused for idle_ns (trunk's sweep of
    /// FlowIdle): the next datagram from that address opens a new flow.
    pub fn sweep(&mut self, now: u64, idle_ns: u64) {
        for i in 0..self.list.len() {
            let f = &self.list[i];
            if matches!(f.dest, Dest::Client { .. }) && now.saturating_sub(f.used) > idle_ns {
                let id = f.id;
                self.by_addr.remove(&f.key);
                self.end(id);
                self.n.idle += 1;
            }
        }
    }

    fn push(&mut self, mut f: Flow) -> Option<u32> {
        let echo = f.echo();
        let id = match self.free.pop() {
            Some(slot) => {
                let old = self.list[slot as usize].id;
                let id = (old & !SLOT_MASK).wrapping_add(1 << SLOT_BITS) | (slot + 1);
                f.id = id;
                self.list[slot as usize] = f;
                id
            }
            None => {
                if self.list.len() >= MAX_FLOWS {
                    return None;
                }
                let id = self.list.len() as u32 + 1;
                f.id = id;
                self.list.push(f);
                id
            }
        };
        if !echo {
            self.clients += 1;
        }
        Some(id)
    }

    fn end(&mut self, id: u32) {
        let slot = (id & SLOT_MASK) - 1;
        let f = &mut self.list[slot as usize];
        f.dest = Dest::Gone;
        if !f.echo() {
            self.clients -= 1;
        }
        self.free.push(slot);
    }
}

/// A hash for keys the pipe made itself (addresses, tags): one multiply,
/// no SipHash per packet.
#[derive(Default)]
pub struct Fx(u64);

impl Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!()
    }
    fn write_u64(&mut self, v: u64) {
        self.0 = (v ^ (v >> 29)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    fn write_u32(&mut self, v: u32) {
        self.write_u64(v as u64)
    }
}

pub type FxMap<K> = HashMap<K, u32, BuildHasherDefault<Fx>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::ANY_WIRE;

    const S: u64 = 1_000_000_000;

    fn client(now: u64) -> Flow {
        let addr = hikkari_sys::sockaddr("127.0.0.1:9".parse().unwrap());
        Flow::new(Dest::Client { listen: 0, addr }, CLASS_VOICE, ANY_WIRE, 443, 1, now)
    }

    #[test]
    fn a_client_unused_past_idle_ends_and_comes_back_under_a_new_id() {
        let mut fl = Flows::new();
        let a = fl.client(1, || client(0)).unwrap();
        let b = fl.client(2, || client(0)).unwrap();
        assert_eq!(fl.client(1, || unreachable!()), Some(a), "one flow per address");
        fl.with_counts(b).unwrap().0.used = 100 * S;
        fl.sweep(121 * S, 120 * S);
        assert_eq!((fl.clients, fl.n.idle), (1, 1), "a, unused for 121 s, ended; b, used at 100 s, not");
        assert!(fl.with_counts(a).is_none(), "the exit's late answers on a find no flow");
        let a2 = fl.client(1, || client(121 * S)).unwrap();
        assert_ne!(a2, a, "the address's next datagram opens a new flow");
        assert_eq!(a2 & SLOT_MASK, a & SLOT_MASK, "in a's slot");
        assert!(fl.with_counts(a).is_none() && fl.with_counts(a2).is_some());
        assert_eq!(fl.clients, 2);
    }

    #[test]
    fn the_brains_flows_end_by_close_alone_and_calls_count_as_no_clients() {
        let mut fl = Flows::new();
        let call = Flow::new(Dest::Brain { tag: 9 }, CLASS_VOICE, 2, ECHO_PORT, 1, 0);
        fl.open(9, call).unwrap();
        assert!(fl.open(9, Flow::new(Dest::Brain { tag: 9 }, CLASS_VOICE, 2, ECHO_PORT, 1, 0)).is_err());
        assert_eq!(fl.clients, 0, "the trunk's own call is no client's flow");
        fl.sweep(1000 * S, 120 * S);
        let id = fl.tagged(9).unwrap();
        assert!(fl.with_counts(id).is_some(), "a call the brain keeps is not swept");
        fl.close(9);
        assert!(fl.tagged(9).is_none() && fl.with_counts(id).is_none());
    }

    #[test]
    fn a_slots_ids_stay_apart_through_4096_reuses() {
        let mut fl = Flows::new();
        let mut seen = std::collections::HashSet::new();
        for i in 0..4096u64 {
            let id = fl.client(i, || client(0)).unwrap();
            assert!(seen.insert(id), "id {id:#x} given twice");
            fl.sweep(200 * S, 120 * S);
        }
        assert_eq!(fl.list.len(), 1, "one slot, used again each time");
    }
}
