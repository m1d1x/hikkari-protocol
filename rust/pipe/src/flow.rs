//! Flows: a client's address on a listened port, or a flow the brain opened
//! (its calls on each wire). A flow is a stream id on the trunk (its index
//! plus one), its datagrams numbered by seq; the exit answers it on the wire
//! the entry last sent it on.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};

use hikkari_sys::sockaddr_in;

pub const CLASS_BULK: u8 = 0;
pub const CLASS_VOICE: u8 = 1;

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
}

/// Every flow the pipe has opened, by stream id, client address and the
/// brain's tag.
pub struct Flows {
    list: Vec<Flow>,
    by_addr: FxMap<u64>,
    by_tag: FxMap<u32>,
    /// Flows not closed.
    pub live: u32,
}

impl Flows {
    pub fn new() -> Flows {
        Flows {
            list: Vec::with_capacity(4096),
            by_addr: HashMap::with_capacity_and_hasher(4096, Default::default()),
            by_tag: HashMap::with_capacity_and_hasher(64, Default::default()),
            live: 0,
        }
    }

    /// The id of a client's flow by its key (listen and address), opened
    /// with `new` on its first datagram.
    #[inline]
    pub fn client(&mut self, key: u64, new: impl FnOnce() -> Flow) -> u32 {
        if let Some(&id) = self.by_addr.get(&key) {
            return id;
        }
        let id = self.push(new());
        self.by_addr.insert(key, id);
        id
    }

    /// Opens the brain's flow `tag`.
    pub fn open(&mut self, tag: u32, f: Flow) -> Result<(), String> {
        if self.by_tag.contains_key(&tag) {
            return Err(format!("flow tag {tag} is open already"));
        }
        let id = self.push(f);
        self.by_tag.insert(tag, id);
        Ok(())
    }

    /// The id of the brain's flow `tag`, if it is open.
    pub fn tagged(&self, tag: u32) -> Option<u32> {
        self.by_tag.get(&tag).copied()
    }

    pub fn close(&mut self, tag: u32) {
        if let Some(id) = self.by_tag.remove(&tag) {
            self.list[id as usize - 1].dest = Dest::Gone;
            self.live -= 1;
        }
    }

    #[inline]
    pub fn get_mut(&mut self, id: u32) -> &mut Flow {
        &mut self.list[id as usize - 1]
    }

    /// Where the answers of trunk stream `stream` go; None for no such flow.
    #[inline]
    pub fn dest(&self, stream: u32) -> Option<&Dest> {
        self.list.get((stream as usize).wrapping_sub(1)).map(|f| &f.dest)
    }

    fn push(&mut self, f: Flow) -> u32 {
        self.list.push(f);
        self.live += 1;
        self.list.len() as u32
    }
}

/// A hash for keys the pipe made itself (addresses, tags): one multiply,
/// no SipHash per packet.
#[derive(Default)]
struct Fx(u64);

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

type FxMap<K> = HashMap<K, u32, BuildHasherDefault<Fx>>;
