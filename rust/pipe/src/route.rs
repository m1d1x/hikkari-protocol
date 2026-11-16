//! The route the brain gives the pipe (B_ROUTE; trunk wires.go Route,
//! fates.go): which wires each class of datagrams goes on, and each wire's
//! fate. Live datagrams ride two fates at once (spec/trunk.md, "Datagrams"
//! and "Wires"): a voice datagram goes on a set of wires of different fates,
//! the exit takes the first copy by its flow's seq. Video goes on one wire,
//! bulk on one wire. Which wires is the brain's choice; the pipe only puts
//! a wire with no member up aside for the best one of its fate that is up
//! (carry.rs), as the Go session does a datagram at a time.

pub use hikkari_trunk::flow::MAX_CARRIES;

use crate::ctl::ANY_WIRE;

/// A wire's fate as the route says it (trunk Fate): what must break on the
/// path for the wire to lose a frame. The brain numbers the fates it knows;
/// the pipe only compares them. FATE_NONE is a wire the route says nothing
/// of: a stream wire's is FATE_TCP, a packet wire's FATE_UDP (trunk fateOr).
pub const FATE_NONE: u8 = 0;
pub const FATE_UDP: u8 = 1;
pub const FATE_TCP: u8 = 2;

/// One wire of a set (trunk Carry): how many of its members carry each
/// datagram (0: the flow's copies), and how long after the datagram they
/// send it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Carry {
    pub wire: u8,
    pub copies: u8,
    pub after_ns: u64,
}

/// The wires a class's datagrams go on at once (trunk Set).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Set {
    n: u8,
    c: [Carry; MAX_CARRIES],
}

impl Set {
    pub fn of(carries: &[Carry]) -> Set {
        let mut s = Set::default();
        for &c in carries.iter().take(MAX_CARRIES) {
            s.c[s.n as usize] = c;
            s.n += 1;
        }
        s
    }

    pub fn len(&self) -> usize {
        self.n as usize
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    pub fn carries(&self) -> &[Carry] {
        &self.c[..self.n as usize]
    }

    pub fn has(&self, wire: u8) -> bool {
        self.carries().iter().any(|c| c.wire == wire)
    }

    /// Puts c in the set: a wire once, but for its later copies (trunk
    /// Set.add).
    pub fn add(&mut self, c: Carry) {
        if self.len() == MAX_CARRIES || c.after_ns == 0 && self.has(c.wire) {
            return;
        }
        self.c[self.n as usize] = c;
        self.n += 1;
    }
}

/// Which wires each class goes on, and the wires' fates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    /// The voice class's main wire: its datagrams go there with their
    /// flow's copies, and with one copy on the best wire of the other fate
    /// that is up (trunk Route.Voice).
    pub voice: u8,
    /// When it holds a wire, the voice class's whole set instead.
    pub voice_set: Set,
    pub bulk: u8,
    /// The video class's one wire; ANY_WIRE is voice's main wire.
    pub video: u8,
    /// Each wire's fate by id, FATE_NONE for one the route says nothing of.
    pub fates: [u8; 256],
}

impl Default for Route {
    fn default() -> Route {
        Route::one(ANY_WIRE)
    }
}

impl Route {
    /// Every class on wire w, no fates said (a pipe without a brain).
    pub fn one(w: u8) -> Route {
        Route { voice: w, voice_set: Set::default(), bulk: w, video: ANY_WIRE, fates: [FATE_NONE; 256] }
    }

    /// The video class's wire: its own, or voice's main wire.
    pub fn video(&self) -> u8 {
        if self.video == ANY_WIRE {
            self.voice
        } else {
            self.video
        }
    }

    /// Reads B_ROUTE's body: voice u8, bulk u8, video u8, n u8 and n ×
    /// (wire u8, copies u8, after_ms u16), m u8 and m × (wire u8, fate u8).
    /// None for one torn.
    pub fn parse(b: &[u8]) -> Option<Route> {
        let (&voice, &bulk, &video, &n) = (b.first()?, b.get(1)?, b.get(2)?, b.get(3)?);
        let mut at = 4;
        let mut set = Set::default();
        for _ in 0..n {
            let c = b.get(at..at + 4)?;
            if set.len() == MAX_CARRIES {
                return None;
            }
            let after_ms = u16::from_le_bytes([c[2], c[3]]);
            set.c[set.len()] = Carry { wire: c[0], copies: c[1], after_ns: after_ms as u64 * 1_000_000 };
            set.n += 1;
            at += 4;
        }
        let m = *b.get(at)?;
        at += 1;
        let mut fates = [FATE_NONE; 256];
        for _ in 0..m {
            let f = b.get(at..at + 2)?;
            fates[f[0] as usize] = f[1];
            at += 2;
        }
        if at != b.len() {
            return None;
        }
        Some(Route { voice, voice_set: set, bulk, video, fates })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden bytes of trunk/pipectl msg_test.go TestRouteBytes.
    pub const ROUTE_GOLDEN: &str = "05010003020200000001010a000200020101";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn a_route_reads_as_the_brain_wrote_it() {
        let b = unhex(ROUTE_GOLDEN);
        let r = Route::parse(&b[1..]).expect("the golden route");
        assert_eq!((r.voice, r.bulk, r.video, r.video()), (1, 0, 3, 3));
        let want = Set::of(&[Carry { wire: 2, copies: 0, after_ns: 0 }, Carry { wire: 1, copies: 1, after_ns: 10_000_000 }]);
        assert_eq!(r.voice_set, want);
        assert_eq!((r.fates[0], r.fates[1], r.fates[2]), (FATE_TCP, FATE_UDP, FATE_NONE));
        assert!(Route::parse(&b[1..b.len() - 1]).is_none(), "a fate torn short");
        let mut long = b[1..].to_vec();
        long.push(0);
        assert!(Route::parse(&long).is_none(), "a byte past the end");
    }

    #[test]
    fn a_later_copy_of_a_wire_in_the_set_is_its_own_carry() {
        let mut s = Set::default();
        s.add(Carry { wire: 1, copies: 1, after_ns: 0 });
        s.add(Carry { wire: 1, copies: 1, after_ns: 0 });
        s.add(Carry { wire: 1, copies: 1, after_ns: 10_000_000 });
        assert_eq!(s.len(), 2, "a wire once, but for its later copies");
        assert_eq!(Route::one(5).video(), 5, "video on voice's main wire");
    }
}
