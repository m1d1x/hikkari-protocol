//! The exit's part of the trunk's call (spec/trunk.md, "Datagrams";
//! the reference is trunk echo.go): before the echo sends a call's datagram
//! back, it writes into it when the datagram reached it, by its wall clock,
//! and which of the call's last 64 frames it has had on this flow. The entry
//! hears each direction apart from them (trunk hearing.go).
//!
//! A call's datagram starts with its frame number (8 bytes, big endian), then
//! 8 bytes of the exit's stamp (unix ns) and 8 of its map, sent as zeros.

/// Where the exit writes in a call's datagram, and how long a datagram must
/// be to take both.
const STAMP_AT: usize = 8;
const MAP_AT: usize = 16;
pub const STAMPED: usize = 24;

/// Which of a flow's last 64 frame numbers the exit has had: bit i of bits
/// is top - i (trunk echoMap).
#[derive(Default, Clone, Copy)]
pub struct EchoMap {
    top: u64,
    bits: u64,
}

impl EchoMap {
    /// Marks frame n had and gives the map as of n: bit i is n - i. A frame
    /// older than the map by 64 or more is had alone.
    pub fn note(&mut self, n: u64) -> u64 {
        if n > self.top {
            let d = n - self.top;
            self.bits = if d >= 64 { 0 } else { self.bits << d };
            self.top = n;
            self.bits |= 1;
            return self.bits;
        }
        let d = self.top - n;
        if d >= 64 {
            return 1;
        }
        self.bits |= 1 << d;
        self.bits >> d
    }

    /// Writes the exit's part into a call's datagram p in place, wall_ns
    /// being the exit's wall clock now. A datagram too short to take it, or
    /// whose stamp and map are not zeros (another user of the echo: a bench,
    /// a tool), goes back as it came.
    pub fn stamp(&mut self, p: &mut [u8], wall_ns: u64) {
        if p.len() < STAMPED || p[STAMP_AT..STAMPED].iter().any(|&b| b != 0) {
            return;
        }
        let n = u64::from_be_bytes(p[..8].try_into().expect("8 bytes"));
        let bits = self.note(n);
        p[STAMP_AT..MAP_AT].copy_from_slice(&wall_ns.to_be_bytes());
        p[MAP_AT..STAMPED].copy_from_slice(&bits.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// trunk TestTheEchoMapSaysTheFramesTheExitHad, its golden frames.
    #[test]
    fn echo_map_follows_go() {
        let golden: [(u64, u64); 9] = [(1, 0x1), (2, 0x3), (3, 0x7), (5, 0x1d), (4, 0xf), (70, 0x1), (6, 0x1), (71, 0x3), (200, 0x1)];
        let mut m = EchoMap::default();
        for (n, want) in golden {
            assert_eq!(m.note(n), want, "frame {n}");
        }
        let mut p = [0u8; STAMPED];
        p[..8].copy_from_slice(&201u64.to_be_bytes());
        m.stamp(&mut p, 0x0102030405060708);
        let hex: String = p.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "00000000000000c901020304050607080000000000000003");
        let mut short = [0, 0, 0, 0, 0, 0, 0, 9u8];
        m.stamp(&mut short, 1);
        assert_eq!(short, [0, 0, 0, 0, 0, 0, 0, 9]);
        let before = p;
        m.stamp(&mut p, 2);
        assert_eq!(p, before, "a datagram stamped already is not stamped again");
    }
}
