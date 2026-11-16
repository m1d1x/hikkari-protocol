//! A tester's stream or flow, as either end of the trunk counts it
//! (spec/trunk.md, "Observation"; trunk observe.go). The exit marks a
//! stream or flow only for a tester's key, reports it and tells the entry
//! the observation's id in an observe frame (the entry's hello said it reads
//! them, frame::CAP_OBSERVE), never the key; each end then reports it at the
//! mark and at its end. A stream or flow nobody marked is reported by no
//! one; every one keeps these counters in memory, as the Go ends' do. Here
//! are the counters and the codes of a report; each pipe says them to its
//! brain in its own message.

/// A report at the mark (what it did so far) and at its end (trunk
/// PhaseMark, PhaseEnd).
pub const PHASE_MARK: u8 = 0;
pub const PHASE_END: u8 = 1;

/// How it ended (trunk EndFin, EndLocal, EndPeer, EndEpoch, EndSession,
/// EndIdle); END_NONE at the mark.
pub const END_NONE: u8 = 0;
pub const END_FIN: u8 = 1;
pub const END_LOCAL: u8 = 2;
pub const END_PEER: u8 = 3;
pub const END_EPOCH: u8 = 4;
pub const END_SESSION: u8 = 5;
pub const END_IDLE: u8 = 6;

/// What a stream did (trunk streamReportLocked): its observation, when it
/// opened, the client's bytes numbered toward the exit and the exit's
/// written to the client, chunks sent and sent again after their member
/// died, the members that carried it (one bit per member index of its
/// session) and how many died owing it, the longest a chunk waited for its
/// confirmation.
#[derive(Clone, Copy, Default)]
pub struct StreamObs {
    pub id: u64,
    pub opened: u64,
    pub up: u64,
    pub down: u64,
    pub chunks: u64,
    pub resent: u64,
    pub carriers: u64,
    pub deaths: u32,
    pub max_wait_ns: u64,
}

impl StreamObs {
    pub fn new(now: u64) -> StreamObs {
        StreamObs { opened: now, ..StreamObs::default() }
    }

    /// Member `index` carried a frame of it.
    #[inline]
    pub fn carried(&mut self, index: usize) {
        self.carriers |= 1u64 << (index % 64);
    }

    /// A frame it owed was confirmed `wait_ns` after it was first sent.
    #[inline]
    pub fn waited(&mut self, wait_ns: u64) {
        if wait_ns > self.max_wait_ns {
            self.max_wait_ns = wait_ns;
        }
    }
}

/// What a flow did (trunk flowReportLocked): its observation, when it
/// opened, datagrams read from its local end (the entry's client, the exit's
/// relay) and sent, received and delivered, and copies dropped.
#[derive(Clone, Copy, Default)]
pub struct FlowObs {
    pub id: u64,
    pub opened: u64,
    pub out: u64,
    pub delivered: u64,
    pub copies: u64,
}


impl FlowObs {
    pub fn new(now: u64) -> FlowObs {
        FlowObs { opened: now, ..FlowObs::default() }
    }
}
