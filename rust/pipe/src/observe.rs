//! A tester's stream or flow, as the entry's pipe saw it (spec/trunk.md,
//! "Observation"; trunk observe.go, the Go entry's reports). The exit marks
//! a stream or flow only for a tester's key and tells the entry the
//! observation's id in an observe frame (the entry's hello said it reads
//! them, frame::CAP_OBSERVE), never the key; the pipe then reports it to
//! the brain at the mark and at its end: the trunk's counters for it and,
//! for a stream, its client's TCP as the kernel sees it. A stream or flow
//! nobody marked is reported by no one; every one keeps its counters in
//! memory, as the Go entry's do.

use hikkari_sys::TcpInfo;

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
/// opened, datagrams read from the client and sent, received and delivered,
/// and copies dropped.
#[derive(Clone, Copy, Default)]
pub struct FlowObs {
    pub id: u64,
    pub opened: u64,
    pub out: u64,
    pub delivered: u64,
    pub copies: u64,
}

/// One report to the brain (ctl::put_observed).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Report {
    pub id: u64,
    /// frame::OBS_STREAM or OBS_FLOW.
    pub kind: u8,
    pub phase: u8,
    pub port: u16,
    pub age_ms: u32,
    pub up: u64,
    pub down: u64,
    pub chunks: u64,
    pub resent: u64,
    pub carriers: u8,
    pub deaths: u32,
    pub max_wait_ms: u32,
    pub dgrams_out: u64,
    pub dgrams_in: u64,
    pub copies: u64,
    pub end: u8,
    /// The client's TCP (a stream's, read at the report); None for a flow.
    pub tcp: Option<TcpInfo>,
}

fn ms(ns: u64) -> u32 {
    (ns / 1_000_000).min(u32::MAX as u64) as u32
}

impl Report {
    pub fn stream(o: &StreamObs, port: u16, phase: u8, end: u8, tcp: Option<TcpInfo>, now: u64) -> Report {
        Report {
            id: o.id,
            kind: hikkari_trunk::frame::OBS_STREAM,
            phase,
            port,
            age_ms: ms(now.saturating_sub(o.opened)),
            up: o.up,
            down: o.down,
            chunks: o.chunks,
            resent: o.resent,
            carriers: o.carriers.count_ones() as u8,
            deaths: o.deaths,
            max_wait_ms: ms(o.max_wait_ns),
            end,
            tcp,
            ..Report::default()
        }
    }

    pub fn flow(o: &FlowObs, port: u16, phase: u8, end: u8, now: u64) -> Report {
        Report {
            id: o.id,
            kind: hikkari_trunk::frame::OBS_FLOW,
            phase,
            port,
            age_ms: ms(now.saturating_sub(o.opened)),
            dgrams_out: o.out,
            dgrams_in: o.delivered,
            copies: o.copies,
            end,
            ..Report::default()
        }
    }
}
