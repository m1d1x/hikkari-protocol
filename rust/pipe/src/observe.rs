//! A tester's stream or flow as the entry's pipe reports it to the brain
//! (spec/trunk.md, "Observation"): the counters and codes are
//! hikkari_trunk::observe's, shared with the exit; here is the report with
//! the client's TCP as the kernel sees it.

use hikkari_sys::TcpInfo;
pub use hikkari_trunk::observe::*;

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
