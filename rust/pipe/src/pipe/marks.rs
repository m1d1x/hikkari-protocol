//! The exit's marks of testers' streams and flows (spec/trunk.md,
//! "Observation"; crate::observe): applied after the turn that read them,
//! and every report of the turn sent to the brain (ctl::put_observed), the
//! mark's and the ends'. Without a brain (the bench) a report is a line on
//! stderr.

use hikkari_trunk::frame::{OBS_FLOW, OBS_STREAM};

use super::Pipe;
use crate::ctl;

impl Pipe {
    pub(super) fn observed(&mut self, now: u64) {
        while let Some((kind, stream, token)) = self.marks.pop() {
            match kind {
                OBS_STREAM => self.streams.mark(stream, token, now),
                OBS_FLOW => self.flows.mark(stream, token, now),
                _ => {}
            }
        }
        if self.streams.reports.is_empty() && self.flows.reports.is_empty() {
            return;
        }
        let mut b = [0u8; ctl::OBSERVED_LEN];
        for r in self.streams.reports.drain(..).chain(self.flows.reports.drain(..)) {
            match &mut self.ctl {
                Some(c) => {
                    let n = ctl::put_observed(&mut b, &r);
                    c.send(&b[..n]);
                }
                None => eprintln!("hk-pipe: observed {r:?}"),
            }
        }
    }
}
