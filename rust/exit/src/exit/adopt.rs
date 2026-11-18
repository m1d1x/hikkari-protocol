//! Adopt (spec/trunk.md, "An entry's own process replaced"): the entry's
//! new process claims a flow or a stream of its old process's session, and
//! it moves into the new one's session here, with its socket to the relay,
//! which sees nothing. The old session's id is the proof: only the entry
//! that opened it knows it. A flow's old id goes on reaching it until the
//! old session ends (flow::Flow::alias), so what the old process sent before
//! it learned of the move is not lost. A stream is not adopted yet: the
//! answer is not ok, and it stays with the old process.

use hikkari_trunk::flow::MAX_CARRIES;
use hikkari_trunk::frame::{self, OBS_FLOW};

use super::Exit;
use crate::flow::Heard;

impl Exit {
    /// The entry's adopt on member li: answered there with adopted. A
    /// stream's `up` and `down` are not read: no stream is adopted yet.
    pub(super) fn adopt_frame(&mut self, li: usize, kind: u8, from: &[u8; 16], old: u32, new: u32) {
        let s = self.links.all[li].session;
        let ok = match (kind, self.sessions.find(from)) {
            (OBS_FLOW, Some(o)) if o != s => self.adopt_flow(o, s, old, new),
            _ => false,
        };
        if ok {
            self.adopted += 1;
        } else {
            self.adopt_refused += 1;
        }
        self.links.all[li].out.frame(frame::ADOPTED_LEN, |b| frame::put_adopted(b, kind, new, ok));
    }

    /// Flow `old` of session o is `new` of session s. Adopting twice is
    /// adopting once.
    fn adopt_flow(&mut self, o: usize, s: usize, old: u32, new: u32) -> bool {
        if let Some(&fi) = self.sessions.all[s].flows.get(&new) {
            return self.flows.all[fi].alias == (o, old);
        }
        let Some(&fi) = self.sessions.all[o].flows.get(&old) else { return false };
        let f = &mut self.flows.all[fi];
        if f.session != o || f.echo() {
            return false;
        }
        f.session = s;
        f.stream = new;
        f.alias = (o, old);
        // The members it came on are the old session's: its answers go on
        // the new one's from now on (Heard::FREE: any member up).
        f.heard = [Heard::FREE; MAX_CARRIES];
        self.sessions.all[s].flows.insert(new, fi);
        true
    }
}
