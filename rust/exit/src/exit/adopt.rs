//! Adopt (spec/trunk.md, "An entry's own process replaced"): the entry's
//! new process claims a flow or a stream of its old process's session, and
//! it moves into the new one's session here, with its socket to the relay,
//! which sees nothing. The old session's id is the proof: only the entry
//! that opened it knows it. A flow's old id goes on reaching it until the
//! old session ends (flow::Flow::alias), so what the old process sent before
//! it learned of the move is not lost. A stream's old process sent nothing
//! after it waited for every byte to be confirmed: its old id ends here, and
//! what this exit sent past `down`, which the old process never wrote to its
//! client, goes again on the new session.

use hikkari_trunk::flow::MAX_CARRIES;
use hikkari_trunk::frame::{self, NO_GOT, OBS_FLOW, OBS_STREAM};
use hikkari_trunk::stream::{NO_CARRIER, WINDOW};

use super::stream::{ack_on, forget};
use super::Exit;
use crate::flow::Heard;

impl Exit {
    /// The entry's adopt on member li: answered there with adopted.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn adopt_frame(&mut self, li: usize, kind: u8, from: &[u8; 16], old: u32, new: u32, up: u64, down: u64, now: u64) {
        let s = self.links.all[li].session;
        let ok = match (kind, self.sessions.find(from)) {
            (OBS_FLOW, Some(o)) if o != s => self.adopt_flow(o, s, old, new),
            (OBS_STREAM, Some(o)) if o != s => self.adopt_stream(li, o, s, old, new, up, down, now),
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

    /// Stream `old` of session o is `new` of session s, whose member li the
    /// adopt came on; the client sent `up` bytes and got `down`. `up` must
    /// be what this exit received, all of it in order. What it owes past
    /// `down` goes again on s; an ack there gives the new process its
    /// credit. Adopting twice is adopting once.
    #[allow(clippy::too_many_arguments)]
    fn adopt_stream(&mut self, li: usize, o: usize, s: usize, old: u32, new: u32, up: u64, down: u64, now: u64) -> bool {
        if let Some(&slot) = self.sessions.all[s].streams.get(&new) {
            let st = &mut self.streams.all[slot];
            if st.adopted_from != (o, old) {
                return false;
            }
            ack_on(&mut self.links.all[li].out, st, NO_GOT);
            return true;
        }
        let Some(&slot) = self.sessions.all[o].streams.get(&old) else { return false };
        let st = &self.streams.all[slot];
        if st.recv.received != up || !st.recv.none_ahead() || st.recv.fin_at.is_some() || down > st.send.sent {
            return false;
        }
        let wire = self.links.all[li].wire;
        let Exit { streams, links, released, sessions, .. } = self;
        let st = &mut streams.all[slot];
        // What the old process wrote to its client is confirmed; the rest
        // went on the old session's members and goes again.
        st.send.acked(down, down + WINDOW, 0, NO_GOT, |w| released.push((w.carrier, w.len)));
        for w in st.send.owed.iter_mut().filter(|w| w.carrier != NO_CARRIER) {
            forget(links, w.carrier, w.len);
            w.carrier = NO_CARRIER;
            st.send.stranded += 1;
        }
        st.session = s;
        st.id = new;
        st.wire = wire;
        st.adopted_from = (o, old);
        ack_on(&mut links.all[li].out, st, NO_GOT);
        let stranded = st.send.stranded > 0;
        sessions.all[o].streams.remove(&old);
        sessions.all[o].stranded.remove(&old);
        let sess = &mut sessions.all[s];
        sess.streams.insert(new, slot);
        if stranded {
            sess.stranded.insert(new);
        }
        self.confirm(now);
        self.resend(s, now);
        true
    }
}
