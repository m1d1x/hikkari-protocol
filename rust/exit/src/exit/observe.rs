//! A tester's stream or flow at the exit (spec/trunk.md, "Observation"; the
//! Go exit's Session.Observe and its reports, trunk observe.go; edge
//! trunk_observe.go). The relay that knows the client's key is the brain's
//! process, not this one: the exit tells the brain the local port of each of
//! its connections to the relay with the stream or flow it carries (`local`),
//! the brain marks the one whose connection the relay admitted a tester's
//! key on (`mark`, with an observation id it drew), and the exit reports it
//! at the mark and at its end (`observed`), and tells the entry the id in an
//! observe frame on two members, if the entry's hello said it reads them.
//! A stream or flow never marked is reported by no one.

use hikkari_trunk::frame::{self, OBS_FLOW, OBS_STREAM};
use hikkari_trunk::observe::{FlowObs, StreamObs, END_NONE, PHASE_END, PHASE_MARK};

use super::Exit;
use crate::ctl::{self, Observed};
use crate::peer::Class;

fn ms(ns: u64) -> u32 {
    (ns / 1_000_000).min(u32::MAX as u64) as u32
}

fn of_stream(o: &StreamObs, port: u16, phase: u8, end: u8, now: u64) -> Observed {
    Observed {
        id: o.id,
        kind: OBS_STREAM,
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
        ..Observed::default()
    }
}

fn of_flow(o: &FlowObs, port: u16, phase: u8, end: u8, now: u64) -> Observed {
    Observed { id: o.id, kind: OBS_FLOW, phase, port, age_ms: ms(now.saturating_sub(o.opened)), dgrams_out: o.out, dgrams_in: o.delivered, copies: o.copies, end, ..Observed::default() }
}

impl Exit {
    /// Tells the brain a connection to the relay opened or closed: its
    /// local port names the stream or flow of session s.
    pub(super) fn tell_local(&mut self, open: bool, kind: u8, port: u16, s: usize, stream: u32) {
        if port == 0 {
            return;
        }
        let Some(c) = self.ctl.as_mut() else { return };
        let mut b = [0u8; ctl::LOCAL_LEN];
        let n = ctl::put_local(&mut b, open, kind, port, &self.sessions.all[s].id, stream);
        c.send(&b[..n]);
    }

    fn tell_observed(&mut self, r: &Observed) {
        let Some(c) = self.ctl.as_mut() else { return };
        let mut b = [0u8; ctl::OBSERVED_LEN];
        let n = ctl::put_observed(&mut b, r);
        c.send(&b[..n]);
    }

    /// The brain's `mark`: the stream or flow is a tester's. One that ended,
    /// or is marked already, is not marked again (trunk Session.Observe).
    pub(super) fn mark(&mut self, kind: u8, session: &[u8; 16], stream: u32, id: u64, now: u64) {
        let Some(s) = self.sessions.find(session) else { return };
        let r = match kind {
            OBS_STREAM => {
                let Some(&slot) = self.sessions.all[s].streams.get(&stream) else { return };
                let st = &mut self.streams.all[slot];
                if st.obs.id != 0 || id == 0 {
                    return;
                }
                st.obs.id = id;
                of_stream(&st.obs, st.port, PHASE_MARK, END_NONE, now)
            }
            OBS_FLOW => {
                let Some(&fi) = self.sessions.all[s].flows.get(&stream) else { return };
                let f = &mut self.flows.all[fi];
                if f.obs.id != 0 || id == 0 {
                    return;
                }
                f.obs.id = id;
                of_flow(&f.obs, f.port, PHASE_MARK, END_NONE, now)
            }
            _ => return,
        };
        self.tell_observed(&r);
        if self.sessions.all[s].observe {
            self.observe_frame(s, kind, stream, id, now);
        }
    }

    /// The observe frame on two members of session s, as a reset goes: one
    /// that dies with it would leave the entry blind to this stream for good.
    fn observe_frame(&mut self, s: usize, kind: u8, stream: u32, id: u64, now: u64) {
        let Exit { sessions, peers, wires, links, .. } = self;
        let sess = &sessions.all[s];
        let mut sent = 0;
        for &(pi, gen) in &sess.members {
            let p = &mut peers[pi];
            if sent < 2 && p.live && p.gen == gen && wires[p.wire].glue(p, Class::Own, 14, now, |b| frame::put_observe(b, kind, stream, id)) {
                sent += 1;
            }
        }
        for &(li, _) in &sess.links {
            if sent < 2 && links.all[li].out.frame(14, |b| frame::put_observe(b, kind, stream, id)) {
                sent += 1;
            }
        }
    }

    /// Stream slot ends: its end reported if it was marked, its connection
    /// to the relay told closed.
    pub(super) fn stream_ended(&mut self, slot: usize, end: u8, now: u64) {
        let st = &self.streams.all[slot];
        let (s, id, port, local) = (st.session, st.id, st.port, st.local_port);
        let r = (st.obs.id != 0).then(|| of_stream(&st.obs, port, PHASE_END, end, now));
        if let Some(r) = r {
            self.tell_observed(&r);
        }
        self.tell_local(false, OBS_STREAM, local, s, id);
    }

    /// Flow fi ends: as a stream does.
    pub(super) fn flow_ended(&mut self, fi: usize, end: u8, now: u64) {
        let f = &self.flows.all[fi];
        let (s, stream, port, local) = (f.session, f.stream, f.port, f.local_port);
        let r = (f.obs.id != 0).then(|| of_flow(&f.obs, port, PHASE_END, end, now));
        if let Some(r) = r {
            self.tell_observed(&r);
        }
        self.tell_local(false, OBS_FLOW, local, s, stream);
    }
}
