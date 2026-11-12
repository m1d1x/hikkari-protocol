//! A stream member's death on the exit (spec/trunk.md, "Member": dead, its
//! chunks sent again on the other members oldest first as they have room),
//! the exit's side of what the entry's pipe does (hk-pipe death.rs): what
//! it carried unconfirmed, chunks and FINs, waits as stranded in its
//! session's streams and goes again ahead of anything new, a chunk with the
//! bytes its stream kept (hikkari_trunk::stream::Kept); no stream is reset by
//! it. The exit cannot open members: the entry's new member is what the
//! session waits for. The reference is trunk session.go: dropMemberLocked,
//! drainPendingLocked.

use hikkari_trunk::frame::{self, F_DATA, F_FIN, NO_GOT};

use super::stream::ack_on;
use super::tcp::{pick, Down};
use super::Exit;
use crate::link::carrier;

impl Exit {
    /// What dead members of session s carried, sent again oldest first
    /// (stream by stream in the order the entry opened them, each in the
    /// order it sent) as far as the members up have room; a chunk only on a
    /// member with room under INFLIGHT. Whether nothing waits any more.
    pub(super) fn resend(&mut self, s: usize, now: u64) -> bool {
        let Exit { sessions, streams, links, moved, .. } = self;
        let sess = &mut sessions.all[s];
        let mut resent = 0;
        let mut all = true;
        'streams: while let Some(&id) = sess.stranded.first() {
            let Some(&slot) = sess.streams.get(&id) else {
                sess.stranded.pop_first();
                continue;
            };
            let st = &mut streams.all[slot];
            while let Some(i) = st.send.next_stranded() {
                let o = st.send.owed[i];
                let Some(li) = pick(links, &sess.links, st.wire, o.kind == F_DATA) else {
                    all = false;
                    break 'streams;
                };
                let l = &mut links.all[li];
                let went = match o.kind {
                    F_FIN => l.out.frame(13, |b| frame::put_fin(b, st.id, o.off)),
                    _ => {
                        let len = o.len as usize;
                        if l.out.chunk_room(len) < len {
                            false
                        } else {
                            l.out.chunk_buf(len).copy_from_slice(st.send.kept.get(o.off, len));
                            l.out.chunk_done(st.id, o.off, len);
                            resent += 1;
                            *moved += 1;
                            true
                        }
                    }
                };
                if !went {
                    all = false;
                    break 'streams;
                }
                st.send.resent(i, carrier(li, l.gen));
                l.owe(o.len as usize, now);
            }
            sess.stranded.pop_first();
        }
        streams.n.resent += resent;
        all
    }

    /// Stream member li is down (trunk dropMemberLocked): its connection
    /// closed, what it carried unconfirmed goes again on the session's other
    /// members, and every stream of the session acks again elsewhere (the
    /// acks it carried may be lost).
    pub(super) fn link_down(&mut self, li: usize, why: Down, now: u64) {
        let l = &self.links.all[li];
        if !l.live {
            return;
        }
        let (joined, s, c) = (l.joined(), l.session, carrier(li, l.gen));
        self.links.close(li);
        if !joined {
            return;
        }
        match why {
            Down::Silent => self.t.silent += 1,
            Down::Quiet => self.t.quiet += 1,
            Down::Gone => self.t.gone += 1,
        }
        self.t.links -= 1;
        let Exit { sessions, streams, .. } = self;
        let sess = &mut sessions.all[s];
        sess.link_leave(li, now);
        let mut hit = 0;
        for &slot in sess.streams.values() {
            let st = &mut streams.all[slot];
            if st.send.strand(c) {
                sess.stranded.insert(st.id);
                hit += 1;
            }
        }
        streams.n.deaths += hit;
        if hit > 0 {
            self.resend(s, now);
        }
        let Exit { sessions, streams, links, .. } = self;
        let sess = &sessions.all[s];
        for &slot in sess.streams.values() {
            let st = &mut streams.all[slot];
            let Some(li) = pick(links, &sess.links, st.wire, false) else { break };
            ack_on(&mut links.all[li].out, st, NO_GOT);
        }
    }
}
