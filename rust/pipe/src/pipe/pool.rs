//! The brain's streams (README.md, «Brain and pipe»): client ports of
//! streams (a listening TCP socket the brain bound, `tcp_listen`) and wires
//! of stream members (`pool`): plain TCP to the exit's member port, or
//! Chromium's CONNECT to the exit's relay, the pool's form (trunk/chromium,
//! hikkari_cronet). The members are the pipe's own: dialed from its book of
//! source ports, so the brain gives the form, not sockets.

use std::os::fd::OwnedFd;

use hikkari_sys as sys;
use hikkari_trunk::ports::{self, Book};

use super::death::Down;
use super::tcp::TcpListen;
use super::Pipe;
use crate::ctl::{self, Pool, ANY_WIRE};
use crate::link::{Link, Reach, StreamWire};

/// Whether two ways to the exit are the same: a pool sent again unchanged
/// keeps its members.
fn same_reach(a: &Reach, b: &Reach) -> bool {
    match (a, b) {
        (Reach::Plain(x), Reach::Plain(y)) => x == y,
        (Reach::Chromium(x), Reach::Chromium(y)) => {
            let (x, y) = (x.form(), y.form());
            x.exit == y.exit && x.sni == y.sni && x.key == y.key && x.roots == y.roots
        }
        _ => false,
    }
}

impl Pipe {
    /// The brain's client port of streams `id` (a new one, or the same id
    /// again: the socket replaced) to the exit's port `to`.
    pub(super) fn tcp_listen(&mut self, id: u8, to: u16, fd: OwnedFd) {
        let l = TcpListen { id, fd, to };
        match self.tcp_listens.iter_mut().find(|l| l.id == id) {
            Some(old) => *old = l,
            None => self.tcp_listens.push(l),
        }
        self.dirty = true;
    }

    /// The brain's pool: a wire of stream members of the session that takes
    /// everything new (session.rs). Sent again unchanged it changes only the
    /// members' stall; a new form, exit or number of members takes its
    /// members down (what they carried goes again, no stream is reset) and
    /// dials them anew. A new range of source ports does so for every stream
    /// member of the pipe.
    pub(super) fn set_pool(&mut self, p: &Pool) -> Result<(), String> {
        let id = p.id;
        if id == ANY_WIRE {
            return Err("pool 255 is no wire".into());
        }
        if p.members == 0 {
            return Err(format!("pool {id}: no member"));
        }
        let Some(sess) = self.taker() else {
            return Err(format!("pool {id}: the pipe drains, it takes no new member"));
        };
        let reach = match p.form {
            ctl::POOL_PLAIN => Reach::Plain(p.exit),
            ctl::POOL_CHROMIUM => {
                hikkari_cronet::load((!p.cronet.is_empty()).then_some(p.cronet))?;
                let roots = (!p.roots.is_empty()).then(|| p.roots.to_string());
                let form = hikkari_cronet::Form::new(p.exit, p.sni, p.key, roots)?;
                Reach::Chromium(hikkari_cronet::Engine::new(form))
            }
            f => return Err(format!("pool {id}: form {f} is not one the pipe carries")),
        };
        let now = sys::now_ns();
        if p.ports != self.ports_range {
            let book = Book::new(p.ports.0, p.ports.1, ports::DEAD_FOR_NS).map_err(|e| format!("pool {id}: {e}"))?;
            self.all_links_down(now);
            self.ports = book;
            self.ports_range = p.ports;
        }
        let stall_ns = p.dead_ms.max(1) as u64 * 1_000_000;
        let members = p.members as usize;
        let Some(wi) = self.swires.iter().position(|w| w.id == id && w.sess == sess) else {
            let mut w = StreamWire::new(id, reach, members, stall_ns);
            w.sess = sess;
            let wi = match self.swires.iter().position(|w| w.sess == crate::link::NO_SESSION) {
                Some(i) => {
                    self.swires[i] = w;
                    i
                }
                None => {
                    self.swires.push(w);
                    self.swires.len() - 1
                }
            };
            for li in 0..members {
                self.redial(wi, li, now);
            }
            return Ok(());
        };
        self.swires[wi].stall_ns = stall_ns;
        if self.swires[wi].links.len() == members && same_reach(&self.swires[wi].reach, &reach) {
            return Ok(());
        }
        for li in 0..self.swires[wi].links.len() {
            if self.swires[wi].links[li].sock.is_some() {
                self.link_down(wi, li, Down::Lost, now);
            }
        }
        let w = &mut self.swires[wi];
        w.reach = reach;
        w.links.truncate(members);
        while w.links.len() < members {
            w.links.push(Link::new());
        }
        for li in 0..members {
            if self.swires[wi].links[li].renew_at == 0 {
                self.redial(wi, li, now);
            }
        }
        Ok(())
    }

    /// Every stream member down (a new book of source ports): what they
    /// carried goes again once they are back.
    fn all_links_down(&mut self, now: u64) {
        for wi in 0..self.swires.len() {
            for li in 0..self.swires[wi].links.len() {
                if self.swires[wi].links[li].sock.is_some() {
                    self.link_down(wi, li, Down::Lost, now);
                }
            }
        }
    }

    /// Takes a pool's stream wire away (`unwire` of its id): its members
    /// close, what they carried goes again on the session's other wires.
    pub(super) fn unpool(&mut self, id: u8) {
        let now = sys::now_ns();
        for wi in 0..self.swires.len() {
            if self.swires[wi].id != id || self.swires[wi].sess == crate::link::NO_SESSION {
                continue;
            }
            self.swires[wi].sess = crate::link::NO_SESSION;
            for li in 0..self.swires[wi].links.len() {
                if self.swires[wi].links[li].sock.is_some() {
                    self.link_down(wi, li, Down::Lost, now);
                }
                self.swires[wi].links[li].renew_at = 0;
            }
        }
        self.dirty = true;
    }
}
