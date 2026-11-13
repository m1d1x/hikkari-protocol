//! The Chromium QUIC wire on the exit (spec/trunk.md, "Wires": `h3dgram`):
//! one UDP socket for every member, QUIC and HTTP/3 by quiche (sans-IO, in
//! the exit's own loop), a member per QUIC connection that asked a
//! CONNECT-UDP with a known token. Here are the connections and what QUIC
//! and HTTP/3 make of their packets; what the frames of a member's
//! datagrams do is the exit's, as for any packet member (exit/h3.rs).
//!
//! On a packet: a connection by its destination id, read from the header
//! here (quiche's own header parse allocates; it reads only a new
//! connection's Initial). Datagrams are copied into buffers of a fixed size
//! (Bufs), not allocated one by one. Packets out go in one sendmmsg a turn.

use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::os::fd::AsRawFd;

use hikkari_sys::{self as sys, sockaddr_in, SendBatch, BATCH};
use hikkari_trunk::h3dgram::{self, TOKEN};
use quiche::h3;

/// The exit's connection ids: random, this long.
pub const CID: usize = 16;
/// The largest UDP payload the exit reads or sends; packets out are at most
/// SEND_MAX (what Google's servers send; Chromium takes up to 1452).
pub const PKT: usize = 1500;
const SEND_MAX: usize = 1350;
/// The largest DATAGRAM frame either side takes: a QUIC packet's worth.
pub const DGRAM: usize = 1400;
/// Datagrams each connection queues each way (quiche's queues).
const DGRAM_QUEUE: usize = 1024;
/// A connection silent this long is closed by QUIC itself; a member pings
/// every 100 ms, so only a dead one gets there (the exit's Quiet is the
/// same 30 s).
const IDLE_MS: u64 = 30_000;
/// H3_NO_ERROR, and H3_REQUEST_REJECTED for a member closed by the exit.
const H3_NO_ERROR: u64 = 0x100;
const H3_CLOSED: u64 = 0x10b;

/// A datagram's buffer of a fixed size: quiche keeps its datagram queues
/// in these, with no allocation per datagram.
pub struct Dg {
    n: u16,
    b: [u8; DGRAM],
}

impl Dg {
    fn of(s: &[u8]) -> Dg {
        let mut d = Dg { n: s.len().min(DGRAM) as u16, b: [0; DGRAM] };
        d.b[..d.n as usize].copy_from_slice(&s[..d.n as usize]);
        d
    }
}

impl AsRef<[u8]> for Dg {
    fn as_ref(&self) -> &[u8] {
        &self.b[..self.n as usize]
    }
}

impl From<Vec<u8>> for Dg {
    fn from(v: Vec<u8>) -> Dg {
        Dg::of(&v)
    }
}

/// The buffers the exit's connections use: streams' as quiche's default
/// (only HTTP/3's own streams and a request's headers), datagrams' Dg.
#[derive(Clone, Default, Debug)]
pub struct Bufs;

impl quiche::BufFactory for Bufs {
    type Buf = std::sync::Arc<[u8]>;
    type DgramBuf = Dg;

    fn buf_from_slice(buf: &[u8]) -> Self::Buf {
        buf.into()
    }

    fn dgram_buf_from_slice(buf: &[u8]) -> Dg {
        Dg::of(buf)
    }
}

impl std::fmt::Debug for Dg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Dg({} B)", self.n)
    }
}

/// A connection id as a map key: its length, then its bytes.
type CidKey = [u8; 1 + quiche::MAX_CONN_ID_LEN];

fn cid_key(id: &[u8]) -> Option<CidKey> {
    if id.len() > quiche::MAX_CONN_ID_LEN {
        return None;
    }
    let mut k = [0u8; 1 + quiche::MAX_CONN_ID_LEN];
    k[0] = id.len() as u8;
    k[1..1 + id.len()].copy_from_slice(id);
    Some(k)
}

/// What a request on a connection came to.
pub enum Req {
    /// A CONNECT-UDP with a known token on this request stream: a member.
    Member(u64),
    /// A member's request stream ended (finished or reset by the entry).
    Ended(u64),
}

/// One QUIC connection from the entry.
pub struct Conn {
    q: quiche::Connection<Bufs>,
    h3: Option<h3::Connection>,
    /// Its ids in the map: the exit's own and the entry's first one.
    keys: [CidKey; 2],
    /// Its members: request stream, peer slot and gen.
    pub members: Vec<(u64, usize, u32)>,
    /// When QUIC wants on_timeout (monotonic ns; 0: never).
    due: u64,
    dirty: bool,
}

/// What the wire counts since it came.
#[derive(Default)]
pub struct Counts {
    pub conns: u64,
    pub refused: u64,
    /// Datagrams no member took (not a member's stream, another context),
    /// and those over what the connection's datagram holds or past its full
    /// queue.
    pub stray: u64,
    pub too_big: u64,
    pub full: u64,
}

pub struct H3Wire {
    sock: UdpSocket,
    local: SocketAddr,
    config: quiche::Config,
    h3c: h3::Config,
    tokens: Vec<[u8; TOKEN]>,
    conns: Vec<Option<Conn>>,
    free: Vec<usize>,
    by_cid: HashMap<CidKey, usize>,
    out: Vec<u8>,
    out_n: usize,
    pub send: SendBatch,
    body: Vec<u8>,
    pub n: Counts,
}

impl H3Wire {
    /// The wire on `sock` with the certificate and key in PEM files and the
    /// tokens of its trunk keys (h3dgram::token).
    pub fn new(sock: UdpSocket, cert: &str, key: &str, tokens: Vec<[u8; TOKEN]>) -> Result<H3Wire, String> {
        let local = sock.local_addr().map_err(|e| format!("h3dgram: the socket: {e}"))?;
        let mut c = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("h3dgram: QUIC: {e}"))?;
        c.load_cert_chain_from_pem_file(cert).map_err(|e| format!("h3dgram: certificate {cert}: {e}"))?;
        c.load_priv_key_from_pem_file(key).map_err(|e| format!("h3dgram: key {key}: {e}"))?;
        c.set_application_protos(h3::APPLICATION_PROTOCOL).map_err(|e| format!("h3dgram: ALPN: {e}"))?;
        c.set_max_idle_timeout(IDLE_MS);
        c.set_max_recv_udp_payload_size(PKT);
        c.set_max_send_udp_payload_size(SEND_MAX);
        c.set_initial_max_data(10 << 20);
        c.set_initial_max_stream_data_bidi_local(1 << 20);
        c.set_initial_max_stream_data_bidi_remote(1 << 20);
        c.set_initial_max_stream_data_uni(1 << 20);
        c.set_initial_max_streams_bidi(100);
        c.set_initial_max_streams_uni(100);
        c.set_disable_active_migration(true);
        c.enable_dgram(true, DGRAM_QUEUE, DGRAM_QUEUE);
        let mut h3c = h3::Config::new().map_err(|e| format!("h3dgram: HTTP/3: {e}"))?;
        h3c.enable_extended_connect(true);
        Ok(H3Wire {
            sock,
            local,
            config: c,
            h3c,
            tokens,
            conns: Vec::new(),
            free: Vec::new(),
            by_cid: HashMap::with_capacity(64),
            out: vec![0; PKT * BATCH],
            out_n: 0,
            send: SendBatch::new(),
            body: vec![0; 4096],
            n: Counts::default(),
        })
    }

    #[inline]
    pub fn fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }

    /// One packet from `from`: the connection it is for, made on a new
    /// connection's Initial; None for a packet of no connection.
    pub fn recv(&mut self, from: sockaddr_in, d: &mut [u8]) -> Option<usize> {
        let ci = match dcid(d).and_then(cid_key).and_then(|k| self.by_cid.get(&k).copied()) {
            Some(ci) => ci,
            None => self.accept(from, d)?,
        };
        let from = SocketAddr::V4(addr_of(&from));
        let c = self.conns[ci].as_mut().expect("a connection in the map");
        c.dirty = true;
        if c.q.recv(d, quiche::RecvInfo { from, to: self.local }).is_err() {
            return Some(ci);
        }
        if c.h3.is_none() && (c.q.is_established() || c.q.is_in_early_data()) {
            match h3::Connection::with_transport(&mut c.q, &self.h3c) {
                Ok(h) => c.h3 = Some(h),
                Err(_) => {
                    let _ = c.q.close(true, H3_CLOSED, b"");
                }
            }
        }
        Some(ci)
    }

    /// A new connection for an Initial; a version QUIC v1 is not gets the
    /// versions the exit speaks.
    fn accept(&mut self, from: sockaddr_in, d: &mut [u8]) -> Option<usize> {
        let hdr = quiche::Header::from_slice(d, CID).ok()?;
        if hdr.ty != quiche::Type::Initial {
            return None;
        }
        if !quiche::version_is_supported(hdr.version) {
            self.queue_raw(&from, |out| quiche::negotiate_version(&hdr.scid, &hdr.dcid, out).ok());
            return None;
        }
        let mut id = [0u8; CID];
        sys::urandom(&mut id);
        let scid = quiche::ConnectionId::from_ref(&id);
        let peer = SocketAddr::V4(addr_of(&from));
        let q = quiche::accept_with_buf_factory::<Bufs>(&scid, None, self.local, peer, &mut self.config).ok()?;
        let keys = [cid_key(&id)?, cid_key(&hdr.dcid)?];
        let ci = self.free.pop().unwrap_or_else(|| {
            self.conns.push(None);
            self.conns.len() - 1
        });
        self.conns[ci] = Some(Conn { q, h3: None, keys, members: Vec::with_capacity(1), due: 0, dirty: true });
        for k in keys {
            self.by_cid.insert(k, ci);
        }
        self.n.conns += 1;
        Some(ci)
    }

    /// The next request event of connection ci that is the exit's to act
    /// on; requests that are no member's are answered here.
    pub fn poll(&mut self, ci: usize) -> Option<Req> {
        let c = self.conns[ci].as_mut()?;
        let h = c.h3.as_mut()?;
        loop {
            match h.poll(&mut c.q) {
                Ok((stream, h3::Event::Headers { list, .. })) => {
                    if request_is_member(&list, &self.tokens) {
                        let ok = [h3::Header::new(b":status", b"200"), h3::Header::new(b"capsule-protocol", b"?1")];
                        if h.send_response(&mut c.q, stream, &ok, false).is_ok() {
                            return Some(Req::Member(stream));
                        }
                    }
                    self.n.refused += 1;
                    let _ = h.send_response(&mut c.q, stream, &[h3::Header::new(b":status", b"404")], true);
                }
                // Capsules on a member's stream, or a body nobody asked
                // for: read and dropped.
                Ok((stream, h3::Event::Data)) => while h.recv_body(&mut c.q, stream, &mut self.body).is_ok() {},
                Ok((stream, h3::Event::Finished)) | Ok((stream, h3::Event::Reset(_))) => {
                    if c.members.iter().any(|m| m.0 == stream) {
                        return Some(Req::Ended(stream));
                    }
                }
                Ok(_) => {}
                Err(h3::Error::Done) => return None,
                Err(_) => {
                    let _ = c.q.close(true, H3_CLOSED, b"");
                    return None;
                }
            }
        }
    }

    /// Peer pi (of gen) is the member of request `stream` on ci.
    pub fn bind(&mut self, ci: usize, stream: u64, pi: usize, gen: u32) {
        if let Some(c) = self.conns[ci].as_mut() {
            c.members.push((stream, pi, gen));
        }
    }

    /// The next datagram of connection ci for a member: its peer slot and
    /// where its frames are in buf.
    pub fn dgram(&mut self, ci: usize, buf: &mut [u8]) -> Option<(usize, usize, usize)> {
        let c = self.conns[ci].as_mut()?;
        loop {
            let n = c.q.dgram_recv(buf).ok()?;
            let member = h3dgram::read_head(&buf[..n]).and_then(|(s, at)| c.members.iter().find(|m| m.0 == s).map(|m| (m.1, at)));
            match member {
                Some((pi, at)) => return Some((pi, at, n)),
                None => self.n.stray += 1,
            }
        }
    }

    /// The frames at `glue[from..end]` as one datagram of request `stream`
    /// on ci: the head goes into the bytes before them. False when the
    /// datagram is over what the connection holds or its queue is full.
    pub fn send_dgram(&mut self, ci: usize, stream: u64, glue: &mut [u8], from: usize, end: usize) -> bool {
        let Some(c) = self.conns[ci].as_mut() else { return false };
        let at = h3dgram::put_head(glue, from, stream);
        c.dirty = true;
        match c.q.dgram_send(&glue[at..end]) {
            Ok(()) => true,
            Err(quiche::Error::Done) => {
                self.n.full += 1;
                false
            }
            Err(_) => {
                self.n.too_big += 1;
                false
            }
        }
    }

    /// The most frames one datagram of ci holds for `stream` now (QUIC's
    /// DATAGRAM frame on the connection's path, less the head).
    pub fn room(&self, ci: usize, stream: u64) -> usize {
        self.conns[ci]
            .as_ref()
            .and_then(|c| c.q.dgram_max_writable_len())
            .map_or(0, |n| n.saturating_sub(h3dgram::head_len(stream)))
    }

    /// The exit closes connection ci (its member died).
    pub fn close(&mut self, ci: usize) {
        if let Some(c) = self.conns[ci].as_mut() {
            let _ = c.q.close(true, H3_NO_ERROR, b"");
            c.dirty = true;
        }
    }

    /// QUIC's timers that are due fire; returns when the next one is.
    pub fn timers(&mut self, now: u64) -> u64 {
        let mut next = u64::MAX;
        for c in self.conns.iter_mut().flatten() {
            if c.due != 0 && c.due <= now {
                c.q.on_timeout();
                c.dirty = true;
                c.due = 0;
            }
            if c.due != 0 {
                next = next.min(c.due);
            }
        }
        next
    }

    /// Every packet the touched connections have to send, in sendmmsg
    /// batches; each one's next timer.
    pub fn flush(&mut self, now: u64) {
        for ci in 0..self.conns.len() {
            let Some(c) = self.conns[ci].as_mut() else { continue };
            if !c.dirty {
                continue;
            }
            c.dirty = false;
            loop {
                if self.out_n == BATCH {
                    self.send_out();
                }
                let slot = &mut self.out[self.out_n * PKT..(self.out_n + 1) * PKT];
                let c = self.conns[ci].as_mut().expect("a connection");
                let Ok((n, info)) = c.q.send(slot) else { break };
                let SocketAddr::V4(to) = info.to else { continue };
                self.send.push(slot.as_ptr(), n, Some(&sys::sockaddr(to)));
                self.out_n += 1;
            }
            let c = self.conns[ci].as_mut().expect("a connection");
            c.due = c.q.timeout().map_or(0, |d| now + d.as_nanos() as u64);
        }
        self.send_out();
    }

    fn send_out(&mut self) {
        if self.out_n > 0 {
            self.send.flush(self.sock.as_raw_fd());
            self.out_n = 0;
        }
    }

    /// One packet QUIC makes outside a connection (version negotiation).
    fn queue_raw(&mut self, to: &sockaddr_in, put: impl FnOnce(&mut [u8]) -> Option<usize>) {
        if self.out_n == BATCH {
            self.send_out();
        }
        let slot = &mut self.out[self.out_n * PKT..(self.out_n + 1) * PKT];
        if let Some(n) = put(slot) {
            self.send.push(slot.as_ptr(), n, Some(to));
            self.out_n += 1;
        }
    }

    /// Closed connections are forgotten; their members (peer slot and gen)
    /// go into `gone` for the exit to drop.
    pub fn reap(&mut self, gone: &mut Vec<(usize, u32)>) {
        for ci in 0..self.conns.len() {
            if !self.conns[ci].as_ref().is_some_and(|c| c.q.is_closed()) {
                continue;
            }
            let c = self.conns[ci].take().expect("a connection");
            for k in c.keys {
                if self.by_cid.get(&k) == Some(&ci) {
                    self.by_cid.remove(&k);
                }
            }
            gone.extend(c.members.iter().map(|m| (m.1, m.2)));
            self.free.push(ci);
        }
    }

    /// Connections open now.
    pub fn open(&self) -> usize {
        self.conns.iter().flatten().count()
    }
}

/// Whether a request is a CONNECT-UDP (RFC 9298) with a known token
/// (spec/trunk.md, `h3dgram`).
fn request_is_member(list: &[h3::Header], tokens: &[[u8; TOKEN]]) -> bool {
    use h3::NameValue;
    let get = |name: &[u8]| list.iter().find(|h| h.name() == name).map(|h| h.value());
    get(b":method") == Some(b"CONNECT")
        && get(b":protocol") == Some(b"connect-udp")
        && get(b":path").is_some_and(h3dgram::connect_udp_path)
        && get(b"proxy-authorization").and_then(h3dgram::read_authorization).is_some_and(|t| h3dgram::known(tokens, &t))
}

/// A packet's destination connection id, from its header: a long header
/// says its length, a short one is the exit's own, CID long.
fn dcid(d: &[u8]) -> Option<&[u8]> {
    let first = *d.first()?;
    if first & 0x80 != 0 {
        let n = *d.get(5)? as usize;
        d.get(6..6 + n)
    } else {
        d.get(1..1 + CID)
    }
}

fn addr_of(s: &sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(u32::from_be(s.sin_addr.s_addr).into(), u16::from_be(s.sin_port))
}
