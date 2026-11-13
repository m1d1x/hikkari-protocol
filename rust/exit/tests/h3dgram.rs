//! The exit's Chromium QUIC wire (spec/trunk.md, `h3dgram`) against a QUIC
//! client of its own (quiche), the bench's hk-exit run as a process: a
//! CONNECT-UDP with the trunk key's token is a member that says its hello
//! and hears the trunk's call back; one with another token is answered 404
//! and carries nothing. Chromium's own client is checked by
//! bench/h3dgram.sh (it needs the patched libcronet).
#![cfg(target_os = "linux")]

use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use hikkari_trunk::flow::ECHO_PORT;
use hikkari_trunk::frame::{self, Frame, F_PONG};
use hikkari_trunk::h3dgram;
use quiche::h3::{self, NameValue};

const KEY: &str = "bench-trunk-key-0123456789abcdef";
const WIRE: u8 = 6;

struct ExitProc(Child);

impl Drop for ExitProc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// hk-exit with its UDP wire and the QUIC wire on free loopback ports.
fn exit() -> (ExitProc, SocketAddr) {
    let free = |s: UdpSocket| s.local_addr().unwrap();
    let udp = free(UdpSocket::bind("127.0.0.1:0").unwrap());
    let quic = free(UdpSocket::bind("127.0.0.1:0").unwrap());
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
    let child = Command::new(env!("CARGO_BIN_EXE_hk-exit"))
        .args(["--listen", &udp.to_string(), "--key", KEY, "--h3", &quic.to_string(), "--h3-wire-id", &WIRE.to_string()])
        .args(["--cert", &format!("{data}/h3dgram-cert.pem"), "--cert-key", &format!("{data}/h3dgram-key.pem")])
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("hk-exit");
    std::thread::sleep(Duration::from_millis(300));
    (ExitProc(child), quic)
}

/// A client of the wire: one QUIC connection and its HTTP/3.
struct Client {
    sock: UdpSocket,
    q: quiche::Connection,
    h3: Option<h3::Connection>,
    buf: Vec<u8>,
}

impl Client {
    fn connect(to: SocketAddr) -> Client {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let mut c = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        c.verify_peer(false);
        c.set_application_protos(h3::APPLICATION_PROTOCOL).unwrap();
        c.set_max_idle_timeout(30_000);
        c.set_initial_max_data(10 << 20);
        c.set_initial_max_stream_data_bidi_local(1 << 20);
        c.set_initial_max_stream_data_bidi_remote(1 << 20);
        c.set_initial_max_stream_data_uni(1 << 20);
        c.set_initial_max_streams_bidi(100);
        c.set_initial_max_streams_uni(100);
        c.enable_dgram(true, 1024, 1024);
        let scid = [7u8; 16];
        let local = sock.local_addr().unwrap();
        let q = quiche::connect(Some("hk.example"), &quiche::ConnectionId::from_ref(&scid), local, to, &mut c).unwrap();
        let mut cl = Client { sock, q, h3: None, buf: vec![0; 2048] };
        let until = Instant::now() + Duration::from_secs(5);
        while !cl.q.is_established() {
            assert!(Instant::now() < until, "no handshake in 5 s");
            cl.turn();
        }
        let mut hc = h3::Config::new().unwrap();
        hc.enable_extended_connect(true);
        cl.h3 = Some(h3::Connection::with_transport(&mut cl.q, &hc).unwrap());
        cl
    }

    /// Sends what QUIC has, reads what came in 5 ms.
    fn turn(&mut self) {
        let mut out = [0u8; 1500];
        while let Ok((n, info)) = self.q.send(&mut out) {
            self.sock.send_to(&out[..n], info.to).unwrap();
        }
        let local = self.sock.local_addr().unwrap();
        while let Ok((n, from)) = self.sock.recv_from(&mut self.buf) {
            let _ = self.q.recv(&mut self.buf[..n], quiche::RecvInfo { from, to: local });
        }
        if self.q.timeout() == Some(Duration::ZERO) {
            self.q.on_timeout();
        }
    }

    /// A CONNECT-UDP with this authorization: its stream and the status
    /// the exit answered.
    fn connect_udp(&mut self, auth: &str) -> (u64, Vec<u8>) {
        let req = [
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":protocol", b"connect-udp"),
            h3::Header::new(b":scheme", b"https"),
            h3::Header::new(b":authority", b"hk.example:443"),
            h3::Header::new(b":path", b"/.well-known/masque/udp/trunk.hikkari.arpa/443/"),
            h3::Header::new(b"capsule-protocol", b"?1"),
            h3::Header::new(b"proxy-authorization", auth.as_bytes()),
        ];
        let until = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            self.turn();
            // The exit's SETTINGS (extended CONNECT) first.
            if let Ok(s) = self.h3.as_mut().unwrap().send_request(&mut self.q, &req, false) {
                break s;
            }
            assert!(Instant::now() < until, "the request did not go");
        };
        loop {
            assert!(Instant::now() < until, "no answer to the request in 5 s");
            self.turn();
            while let Ok((s, ev)) = self.h3.as_mut().unwrap().poll(&mut self.q) {
                if let (true, h3::Event::Headers { list, .. }) = (s == stream, ev) {
                    let status = list.iter().find(|h| h.name() == b":status").unwrap().value().to_vec();
                    return (stream, status);
                }
            }
        }
    }

    /// The frames of one write as an HTTP Datagram of `stream`.
    fn send(&mut self, stream: u64, frames: &[u8]) {
        let mut d = vec![0u8; h3dgram::HEAD_MAX + frames.len()];
        let at = h3dgram::put_head(&mut d, h3dgram::HEAD_MAX, stream);
        d[h3dgram::HEAD_MAX..].copy_from_slice(frames);
        self.q.dgram_send(&d[at..]).unwrap();
    }

    /// The frames of every datagram in, after their head; the exit's pings
    /// answered.
    fn recv(&mut self, stream: u64) -> Vec<Vec<u8>> {
        self.turn();
        let mut got = Vec::new();
        let mut d = [0u8; 1500];
        while let Ok(n) = self.q.dgram_recv(&mut d) {
            let (s, at) = h3dgram::read_head(&d[..n]).unwrap();
            assert_eq!(s, stream, "a datagram of another request");
            got.push(d[at..n].to_vec());
        }
        for g in &got {
            let mut at = 0;
            while let Some((f, next)) = frame::next_frame(g, at) {
                if let Frame::Ping(t) = f {
                    let mut b = [0u8; 9];
                    frame::put_ping(&mut b, F_PONG, t);
                    self.send(stream, &b);
                }
                at = next;
            }
        }
        got
    }
}

fn has(got: &[Vec<u8>], want: impl Fn(&Frame, &[u8]) -> bool) -> bool {
    got.iter().any(|g| {
        let mut at = 0;
        while let Some((f, next)) = frame::next_frame(g, at) {
            if want(&f, g) {
                return true;
            }
            at = next;
        }
        false
    })
}

#[test]
fn a_connect_udp_with_the_token_is_a_member_that_hears_the_call() {
    let (_x, at) = exit();
    let mut c = Client::connect(at);
    let auth = h3dgram::authorization(&h3dgram::token(KEY));
    let (stream, status) = c.connect_udp(&auth);
    assert_eq!(status, b"200");

    let session = [9u8; 16];
    let mut b = [0u8; 64];
    let n = frame::hello_t2(&mut b, &session, WIRE);
    c.send(stream, &b[..n]);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < until, "no answer to the hello");
        if has(&c.recv(stream), |f, _| matches!(f, Frame::Hello)) {
            break;
        }
    }

    let mut back = 0;
    for seq in 1..=50u32 {
        let payload = seq.to_be_bytes();
        let mut b = [0u8; 64];
        let n = frame::put_dgram(&mut b, 1, seq, ECHO_PORT, &payload);
        c.send(stream, &b[..n]);
        std::thread::sleep(Duration::from_millis(2));
        let got = c.recv(stream);
        back += got
            .iter()
            .filter(|g| has(std::slice::from_ref(g), |f, g| matches!(f, Frame::Dgram { port: ECHO_PORT, off, len: 4, .. } if g[*off..*off + 4] == payload)))
            .count();
    }
    let until = Instant::now() + Duration::from_secs(1);
    while back < 50 && Instant::now() < until {
        let got = c.recv(stream);
        back += got.iter().filter(|g| has(std::slice::from_ref(g), |f, _| matches!(f, Frame::Dgram { port: ECHO_PORT, .. }))).count();
    }
    assert!(back >= 50, "the call came back {back} of 50 times");
}

#[test]
fn a_connect_udp_with_another_token_is_answered_as_a_site_would() {
    let (_x, at) = exit();
    let mut c = Client::connect(at);
    let (_, status) = c.connect_udp(&h3dgram::authorization(&h3dgram::token("another trunk key")));
    assert_eq!(status, b"404");
}
