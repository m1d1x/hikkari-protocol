//! The exit's Chromium QUIC wire (spec/trunk.md, `h3dgram`) against a QUIC
//! client of its own (quiche), the bench's hk-exit run as a process: a
//! CONNECT-UDP with the trunk key's token is a member that says its hello
//! and hears the trunk's call back; one with another token is answered 404
//! and carries nothing. Chromium's own client is checked by
//! bench/h3dgram.sh (it needs the patched libcronet).
#![cfg(target_os = "linux")]

mod common;

use std::time::{Duration, Instant};

use common::{exit, has, Client, KEY, WIRE};
use hikkari_trunk::flow::ECHO_PORT;
use hikkari_trunk::frame::{self, Frame};
use hikkari_trunk::h3dgram;

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

/// Datagrams of a client's QUIC size over a member (spec/trunk.md, `h3dgram`:
/// a frame over the room is cut): the entry cuts each call datagram of 1200,
/// 1250, 1350 and 1500 B into pieces that fit its 1194 B, the exit puts them
/// together and answers on the call's port; the answer, over what the
/// exit's datagram holds, comes down cut and is put together whole, byte for
/// byte. The member lives on: a small datagram after them comes back too.
#[test]
fn a_datagram_over_the_room_goes_cut_both_ways_and_comes_back_whole() {
    use hikkari_trunk::frag::{self, Reasm};

    let (_x, at) = exit();
    let mut c = Client::connect(at);
    let (stream, status) = c.connect_udp(&h3dgram::authorization(&h3dgram::token(KEY)));
    assert_eq!(status, b"200");
    let mut b = [0u8; 64];
    let n = frame::hello_t2(&mut b, &[3u8; 16], WIRE);
    c.send(stream, &b[..n]);
    let until = Instant::now() + Duration::from_secs(5);
    while !has(&c.recv(stream), |f, _| matches!(f, Frame::Hello)) {
        assert!(Instant::now() < until, "no answer to the hello");
    }

    let sizes = [1200usize, 1250, 1350, 1500];
    let mut want: Vec<Vec<u8>> = Vec::new();
    for (k, &size) in sizes.iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|i| (i * 13 + k) as u8).collect();
        let mut whole = vec![0u8; frame::DGRAM_HEAD + size];
        frame::put_dgram(&mut whole, 1, k as u32 + 1, ECHO_PORT, &payload);
        let (count, piece) = frag::cut(whole.len(), 1194).expect("a cut");
        for (i, p) in whole.chunks(piece).enumerate() {
            let mut d = vec![0u8; frag::HEAD + p.len()];
            frag::put_piece(&mut d, k as u16, i as u8, count as u8, p);
            assert!(d.len() <= 1194);
            c.send(stream, &d);
        }
        want.push(payload);
    }
    let n = frame::put_dgram(&mut b, 1, 99, ECHO_PORT, b"small");
    c.send(stream, &b[..n]);
    want.push(b"small".to_vec());

    let mut r = Reasm::new();
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut pieces = 0;
    let until = Instant::now() + Duration::from_secs(3);
    while got.len() < want.len() && Instant::now() < until {
        for g in c.recv(stream) {
            let mut at = 0;
            while let Some((f, next)) = frame::next_frame(&g, at) {
                match f {
                    Frame::Dgram { port: ECHO_PORT, off, len, .. } => got.push(g[off..off + len].to_vec()),
                    Frame::Frag { id, index, count, off, len } => {
                        pieces += 1;
                        if let Some(w) = r.piece(0, id, index, count, &g[off..off + len]) {
                            match frame::next_frame(w, 0) {
                                Some((Frame::Dgram { off, len, .. }, end)) if end == w.len() => got.push(w[off..off + len].to_vec()),
                                _ => panic!("a whole frame is one dgram"),
                            }
                        }
                        r.release();
                    }
                    _ => {}
                }
                at = next;
            }
        }
    }
    got.sort();
    want.sort();
    assert_eq!(got.len(), want.len(), "came back {} of {}", got.len(), want.len());
    assert!(got == want, "a datagram came back changed");
    // The exit's room is QUIC's on this path (quiche to quiche, wider than
    // Chromium's 1194): the 1500 B answer at least comes down cut.
    assert!(pieces >= 2, "the answers came down cut ({pieces} pieces)");
    assert_eq!(r.n.lost, 0);
}
