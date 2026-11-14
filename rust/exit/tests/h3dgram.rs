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
