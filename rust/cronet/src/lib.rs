//! A trunk pool member over Chromium's network stack (spec/trunk.md,
//! "Member"): TLS, HTTP/2 and the CONNECT of the Hikkari client's own cronet
//! build, so what crosses the border is Chromium's ClientHello, not an
//! imitation. The Go reference is trunk/chromium (the Go entry's pool).
//!
//! As there, a member is one TCP connection the trunk can account for, from
//! the port the pool chose; unlike there, a wire's members share one engine
//! and its one network thread (engine.rs), each on a connection and an
//! HTTP/2 session of its own, and the socket is the pipe's, connected by
//! its loop and handed to Chromium once up.
//!
//! The pipe's loop never waits on the library: a member's bytes cross in
//! two buffers (one read and one write outstanding, as the stream API
//! allows), cronet's network thread rings the member's wake-up when either
//! is done, and the loop polls it like a socket. Engines are started and
//! shut down, and streams begun and ended, on a thread of their own
//! (keeper), since an engine's start and shutdown block.
//!
//! libcronet is loaded at run time (`load`), as the Go entry does on Linux.
#![cfg(target_os = "linux")]

mod api;
mod conn;
mod engine;
mod keeper;

pub use api::load;
pub use conn::{Conn, Form};
pub use engine::Engine;
pub use keeper::version;
