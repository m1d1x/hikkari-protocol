//! A trunk pool member over Chromium's network stack (spec/trunk.md,
//! "Member"): TLS, HTTP/2 and the CONNECT of the Hikkari client's own cronet
//! build, so what crosses the border is Chromium's ClientHello, not an
//! imitation. The Go reference is trunk/chromium (the Go entry's pool).
//!
//! As there: one Chromium engine per member, so a member is one TCP
//! connection the trunk can account for; the engine takes its socket from
//! this crate's dialer, to the exit only, from the port the pool chose.
//!
//! The pipe's loop never waits on the library: a member's bytes cross in
//! two buffers (one read and one write outstanding, as the stream API
//! allows), cronet's network thread rings the member's wake-up when either
//! is done, and the loop polls it like a socket. Engines are started and
//! shut down on a thread of their own (keeper), since both block.
//!
//! libcronet is loaded at run time (`load`), as the Go entry does on Linux.
#![cfg(target_os = "linux")]

mod api;
mod conn;
mod keeper;

pub use api::load;
pub use conn::{Conn, Form};
pub use keeper::version;
