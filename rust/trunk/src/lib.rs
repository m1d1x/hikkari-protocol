//! The trunk's protocol (spec/trunk.md) in Rust: what the cascade entry's
//! pipe speaks to the exit, and what the messenger's own trunk will speak.
//! No sockets, no clock, no threads: every call takes its buffer and `now`,
//! so any loop can carry it and tests run it on a clock of their own. The
//! Go package trunk is the reference: a change here is a change of the spec
//! first, and a test against the Go side.

pub mod buf;
pub mod flow;
pub mod frame;
pub mod health;
pub mod stream;
pub mod udpwire;
