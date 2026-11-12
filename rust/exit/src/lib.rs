//! The cascade exit's pipe (README.md, «The exit»): everything the exit does
//! with each packet of the entry's packet members, run by the Go brain
//! (trunk/pipectl) over a local socket, as the entry's pipe is. The trunk's
//! protocol is hikkari_trunk, the syscalls hikkari_sys; here is only what
//! makes it the exit: the wire's peers and their sessions, flows to the
//! loopback services, answers glued down for a tick.
//!
//! - ctl: the brain ↔ exit messages
//! - peer: a wire's socket and the entry's members on it, each member's glue
//! - session: sessions by the entry's session id, each with its members
//! - flow: flows by stream id, which members carry an answer
//! - link: the entry's stream members, each on a TCP connection
//! - streams: streams to the loopback services, and what came before an open
//! - exit: the loop (wire, relay, tcp, death, timers, brain)

pub mod ctl;
#[cfg(target_os = "linux")]
pub mod exit;
#[cfg(target_os = "linux")]
mod flow;
#[cfg(target_os = "linux")]
mod link;
#[cfg(target_os = "linux")]
mod peer;
#[cfg(target_os = "linux")]
mod session;
#[cfg(target_os = "linux")]
mod streams;
