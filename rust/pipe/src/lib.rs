//! The cascade entry's pipe (README.md): everything the entry does with each
//! packet, run by the Go brain (trunk/pipectl) over a local socket. The
//! trunk's protocol is hikkari_trunk, the syscalls hikkari_sys; here is only
//! what makes it the entry: client ports, flows, wires, routes, the loop.
//!
//! - ctl: the brain ↔ pipe messages
//! - flow: flows by stream id, client address and the brain's tag
//! - member: wires and their members, each member's glue and seal
//! - link: stream members, each over a TCP connection of its own
//! - streams: clients' TCP connections as streams to the exit
//! - carry: which wire and member carry a flow's datagram
//! - handoff: the messages between an old generation of the pipe and a new one
//! - pipe: the loop (brain, timers, data)

pub mod ctl;
pub mod handoff;
#[cfg(target_os = "linux")]
mod carry;
#[cfg(target_os = "linux")]
mod flow;
#[cfg(target_os = "linux")]
mod link;
#[cfg(target_os = "linux")]
mod member;
#[cfg(target_os = "linux")]
pub mod pipe;
#[cfg(target_os = "linux")]
mod streams;
