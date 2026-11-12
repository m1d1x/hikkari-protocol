//! The cascade entry's pipe, prototype (README.md): the trunk's frames and
//! the bare UDP wire's seal, batched UDP on Linux.

pub mod health;
pub mod wire;
#[cfg(target_os = "linux")]
pub mod ctl;
#[cfg(target_os = "linux")]
pub mod pipe;
#[cfg(target_os = "linux")]
pub mod sys;
