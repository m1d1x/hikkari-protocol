//! A wake-up a thread outside the loop rings and the loop polls: an eventfd.
//! The callbacks of a library thread (cronet's network thread) ring it, the
//! pipe's loop sees it readable and clears it.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub struct Wake(OwnedFd);

impl Wake {
    pub fn new() -> io::Result<Wake> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Wake(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// The descriptor to poll for reading.
    pub fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }

    /// Rings it, from any thread: it stays readable until cleared.
    pub fn ring(&self) {
        let one: u64 = 1;
        unsafe { libc::write(self.0.as_raw_fd(), &one as *const u64 as *const _, 8) };
    }

    /// Clears it: rings after this make it readable again.
    pub fn clear(&self) {
        let mut v: u64 = 0;
        unsafe { libc::read(self.0.as_raw_fd(), &mut v as *mut u64 as *mut _, 8) };
    }
}
