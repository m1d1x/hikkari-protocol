//! A wire's Chromium engine: one engine and one network thread for all its
//! members, as cronet-go NaiveClient runs with `concurrency` on a single
//! engine. Each member's CONNECT carries a network isolation key of its own
//! (`-network-isolation-key`, NaiveClient.DialEarly), so Chromium gives it a
//! TCP connection and an HTTP/2 session of its own and never pools two
//! members on one, nor resumes one member's TLS session in another's hello.
//!
//! The member's socket is the pipe's: the loop connects it from the member's
//! port without waiting (hikkari_sys::member_connect) and hands it over once
//! it is up. The engine's dialer only takes that socket from the hand-over
//! slot; the keeper starts one member's stream at a time and waits until the
//! dialer has taken its socket, so a socket always goes to the stream it was
//! connected for. A dial the slot has nothing for is refused: Chromium opens
//! no connection of its own.

use std::ffi::{c_char, c_void, CStr, CString};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering::*};
use std::sync::{Arc, Condvar, Mutex};

use hikkari_sys as sys;

use crate::api::Ptr;
use crate::conn::Form;
use crate::keeper::{self, Job};

// Chromium's net error the dialer answers with (net/base/net_error_list.h).
const ERR_CONNECTION_FAILED: isize = -104;

/// What the keeper, the engine's dialer and the members of one wire share.
pub(crate) struct Hub {
    pub form: Arc<Form>,
    /// The exit's address as cronet names it to the dialer.
    pub exit_ip: CString,
    /// The engine once the keeper started it (null before, and after a start
    /// that failed).
    pub engine: AtomicPtr<c_void>,
    /// The socket of the member whose stream is starting, until the dialer
    /// takes it.
    pub slot: Mutex<Option<OwnedFd>>,
    pub taken: Condvar,
    /// Numbers the members' isolation keys.
    keys: AtomicU64,
}

impl Hub {
    /// The next member's isolation key: a name no other member of the
    /// engine has had (it never goes on the wire).
    pub fn next_key(&self) -> CString {
        let n = self.keys.fetch_add(1, Relaxed);
        CString::new(format!("https://member-{n}:443")).expect("digits have no NUL")
    }
}

/// A wire's engine, the pipe's handle on it. Clones are the same engine;
/// it is shut down (on the keeper's thread) once the last handle and the
/// last member are gone.
pub struct Engine(Option<Arc<Hub>>);

impl Engine {
    /// An engine to `form`'s exit, started with its first member.
    pub fn new(form: Form) -> Engine {
        let exit_ip = CString::new(form.exit.ip().to_string()).expect("an address has no NUL");
        Engine(Some(Arc::new(Hub {
            form: Arc::new(form),
            exit_ip,
            engine: AtomicPtr::new(std::ptr::null_mut()),
            slot: Mutex::new(None),
            taken: Condvar::new(),
            keys: AtomicU64::new(0),
        })))
    }

    /// Where its members go.
    pub fn form(&self) -> &Form {
        &self.hub().form
    }

    pub(crate) fn hub(&self) -> &Arc<Hub> {
        self.0.as_ref().expect("a live handle")
    }
}

impl Clone for Engine {
    fn clone(&self) -> Engine {
        Engine(Some(self.hub().clone()))
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            keeper::send(Job::Release(h));
        }
    }
}

/// Cronet's dialer: the starting member's socket from the slot, if the
/// engine asks for the exit. Anything else (a DNS server, another address,
/// a second connection) is refused, as trunk/chromium portDialer refuses it.
///
/// SAFETY (cronet): ctx is the Hub the keeper keeps alive until the engine
/// is shut down; address is a C string or null.
pub(crate) unsafe extern "C" fn dial(ctx: Ptr, address: *const c_char, port: u16) -> isize {
    let hub = &*(ctx as *const Hub);
    if address.is_null() || CStr::from_ptr(address) != hub.exit_ip.as_c_str() || port != hub.form.exit.port() {
        return ERR_CONNECTION_FAILED;
    }
    let fd = hub.slot.lock().expect("the slot's lock").take();
    hub.taken.notify_all();
    match fd {
        Some(fd) => sys::into_raw(fd) as isize,
        None => ERR_CONNECTION_FAILED,
    }
}
