//! One member's CONNECT tunnel: the state cronet's network thread and the
//! pipe's loop share, the stream's callbacks, and the loop's side (read,
//! write) in the shape of a non-blocking socket (hikkari_sys::Io). The Go
//! reference is cronet-go bidirectional_conn.go and naive_conn.go under
//! trunk/chromium Dial.
//!
//! Who owns a buffer: rx is cronet's while a read is outstanding and the
//! loop's once `rx_len` says how much came; tx is the loop's until it hands
//! it to a write and cronet's until `tx_busy` clears. Each hand-over is one
//! atomic store with Release and a load with Acquire on the other side.

use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::io;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU8, AtomicUsize, Ordering::*};
use std::sync::Arc;

use hikkari_sys::{self as sys, Io, Wake};
use hikkari_trunk::naive::{self, Pad, Unpad, PADDED};

use crate::api::{self, Stream};
use crate::keeper::{self, Job};

/// Where and as whom members go: the exit's relay.
pub struct Form {
    /// The relay's address.
    pub exit: SocketAddrV4,
    /// The relay's domain: Chromium checks the certificate against it.
    pub sni: String,
    /// The trunk key the relay admits.
    pub key: String,
    /// PEM roots that replace the system's trust (tests); None is the
    /// system's.
    pub roots: Option<String>,
}

impl Form {
    /// A form whose domain and key are what the CONNECT may carry.
    pub fn new(exit: SocketAddrV4, sni: &str, key: &str, roots: Option<String>) -> Result<Form, String> {
        if sni.is_empty() || !sni.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return Err(format!("cronet: {sni:?} is not a domain"));
        }
        if key.len() < 24 || key.bytes().any(|b| !b.is_ascii_graphic() || b == b':' || b == b',') {
            return Err("cronet: a trunk key is 24+ printable characters without ':' or ','".into());
        }
        Ok(Form { exit, sni: sni.into(), key: key.into(), roots })
    }
}

/// Bytes cronet reads into at once; what a padded write may carry.
const RX: usize = 128 << 10;
const TX: usize = 64 << 10;

pub(crate) const OPENING: u8 = 0;
pub(crate) const UP: u8 = 1;
pub(crate) const FAILED: u8 = 2;

/// What cronet's network thread, the keeper and the loop share.
pub(crate) struct Shared {
    pub wake: Wake,
    pub form: Arc<Form>,
    /// The exit's address as cronet names it to the dialer.
    pub exit_ip: CString,
    /// The local port the member's socket comes from (0: the kernel's).
    pub from: u16,
    pub headers: Vec<(CString, CString)>,
    pub url: CString,
    /// OPENING, UP (the relay answered 200), FAILED.
    pub stage: AtomicU8,
    /// No callback comes again (succeeded, failed or canceled).
    pub over: AtomicBool,
    /// The relay ended its side.
    pub eof: AtomicBool,
    /// The dial got no answer within its time (trunk ErrSilent).
    pub silent: AtomicBool,
    /// The net error cronet failed with, or the relay's status as -status.
    pub why: AtomicI32,
    pub stream: AtomicPtr<Stream>,
    pub engine: AtomicPtr<std::ffi::c_void>,
    rx: UnsafeCell<Box<[u8]>>,
    /// Bytes cronet read into rx and the loop has not taken (0: none, or a
    /// read is outstanding).
    rx_len: AtomicUsize,
    tx: UnsafeCell<Box<[u8]>>,
    tx_busy: AtomicBool,
}

// SAFETY: rx and tx are touched by one side at a time, handed over by the
// atomics as the module's comment says; everything else is atomic or read
// only after the Arc is made.
unsafe impl Sync for Shared {}
unsafe impl Send for Shared {}

impl Shared {
    fn fail(&self, why: i32) {
        self.why.store(why, Relaxed);
        self.stage.store(FAILED, Release);
        self.wake.ring();
    }

    /// Asks cronet to read into rx (the loop or the network thread, rx
    /// being nobody's).
    fn read_more(&self) {
        let (Some(a), s) = (api::api(), self.stream.load(Acquire)) else { return };
        // SAFETY: the stream lives until the keeper destroys it, which is
        // after the Conn is dropped; rx is cronet's until rx_len is stored.
        unsafe {
            let rx = &mut *self.rx.get();
            (a.stream_read)(s, rx.as_mut_ptr() as *mut c_char, RX as c_int);
        }
    }
}

/// A member's tunnel, the loop's side: polled by `fd`, read and written
/// like a non-blocking socket. Dropping it closes the tunnel and its engine
/// (on the keeper's thread).
pub struct Conn {
    sh: Arc<Shared>,
    pad: Pad,
    unpad: Unpad,
    /// Of rx: bytes the loop holds, and how far it has taken them.
    rx_have: usize,
    rx_at: usize,
    /// The padding of the first writes, drawn at open.
    pads: [u8; PADDED as usize],
}

impl Conn {
    /// Begins a member: an engine and its CONNECT to the exit, its socket
    /// from local port `from`. It returns at once; the tunnel is up when
    /// writes are taken, and failed when a read says Gone.
    pub fn open(form: &Arc<Form>, from: u16) -> io::Result<Conn> {
        if api::api().is_none() {
            return Err(io::Error::other("cronet: libcronet is not loaded"));
        }
        let mut rnd = [0u8; 9 + PADDED as usize];
        sys::urandom(&mut rnd);
        let cs = |s: &str| CString::new(s).expect("checked by Form::new");
        let headers = vec![
            (cs("-connect-authority"), cs(naive::HOST)),
            (cs("padding"), cs(&naive::padding_header(rnd[..9].try_into().expect("9 bytes")))),
            (cs("proxy-authorization"), cs(&naive::proxy_authorization(&form.key))),
        ];
        let sh = Arc::new(Shared {
            wake: Wake::new()?,
            form: form.clone(),
            exit_ip: cs(&form.exit.ip().to_string()),
            from,
            headers,
            url: cs(&format!("https://{}:{}", form.sni, form.exit.port())),
            stage: AtomicU8::new(OPENING),
            over: AtomicBool::new(false),
            eof: AtomicBool::new(false),
            silent: AtomicBool::new(false),
            why: AtomicI32::new(0),
            stream: AtomicPtr::new(std::ptr::null_mut()),
            engine: AtomicPtr::new(std::ptr::null_mut()),
            rx: UnsafeCell::new(vec![0; RX].into_boxed_slice()),
            rx_len: AtomicUsize::new(0),
            tx: UnsafeCell::new(vec![0; TX + naive::HEAD + naive::TAIL].into_boxed_slice()),
            tx_busy: AtomicBool::new(false),
        });
        keeper::send(Job::Open(sh.clone()));
        let pads = rnd[9..].try_into().expect("PADDED bytes");
        Ok(Conn { sh, pad: Pad::default(), unpad: Unpad::default(), rx_have: 0, rx_at: 0, pads })
    }

    /// The descriptor to poll for reading: readable when cronet read
    /// something, finished a write, or the tunnel came up or failed.
    pub fn fd(&self) -> i32 {
        self.sh.wake.fd()
    }

    /// Whether the dial got no answer (the port it came from is suspect).
    pub fn silent(&self) -> bool {
        self.sh.silent.load(Relaxed)
    }

    /// Why it failed: a negative net error of Chromium's, or the relay's
    /// HTTP status (a positive number) when it was not 200.
    pub fn why(&self) -> i32 {
        self.sh.why.load(Relaxed)
    }

    /// The relay's bytes, without the padding of its first writes.
    pub fn read(&mut self, buf: &mut [u8]) -> Io {
        self.sh.wake.clear();
        let mut n = 0;
        while n < buf.len() {
            if self.rx_have == 0 {
                self.rx_have = self.sh.rx_len.load(Acquire);
                self.rx_at = 0;
                if self.rx_have == 0 {
                    break;
                }
            }
            // SAFETY: rx is the loop's while rx_len is not 0.
            let rx = unsafe { &*self.sh.rx.get() };
            let (took, gave) = self.unpad.take(&rx[self.rx_at..self.rx_have], &mut buf[n..]);
            self.rx_at += took;
            n += gave;
            if self.rx_at == self.rx_have {
                self.rx_have = 0;
                self.sh.rx_len.store(0, Release);
                self.sh.read_more();
                break;
            }
        }
        if n > 0 {
            return Io::Done(n);
        }
        match self.sh.stage.load(Acquire) {
            FAILED => Io::Gone,
            _ if self.sh.eof.load(Acquire) => Io::Eof,
            _ if self.sh.over.load(Acquire) => Io::Gone,
            _ => Io::Again,
        }
    }

    /// Hands as much of buf as one write takes to cronet: Again while the
    /// tunnel is not up or the last write is not done.
    pub fn write(&mut self, buf: &[u8]) -> Io {
        match self.sh.stage.load(Acquire) {
            FAILED => return Io::Gone,
            OPENING => return Io::Again,
            _ => {}
        }
        if self.sh.over.load(Acquire) {
            return Io::Gone;
        }
        if buf.is_empty() || self.sh.tx_busy.load(Acquire) {
            return Io::Again;
        }
        let (Some(a), s) = (api::api(), self.sh.stream.load(Acquire)) else { return Io::Gone };
        // SAFETY: tx is the loop's while tx_busy is false.
        let tx = unsafe { &mut *self.sh.tx.get() };
        let pad = self.pads.get(self.pad.written() as usize).copied().unwrap_or(0);
        let (took, len) = self.pad.put(&buf[..buf.len().min(TX)], tx, pad);
        self.sh.tx_busy.store(true, Release);
        // SAFETY: the stream lives until the keeper destroys it, after this
        // Conn is dropped; tx stays put until on_write_completed.
        unsafe { (a.stream_write)(s, tx.as_ptr() as *const c_char, len as c_int, false) };
        Io::Done(took)
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        keeper::send(Job::Close(self.sh.clone()));
    }
}

/// The member's state behind a stream's annotation.
///
/// SAFETY (callers): the annotation is the Arc<Shared>'s pointer, alive
/// until the keeper has destroyed the stream and shut the engine down.
unsafe fn shared<'a>(s: *mut Stream) -> &'a Shared {
    &*((*s).annotation as *const Shared)
}

pub(crate) static CALLBACKS: api::Callbacks = api::Callbacks {
    on_stream_ready: Some(on_ready),
    on_response_headers_received: Some(on_headers),
    on_read_completed: Some(on_read),
    on_write_completed: Some(on_written),
    on_response_trailers_received: Some(on_trailers),
    on_succeded: Some(on_succeeded),
    on_failed: Some(on_failed),
    on_canceled: Some(on_canceled),
};

unsafe extern "C" fn on_ready(_: *mut Stream) {}

/// The relay's answer: 200 opens the tunnel (cronet-go naiveConn.Handshake)
/// and the first read is asked for; anything else is the relay's site.
unsafe extern "C" fn on_headers(s: *mut Stream, h: *const api::Headers, _: *const c_char) {
    let sh = shared(s);
    let mut status = 0;
    if !h.is_null() {
        let h = &*h;
        for i in 0..h.count {
            let e = &*h.headers.add(i);
            if !e.key.is_null() && CStr::from_ptr(e.key).to_bytes() == b":status" && !e.value.is_null() {
                status = CStr::from_ptr(e.value).to_str().ok().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
        }
    }
    if status != 200 {
        sh.fail(status);
        return;
    }
    sh.stage.store(UP, Release);
    sh.read_more();
    sh.wake.ring();
}

unsafe extern "C" fn on_read(s: *mut Stream, _: *mut c_char, n: c_int) {
    let sh = shared(s);
    if n > 0 {
        sh.rx_len.store(n as usize, Release);
    } else {
        sh.eof.store(true, Release);
    }
    sh.wake.ring();
}

unsafe extern "C" fn on_written(s: *mut Stream, _: *const c_char) {
    let sh = shared(s);
    sh.tx_busy.store(false, Release);
    sh.wake.ring();
}

unsafe extern "C" fn on_trailers(_: *mut Stream, _: *const api::Headers) {}

unsafe extern "C" fn on_succeeded(s: *mut Stream) {
    let sh = shared(s);
    sh.eof.store(true, Release);
    sh.over.store(true, Release);
    sh.wake.ring();
}

unsafe extern "C" fn on_failed(s: *mut Stream, err: c_int) {
    let sh = shared(s);
    sh.over.store(true, Release);
    sh.fail(err);
}

unsafe extern "C" fn on_canceled(s: *mut Stream) {
    let sh = shared(s);
    sh.over.store(true, Release);
    sh.wake.ring();
}
