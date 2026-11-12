//! The keeper: one thread that starts members' engines and shuts them down,
//! since both block (an engine's start spins up its network thread, its
//! shutdown joins it) and the pipe's loop must not. The engine is set up as
//! cronet-go NaiveClient.startEngine sets it for the Go entry's members:
//! HTTP/2 without QUIC, its windows, its socket pools, and a dialer of ours;
//! the exit's domain is mapped to its address, so no name is ever looked up.

use std::ffi::{c_char, CStr, CString};
use std::sync::atomic::Ordering::*;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hikkari_sys::{self as sys, DialErr};

use crate::api::{self, Api, Header, Headers, Ptr};
use crate::conn::{Shared, CALLBACKS};

/// Bounds a member's TCP connect (trunk/chromium DefaultTimeout bounds TCP,
/// TLS and the CONNECT answer together; the pipe's hello wait bounds the
/// rest).
const DIAL_NS: u64 = 5_000_000_000;

/// How long a close waits for a canceled stream's last callback.
const CANCEL_WAIT: Duration = Duration::from_secs(2);

// Chromium's net errors the dialer answers with (net/base/net_error_list.h).
const ERR_CONNECTION_REFUSED: isize = -102;
const ERR_CONNECTION_FAILED: isize = -104;
const ERR_CONNECTION_TIMED_OUT: isize = -118;
const ERR_ADDRESS_IN_USE: isize = -147;

pub(crate) enum Job {
    Open(Arc<Shared>),
    Close(Arc<Shared>),
}

static KEEPER: OnceLock<Sender<Job>> = OnceLock::new();

pub(crate) fn send(job: Job) {
    let tx = KEEPER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("cronet-keeper".into())
            .spawn(move || {
                for job in rx {
                    match job {
                        Job::Open(sh) => {
                            if let Err(e) = open(&sh) {
                                eprintln!("cronet: {e}");
                                sh.over.store(true, Release);
                                sh.stage.store(crate::conn::FAILED, Release);
                                sh.wake.ring();
                            }
                        }
                        Job::Close(sh) => close(sh),
                    }
                }
            })
            .expect("the keeper's thread");
        tx
    });
    let _ = tx.send(job);
}

/// The Chromium build the members speak, from an engine made for the asking.
pub fn version() -> Option<String> {
    let a = api::api()?;
    // SAFETY: an engine made, asked and destroyed here, never started.
    unsafe {
        let e = (a.engine_create)();
        let v = (a.engine_version)(e);
        let s = (!v.is_null()).then(|| CStr::from_ptr(v).to_string_lossy().into_owned());
        (a.engine_destroy)(e);
        s
    }
}

/// The engine's experimental options (cronet-go engine_params_experimental_
/// options.go): the windows and socket pools of NaiveClient, the exit's
/// domain mapped to its address, the built-in DNS client pointed at
/// loopback, so no name ever leaves the box.
fn options(sh: &Shared) -> CString {
    let f = &sh.form;
    let s = format!(
        concat!(
            r#"{{"AsyncDNS":{{"enable":true}},"DnsServerOverride":{{"nameservers":["127.0.0.1:53"]}},"#,
            r#""UseDnsHttpsSvcb":{{"enable":false}},"HostResolverRules":{{"host_resolver_rules":"MAP {} {}"}},"#,
            r#""HTTP2Options":{{"session_max_recv_window_size":{},"initial_window_size":{}}},"#,
            r#""SocketPoolOptions":{{"max_sockets_per_pool":2048,"max_sockets_per_proxy_chain":2048,"max_sockets_per_group":2040}}}}"#
        ),
        f.sni,
        f.exit.ip(),
        128u64 << 20,
        64u64 << 20
    );
    CString::new(s).expect("a domain and an address have no NUL")
}

fn open(sh: &Arc<Shared>) -> Result<(), String> {
    let a = api::api().ok_or("libcronet is not loaded")?;
    let ctx = Arc::as_ptr(sh) as Ptr;
    // SAFETY: the engine and stream are made and set up here, in the order
    // cronet_c.h asks (dialer and verifier before the start); ctx and the
    // annotation are the Shared the keeper keeps alive until close.
    unsafe {
        let e = (a.engine_create)();
        sh.engine.store(e, Release);
        (a.engine_set_dialer)(e, Some(dial), ctx);
        if let Some(pem) = &sh.form.roots {
            let pem = CString::new(pem.as_str()).map_err(|_| "roots have a NUL")?;
            let v = (a.verifier_with_roots)(pem.as_ptr());
            if v.is_null() {
                return Err("the roots are no PEM certificates".into());
            }
            (a.engine_set_verifier)(e, v);
        }
        let p = (a.params_create)();
        (a.params_quic)(p, false);
        (a.params_http2)(p, true);
        let opts = options(sh);
        (a.params_experimental)(p, opts.as_ptr());
        let r = (a.engine_start)(e, p);
        (a.params_destroy)(p);
        if r != 0 {
            return Err(format!("the engine did not start: {r}"));
        }
        let se = (a.engine_stream_engine)(e);
        let s = (a.stream_create)(se, ctx, &CALLBACKS);
        if s.is_null() {
            return Err("no stream".into());
        }
        sh.stream.store(s, Release);
        start(a, sh, s)
    }
}

/// The CONNECT (cronet-go NaiveClient.DialEarly): the trunk's authority,
/// the padding header, the key.
unsafe fn start(a: &Api, sh: &Shared, s: *mut api::Stream) -> Result<(), String> {
    let mut hs: Vec<Header> = sh.headers.iter().map(|(k, v)| Header { key: k.as_ptr(), value: v.as_ptr() }).collect();
    let arr = Headers { count: hs.len(), capacity: hs.len(), headers: hs.as_mut_ptr() };
    let method = c"CONNECT";
    if (a.stream_start)(s, sh.url.as_ptr(), 0, method.as_ptr(), &arr, false) != 0 {
        return Err("the stream did not start".into());
    }
    Ok(())
}

/// Ends a member: its stream canceled and destroyed, its engine shut down,
/// and only then its shared state let go, since cronet's thread may call
/// back into it until the engine is down.
fn close(sh: Arc<Shared>) {
    let Some(a) = api::api() else { return };
    let s = sh.stream.load(Acquire);
    let e = sh.engine.load(Acquire);
    // SAFETY: the loop's Conn is gone, so no one else calls the stream; the
    // stream is destroyed before its engine, the engine shut down off its
    // own thread.
    unsafe {
        if !s.is_null() {
            if !sh.over.load(Acquire) {
                (a.stream_cancel)(s);
                let t = Instant::now();
                while !sh.over.load(Acquire) && t.elapsed() < CANCEL_WAIT {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            (a.stream_destroy)(s);
        }
        if !e.is_null() {
            (a.engine_shutdown)(e);
            (a.engine_destroy)(e);
        }
    }
    drop(sh);
}

/// Cronet's dialer: a socket to the exit only, from the member's port.
/// Anything else (a DNS server, another address) is refused, as
/// trunk/chromium portDialer refuses it.
unsafe extern "C" fn dial(ctx: Ptr, address: *const c_char, port: u16) -> isize {
    let sh = &*(ctx as *const Shared);
    if address.is_null() || CStr::from_ptr(address) != sh.exit_ip.as_c_str() || port != sh.form.exit.port() {
        return ERR_CONNECTION_FAILED;
    }
    match sys::tcp_dial(sh.form.exit, sh.from, DIAL_NS) {
        Ok(fd) => sys::into_raw(fd) as isize,
        Err(DialErr::Silent) => {
            sh.silent.store(true, Relaxed);
            ERR_CONNECTION_TIMED_OUT
        }
        Err(DialErr::Failed(e)) => match e.raw_os_error() {
            Some(libc::ECONNREFUSED) => ERR_CONNECTION_REFUSED,
            Some(libc::EADDRINUSE) => ERR_ADDRESS_IN_USE,
            _ => ERR_CONNECTION_FAILED,
        },
    }
}
