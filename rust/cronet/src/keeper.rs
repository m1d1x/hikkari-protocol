//! The keeper: one thread that starts the wires' engines and shuts them
//! down, since both block (an engine's start spins up its network thread,
//! its shutdown joins it) and the pipe's loop must not; it also starts and
//! ends the members' streams, one at a time, so each member's socket goes
//! to its own stream (engine.rs). An engine is set up as cronet-go
//! NaiveClient.startEngine sets it for the Go entry's members: HTTP/2
//! without QUIC, its windows, its socket pools, and the dialer of ours; the
//! exit's domain is mapped to its address, so no name is ever looked up.

use std::ffi::{CStr, CString};
use std::sync::atomic::Ordering::*;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hikkari_sys as sys;

use crate::api::{self, Api, Header, Headers, Ptr};
use crate::conn::{Shared, CALLBACKS};
use crate::engine::{self, Hub};

/// How long a starting stream may take to ask for its socket. Chromium asks
/// within a turn of its network thread; a stream that does not ask has
/// found a connection to reuse, which a member must never have.
const HANDOFF_WAIT: Duration = Duration::from_secs(1);

/// How long a close waits for a canceled stream's last callback.
const CANCEL_WAIT: Duration = Duration::from_secs(2);

pub(crate) enum Job {
    /// A member's stream on its socket.
    Open(Arc<Shared>, std::os::fd::OwnedFd),
    /// A member gone from the loop.
    Close(Arc<Shared>),
    /// A handle on an engine dropped.
    Release(Arc<Hub>),
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
                        Job::Open(sh, fd) => {
                            if let Err(e) = open(&sh, fd) {
                                eprintln!("cronet: {e}");
                                sh.fail(0);
                            }
                        }
                        Job::Close(sh) => {
                            let hub = sh.hub.clone();
                            close(sh);
                            release(hub);
                        }
                        Job::Release(hub) => release(hub),
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
fn options(hub: &Hub) -> CString {
    let f = &hub.form;
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

/// The wire's engine, started on its first member.
fn engine(a: &Api, hub: &Arc<Hub>) -> Result<Ptr, String> {
    let e = hub.engine.load(Acquire);
    if !e.is_null() {
        return Ok(e);
    }
    let ctx = Arc::as_ptr(hub) as Ptr;
    // SAFETY: made and set up in the order cronet_c.h asks (dialer and
    // verifier before the start); ctx is the Hub, which outlives the engine
    // (release shuts the engine down before the last Arc goes).
    unsafe {
        let e = (a.engine_create)();
        (a.engine_set_dialer)(e, Some(engine::dial), ctx);
        if let Some(pem) = &hub.form.roots {
            let pem = CString::new(pem.as_str()).map_err(|_| "roots have a NUL")?;
            let v = (a.verifier_with_roots)(pem.as_ptr());
            if v.is_null() {
                (a.engine_destroy)(e);
                return Err("the roots are no PEM certificates".into());
            }
            (a.engine_set_verifier)(e, v);
        }
        let p = (a.params_create)();
        (a.params_quic)(p, false);
        (a.params_http2)(p, true);
        let opts = options(hub);
        (a.params_experimental)(p, opts.as_ptr());
        let r = (a.engine_start)(e, p);
        (a.params_destroy)(p);
        if r != 0 {
            (a.engine_destroy)(e);
            return Err(format!("the engine did not start: {r}"));
        }
        hub.engine.store(e, Release);
        Ok(e)
    }
}

/// A member's stream: its socket in the slot, its CONNECT started, and the
/// keeper waits until the engine's dialer has taken the socket.
fn open(sh: &Arc<Shared>, fd: std::os::fd::OwnedFd) -> Result<(), String> {
    let a = api::api().ok_or("libcronet is not loaded")?;
    let hub = &sh.hub;
    let e = engine(a, hub)?;
    *hub.slot.lock().expect("the slot's lock") = Some(fd);
    // SAFETY: the stream is made on the started engine with the Shared as
    // its annotation, which the keeper keeps alive until close.
    unsafe {
        let s = (a.stream_create)((a.engine_stream_engine)(e), Arc::as_ptr(sh) as Ptr, &CALLBACKS);
        if s.is_null() {
            hub.slot.lock().expect("the slot's lock").take();
            return Err("no stream".into());
        }
        sh.stream.store(s, Release);
        if let Err(e) = start(a, sh, s) {
            hub.slot.lock().expect("the slot's lock").take();
            return Err(e);
        }
    }
    let g = hub.slot.lock().expect("the slot's lock");
    let (mut g, _) = hub.taken.wait_timeout_while(g, HANDOFF_WAIT, |s| s.is_some()).expect("the slot's lock");
    if g.take().is_some() {
        return Err("Chromium asked for no socket for a member's stream: it found a connection to reuse".into());
    }
    Ok(())
}

/// The CONNECT (cronet-go NaiveClient.DialEarly): the trunk's authority,
/// the padding header, the key, the member's isolation key.
unsafe fn start(a: &Api, sh: &Shared, s: *mut api::Stream) -> Result<(), String> {
    let mut hs: Vec<Header> = sh.headers.iter().map(|(k, v)| Header { key: k.as_ptr(), value: v.as_ptr() }).collect();
    let arr = Headers { count: hs.len(), capacity: hs.len(), headers: hs.as_mut_ptr() };
    let method = c"CONNECT";
    if (a.stream_start)(s, sh.url.as_ptr(), 0, method.as_ptr(), &arr, false) != 0 {
        return Err("the stream did not start".into());
    }
    Ok(())
}

/// Ends a member: its stream canceled and destroyed, then its connection
/// shut down under Chromium (which then closes its session and socket),
/// and only then its shared state let go, since cronet's thread may call
/// back into it until the stream is over.
fn close(sh: Arc<Shared>) {
    let Some(a) = api::api() else { return };
    let s = sh.stream.load(Acquire);
    // SAFETY: the loop's Conn is gone, so no one else calls the stream; the
    // stream belongs to the hub's engine, which is up while sh holds the hub.
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
    }
    sys::shutdown_both(&sh.sock);
    drop(sh);
}

/// Shuts the engine down once nothing but this job holds its hub: no
/// handle in the pipe, no member.
fn release(hub: Arc<Hub>) {
    if Arc::strong_count(&hub) > 1 {
        return;
    }
    let e = hub.engine.swap(std::ptr::null_mut(), AcqRel);
    if e.is_null() {
        return;
    }
    let Some(a) = api::api() else { return };
    // SAFETY: no stream of the engine is left; it is shut down off its own
    // thread and destroyed after.
    unsafe {
        (a.engine_shutdown)(e);
        (a.engine_destroy)(e);
    }
}
