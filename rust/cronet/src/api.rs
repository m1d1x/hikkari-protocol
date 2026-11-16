//! libcronet loaded at run time (dlopen), as the Go entry loads it with
//! purego (cronet-go loader_purego.go, chromium.Load): the calls of
//! cronet.idl_c.h, cronet_c.h (sagernet's dialer and root certificates) and
//! bidirectional_stream_c.h that a member makes, and the CONNECT-UDP tunnel
//! of our patch (rust/cronet/chromium, cronet_c.h `Cronet_UdpTunnel_*`),
//! which only a patched build has. The C types are mirrored here as the
//! headers define them.

use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::OnceLock;

pub type Ptr = *mut c_void;

/// bidirectional_stream: the library's object and the caller's annotation.
#[repr(C)]
pub struct Stream {
    pub obj: Ptr,
    pub annotation: Ptr,
}

#[repr(C)]
pub struct Header {
    pub key: *const c_char,
    pub value: *const c_char,
}

#[repr(C)]
pub struct Headers {
    pub count: usize,
    pub capacity: usize,
    pub headers: *mut Header,
}

/// bidirectional_stream_callback, in the header's order.
#[repr(C)]
pub struct Callbacks {
    pub on_stream_ready: Option<unsafe extern "C" fn(*mut Stream)>,
    pub on_response_headers_received: Option<unsafe extern "C" fn(*mut Stream, *const Headers, *const c_char)>,
    pub on_read_completed: Option<unsafe extern "C" fn(*mut Stream, *mut c_char, c_int)>,
    pub on_write_completed: Option<unsafe extern "C" fn(*mut Stream, *const c_char)>,
    pub on_response_trailers_received: Option<unsafe extern "C" fn(*mut Stream, *const Headers)>,
    pub on_succeded: Option<unsafe extern "C" fn(*mut Stream)>,
    pub on_failed: Option<unsafe extern "C" fn(*mut Stream, c_int)>,
    pub on_canceled: Option<unsafe extern "C" fn(*mut Stream)>,
}

/// Cronet_DialerFunc: a connected socket's descriptor, or a negative net
/// error.
pub type DialerFn = unsafe extern "C" fn(ctx: Ptr, address: *const c_char, port: u16) -> isize;

/// Cronet_UdpTunnelHeader.
#[repr(C)]
pub struct TunnelHeader {
    pub key: *const c_char,
    pub value: *const c_char,
}

/// Cronet_UdpTunnelParams, in the header's order.
#[repr(C)]
pub struct TunnelParams {
    pub proxy_host: *const c_char,
    pub proxy_port: u16,
    pub target_host: *const c_char,
    pub target_port: u16,
    pub headers: *const TunnelHeader,
    pub header_count: usize,
    pub isolation_key: *const c_char,
    pub fd: c_int,
    pub session_usage: c_int,
    pub live: *mut Live,
}

/// Cronet_UdpTunnelLive: each field a word the network thread stores
/// atomically (AtomicU64 has u64's layout), read here without a wait.
#[repr(C)]
#[derive(Default)]
pub struct Live {
    pub bytes_sent: std::sync::atomic::AtomicU64,
    pub packets_sent: std::sync::atomic::AtomicU64,
    pub packets_lost: std::sync::atomic::AtomicU64,
    pub srtt_us: std::sync::atomic::AtomicU64,
    pub up_dropped: std::sync::atomic::AtomicU64,
}

/// Cronet_UdpTunnelStats.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TunnelStats {
    pub up_sent: u64,
    pub up_dropped: u64,
    pub down_received: u64,
    pub down_dropped: u64,
}

/// Cronet_UdpTunnelEvent.
pub const TUNNEL_UP: c_int = 1;
pub const TUNNEL_CLOSED: c_int = 2;
/// Cronet_UdpTunnelSessionUsage.
pub const SESSION_DESTINATION: c_int = 0;
pub const SESSION_PROXY: c_int = 1;

/// Cronet_UdpTunnelCallback, called on cronet's network thread.
pub type TunnelCallback = unsafe extern "C" fn(ctx: Ptr, event: c_int, net_error: c_int);

/// Cronet_UdpDialerFunc: a ready UDP socket's descriptor and its local
/// address and port written out, or a negative net error. A socket id of 0
/// asks for no close callback.
pub type UdpDialerFn =
    unsafe extern "C" fn(ctx: Ptr, address: *const c_char, port: u16, out_local: *mut c_char, out_port: *mut u16, out_id: *mut u64) -> isize;

/// Cronet_UdpSocketCloseFunc.
pub type UdpCloseFn = unsafe extern "C" fn(socket_id: u64);

/// The CONNECT-UDP tunnel's calls, in a patched libcronet only, with the
/// engine's UDP dialer (sagernet's, cronet_c.h) the tunnels' sockets come
/// from.
pub struct TunnelApi {
    pub create: unsafe extern "C" fn(Ptr, *const TunnelParams, TunnelCallback, Ptr) -> Ptr,
    pub destroy: unsafe extern "C" fn(Ptr),
    pub stats: unsafe extern "C" fn(Ptr) -> TunnelStats,
    pub set_udp_dialer: unsafe extern "C" fn(Ptr, Option<UdpDialerFn>, Ptr, Option<UdpCloseFn>),
}

pub struct Api {
    pub engine_create: unsafe extern "C" fn() -> Ptr,
    pub engine_destroy: unsafe extern "C" fn(Ptr),
    pub engine_start: unsafe extern "C" fn(Ptr, Ptr) -> c_int,
    pub engine_shutdown: unsafe extern "C" fn(Ptr) -> c_int,
    pub engine_version: unsafe extern "C" fn(Ptr) -> *const c_char,
    pub engine_set_dialer: unsafe extern "C" fn(Ptr, Option<DialerFn>, Ptr),
    pub engine_stream_engine: unsafe extern "C" fn(Ptr) -> Ptr,
    pub engine_set_verifier: unsafe extern "C" fn(Ptr, Ptr),
    pub verifier_with_roots: unsafe extern "C" fn(*const c_char) -> Ptr,
    pub params_create: unsafe extern "C" fn() -> Ptr,
    pub params_destroy: unsafe extern "C" fn(Ptr),
    pub params_quic: unsafe extern "C" fn(Ptr, bool),
    pub params_http2: unsafe extern "C" fn(Ptr, bool),
    pub params_experimental: unsafe extern "C" fn(Ptr, *const c_char),
    pub stream_create: unsafe extern "C" fn(Ptr, Ptr, *const Callbacks) -> *mut Stream,
    pub stream_destroy: unsafe extern "C" fn(*mut Stream) -> c_int,
    pub stream_start: unsafe extern "C" fn(*mut Stream, *const c_char, c_int, *const c_char, *const Headers, bool) -> c_int,
    pub stream_read: unsafe extern "C" fn(*mut Stream, *mut c_char, c_int) -> c_int,
    pub stream_write: unsafe extern "C" fn(*mut Stream, *const c_char, c_int, bool) -> c_int,
    pub stream_cancel: unsafe extern "C" fn(*mut Stream),
    /// None when the library is not our patched build.
    pub tunnel: Option<TunnelApi>,
}

static API: OnceLock<Api> = OnceLock::new();

/// The library, once loaded.
pub fn api() -> Option<&'static Api> {
    API.get()
}

/// Loads libcronet: from `path`, or else libcronet.so in the executable's
/// directory, then where the dynamic linker looks (LD_LIBRARY_PATH,
/// /usr/local/lib, /usr/lib), as cronet.LoadLibrary("") does. Loading it
/// again is nothing.
pub fn load(path: Option<&str>) -> Result<(), String> {
    if API.get().is_some() {
        return Ok(());
    }
    let mut tried = Vec::new();
    match path {
        Some(p) => tried.push(p.to_string()),
        None => {
            if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.to_path_buf())) {
                tried.push(dir.join("libcronet.so").to_string_lossy().into_owned());
            }
            tried.push("libcronet.so".into());
        }
    }
    let mut why = String::new();
    for p in &tried {
        let c = CString::new(p.as_str()).map_err(|_| format!("cronet: path {p:?} has a NUL"))?;
        // SAFETY: dlopen with a valid C string; the handle is never closed,
        // so the symbols stay valid for the process's life.
        let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if h.is_null() {
            // SAFETY: dlerror's string is valid until the next dl call here.
            let e = unsafe { libc::dlerror() };
            if !e.is_null() {
                why = unsafe { std::ffi::CStr::from_ptr(e) }.to_string_lossy().into_owned();
            }
            continue;
        }
        let api = resolve(h)?;
        let _ = API.set(api);
        return Ok(());
    }
    Err(format!("cronet: no libcronet in {tried:?}: {why}"))
}

fn resolve(h: Ptr) -> Result<Api, String> {
    /// The symbol `name` as a function of type T.
    unsafe fn sym<T: Copy>(h: Ptr, name: &str) -> Result<T, String> {
        let c = CString::new(name).expect("symbol names have no NUL");
        let p = libc::dlsym(h, c.as_ptr());
        if p.is_null() {
            return Err(format!("cronet: libcronet has no {name}"));
        }
        debug_assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<Ptr>());
        Ok(std::mem::transmute_copy(&p))
    }
    // SAFETY: each type is the C declaration of the symbol it names
    // (include/cronet.idl_c.h, cronet_c.h, bidirectional_stream_c.h of the
    // cronet-go build the Go entry loads).
    unsafe {
        Ok(Api {
            engine_create: sym(h, "Cronet_Engine_Create")?,
            engine_destroy: sym(h, "Cronet_Engine_Destroy")?,
            engine_start: sym(h, "Cronet_Engine_StartWithParams")?,
            engine_shutdown: sym(h, "Cronet_Engine_Shutdown")?,
            engine_version: sym(h, "Cronet_Engine_GetVersionString")?,
            engine_set_dialer: sym(h, "Cronet_Engine_SetDialer")?,
            engine_stream_engine: sym(h, "Cronet_Engine_GetStreamEngine")?,
            engine_set_verifier: sym(h, "Cronet_Engine_SetMockCertVerifierForTesting")?,
            verifier_with_roots: sym(h, "Cronet_CreateCertVerifierWithRootCerts")?,
            params_create: sym(h, "Cronet_EngineParams_Create")?,
            params_destroy: sym(h, "Cronet_EngineParams_Destroy")?,
            params_quic: sym(h, "Cronet_EngineParams_enable_quic_set")?,
            params_http2: sym(h, "Cronet_EngineParams_enable_http2_set")?,
            params_experimental: sym(h, "Cronet_EngineParams_experimental_options_set")?,
            stream_create: sym(h, "bidirectional_stream_create")?,
            stream_destroy: sym(h, "bidirectional_stream_destroy")?,
            stream_start: sym(h, "bidirectional_stream_start")?,
            stream_read: sym(h, "bidirectional_stream_read")?,
            stream_write: sym(h, "bidirectional_stream_write")?,
            stream_cancel: sym(h, "bidirectional_stream_cancel")?,
            tunnel: match (
                sym(h, "Cronet_UdpTunnel_Create"),
                sym(h, "Cronet_UdpTunnel_Destroy"),
                sym(h, "Cronet_UdpTunnel_GetStats"),
                sym(h, "Cronet_Engine_SetUdpDialer"),
            ) {
                (Ok(create), Ok(destroy), Ok(stats), Ok(set_udp_dialer)) => Some(TunnelApi { create, destroy, stats, set_udp_dialer }),
                _ => None,
            },
        })
    }
}
