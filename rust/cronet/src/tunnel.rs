//! CONNECT-UDP tunnels (RFC 9298) through an HTTP/3 proxy, over Chromium's
//! own QUIC: the client Chrome uses for its IP Protection proxies, put out
//! to the C API by our cronet patch (rust/cronet/chromium, hot path plan
//! R6.1). On the wire this is Chromium's QUIC hello, its HTTP/3 SETTINGS
//! with H3_DATAGRAM, an extended CONNECT with `:protocol connect-udp` and
//! HTTP Datagrams (RFC 9297) on the request stream: the form the `h3dgram`
//! wire of the trunk will have (R6.3), the proxy being the exit (R6.2).
//!
//! A tunnel's datagrams cross between the loop and cronet's network thread
//! through a pair of AF_UNIX datagram sockets: the loop reads and writes its
//! end like a UDP socket, one message per datagram, and never calls the
//! library per datagram. The network thread rings the tunnel's wake-up when
//! it is up or over.
//!
//! Opening an engine and destroying a tunnel or an engine wait for cronet's
//! network thread; whoever calls them is not the pipe's loop.

use std::ffi::{c_char, c_int, CStr, CString};
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering::*};
use std::sync::{Arc, Mutex};

use hikkari_sys as sys;

use crate::api::{self, Live, Ptr, TunnelHeader, TunnelParams, TunnelStats, SESSION_DESTINATION, SESSION_PROXY, TUNNEL_CLOSED, TUNNEL_UP};

// Chromium's net error for a dial the engine must not make
// (net/base/net_error_list.h).
const ERR_CONNECTION_FAILED: isize = -104;

/// Each end's send buffer: about 400 voice frames, or a tick's glued
/// datagrams of a busy member, wait there rather than drop at once.
const PAIR_BUF: usize = 256 << 10;

/// Where an engine's tunnels go: the proxy's domain (the certificate's name
/// and the authority of every request), its address, so the name is never
/// looked up, and the roots it is checked by (None: the system's).
pub struct Proxy {
    pub sni: String,
    pub addr: SocketAddrV4,
    pub roots: Option<String>,
}

/// An engine for tunnels: QUIC on, the proxy's domain mapped to its address,
/// DNS pointed at loopback, every TCP dial refused, so nothing but the
/// tunnels' QUIC leaves it.
pub struct TunnelEngine {
    engine: Ptr,
    proxy: Proxy,
    /// Where its sessions' UDP sockets come from (None: Chromium binds its
    /// own, from a port of the kernel's).
    hand: Option<Arc<UdpHand>>,
}

// SAFETY: the engine is a cronet object whose calls are thread-safe
// (cronet_c.h); the pointer is only handed to them.
unsafe impl Send for TunnelEngine {}
unsafe impl Sync for TunnelEngine {}

impl TunnelEngine {
    /// Starts an engine for tunnels to `proxy`. Blocks until its network
    /// thread is up. With `own_sockets` every QUIC session of the engine
    /// takes the UDP socket its tunnel's opener put in `hand()`.
    pub fn start(proxy: Proxy, own_sockets: bool) -> Result<Arc<TunnelEngine>, String> {
        let a = api::api().ok_or("cronet: libcronet is not loaded")?;
        let Some(t) = a.tunnel.as_ref() else {
            return Err("cronet: this libcronet has no CONNECT-UDP tunnel (not our patched build)".into());
        };
        let opts = options(&proxy);
        let hand = own_sockets.then(|| Arc::new(UdpHand::new(proxy.addr)));
        // SAFETY: made and set up in the order cronet_c.h asks (dialers and
        // verifier before the start); the TCP dialer needs no context, the
        // UDP one the hand, which the engine holds until it is shut down.
        unsafe {
            let e = (a.engine_create)();
            (a.engine_set_dialer)(e, Some(refuse), std::ptr::null_mut());
            if let Some(h) = &hand {
                (t.set_udp_dialer)(e, Some(dial_udp), Arc::as_ptr(h) as Ptr, None);
            }
            if let Some(pem) = &proxy.roots {
                let pem = CString::new(pem.as_str()).map_err(|_| "cronet: the roots have a NUL")?;
                let v = (a.verifier_with_roots)(pem.as_ptr());
                if v.is_null() {
                    (a.engine_destroy)(e);
                    return Err("cronet: the roots are no PEM certificates".into());
                }
                (a.engine_set_verifier)(e, v);
            }
            let p = (a.params_create)();
            (a.params_quic)(p, true);
            (a.params_http2)(p, true);
            (a.params_experimental)(p, opts.as_ptr());
            let r = (a.engine_start)(e, p);
            (a.params_destroy)(p);
            if r != 0 {
                (a.engine_destroy)(e);
                return Err(format!("cronet: the tunnel engine did not start: {r}"));
            }
            Ok(Arc::new(TunnelEngine { engine: e, proxy, hand }))
        }
    }

    /// Starts one on the keeper's thread (the pipe's loop must not wait for
    /// a network thread); `Starting::ready` has it once it is up.
    pub fn start_off_loop(proxy: Proxy, own_sockets: bool) -> Starting {
        let s = Starting(Arc::new(Mutex::new(None)));
        let done = s.0.clone();
        crate::keeper::off_loop(move || {
            let r = TunnelEngine::start(proxy, own_sockets);
            *done.lock().expect("the start's lock") = Some(r);
        });
        s
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// The hand its sessions take their sockets from, if it was started
    /// with own sockets.
    pub fn hand(&self) -> Option<&UdpHand> {
        self.hand.as_deref()
    }
}

/// What a start off the loop came to: the engine or why it did not start.
type Started = Option<Result<Arc<TunnelEngine>, String>>;

/// A tunnel engine starting off the loop.
pub struct Starting(Arc<Mutex<Started>>);

impl Starting {
    /// The engine or why it did not start, once; None while it starts.
    pub fn ready(&self) -> Option<Result<Arc<TunnelEngine>, String>> {
        self.0.lock().expect("the start's lock").take()
    }
}

/// The UDP socket a tunnel's QUIC session gets (Cronet_Engine_SetUdpDialer),
/// as the pool's members get their TCP sockets (engine.rs): the opener binds
/// it from a port of its own book, connects it to the proxy and puts it
/// here, then opens the tunnel; the engine's dial for that tunnel's new
/// session takes it. The opener opens no other tunnel until the socket is
/// taken, so a socket goes to the session it was bound for. A dial that
/// finds nothing here, or one to another address (a DNS server; a port
/// migration's new path), is refused: Chromium binds no socket of its own.
pub struct UdpHand {
    proxy_ip: CString,
    proxy_port: u16,
    slot: Mutex<Option<(OwnedFd, SocketAddrV4)>>,
}

impl UdpHand {
    fn new(proxy: SocketAddrV4) -> UdpHand {
        let proxy_ip = CString::new(proxy.ip().to_string()).expect("an address has no NUL");
        UdpHand { proxy_ip, proxy_port: proxy.port(), slot: Mutex::new(None) }
    }

    /// Puts a connected UDP socket and its local address for the next dial;
    /// one left there is given back.
    pub fn put(&self, fd: OwnedFd, local: SocketAddrV4) -> Option<OwnedFd> {
        self.slot.lock().expect("the hand's lock").replace((fd, local)).map(|(f, _)| f)
    }

    /// Whether the socket put last was taken.
    pub fn taken(&self) -> bool {
        self.slot.lock().expect("the hand's lock").is_none()
    }

    /// The socket put last, if no dial took it.
    pub fn take_back(&self) -> Option<OwnedFd> {
        self.slot.lock().expect("the hand's lock").take().map(|(f, _)| f)
    }
}

/// Cronet's UDP dialer: the socket in the hand, for the proxy only.
///
/// SAFETY (cronet): ctx is the UdpHand the engine holds until it is shut
/// down; address is a C string or null; out_local has room for 46 bytes
/// (INET6_ADDRSTRLEN, cronet_c.h), out_port and out_id are writable.
unsafe extern "C" fn dial_udp(ctx: Ptr, address: *const c_char, port: u16, out_local: *mut c_char, out_port: *mut u16, out_id: *mut u64) -> isize {
    let h = &*(ctx as *const UdpHand);
    if address.is_null() || CStr::from_ptr(address) != h.proxy_ip.as_c_str() || port != h.proxy_port {
        return ERR_CONNECTION_FAILED;
    }
    let Some((fd, local)) = h.slot.lock().expect("the hand's lock").take() else {
        return ERR_CONNECTION_FAILED;
    };
    let ip = local.ip().to_string();
    std::ptr::copy_nonoverlapping(ip.as_ptr() as *const c_char, out_local, ip.len());
    *out_local.add(ip.len()) = 0;
    *out_port = local.port();
    *out_id = 0;
    sys::into_raw(fd) as isize
}

impl Drop for TunnelEngine {
    fn drop(&mut self) {
        let a = api::api().expect("an engine was started, so the library is loaded");
        // SAFETY: every tunnel holds the engine, so none is left; shutdown
        // joins the network thread, then the engine goes.
        unsafe {
            (a.engine_shutdown)(self.engine);
            (a.engine_destroy)(self.engine);
        }
    }
}

/// The engine's experimental options (cronet-go engine_params_experimental_
/// options.go), as the pool's engine has them (keeper.rs options) less the
/// HTTP/2 windows and socket pools a tunnel has no use for.
fn options(p: &Proxy) -> CString {
    let s = format!(
        concat!(
            r#"{{"AsyncDNS":{{"enable":true}},"DnsServerOverride":{{"nameservers":["127.0.0.1:53"]}},"#,
            r#""UseDnsHttpsSvcb":{{"enable":false}},"HostResolverRules":{{"host_resolver_rules":"MAP {} {}"}}}}"#
        ),
        p.sni,
        p.addr.ip(),
    );
    CString::new(s).expect("a domain and an address have no NUL")
}

/// The tunnel engine's TCP dialer: no TCP at all.
unsafe extern "C" fn refuse(_ctx: Ptr, _address: *const std::ffi::c_char, _port: u16) -> isize {
    ERR_CONNECTION_FAILED
}

/// Where a tunnel is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Opening,
    Up,
    /// Over, with Chromium's net error (0 when it was over without one).
    Closed(i32),
}

/// How Chromium uses a tunnel's QUIC session (net::SessionUsage), the one
/// thing on the wire it changes being the size of its packets: as Chrome's
/// session to a site (1250 B, the default since the owner's choice of
/// 2026-11-14, hikkari-client plans/research/2026-11-14-h3dgram-wire-shape-
/// research.md) or to an IP Protection proxy (1350 B).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Usage {
    #[default]
    Destination,
    Proxy,
}

impl Usage {
    /// A usage by its name: `destination` or `proxy`.
    pub fn parse(s: &str) -> Result<Usage, String> {
        match s {
            "destination" => Ok(Usage::Destination),
            "proxy" => Ok(Usage::Proxy),
            _ => Err(format!("session usage {s:?} is not destination or proxy")),
        }
    }

    fn c(self) -> c_int {
        match self {
            Usage::Destination => SESSION_DESTINATION,
            Usage::Proxy => SESSION_PROXY,
        }
    }
}

/// What the network thread tells the loop: the state, and the QUIC
/// connection's counts it copies as they move (cronet_c.h
/// Cronet_UdpTunnelLive), for the embedder's own sender.
struct Shared {
    wake: sys::Wake,
    /// 0 opening, 1 up, 2 closed.
    state: AtomicI32,
    net_error: AtomicI32,
    live: Live,
}

/// The tunnel's QUIC connection as last copied (`Tunnel::counts`): bytes and
/// packets sent, packets lost, the smoothed round trip, datagrams the
/// connection would not take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub bytes_sent: u64,
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub srtt_ns: u64,
    pub up_dropped: u64,
}

/// One CONNECT-UDP tunnel: its end of the datagram pair, its wake-up.
pub struct Tunnel {
    handle: Ptr,
    end: OwnedFd,
    shared: Arc<Shared>,
    _engine: Arc<TunnelEngine>,
}

// SAFETY: the handle is only passed to the tunnel calls, which are
// thread-safe; Shared is atomics and an eventfd.
unsafe impl Send for Tunnel {}

impl Tunnel {
    /// Starts a tunnel to `target` (host, port) through the engine's proxy,
    /// with `headers` on its CONNECT-UDP, in the network partition named by
    /// `isolation_key` (a URL; tunnels with different keys never share a
    /// QUIC connection), its QUIC session used as `usage` says. Returns at
    /// once; the wake-up rings when it is up.
    pub fn open(
        engine: &Arc<TunnelEngine>,
        target: (&str, u16),
        headers: &[(&str, &str)],
        isolation_key: Option<&str>,
        usage: Usage,
    ) -> Result<Tunnel, String> {
        let a = api::api().ok_or("cronet: libcronet is not loaded")?;
        let t = a.tunnel.as_ref().ok_or("cronet: this libcronet has no CONNECT-UDP tunnel")?;
        let c = |s: &str| CString::new(s).map_err(|_| format!("cronet: {s:?} has a NUL"));
        let proxy_host = c(&engine.proxy.sni)?;
        let target_host = c(target.0)?;
        let owned: Vec<(CString, CString)> =
            headers.iter().map(|(k, v)| Ok((c(k)?, c(v)?))).collect::<Result<_, String>>()?;
        let hdrs: Vec<TunnelHeader> =
            owned.iter().map(|(k, v)| TunnelHeader { key: k.as_ptr(), value: v.as_ptr() }).collect();
        let key = isolation_key.map(c).transpose()?;
        let (end, theirs) = sys::dgram_pair(PAIR_BUF).map_err(|e| format!("cronet: datagram pair: {e}"))?;
        let shared = Arc::new(Shared {
            wake: sys::Wake::new().map_err(|e| format!("cronet: wake-up: {e}"))?,
            state: AtomicI32::new(0),
            net_error: AtomicI32::new(0),
            live: Live::default(),
        });
        let params = TunnelParams {
            proxy_host: proxy_host.as_ptr(),
            proxy_port: engine.proxy.addr.port(),
            target_host: target_host.as_ptr(),
            target_port: target.1,
            headers: hdrs.as_ptr(),
            header_count: hdrs.len(),
            isolation_key: key.as_ref().map_or(std::ptr::null(), |k| k.as_ptr()),
            fd: theirs.as_raw_fd(),
            session_usage: usage.c(),
            // Shared outlives the tunnel in the library (ctx below).
            live: &shared.live as *const Live as *mut Live,
        };
        let ctx = Arc::into_raw(shared.clone()) as Ptr;
        // SAFETY: params and the strings it points to live through the call,
        // which copies them; on success the library owns `theirs` (released
        // below) and calls `event` with ctx until destroy returns.
        let handle = unsafe { (t.create)(engine.engine, &params, event, ctx) };
        if handle.is_null() {
            // SAFETY: the library took neither ctx nor the descriptor.
            unsafe { drop(Arc::from_raw(ctx as *const Shared)) };
            return Err("cronet: the tunnel was refused (engine not started?)".into());
        }
        sys::into_raw(theirs);
        Ok(Tunnel { handle, end, shared, _engine: engine.clone() })
    }

    /// The loop's end of the datagram pair: read and write it as a connected
    /// UDP socket.
    pub fn fd(&self) -> i32 {
        self.end.as_raw_fd()
    }

    /// The descriptor that turns readable when the state changes; clear it
    /// with `clear`.
    pub fn wake_fd(&self) -> i32 {
        self.shared.wake.fd()
    }

    pub fn clear(&self) {
        self.shared.wake.clear();
    }

    pub fn state(&self) -> State {
        match self.shared.state.load(Acquire) {
            0 => State::Opening,
            1 => State::Up,
            _ => State::Closed(self.shared.net_error.load(Acquire)),
        }
    }

    /// The QUIC connection's counts as the network thread last copied them;
    /// no wait, nothing allocated.
    #[inline]
    pub fn counts(&self) -> Counts {
        let l = &self.shared.live;
        Counts {
            bytes_sent: l.bytes_sent.load(Relaxed),
            packets_sent: l.packets_sent.load(Relaxed),
            packets_lost: l.packets_lost.load(Relaxed),
            srtt_ns: l.srtt_us.load(Relaxed) * 1000,
            up_dropped: l.up_dropped.load(Relaxed),
        }
    }

    /// What the network thread has carried so far. Waits for it.
    pub fn stats(&self) -> TunnelStats {
        let t = api::api().and_then(|a| a.tunnel.as_ref()).expect("an open tunnel has the calls");
        // SAFETY: the handle is live until drop.
        unsafe { (t.stats)(self.handle) }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        let t = api::api().and_then(|a| a.tunnel.as_ref()).expect("an open tunnel has the calls");
        // SAFETY: after destroy returns the library calls `event` no more,
        // so the reference it held on Shared can go.
        unsafe {
            (t.destroy)(self.handle);
            drop(Arc::from_raw(Arc::as_ptr(&self.shared)));
        }
    }
}

/// Cronet_UdpTunnelCallback: on cronet's network thread.
///
/// SAFETY (cronet): ctx is the Shared that Tunnel::open leaked for the
/// library, alive until Cronet_UdpTunnel_Destroy returns.
unsafe extern "C" fn event(ctx: Ptr, ev: c_int, net_error: c_int) {
    let s = &*(ctx as *const Shared);
    match ev {
        TUNNEL_UP => s.state.store(1, Release),
        TUNNEL_CLOSED => {
            s.net_error.store(net_error, Release);
            s.state.store(2, Release);
        }
        _ => return,
    }
    s.wake.ring();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnel's session is Chrome's to a site unless proxy is named, and
    /// the names give the patch's Cronet_UdpTunnelSessionUsage values.
    #[test]
    fn a_session_is_a_sites_unless_proxy_is_named() {
        assert_eq!(Usage::default(), Usage::Destination);
        assert_eq!(Usage::parse("destination").map(Usage::c), Ok(0));
        assert_eq!(Usage::parse("proxy").map(Usage::c), Ok(1));
        assert!(Usage::parse("kProxy").is_err());
    }
}
