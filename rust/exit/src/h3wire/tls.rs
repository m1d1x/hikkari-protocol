//! TLS identities of the forwarding points (spec/trunk.md, "Border points").

use std::net::Ipv4Addr;
use std::sync::Arc;

use boring::pkey::{PKey, Private};
use boring::ssl::{NameType, SelectCertError, SslContextBuilder, SslMethod, SslRef};
use boring::x509::X509;

use crate::ctl::PointTls;

struct Identity {
    name: String,
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl Identity {
    fn load(name: &str, cert: &str, key: &str) -> Result<Self, String> {
        let read = |path: &str| std::fs::read(path).map_err(|e| format!("h3dgram: {path}: {e}"));
        let mut chain = X509::stack_from_pem(&read(cert)?).map_err(|e| format!("h3dgram: {cert}: {e}"))?.into_iter();
        let leaf = chain.next().ok_or_else(|| format!("h3dgram: {cert}: empty certificate chain"))?;
        let key = PKey::private_key_from_pem(&read(key)?).map_err(|e| format!("h3dgram: {key}: {e}"))?;
        let public = leaf.public_key().map_err(|e| format!("h3dgram: {cert}: {e}"))?;
        if !public.public_eq(&key) {
            return Err(format!("h3dgram: {name}: certificate and key do not match"));
        }
        Ok(Self { name: name.to_owned(), leaf, chain: chain.collect(), key })
    }

    fn apply(&self, ssl: &mut SslRef) -> Result<(), SelectCertError> {
        ssl.set_certificate(&self.leaf).map_err(|_| SelectCertError::ERROR)?;
        ssl.set_private_key(&self.key).map_err(|_| SelectCertError::ERROR)?;
        for issuer in &self.chain {
            ssl.add_chain_cert(issuer).map_err(|_| SelectCertError::ERROR)?;
        }
        Ok(())
    }
}

fn named(primary: Arc<Identity>, legacy: Option<Arc<Identity>>) -> Result<quiche::Config, String> {
    let mut tls = SslContextBuilder::new(SslMethod::tls()).map_err(|e| format!("h3dgram: TLS: {e}"))?;
    tls.set_select_certificate_callback(move |mut hello| {
        let name = hello.servername(NameType::HOST_NAME).ok_or(SelectCertError::ERROR)?;
        let identity = if name.eq_ignore_ascii_case(&primary.name) {
            &primary
        } else {
            legacy.as_ref().filter(|id| name.eq_ignore_ascii_case(&id.name)).ok_or(SelectCertError::ERROR)?
        };
        identity.apply(hello.ssl_mut())
    });
    quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls).map_err(|e| format!("h3dgram: QUIC: {e}"))
}

pub struct Configs {
    fallback: Option<quiche::Config>,
    points: Vec<(Ipv4Addr, quiche::Config)>,
}

impl Configs {
    pub fn new(cert: &str, key: &str, tls: Option<PointTls<'_>>) -> Result<Self, String> {
        let Some(tls) = tls else {
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|e| format!("h3dgram: QUIC: {e}"))?;
            config.load_cert_chain_from_pem_file(cert).map_err(|e| format!("h3dgram: certificate {cert}: {e}"))?;
            config.load_priv_key_from_pem_file(key).map_err(|e| format!("h3dgram: key {key}: {e}"))?;
            return Ok(Self { fallback: Some(super::configure(config)?), points: Vec::new() });
        };
        // The core's own name answers whoever is not a point, as Caddy's
        // policies do on TCP; from a point only during the transition.
        let core = Arc::new(Identity::load(tls.core_name, cert, key)?);
        let legacy = tls.legacy.then(|| core.clone());
        let fallback = Some(super::configure(named(core, None)?)?);
        let points = tls.points.into_iter().map(|p| {
            let identity = Arc::new(Identity::load(p.name, p.cert, p.key)?);
            Ok((p.ip, super::configure(named(identity, legacy.clone())?)?))
        }).collect::<Result<_, String>>()?;
        Ok(Self { fallback, points })
    }

    pub fn for_peer(&mut self, ip: Ipv4Addr) -> Option<&mut quiche::Config> {
        self.points.iter_mut().find(|(point, _)| *point == ip).map(|(_, config)| config).or(self.fallback.as_mut())
    }
}
