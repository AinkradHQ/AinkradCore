//! TLS for the public listener: rustls, TLS 1.3 only, on `ring`. One `ServerConfig` is built
//! at start and never replaced; the certificate behind it is swapped in place (`Certs::set`),
//! so connections already open, WebSockets included, keep their session and every new
//! handshake gets the new certificate at once.
//!
//! A ClientHello that offers `acme-tls/1` is an ACME server validating a TLS-ALPN-01
//! challenge: it gets the challenge certificate, and the connection is closed right after the
//! handshake (`ACME_ALPN`).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::ServerConfig;
use rustls::crypto::ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// The ALPN protocol of a TLS-ALPN-01 validation (RFC 8737).
pub const ACME_ALPN: &[u8] = b"acme-tls/1";

/// A certificate ready to serve, with its validity.
#[derive(Debug, Clone)]
pub struct Cert {
    pub key: Arc<CertifiedKey>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

impl Cert {
    /// A PEM chain (leaf first) and its PEM private key.
    pub fn from_pem(chain: &str, key: &str) -> Result<Self, String> {
        let chain = CertificateDer::pem_slice_iter(chain.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("certificate chain: {e}"))?;
        let leaf = chain.first().ok_or("an empty certificate chain")?;
        let (not_before, not_after) = validity(leaf)?;
        let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
            .map_err(|e| format!("private key: {e}"))?;
        let key = ring::sign::any_supported_type(&key).map_err(|e| format!("private key: {e}"))?;
        let key = CertifiedKey::new(chain, key);
        key.keys_match()
            .map_err(|e| format!("key and certificate: {e}"))?;
        Ok(Self {
            key: Arc::new(key),
            not_before,
            not_after,
        })
    }

    /// When to renew: two thirds into the lifetime.
    pub fn renew_at(&self) -> SystemTime {
        let life = self
            .not_after
            .duration_since(self.not_before)
            .unwrap_or_default();
        self.not_after - life / 3
    }

    /// The leaf's serial number, for logs and tests.
    pub fn serial(&self) -> Vec<u8> {
        self.key
            .end_entity_cert()
            .ok()
            .and_then(|c| x509_parser::parse_x509_certificate(c).ok())
            .map(|(_, c)| c.raw_serial().to_vec())
            .unwrap_or_default()
    }
}

/// A TLS-ALPN-01 validation certificate (DER) and its PKCS#8 key. Not checked like a served
/// certificate: webpki refuses its critical `acmeIdentifier` extension, which is the point.
pub fn challenge_key(cert: Vec<u8>, pkcs8: Vec<u8>) -> Result<Arc<CertifiedKey>, String> {
    let key = PrivateKeyDer::Pkcs8(pkcs8.into());
    let key = ring::sign::any_supported_type(&key).map_err(|e| format!("private key: {e}"))?;
    Ok(Arc::new(CertifiedKey::new(vec![cert.into()], key)))
}

/// The leaf's `notBefore` and `notAfter`.
fn validity(leaf: &CertificateDer<'_>) -> Result<(SystemTime, SystemTime), String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(leaf).map_err(|e| format!("certificate: {e}"))?;
    let at = |t: x509_parser::time::ASN1Time| {
        let secs = u64::try_from(t.timestamp()).unwrap_or(0);
        UNIX_EPOCH + Duration::from_secs(secs)
    };
    let v = cert.validity();
    Ok((at(v.not_before), at(v.not_after)))
}

/// What the resolver serves: the live certificate and, during an order, the TLS-ALPN-01
/// challenge certificate; and the HTTP-01 answers the :80 listener serves.
#[derive(Debug, Default)]
pub struct Certs {
    live: RwLock<Option<Cert>>,
    alpn_challenge: RwLock<Option<Arc<CertifiedKey>>>,
    /// HTTP-01: token to key authorization.
    http01: RwLock<HashMap<String, String>>,
}

impl Certs {
    pub fn http01(&self, token: &str) -> Option<String> {
        self.http01
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(token)
            .cloned()
    }

    pub fn set_http01(&self, token: String, key_authorization: String) {
        let mut map = self.http01.write().unwrap_or_else(|p| p.into_inner());
        map.insert(token, key_authorization);
    }

    /// Drops every challenge answer once an order is over.
    pub fn clear_challenges(&self) {
        self.set_alpn_challenge(None);
        self.http01
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Swaps the live certificate in place.
    pub fn set(&self, cert: Cert) {
        *self.live.write().unwrap_or_else(|p| p.into_inner()) = Some(cert);
    }

    pub fn live(&self) -> Option<Cert> {
        self.live.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn set_alpn_challenge(&self, key: Option<Arc<CertifiedKey>>) {
        *self
            .alpn_challenge
            .write()
            .unwrap_or_else(|p| p.into_inner()) = key;
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello.alpn().is_some_and(|mut p| p.any(|p| p == ACME_ALPN)) {
            return self
                .alpn_challenge
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
        }
        // None before the first certificate: the handshake fails, nothing panics.
        self.live().map(|c| c.key)
    }
}

/// TLS 1.3 only, no client certificates, our resolver; HTTP/2, HTTP/1.1 and `acme-tls/1`.
pub fn server_config(certs: Arc<Certs>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(certs);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ACME_ALPN.to_vec()];
    Arc::new(config)
}
