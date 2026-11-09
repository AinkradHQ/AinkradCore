//! Shared by the gateway tests: a database with an enrolled device, a test CA for the public
//! listener's certificates, a TLS client that trusts it, and HTTP/1.1 by hand over any stream
//! (reqwest cannot speak to a Unix socket).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ainkrad_core_server::api::App;
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SerialNumber};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// A scratch dir with a migrated database, a Core identity and an enrolled device; removed on
/// drop.
pub struct Fx {
    pub dir: PathBuf,
    pub pool: sqlx::SqlitePool,
    pub identity: Arc<Identity>,
    pub dev: TestDevice,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fx {
    pub async fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("core-gw-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = store::connect(&dir.join("core.db")).await.unwrap();
        let identity = Arc::new(
            Identity::load_or_create(
                &dir,
                &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
            )
            .unwrap(),
        );
        let dev = TestDevice::enroll(
            &pool,
            "mac",
            "device",
            &["read"],
            &identity.fp,
            Arc::new(SystemClock),
        )
        .await;
        Self {
            dir,
            pool,
            identity,
            dev,
        }
    }

    /// The app on `host`, with a session issued to the device.
    pub fn app(&self, host: &str) -> App {
        let app = App::new(
            self.pool.clone(),
            Arc::new(SystemClock),
            host.to_owned(),
            Arc::clone(&self.identity),
        );
        let s = app.auth.issue_session(&self.dev.id, SystemClock.unix());
        self.dev.set_session(Some(s.id));
        app
    }
}

/// A test CA that signs leaf certificates for `localhost`.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pub der: CertificateDer<'static>,
}

static SERIAL: AtomicU64 = AtomicU64::new(1);

impl Ca {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().clone();
        Self {
            issuer: Issuer::new(params, key),
            der,
        }
    }

    /// A leaf for `localhost`, valid from now for `days`, with a fresh serial: its PEM chain
    /// and PEM key.
    pub fn leaf(&self, days: i64) -> (String, String) {
        let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
        let serial = (u64::from(std::process::id()) << 20) + SERIAL.fetch_add(1, Ordering::Relaxed);
        params.serial_number = Some(SerialNumber::from(serial.to_be_bytes().to_vec()));
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// A client that trusts this CA, for these TLS versions and ALPN protocols.
    pub fn client(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[&[u8]],
    ) -> tokio_rustls::TlsConnector {
        client(self.der.clone(), versions, alpn)
    }
}

/// A TLS client that trusts `root`.
pub fn client(
    root: CertificateDer<'static>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// TLS 1.3 to `127.0.0.1:port` as `localhost`.
pub async fn tls(
    ca: &Ca,
    port: u16,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    tls_to(ca.der.clone(), "localhost", port).await
}

/// TLS 1.3 to `127.0.0.1:port` as `name`, trusting `root`.
pub async fn tls_to(
    root: CertificateDer<'static>,
    name: &str,
    port: u16,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let name = ServerName::try_from(name.to_owned()).unwrap();
    client(root, &[&rustls::version::TLS13], &[b"http/1.1"])
        .connect(name, tcp)
        .await
}

/// The leaf certificate's serial on a TLS connection.
pub fn peer_serial(s: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>) -> Vec<u8> {
    let leaf = &s.get_ref().1.peer_certificates().unwrap()[0];
    let (_, cert) = x509_parser::parse_x509_certificate(leaf).unwrap();
    cert.raw_serial().to_vec()
}

/// One HTTP/1.1 request on a kept-alive connection: the status and the body.
pub async fn get(
    io: &mut (impl Io + ?Sized),
    path: &str,
    host: &str,
    signer: Option<&TestDevice>,
) -> (u16, String) {
    let auth: String = signer
        .map(|d| d.headers("GET", path, b""))
        .unwrap_or_default()
        .iter()
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .collect();
    let head = format!("GET {path} HTTP/1.1\r\nhost: {host}\r\n{auth}\r\n");
    io.write_all(head.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(io);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let status = line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut length = 0;
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}
