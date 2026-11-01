//! Certificates for the public listener (E1-06.3): an ACME account, orders, the renewal timer
//! and the hot swap, with `instant-acme` (`Specs/2026-10-29-acme-library-decision.md`).
//!
//! - Challenge: TLS-ALPN-01 on the TLS port by default (needs nothing but :443); HTTP-01 on
//!   :80 when the operator opens it (`--acme-http01`).
//! - Storage: `<state>/tls/{account.json,cert.pem,key.pem}`, each `0600` in a `0700`
//!   directory, written to a temporary file and renamed. A certificate is persisted first and
//!   swapped in second, so a restart never serves something older than the live one.
//! - Schedule: renew two thirds into the lifetime, a little earlier by a random jitter; a
//!   failed order keeps the old certificate and retries with jittered exponential backoff
//!   (1 min to 1 h), warning once fewer than 7 days are left. The clock is a parameter, so a
//!   test can run 90 days in a second (`renew`).
//!
//! The account key (`account.json`) is sealed under the master key (`ops::sealed`); the
//! certificate key (`key.pem`) is a plain `0600` file.
//! ponytail: the certificate key stays plain: it is renewed every ~60 days and a copy of it is
//! revoked by reordering; seal it the same way (label `acme.cert`) if that is not enough.
//! ponytail: no lock against two Core processes ordering for one state dir; one process per
//! state dir is the deployment (E1-15's systemd unit).
//! ponytail: ARI (`renewal_info`) is not used: a fixed 2/3 point, which is what Let's Encrypt
//! recommends without ARI; add it with instant-acme's `time` and `x509-parser` features.

use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair};

use super::tls::{Cert, Certs, challenge_key};
use crate::ops::sealed;
use crate::ops::secretbox::SecretBox;

/// Let's Encrypt production, the default directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging, for tests and trials.
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// How to get certificates for the public listener.
#[derive(Debug, Clone)]
pub struct Acme {
    /// The one DNS name on the certificate.
    pub hostname: String,
    /// The account's contact email (no `mailto:`).
    pub contact: String,
    /// The ACME directory URL.
    pub directory: String,
    /// HTTP-01 on the :80 listener instead of TLS-ALPN-01.
    pub http01: bool,
    /// A PEM root to trust for the ACME server instead of the system's (a test CA).
    pub ca_root: Option<PathBuf>,
    /// Where the account and certificate live: `<state>/tls`.
    pub dir: PathBuf,
    /// The master key the account key is sealed under (`<dir>/account.json`).
    pub seal: Arc<SecretBox>,
}

type Error = Box<dyn std::error::Error + Send + Sync>;

impl Acme {
    /// The stored certificate, when there is a usable one.
    pub fn load_cert(&self) -> Option<Cert> {
        let chain = std::fs::read_to_string(self.dir.join("cert.pem")).ok()?;
        let key = std::fs::read_to_string(self.dir.join("key.pem")).ok()?;
        match Cert::from_pem(&chain, &key) {
            Ok(cert) => Some(cert),
            Err(why) => {
                tracing::warn!(why, "stored certificate unusable; ordering a new one");
                None
            }
        }
    }

    /// Persists a chain and its key, then returns them as a certificate to swap in.
    pub fn store_cert(&self, chain: &str, key: &str) -> Result<Cert, Error> {
        let cert = Cert::from_pem(chain, key)?;
        write_private(&self.dir, "key.pem", key.as_bytes())?;
        write_private(&self.dir, "cert.pem", chain.as_bytes())?;
        Ok(cert)
    }

    /// The stored account, or a new one, stored.
    async fn account(&self) -> Result<Account, Error> {
        let builder = || match &self.ca_root {
            Some(root) => Account::builder_with_root(root),
            None => Account::builder(),
        };
        let path = self.dir.join("account.json");
        // Sealed under the master key; a legacy plaintext file is sealed here, once, in place.
        // A file that is there but will not open stops the order: never a silent new account.
        if path.exists() {
            let text = sealed::read(&path, &self.seal, sealed::ACME_LABEL, true, |b| {
                serde_json::from_slice::<AccountCredentials>(b).is_ok()
            })?;
            let creds: AccountCredentials = serde_json::from_slice(&text)?;
            return Ok(builder()?.from_credentials(creds).await?);
        }
        let contact = format!("mailto:{}", self.contact);
        let (account, creds) = builder()?
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory.clone(),
                None,
            )
            .await?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)?;
        sealed::replace(
            &self.dir.join("account.json"),
            &self.seal,
            sealed::ACME_LABEL,
            serde_json::to_string(&creds)?.as_bytes(),
        )?;
        tracing::info!(directory = self.directory, "ACME account created");
        Ok(account)
    }

    /// One order, start to finish: the challenge answered through `certs`, the certificate
    /// persisted. Returns it for the caller to swap in.
    pub async fn order(&self, certs: &Certs) -> Result<Cert, Error> {
        let account = self.account().await?;
        let result = self.order_with(&account, certs).await;
        certs.clear_challenges();
        result
    }

    async fn order_with(&self, account: &Account, certs: &Certs) -> Result<Cert, Error> {
        let ids = [Identifier::Dns(self.hostname.clone())];
        let mut order = account.new_order(&NewOrder::new(&ids)).await?;
        let mut authzs = order.authorizations();
        while let Some(authz) = authzs.next().await {
            let mut authz = authz?;
            // A still-valid authorization is reused: no challenge this time.
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            let kind = match self.http01 {
                true => ChallengeType::Http01,
                false => ChallengeType::TlsAlpn01,
            };
            let mut challenge = authz
                .challenge(kind.clone())
                .ok_or_else(|| format!("the CA does not offer {kind:?}"))?;
            let key_auth = challenge.key_authorization();
            match self.http01 {
                true => certs.set_http01(challenge.token.clone(), key_auth.as_str().to_owned()),
                false => {
                    let mut params = CertificateParams::new(vec![self.hostname.clone()])?;
                    params.custom_extensions = vec![CustomExtension::new_acme_identifier(
                        key_auth.digest().as_ref(),
                    )];
                    let key = KeyPair::generate()?;
                    let cert = params.self_signed(&key)?;
                    let key = challenge_key(cert.der().to_vec(), key.serialize_der())?;
                    certs.set_alpn_challenge(Some(key));
                }
            }
            challenge.set_ready().await?;
        }
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            return Err(format!("order is {status:?}, not ready").into());
        }
        let key = order.finalize().await?;
        let chain = order.poll_certificate(&RetryPolicy::default()).await?;
        self.store_cert(&chain, &key)
    }
}

/// Writes `dir/name` as `0600` (and `dir` as `0700`) through a temporary file and a rename.
fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, dir.join(name))
}

/// A random fraction in `[0, 1)`, for jitter.
fn jitter() -> f64 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    f64::from(u32::from_le_bytes(b)) / (f64::from(u32::MAX) + 1.0)
}

/// Keeps `certs` holding a current certificate until `stop` resolves. `now` is the clock
/// (`SystemTime::now` in production) and `poll` how often it is read while waiting, so a jump
/// in the clock is noticed. `obtain` gets and persists a new certificate (`Acme::order`).
pub async fn renew<Obtain, Fut>(
    certs: Arc<Certs>,
    now: impl Fn() -> SystemTime,
    poll: Duration,
    mut obtain: Obtain,
    stop: impl Future<Output = ()>,
) where
    Obtain: FnMut() -> Fut,
    Fut: Future<Output = Result<Cert, Error>>,
{
    tokio::pin!(stop);
    let mut backoff = Duration::from_secs(60);
    let mut retry_at = None;
    let mut early = jitter();
    loop {
        let due = retry_at.or_else(|| {
            certs.live().map(|c| {
                let life = c.not_after.duration_since(c.not_before).unwrap_or_default();
                // Up to 2% of the lifetime early (a day of a 90-day certificate).
                c.renew_at() - life.mul_f64(0.02 * early)
            })
        });
        let t = now();
        if due.is_none_or(|due| t >= due) {
            let result = tokio::select! {
                r = obtain() => r,
                () = &mut stop => return,
            };
            match result {
                Ok(cert) => {
                    tracing::info!(not_after = ?cert.not_after, "certificate renewed and swapped in");
                    // A certificate due as soon as it is issued (a lifetime shorter than the
                    // clock's error) must not turn into an order loop: back off as on failure.
                    retry_at = (cert.renew_at() <= t).then(|| {
                        tracing::warn!("the new certificate is already due; backing off");
                        t + backoff
                    });
                    certs.set(cert);
                    early = jitter();
                    backoff = match retry_at {
                        Some(_) => (backoff * 2).min(Duration::from_secs(3600)),
                        None => Duration::from_secs(60),
                    };
                }
                Err(e) => {
                    let wait = backoff.mul_f64(0.5 + jitter());
                    let expiring = certs
                        .live()
                        .is_none_or(|c| c.not_after < t + Duration::from_secs(7 * 86_400));
                    match expiring {
                        true => {
                            tracing::error!(error = %e, ?wait, "certificate order failed; under 7 days left")
                        }
                        false => {
                            tracing::warn!(error = %e, ?wait, "certificate order failed; retrying")
                        }
                    }
                    retry_at = Some(t + wait);
                    backoff = (backoff * 2).min(Duration::from_secs(3600));
                }
            }
            // At least `poll` of real time between two orders, whatever the clock says: a
            // clock that jumps (or a test's fast one) never turns into an order loop.
            tokio::select! {
                () = tokio::time::sleep(poll) => {}
                () = &mut stop => return,
            }
            continue;
        }
        let left = due.and_then(|d| d.duration_since(t).ok()).unwrap_or(poll);
        tokio::select! {
            () = tokio::time::sleep(left.min(poll)) => {}
            () = &mut stop => return,
        }
    }
}
