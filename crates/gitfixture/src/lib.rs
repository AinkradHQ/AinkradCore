//! A local HTTPS git server for tests, over loopback, with a throwaway CA made at test time.
//!
//! **How the trust is scoped.** Nothing in the runner trusts this CA. [`Server::git_shim`] writes a
//! script that sets `GIT_SSL_CAINFO` to the CA file and execs `git`; a test assigns that script to
//! `Workspaces::git`. So exactly the git processes the test's `Workspaces` spawns trust the CA,
//! only for the life of that test, and certificate verification stays on (`http.sslVerify` is
//! never touched, `GIT_SSL_NO_VERIFY` is never set). `Workspaces::new` still runs plain `git`
//! with the system trust store, and the CA key never leaves this process.
//!
//! The server speaks just enough HTTP/1.1 to put `git http-backend` (CGI) behind TLS, and can
//! misbehave on request (see [`Config`]): demand a token, redirect, stall, or throttle.

mod server;

pub use server::{Config, Seen, Server};

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, crypto::ring, version};

/// A throwaway CA, and the `localhost` / `127.0.0.1` server certificate it signed.
pub struct Ca {
    /// The CA certificate, PEM, in a file: what `GIT_SSL_CAINFO` points at.
    pub file: PathBuf,
    pub(crate) tls: Arc<ServerConfig>,
}

impl Ca {
    /// Generates the CA and the leaf; writes the CA's PEM to `dir/ca.pem`.
    pub fn new(dir: &Path) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&ca_key).unwrap().pem();
        let issuer = Issuer::new(params, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let tls = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], key)
            .unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let file = dir.join("ca.pem");
        std::fs::write(&file, pem).unwrap();
        Self {
            file,
            tls: Arc::new(tls),
        }
    }

    /// An executable that runs `git` trusting this CA (and only it) for that one process.
    pub fn git_shim(&self, dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let shim = dir.join("fixture-git");
        let body = format!(
            "#!/bin/sh\nexport GIT_SSL_CAINFO='{}'\nexec git \"$@\"\n",
            self.file.display()
        );
        std::fs::write(&shim, body).unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
        shim
    }
}

/// `git args…` in `dir` for a test's own setup, with no user or system config. Panics on failure.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// A bare repo `root/<name>` whose one commit on `main` holds the files `seed` writes into the
/// work dir it is given (it may also run [`git`] there). Returns the commit id.
pub fn bare_repo(root: &Path, name: &str, seed: impl FnOnce(&Path)) -> String {
    let work = root.join(format!("{name}.seed"));
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q"]);
    seed(&work);
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "--allow-empty", "-m", "Start"]);
    git(
        root,
        &["clone", "-q", "--bare", &format!("{name}.seed"), name],
    );
    std::fs::remove_dir_all(&work).unwrap();
    git(&root.join(name), &["rev-parse", "HEAD"])
        .trim()
        .to_owned()
}
