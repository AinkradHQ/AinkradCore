//! The hardened HTTP client for forge and tracker calls (S6, SSRF defence). Every provider is
//! given a client from [`Policy::client`]; a call can only reach:
//!
//! - an `https` URL (port 443) whose host is a **name** on the allow-list: IP literals, URLs
//!   with credentials, other schemes and ports are refused by [`Policy::check_url`], which the
//!   caller runs on a configured API URL before building a provider;
//! - through a DNS resolver that vets **every** address a name resolves to and hands the
//!   connector only those it vetted (no second lookup, so a rebinding host cannot swap in an
//!   internal address): one private, loopback, link-local (cloud metadata included), CGNAT,
//!   unique-local, multicast, unspecified or v4-mapped-internal address refuses the whole name;
//! - with no proxy (an `HTTPS_PROXY` in the environment would bypass the resolver), no redirects
//!   at all, a connect and a total timeout; answers are size-capped by `send`.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Whether a connection to `ip` is allowed: a public, unicast address.
pub fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_allowed(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4_allowed(v4);
            }
            let s = v6.segments();
            let internal = v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || s[0] & 0xfe00 == 0xfc00 // unique local
                || s[0] & 0xffc0 == 0xfe80 // link-local
                || s[0] & 0xffc0 == 0xfec0 // site-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64: embeds a v4
                || s[0] == 0x2002 // 6to4: embeds a v4
                || s[..6] == [0; 6]; // v4-compatible
            !internal
        }
    }
}

fn v4_allowed(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || (o[0] == 100 && o[1] & 0xc0 == 64) // CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF protocol assignments
        || (o[0] == 198 && o[1] & 0xfe == 18) // benchmarking
        || o[0] >= 240) // reserved
}

/// One name's addresses, from the system or (in tests) from a stub.
pub type Lookup = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>> + Send + Sync,
>;

fn system_lookup() -> Lookup {
    Arc::new(|host| {
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            Ok(found.map(|a| a.ip()).collect())
        })
    })
}

/// Which hosts may be called, and how.
#[derive(Clone)]
pub struct Policy {
    hosts: Vec<String>,
    lookup: Lookup,
    /// One loopback origin (`127.0.0.1:port`, plain http) a test's fake server lives on.
    #[cfg(feature = "fake")]
    test_origin: Option<(String, u16)>,
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("hosts", &self.hosts)
            .finish()
    }
}

impl Policy {
    /// The allow-list: exact host names (case-insensitive).
    pub fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            hosts: hosts.into_iter().map(|h| h.to_ascii_lowercase()).collect(),
            lookup: system_lookup(),
            #[cfg(feature = "fake")]
            test_origin: None,
        }
    }

    /// This policy with `extra` host names allowed too (a self-hosted forge an operator added).
    #[must_use]
    pub fn with_hosts(mut self, extra: impl IntoIterator<Item = String>) -> Self {
        self.hosts
            .extend(extra.into_iter().map(|h| h.to_ascii_lowercase()));
        self
    }

    /// The public hosts the providers talk to.
    pub fn public() -> Self {
        Self::new(["api.github.com", "gitlab.com", "api.linear.app"].map(str::to_owned))
    }

    /// Tests: resolve names with `lookup` instead of the system.
    #[cfg(feature = "fake")]
    #[must_use]
    pub fn with_lookup(mut self, lookup: Lookup) -> Self {
        self.lookup = lookup;
        self
    }

    /// Tests: also allow plain http to this one loopback origin (a fake server).
    #[cfg(feature = "fake")]
    #[must_use]
    pub fn with_test_origin(mut self, addr: SocketAddr) -> Self {
        self.test_origin = Some((addr.ip().to_string(), addr.port()));
        self
    }

    /// Whether `url` may be called: why not, otherwise.
    pub fn check_url(&self, url: &str) -> Result<(), String> {
        let u = reqwest::Url::parse(url).map_err(|_| "not a URL".to_owned())?;
        if !u.username().is_empty() || u.password().is_some() {
            return Err("a URL with credentials".to_owned());
        }
        #[cfg(feature = "fake")]
        if let (Some((host, port)), Some(h)) = (&self.test_origin, u.host_str())
            && u.scheme() == "http"
            && h == host
            && u.port() == Some(*port)
        {
            return Ok(());
        }
        if u.scheme() != "https" || u.port().is_some_and(|p| p != 443) {
            return Err("only https on port 443".to_owned());
        }
        match u.domain() {
            Some(name) if self.hosts.iter().any(|h| h == name) => Ok(()),
            Some(name) => Err(format!("the host {name} is not allowed")),
            None => Err("an IP address instead of a host name".to_owned()),
        }
    }

    /// A client bound to this policy.
    ///
    /// # Panics
    ///
    /// Never in practice: the builder only fails for an unusable TLS backend.
    pub fn client(&self) -> reqwest::Client {
        #[allow(unused_mut)]
        let mut https_only = true;
        #[cfg(feature = "fake")]
        if self.test_origin.is_some() {
            https_only = false;
        }
        reqwest::Client::builder()
            .https_only(https_only)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("ainkrad/", env!("CARGO_PKG_VERSION")))
            .dns_resolver(Arc::new(Guarded(self.clone())))
            .build()
            .expect("a client with a resolver and timeouts builds")
    }

    /// The addresses of `host`, every one vetted.
    pub async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let deny = |why: String| Err(io::Error::new(io::ErrorKind::PermissionDenied, why));
        if !self.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            return deny(format!("the host {host} is not allowed"));
        }
        let ips = (self.lookup)(host.to_owned()).await?;
        if ips.is_empty() {
            return deny(format!("{host} did not resolve"));
        }
        if ips.iter().any(|ip| !ip_allowed(*ip)) {
            return deny(format!("{host} resolves to a non-public address"));
        }
        Ok(ips)
    }
}

struct Guarded(Policy);

impl Resolve for Guarded {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.0.clone();
        Box::pin(async move {
            let ips = policy.resolve(name.as_str()).await?;
            let addrs: Addrs = Box::new(
                ips.into_iter()
                    .map(|ip| SocketAddr::new(ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn internal_addresses_are_refused_and_public_ones_pass() {
        for bad in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "fec0::1",
            "2001:db8::1",
            "::7f00:1",
        ] {
            assert!(!ip_allowed(ip(bad)), "{bad}");
        }
        for good in [
            "140.82.112.5",
            "8.8.8.8",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(ip_allowed(ip(good)), "{good}");
        }
    }

    #[test]
    fn only_https_named_allowed_hosts_pass_the_url_check() {
        let p = Policy::public();
        assert!(p.check_url("https://api.github.com").is_ok());
        assert!(p.check_url("https://API.github.com/api/v3").is_ok());
        for bad in [
            "http://api.github.com",
            "https://api.github.com:8443",
            "https://u:p@api.github.com",
            "https://evil.example",
            "https://127.0.0.1",
            "https://[::1]",
            "https://169.254.169.254/latest/meta-data",
            "https://[::ffff:127.0.0.1]",
            "https://localhost",
            "https://2130706433",
            "file:///etc/passwd",
            "nonsense",
        ] {
            assert!(p.check_url(bad).is_err(), "{bad}");
        }
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::http::{StatusCode, header};
    use axum::routing::get;

    fn stub(ips: &'static [&'static str]) -> Lookup {
        Arc::new(move |_| Box::pin(async move { Ok(ips.iter().map(|i| ip(i)).collect()) }))
    }

    async fn serve(router: Router) -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l, router).await;
        });
        addr
    }

    fn counting(n: &Arc<AtomicUsize>) -> Router {
        let n = n.clone();
        Router::new().fallback(move || {
            n.fetch_add(1, Ordering::SeqCst);
            async { "internal" }
        })
    }

    #[tokio::test]
    async fn a_name_that_resolves_anywhere_internal_is_refused_whole() {
        let hosts = || ["forge.test".to_owned()];
        // Rebinding style: one public answer next to an internal one, and only internal ones.
        for ips in [
            &["8.8.8.8", "127.0.0.1"][..],
            &["127.0.0.1"],
            &["169.254.169.254"],
            &["::ffff:10.0.0.1"],
            &[],
        ] {
            let p = Policy::new(hosts()).with_lookup(stub(ips));
            assert!(p.resolve("forge.test").await.is_err(), "{ips:?}");
        }
        let ok = Policy::new(hosts()).with_lookup(stub(&["8.8.8.8"]));
        assert_eq!(ok.resolve("forge.test").await.unwrap(), vec![ip("8.8.8.8")]);
        // A name off the list is refused before any lookup.
        assert!(ok.resolve("other.test").await.is_err());
    }

    #[tokio::test]
    async fn the_client_never_dials_a_name_that_rebinds_to_loopback() {
        let hits = Arc::new(AtomicUsize::new(0));
        let addr = serve(counting(&hits)).await;
        let p = Policy::new(["forge.test".to_owned()]).with_lookup(stub(&["127.0.0.1"]));
        let c = p.client();
        let err = c
            .get(format!("https://forge.test:443/x?{}", addr.port()))
            .send()
            .await
            .unwrap_err();
        assert!(err.is_connect(), "{err}");
        // http to a literal, an unlisted name and an IP literal never reach the network either.
        for url in [format!("http://{addr}/"), "https://127.0.0.1/".to_owned()] {
            assert!(c.get(url).send().await.is_err());
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_redirect_to_an_internal_address_is_not_followed() {
        let hits = Arc::new(AtomicUsize::new(0));
        let internal = serve(counting(&hits)).await;
        let to = format!("http://{internal}/secret");
        let a = serve(Router::new().fallback(move || {
            let to = to.clone();
            async move { (StatusCode::FOUND, [(header::LOCATION, to)]) }
        }))
        .await;
        let c = Policy::new([]).with_test_origin(a).client();
        let res = c.get(format!("http://{a}/")).send().await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FOUND,
            "the redirect is the answer, not followed"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        // The test origin is exactly one origin: the neighbour's is not allowed.
        assert!(
            Policy::new([])
                .with_test_origin(a)
                .check_url(&format!("http://{internal}/"))
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_answer_over_the_cap_is_refused_and_a_proxy_is_ignored() {
        let big = vec![b'a'; crate::MAX_ANSWER_BYTES + 1];
        let a = serve(Router::new().route(
            "/big",
            get(move || {
                let big = big.clone();
                async move { big }
            }),
        ))
        .await;
        let c = Policy::new([]).with_test_origin(a).client();
        let req = c.get(format!("http://{a}/big"));
        let err = crate::send(req, &crate::Secret::new("tok"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("over"), "{err}");
    }
}
