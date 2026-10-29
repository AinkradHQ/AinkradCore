//! A minimal S3 client for the create-only backup bucket (E1-13.2): one single-part PUT of a new
//! object, GET, and LIST. Path-style addressing, AWS SigV4 signed headers with the payload's
//! real SHA-256 in `x-amz-content-sha256`, no `aws-chunked`, no checksum trailers, so it works
//! with OCI's S3-compatible gateway, which answers the AWS SDK's default checksum trailers with
//! `501 NotImplemented` (runbook `ainkrad-core-host.md`, Backups). HTTPS is reqwest on rustls
//! with `ring`, already in the tree; nothing new is pulled in for S3.
//!
//! The bucket's credentials come from the environment only and are never logged, printed or put
//! in an error: `Bucket`'s `Debug` leaves them out.

use std::fmt;
use std::path::Path;

use reqwest::{Method, Url};
use ring::digest::{SHA256, digest};
use ring::hmac;

use crate::scheduler::{Clock, SystemClock};

/// The largest snapshot `backup` uploads, in one PUT. OCI documents no separate single-PUT
/// ceiling for its S3-compatible API (its docs give 10 TiB per object and 50 GiB per multipart
/// part: docs.oracle.com, Object Storage, "Using Multipart Uploads"), so this is the S3 API's
/// own PutObject limit, 5 GiB, which S3-compatible gateways mirror. Multipart is not an option:
/// on OCI it needs `OBJECT_OVERWRITE`, which the backup key deliberately lacks (threat model
/// T-BAK-3).
pub const MAX_SINGLE_PUT: u64 = 5 * 1024 * 1024 * 1024;

pub struct Bucket {
    endpoint: Url,
    bucket: String,
    region: String,
    /// Object key prefix, e.g. `core/`.
    pub prefix: String,
    access_key: String,
    secret_key: String,
    http: reqwest::Client,
}

impl fmt::Debug for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bucket")
            .field("endpoint", &self.endpoint.as_str())
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

/// A refusal from the gateway: its HTTP status and S3 error code. Never a credential.
#[derive(Debug)]
pub struct S3Error {
    pub status: u16,
    pub code: String,
    pub what: String,
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: HTTP {} {}", self.what, self.status, self.code)
    }
}

impl std::error::Error for S3Error {}

type Error = Box<dyn std::error::Error>;

/// RFC 3986 percent-encoding as SigV4 wants it; `/` kept when `slash`.
fn encode(s: &str, slash: bool) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) || (slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
        .as_ref()
        .to_vec()
}

impl Bucket {
    /// The bucket from `AINKRAD_BACKUP_ENDPOINT`, `_BUCKET`, `_REGION`, `_PREFIX` (default
    /// `core/`), `_ACCESS_KEY`, `_SECRET_KEY`; `None` when no endpoint is set.
    pub fn from_env() -> Result<Option<Self>, Error> {
        let var = |n: &str| std::env::var(format!("AINKRAD_BACKUP_{n}")).unwrap_or_default();
        if var("ENDPOINT").is_empty() {
            return Ok(None);
        }
        let prefix = Some(var("PREFIX"))
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "core/".to_owned());
        Self::new(
            &var("ENDPOINT"),
            &var("BUCKET"),
            &var("REGION"),
            &prefix,
            var("ACCESS_KEY"),
            var("SECRET_KEY"),
        )
        .map(Some)
    }

    /// HTTPS only, except plain HTTP to loopback (a local MinIO).
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        prefix: &str,
        access_key: String,
        secret_key: String,
    ) -> Result<Self, Error> {
        let endpoint = Url::parse(endpoint).map_err(|e| format!("AINKRAD_BACKUP_ENDPOINT: {e}"))?;
        let loopback = matches!(
            endpoint.host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        );
        if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && loopback) {
            return Err("AINKRAD_BACKUP_ENDPOINT must be https:// (http only to loopback)".into());
        }
        for (name, v) in [
            ("BUCKET", bucket),
            ("REGION", region),
            ("ACCESS_KEY", &access_key),
            ("SECRET_KEY", &secret_key),
        ] {
            if v.is_empty() {
                return Err(format!("AINKRAD_BACKUP_{name} is not set").into());
            }
        }
        Ok(Self {
            endpoint,
            bucket: bucket.to_owned(),
            region: region.to_owned(),
            prefix: prefix.to_owned(),
            access_key,
            secret_key,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3600))
                .build()?,
        })
    }

    /// A signed request for `/<bucket>/<key>` with `query`; `payload` is the body's SHA-256 hex.
    fn request(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        payload: &str,
    ) -> Result<reqwest::RequestBuilder, Error> {
        let path = format!("/{}/{}", encode(&self.bucket, false), encode(key, true));
        let mut q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (encode(k, false), encode(v, false)))
            .collect();
        q.sort();
        let query = q
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let mut url = self.endpoint.clone();
        url.set_path(&path);
        url.set_query((!query.is_empty()).then_some(query.as_str()));
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_owned(),
        };
        let amz_date = super::compact(&SystemClock.now());
        let date = &amz_date[..8];
        let signed = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!(
            "{method}\n{path}\n{query}\nhost:{host}\nx-amz-content-sha256:{payload}\n\
             x-amz-date:{amz_date}\n\n{signed}\n{payload}"
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(digest(&SHA256, canonical.as_bytes()).as_ref())
        );
        let mut k = hmac(format!("AWS4{}", self.secret_key).as_bytes(), date);
        for part in [self.region.as_str(), "s3", "aws4_request"] {
            k = hmac(&k, part);
        }
        let signature = hex(&hmac(&k, &to_sign));
        Ok(self
            .http
            .request(method, url)
            .header("x-amz-date", amz_date.as_str())
            .header("x-amz-content-sha256", payload)
            .header(
                "authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, \
                     Signature={signature}",
                    self.access_key
                ),
            ))
    }

    async fn check(what: String, r: reqwest::Response) -> Result<reqwest::Response, Error> {
        if r.status().is_success() {
            return Ok(r);
        }
        let status = r.status();
        let body = r.text().await.unwrap_or_default();
        let code = tag(&body, "Code").unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("error")
                .replace(' ', "")
        });
        Err(Box::new(S3Error {
            status: status.as_u16(),
            code,
            what,
        }))
    }

    /// One PUT of `path` as the object `key` (the caller makes `key` unique: the backup key may
    /// not overwrite). Refuses a file above `MAX_SINGLE_PUT`.
    pub async fn put_new(&self, key: &str, path: &Path) -> Result<(), Error> {
        let size = std::fs::metadata(path)?.len();
        if size > MAX_SINGLE_PUT {
            return Err(format!(
                "{} is {size} bytes, above the single-PUT limit of {MAX_SINGLE_PUT}. The backup \
                 key cannot do multipart uploads (on OCI they need overwrite rights, which it \
                 must not have). Upload this file by hand with an admin key, or shrink the \
                 database (events retention, VACUUM) and back up again.",
                path.display()
            )
            .into());
        }
        let sha = super::archive::sha256_hex(path)?;
        let file = tokio::fs::File::open(path).await?;
        let r = self
            .request(Method::PUT, key, &[], &sha)?
            .header("content-length", size)
            .body(reqwest::Body::from(file))
            .send()
            .await?;
        Self::check(format!("PUT {key}"), r).await.map(drop)
    }

    /// GETs `key` into a new file at `dest` (0600).
    pub async fn get(&self, key: &str, dest: &Path) -> Result<u64, Error> {
        use std::io::Write;
        let empty = hex(digest(&SHA256, b"").as_ref());
        let r = self.request(Method::GET, key, &[], &empty)?.send().await?;
        let mut r = Self::check(format!("GET {key}"), r).await?;
        let mut out = super::private_file(dest)?;
        let mut n = 0u64;
        while let Some(chunk) = r.chunk().await? {
            out.write_all(&chunk)?;
            n += chunk.len() as u64;
        }
        out.sync_all()?;
        Ok(n)
    }

    /// The object keys under `prefix` (the first 1000).
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, Error> {
        let empty = hex(digest(&SHA256, b"").as_ref());
        let r = self
            .request(
                Method::GET,
                "",
                &[("list-type", "2"), ("prefix", prefix)],
                &empty,
            )?
            .send()
            .await?;
        let body = Self::check("LIST".to_owned(), r).await?.text().await?;
        Ok(body
            .split("<Key>")
            .skip(1)
            .filter_map(|s| s.split_once("</Key>"))
            .map(|(k, _)| unescape(k))
            .collect())
    }
}

/// The text of the first `<name>…</name>` in an S3 XML body.
fn tag(body: &str, name: &str) -> Option<String> {
    let start = body.find(&format!("<{name}>"))? + name.len() + 2;
    let len = body[start..].find(&format!("</{name}>"))?;
    Some(unescape(&body[start..start + len]))
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests;
