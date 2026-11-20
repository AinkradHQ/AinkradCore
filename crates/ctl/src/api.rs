//! `api <METHOD> <path[?query]> [json-body]`: one signed request in this device's session, the
//! answer's body printed as is. For routes with no command of their own (hardware, jobs, projects);
//! the Core checks scopes and step-up exactly as for any other command.

use std::io::Write;

use serde_json::Value;

use crate::Error;
use crate::client::Client;

const USAGE: &str = "api <GET|POST|PUT|DELETE> </api/v1/...[?query]> [json-body]";

/// Splits `path?query`, refusing anything that is not an `/api/v1/` path.
fn target(p: &str) -> Result<(&str, &str), Error> {
    let (path, query) = p.split_once('?').unwrap_or((p, ""));
    if !path.starts_with("/api/v1/") || path.contains("..") {
        return Err(Error::Usage(format!(
            "{p:?} is not an /api/v1/ path; {USAGE}"
        )));
    }
    Ok((path, query))
}

pub async fn api(c: &mut Client, words: &[&str], out: &mut impl Write) -> Result<(), Error> {
    let (method, p, body) = match words {
        [m, p] => (*m, *p, None),
        [m, p, b] => (*m, *p, Some(*b)),
        _ => return Err(Error::Usage(USAGE.into())),
    };
    if !matches!(method, "GET" | "POST" | "PUT" | "DELETE") {
        return Err(Error::Usage(format!("unknown method {method:?}; {USAGE}")));
    }
    let (path, query) = target(p)?;
    let body: Option<Value> = body
        .map(|b| {
            serde_json::from_str(b).map_err(|e| Error::Usage(format!("the body is not JSON: {e}")))
        })
        .transpose()?;
    let res = c.call(method, path, query, body.as_ref()).await?;
    out.write_all(&res.body)
        .and_then(|()| {
            if res.body.ends_with(b"\n") {
                Ok(())
            } else {
                out.write_all(b"\n")
            }
        })
        .map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

#[cfg(test)]
mod tests {
    use super::target;

    #[test]
    fn only_api_paths() {
        assert_eq!(
            target("/api/v1/hardware").unwrap(),
            ("/api/v1/hardware", "")
        );
        assert_eq!(
            target("/api/v1/jobs?limit=5").unwrap(),
            ("/api/v1/jobs", "limit=5")
        );
        assert!(target("/healthz").is_err());
        assert!(target("/api/v1/../admin").is_err());
        assert!(target("api/v1/hardware").is_err());
    }
}
