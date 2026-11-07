//! What `connection …` takes from the person and how it says what went wrong: syntax checks
//! only (ids, kind names, capability names, limit syntax; never policy, the Core is the judge),
//! secrets read without ever echoing them, and a refusal put after what was being done.

use std::io::{IsTerminal, Write};

use zeroize::Zeroizing;

use crate::Error;

/// The environment variable `add` and `credential` read a token from.
pub const TOKEN_ENV: &str = "AINKRAD_CONNECTION_TOKEN";

pub fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

fn word_ok(w: &str, max: usize, extra: &[u8]) -> bool {
    (1..=max).contains(&w.len())
        && w.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// A connection id (a positive number).
pub fn conn_id(id: &str) -> Result<i64, Error> {
    id.parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not a connection id (a number)")))
}

/// A kind name goes into a path: `[a-z][a-z0-9_-]*`.
pub fn kind(k: &str) -> Result<&str, Error> {
    let ok = word_ok(k, 32, b"_-") && k.as_bytes()[0].is_ascii_lowercase() && k == k.to_lowercase();
    ok.then_some(k)
        .ok_or_else(|| Error::Usage(format!("{k:?} is not a kind of connection (like github)")))
}

/// `user`, `role` or `agent`, and who: they go into a path.
pub fn grantee<'a>(kind: &'a str, who: &'a str) -> Result<(&'a str, &'a str), Error> {
    if !matches!(kind, "user" | "role" | "agent") {
        return Err(Error::Usage(format!(
            "{kind:?} is not a grantee kind (user, role or agent)"
        )));
    }
    if !word_ok(who, 64, b"._:@-") {
        return Err(Error::Usage(format!(
            "{who:?} is not a grantee ([A-Za-z0-9._:@-], 1 to 64)"
        )));
    }
    Ok((kind, who))
}

/// `a,b,c` as capability names (`[a-z][a-z0-9_.:-]*`); an empty list is for the caller to judge.
pub fn names(list: &str) -> Result<Vec<String>, Error> {
    list.split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| {
            let ok = word_ok(n, 64, b"_.:-") && n.as_bytes()[0].is_ascii_lowercase();
            ok.then(|| n.to_owned())
                .ok_or_else(|| Error::Usage(format!("{n:?} is not a capability name")))
        })
        .collect()
}

/// `key=v1,v2` as a limit: the key's name and its values.
pub fn limit(spec: &str) -> Result<(String, Vec<String>), Error> {
    let bad = || Error::Usage(format!("{spec:?} is not key=value[,value...]"));
    let (key, values) = spec.split_once('=').ok_or_else(bad)?;
    let values: Vec<String> = values.split(',').map(|v| v.trim().to_owned()).collect();
    let key_ok = word_ok(key, 64, b"_.") && key.as_bytes()[0].is_ascii_lowercase();
    if !key_ok || values.iter().any(String::is_empty) {
        return Err(bad());
    }
    Ok((key.to_owned(), values))
}

/// A secret from, in order: `--<flag>` (warned about: the process list and the shell history
/// show it), `--<file_flag>`, `$AINKRAD_CONNECTION_TOKEN` (when `env`), then stdin, which must not
/// be a terminal (a typed secret would be echoed). One trailing newline is dropped. Nothing
/// printed ever contains it.
pub fn secret(
    what: &str,
    flag: (&str, Option<&str>),
    file: (&str, Option<&str>),
    env: Option<&str>,
) -> Result<Zeroizing<String>, Error> {
    let given = if let Some(v) = flag.1 {
        eprintln!(
            "ainkradctl: warning: {} puts the {what} in the process list and the shell history; \
             use {} <file>, stdin or ${TOKEN_ENV} instead",
            flag.0, file.0
        );
        Zeroizing::new(v.to_owned())
    } else if let Some(path) = file.1 {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Usage(format!("reading {} {path}: {e}", file.0)))?;
        Zeroizing::new(text)
    } else if let Some(v) = env
        .and_then(|n| std::env::var(n).ok())
        .filter(|v| !v.is_empty())
    {
        Zeroizing::new(v)
    } else if std::io::stdin().is_terminal() {
        return Err(Error::Usage(format!(
            "the {what} is read from stdin, {} <file> or ${TOKEN_ENV}, never typed here (a \
             terminal would echo it): pipe it in",
            file.0
        )));
    } else {
        crate::secrets::value_from_stdin()?
    };
    let mut v = given;
    for suffix in ["\n", "\r"] {
        if let Some(t) = v.strip_suffix(suffix) {
            let n = t.len();
            v.truncate(n);
        }
    }
    if v.is_empty() {
        return Err(Error::Usage(format!("the {what} is empty")));
    }
    Ok(v)
}

/// A refusal said plainly: what was being done, then the Core's reason (and a 429's wait). Any
/// text in `hide` (secrets this command sent) is blanked, should the Core echo it.
pub fn said(e: Error, what: &str, retry_after: Option<u64>, hide: &[&str]) -> Error {
    let Error::Refused {
        status: status @ (400 | 403 | 404 | 409 | 429 | 502 | 503),
        code,
        message,
        server_time,
        local_time,
    } = e
    else {
        return e;
    };
    let mut reason = match (message.is_empty(), status) {
        (false, _) => message,
        (true, 400) => "the Core refused the input".into(),
        (true, 403) => "this device may not do that".into(),
        (true, 404) => "not found".into(),
        (true, 409) => "it conflicts with what the Core holds".into(),
        (true, _) => "try again later".into(),
    };
    if status == 429 {
        reason = match retry_after {
            Some(n) => format!("too soon, wait {n} s and try again"),
            None => "too soon, wait a little and try again".into(),
        };
    }
    for s in hide.iter().filter(|s| !s.is_empty()) {
        reason = reason.replace(s, "***");
    }
    Error::Refused {
        status,
        code,
        message: format!("{what}: {reason}"),
        server_time,
        local_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_is_checked_and_nothing_else() {
        assert_eq!(conn_id("12").unwrap(), 12);
        for bad in ["0", "-1", "x", ""] {
            assert!(conn_id(bad).is_err(), "{bad:?}");
        }
        assert!(kind("github").is_ok() && kind("my-kind_2").is_ok());
        for bad in ["", "Git", "a/b", "../x", "1a"] {
            assert!(kind(bad).is_err(), "{bad:?}");
        }
        assert!(grantee("agent", "repo-bot:v1").is_ok() && grantee("role", "member").is_ok());
        assert!(grantee("team", "x").is_err() && grantee("user", "a/b").is_err());
        assert_eq!(names("a, b,,c_d").unwrap(), ["a", "b", "c_d"]);
        assert!(names("a,*").is_err() && names("A").is_err());
        assert_eq!(
            limit("repos=ab,c").unwrap(),
            ("repos".into(), vec!["ab".into(), "c".into()])
        );
        for bad in ["repos", "=a", "repos=", "repos=a,", "Repos=a"] {
            assert!(limit(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_429_says_how_long_to_wait_and_a_secret_is_blanked() {
        let r = |status, message: &str| Error::Refused {
            status,
            code: "c".into(),
            message: message.into(),
            server_time: None,
            local_time: 0,
        };
        assert_eq!(
            said(
                r(429, "too many requests; retry later"),
                "testing connection 3",
                Some(7),
                &[]
            )
            .to_string(),
            "429 c: testing connection 3: too soon, wait 7 s and try again"
        );
        assert_eq!(
            said(r(400, "bad token hunter2"), "adding", None, &["hunter2"]).to_string(),
            "400 c: adding: bad token ***"
        );
        // Not one of ours: untouched.
        assert_eq!(
            said(r(500, "x"), "adding", None, &[]).to_string(),
            "500 c: x"
        );
    }
}
