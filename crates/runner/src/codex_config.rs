//! The `config.toml` the runner generates in a session's isolated `CODEX_HOME`.
//!
//! One writer for every generated Codex config: the auth gateway's today (KAN-435 G6), and the
//! subscription config KAN-434 adds reuses [`write`] and [`render`]. The runner writes it from
//! outside the sandbox into a directory the agent can write to, so [`write`] never follows a link
//! the agent left there: it replaces the file by a rename.

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// The file name Codex reads in its home.
pub const FILE: &str = "config.toml";

/// A `[model_providers.<id>]` table: where Codex sends model requests, and the variable it reads
/// the key from.
pub struct Provider<'a> {
    pub id: &'a str,
    pub base_url: &'a str,
    pub env_key: &'a str,
}

/// A TOML basic string, for the plain values the runner puts in a config: no quote, backslash or
/// control character (nothing the runner writes needs one, so none is escaped).
fn quoted(v: &str) -> Result<String, &'static str> {
    if v.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return Err("a config value holds a character that needs escaping");
    }
    Ok(format!("\"{v}\""))
}

/// The config that makes `provider` the only model provider: the Responses wire over HTTP (no
/// websocket, which the gateway refuses) and no provider-side web search (a request that carries
/// that tool is refused by the gateway as network reach, so it must not be offered).
pub fn render(provider: &Provider) -> Result<String, &'static str> {
    if provider.id.is_empty()
        || !provider
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("a config provider id is not a plain name");
    }
    let (id, url, key) = (
        quoted(provider.id)?,
        quoted(provider.base_url)?,
        quoted(provider.env_key)?,
    );
    Ok(format!(
        "# Written by the runner for this session. Edits are replaced when it starts.\n\
         web_search = \"disabled\"\n\
         model_provider = {id}\n\
         \n\
         [model_providers.{}]\n\
         name = {id}\n\
         base_url = {url}\n\
         env_key = {key}\n\
         wire_api = \"responses\"\n\
         supports_websockets = false\n",
        provider.id
    ))
}

/// The gateway's config: the provider `gw`, at the session's loopback port inside the sandbox.
/// The key it names is `OPENAI_API_KEY`, which holds the placeholder.
pub fn gateway(port: u16) -> String {
    render(&Provider {
        id: "gw",
        base_url: &format!("http://127.0.0.1:{port}/v1"),
        env_key: "OPENAI_API_KEY",
    })
    .expect("the gateway's config values are plain")
}

/// Writes `text` as `home/config.toml`, replacing what is there. The agent can write in `home`, so
/// the old file may be a link to anywhere: it is replaced, never written through.
pub fn write(home: &Path, text: &str) -> io::Result<()> {
    let tmp = home.join(format!("{FILE}.runner-tmp"));
    // A link planted at the temp name is removed (not followed); `create_new` then refuses to
    // follow anything that appears between the two calls.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, home.join(FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("codex-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_gateway_config_is_the_one_the_design_names() {
        let want = [
            "web_search = \"disabled\"",
            "model_provider = \"gw\"",
            "[model_providers.gw]",
            "base_url = \"http://127.0.0.1:47833/v1\"",
            "env_key = \"OPENAI_API_KEY\"",
            "wire_api = \"responses\"",
            "supports_websockets = false",
        ];
        let text = gateway(47833);
        for line in want {
            assert!(text.lines().any(|l| l == line), "{line} missing:\n{text}");
        }
    }

    #[test]
    fn a_value_that_needs_escaping_or_a_bad_id_is_refused_not_written() {
        let ok = |id, url, key| {
            render(&Provider {
                id,
                base_url: url,
                env_key: key,
            })
        };
        assert!(ok("gw", "http://127.0.0.1:1/v1", "K").is_ok());
        assert!(ok("gw", "http://x\"\nmodel = \"y", "K").is_err());
        assert!(ok("gw", "http://x", "K\\").is_err());
        assert!(ok("g w", "http://x", "K").is_err());
        assert!(ok("gw]\n[x", "http://x", "K").is_err());
        assert!(ok("", "http://x", "K").is_err());
    }

    #[test]
    fn writing_replaces_a_planted_link_and_never_writes_through_it() {
        let home = dir("link");
        let victim = home.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        std::os::unix::fs::symlink(&victim, home.join(FILE)).unwrap();
        std::os::unix::fs::symlink(&victim, home.join(format!("{FILE}.runner-tmp"))).unwrap();
        write(&home, "new = 1\n").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        let meta = std::fs::symlink_metadata(home.join(FILE)).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(
            std::fs::read_to_string(home.join(FILE)).unwrap(),
            "new = 1\n"
        );
        // Writing again replaces the file.
        write(&home, "again = 2\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join(FILE)).unwrap(),
            "again = 2\n"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
