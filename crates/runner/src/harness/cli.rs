//! The run-scoped `citadel` CLI (E15.18 step 3, decision #59): a small script in every run's
//! private dir, first on its harness's `PATH`, so an agent runs its Citadel tools from its own
//! shell, JSON in and out, and chains many in one command (`citadel batch`, pipes): only the
//! command's final output enters its context, not every call and result.
//!
//! It posts to the server's `/mcp/v1/call/<op>` (the MCP gate, the run token, the same tools,
//! permission checks, redaction and audit). The token is read from the run's private 0600
//! `token` file, beside its MCP config, named by `CITADEL_RUN_TOKEN_FILE` (`CITADEL_RUN_TOKEN`
//! overrides it when set): the token itself is never put in the harness's environment, which
//! every process it starts inherits and a warm server keeps from its first run. curl reads it
//! as a config file on fd 3, never from argv.
//!
//! The script is one per runner (`<work root>/private/bin/citadel`), rewritten only when it
//! changes: macOS checks a new executable on its first run (about 0.25 s), which a script
//! written per run would pay every run.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The script; `__URL__` is filled in, single-quoted.
const SCRIPT: &str = r#"#!/bin/sh
# citadel: this run's Citadel tools from your shell, JSON in and JSON out.
#   citadel schema                    your operations, one line each: (args) what it does
#   citadel <op> ['<json args>' | -]  one operation; - reads the args from stdin
#   citadel batch < ops.json          [{"op": "...", "args": {...}}, ...] in order, stopping
#                                     at the first failure; prints every result
set -eu
url=__URL__
op=${1:-}
case $op in
'' | -h | --help | help) sed -n '2,6s/^# \{0,1\}//p' "$0"; exit 0 ;;
*[!a-z_]*) echo "citadel: no operation '$op' (citadel schema lists them)" >&2; exit 2 ;;
esac
shift
token=${CITADEL_RUN_TOKEN:-$(cat "${CITADEL_RUN_TOKEN_FILE:?citadel: no run token}")}
if [ "$op" = batch ] || [ "${1:-}" = - ]; then
    body=$(cat)
else
    body=${1:-'{}'}
fi
printf '%s' "$body" | curl -sS --fail-with-body -K /dev/fd/3 \
    -H 'Content-Type: application/json' --data-binary @- "$url/call/$op" 3<<CITADEL_CONFIG
header = "Authorization: Bearer $token"
CITADEL_CONFIG
echo
"#;

/// What every run with the CLI is told, after its own instructions.
pub(super) const SKILL: &str = "\n\n## Citadel from your shell\n\n\
`citadel` (on your PATH) runs your Citadel tools from the shell, JSON in and out: \
`citadel schema` lists your operations, `citadel <op> '<json>'` runs one, and \
`citadel batch < ops.json` runs `[{\"op\": ..., \"args\": {...}}, ...]` in order. When a task \
takes many steps (filing a plan, moving or updating many issues), prefer it to one tool call \
per step: chain the steps in one command and filter the output (`| jq`, `| python3`) so only \
what you need comes back. A planner files a whole plan with `citadel apply_plan -` and the \
plan's JSON on stdin.\n";

/// `s` single-quoted for `sh`.
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The script for the MCP endpoint `url`.
fn script(url: &str) -> String {
    SCRIPT.replace("__URL__", &quoted(url))
}

/// Installs the script for `url` as `<root>/bin/citadel` (0700) unless it is there already, and
/// returns its dir.
pub(super) fn install(root: &Path, url: &str) -> io::Result<PathBuf> {
    let bin = root.join("bin");
    DirBuilder::new().recursive(true).mode(0o700).create(&bin)?;
    let path = bin.join("citadel");
    let script = script(url);
    if std::fs::read(&path).ok().as_deref() == Some(script.as_bytes()) {
        return Ok(bin);
    }
    let part = bin.join(format!("citadel.{}.part", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o700)
        .open(&part)?;
    file.write_all(script.as_bytes())?;
    drop(file);
    std::fs::rename(&part, &path)?;
    Ok(bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_names_its_endpoint_quoted() {
        let s = script("http://127.0.0.1:7/mcp/v1?it's");
        assert!(s.contains(r"url='http://127.0.0.1:7/mcp/v1?it'\''s'"));
        assert!(!s.contains("__"), "every placeholder filled");
    }
}
