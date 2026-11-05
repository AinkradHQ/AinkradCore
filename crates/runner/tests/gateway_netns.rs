//! KAN-435: the auth gateway under the real bubblewrap sandbox. The start-up check that gates the
//! `gateway` capability passes for real; the slot is reachable when the network is denied and
//! when it is filtered; the key is nowhere a harness can look; a host-network session cannot be
//! built with the slot at all. On Linux CI these fail, never skip, when the sandbox cannot run.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{Ceiling, GatewayAuth, GatewayGrant, ModelPrice, Rate, Upstream, Wire};
use ainkrad_runner::egress::{self, Policy};
use ainkrad_runner::gateway::dial::Dialer;
use ainkrad_runner::gateway::wiring;
use ainkrad_runner::gateway::{self, Config, Key};
use zeroize::Zeroizing;

fn require_sandbox() {
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .status();
    assert!(
        probe.is_ok_and(|s| s.success()),
        "bubblewrap cannot run here: the gateway test must not be skipped"
    );
}

fn exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ainkrad-runner"))
}

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("gwn-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["work", "config", "tmp", "s"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    root.canonicalize().unwrap()
}

#[tokio::test]
async fn the_start_up_check_passes_under_real_bubblewrap_and_fails_clearly_when_it_cannot() {
    require_sandbox();
    let agents = scratch("selftest").join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    gateway::selftest(&agents, &exe())
        .await
        .expect("the gateway start-up check passes on this host");
    // A state directory that leaves no room for a session's socket is refused, by name.
    let long = PathBuf::from(format!("/{}", "a".repeat(90)));
    let why = gateway::selftest(&long, &exe()).await.unwrap_err();
    assert!(why.contains("shorter state directory"), "{why}");
}

/// A gateway on a socket under `root`, for a made-up grant and a key built at runtime.
fn serve(root: &Path, key: &str) -> gateway::Gateway {
    let grant = GatewayGrant {
        lease: String::new(),
        account: 1,
        provider: "anthropic".to_owned(),
        user_key: None,
        upstream: Upstream {
            host: "api.anthropic.com".to_owned(),
            base_path: String::new(),
            wire: Wire::AnthropicMessages,
            auth: GatewayAuth::XApiKey,
        },
        models: vec!["m".to_owned()],
        prices: vec![ModelPrice {
            model: "m".to_owned(),
            input: 1,
            output: 1,
            cache_read: 1,
            cache_write: 1,
        }],
        ceiling: Ceiling {
            tokens: 1,
            usd_micros: 1,
        },
        rate: Rate {
            per_minute: 1,
            concurrent: 1,
        },
    };
    let cfg = Config::new(
        &grant,
        Key::new(Zeroizing::new(key.to_owned())).unwrap(),
        Arc::new(Dialer::new(vec![])),
    )
    .unwrap();
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
    // The receiver is dropped: reports are not looked at here.
    gateway::start(&gateway::socket_in(&root.join("s")), cfg, tx).unwrap()
}

/// Runs `script` in a sandbox with the gateway's slot, in network mode `mode`.
fn run(root: &Path, mode: &str, extra: Vec<(String, std::ffi::OsString)>, script: &str) -> String {
    run_with(root, mode, extra, &[], script)
}

/// [`run`], with `vars` set in the harness's own environment (what the runner wires for it).
fn run_with(
    root: &Path,
    mode: &str,
    extra: Vec<(String, std::ffi::OsString)>,
    vars: &[(String, std::ffi::OsString)],
    script: &str,
) -> String {
    let sock = gateway::socket_in(&root.join("s"));
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), mode.into()),
    ];
    env.extend(gateway::sandbox_env(&sock, &exe()));
    env.extend(extra);
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env,
        ..ainkrad_harness::Spec::default()
    };
    let mut cmd = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), script.into()],
        &spec,
    );
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.envs(vars.iter().map(|(n, v)| (n, v)));
    let out = cmd
        .into_std()
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the sandbox ran");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn ask() -> String {
    format!(
        r#"for i in $(seq 100); do exec 3<>/dev/tcp/127.0.0.1/{} 2>/dev/null && break; sleep 0.1; done
printf 'GET /nope HTTP/1.1\r\nHost: x\r\n\r\n' >&3; read -r -t 5 l <&3; echo "gw=${{l%$'\r'}}"
"#,
        gateway::GW_PORT
    )
}

#[tokio::test]
async fn the_slot_is_reachable_denied_and_filtered_and_the_key_is_nowhere_inside() {
    require_sandbox();
    let key = format!("sk-ant-{}", "z7".repeat(12));
    for mode in ["deny", "filtered"] {
        let root = scratch(mode);
        let _gw = serve(&root, &key);
        let mut extra = vec![];
        let _egress;
        if mode == "filtered" {
            let policy = Policy::parse("", "", "443").unwrap();
            let sock = egress::socket_in(&root.join("s"));
            _egress = egress::start(&sock, Arc::new(policy)).unwrap();
            extra = egress::sandbox_env(&sock, &exe());
        }
        let script = format!(
            "{}\nenv | grep -c '{key}' ; cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n' | grep -c '{key}'; grep -rl '{key}' /tmp /proc/self/cwd 2>/dev/null | wc -l",
            ask()
        );
        let said = tokio::task::spawn_blocking({
            let root = root.clone();
            move || run(&root, mode, extra, &script)
        })
        .await
        .unwrap();
        assert!(said.contains("gw=HTTP/1.1 403 "), "{mode}: {said}");
        let counts: Vec<&str> = said.lines().skip(1).collect();
        assert_eq!(counts, ["0", "0", "0"], "{mode}: the key is visible inside");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_host_network_session_cannot_be_built_with_the_slot() {
    require_sandbox();
    let root = scratch("allow");
    let _gw = serve(&root, &format!("sk-ant-{}", "z7".repeat(12)));
    let sock = gateway::socket_in(&root.join("s"));
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), "allow".into()),
    ];
    env.extend(gateway::sandbox_env(&sock, &exe()));
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env,
        ..ainkrad_harness::Spec::default()
    };
    let cmd = ainkrad_harness::sandbox_command(std::ffi::OsStr::new("/bin/true"), &[], &spec);
    assert_eq!(
        cmd.as_std().get_program(),
        "/nonexistent/ainkrad-sandbox-refused"
    );
}

/// A POST to the gateway at `$1` (a port), path `$2`, with the header line `$3` and body `$4`;
/// prints `<$5>=<status line>`. The forwarder may take a moment to listen.
const POST: &str = r#"post() {
  for i in $(seq 100); do exec 3<>/dev/tcp/127.0.0.1/$1 2>/dev/null && break; sleep 0.1; done
  printf 'POST %s HTTP/1.1\r\nHost: x\r\n%s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s' "$2" "$3" "${#4}" "$4" >&3
  read -r -t 5 l <&3; echo "$5=${l%$'\r'}"; exec 3<&-
}
"#;

#[tokio::test]
async fn the_base_url_and_config_the_runner_writes_reach_the_slot_and_hold_no_key() {
    require_sandbox();
    let key = format!("sk-ant-{}", "z7".repeat(12));
    let root = scratch("wired");
    let _gw = serve(&root, &key);
    let config = root.join("config");
    let port = gateway::GW_PORT;
    // What the runner writes for Claude (env) and for Codex (env and `config.toml`), as it does
    // for a gateway session, then handed to the harness's own environment.
    let (mut vars, mut allow) = (vec![], vec![]);
    wiring::wire("claude", port, &config, &mut vars, &mut allow).unwrap();
    let mut codex = vec![];
    wiring::wire("codex", port, &config, &mut codex, &mut allow).unwrap();
    vars.extend(codex);
    vars.push(("CODEX_HOME".into(), config.clone().into()));
    // This grant is for Anthropic and does not name these models, so each request is refused with
    // a 403 before anything is dialled: the status line shows it reached the gateway, on the URL
    // the runner wrote and with the placeholder, which is all that is on the harness's side.
    let script = format!(
        r#"{POST}
post "${{ANTHROPIC_BASE_URL##*:}}" '/v1/messages?beta=true' "x-api-key: $ANTHROPIC_API_KEY" '{{"model":"unpriced","max_tokens":1}}' claude
line=$(grep '^base_url' "$CODEX_HOME/config.toml"); p=${{line##*127.0.0.1:}}
post "${{p%%/*}}" /v1/responses "Authorization: Bearer $OPENAI_API_KEY" '{{"model":"unpriced","stream":true}}' codex
echo "keys=$ANTHROPIC_API_KEY,$OPENAI_API_KEY"
env | grep -c '{key}'; grep -rl '{key}' "$CODEX_HOME" /tmp 2>/dev/null | wc -l"#
    );
    let said = tokio::task::spawn_blocking({
        let root = root.clone();
        move || run_with(&root, "deny", vec![], &vars, &script)
    })
    .await
    .unwrap();
    assert!(said.contains("claude=HTTP/1.1 403 "), "{said}");
    assert!(said.contains("codex=HTTP/1.1 403 "), "{said}");
    assert!(said.contains("keys=placeholder,placeholder"), "{said}");
    let counts: Vec<&str> = said.lines().skip(3).collect();
    assert_eq!(counts, ["0", "0"], "the key is visible inside: {said}");
}
