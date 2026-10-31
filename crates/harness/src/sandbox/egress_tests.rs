//! The bubblewrap argument list for each network mode (E8a-01): a network namespace for every
//! value but the literal `allow`, and a filtered sandbox that cannot be built without its proxy.
#![cfg(target_os = "linux")]

use super::tests::fixture;
use super::*;

fn argv(spec: &Spec) -> io::Result<Vec<String>> {
    compile(OsStr::new("/bin/true"), &[], spec).map(|c| {
        c.as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    })
}

fn set(spec: &mut Spec, pairs: &[(&str, &str)]) {
    for (k, v) in pairs {
        spec.env.retain(|(n, _)| n != k);
        spec.env.push(((*k).into(), (*v).into()));
    }
}

const EGRESS: [(&str, &str); 3] = [
    ("AINKRAD_SANDBOX_EGRESS_SOCK", "/run/run-1/egress.sock"),
    ("AINKRAD_SANDBOX_EGRESS_FWD", "/usr/bin/ainkrad-runner"),
    ("AINKRAD_SANDBOX_EGRESS_PORT", "47832"),
];

fn has(args: &[String], seq: &[&str]) -> bool {
    args.windows(seq.len()).any(|w| w == seq)
}

#[test]
fn every_network_value_but_allow_gets_its_own_namespace() {
    let (_, mut spec) = fixture("egress-argv");
    for mode in ["deny", "", "lan", "ALLOW", "allow ", "filtered", "host"] {
        set(&mut spec, &[("AINKRAD_SANDBOX_NETWORK", mode)]);
        set(&mut spec, &EGRESS);
        let args = argv(&spec).unwrap_or_else(|e| panic!("{mode}: {e}"));
        assert!(args.iter().any(|a| a == "--unshare-net"), "{mode}");
    }
    set(&mut spec, &[("AINKRAD_SANDBOX_NETWORK", "allow")]);
    assert!(!argv(&spec).unwrap().iter().any(|a| a == "--unshare-net"));
    // The only place the flag is added is behind the `!= "allow"` guard.
    let source = include_str!("../sandbox.rs");
    assert_eq!(source.matches("\"--unshare-net\"").count(), 1);
    assert!(source.contains("\"AINKRAD_SANDBOX_NETWORK\") != \"allow\" {"));
}

#[test]
fn a_filtered_sandbox_without_its_proxy_socket_is_refused() {
    let (_, mut spec) = fixture("egress-missing");
    set(&mut spec, &[("AINKRAD_SANDBOX_NETWORK", "filtered")]);
    assert!(argv(&spec).is_err());
    for skip in 0..3 {
        let mut partial = spec.clone();
        set(
            &mut partial,
            &EGRESS
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, p)| *p)
                .collect::<Vec<_>>(),
        );
        assert!(argv(&partial).is_err(), "without part {skip}");
    }
    // The refusal reaches the caller as a command that cannot start.
    let cmd = command(OsStr::new("/bin/true"), &[], &spec);
    assert_eq!(
        cmd.as_std().get_program(),
        "/nonexistent/ainkrad-sandbox-refused"
    );
}

#[test]
fn a_filtered_sandbox_reaches_only_the_proxy_and_has_no_resolver_config() {
    let (_, mut spec) = fixture("egress-filtered");
    set(&mut spec, &[("AINKRAD_SANDBOX_NETWORK", "filtered")]);
    set(&mut spec, &EGRESS);
    let args = argv(&spec).unwrap();
    assert!(has(
        &args,
        &["--bind", "/run/run-1/egress.sock", "/run/run-1/egress.sock"]
    ));
    assert!(has(&args, &["--setenv", "AINKRAD_EGRESS_PORT", "47832"]));
    for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        assert!(
            has(&args, &["--setenv", k, "http://127.0.0.1:47832"]),
            "{k}"
        );
    }
    assert!(has(&args, &["--setenv", "NO_PROXY", "127.0.0.1,localhost"]));
    assert!(has(&args, &["--setenv", "NODE_USE_ENV_PROXY", "1"]));
    for p in ["/etc/resolv.conf", "/etc/hosts"] {
        assert!(
            !args.iter().any(|a| a == p),
            "{p} is bound into a filtered sandbox"
        );
    }
    // The deny mode keeps what it had, and gains no proxy.
    set(&mut spec, &[("AINKRAD_SANDBOX_NETWORK", "deny")]);
    let deny = argv(&spec).unwrap();
    assert!(!deny.iter().any(|a| a.contains("PROXY")));
}
