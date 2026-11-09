//! E8a-01.4 vector 11: a descriptor the runner leaked into the sandbox launcher (a connected socket to
//! a host service) is not usable from inside; the same descriptor is, with no sandbox. Bubblewrap
//! passes inherited descriptors through, so the sandbox script closes them first.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// A listener that records everything it is sent.
fn listener() -> (u16, Arc<Mutex<Vec<u8>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let got: Arc<Mutex<Vec<u8>>> = Arc::default();
    let g = got.clone();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let g = g.clone();
            std::thread::spawn(move || {
                let _ = c.write_all(b"hi");
                let mut b = [0u8; 256];
                while let Ok(n) = c.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    g.lock().unwrap().extend_from_slice(&b[..n]);
                }
            });
        }
    });
    (port, got)
}

fn parse(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// v11: a socket the runner leaked into the sandbox's launcher (a connected descriptor to a host
/// service) is not usable from inside; the same descriptor is, with no sandbox.
#[tokio::test]
async fn an_inherited_descriptor_does_not_reach_the_agent() {
    let root = std::env::temp_dir().join(format!("egress-fd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["work", "config", "tmp"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    let root = root.canonicalize().unwrap();
    let (port, received) = listener();
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env: vec![
            ("AINKRAD_SANDBOX".into(), "1".into()),
            ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
            ("AINKRAD_SANDBOX_NETWORK".into(), "deny".into()),
        ],
        ..ainkrad_harness::Spec::default()
    };
    let probe =
        r#"echo "FDS=$(ls /proc/$$/fd | tr '\n' ' ')"; echo leak >&5 2>/dev/null; echo "WRITE=$?""#;
    let launcher = format!(
        "exec 5<>/dev/tcp/127.0.0.1/{port}; exec 6<>/dev/tcp/127.0.0.1/{port}; exec \"$@\""
    );
    let sandbox = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), probe.into()],
        &spec,
    );
    let std_cmd = sandbox.as_std();
    let mut wrapped = tokio::process::Command::new("/bin/bash");
    wrapped
        .args(["-c", &launcher, "launcher"])
        .arg(std_cmd.get_program())
        .args(std_cmd.get_args())
        .env("PATH", "/usr/bin:/bin");
    for (k, val) in std_cmd.get_envs() {
        match val {
            Some(val) => wrapped.env(k, val),
            None => wrapped.env_remove(k),
        };
    }
    let out = tokio::time::timeout(std::time::Duration::from_secs(60), wrapped.output())
        .await
        .expect("timed out")
        .unwrap();
    let got = parse(&String::from_utf8_lossy(&out.stdout));
    let fds: Vec<&str> = got["FDS"].split_whitespace().collect();
    assert!(
        !fds.contains(&"5") && !fds.contains(&"6"),
        "leaked descriptors: {fds:?}"
    );
    assert_ne!(got["WRITE"], "0", "a leaked socket accepted a write");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(
        received.lock().unwrap().is_empty(),
        "the host service received data from the sandbox"
    );

    // Control: the same launcher and probe, no sandbox.
    let out = std::process::Command::new("/bin/bash")
        .args(["-c", &launcher, "launcher", "/bin/bash", "-c", probe])
        .output()
        .unwrap();
    let got = parse(&String::from_utf8_lossy(&out.stdout));
    assert!(
        got["FDS"].split_whitespace().any(|f| f == "5"),
        "control: {got:?}"
    );
    assert_eq!(got["WRITE"], "0");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(
        !received.lock().unwrap().is_empty(),
        "control: no data arrived"
    );
    let _ = std::fs::remove_dir_all(root);
}
