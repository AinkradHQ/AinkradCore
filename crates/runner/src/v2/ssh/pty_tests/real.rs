//! Y2-02 against real OpenSSH in Podman (`#[ignore]`: it needs them): a key login with resize and
//! the remote exit code, the host-key fingerprint OpenSSH itself prints, and a password and a
//! keyboard-interactive (PAM) login typed in the terminal. Run:
//! `cargo test -p ainkrad-runner --lib -- --ignored real_openssh_terminal`.

use super::*;

#[tokio::test]
#[ignore = "needs throwaway OpenSSH containers (LEYLINE_IT_*)"]
async fn real_openssh_terminal_key_password_and_keyboard_interactive() {
    let env = |k: &str| std::env::var(format!("LEYLINE_IT_{k}")).unwrap_or_else(|_| panic!("{k}"));
    let key = std::fs::read_to_string(env("KEY_TEXT_FILE")).unwrap();
    let pass = env("PASS");
    let hop = |port: &str, fp: &str, pinned: bool| PtyHop {
        host: "127.0.0.1".to_owned(),
        port: env(port).parse().unwrap(),
        user: "it".to_owned(),
        pinned_keys: if pinned { vec![env(fp)] } else { vec![] },
        key: key.clone(),
    };
    let one = |h: PtyHop| Params { hops: vec![h] };

    // Key login: output, resize (the remote pty is what `stty size` reports), the exit code.
    let rig = Rig::start(one(hop("A", "A_FP", true)));
    rig.shown.until("$").await;
    rig.type_("echo hi-$((6*7))\r");
    rig.shown.until("hi-42").await;
    rig.resize.send((40, 132)).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    rig.type_("stty size\r");
    rig.shown.until("40 132").await;
    rig.type_("exit 3\r");
    assert_eq!(rig.code().await, 3);

    // A host key that is not pinned: the fingerprint is OpenSSH's, and nothing was authenticated.
    let rig = Rig::start(one(hop("A", "A_FP", false)));
    let shown = rig.shown.clone();
    assert_eq!(rig.code().await, SSH_PTY_EXIT_HOST_KEY_UNKNOWN);
    assert!(shown.text().contains(&env("A_FP")), "{:?}", shown.text());

    // Password (the key is not authorised there) and keyboard-interactive (PAM).
    for (port, fp) in [("P", "P_FP"), ("K", "K_FP")] {
        let rig = Rig::start(one(hop(port, fp, true)));
        rig.shown.until("assword").await;
        rig.type_(&format!("{pass}\r"));
        rig.shown.until("$").await;
        rig.type_("echo ok-$((1+1))\r");
        rig.shown.until("ok-2").await;
        assert!(!rig.shown.text().contains(&pass), "the password was echoed");
        rig.type_("exit\r");
        assert_eq!(rig.code().await, 0, "{port}");
    }
}
