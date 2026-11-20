use super::*;

fn origin() -> Origin {
    Origin {
        terminal: Some("t1".into()),
        session: None,
        project: Some(7),
        folder: Some(PathBuf::from("/w/p")),
        net: Net::Allow,
    }
}

#[test]
fn the_sandbox_network_goes_with_every_request_and_defaults_to_deny() {
    // E15 H2: a `deny` session's job must stay local, a `filtered` one keeps its own list.
    let ok = json!({"argv": ["cargo", "build"], "cwd": "/w/p", "env": {}});
    let sent = |net: Net| -> Value {
        let o = Origin { net, ..origin() };
        serde_json::from_slice(&build(&ok, &o).unwrap()).unwrap()
    };
    let d = sent(Net::default());
    assert_eq!((&d["network"], &d["hosts"]), (&json!("deny"), &Value::Null));
    let f = sent(Net::Filtered(vec!["crates.io".into()]));
    assert_eq!(
        (&f["network"], &f["hosts"]),
        (&json!("filtered"), &json!(["crates.io"]))
    );
    assert_eq!(sent(Net::Allow)["network"], "allow");
    assert_eq!(Net::from_mode(None, Vec::new), Net::Deny);
    assert_eq!(Net::from_mode(Some("none"), Vec::new), Net::Deny);
    assert_eq!(Net::from_mode(Some("bogus"), Vec::new), Net::Deny);
    assert_eq!(Net::from_mode(Some("host"), Vec::new), Net::Allow);
    assert_eq!(
        Net::from_mode(Some("filtered"), || vec!["pypi.org".into()]),
        Net::Filtered(vec!["pypi.org".into()])
    );
}

#[test]
fn shims_are_linked_and_found_first_on_path() {
    let dir = std::env::temp_dir().join(format!("ainkrad-shims-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("ainkrad-job");
    std::fs::write(&shim, "x").unwrap();
    let bin = install_shims(&dir, &shim).unwrap();
    for n in SHIM_NAMES {
        assert!(bin.join(n).is_file(), "{n}");
    }
    install_shims(&dir, &shim).unwrap();
    let env = shim_env(Some("/usr/bin"), &bin, Path::new("/s/job.sock"));
    assert!(env[0].1.starts_with(&format!("{}:/usr/bin", bin.display())));
    assert_eq!(env[2], ("AINKRAD_JOB_SOCK".into(), "/s/job.sock".into()));
    assert!(
        shim_env(None, &bin, Path::new("/s"))[0]
            .1
            .ends_with(":/usr/bin:/bin")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_request_is_checked_and_its_env_filtered() {
    let ok = json!({"argv": ["cargo", "test"], "cwd": "/w/p", "tty": true,
        "env": {"CI": "1", "AWS_SECRET_ACCESS_KEY": "x"}});
    let first: Value = serde_json::from_slice(&build(&ok, &origin()).unwrap()).unwrap();
    assert_eq!(
        (&first["terminal"], &first["project"], &first["cwd_rel"]),
        (&json!("t1"), &json!(7), &json!(""))
    );
    let deeper = json!({"argv": ["make"], "cwd": "/w/p/app/x", "env": {}});
    let b: Value = serde_json::from_slice(&build(&deeper, &origin()).unwrap()).unwrap();
    assert_eq!(b["cwd_rel"], "app/x");
    // Outside the sandbox's folder, or a sandbox with none: the shim runs the tool itself.
    let outside = json!({"argv": ["make"], "cwd": "/w/other", "env": {}});
    assert!(build(&outside, &origin()).is_none());
    let home = Origin {
        folder: None,
        ..origin()
    };
    assert!(build(&deeper, &home).is_none());
    assert_eq!(first["env"], json!({"CI": "1"}));
    assert_eq!(first["tty"], true);
    for bad in [
        json!({"argv": [], "cwd": "/w"}),
        json!({"argv": ["cargo"], "cwd": "w"}),
        json!({"argv": ["cargo", 1], "cwd": "/w"}),
        json!({"argv": [""], "cwd": "/w"}),
        json!({"cwd": "/w"}),
    ] {
        assert!(build(&bad, &origin()).is_none(), "{bad}");
    }
}

#[test]
fn shim_frames_and_job_ids_are_checked() {
    assert_eq!(
        parse_ask(r#"{"t":"signal","sig":"INT"}"#),
        Some(Ask::Signal("INT"))
    );
    assert_eq!(parse_ask(r#"{"t":"cancel"}"#), Some(Ask::Cancel));
    assert_eq!(parse_ask(r#"{"t":"signal","sig":"KILL"}"#), None);
    assert!(job_id_ok("j_abc123"));
    assert!(!job_id_ok("j_../x") && !job_id_ok("x_abc") && !job_id_ok("j_"));
    assert_eq!(
        signal_call("j_a", &Ask::Cancel).path,
        "/api/v1/runner/jobs/j_a/signal"
    );
}

#[test]
fn the_shim_and_the_endpoint_agree_on_env_names() {
    let shim = include_str!("../bin/ainkrad-job.rs");
    for n in ENV_ALLOW {
        assert!(shim.contains(&format!("\"{n}\"")), "{n}");
    }
}

fn fake(reply: Vec<&'static str>, seen: Arc<Mutex<Vec<(String, String)>>>) -> Upstream {
    Arc::new(move |call: Call| {
        let (reply, seen) = (reply.clone(), Arc::clone(&seen));
        Box::pin(async move {
            seen.lock().unwrap().push((
                call.path.clone(),
                String::from_utf8_lossy(&call.body).into_owned(),
            ));
            let (tx, body) = mpsc::channel(8);
            if call.path == JOBS_PATH {
                for l in reply {
                    tx.send(Ok(l.as_bytes().to_vec())).await.unwrap();
                }
                // Held open until the test ends: a job that has not exited.
                std::mem::forget(tx);
            }
            Ok(crate::workspace::relay::Reply {
                status: if call.path == JOBS_PATH { 201 } else { 204 },
                content_type: "application/x-ndjson".into(),
                body,
            })
        })
    })
}

async fn talk(up: Upstream, send: &str) -> (UnixStream, tempdir::Guard) {
    let dir = tempdir::Guard::new();
    let socks = JobSocks::new(dir.0.clone(), up);
    let sock = socks.open("t1", origin()).await.unwrap();
    let mut c = UnixStream::connect(&sock).await.unwrap();
    c.write_all(send.as_bytes()).await.unwrap();
    (c, dir)
}

mod tempdir {
    pub struct Guard(pub std::path::PathBuf);
    impl Guard {
        pub fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "ainkrad-jobsock-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            ));
            Self(p)
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[tokio::test]
async fn a_remote_job_is_streamed_through_and_a_signal_reaches_the_core() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let up = fake(
        vec![
            "{\"verdict\":\"remote\",\"job\":\"j_a1\",\"device_name\":\"box\"}\n{\"t\":\"state\",\"state\":\"running\"}\n",
        ],
        Arc::clone(&seen),
    );
    let (c, _g) = talk(
        up,
        "{\"argv\":[\"cargo\",\"build\"],\"cwd\":\"/w/p\",\"tty\":false,\"env\":{}}\n",
    )
    .await;
    let (rd, mut wr) = c.into_split();
    let mut rd = BufReader::new(rd);
    let v = line(&mut rd, 4096).await.unwrap();
    assert!(v.contains("\"remote\""));
    assert!(line(&mut rd, 4096).await.unwrap().contains("running"));
    wr.write_all(b"{\"t\":\"signal\",\"sig\":\"TERM\"}\n")
        .await
        .unwrap();
    for _ in 0..50 {
        if seen
            .lock()
            .unwrap()
            .iter()
            .any(|(p, _)| p.ends_with("/j_a1/signal"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls[0].0, JOBS_PATH);
    assert!(calls[0].1.contains("\"terminal\":\"t1\""));
    assert!(
        calls
            .iter()
            .any(|(p, b)| p.ends_with("/j_a1/signal") && b.contains("TERM"))
    );
}

#[tokio::test]
async fn a_bad_request_is_told_to_run_locally() {
    let up = fake(vec![], Arc::new(Mutex::new(Vec::new())));
    let (c, _g) = talk(up, "{\"argv\":[]}\n").await;
    let mut rd = BufReader::new(c);
    assert!(line(&mut rd, 4096).await.unwrap().contains("\"local\""));
}
