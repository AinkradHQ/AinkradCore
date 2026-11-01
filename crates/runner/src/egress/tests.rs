//! The proxy against hostile clients and hostile answers, without a sandbox. The sandbox pairs
//! (each vector once with the sandbox on, once off) are in `tests/egress_netns.rs`.

use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;

/// A resolver that answers from a queue (the last answer repeats) and counts its lookups.
struct Stub {
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
    lookups: AtomicUsize,
}

impl Stub {
    fn new(answers: Vec<Vec<IpAddr>>) -> Arc<Stub> {
        Arc::new(Stub {
            answers: Mutex::new(answers.into()),
            lookups: AtomicUsize::new(0),
        })
    }
    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl Resolve for Stub {
    fn resolve<'a>(&'a self, _: &'a str) -> Answers<'a> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let mut q = self.answers.lock().unwrap();
        let a = if q.len() > 1 {
            q.pop_front()
        } else {
            q.front().cloned()
        };
        Box::pin(async move { Ok(a.unwrap_or_default()) })
    }
}

/// A listener that counts connections and greets each one.
async fn listener(ip: &str) -> (u16, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = c.write_all(b"hello-from-target").await;
                let mut b = [0u8; 64];
                while c.read(&mut b).await.is_ok_and(|n| n > 0) {}
            });
        }
    });
    (port, hits)
}

/// Removes a test's directory when the test ends.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Rig {
    proxy: Proxy,
    sock: PathBuf,
    stub: Arc<Stub>,
    _dir: Cleanup,
}

fn rig(name: &str, policy: Policy, stub: Arc<Stub>, limits: Limits) -> Rig {
    let dir = std::env::temp_dir().join(format!("egress-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("s");
    let proxy = start_with(&sock, Arc::new(policy), stub.clone(), limits).unwrap();
    Rig {
        proxy,
        sock,
        stub,
        _dir: Cleanup(dir),
    }
}

async fn ask(sock: &Path, raw: &[u8]) -> String {
    let mut c = UnixStream::connect(sock).await.unwrap();
    // The proxy may refuse and close before the whole request is written.
    let _ = c.write_all(raw).await;
    let mut out = vec![0u8; 512];
    let n = timeout(Duration::from_secs(5), c.read(&mut out))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    String::from_utf8_lossy(&out[..n])
        .lines()
        .next()
        .unwrap_or("")
        .to_owned()
}

fn connect(target: &str) -> Vec<u8> {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn denied_destinations_are_refused_before_anything_is_dialled_or_looked_up() {
    let (allowed, allowed_hits) = listener("127.0.0.2").await;
    let (canary, canary_hits) = listener("127.0.0.1").await;
    let stub = Stub::new(vec![vec![ip("169.254.169.254")]]);
    let policy = Policy::parse(
        "127.0.0.2/32",
        "meta.test",
        &format!("{allowed},{canary},443,25,22,80"),
    )
    .unwrap();
    let r = rig("denied", policy, stub, Limits::default());
    let public = "198.51.100.9";
    let cgnat = Ipv4Addr::new(100, 64, 0, 1);
    let denied = [
        // 1: not in the allow list
        format!("{public}:443"),
        // 2: metadata, literal and by a listed name that resolves to it
        "169.254.169.254:80".to_owned(),
        "[fd00:ec2::254]:80".to_owned(),
        "meta.test:443".to_owned(),
        // 3: the host's loopback in every spelling, and a name the policy does not list
        format!("127.0.0.1:{canary}"),
        format!("[::1]:{canary}"),
        format!("0.0.0.0:{canary}"),
        format!("localhost:{canary}"),
        format!("[::ffff:127.0.0.1]:{canary}"),
        // 5: private, CGNAT, ULA, link-local
        "10.1.2.3:443".to_owned(),
        "192.168.1.1:443".to_owned(),
        format!("{cgnat}:443"),
        "[fd12::1]:443".to_owned(),
        "[fe80::1]:443".to_owned(),
        // 9: IPv6 forms of denied space
        "[64:ff9b::7f00:1]:443".to_owned(),
        "[2002:7f00:1::]:443".to_owned(),
        "[::ffff:10.0.0.1]:443".to_owned(),
        // 12: ports outside the list
        "127.0.0.2:2525".to_owned(),
        "127.0.0.2:0".to_owned(),
    ];
    for target in &denied {
        let got = ask(&r.sock, &connect(target)).await;
        assert!(
            got.contains(" 403 ") || got.contains(" 400 "),
            "{target}: {got}"
        );
    }
    // Only the listed name that resolved into denied space was looked up; nothing was dialled.
    assert_eq!(r.stub.lookups(), 1);
    assert_eq!(r.proxy.dials(), 0);
    assert_eq!(
        (
            allowed_hits.load(Ordering::SeqCst),
            canary_hits.load(Ordering::SeqCst)
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn a_broad_allow_list_still_cannot_reach_reserved_space_or_metadata() {
    let (canary, canary_hits) = listener("127.0.0.1").await;
    let policy = Policy::parse(
        "0.0.0.0/0,::/0,169.254.0.0/16,fd00:ec2::/32",
        "",
        &format!("443,{canary}"),
    )
    .unwrap();
    let r = rig("broad", policy, Stub::new(vec![]), Limits::default());
    for target in [
        "169.254.169.254:443".to_owned(),
        "[fd00:ec2::254]:443".to_owned(),
        format!("127.0.0.1:{canary}"),
        "10.0.0.1:443".to_owned(),
        "[fd00::1]:443".to_owned(),
        "[::ffff:169.254.169.254]:443".to_owned(),
    ] {
        let got = ask(&r.sock, &connect(&target)).await;
        assert!(got.contains(" 403 "), "{target}: {got}");
    }
    assert_eq!(
        (r.proxy.dials(), canary_hits.load(Ordering::SeqCst)),
        (0, 0)
    );
}

#[tokio::test]
async fn an_unlisted_name_never_reaches_the_resolver() {
    let stub = Stub::new(vec![vec![ip("127.0.0.2")]]);
    let policy = Policy::parse("127.0.0.2/32", "model.test", "443").unwrap();
    let r = rig("exfil", policy, stub, Limits::default());
    for name in [
        "c2VjcmV0.attacker.test",
        "model.test.attacker.test",
        "sub.model.test",
        "Model.Test.Evil",
    ] {
        let got = ask(&r.sock, &connect(&format!("{name}:443"))).await;
        assert!(got.contains(" 403 "), "{name}: {got}");
    }
    assert_eq!(r.stub.lookups(), 0, "an unlisted name was looked up");
    // The control: the listed name is looked up, once.
    let got = ask(&r.sock, &connect("model.test:443")).await;
    assert!(got.contains(" 502 ") || got.contains(" 200 "), "{got}");
    assert_eq!(r.stub.lookups(), 1);
}

#[tokio::test]
async fn an_allowed_address_is_tunnelled_by_literal_mapped_form_and_by_name() {
    let (port, hits) = listener("127.0.0.2").await;
    let stub = Stub::new(vec![vec![ip("127.0.0.2")]]);
    let policy = Policy::parse("127.0.0.2/32", "model.test", &port.to_string()).unwrap();
    let r = rig("allow", policy, stub, Limits::default());
    for target in [
        format!("127.0.0.2:{port}"),
        format!("[::ffff:127.0.0.2]:{port}"),
        format!("model.test:{port}"),
        format!("MODEL.TEST.:{port}"),
    ] {
        let mut c = UnixStream::connect(&r.sock).await.unwrap();
        c.write_all(&connect(&target)).await.unwrap();
        let mut got = vec![0u8; 256];
        let mut n = 0;
        while !String::from_utf8_lossy(&got[..n]).contains("hello-from-target") {
            let m = timeout(Duration::from_secs(5), c.read(&mut got[n..]))
                .await
                .unwrap()
                .unwrap();
            assert!(
                m > 0,
                "{target}: closed early: {}",
                String::from_utf8_lossy(&got[..n])
            );
            n += m;
        }
        assert!(
            String::from_utf8_lossy(&got[..n]).starts_with("HTTP/1.1 200 "),
            "{target}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 4);
    assert_eq!(r.stub.lookups(), 2);
}

#[tokio::test]
async fn a_rebinding_answer_never_gets_a_denied_address_dialled() {
    let (good, good_hits) = listener("127.0.0.2").await;
    let (_, canary_hits) = listener("127.0.0.1").await;
    // One CONNECT is one lookup; a later, different answer cannot change that connection, and the
    // denied address in a mixed answer is skipped.
    let stub = Stub::new(vec![
        vec![ip("127.0.0.1"), ip("127.0.0.2")],
        vec![ip("127.0.0.2"), ip("127.0.0.1")],
        vec![ip("127.0.0.1")],
    ]);
    let policy = Policy::parse("127.0.0.2/32", "rebind.test", &good.to_string()).unwrap();
    let r = rig("rebind", policy, stub, Limits::default());
    let mut statuses = vec![];
    for _ in 0..3 {
        statuses.push(ask(&r.sock, &connect(&format!("rebind.test:{good}"))).await);
    }
    assert!(
        statuses[0].contains(" 200 ") && statuses[1].contains(" 200 "),
        "{statuses:?}"
    );
    assert!(
        statuses[2].contains(" 403 "),
        "only a denied address: {statuses:?}"
    );
    assert_eq!(r.stub.lookups(), 3);
    assert_eq!(good_hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        canary_hits.load(Ordering::SeqCst),
        0,
        "a denied address was dialled"
    );
    assert_eq!(r.proxy.dials(), 2);
}

#[tokio::test]
async fn malformed_and_hostile_requests_are_refused_and_never_dial() {
    let (port, hits) = listener("127.0.0.2").await;
    let policy = Policy::parse("127.0.0.2/32", "", &port.to_string()).unwrap();
    let r = rig("hostile", policy, Stub::new(vec![]), Limits::default());
    let ok = format!("CONNECT 127.0.0.2:{port} HTTP/1.1\r\nHost: x\r\n");
    let many = "X: y\r\n".repeat(40);
    let big = format!("X: {}\r\n", "a".repeat(20_000));
    let cases: Vec<(String, &str)> = vec![
        ("GET http://x.test/ HTTP/1.1\r\n\r\n".into(), " 405 "),
        ("POST / HTTP/1.1\r\n\r\n".into(), " 405 "),
        ("CONNECT HTTP/1.1\r\n\r\n".into(), " 400 "),
        (format!("CONNECT 127.0.0.2:{port} HTTP/2\r\n\r\n"), " 400 "),
        ("\u{0}\u{1}\r\n\r\n".into(), " 400 "),
        (format!("CONNECT 127.0.0.2:{port} HTTP/1.1\n\n"), " 400 "),
        (
            format!("CONNECT user@127.0.0.2:{port} HTTP/1.1\r\n\r\n"),
            " 400 ",
        ),
        (
            format!("CONNECT 127.0.0.2:{port}/x HTTP/1.1\r\n\r\n"),
            " 400 ",
        ),
        ("CONNECT 127.0.0.2:99999 HTTP/1.1\r\n\r\n".into(), " 400 "),
        (
            format!("{ok}Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
            " 400 ",
        ),
        (format!("{ok}Content-Length: 5\r\n\r\nhello"), " 400 "),
        (format!("{ok}Host : x\r\n\r\n"), " 400 "),
        (format!("{ok} folded\r\n\r\n"), " 400 "),
        (format!("{ok}{many}\r\n"), " 431 "),
        (format!("{ok}{big}\r\n"), " 431 "),
        // Bytes sent ahead of the 200 are not tunnelled.
        (format!("{ok}\r\nGET / HTTP/1.1\r\n\r\n"), " 400 "),
    ];
    for (raw, want) in cases {
        let got = ask(&r.sock, raw.as_bytes()).await;
        assert!(
            got.contains(want),
            "{want}: {:?} -> {got}",
            &raw[..raw.len().min(60)]
        );
    }
    assert_eq!((hits.load(Ordering::SeqCst), r.proxy.dials()), (0, 0));
    // Still serving.
    assert!(
        ask(&r.sock, &connect(&format!("127.0.0.2:{port}")))
            .await
            .contains(" 200 ")
    );
}

#[tokio::test]
async fn a_slow_head_is_cut_off() {
    let limits = Limits {
        head: Duration::from_millis(300),
        ..Limits::default()
    };
    let r = rig(
        "slow",
        Policy::parse("", "", "").unwrap(),
        Stub::new(vec![]),
        limits,
    );
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(b"CONNECT 127.0").await.unwrap();
    let mut out = Vec::new();
    timeout(Duration::from_secs(5), c.read_to_end(&mut out))
        .await
        .expect("the proxy kept a stalled head")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out).contains(" 408 "),
        "{}",
        String::from_utf8_lossy(&out)
    );
}

#[tokio::test]
async fn connections_are_capped_and_the_proxy_stays_responsive() {
    let (port, _) = listener("127.0.0.2").await;
    let limits = Limits {
        per_run: 4,
        head: Duration::from_secs(30),
        ..Limits::default()
    };
    let r = rig(
        "cap",
        Policy::parse("127.0.0.2/32", "", &port.to_string()).unwrap(),
        Stub::new(vec![]),
        limits,
    );
    let mut held = vec![];
    for _ in 0..4 {
        held.push(UnixStream::connect(&r.sock).await.unwrap());
    }
    // A thousand more: each is closed at once with no reply.
    for _ in 0..1000 {
        let mut c = UnixStream::connect(&r.sock).await.unwrap();
        let mut b = [0u8; 8];
        let n = timeout(Duration::from_secs(5), c.read(&mut b))
            .await
            .expect("an extra connection hung");
        assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
    }
    drop(held);
    // Slots free up as the held clients go away.
    let mut ok = false;
    for _ in 0..50 {
        if ask(&r.sock, &connect(&format!("127.0.0.2:{port}")))
            .await
            .contains(" 200 ")
        {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "the proxy did not recover after the flood");
}

#[tokio::test]
async fn an_idle_tunnel_closes_and_ending_the_proxy_closes_every_tunnel() {
    let (port, _) = listener("127.0.0.2").await;
    let idle = Limits {
        idle: Duration::from_millis(400),
        ..Limits::default()
    };
    let r = rig(
        "idle",
        Policy::parse("127.0.0.2/32", "", &port.to_string()).unwrap(),
        Stub::new(vec![]),
        idle,
    );
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(&connect(&format!("127.0.0.2:{port}")))
        .await
        .unwrap();
    let mut all = Vec::new();
    timeout(Duration::from_secs(5), c.read_to_end(&mut all))
        .await
        .expect("an idle tunnel stayed open")
        .ok();
    drop(r);

    let r = rig(
        "drop",
        Policy::parse("127.0.0.2/32", "", &port.to_string()).unwrap(),
        Stub::new(vec![]),
        Limits::default(),
    );
    let mut c = UnixStream::connect(&r.sock).await.unwrap();
    c.write_all(&connect(&format!("127.0.0.2:{port}")))
        .await
        .unwrap();
    let mut b = [0u8; 256];
    assert!(c.read(&mut b).await.unwrap() > 0);
    drop(r.proxy);
    let mut closed = false;
    for _ in 0..50 {
        if let Ok(Ok(0) | Err(_)) = timeout(Duration::from_millis(200), c.read(&mut b)).await {
            closed = true;
            break;
        }
    }
    assert!(closed, "a tunnel outlived the proxy");
}

#[tokio::test]
async fn the_proxy_refuses_to_start_without_a_socket_it_can_own() {
    let policy = Arc::new(Policy::parse("", "", "").unwrap());
    assert!(start(Path::new("/nonexistent-dir/egress.sock"), policy.clone()).is_err());
    let dir = std::env::temp_dir().join(format!("egress-twice-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let first = start(&dir.join("s"), policy.clone()).unwrap();
    assert!(
        start(&dir.join("s"), policy).is_err(),
        "a socket in use was taken over"
    );
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(dir.join("s")).unwrap().permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
    drop(first);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_sandbox_env_names_the_socket_the_forwarder_and_the_port() {
    let env = sandbox_env(
        Path::new("/run/e.sock"),
        Path::new("/usr/bin/ainkrad-runner"),
    );
    let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "AINKRAD_SANDBOX_EGRESS_SOCK",
            "AINKRAD_SANDBOX_EGRESS_FWD",
            "AINKRAD_SANDBOX_EGRESS_PORT"
        ]
    );
    assert_eq!(env[2].1, "47832");
    assert_eq!(EGRESS_PORT, crate::mcp_bridge::FORWARD_PORT + 1);
}
