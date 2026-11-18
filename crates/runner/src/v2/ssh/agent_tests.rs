//! The Mac-direct agent (Y6-01): host binding with real russh clients against two fixture hosts, the
//! protocol's refusals, revoke, a TTL under a faked clock, the uid check, and what is on disk.

use ainkrad_proto::v2::AgentKey;
use russh::client;
use russh::keys::agent::client::AgentClient;

use super::super::fixture::*;
use super::super::{Verify, config};
use super::*;

fn req(id: &str, ttl: u32, keys: Vec<(&str, Vec<String>)>) -> SshAgentLoad {
    SshAgentLoad {
        id: id.to_owned(),
        ttl_secs: ttl,
        keys: keys
            .into_iter()
            .map(|(lease, pins)| AgentKey {
                lease: lease.to_owned(),
                pinned_keys: pins,
            })
            .collect(),
    }
}

/// A driver whose leases `l_1`, `l_2`... are fresh keys, and the keys.
fn driver(n: usize) -> (SshDriver, Vec<PrivateKey>) {
    let leases = Leases::default();
    let keys = (1..=n).map(|i| leases.key(&format!("l_{i}"))).collect();
    (ssh(&leases), keys)
}

/// A fake clock the test moves.
fn fake() -> (Clock, Arc<Mutex<Instant>>) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let n = Arc::clone(&now);
    (Arc::new(move || *n.lock().unwrap()), now)
}

async fn ask(s: &mut UnixStream, msg: &[u8]) -> Vec<u8> {
    let mut frame = (msg.len() as u32).to_be_bytes().to_vec();
    frame.extend(msg);
    s.write_all(&frame).await.unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.unwrap();
    let mut out = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut out).await.unwrap();
    out
}

fn bind_msg(host: &PrivateKey, sid: &[u8], signer: &PrivateKey, forwarded: u8) -> Vec<u8> {
    let mut m = vec![27];
    put(&mut m, b"session-bind@openssh.com");
    put(&mut m, &host.public_key().to_bytes().unwrap());
    put(&mut m, sid);
    let sig: Signature = Signer::try_sign(signer, sid).unwrap();
    put(&mut m, &Vec::<u8>::try_from(sig).unwrap());
    m.push(forwarded);
    m
}

fn userauth(sid: &[u8], user: &PrivateKey) -> Vec<u8> {
    let mut d = Vec::new();
    put(&mut d, sid);
    d.push(50);
    put(&mut d, b"me");
    put(&mut d, b"ssh-connection");
    put(&mut d, b"publickey");
    d.push(1);
    put(&mut d, b"ssh-ed25519");
    put(&mut d, &user.public_key().to_bytes().unwrap());
    d
}

fn sign_msg(user: &PrivateKey, data: &[u8]) -> Vec<u8> {
    let mut m = vec![13];
    put(&mut m, &user.public_key().to_bytes().unwrap());
    put(&mut m, data);
    m.extend(0u32.to_be_bytes());
    m
}

async fn connect(sock: &str) -> UnixStream {
    UnixStream::connect(sock).await.unwrap()
}

/// Binds `s` to a session of `host` (the host key signs the session id, as ssh's does).
async fn bound(s: &mut UnixStream, host: &PrivateKey, sid: &[u8]) {
    assert_eq!(ask(s, &bind_msg(host, sid, host, 0)).await, [SUCCESS]);
}

/// Logs in to `server` the way ssh does: bind the agent to the session, then ask it to sign.
async fn login(server: &Server, sock: &str, key: &PrivateKey) -> bool {
    let tcp = TcpStream::connect(("127.0.0.1", server.port))
        .await
        .unwrap();
    let verify = Verify {
        pinned: server.pin(),
        seen: Arc::default(),
    };
    let mut handle = client::connect_stream(config(false), tcp, verify)
        .await
        .unwrap();
    let mut agent = AgentClient::connect_uds(sock).await.unwrap();
    if let Some(b) = handle.agent_session_binding() {
        // An agent that refuses the bind answers failure; ssh goes on, and so do we.
        let _ = agent.bind_session(b, false).await;
    }
    let done = handle
        .authenticate_publickey_with("me", key.public_key().clone(), None, &mut agent)
        .await;
    matches!(done, Ok(r) if r.success())
}

use tokio::net::TcpStream;

#[tokio::test]
async fn ssh_to_the_bound_host_works_and_to_another_host_through_the_same_socket_is_refused() {
    let (d, keys) = driver(1);
    let (a, b) = (serve("A", true).await, serve("B", true).await);
    let loaded = d
        .agent_load(&req("ld_1", 3600, vec![("l_1", a.pin())]))
        .await
        .unwrap();
    assert!(login(&a, &loaded.socket, &keys[0]).await, "the bound host");
    assert!(
        !login(&b, &loaded.socket, &keys[0]).await,
        "the second host signed"
    );
    let done = d.agent_drop(&SshAgentDrop { id: "ld_1".into() });
    assert_eq!((done.signatures, done.was_live), (1, true));
    assert!(done.refused >= 1, "the refusal was not counted");
}

#[tokio::test]
async fn a_jump_key_signs_only_for_the_jump_and_the_target_key_only_for_the_target() {
    let (d, keys) = driver(2);
    let (jump, target) = (serve("J", true).await, serve("T", true).await);
    let pins = vec![("l_1", jump.pin()), ("l_2", target.pin())];
    let loaded = d.agent_load(&req("ld_1", 3600, pins)).await.unwrap();
    assert!(login(&jump, &loaded.socket, &keys[0]).await);
    assert!(login(&target, &loaded.socket, &keys[1]).await);
    assert!(!login(&jump, &loaded.socket, &keys[1]).await);
    assert!(!login(&target, &loaded.socket, &keys[0]).await);
}

#[tokio::test]
async fn the_protocol_offers_no_way_in_or_out_for_a_key() {
    let (d, keys) = driver(1);
    let host = new_key();
    let sock = d
        .agent_load(&req("ld_1", 3600, vec![("l_1", vec![fp(&host)])]))
        .await
        .unwrap()
        .socket;
    let mut s = connect(&sock).await;
    // Identities: the public key, nothing more.
    let ids = ask(&mut s, &[11]).await;
    assert_eq!(ids[0], IDENTITIES);
    assert!(!ids.windows(8).any(|w| w == b"PRIVATE "));
    // Add, remove, remove all, lock, unlock, an unknown extension: all refused.
    for m in [vec![17], vec![18], vec![19], vec![22], vec![23], vec![25]] {
        assert_eq!(ask(&mut s, &m).await, [FAILURE], "message {m:?}");
    }
    let mut ext = vec![27];
    put(&mut ext, b"query");
    assert_eq!(ask(&mut s, &ext).await, [FAILURE]);
    // Unbound: no signature, for well-formed userauth data too.
    let data = userauth(b"sid-1", &keys[0]);
    assert_eq!(ask(&mut s, &sign_msg(&keys[0], &data)).await, [FAILURE]);
    // A frame that is too large ends the connection.
    s.write_all(&(1u32 << 20).to_be_bytes()).await.unwrap();
    assert_eq!(s.read(&mut [0u8; 1]).await.unwrap_or(0), 0);
}

#[tokio::test]
async fn a_bind_must_be_signed_by_the_host_key_not_forwarded_and_for_a_pinned_host() {
    let (d, keys) = driver(1);
    let (host, other) = (new_key(), new_key());
    let sock = d
        .agent_load(&req("ld_1", 3600, vec![("l_1", vec![fp(&host)])]))
        .await
        .unwrap()
        .socket;
    let mut s = connect(&sock).await;
    // The pinned host's key presented, but the session id signed by somebody else.
    assert_eq!(
        ask(&mut s, &bind_msg(&host, b"sid", &other, 0)).await,
        [FAILURE]
    );
    // A forwarded bind (ssh -A): the remote host could use the key.
    assert_eq!(
        ask(&mut s, &bind_msg(&host, b"sid", &host, 1)).await,
        [FAILURE]
    );
    // A host key nobody pinned, properly signed.
    assert_eq!(
        ask(&mut s, &bind_msg(&other, b"sid", &other, 0)).await,
        [FAILURE]
    );
    // None of those bound anything.
    let data = userauth(b"sid", &keys[0]);
    assert_eq!(ask(&mut s, &sign_msg(&keys[0], &data)).await, [FAILURE]);
    // The real bind works, and its signature verifies under the user's key.
    bound(&mut s, &host, b"sid").await;
    let r = ask(&mut s, &sign_msg(&keys[0], &data)).await;
    assert_eq!(r[0], SIGN_RESPONSE);
    let wire = Rd(&r[1..]).string().unwrap();
    let sig = Signature::try_from(wire).unwrap();
    Verifier::<Signature>::verify(keys[0].public_key(), &data, &sig).unwrap();
}

#[tokio::test]
async fn only_ssh_userauth_data_for_the_bound_session_is_signed() {
    let (d, keys) = driver(1);
    let host = new_key();
    let sock = d
        .agent_load(&req("ld_1", 3600, vec![("l_1", vec![fp(&host)])]))
        .await
        .unwrap()
        .socket;
    let mut s = connect(&sock).await;
    bound(&mut s, &host, b"sid").await;
    // Arbitrary bytes, a userauth request of another session, another service, another method.
    let other_sid = userauth(b"other", &keys[0]);
    let mut service = Vec::new();
    for (sid, svc, method) in [
        (&b"sid"[..], &b"ssh-userauth"[..], &b"publickey"[..]),
        (&b"sid"[..], &b"ssh-connection"[..], &b"password"[..]),
    ] {
        put(&mut service, sid);
        service.push(50);
        put(&mut service, b"me");
        put(&mut service, svc);
        put(&mut service, method);
        assert_eq!(ask(&mut s, &sign_msg(&keys[0], &service)).await, [FAILURE]);
        service.clear();
    }
    for data in [b"hello".to_vec(), other_sid] {
        assert_eq!(ask(&mut s, &sign_msg(&keys[0], &data)).await, [FAILURE]);
    }
    // Hash flags (RSA) are not honoured.
    let mut m = sign_msg(&keys[0], &userauth(b"sid", &keys[0]));
    let n = m.len();
    m[n - 1] = 2;
    assert_eq!(ask(&mut s, &m).await, [FAILURE]);
}

#[tokio::test]
async fn a_drop_closes_connections_and_the_socket_within_two_seconds() {
    let (d, keys) = driver(1);
    let host = new_key();
    let sock = d
        .agent_load(&req("ld_1", 3600, vec![("l_1", vec![fp(&host)])]))
        .await
        .unwrap()
        .socket;
    let mut s = connect(&sock).await;
    bound(&mut s, &host, b"sid").await;
    let data = userauth(b"sid", &keys[0]);
    assert_eq!(
        ask(&mut s, &sign_msg(&keys[0], &data)).await[0],
        SIGN_RESPONSE
    );
    let t = Instant::now();
    let done = d.agent_drop(&SshAgentDrop { id: "ld_1".into() });
    assert_eq!((done.was_live, done.signatures), (true, 1));
    let eof = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 1]))
        .await
        .expect("the connection stayed open");
    assert_eq!(eof.unwrap_or(0), 0);
    let dir = Path::new(&sock).parent().unwrap().to_owned();
    while dir.exists() {
        assert!(t.elapsed() < Duration::from_secs(2), "the directory stayed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(UnixStream::connect(&sock).await.is_err());
    // Dropping again is not an error.
    assert!(!d.agent_drop(&SshAgentDrop { id: "ld_1".into() }).was_live);
}

#[tokio::test]
async fn the_ttl_ends_the_agent_under_a_faked_clock() {
    let (d, keys) = driver(1);
    let host = new_key();
    let (clock, now) = fake();
    let sock = d
        .load_agent(
            &req("ld_1", 60, vec![("l_1", vec![fp(&host)])]),
            clock,
            None,
        )
        .await
        .unwrap()
        .socket;
    let mut s = connect(&sock).await;
    bound(&mut s, &host, b"sid").await;
    let data = userauth(b"sid", &keys[0]);
    assert_eq!(
        ask(&mut s, &sign_msg(&keys[0], &data)).await[0],
        SIGN_RESPONSE
    );
    *now.lock().unwrap() += Duration::from_secs(59);
    assert_eq!(
        ask(&mut s, &sign_msg(&keys[0], &data)).await[0],
        SIGN_RESPONSE
    );
    *now.lock().unwrap() += Duration::from_secs(2);
    // Past the deadline: refused on the very next request, then the connection and socket go.
    assert_eq!(ask(&mut s, &sign_msg(&keys[0], &data)).await, [FAILURE]);
    let eof = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 1])).await;
    assert_eq!(eof.expect("still open").unwrap_or(0), 0);
    let done = d.agent_drop(&SshAgentDrop { id: "ld_1".into() });
    assert_eq!((done.was_live, done.signatures), (false, 2));
}

#[tokio::test]
async fn a_peer_with_another_uid_is_closed_before_a_byte_is_read() {
    let (d, _) = driver(1);
    // No test can become another user; the directory's owner is made someone else instead.
    let sock = d
        .load_agent(
            &req("ld_1", 3600, vec![("l_1", vec![fp(&new_key())])]),
            Arc::new(Instant::now),
            Some(u32::MAX - 7),
        )
        .await
        .unwrap()
        .socket;
    let mut s = connect(&sock).await;
    let _ = s.write_all(&[0, 0, 0, 1, 11]).await;
    let got = tokio::time::timeout(Duration::from_secs(2), s.read(&mut [0u8; 16])).await;
    assert_eq!(got.expect("not closed").unwrap_or(0), 0, "an answer came");
}

#[tokio::test]
async fn nothing_but_a_socket_and_public_settings_is_on_disk_with_private_modes() {
    let (d, _) = driver(1);
    let l = d
        .agent_load(&req("ld_1", 3600, vec![("l_1", vec![fp(&new_key())])]))
        .await
        .unwrap();
    let dir = Path::new(&l.socket).parent().unwrap().to_owned();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(Path::new(&l.socket)), 0o600);
    assert_eq!(mode(Path::new(&l.config)), 0o600);
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["agent.sock", "ssh_config"]);
    let config = std::fs::read_to_string(&l.config).unwrap();
    assert!(!config.contains("PRIVATE") && !config.contains("l_1"));
    assert!(config.contains(&format!("IdentityAgent \"{}\"", l.socket)));
    assert!(config.contains("ForwardAgent no") && config.contains("PasswordAuthentication no"));
    d.agent_drop(&SshAgentDrop { id: "ld_1".into() });
}

#[tokio::test]
async fn a_bad_request_is_refused_before_any_lease_is_redeemed() {
    let leases = Leases::default();
    leases.key("l_1");
    let d = ssh(&leases);
    let pin = || vec![fp(&new_key())];
    let five: Vec<_> = (0..5).map(|_| ("l_1", pin())).collect();
    for bad in [
        req("", 60, vec![("l_1", pin())]),
        req("a b", 60, vec![("l_1", pin())]),
        req("ld", 0, vec![("l_1", pin())]),
        req("ld", SSH_AGENT_MAX_TTL_SECS + 1, vec![("l_1", pin())]),
        req("ld", 60, vec![]),
        req("ld", 60, five),
        req("ld", 60, vec![("l_1", vec![])]),
        req("ld", 60, vec![("l_1", vec!["MD5:abc".into()])]),
    ] {
        let e = d.agent_load(&bad).await.unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs, "{bad:?}");
    }
    assert_eq!(leases.redeemed.load(SeqCst), 0);
    // A lease that cannot be redeemed, and an id already live.
    let e = d.agent_load(&req("ld", 60, vec![("l_x", pin())])).await;
    assert_eq!(e.unwrap_err().code, ErrorCode::SshAuthFailed);
    d.agent_load(&req("ld", 60, vec![("l_1", pin())]))
        .await
        .unwrap();
    leases.key("l_2");
    let e = d.agent_load(&req("ld", 60, vec![("l_2", pin())])).await;
    assert_eq!(e.unwrap_err().code, ErrorCode::InvalidArgs);
}

#[tokio::test(start_paused = true)]
async fn five_minutes_without_the_core_ends_every_agent_but_a_return_in_time_does_not() {
    let (d, _) = driver(2);
    for id in ["ld_1", "ld_2"] {
        let lease = if id == "ld_1" { "l_1" } else { "l_2" };
        d.agent_load(&req(id, 3600, vec![(lease, vec![fp(&new_key())])]))
            .await
            .unwrap();
    }
    d.link_lost();
    d.link_lost(); // a failed redial does not restart the countdown
    tokio::time::advance(Duration::from_secs(200)).await;
    d.link_up();
    tokio::time::advance(Duration::from_secs(400)).await;
    let back = d.agent_drop(&SshAgentDrop { id: "ld_1".into() });
    assert!(back.was_live, "a link that came back ended the agent");
    d.link_lost();
    tokio::time::advance(Duration::from_secs(299)).await;
    tokio::task::yield_now().await;
    assert!(!*d.agents.live.lock().unwrap()["ld_2"].stop.borrow());
    tokio::time::advance(Duration::from_secs(2)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(!d.agent_drop(&SshAgentDrop { id: "ld_2".into() }).was_live);
}
