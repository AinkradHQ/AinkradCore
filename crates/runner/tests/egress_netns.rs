//! E8a-01.4: the filtered sandbox against the hostile vectors of the design note, each as a pair:
//! what the real bubblewrap sandbox cannot do, and the same thing done from the host (the control),
//! so a refusal cannot be an artefact of the stand-ins. Counters are read before and after the run,
//! and every sandbox result is parsed from that run's own output.
//!
//! Stand-ins: the cloud metadata address cannot be bound on a test host, so the control for
//! metadata, public, LAN and DNS-resolver destinations is a loopback listener the sandbox tries
//! directly (and, through the proxy, the real address is refused). The harnesses themselves
//! (vector 13) are not run here; the proxy variables they must honour are asserted in
//! `crates/harness/src/sandbox/egress_tests.rs`.
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ainkrad_runner::egress::{self, Answers, Limits, Policy, Resolve};
use ainkrad_runner::mcp_bridge::{self, Target};

type Log = Arc<Mutex<Vec<u8>>>;

/// A listener that counts connections, records what it is sent and greets (17 bytes).
fn listener(ip: &str) -> (u16, Arc<AtomicUsize>, Log) {
    let l = TcpListener::bind((ip, 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    let (hits, got): (Arc<AtomicUsize>, Log) = Default::default();
    let (h, g) = (hits.clone(), got.clone());
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            h.fetch_add(1, Ordering::SeqCst);
            let g = g.clone();
            std::thread::spawn(move || {
                let _ = c.write_all(b"hello-from-target");
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
    (port, hits, got)
}

/// Answers every HTTP request with 200, counting them.
fn mcp_server() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let h = h.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0u8; 512];
                    match c.read(&mut chunk) {
                        Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                    while let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        buf.drain(..p + 4);
                        h.fetch_add(1, Ordering::SeqCst);
                        let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nmcp-ok");
                    }
                }
            });
        }
    });
    (port, hits)
}

/// Resolves the test names and remembers every name it was asked for.
struct Names {
    asked: Mutex<Vec<String>>,
}

impl Resolve for Names {
    fn resolve<'a>(&'a self, name: &'a str) -> Answers<'a> {
        self.asked.lock().unwrap().push(name.to_owned());
        let ip = |s: &str| s.parse().unwrap();
        let answer = match name {
            "model.test" => vec![ip("127.0.0.2")],
            "meta.test" => vec![ip("169.254.169.254")],
            "loop.test" => vec![ip("127.0.0.1")],
            "mixed.test" => vec![ip("127.0.0.1"), ip("127.0.0.2")],
            _ => vec![],
        };
        Box::pin(async move { Ok(answer) })
    }
}

fn run_host(script: &str) -> String {
    let out = std::process::Command::new("/bin/bash")
        .args(["-c", script])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `key=value` lines of a script's output.
fn parse(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

const PRELUDE: &str = r#"
via() { local t=$1 l b g
  exec 3<>/dev/tcp/127.0.0.1/47832 2>/dev/null || { echo noproxy; return; }
  printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$t" "$t" >&3
  read -r -t 5 l <&3; l=${l%$'\r'}
  case $l in *" 200 "*) read -r -t 5 b <&3; read -r -t 3 -N 17 g <&3;; esac
  exec 3>&-; echo "$l|$g"; }
direct() { if timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then echo reached; else echo unreachable; fi; }
rc() { "$@" >/dev/null 2>&1; echo $?; }
for i in $(seq 60); do exec 3<>/dev/tcp/127.0.0.1/47832 2>/dev/null && break; sleep 0.2; done; exec 3>&-
"#;

#[tokio::test]
async fn the_filtered_sandbox_refuses_every_vector_and_the_controls_succeed() {
    let probe = std::process::Command::new("/usr/bin/bwrap")
        .args(["--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"])
        .output();
    assert!(
        probe.is_ok_and(|o| o.status.success()),
        "bubblewrap cannot run here: the egress test must not be skipped"
    );
    let root = std::env::temp_dir().join(format!("egress-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["work", "config", "tmp", "outside"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    let root = root.canonicalize().unwrap();

    let (target, target_hits, _) = listener("127.0.0.2");
    let (canary, canary_hits, _) = listener("127.0.0.1");
    let (mcp_port, mcp_hits) = mcp_server();
    let (tcp_dns, dns_hits, _) = listener("127.0.0.1");
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_port = udp.local_addr().unwrap().port();
    udp.set_read_timeout(Some(std::time::Duration::from_millis(50)))
        .unwrap();
    // Host sockets a sandbox must not reach: an abstract unix socket and a path socket outside its binds.
    let abstract_name = format!("egress-netns-{}", std::process::id());
    let abstract_sock =
        UnixListener::bind_addr(&UnixAddr::from_abstract_name(&abstract_name).unwrap()).unwrap();
    let path_sock_at = root.join("outside/host.sock");
    let path_sock = UnixListener::bind(&path_sock_at).unwrap();
    let unix_hits = Arc::new(AtomicUsize::new(0));
    for l in [abstract_sock, path_sock] {
        let h = unix_hits.clone();
        std::thread::spawn(move || {
            for _ in l.incoming().flatten() {
                h.fetch_add(1, Ordering::SeqCst);
            }
        });
    }

    let names = Arc::new(Names {
        asked: Mutex::new(vec![]),
    });
    let policy = Policy::parse(
        "127.0.0.2/32",
        "model.test,meta.test,loop.test,mixed.test",
        &format!("443,{target},{canary},{mcp_port}"),
    )
    .unwrap();
    let sock = root.join("egress.sock");
    let proxy =
        egress::start_with(&sock, Arc::new(policy), names.clone(), Limits::default()).unwrap();
    let mcp_sock = root.join("mcp.sock");
    let _bridge = mcp_bridge::start(
        &mcp_sock,
        Target {
            host: "127.0.0.1".into(),
            port: mcp_port,
            tls: false,
            authority: format!("127.0.0.1:{mcp_port}"),
            path: "/token/citadel/v1/mcp".into(),
        },
        None,
    )
    .unwrap();

    let exe = PathBuf::from(env!("CARGO_BIN_EXE_ainkrad-runner"));
    let mut env: Vec<(String, std::ffi::OsString)> = vec![
        ("AINKRAD_SANDBOX".into(), "1".into()),
        ("AINKRAD_SANDBOX_TMP".into(), root.join("tmp").into()),
        ("AINKRAD_SANDBOX_NETWORK".into(), "filtered".into()),
        ("AINKRAD_SANDBOX_MCP_SOCK".into(), mcp_sock.clone().into()),
        ("AINKRAD_SANDBOX_MCP_FWD".into(), exe.clone().into()),
        (
            "AINKRAD_SANDBOX_MCP_PORT".into(),
            mcp_bridge::FORWARD_PORT.to_string().into(),
        ),
    ];
    env.extend(egress::sandbox_env(&sock, &exe));
    let spec = ainkrad_harness::Spec {
        cwd: root.join("work"),
        config_dir: root.join("config"),
        env,
        ..ainkrad_harness::Spec::default()
    };

    let public = "198.51.100.9";
    let cgnat = Ipv4Addr::new(100, 64, 0, 1);
    let proxied: Vec<(&str, String)> = vec![
        ("v1_public", format!("{public}:443")),
        ("v2_meta4", "169.254.169.254:80".into()),
        ("v2_meta6", "[fd00:ec2::254]:80".into()),
        ("v2_meta_name", "meta.test:443".into()),
        ("v3_loop4", format!("127.0.0.1:{canary}")),
        ("v3_loop6", format!("[::1]:{canary}")),
        ("v3_any", format!("0.0.0.0:{canary}")),
        ("v3_localhost", format!("localhost:{canary}")),
        ("v3_loop_name", format!("loop.test:{canary}")),
        ("v5_rfc1918a", "10.1.2.3:443".into()),
        ("v5_rfc1918b", "192.168.1.1:443".into()),
        ("v5_cgnat", format!("{cgnat}:443")),
        ("v5_ula", "[fd12::1]:443".into()),
        ("v7_exfil", "c2VjcmV0.unlisted.test:443".into()),
        ("v8_mixed", format!("mixed.test:{target}")),
        ("v9_mapped_loop", format!("[::ffff:127.0.0.1]:{canary}")),
        ("v9_nat64", "[64:ff9b::7f00:1]:443".into()),
        ("v9_6to4", "[2002:7f00:1::]:443".into()),
        ("v9_mapped_lan", "[::ffff:10.0.0.1]:443".into()),
        ("v9_mapped_ok", format!("[::ffff:127.0.0.2]:{target}")),
        ("v12_smtp", "127.0.0.2:25".into()),
        ("v12_ssh", "127.0.0.2:22".into()),
        ("v13_named", format!("model.test:{target}")),
        ("v14_mcp_via_proxy", format!("127.0.0.1:{mcp_port}")),
    ];
    let mut script = String::from(PRELUDE);
    for (label, t) in &proxied {
        script += &format!("echo \"P_{label}=$(via '{t}')\"\n");
    }
    script += &format!(
        r#"
echo "D_canary=$(direct 127.0.0.1 {canary})"
echo "D_target=$(direct 127.0.0.2 {target})"
echo "D_meta=$(direct 169.254.169.254 80)"
echo "D_public=$(direct {public} 443)"
echo "D_lan=$(direct 10.1.2.3 443)"
echo "D_cgnat=$(direct {cgnat} 443)"
echo "D_meta6=$(direct fd00:ec2::254 80)"
echo "D_dns_tcp=$(direct 127.0.0.1 {tcp_dns})"
echo "D_dns_route=$(direct 192.0.2.53 53)"
printf x >/dev/udp/127.0.0.1/{udp_port} 2>/dev/null; echo "D_dns_udp=sent"
exec 4<>/dev/tcp/127.0.0.1/47831
printf 'POST /token/citadel/v1/mcp HTTP/1.1\r\nHost: 127.0.0.1:47831\r\nContent-Length: 0\r\n\r\n' >&4
read -r -t 5 m <&4; echo "M_mcp=${{m%$'\r'}}"
PY='import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(2)
a=sys.argv[1]; a=b"\0"+a[1:].encode() if a[0]=="@" else a
try:
    s.connect(a); print("reached")
except Exception:
    print("unreachable")'
echo "U_abstract=$(python3 -c "$PY" '@{abstract_name}')"
echo "U_path=$(python3 -c "$PY" '{path_sock}')"
echo "T_iplink=$(rc ip link set lo down)"
echo "T_iproute=$(rc ip route add 10.9.9.0/24 dev lo)"
echo "T_nft=$(rc nft add table inet x)"
echo "T_unshare_net=$(rc unshare -n true)"
echo "T_unshare_user=$(rc unshare -Ur true)"
echo "T_mount=$(rc mount -t tmpfs none /tmp)"
echo "T_sockdir=$(rc touch "$(dirname "$AINKRAD_EGRESS_SOCK")/x")"
echo "T_rmsock=$(rc rm -f "$AINKRAD_EGRESS_SOCK")"
echo "E_proxy=$HTTPS_PROXY $NO_PROXY $NODE_USE_ENV_PROXY"
echo "E_resolv=$(ls /etc/resolv.conf /etc/hosts 2>&1 | grep -c 'No such file')"
"#,
        path_sock = path_sock_at.display(),
    );

    let before = (
        canary_hits.load(Ordering::SeqCst),
        target_hits.load(Ordering::SeqCst),
        dns_hits.load(Ordering::SeqCst),
        mcp_hits.load(Ordering::SeqCst),
    );
    let mut cmd = ainkrad_harness::sandbox_command(
        std::ffi::OsStr::new("/bin/bash"),
        &["-c".into(), script],
        &spec,
    );
    cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    let out = tokio::time::timeout(std::time::Duration::from_secs(180), cmd.output())
        .await
        .expect("sandbox run timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let err = String::from_utf8_lossy(&out.stderr);
    let got = parse(&text);
    let v = |k: &str| {
        got.get(k)
            .unwrap_or_else(|| panic!("no result for {k}: {text} {err}"))
            .clone()
    };

    // The proxied vectors: refused, with the status alone.
    for (label, t) in &proxied {
        let r = v(&format!("P_{label}"));
        let allowed = matches!(*label, "v8_mixed" | "v9_mapped_ok" | "v13_named");
        if allowed {
            assert_eq!(
                r, "HTTP/1.1 200 Connection Established|hello-from-target",
                "{label} {t}"
            );
        } else {
            assert!(r.starts_with("HTTP/1.1 403 "), "{label} {t}: {r}");
        }
    }
    // Only the three allowed connections were ever dialled; nothing denied touched a listener.
    assert_eq!(
        proxy.dials(),
        3,
        "an upstream was dialled for a denied destination"
    );
    assert_eq!(target_hits.load(Ordering::SeqCst) - before.1, 3);
    assert_eq!(
        canary_hits.load(Ordering::SeqCst) - before.0,
        0,
        "v3/v8: the host loopback was reached"
    );
    // v7: the exfil name never reached the resolver; the listed names did.
    let asked = names.asked.lock().unwrap().clone();
    assert!(
        !asked
            .iter()
            .any(|n| n.contains("unlisted") || n == "localhost"),
        "{asked:?}"
    );
    assert_eq!(
        asked.iter().filter(|n| *n == "meta.test").count(),
        1,
        "{asked:?}"
    );

    // Direct attempts from inside: no interface reaches the host, whatever the destination.
    for k in [
        "D_canary",
        "D_target",
        "D_meta",
        "D_meta6",
        "D_public",
        "D_lan",
        "D_cgnat",
        "D_dns_tcp",
        "D_dns_route",
    ] {
        assert_eq!(v(k), "unreachable", "{k}");
    }
    assert_eq!(
        dns_hits.load(Ordering::SeqCst),
        0,
        "v6: a resolver stand-in was reached"
    );
    let mut buf = [0u8; 8];
    assert!(
        udp.recv_from(&mut buf).is_err(),
        "v6: a UDP datagram left the sandbox"
    );
    assert_eq!(
        unix_hits.load(Ordering::SeqCst),
        0,
        "v4: a host unix socket was reached"
    );
    assert_eq!(v("U_abstract"), "unreachable");
    assert_eq!(v("U_path"), "unreachable");
    // v14: the MCP route works beside the filter, and sent through the proxy it is refused (above).
    assert_eq!(v("M_mcp"), "HTTP/1.1 200 OK");
    assert_eq!(mcp_hits.load(Ordering::SeqCst) - before.3, 1);
    // v10: nothing that changes the namespace, the routes or the mounts works (found, and failed).
    for k in [
        "iplink",
        "iproute",
        "nft",
        "unshare_net",
        "unshare_user",
        "mount",
        "sockdir",
        "rmsock",
    ] {
        let rc: i32 = v(&format!("T_{k}")).parse().unwrap();
        assert!(
            (1..=126).contains(&rc),
            "T_{k}: exit {rc} (0 worked, 127 not found)"
        );
    }
    // The proxy variables are set, and no resolver config is bound.
    assert_eq!(v("E_proxy"), "http://127.0.0.1:47832 127.0.0.1,localhost 1");
    assert_eq!(v("E_resolv"), "2");

    // ---- The controls: the same things from the host, no sandbox.
    let control = parse(&run_host(&format!(
        r#"{PRELUDE_DIRECT}
echo "D_canary=$(direct 127.0.0.1 {canary})"
echo "D_target=$(direct 127.0.0.2 {target})"
echo "D_dns_tcp=$(direct 127.0.0.1 {tcp_dns})"
printf x >/dev/udp/127.0.0.1/{udp_port}; echo "D_dns_udp=sent"
PY='import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(2)
a=sys.argv[1]; a=b"\0"+a[1:].encode() if a[0]=="@" else a
try:
    s.connect(a); print("reached")
except Exception:
    print("unreachable")'
echo "U_abstract=$(python3 -c "$PY" '@{abstract_name}')"
echo "U_path=$(python3 -c "$PY" '{path_sock}')"
echo "T_iplink=$(rc unshare -Urn ip link set lo up)"
echo "T_iproute=$(rc unshare -Urn sh -c 'ip link set lo up && ip route add 10.9.9.0/24 dev lo')"
echo "T_nft=$(rc unshare -Urn nft add table inet x)"
echo "T_unshare_net=$(rc unshare -Urn true)"
echo "T_unshare_user=$(rc unshare -Ur true)"
echo "T_mount=$(rc unshare -Urm mount -t tmpfs none /mnt)"
d={work}; echo "T_sockdir=$(rc touch "$d/x")"
touch {work}/s; echo "T_rmsock=$(rc rm -f {work}/s)"
"#,
        path_sock = path_sock_at.display(),
        work = root.join("work").display(),
    )));
    // The same addresses the sandbox could not reach (metadata v4 and v6, a documentation-range
    // "public" address, private, CGNAT), made real on the loopback of a private user+network
    // namespace with a listener each: from there, with no sandbox, every one connects.
    let stand_ins = parse(&run_host(&format!(
        r#"unshare -Urn python3 -c '
import socket, subprocess
addrs = ["169.254.169.254", "198.51.100.9", "10.1.2.3", "{cgnat}", "fd00:ec2::254"]
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
for a in addrs:
    v6 = ":" in a
    subprocess.run(["ip", "addr", "add", a + ("/128" if v6 else "/32"), "dev", "lo"] + (["nodad"] if v6 else []), check=True)
for a in addrs:
    fam = socket.AF_INET6 if ":" in a else socket.AF_INET
    l = socket.socket(fam); l.bind((a, 8099)); l.listen(1)
    c = socket.socket(fam); c.settimeout(2)
    try:
        c.connect((a, 8099)); print("C_" + a + "=reached")
    except Exception:
        print("C_" + a + "=unreachable")
'"#
    )));
    let cgnat_text = cgnat.to_string();
    for a in [
        "169.254.169.254",
        "198.51.100.9",
        "10.1.2.3",
        cgnat_text.as_str(),
        "fd00:ec2::254",
    ] {
        assert_eq!(stand_ins[&format!("C_{a}")], "reached", "control for {a}");
    }
    for k in ["D_canary", "D_target", "D_dns_tcp", "U_abstract", "U_path"] {
        assert_eq!(control[k], "reached", "control {k}");
    }
    for k in [
        "iplink",
        "iproute",
        "nft",
        "unshare_net",
        "unshare_user",
        "mount",
        "sockdir",
        "rmsock",
    ] {
        assert_eq!(control[&format!("T_{k}")], "0", "control T_{k}");
    }
    assert!(canary_hits.load(Ordering::SeqCst) >= 1);
    assert!(dns_hits.load(Ordering::SeqCst) >= 1);
    assert!(
        udp.recv_from(&mut buf).is_ok(),
        "control: the UDP datagram was not delivered"
    );
    assert!(unix_hits.load(Ordering::SeqCst) >= 2);
    let _ = std::fs::remove_dir_all(root);
}

const PRELUDE_DIRECT: &str = r#"
direct() { if timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then echo reached; else echo unreachable; fi; }
rc() { "$@" >/dev/null 2>&1; echo $?; }
"#;

#[tokio::test]
async fn the_start_up_self_test_passes_on_a_host_that_can_filter() {
    let policy = Policy::parse("", "model.test", "443").unwrap();
    egress::selftest(
        &policy,
        std::path::Path::new(env!("CARGO_BIN_EXE_ainkrad-runner")),
    )
    .await
    .expect("the self-test must pass here");
}
