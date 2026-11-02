//! KAN-416 on macOS: a Seatbelt `none` shell against a real `sandbox-exec`, each refusal with a
//! host-network control. Best effort by design (see the sandbox residual-risk spec): TCP, a
//! file-path unix socket and the Mach name-resolution service are refused.
#![cfg(target_os = "macos")]

use std::io::Write;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_runner::v2::termbox::{Net, wrap_net};

async fn shell(net: &Net, script: &str) -> String {
    let (launcher, args) = wrap_net(
        &[],
        &[],
        "/bin/bash",
        &["-c".to_owned(), script.to_owned()],
        "/",
        net,
    )
    .unwrap();
    let out = tokio::process::Command::new(launcher)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[tokio::test]
async fn a_none_shell_reaches_neither_tcp_nor_a_path_socket() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for mut c in tcp.incoming().flatten() {
            h.fetch_add(1, Ordering::SeqCst);
            let _ = c.write_all(b"hello");
        }
    });
    let path = std::env::temp_dir().join(format!("termnet-mac-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let unix = UnixListener::bind(&path).unwrap();
    let uhits = Arc::new(AtomicUsize::new(0));
    let u = uhits.clone();
    std::thread::spawn(move || {
        for _ in unix.incoming().flatten() {
            u.fetch_add(1, Ordering::SeqCst);
        }
    });
    let probe = format!(
        "(exec 9<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null && echo TCP-OPEN || echo TCP-REFUSED; \
         printf x | /usr/bin/nc -w 2 -U {} >/dev/null 2>&1 && echo UNIX-OPEN || echo UNIX-REFUSED",
        path.display()
    );
    let host = shell(&Net::Host, &probe).await;
    assert!(
        host.contains("TCP-OPEN") && host.contains("UNIX-OPEN"),
        "control: {host}"
    );
    let (t0, u0) = (hits.load(Ordering::SeqCst), uhits.load(Ordering::SeqCst));
    let none = shell(&Net::None, &probe).await;
    assert!(none.contains("TCP-REFUSED"), "{none}");
    assert!(none.contains("UNIX-REFUSED"), "{none}");
    assert_eq!(
        (t0, u0),
        (hits.load(Ordering::SeqCst), uhits.load(Ordering::SeqCst))
    );
    let _ = std::fs::remove_file(&path);
}
