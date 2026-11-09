//! E8a-01.4 controls for vectors 1, 2 and 5: the metadata addresses (v4 and v6), a "public"
//! documentation-range address, a private and a CGNAT address, made real on the loopback of a
//! private user and network namespace with a listener each. With no sandbox every one connects,
//! so the sandbox's failure to reach them (`egress_netns.rs`) is the sandbox, not the stand-in.
#![cfg(target_os = "linux")]

use std::collections::HashMap;

#[test]
fn every_stand_in_address_connects_when_no_sandbox_is_in_the_way() {
    let cgnat = std::net::Ipv4Addr::new(100, 64, 0, 1).to_string();
    let script = format!(
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
    );
    let out = std::process::Command::new("/bin/bash")
        .args(["-c", &script])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let got: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once('=')).collect();
    for a in [
        "169.254.169.254",
        "198.51.100.9",
        "10.1.2.3",
        cgnat.as_str(),
        "fd00:ec2::254",
    ] {
        assert_eq!(
            got.get(format!("C_{a}").as_str()),
            Some(&"reached"),
            "control for {a}: {text} {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
