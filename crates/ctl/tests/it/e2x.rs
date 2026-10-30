//! The E2 fault scenarios (E2-17.2): each drives `scripts/e2-exit.sh fault <name>` (the real Core, runner, ptyhost
//! and ainkradctl) and passes only when the script's asserted outcome for that fault is PASS. `#[ignore]`d (they wait
//! on real timeouts): `make e2-exit-faults` runs them one at a time.

use std::path::Path;
use std::process::Command;

fn fault(name: &str) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/e2-exit.sh");
    let out = Command::new(script)
        .args(["fault", name])
        .env(
            "E2_BIN",
            Path::new(env!("CARGO_BIN_EXE_ainkradctl"))
                .parent()
                .unwrap(),
        )
        .output()
        .expect("run scripts/e2-exit.sh");
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find(|l| l.starts_with(&format!("FAULT {name}: ")))
        .unwrap_or_else(|| {
            panic!(
                "no FAULT line:\n{text}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
    println!("{line}");
    assert!(line.starts_with(&format!("FAULT {name}: PASS")), "{line}");
}

macro_rules! faults {
    ($($name:ident),*) => {$(
        #[test]
        #[ignore = "E2 fault suite: make e2-exit-faults"]
        fn $name() {
            fault(stringify!($name));
        }
    )*};
}

faults!(
    core_kill,
    runner_kill,
    host_kill,
    network_cut,
    slow_client,
    disk_full
);
