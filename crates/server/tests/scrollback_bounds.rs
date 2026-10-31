//! The scrollback limits the Core sends with `pty.open` and the bounds the runner clamps them
//! to are one set of numbers (E2-06.2): the settings registry and `ainkrad_proto::v2`.

use ainkrad_core::settings::Key;
use ainkrad_proto::v2::{SCROLLBACK_BUDGET, SCROLLBACK_BYTES};

#[test]
fn the_runner_clamps_to_the_bounds_the_registry_enforces() {
    for (key, (min, max, default)) in [
        (Key::TerminalScrollbackBytes, SCROLLBACK_BYTES),
        (Key::TerminalScrollbackBudget, SCROLLBACK_BUDGET),
    ] {
        let s = key.spec();
        assert_eq!(
            (s.min, s.max, s.default),
            (min as i64, max as i64, default as i64),
            "{}",
            s.name
        );
    }
}
