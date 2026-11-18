//! Y4-02 review, MEDIUM: a run's output can hold what a step printed, so `GET /runs/{run}` is a
//! `admin`-scope (no `write` scope exists) route, not `read`.

use ainkrad_core_server::module::Module;
use leyline_module::Leyline;

#[test]
fn reading_a_run_needs_admin_scope() {
    let scopes = Leyline.route_scopes();
    let run = scopes
        .iter()
        .find(|(m, p, _)| *m == "GET" && *p == "/runs/{run}");
    assert_eq!(run.map(|r| r.2), Some("admin"));
    // the command definitions themselves hold no output: still readable
    let cmds = scopes
        .iter()
        .find(|(m, p, _)| *m == "GET" && *p == "/commands");
    assert_eq!(cmds.map(|r| r.2), Some("read"));
}
