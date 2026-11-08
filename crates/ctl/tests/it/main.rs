//! ctl against the real `ainkrad-core-server` (and, where the real one cannot be made to
//! misbehave, a fake Core). One test binary, so the server is built once.

mod acct_cli;
mod acct_fake;
mod acct_login_cli;
mod acct_refusals;
mod chains;
mod common;
mod connections;
mod connections_fake;
mod connections_login;
mod connections_more;
mod contract;
mod e2x;
mod fake;
mod faults;
mod faults_edge;
mod flow;
mod negative;
mod proxy;
mod runner;
mod scheduler_fake;
mod stepup;
mod tls;
