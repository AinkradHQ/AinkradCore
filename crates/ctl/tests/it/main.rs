//! ctl against the real `ainkrad-core-server` (and, where the real one cannot be made to
//! misbehave, a fake Core). One test binary, so the server is built once.

mod common;
mod contract;
mod fake;
mod flow;
mod negative;
mod stepup;
mod tls;
