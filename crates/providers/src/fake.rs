//! Fake provider servers on loopback, for tests only (feature `fake`): each keeps its state in
//! memory behind a mutex the test reads and steers, answers the API calls the providers make,
//! and records every request it got.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::Value;

mod github;
mod gitlab;
mod linear;
pub use github::*;
pub use gitlab::*;
pub use linear::*;

/// Serves `router` on a fresh loopback port; its base URL.
async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    format!("http://{addr}")
}

fn reply(status: StatusCode, body: Value) -> Response {
    (status, axum::Json(body)).into_response()
}

/// The sha of `branch` in the bare repo `repo`, if it has the branch.
fn branch_sha(repo: &std::path::Path, branch: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--verify", "--quiet"])
        .arg(format!("refs/heads/{branch}"))
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Shared, steerable state of one fake.
pub type Shared<T> = Arc<Mutex<T>>;
