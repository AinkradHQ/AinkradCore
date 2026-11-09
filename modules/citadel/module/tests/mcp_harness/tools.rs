//! Helpers of the tool tests: one call, an expected answer, a refusal, two companies.
#![allow(dead_code, unused_imports)]

use super::*;
use crate::common::*;
use base64::Engine;
use serde_json::{Value, json};

/// One tool call: whether it failed, and its text.
pub async fn invoke(w: &W, token: &str, name: &str, args: Value) -> (bool, String) {
    answer(&rpc(&w.fx.app, Some(token), tool(name, args)).await.1)
}

pub async fn ok(w: &W, token: &str, name: &str, args: Value) -> Value {
    let (failed, text) = invoke(w, token, name, args).await;
    assert!(!failed, "{name}: {text}");
    serde_json::from_str(&text).unwrap()
}

pub async fn refused(w: &W, token: &str, name: &str, args: Value) -> String {
    let (failed, text) = invoke(w, token, name, args).await;
    assert!(failed, "{name} should be refused: {text}");
    text
}

/// Makes the company's one agent its CEO, which makes it a planner of every project.
pub async fn make_ceo(w: &W, co: &Co) {
    sqlx::query("UPDATE citadel_agents SET org_role = 'ceo' WHERE id = ?")
        .bind(co.seed.agent)
        .execute(&w.fx.app.pool)
        .await
        .unwrap();
}

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Two companies, each with a started run and a token.
pub async fn two() -> (W, Co, String, Co, String) {
    let w = world().await;
    let a = w.co("A", "AAA").await;
    let b = w.co("B", "BBB").await;
    let (ta, tb) = (w.token(a.run.id).await, w.token(b.run.id).await);
    (w, a, ta, b, tb)
}

pub fn app_pool(w: &W) -> &sqlx::SqlitePool {
    &w.fx.app.pool
}
