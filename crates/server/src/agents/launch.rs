//! Idempotent start attempts retain leases until acknowledgement or their actual expiry.
use super::*;

/// Leases each of the session's secrets to its runner for one start.
async fn leases(app: &App, s: &Session) -> Result<(i64, Vec<SecretGrant>), Refusal> {
    let mut expires = i64::MAX;
    let mut out = Vec::with_capacity(s.secrets.len());
    for secret in &s.secrets {
        let (lease, until) = crate::store::secrets::lease(
            &app.pool,
            &secret.name,
            &s.runner,
            None,
            &s.created_by,
            AuditActor::System,
            &app.clock.now(),
            app.clock.unix(),
        )
        .await?;
        expires = expires.min(until);
        out.push(SecretGrant {
            lease,
            var: secret.var.clone(),
        });
    }
    // What the owning module mints for this start (the run token): held in memory for the
    // runner to redeem once, sent as a lease like any other, never stored.
    if let Some(module) = s
        .owner_module
        .as_deref()
        .and_then(|id| app.modules.iter().find(|m| m.id() == id))
    {
        let invalid = |why: String| Refusal::Runner(StreamError::new(ErrorCode::InvalidArgs, why));
        let minted = module.credentials(app, s).await.map_err(invalid)?;
        let now = app.clock.unix();
        for c in minted {
            if !ainkrad_proto::v2::valid_secret_var(&c.var) {
                return Err(invalid(
                    "a module credential names an illegal variable".into(),
                ));
            }
            let lease = crate::auth::crypto::random_id("l_");
            let until = now + EPHEMERAL_SECS;
            let held = Ephemeral {
                runner: s.runner.clone(),
                var: c.var.to_lowercase(),
                value: c.value,
                expires: until,
            };
            if !app.agents.stash(&lease, held, now) {
                return Err(busy("too many credentials await redemption"));
            }
            expires = expires.min(until);
            out.push(SecretGrant { lease, var: c.var });
        }
    }
    Ok((expires, out))
}

/// The `agent.start` of `s`, continuing the harness's own session when `resume`.
fn start_command(s: &Session, secrets: Vec<SecretGrant>, resume: bool) -> Command {
    Command::AgentStart(AgentStart {
        session: s.id.clone(),
        harness: s.harness.clone(),
        model: s.model.clone(),
        prompt: s.prompt.clone(),
        workspace: s
            .workspace
            .clone()
            .and_then(|w| serde_json::from_value(w).ok()),
        policy: serde_json::from_value(s.policy.clone()).unwrap_or_default(),
        resume: resume.then(|| s.harness_session.clone()).flatten(),
        secrets,
    })
}

/// Starts (or resumes) `s` on its runner with fresh leases; its state moves to `running`.
/// A refusal that retrying cannot fix ends the session as failed.
pub(super) async fn launch(app: &App, s: &Session, resume: bool) -> Result<(), Refusal> {
    // No lease for a runner that cannot redeem it now: they would only pile up to the cap.
    if !app.hub.online(&s.runner) {
        let why = "the runner is not connected";
        return Err(Refusal::Runner(StreamError::new(ErrorCode::Offline, why)));
    }
    let cached = { app.agents.leases.lock().unwrap().get(&s.id).cloned() };
    let secrets = match cached {
        Some((until, grants)) if until > app.clock.unix() => grants,
        _ => match leases(app, s).await {
            Ok((until, grants)) => {
                app.agents
                    .leases
                    .lock()
                    .unwrap()
                    .insert(s.id.clone(), (until, grants.clone()));
                grants
            }
            Err(e) => {
                fail(app, s, &format!("leasing its secrets: {}", describe(&e))).await;
                return Err(e);
            }
        },
    };
    let wait = app.agents.config.answer;
    let proof = app.agents.elevated.lock().unwrap().get(&s.id).copied();
    match ask(
        app,
        &s.runner,
        start_command(s, secrets.clone(), resume),
        wait,
        proof,
    )
    .await
    {
        Ok(ev) => {
            app.agents.leases.lock().unwrap().remove(&s.id);
            let why = if resume { "resumed" } else { "started" };
            store::set_state(&app.pool, &s.id, "running", why, resume, &app.clock.now()).await?;
            store::apply(&app.pool, &s.id, &ev, &app.clock.now()).await?;
            Ok(())
        }
        Err(e) if matches!(e.code, ErrorCode::Busy | ErrorCode::InvalidArgs) => {
            fail(app, s, &e.message).await;
            Err(e.into())
        }
        Err(e) => Err(e.into()),
    }
}
