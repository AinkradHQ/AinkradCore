//! An account's models (E7-2b): the ids a provider listed, each with its list price and an
//! "allow this model" switch. A model is allowed unless someone switched it off; a chain, the AI
//! order and a gateway grant refuse a switched-off one. Reading is `read`; the switch is `admin`
//! and destructive (it changes which model a run may spend on).

use super::*;
use crate::store::{account_models, prices};

/// One model of an account.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountModelRow {
    /// Exactly as the provider names it.
    pub model: String,
    /// Absent switch means allowed: `false` only when someone switched it off.
    pub allowed: bool,
    /// List price per million input tokens, in millionths of a dollar; absent when the model has
    /// no price (it then runs at the flagged default price).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub input_per_mtok_micro: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub output_per_mtok_micro: Option<i64>,
}

/// What `GET /accounts/{id}/models` answers: the model ids the provider listed for the account.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccountModels {
    /// Exactly as the provider names them; empty until a list was read (a preset's add or check
    /// through a runner). No price: an unpriced model runs at the flagged default price.
    pub models: Vec<String>,
    /// When the list was read; absent when none was.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub fetched_at: Option<Timestamp>,
    /// Every model the account can name with its price and switch: the listed ids, the provider's
    /// priced ones and any switched off. Absent when there is none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(required = false)]
    pub items: Vec<AccountModelRow>,
    /// `plan`: a subscription; its models are included in the plan, so they have no prices here.
    /// `metered`: an API key, billed per token at the prices in `items`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub billing: Option<String>,
    /// As `ProviderAccount.models_enforced`: whether a switched-off model is refused in its sessions
    /// (an API key's gateway), or only advice (a plan: the harness talks to its provider itself,
    /// and the Core only skips the account when a session asks for that model at its start).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(required = false)]
    pub models_enforced: Option<bool>,
}

/// Switches a model on or off for one account.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetModelAllowed {
    pub allowed: bool,
}

#[utoipa::path(get, path = "/api/v1/accounts/{id}/models", operation_id = "listAccountModels",
    tag = "accounts", params(("id" = String, Path, description = "The account's id")),
    responses((status = 200, description = "The model ids the provider listed for the account \
        when its key was added or checked (a preset's list is read through a runner's gateway), \
        and in `items` each model with its list price where there is one and whether it is \
        allowed. A plan account (`billing: plan`) has no key to list them: its models are the ones \
        its harness runs on a plan (the shipped Anthropic models for Claude, the Codex models for \
        ChatGPT) and every model its sessions were seen running, all included in the plan. 404 for \
        no such account", body = AccountModels)))]
pub async fn list_models(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<AccountModels> {
    let id = num(&id, "account")?;
    let a = acc::get(&app.pool, id).await.map_err(err)?;
    let (mut models, at) = account_models::get(&app.pool, id).await?;
    // A plan has no key to list its models: what its harness runs on a plan, and what it was seen running.
    let plan = crate::store::account_keys::subscription_provider(&a.provider);
    let known = match plan {
        true => account_models::plan_models(&a.provider),
        false => Vec::new(),
    };
    for m in known
        .into_iter()
        .chain(account_models::seen(&app.pool, id).await?)
    {
        if !models.contains(&m) {
            models.push(m);
        }
    }
    let off = account_models::denied(&app.pool, id).await?;
    let def = prov::get(&app.pool, &a.provider).await.map_err(err)?;
    let book = prices::book_of(prices::list(&app.pool).await?, &a.provider, &def);
    let mut ids = models.clone();
    for m in book.iter().map(|p| &p.model).chain(&off) {
        if !ids.contains(m) {
            ids.push(m.clone());
        }
    }
    let items = ids
        .into_iter()
        .map(|m| {
            let p = book.iter().find(|p| p.model == m);
            AccountModelRow {
                allowed: !off.contains(&m),
                input_per_mtok_micro: p.map(|p| p.input_per_mtok_micro),
                output_per_mtok_micro: p.map(|p| p.output_per_mtok_micro),
                model: m,
            }
        })
        .collect();
    Ok(Json(AccountModels {
        models,
        fetched_at: opt_ts(at.as_deref()),
        items,
        billing: Some(if plan { "plan" } else { "metered" }.to_owned()),
        models_enforced: Some(!plan),
    }))
}

#[utoipa::path(put, path = "/api/v1/accounts/{id}/models/{model}",
    operation_id = "setAccountModelAllowed", tag = "accounts",
    params(("id" = String, Path, description = "The account's id"),
        ("model" = String, Path, description = "The model id")),
    request_body = SetModelAllowed,
    responses((status = 200, description = "Allows or switches off the model for the account \
        (audited as `account.model_allowed_set`); a chain, the AI order and a gateway grant \
        refuse a switched-off model. Needs a step-up. 404 for no such account", body = AccountModels)))]
pub async fn set_model_allowed(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, model)): Path<(String, String)>,
    Json(b): Json<SetModelAllowed>,
) -> ApiResult<AccountModels> {
    let n = num(&id, "account")?;
    account_models::set_allowed(
        &app.pool,
        n,
        &model,
        b.allowed,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    list_models(State(app), Path(id)).await
}
