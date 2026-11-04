//! Pool and binding routes.

use super::*;

// ----- pools and bindings -----------------------------------------------------------------

#[utoipa::path(get, path = "/api/v1/pools", operation_id = "listPools", tag = "accounts",
    responses((status = 200, description = "Every pool, its members in fallback order", body = Vec<Pool>)))]
pub async fn list_pools(State(app): State<App>) -> ApiResult<Vec<Pool>> {
    Ok(Json(
        pl::list(&app.pool)
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[utoipa::path(post, path = "/api/v1/pools", operation_id = "createPool", tag = "accounts",
    request_body = NewPool,
    responses((status = 200, description = "Created, empty (audited as `pool.created`)", body = Pool)))]
pub async fn create_pool(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<NewPool>,
) -> ApiResult<Pool> {
    let p = pl::create(
        &app.pool,
        &b.name,
        &b.provider,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(delete, path = "/api/v1/pools/{id}", operation_id = "deletePool", tag = "accounts",
    params(("id" = String, Path, description = "The pool's id")),
    responses((status = 200, description = "Deleted with its bindings (audited as \
        `pool.deleted`); the default pool is refused (409)", body = AccountsDeleted)))]
pub async fn delete_pool(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<AccountsDeleted> {
    pl::delete(&app.pool, num(&id, "pool")?, &me.device.id, BY)
        .await
        .map_err(err)?;
    Ok(Json(AccountsDeleted { deleted: true }))
}

#[utoipa::path(put, path = "/api/v1/pools/{id}/members/{account}", operation_id = "addPoolMember",
    tag = "accounts",
    params(("id" = String, Path, description = "The pool's id"),
           ("account" = String, Path, description = "The account's id")),
    responses((status = 200, description = "Appended to the pool's fallback order (audited as \
        `pool.member_added`); an account of another provider is refused (400)", body = Pool)))]
pub async fn add_member(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, account)): Path<(String, String)>,
) -> ApiResult<Pool> {
    let p = pl::add_member(
        &app.pool,
        num(&id, "pool")?,
        num(&account, "account")?,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(delete, path = "/api/v1/pools/{id}/members/{account}",
    operation_id = "removePoolMember", tag = "accounts",
    params(("id" = String, Path, description = "The pool's id"),
           ("account" = String, Path, description = "The account's id")),
    responses((status = 200, description = "Removed (audited as `pool.member_removed`)", body = Pool)))]
pub async fn remove_member(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((id, account)): Path<(String, String)>,
) -> ApiResult<Pool> {
    let p = pl::remove_member(
        &app.pool,
        num(&id, "pool")?,
        num(&account, "account")?,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(put, path = "/api/v1/pools/{id}/default", operation_id = "setDefaultPool",
    tag = "accounts", params(("id" = String, Path, description = "The pool's id")),
    responses((status = 200, description = "Its provider's default pool from now on (audited \
        as `pool.default_set`)", body = Pool)))]
pub async fn set_default(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
) -> ApiResult<Pool> {
    let p = pl::set_default(
        &app.pool,
        num(&id, "pool")?,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    Ok(Json(p.into()))
}

#[utoipa::path(get, path = "/api/v1/bindings", operation_id = "listBindings", tag = "accounts",
    responses((status = 200, description = "Every agent's binding to a pool", body = Vec<Binding>)))]
pub async fn list_bindings(State(app): State<App>) -> ApiResult<Vec<Binding>> {
    let all = pl::list_bindings(&app.pool).await?;
    Ok(Json(
        all.into_iter()
            .map(|b| Binding {
                agent: b.agent,
                provider: b.provider,
                pool_id: b.pool_id,
            })
            .collect(),
    ))
}

#[utoipa::path(put, path = "/api/v1/bindings", operation_id = "bindAgent", tag = "accounts",
    request_body = NewBinding,
    responses((status = 200, description = "The agent draws its pool's provider from this pool, \
        replacing an earlier binding for that provider (audited as `pool.bound`)",
        body = Binding)))]
pub async fn bind(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Json(b): Json<NewBinding>,
) -> ApiResult<Binding> {
    pl::bind(
        &app.pool,
        &b.agent,
        b.pool_id,
        &me.device.id,
        BY,
        &app.clock.now(),
    )
    .await
    .map_err(err)?;
    let p = pl::get(&app.pool, b.pool_id).await.map_err(err)?;
    Ok(Json(Binding {
        agent: b.agent,
        provider: p.provider,
        pool_id: p.id,
    }))
}

#[utoipa::path(delete, path = "/api/v1/bindings/{agent}/{provider}", operation_id = "unbindAgent",
    tag = "accounts",
    params(("agent" = String, Path, description = "The agent's id"),
           ("provider" = String, Path, description = "`anthropic`, `openai` or `google`")),
    responses((status = 200, description = "The agent falls back to the provider's default \
        pool (audited as `pool.unbound`)", body = AccountsDeleted)))]
pub async fn unbind(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path((agent, provider)): Path<(String, String)>,
) -> ApiResult<AccountsDeleted> {
    pl::unbind(&app.pool, &agent, &provider, &me.device.id, BY)
        .await
        .map_err(err)?;
    Ok(Json(AccountsDeleted { deleted: true }))
}
