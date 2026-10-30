//! Error mapping: what a store or service failure is on the wire. The body and the `error_id`
//! are the Core's (`ApiError`); this decides the status. A refused write is a 400 (a blank name,
//! a rule the service states), a constraint a 409, anything else an internal error that names
//! no table or SQL (the Core logs it with the error id).

use ainkrad_core_server::api::v1::ApiError;

use crate::store::org::service::is_constraint;

/// A failed write, as the client sees it.
pub fn refused(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Protocol(why) => ApiError::bad_request(why),
        e if is_constraint(&e) => {
            ApiError::conflict("the change breaks a rule (a duplicate name or a missing parent)")
        }
        e => e.into(),
    }
}

/// The row, or a 404 naming `what`.
pub fn found<T>(row: Option<T>, what: &str) -> Result<T, ApiError> {
    row.ok_or_else(|| ApiError::not_found(format!("no such {what}")))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn failures_map_to_the_status_a_client_can_act_on() {
        assert_eq!(
            refused(sqlx::Error::Protocol("a name is required".into())).status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            refused(sqlx::Error::RowNotFound).status,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let internal = refused(sqlx::Error::PoolTimedOut);
        assert_eq!(
            (internal.status, internal.message.as_str()),
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        );
        assert_eq!(
            found(None::<i32>, "agent").unwrap_err().status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(found(Some(1), "agent").unwrap(), 1);
    }
}
