//! Deprecation policy mechanism (E1-05.5, handshake spec "Versioning and deprecation"): a route
//! listed in [`DEPRECATED`] answers with `Deprecation: @<unix>` (RFC 9745) and `Sunset: <date>`
//! (RFC 8594), and the contract marks its operation `deprecated: true` and `x-ainkrad-sunset`.
//! Nothing is deprecated yet: the table is empty and the contract is unchanged.

use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::{Value, json};

/// One deprecated operation: its method and route template (`/api/v1/devices/{id}`), when it
/// was deprecated and the earliest time it may be removed (both Unix seconds).
pub struct Deprecation {
    pub method: &'static str,
    pub path: &'static str,
    pub deprecated_at: u64,
    pub sunset: u64,
}

/// The deprecated operations of the Core. Add a row (and bump `API_MINOR`: the contract changes).
pub const DEPRECATED: &[Deprecation] = &[];

/// `Sun, 06 Nov 1994 08:49:37 GMT`.
fn http_date(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (days, rem) = (unix / 86_400, unix % 86_400);
    // Civil date from days since 1970-01-01 (Hinnant).
    let z = days as i64 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[month as usize - 1],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Adds the headers to a response of a deprecated route in `table`. Layer it with
/// `route_layer` so the matched route is known.
pub async fn headers(table: &'static [Deprecation], req: Request, next: Next) -> Response {
    let hit = req.extensions().get::<MatchedPath>().and_then(|p| {
        table.iter().find(|d| {
            d.path == p.as_str()
                && Method::from_bytes(d.method.as_bytes()).ok().as_ref() == Some(req.method())
        })
    });
    let hit = hit.map(|d| (d.deprecated_at, d.sunset));
    let mut response = next.run(req).await;
    if let Some((at, sunset)) = hit {
        let h = response.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&format!("@{at}")) {
            h.insert("deprecation", v);
        }
        if let Ok(v) = HeaderValue::from_str(&http_date(sunset)) {
            h.insert("sunset", v);
        }
    }
    response
}

/// Marks each operation of `table` in the contract `spec`.
pub fn mark(spec: &mut Value, table: &[Deprecation]) {
    for d in table {
        let op = &mut spec["paths"][d.path][d.method.to_lowercase()];
        assert!(
            op.is_object(),
            "deprecated {} {} is not in the contract",
            d.method,
            d.path
        );
        op["deprecated"] = json!(true);
        op["x-ainkrad-sunset"] = json!(http_date(d.sunset));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware::from_fn;
    use axum::routing::get;
    use tower::ServiceExt;

    static TABLE: &[Deprecation] = &[Deprecation {
        method: "GET",
        path: "/old/{id}",
        deprecated_at: 1_688_169_599,
        sunset: 784_111_777,
    }];

    #[test]
    fn dates_are_rfc_9110() {
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
    }

    #[tokio::test]
    async fn only_the_listed_route_and_method_are_marked() {
        let app = Router::new()
            .route("/old/{id}", get(|| async { "x" }).post(|| async { "x" }))
            .route("/new", get(|| async { "x" }))
            .route_layer(from_fn(|r, n| headers(TABLE, r, n)));
        let call = |m: &str, uri: &str| {
            let app = app.clone();
            let r = Request::builder()
                .method(m)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            async move { app.oneshot(r).await.unwrap() }
        };
        let old = call("GET", "/old/7").await;
        assert_eq!(old.status(), StatusCode::OK);
        assert_eq!(old.headers()["deprecation"], "@1688169599");
        assert_eq!(old.headers()["sunset"], "Sun, 06 Nov 1994 08:49:37 GMT");
        for (m, uri) in [("POST", "/old/7"), ("GET", "/new")] {
            let r = call(m, uri).await;
            assert!(
                r.headers().get("deprecation").is_none() && r.headers().get("sunset").is_none()
            );
        }
    }

    #[test]
    fn the_contract_marks_it_and_the_real_table_is_empty() {
        let mut spec = json!({"paths": {"/old/{id}": {"get": {"operationId": "x"}}}});
        mark(&mut spec, TABLE);
        let op = &spec["paths"]["/old/{id}"]["get"];
        assert_eq!(op["deprecated"], true);
        assert_eq!(op["x-ainkrad-sunset"], "Sun, 06 Nov 1994 08:49:37 GMT");
        assert!(
            DEPRECATED.is_empty(),
            "deprecating a route bumps API_MINOR and regenerates the contract"
        );
    }
}
