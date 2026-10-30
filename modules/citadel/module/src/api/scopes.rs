//! Per-route scopes of the module (`Module::route_scopes`). The module-wide scope is `admin`
//! (deny by default): a route that is not listed needs it. What a read-only device (a phone) may
//! do is listed here and nowhere else:
//!
//! - `read`: a GET that shows company, org, work or governance state a phone may see. Never a
//!   secret, a credential, a transcript or a log.
//! - `approve`: deciding an approval (POST `/approvals/{id}/decide`).
//!
//! Every slice appends the routes it adds. A GET that is **not** a phone read goes in
//! [`ADMIN_READS`] so the choice is explicit: the test below fails for a GET in the contract that
//! is in neither list.

/// `(method, template, scope)`, templates relative to `/modules/citadel/v1`.
pub const ROUTE_SCOPES: &[(&str, &str, &str)] = &[
    // org (S1/S2)
    ("GET", "/companies", "read"),
    ("GET", "/companies/{id}", "read"),
    ("GET", "/companies/{id}/departments", "read"),
    ("GET", "/departments/{id}/teams", "read"),
    ("GET", "/companies/{id}/agents", "read"),
    ("GET", "/agents/{id}", "read"),
];

/// GET routes that deliberately stay `admin`.
pub const ADMIN_READS: &[&str] = &[];

#[cfg(test)]
mod tests {
    use ainkrad_core_server::api::v1::scopes::module_scope;

    use super::*;
    use crate::Citadel;

    /// Every GET operation of the module's contract is either a listed phone read or an explicit
    /// admin read; a write is below `admin` only when it is an approval decision.
    #[test]
    fn every_get_in_the_contract_is_classified() {
        let doc = crate::api::spec::document();
        let mut gets = 0;
        for (path, item) in doc["paths"].as_object().unwrap() {
            for method in item.as_object().unwrap().keys() {
                let scope = module_scope(&Citadel, method, path);
                if method == "get" {
                    gets += 1;
                    let admin = ADMIN_READS.contains(&path.as_str());
                    assert_eq!(
                        scope == "read",
                        !admin,
                        "GET {path} is {scope}: list it in ROUTE_SCOPES or ADMIN_READS"
                    );
                } else if scope != "admin" {
                    assert!(
                        scope == "approve" && path.ends_with("/decide"),
                        "{method} {path} is {scope}: only an approval decision may be below admin"
                    );
                }
            }
        }
        assert!(gets >= 6, "{gets} GETs");
    }

    #[test]
    fn no_route_asks_for_a_scope_the_core_refuses() {
        for (m, t, s) in ROUTE_SCOPES {
            assert!(["read", "approve"].contains(s), "{m} {t}: {s}");
        }
    }
}
