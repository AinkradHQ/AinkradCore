//! A capability minted for one route (KAN-435 G7), apart from `mod.rs` so that file stays small.

use super::{Elevated, Hub};

impl Hub {
    /// The capability of `POST /accounts/{id}/test` (`admin`, not destructive: the design's §5.2).
    /// It sends `gateway.test` only: one fixed, free request, to the host the account's key was
    /// bound to when it was stored, through a runner that is in the key's scope. It runs no code
    /// and takes no request-supplied URL. Not a route entry point for any other op.
    pub(crate) fn gateway_test_elevation(&self, caller: &crate::api::v1::Caller) -> Elevated {
        debug_assert!(caller.device.scopes.iter().any(|s| s == "admin"));
        Elevated(())
    }
}
