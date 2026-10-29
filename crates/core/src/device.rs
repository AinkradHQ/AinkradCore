//! Device keys (#18): each device the admin uses has its own key; only its hash is stored.

use crate::ids::DeviceKeyId;

/// A per-device API key, without the key itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    pub id: DeviceKeyId,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}
