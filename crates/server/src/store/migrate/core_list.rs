//! The platform's migration list, apart from the runner so the runner stays small.

use super::Migration;

/// The platform's migrations, in order. A file, once in a release, never changes: its
/// checksum is recorded, and a changed text refuses to start.
pub static CORE_MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "core_0001",
        up: include_str!("../../../migrations/0001_core_0001.up.sql"),
        down: include_str!("../../../migrations/0001_core_0001.down.sql"),
    },
    Migration {
        version: 2,
        name: "events_audit",
        up: include_str!("../../../migrations/0002_events_audit.up.sql"),
        down: include_str!("../../../migrations/0002_events_audit.down.sql"),
    },
    Migration {
        version: 3,
        name: "device_identity",
        up: include_str!("../../../migrations/0003_device_identity.up.sql"),
        down: include_str!("../../../migrations/0003_device_identity.down.sql"),
    },
    Migration {
        version: 4,
        name: "event_visibility",
        up: include_str!("../../../migrations/0004_event_visibility.up.sql"),
        down: include_str!("../../../migrations/0004_event_visibility.down.sql"),
    },
    Migration {
        version: 5,
        name: "passkeys",
        up: include_str!("../../../migrations/0005_passkeys.up.sql"),
        down: include_str!("../../../migrations/0005_passkeys.down.sql"),
    },
    Migration {
        version: 6,
        name: "audit_device_ref",
        up: include_str!("../../../migrations/0006_audit_device_ref.up.sql"),
        down: include_str!("../../../migrations/0006_audit_device_ref.down.sql"),
    },
    Migration {
        version: 7,
        name: "jobs_push_tokens",
        up: include_str!("../../../migrations/0007_jobs_push_tokens.up.sql"),
        down: include_str!("../../../migrations/0007_jobs_push_tokens.down.sql"),
    },
    Migration {
        version: 8,
        name: "secrets",
        up: include_str!("../../../migrations/0008_secrets.up.sql"),
        down: include_str!("../../../migrations/0008_secrets.down.sql"),
    },
    Migration {
        version: 9,
        name: "agent_sessions",
        up: include_str!("../../../migrations/0009_agent_sessions.up.sql"),
        down: include_str!("../../../migrations/0009_agent_sessions.down.sql"),
    },
    Migration {
        version: 10,
        name: "agent_session_owner",
        up: include_str!("../../../migrations/0010_agent_session_owner.up.sql"),
        down: include_str!("../../../migrations/0010_agent_session_owner.down.sql"),
    },
    Migration {
        version: 11,
        name: "terminals",
        up: include_str!("../../../migrations/0011_terminals.up.sql"),
        down: include_str!("../../../migrations/0011_terminals.down.sql"),
    },
    Migration {
        version: 12,
        name: "agent_session_owner_ref",
        up: include_str!("../../../migrations/0012_agent_session_owner_ref.up.sql"),
        down: include_str!("../../../migrations/0012_agent_session_owner_ref.down.sql"),
    },
    Migration {
        version: 13,
        name: "event_views_scope_index",
        up: include_str!("../../../migrations/0013_event_views_scope_index.up.sql"),
        down: include_str!("../../../migrations/0013_event_views_scope_index.down.sql"),
    },
    Migration {
        version: 14,
        name: "push_kinds",
        up: include_str!("../../../migrations/0014_push_kinds.up.sql"),
        down: include_str!("../../../migrations/0014_push_kinds.down.sql"),
    },
    Migration {
        version: 15,
        name: "accounts",
        up: include_str!("../../../migrations/0015_accounts.up.sql"),
        down: include_str!("../../../migrations/0015_accounts.down.sql"),
    },
    Migration {
        version: 16,
        name: "provider_defs",
        up: include_str!("../../../migrations/0016_provider_defs.up.sql"),
        down: include_str!("../../../migrations/0016_provider_defs.down.sql"),
    },
    Migration {
        version: 17,
        name: "pools",
        up: include_str!("../../../migrations/0017_pools.up.sql"),
        down: include_str!("../../../migrations/0017_pools.down.sql"),
    },
    Migration {
        version: 18,
        name: "cost_ledger",
        up: include_str!("../../../migrations/0018_cost_ledger.up.sql"),
        down: include_str!("../../../migrations/0018_cost_ledger.down.sql"),
    },
    Migration {
        version: 19,
        name: "budgets",
        up: include_str!("../../../migrations/0019_budgets.up.sql"),
        down: include_str!("../../../migrations/0019_budgets.down.sql"),
    },
    Migration {
        version: 20,
        name: "gateway_session",
        up: include_str!("../../../migrations/0020_gateway_session.up.sql"),
        down: include_str!("../../../migrations/0020_gateway_session.down.sql"),
    },
    Migration {
        version: 21,
        name: "gateway_api",
        up: include_str!("../../../migrations/0021_gateway_api.up.sql"),
        down: include_str!("../../../migrations/0021_gateway_api.down.sql"),
    },
    Migration {
        version: 22,
        name: "account_logins",
        up: include_str!("../../../migrations/0022_account_logins.up.sql"),
        down: include_str!("../../../migrations/0022_account_logins.down.sql"),
    },
    Migration {
        version: 23,
        name: "usage_meter",
        up: include_str!("../../../migrations/0023_usage_meter.up.sql"),
        down: include_str!("../../../migrations/0023_usage_meter.down.sql"),
    },
    Migration {
        version: 24,
        name: "account_health",
        up: include_str!("../../../migrations/0024_account_health.up.sql"),
        down: include_str!("../../../migrations/0024_account_health.down.sql"),
    },
    Migration {
        version: 25,
        name: "scheduler_allocator",
        up: include_str!("../../../migrations/0025_scheduler_allocator.up.sql"),
        down: include_str!("../../../migrations/0025_scheduler_allocator.down.sql"),
    },
    Migration {
        version: 26,
        name: "chains",
        up: include_str!("../../../migrations/0026_chains.up.sql"),
        down: include_str!("../../../migrations/0026_chains.down.sql"),
    },
];
