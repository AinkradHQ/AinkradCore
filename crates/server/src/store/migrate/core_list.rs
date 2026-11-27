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
    Migration {
        version: 27,
        name: "failover",
        up: include_str!("../../../migrations/0027_failover.up.sql"),
        down: include_str!("../../../migrations/0027_failover.down.sql"),
    },
    Migration {
        version: 28,
        name: "connections",
        up: include_str!("../../../migrations/0028_connections.up.sql"),
        down: include_str!("../../../migrations/0028_connections.down.sql"),
    },
    Migration {
        version: 29,
        name: "session_connections",
        up: include_str!("../../../migrations/0029_session_connections.up.sql"),
        down: include_str!("../../../migrations/0029_session_connections.down.sql"),
    },
    Migration {
        version: 30,
        name: "connection_apps",
        up: include_str!("../../../migrations/0030_connection_apps.up.sql"),
        down: include_str!("../../../migrations/0030_connection_apps.down.sql"),
    },
    Migration {
        version: 31,
        name: "pairing_invite",
        up: include_str!("../../../migrations/0031_pairing_invite.up.sql"),
        down: include_str!("../../../migrations/0031_pairing_invite.down.sql"),
    },
    Migration {
        version: 32,
        name: "secret_kinds_groups",
        up: include_str!("../../../migrations/0032_secret_kinds_groups.up.sql"),
        down: include_str!("../../../migrations/0032_secret_kinds_groups.down.sql"),
    },
    Migration {
        version: 33,
        name: "live_sessions",
        up: include_str!("../../../migrations/0033_live_sessions.up.sql"),
        down: include_str!("../../../migrations/0033_live_sessions.down.sql"),
    },
    Migration {
        version: 34,
        name: "audit_origin",
        up: include_str!("../../../migrations/0034_audit_origin.up.sql"),
        down: include_str!("../../../migrations/0034_audit_origin.down.sql"),
    },
    Migration {
        version: 35,
        name: "code_mode_writes",
        up: include_str!("../../../migrations/0035_code_mode_writes.up.sql"),
        down: include_str!("../../../migrations/0035_code_mode_writes.down.sql"),
    },
    Migration {
        version: 36,
        name: "session_folder",
        up: include_str!("../../../migrations/0036_session_folder.up.sql"),
        down: include_str!("../../../migrations/0036_session_folder.down.sql"),
    },
    Migration {
        version: 37,
        name: "agent_attachments",
        up: include_str!("../../../migrations/0037_agent_attachments.up.sql"),
        down: include_str!("../../../migrations/0037_agent_attachments.down.sql"),
    },
    Migration {
        version: 38,
        name: "turn_cost",
        up: include_str!("../../../migrations/0038_turn_cost.up.sql"),
        down: include_str!("../../../migrations/0038_turn_cost.down.sql"),
    },
    Migration {
        version: 39,
        name: "projects",
        up: include_str!("../../../migrations/0039_projects.up.sql"),
        down: include_str!("../../../migrations/0039_projects.down.sql"),
    },
    Migration {
        version: 40,
        name: "project_run_specs",
        up: include_str!("../../../migrations/0040_project_run_specs.up.sql"),
        down: include_str!("../../../migrations/0040_project_run_specs.down.sql"),
    },
    Migration {
        version: 41,
        name: "project_runs",
        up: include_str!("../../../migrations/0041_project_runs.up.sql"),
        down: include_str!("../../../migrations/0041_project_runs.down.sql"),
    },
    Migration {
        version: 42,
        name: "mirror_state",
        up: include_str!("../../../migrations/0042_mirror_state.up.sql"),
        down: include_str!("../../../migrations/0042_mirror_state.down.sql"),
    },
    Migration {
        version: 43,
        name: "terminal_sandbox_e6",
        up: include_str!("../../../migrations/0043_terminal_sandbox_e6.up.sql"),
        down: include_str!("../../../migrations/0043_terminal_sandbox_e6.down.sql"),
    },
    Migration {
        version: 44,
        name: "pairing_bundled_e6",
        up: include_str!("../../../migrations/0044_pairing_bundled_e6.up.sql"),
        down: include_str!("../../../migrations/0044_pairing_bundled_e6.down.sql"),
    },
    Migration {
        version: 45,
        name: "approval_rules",
        up: include_str!("../../../migrations/0045_approval_rules.up.sql"),
        down: include_str!("../../../migrations/0045_approval_rules.down.sql"),
    },
    Migration {
        version: 46,
        name: "project_runner_pref",
        up: include_str!("../../../migrations/0046_project_runner_pref.up.sql"),
        down: include_str!("../../../migrations/0046_project_runner_pref.down.sql"),
    },
    Migration {
        version: 47,
        name: "run_configs",
        up: include_str!("../../../migrations/0047_run_configs.up.sql"),
        down: include_str!("../../../migrations/0047_run_configs.down.sql"),
    },
    Migration {
        version: 48,
        name: "project_data",
        up: include_str!("../../../migrations/0048_project_data.up.sql"),
        down: include_str!("../../../migrations/0048_project_data.down.sql"),
    },
    Migration {
        version: 49,
        name: "concurrent_runs",
        up: include_str!("../../../migrations/0049_concurrent_runs.up.sql"),
        down: include_str!("../../../migrations/0049_concurrent_runs.down.sql"),
    },
    Migration {
        version: 50,
        name: "e7_ai_order",
        up: include_str!("../../../migrations/0050_e7_ai_order.up.sql"),
        down: include_str!("../../../migrations/0050_e7_ai_order.down.sql"),
    },
    Migration {
        version: 51,
        name: "e7_codex_sub",
        up: include_str!("../../../migrations/0051_e7_codex_sub.up.sql"),
        down: include_str!("../../../migrations/0051_e7_codex_sub.down.sql"),
    },
    Migration {
        version: 52,
        name: "e7_presets",
        up: include_str!("../../../migrations/0052_e7_presets.up.sql"),
        down: include_str!("../../../migrations/0052_e7_presets.down.sql"),
    },
    Migration {
        version: 53,
        name: "e7_limits",
        up: include_str!("../../../migrations/0053_e7_limits.up.sql"),
        down: include_str!("../../../migrations/0053_e7_limits.down.sql"),
    },
    Migration {
        version: 54,
        name: "e7_model_allow",
        up: include_str!("../../../migrations/0054_e7_model_allow.up.sql"),
        down: include_str!("../../../migrations/0054_e7_model_allow.down.sql"),
    },
    Migration {
        version: 55,
        name: "e7_provider_limits",
        up: include_str!("../../../migrations/0055_e7_provider_limits.up.sql"),
        down: include_str!("../../../migrations/0055_e7_provider_limits.down.sql"),
    },
    Migration {
        version: 56,
        name: "e7_retire_account_limits",
        up: include_str!("../../../migrations/0056_e7_retire_account_limits.up.sql"),
        down: include_str!("../../../migrations/0056_e7_retire_account_limits.down.sql"),
    },
    Migration {
        version: 57,
        name: "e7_account_soft_delete",
        up: include_str!("../../../migrations/0057_e7_account_soft_delete.up.sql"),
        down: include_str!("../../../migrations/0057_e7_account_soft_delete.down.sql"),
    },
    Migration {
        version: 58,
        name: "project_idle_never_e24",
        up: include_str!("../../../migrations/0058_project_idle_never_e24.up.sql"),
        down: include_str!("../../../migrations/0058_project_idle_never_e24.down.sql"),
    },
    Migration {
        version: 59,
        name: "hardware",
        up: include_str!("../../../migrations/0059_hardware.up.sql"),
        down: include_str!("../../../migrations/0059_hardware.down.sql"),
    },
    Migration {
        version: 60,
        name: "ws_path_run_kind",
        up: include_str!("../../../migrations/0060_ws_path_run_kind.up.sql"),
        down: include_str!("../../../migrations/0060_ws_path_run_kind.down.sql"),
    },
    Migration {
        version: 61,
        name: "decisions",
        up: include_str!("../../../migrations/0061_decisions.up.sql"),
        down: include_str!("../../../migrations/0061_decisions.down.sql"),
    },
    Migration {
        version: 62,
        name: "hw_cache_prepared",
        up: include_str!("../../../migrations/0062_hw_cache_prepared.up.sql"),
        down: include_str!("../../../migrations/0062_hw_cache_prepared.down.sql"),
    },
    Migration {
        version: 63,
        name: "hw_first_capacity",
        up: include_str!("../../../migrations/0063_hw_first_capacity.up.sql"),
        down: include_str!("../../../migrations/0063_hw_first_capacity.down.sql"),
    },
    Migration {
        version: 64,
        name: "account_display_name",
        up: include_str!("../../../migrations/0064_account_display_name.up.sql"),
        down: include_str!("../../../migrations/0064_account_display_name.down.sql"),
    },
    Migration {
        version: 65,
        name: "account_details",
        up: include_str!("../../../migrations/0065_account_details.up.sql"),
        down: include_str!("../../../migrations/0065_account_details.down.sql"),
    },
    Migration {
        version: 66,
        name: "terminal_account_uses",
        up: include_str!("../../../migrations/0066_terminal_account_uses.up.sql"),
        down: include_str!("../../../migrations/0066_terminal_account_uses.down.sql"),
    },
    Migration {
        version: 67,
        name: "lent_logins",
        up: include_str!("../../../migrations/0067_lent_logins.up.sql"),
        down: include_str!("../../../migrations/0067_lent_logins.down.sql"),
    },
    Migration {
        version: 68,
        name: "project_color",
        up: include_str!("../../../migrations/0068_project_color.up.sql"),
        down: include_str!("../../../migrations/0068_project_color.down.sql"),
    },
];

#[cfg(test)]
mod tests {
    use super::CORE_MIGRATIONS;

    /// Every `migrations/NNNN_name.up.sql` file is registered, in order, under its own number and name.
    #[test]
    fn every_migration_file_is_registered() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
        let mut files: Vec<(i64, String)> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| {
                let n = e.unwrap().file_name().into_string().unwrap();
                let stem = n.strip_suffix(".up.sql")?;
                let (v, name) = stem.split_once('_')?;
                Some((v.parse().ok()?, name.to_owned()))
            })
            .collect();
        files.sort();
        let listed: Vec<(i64, String)> = CORE_MIGRATIONS
            .iter()
            .map(|m| (m.version, m.name.to_owned()))
            .collect();
        assert_eq!(listed, files);
    }
}
