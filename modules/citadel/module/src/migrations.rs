//! The module's migrations: one squashed baseline (P2.10: a fresh start, not the monolith's 150).
//! A file, once released, never changes (its checksum is recorded).

use ainkrad_core_server::store::Migration;

pub static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "citadel_0001",
        up: include_str!("../migrations/0001_citadel_0001.up.sql"),
        down: include_str!("../migrations/0001_citadel_0001.down.sql"),
    },
    Migration {
        version: 2,
        name: "citadel_0002_accounts",
        up: include_str!("../migrations/0002_citadel_0002_accounts.up.sql"),
        down: include_str!("../migrations/0002_citadel_0002_accounts.down.sql"),
    },
    Migration {
        version: 3,
        name: "citadel_0003_runs",
        up: include_str!("../migrations/0003_citadel_0003_runs.up.sql"),
        down: include_str!("../migrations/0003_citadel_0003_runs.down.sql"),
    },
    Migration {
        version: 4,
        name: "citadel_0004_mcp",
        up: include_str!("../migrations/0004_citadel_0004_mcp.up.sql"),
        down: include_str!("../migrations/0004_citadel_0004_mcp.down.sql"),
    },
    Migration {
        version: 5,
        name: "citadel_0005_mcp_creates",
        up: include_str!("../migrations/0005_citadel_0005_mcp_creates.up.sql"),
        down: include_str!("../migrations/0005_citadel_0005_mcp_creates.down.sql"),
    },
];
