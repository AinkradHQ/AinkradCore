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
        name: "citadel_0003_forge_secrets",
        up: include_str!("../migrations/0003_citadel_0003_forge_secrets.up.sql"),
        down: include_str!("../migrations/0003_citadel_0003_forge_secrets.down.sql"),
    },
];
