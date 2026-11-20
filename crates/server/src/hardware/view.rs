//! The hardware the placement rules read (E15 §3.2, §3.5): the hub's live state joined with what
//! the Core keeps: which device is the Core host (the local enrolment) or This Mac (the attested
//! bundled runner), its pause and slot preferences, and the AI sessions and jobs it holds.

use std::collections::{HashMap, HashSet};

use ainkrad_proto::v2::{Arch, Capacity, HwKind, Os};
use sqlx::sqlite::SqlitePool;

use super::place::HwView;
use crate::api::App;
use crate::hub::HwState;
use crate::store::gov::LOCAL_ENROL_SAS;

/// A job running on a machine.
pub struct LiveJob {
    pub id: String,
    pub project: Option<i64>,
    pub label: String,
    pub started_at: String,
}

/// One machine: the placement view plus what the API shows beyond it.
pub struct Machine {
    pub view: HwView,
    /// A pause in effect: its own or the pool's. On the Core host: the pool's (pause-all), which
    /// the Core row carries so it applies to runners paired later (the Core itself is never paused).
    pub paused_until: Option<String>,
    pub jobs: Vec<LiveJob>,
}

/// The kind of every paired runner device.
async fn kinds(pool: &SqlitePool) -> Result<HashMap<String, HwKind>, sqlx::Error> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT device_id, sas, bundled FROM core_pairings \
         WHERE kind = 'runner' AND device_id IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(d, sas, bundled)| (d, kind_of(&sas, bundled)))
        .collect())
}

/// Whether the runner `device` may host a terminal (E15 security review M6, spec §9): the Core's
/// own runner or the attested This Mac, never a plain paired runner. Every paired device has a
/// pairing row (a pairing claim or the local enrolment is the only way a device is made); a device
/// with none is a test enrolment and is not refused here.
pub async fn hosts_terminals(pool: &SqlitePool, device: &str) -> Result<bool, sqlx::Error> {
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT sas, bundled FROM core_pairings WHERE kind = 'runner' AND device_id = ?",
    )
    .bind(device)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .all(|(sas, bundled)| kind_of(sas, *bundled) != HwKind::Runner))
}

/// The local enrolment is the Core host; an attested bundled runner is This Mac.
fn kind_of(sas: &str, bundled: bool) -> HwKind {
    if sas == LOCAL_ENROL_SAS {
        HwKind::Core
    } else if bundled {
        HwKind::Mac
    } else {
        HwKind::Runner
    }
}

/// The later of two pause times.
fn later(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// `paused_until` in the future at `now` (ISO strings of one format compare as text).
fn is_paused(until: Option<&str>, now: &str) -> bool {
    until.is_some_and(|u| u > now)
}

fn view_of(
    h: HwState,
    kind: HwKind,
    paused: bool,
    slots: Option<u32>,
    sessions: u32,
    jobs: u32,
) -> HwView {
    let job_slots = slots.unwrap_or_else(|| h.capacity.as_ref().map_or(0, |c| c.job_slots));
    HwView {
        os: h.os.as_deref().and_then(Os::from_name),
        arch: h.arch.as_deref().and_then(Arch::from_name),
        device: h.device,
        name: h.name,
        kind,
        online: h.online,
        degraded: h.degraded,
        paused,
        capacity: h.capacity,
        sessions,
        jobs,
        job_slots,
        sustained_full: h.sustained_full,
    }
}

/// Every runner the hub has seen, as machines.
pub async fn machines(app: &App) -> Result<Vec<Machine>, sqlx::Error> {
    let kinds = kinds(&app.pool).await?;
    let now = app.clock.now();
    type PrefRow = (String, Option<String>, Option<u32>, Option<u32>, Option<i64>);
    let rows: Vec<PrefRow> = sqlx::query_as(
        "SELECT device_id, paused_until, job_slots, first_cores, first_mem_mb FROM core_hardware_prefs",
    )
    .fetch_all(&app.pool)
    .await?;
    let mut first: HashMap<String, (u32, u64)> = HashMap::new();
    let mut prefs: HashMap<String, (Option<String>, Option<u32>)> = HashMap::new();
    for (d, p, s, cores, mem) in rows {
        if let (Some(c), Some(m)) = (cores, mem) {
            first.insert(d.clone(), (c, u64::try_from(m).unwrap_or(0)));
        }
        prefs.insert(d, (p, s));
    }
    let cached: HashSet<(String, i64)> =
        sqlx::query_as::<_, (String, i64)>("SELECT device_id, project_id FROM core_hw_cache")
            .fetch_all(&app.pool)
            .await?
            .into_iter()
            .collect();
    let mut hardware = app.hub.hardware();
    for h in &mut hardware {
        let device = h.device.clone();
        let Some(c) = h.capacity.as_mut() else {
            continue;
        };
        let seen = match first.get(&device) {
            Some(f) => *f,
            None => {
                let f = (c.cores, c.mem_total_mb);
                if let Err(e) = record_first(&app.pool, &device, f).await {
                    tracing::warn!(error = %e, device, "recording a runner's first hardware failed");
                }
                first.insert(device.clone(), f);
                f
            }
        };
        held_to(c, seen, |p| cached.contains(&(device.clone(), p)));
    }
    let sessions: HashMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT runner, count(*) FROM core_agent_sessions \
         WHERE state NOT IN ('ended', 'lost') GROUP BY runner",
    )
    .fetch_all(&app.pool)
    .await?
    .into_iter()
    .collect();
    let mut jobs: HashMap<String, Vec<LiveJob>> = HashMap::new();
    type JobRow = (String, String, Option<i64>, String, Option<String>, String);
    let rows: Vec<JobRow> = sqlx::query_as(
        "SELECT device_id, id, project_id, argv, started_at, created_at FROM core_hw_jobs \
         WHERE state IN ('queued', 'syncing', 'running') ORDER BY created_at",
    )
    .fetch_all(&app.pool)
    .await?;
    for (device, id, project, argv, started, created) in rows {
        jobs.entry(device).or_default().push(LiveJob {
            id,
            project,
            label: label_of(&argv),
            started_at: started.unwrap_or(created),
        });
    }
    let pool_pause = kinds
        .iter()
        .find(|(_, k)| **k == HwKind::Core)
        .and_then(|(d, _)| prefs.get(d))
        .and_then(|(p, _)| p.clone())
        .filter(|p| p.as_str() > now.as_str());
    Ok(hardware
        .into_iter()
        .map(|h| {
            let kind = kinds.get(&h.device).copied().unwrap_or(HwKind::Runner);
            let (own, slots) = prefs.get(&h.device).cloned().unwrap_or_default();
            // The later of the two pauses holds; the Core's row is the pool's, not its own.
            let until = if kind == HwKind::Core {
                None
            } else {
                later(own, pool_pause.clone())
            };
            let live = jobs.remove(&h.device).unwrap_or_default();
            let n_sessions =
                u32::try_from(sessions.get(&h.device).copied().unwrap_or(0)).unwrap_or(0);
            let view = view_of(
                h,
                kind,
                is_paused(until.as_deref(), &now),
                slots,
                n_sessions,
                u32::try_from(live.len()).unwrap_or(u32::MAX),
            );
            Machine {
                view,
                paused_until: if kind == HwKind::Core {
                    pool_pause.clone()
                } else {
                    until.filter(|u| u.as_str() > now.as_str())
                },
                jobs: live,
            }
        })
        .collect())
}

/// Records the hardware the Core first saw from `device` (`core_hardware_prefs.first_*`); a later
/// first sight never replaces it.
async fn record_first(pool: &SqlitePool, device: &str, (cores, mem): (u32, u64)) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO core_hardware_prefs (device_id, first_cores, first_mem_mb) VALUES (?, ?, ?) \
         ON CONFLICT (device_id) DO UPDATE SET \
         first_cores = COALESCE(core_hardware_prefs.first_cores, excluded.first_cores), \
         first_mem_mb = COALESCE(core_hardware_prefs.first_mem_mb, excluded.first_mem_mb)",
    )
    .bind(device)
    .bind(cores)
    .bind(i64::try_from(mem).unwrap_or(i64::MAX))
    .execute(pool)
    .await
    .map(|_| ())
}

/// The most toolchains, and the longest name or version, a report keeps (L16).
const MAX_TOOLCHAINS: usize = 32;
const MAX_TOOL_TEXT: usize = 64;

/// A runner's report held to what can be checked (E15 security review M8): no more cores or memory
/// than the Core first saw (`first`), one job slot per core at most, only the warm caches the Core
/// itself synced (`synced`), and a bounded toolchain list. CPU use and the gate cannot be checked
/// from here and stay as sent.
fn held_to(c: &mut Capacity, first: (u32, u64), synced: impl Fn(i64) -> bool) {
    c.cores = c.cores.min(first.0);
    c.mem_total_mb = c.mem_total_mb.min(first.1);
    c.mem_free_mb = c.mem_free_mb.min(c.mem_total_mb);
    c.cpu_pct = c.cpu_pct.min(100);
    c.job_slots = c.job_slots.min(c.cores.max(1));
    c.caches.retain(|k| synced(k.project));
    c.toolchains
        .retain(|k, v| k.len() <= MAX_TOOL_TEXT && v.len() <= MAX_TOOL_TEXT);
    while c.toolchains.len() > MAX_TOOLCHAINS {
        c.toolchains.pop_last();
    }
}

/// The placement views alone.
pub async fn views(app: &App) -> Result<Vec<HwView>, sqlx::Error> {
    Ok(machines(app).await?.into_iter().map(|m| m.view).collect())
}

/// `["cargo","build",…]` as `cargo build`: the program and one subcommand only, cut to 120
/// characters, so a `read` device never sees a task's whole `sh -c` command (E15 L17).
fn label_of(argv: &str) -> String {
    let words: Vec<String> = serde_json::from_str(argv).unwrap_or_default();
    words
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(120)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runners_report_is_held_to_what_the_core_first_saw_and_synced() {
        // M8: a compromised runner claims more of everything to win every heavy job.
        let mut c = Capacity {
            cores: 512,
            cpu_pct: 250,
            mem_total_mb: 1 << 30,
            mem_free_mb: 1 << 30,
            job_slots: 10_000,
            caches: [3, 4]
                .map(|project| ainkrad_proto::v2::CacheInfo {
                    project,
                    ..Default::default()
                })
                .to_vec(),
            toolchains: (0..100).map(|i| (format!("t{i:03}"), "1".to_owned())).collect(),
            ..Default::default()
        };
        held_to(&mut c, (8, 16_384), |p| p == 4);
        assert_eq!((c.cores, c.mem_total_mb, c.mem_free_mb), (8, 16_384, 16_384));
        assert_eq!((c.cpu_pct, c.job_slots), (100, 8));
        assert_eq!(c.caches.iter().map(|k| k.project).collect::<Vec<_>>(), [4]);
        assert_eq!(c.toolchains.len(), MAX_TOOLCHAINS);
        // An honest report is left as it is.
        let mut ok = Capacity {
            cores: 8,
            mem_total_mb: 16_384,
            mem_free_mb: 4_000,
            job_slots: 2,
            ..Default::default()
        };
        let before = ok.clone();
        held_to(&mut ok, (8, 16_384), |_| true);
        assert_eq!(ok, before);
    }

    #[test]
    fn the_local_enrolment_is_the_core_and_the_attested_bundle_is_this_mac() {
        assert_eq!(kind_of(LOCAL_ENROL_SAS, false), HwKind::Core);
        assert_eq!(kind_of(LOCAL_ENROL_SAS, true), HwKind::Core);
        assert_eq!(kind_of("123456", true), HwKind::Mac);
        assert_eq!(kind_of("123456", false), HwKind::Runner);
    }

    #[test]
    fn a_pause_holds_until_its_time() {
        let now = "2026-11-20T10:00:00.000Z";
        assert!(is_paused(Some("2026-11-20T10:00:01.000Z"), now));
        assert!(!is_paused(Some(now), now));
        assert!(!is_paused(None, now));
        assert!(is_paused(Some("9999-12-31T00:00:00.000Z"), now));
    }

    #[test]
    fn the_later_pause_holds() {
        let (a, b) = (
            "2026-11-21T00:00:00.000Z".to_owned(),
            "2026-11-22T00:00:00.000Z".to_owned(),
        );
        assert_eq!(later(Some(a.clone()), Some(b.clone())), Some(b.clone()));
        assert_eq!(later(Some(a.clone()), None), Some(a));
        assert_eq!(later(None, None), None);
    }

    #[test]
    fn a_label_is_the_program_and_one_subcommand() {
        assert_eq!(label_of(r#"["cargo","build","-p","x"]"#), "cargo build");
        assert_eq!(
            label_of(r#"["sh","-c","deploy --token s3cret"]"#),
            "sh -c"
        );
        assert_eq!(label_of("nonsense"), "");
    }
}
