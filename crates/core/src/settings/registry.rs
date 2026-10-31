//! Every platform tunable (E15.17, decision #52): name, unit, default, bounds, scopes, meaning. A
//! new one is appended at the end: `Key` indexes `REGISTRY` by position.

use super::*;

registry! {
    SchedulerTickSecs "scheduler.tick_secs" Seconds 10, 1, 300, SO,
        "Time between scheduler ticks; read at start.";
    PushIntervalSecs "push.interval_secs" Seconds 5, 1, 300, SO,
        "Time between push passes to the app's devices; read at start.";
    ApiRequestBurst "api.request_burst" Count 120, 10, 10_000, SO,
        "Client API requests one device may send at once; read at start.";
    ApiRequestsPerMin "api.requests_per_min" PerMinute 1200, 60, 60_000, SO,
        "Client API requests one device may send per minute, sustained; read at start.";
    EventsRetentionSecs "events.retention_secs" Seconds 2_592_000, 3_600, 315_360_000, SO,
        "How long events stay replayable; older ones are trimmed and a client resuming from \
         before them re-syncs. Read every scheduler tick.";
    AuthStepUpSecs "auth.step_up_secs" Seconds 300, 60, 900, SO,
        "How long a step-up (user verification on the device) keeps its session elevated for \
         destructive routes; read at each step-up.";
    AuthWebSessionSecs "auth.web_session_secs" Seconds 28_800, 3_600, 86_400, SO,
        "How long a web session from a passkey sign-in lives, absolute (never extended); read at \
         each sign-in.";
    AuthPasskeyAdmin "auth.passkey_admin" Count 0, 0, 1, SO,
        "1 lets a passkey (a browser, E1-08) hold the admin scope, 0 (the default) refuses it at \
         pairing, approval and a scope change: a synced passkey is only as strong as its Apple or \
         Google account (threat model T-PK-3). Devices that hold it already keep it. Read at \
         each of those.";
    SecretsMode "secrets.mode" Count 0, 0, 2, SO,
        "The secrets broker (E2-07) and gate G-SEC: 0 (the default) is off, refusing every store, \
         rotation, lease and redemption; 1 takes throwaway credentials only, refusing a value \
         shaped like a real one (a provider key, a GitHub token, a Bearer credential, a PEM block); \
         2 takes real credentials, and is set only once the external security review (G-SEC) has \
         closed. Listing and deleting always work. Read at each use.";
    SecretsMaxBytes "secrets.max_bytes" Bytes 8_192, 1, 65_536, SO,
        "The largest secret value the broker stores; read at each store and rotation.";
    SecretsMaxCount "secrets.max_count" Count 64, 1, 1_024, SO,
        "How many secrets the broker holds at most; read at each store.";
    SecretsLeaseSecs "secrets.lease_secs" Seconds 120, 10, 900, SO,
        "The longest (and the default) lifetime of a secret lease, from grant to redemption; read \
         at each grant.";
    SecretsMaxLeases "secrets.max_leases" Count 64, 1, 1_024, SO,
        "How many unredeemed, unexpired secret leases may exist at once; read at each grant.";
    TerminalIdleSecs "terminal.idle_secs" Seconds 86_400, 0, 2_592_000, SO,
        "How long a running terminal with no client attached is kept before the Core closes it \
         (a client that attaches again restarts the count); 0 never closes one. Read at each \
         pass of the idle reaper, every 30 seconds.";
    TerminalMaxPerDevice "terminal.max_per_device" Count 8, 1, 64, SO,
        "How many terminals (not yet ended) one device may have open; read at each create.";
    TerminalMaxPerRunner "terminal.max_per_runner" Count 16, 1, 256, SO,
        "How many terminals (not yet ended) one runner may hold for the Core; read at each \
         create.";
    AlarmBackupMaxAgeSecs "alarm.backup_max_age_secs" Seconds 172_800, 3_600, 31_536_000, SO,
        "The alarm `backup_age` raises when the newest backup in the home is older than this (or \
         there is none and the database is older); it clears once a newer one lands. Read at \
         each alarm pass.";
    AlarmCertMinDays "alarm.cert_min_days" Count 14, 1, 90, SO,
        "The alarm `cert_expiry` raises when the public listener's certificate has fewer than this \
         many days left; it clears once it is renewed. Read at each alarm pass.";
    AlarmDiskMinFreePct "alarm.disk_min_free_pct" Percent 10, 1, 90, SO,
        "The alarm `disk_free` raises when the filesystem holding the database has less than this \
         share free; it clears once there is more. Read at each alarm pass.";
}
