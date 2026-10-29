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
}
