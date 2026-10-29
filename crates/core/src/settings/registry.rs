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
}
