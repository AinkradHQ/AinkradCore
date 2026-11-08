//! The `--help` text of the account, pool and budget commands.

/// The `--help` text of the account, pool and budget commands (`@@ACCOUNTS@@` in the main text).
pub const HELP: &str = "  account ls | show <id> | providers
      The provider accounts (scope admin): state, the sessions holding a slot now against the
      cap (live N/cap, `-` is no cap) and the health counters; show adds the cooldown's reason
      and end, the last success, the gateway's last status class and a subscription's plan
      limit (status, then each window's use and reset). providers lists the provider ids
      an account can be made for (built-in and user-defined), their base URL and delivery.
  account add <provider>* [--label l] [--cap n] [--runners <runner-id>,...] [--key-file f]
  account rotate <id>* [--runners ...] [--key-file f]
      Makes (or re-keys) an API-key account. The key is read from --key-file, else
      $AINKRAD_ACCOUNT_KEY, else stdin (never a terminal); --key works but is warned about
      (process list, shell history). It is sent in the request body only and never printed. The
      label defaults to the provider id; the cap (live sessions, 0 is no cap) to the Core's
      default. --runners names the runners the key may be leased to (default none: the account
      then serves no session). The Core's 409 (secrets_disabled, real_secret_refused, a taken
      label, limit_reached) and 400 (a key not shaped like the provider's) are said plainly.
  account login <provider>* [--label l] [--runner <runner-id>]
      A subscription account (claude-sub) by sign-in, driven on a runner: prints the address to
      open, asks for the approval code it shows (pasted at the prompt, or $AINKRAD_ACCOUNT_CODE;
      never printed), then follows the sign-in until the account is stored. The sign-in lasts 10
      minutes. Ctrl-C cancels it at the Core (exit 130); failed or cancelled is exit 4 with the
      reason.
  account state <id> <active|cooling|limited|unhealthy|disabled>* [--reason r] [--until t]
      Sets an account's state by hand. `active` is \"it is fine\" (it clears the streaks); with no
      --until a cooling, limited or unhealthy state is a hold that never recovers on its own.
      Disabling a subscription account kills the live sessions holding its token.
  account cap <id> <n>*  |  limit set <id> <tokens|messages> <window-secs> <cap>* [--warn-percent n]
  account limit clear <id> <unit> <window-secs>*  |  session-limits <id>* [--max-tokens n]
                                                                     [--max-usd-micros n]
      The account's concurrency cap (0 to 64), its token/message limits per window, and what
      one session may spend through it (a dimension left out is cleared).
  account test <id>*  |  rm <id>*
      test makes one free request through a runner's gateway and prints the status class and
      latency (the Core paces it: one a minute, a 429 says how long). rm deletes the account with
      its key, leases and pool seats (a subscription's live sessions are killed; the token is
      not revoked at the provider).
  account usage  |  account costs [--account id] [--session id] [--limit n]
      Each account's tokens, messages and dollars over 5 hours and 7 days with its limits, and
      the cost events behind them (newest first; `unpriced` is a plan with no price).
  pool ls | show <id> | create <name> <provider>* | add <pool> <account>* | remove <pool> <account>*
  pool default <pool>*  |  rm <pool>*
      Pools of accounts of one provider, members in fallback order (`pools` too). show adds each
      seat's account. The Core refuses an account of another provider (400), a second
      subscription in a pool, a pool a chain uses or the default pool (409): printed plainly.
  budget ls [--kind k] [--subject s] [--company c]  |  set <kind> <subject> <period> --tokens n*
  budget set ... [--usd-micros n] [--warn-percent n] [--no-hard-stop]  |  raise <id> <period-key>*
  budget rm <id>*
      Spend budgets (read to list, admin to change; kind account, pool, agent, ...; period day,
      week, month or total). A session needs about a turn of room (328000 tokens) in a
      hard-stop budget to start. raise adds headroom to a period that ran out
      (--tokens, --usd-micros).";
