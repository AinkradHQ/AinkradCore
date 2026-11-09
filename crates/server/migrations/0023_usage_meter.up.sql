-- Usage per attempt for a session no gateway serves (KAN-436 S1, design 2026-11-06 §6): a
-- subscription session's harness meter reports a running total per epoch, and the Core turns it
-- into ledger deltas. `hm_*` is the high-water mark already recorded: the epoch it belongs to and
-- its cumulative input, output and cache counts. Additive only; a new epoch starts again from 0.
ALTER TABLE core_agent_sessions ADD COLUMN hm_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_agent_sessions ADD COLUMN hm_in INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_agent_sessions ADD COLUMN hm_out INTEGER NOT NULL DEFAULT 0;
ALTER TABLE core_agent_sessions ADD COLUMN hm_cache INTEGER NOT NULL DEFAULT 0;
