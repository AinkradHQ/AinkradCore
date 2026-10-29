-- Issue checkout (E2.3): the run that holds the issue, and since when. `checkout_run_id`
-- is a plain id, not a foreign key, so the down migration can drop it; a holder that is
-- gone or no longer live is treated as no holder.
ALTER TABLE issues ADD COLUMN checkout_run_id INTEGER;
ALTER TABLE issues ADD COLUMN checked_out_at TEXT
    CHECK ((checkout_run_id IS NULL) = (checked_out_at IS NULL));
