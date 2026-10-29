-- An account's plan tier (e.g. `Max 20x`, `Pro`), set by the admin; shown, never enforced.
ALTER TABLE accounts ADD COLUMN plan_tier TEXT
    CHECK (plan_tier IS NULL OR length(plan_tier) BETWEEN 1 AND 64);
