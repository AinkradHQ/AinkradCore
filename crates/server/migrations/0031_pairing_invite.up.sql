-- Invite pairings (handshake spec §7.3): claimable over the network by the QR secret alone, with no
-- expiry (its `expires_at` is the constant `9999-12-31T23:59:59.999Z`, so the scheduler's sweep never
-- reaches it), single use, and enrolled active at the claim. 1: an invite. Additive only.
ALTER TABLE core_pairings ADD COLUMN invite INTEGER NOT NULL DEFAULT 0;
