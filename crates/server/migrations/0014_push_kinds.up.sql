-- Which notification kinds a device opted into (E2-12.3). No row: every kind its scopes allow
-- (the default, so a device registered before this keeps its pushes). The row is the device's,
-- not the token's: a pruned token registered again keeps the choice. It goes with revocation.
CREATE TABLE core_push_kinds (
    user_id    INTEGER NOT NULL DEFAULT 1 REFERENCES users(id),
    device_seq INTEGER PRIMARY KEY REFERENCES core_devices(seq) ON DELETE CASCADE,
    kinds      TEXT NOT NULL CHECK (json_valid(kinds))
);
