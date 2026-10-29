-- The platform a runner says it runs on (runner protocol 1.25; NULL until it says): Rust's OS and
-- architecture names, e.g. `macos` and `aarch64`.
ALTER TABLE runners ADD COLUMN os TEXT;
ALTER TABLE runners ADD COLUMN arch TEXT;
