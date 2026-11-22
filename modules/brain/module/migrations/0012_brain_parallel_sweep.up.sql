-- The dreaming sweep (`threshold`) may run up to `auto_distil::MAX_PER_ROOM` batches of one room at
-- once; that cap is checked in `auto_distil::queue`'s write transaction. Every other trigger keeps
-- one open distil per room, enforced here as before.
DROP INDEX brain_distils_one_open;
CREATE UNIQUE INDEX brain_distils_one_open ON brain_distils(room)
    WHERE state IN ('queued','needs_local_model','waiting','running') AND "trigger" <> 'threshold';
