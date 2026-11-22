UPDATE brain_distils SET state = 'failed', detail = 'duplicate open distillation'
    WHERE state IN ('queued','needs_local_model','waiting','running')
    AND rowid NOT IN (SELECT min(rowid) FROM brain_distils
        WHERE state IN ('queued','needs_local_model','waiting','running') GROUP BY room);
DROP INDEX brain_distils_one_open;
CREATE UNIQUE INDEX brain_distils_one_open ON brain_distils(room)
    WHERE state IN ('queued','needs_local_model','waiting','running');
