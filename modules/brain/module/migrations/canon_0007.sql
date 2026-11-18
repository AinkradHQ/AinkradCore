-- B6-02 retention: the eligibility query looks a source's import time up in the op log by item id.
CREATE INDEX op_log_ref ON op_log(ref, op);
