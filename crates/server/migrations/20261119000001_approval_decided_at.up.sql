-- When an approval left `pending` (approved, rejected or expired; API minor 17), so the app can
-- say "asked 12m ago" and "decided 3m ago". Existing decided rows take the time of their
-- `approval.<status>` audit entry.
ALTER TABLE approvals ADD COLUMN decided_at TEXT;
UPDATE approvals SET decided_at = (SELECT max(e.at) FROM audit_events e
    WHERE e.entity_kind = 'approval' AND e.entity_id = approvals.id
    AND e.action IN ('approval.approved', 'approval.rejected', 'approval.expired'))
WHERE status <> 'pending';
