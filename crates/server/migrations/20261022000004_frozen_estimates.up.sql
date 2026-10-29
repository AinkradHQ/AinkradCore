-- While a sprint's commit waits on its approval (E5.4), the points of its issues are frozen
-- with its scope: the approval holds them. Every write path (an estimate, an issue edit, a
-- raw update, a new subtask joining its parent's sprint) is refused here; `estimate_issue`
-- checks first to give a typed reason.

CREATE TRIGGER issues_points_frozen_update BEFORE UPDATE OF points ON issues
WHEN NEW.points IS NOT OLD.points AND EXISTS (SELECT 1 FROM approvals
    WHERE sprint_id = NEW.sprint_id AND kind = 'sprint_commit' AND status = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'estimates are frozen while the sprint commit awaits approval');
END;

CREATE TRIGGER issues_points_frozen_insert BEFORE INSERT ON issues
WHEN NEW.points IS NOT NULL AND EXISTS (SELECT 1 FROM approvals
    WHERE sprint_id = NEW.sprint_id AND kind = 'sprint_commit' AND status = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'estimates are frozen while the sprint commit awaits approval');
END;
