-- Epic keys (Quest, E12): each epic is numbered per project, `<KEY>-E<n>` (`CIT-E3`), from its
-- project's counter, never reused (like issue numbers). Existing epics are numbered by id.
-- A trigger numbers every new epic, so no insert path can skip it.
ALTER TABLE projects ADD COLUMN next_epic_number INTEGER NOT NULL DEFAULT 1;
ALTER TABLE epics ADD COLUMN number INTEGER CHECK (number > 0);

UPDATE epics SET number = (SELECT count(*) FROM epics e WHERE e.project_id = epics.project_id
                                                          AND e.id <= epics.id);
UPDATE projects SET next_epic_number =
    (SELECT coalesce(max(number), 0) + 1 FROM epics WHERE project_id = projects.id);
CREATE UNIQUE INDEX epics_number ON epics (project_id, number);

CREATE TRIGGER epics_number AFTER INSERT ON epics
BEGIN
    UPDATE epics SET number = (SELECT next_epic_number FROM projects WHERE id = NEW.project_id)
    WHERE id = NEW.id;
    UPDATE projects SET next_epic_number = next_epic_number + 1 WHERE id = NEW.project_id;
END;
