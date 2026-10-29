-- Why an agent proposes a knowledge entry or profile change (the client's proposal card): an
-- optional line, shown with it; NULL when none was given.
ALTER TABLE knowledge_entries ADD COLUMN rationale TEXT;
