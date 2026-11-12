-- Who distilled a candidate: the provider and account name of the session's account, and its tool.
ALTER TABLE records ADD COLUMN provider TEXT;
ALTER TABLE records ADD COLUMN account TEXT;
ALTER TABLE records ADD COLUMN tool TEXT;
