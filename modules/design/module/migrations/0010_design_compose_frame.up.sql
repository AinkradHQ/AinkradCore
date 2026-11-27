-- An edit compose (`mode: "edit"`): the frame it redraws. NULL for a compose that draws new screens.
ALTER TABLE design_composes ADD COLUMN frame TEXT;
