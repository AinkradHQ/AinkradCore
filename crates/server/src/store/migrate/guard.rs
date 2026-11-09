//! The static check on a module's migration text: it may name, as a table, index, view or
//! trigger, only objects that start with the module's prefix `<id>_`. Conservative on purpose:
//! anything it cannot read with certainty is refused, and a refused migration stops the
//! server at start. A false refusal costs the module author a rename; a false accept would let
//! a module write the platform's tables.
//!
//! It also refuses any word equal to a platform object's name, wherever it stands (a comma
//! join, a column, an expression), so a module column cannot be called `events`, `settings`
//! or `users`. The one exception is `REFERENCES users`, so a module's user-owned rows can
//! follow the `user_id` convention of the baseline migration.
//!
//! The runner backs this with a schema diff after each migration (`super::schema_changes`), so
//! an object this check missed still cannot be created, altered or dropped outside the prefix.

/// One token of SQL text; comments and whitespace are dropped.
#[derive(Debug, PartialEq)]
enum Tok {
    /// An identifier or keyword, lowercased; `quoted` when it was in `"…"`, `` `…` `` or `[…]`.
    Word {
        text: String,
        quoted: bool,
    },
    /// A string, blob or number literal.
    Literal,
    Punct(char),
}

fn tokens(sql: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    // The index just past the closing `close`, where a doubled `close` is an escaped one.
    let quoted_end = |from: usize, close: char| -> Result<usize, String> {
        let mut j = from;
        loop {
            match chars.get(j) {
                None => return Err(format!("unterminated {close} quote")),
                Some(&c) if c == close && chars.get(j + 1) == Some(&close) && close != ']' => {
                    j += 2
                }
                Some(&c) if c == close => return Ok(j + 1),
                Some(_) => j += 1,
            }
        }
    };
    while let Some(&c) = chars.get(i) {
        match c {
            _ if c.is_whitespace() => i += 1,
            '-' if chars.get(i + 1) == Some(&'-') => {
                while chars.get(i).is_some_and(|&c| c != '\n') {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                let end = (i + 2..chars.len().saturating_sub(1))
                    .find(|&j| chars[j] == '*' && chars[j + 1] == '/')
                    .ok_or("unterminated comment")?;
                i = end + 2;
            }
            '\'' => {
                i = quoted_end(i + 1, '\'')?;
                out.push(Tok::Literal);
            }
            '"' | '`' | '[' => {
                let close = if c == '[' { ']' } else { c };
                let end = quoted_end(i + 1, close)?;
                let text: String = chars[i + 1..end - 1].iter().collect();
                let doubled: String = [close, close].iter().collect();
                out.push(Tok::Word {
                    text: text.replace(&doubled, &close.to_string()).to_lowercase(),
                    quoted: true,
                });
                i = end;
            }
            _ if c.is_ascii_digit() => {
                while chars
                    .get(i)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '.')
                {
                    i += 1;
                }
                out.push(Tok::Literal);
            }
            _ if c.is_alphabetic() || c == '_' => {
                let start = i;
                while chars
                    .get(i)
                    .is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                {
                    i += 1;
                }
                let text: String = chars[start..i].iter().collect();
                // A blob literal, x'…'.
                if text.eq_ignore_ascii_case("x") && chars.get(i) == Some(&'\'') {
                    i = quoted_end(i + 1, '\'')?;
                    out.push(Tok::Literal);
                } else {
                    out.push(Tok::Word {
                        text: text.to_lowercase(),
                        quoted: false,
                    });
                }
            }
            _ => {
                out.push(Tok::Punct(c));
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Bare words that end the check at once: they reach outside the migration's transaction or
/// the main schema.
const FORBIDDEN: [&str; 8] = [
    "attach",
    "detach",
    "pragma",
    "vacuum",
    "commit",
    "temp",
    "temporary",
    "load_extension",
];

fn bare(tok: Option<&Tok>) -> Option<&str> {
    match tok {
        Some(Tok::Word {
            text,
            quoted: false,
        }) => Some(text),
        _ => None,
    }
}

/// Checks `sql`, a module's up or down text, against the module's `prefix` (`<id>_`) and the
/// names of the `platform`'s objects.
pub(super) fn check(prefix: &str, platform: &[String], sql: &str) -> Result<(), String> {
    let toks = tokens(sql)?;
    for (i, tok) in toks.iter().enumerate() {
        let Tok::Word { text, .. } = tok else {
            continue;
        };
        let users_fk = text == "users" && i > 0 && bare(toks.get(i - 1)) == Some("references");
        if platform.contains(text) && !users_fk {
            return Err(format!("`{text}` names a platform object"));
        }
    }
    // After `INDEX <name>` or `TRIGGER <name>`, the next `ON` names the table it is on.
    let mut header_on = false;
    let mut i = 0;
    while i < toks.len() {
        let Some(word) = bare(toks.get(i)) else {
            i += 1;
            continue;
        };
        if FORBIDDEN.contains(&word) {
            return Err(format!(
                "`{}` is not allowed in a module migration",
                word.to_uppercase()
            ));
        }
        let next = bare(toks.get(i + 1));
        let mut at = i + 1;
        let names_object = match word {
            "table" | "view" | "into" | "references" => true,
            "index" | "trigger" => {
                header_on = true;
                true
            }
            "from" | "join" => toks.get(at) != Some(&Tok::Punct('(')),
            // `UPDATE OF col ON t` and `UPDATE ON t` (a trigger's event), `DO UPDATE SET` (an
            // upsert), `ON UPDATE CASCADE` (a foreign key): no table follows.
            // `UPDATE OR REPLACE t`: skip the conflict clause.
            "update" if i > 0 && bare(toks.get(i - 1)) == Some("on") => false,
            "update" => match next {
                Some("of" | "on" | "set") => false,
                Some("or") => {
                    at += 2;
                    true
                }
                _ => true,
            },
            "on" if header_on => {
                header_on = false;
                true
            }
            "rename" if next == Some("to") => {
                at += 1;
                true
            }
            _ => false,
        };
        if names_object {
            // `IF [NOT] EXISTS`
            if bare(toks.get(at)) == Some("if") {
                at += if bare(toks.get(at + 1)) == Some("not") {
                    3
                } else {
                    2
                };
            }
            let Some(Tok::Word { text: name, .. }) = toks.get(at) else {
                return Err(format!(
                    "cannot read the name after `{}`",
                    word.to_uppercase()
                ));
            };
            if toks.get(at + 1) == Some(&Tok::Punct('.')) {
                return Err(format!("schema-qualified name `{name}.…` is not allowed"));
            }
            let users_fk = word == "references" && name == "users";
            if !name.starts_with(prefix) && !users_fk {
                return Err(format!(
                    "`{name}` is outside the module's prefix `{prefix}`"
                ));
            }
            i = at + 1;
        } else {
            i += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A stand-in for the platform's object names.
    fn check(prefix: &str, sql: &str) -> Result<(), String> {
        let platform =
            ["users", "settings", "events", "device_keys", "push_cursor"].map(str::to_owned);
        super::check(prefix, &platform, sql)
    }

    #[test]
    fn a_module_may_shape_its_own_tables() {
        let sql = r#"
            -- a comment naming users; and 'a string naming settings'
            CREATE TABLE IF NOT EXISTS toy_items (
                id      INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id) ON DELETE CASCADE,
                parent  INTEGER REFERENCES toy_items(id) ON UPDATE CASCADE,
                note    TEXT NOT NULL DEFAULT 'from users' /* settings */,
                blob    BLOB DEFAULT x'00',
                UNIQUE (note) ON CONFLICT REPLACE
            );
            CREATE UNIQUE INDEX toy_items_note ON toy_items (note);
            CREATE VIEW "toy_view" AS SELECT i.id FROM toy_items AS i JOIN toy_items j ON i.id = j.parent;
            CREATE TRIGGER toy_items_touch AFTER UPDATE OF note ON toy_items
            BEGIN
                INSERT INTO toy_log (item) VALUES (NEW.id) ON CONFLICT (item) DO UPDATE SET n = n + 1;
                UPDATE OR IGNORE toy_items SET note = 'x' WHERE id IN (SELECT id FROM toy_items);
                DELETE FROM toy_log WHERE item = OLD.id;
            END;
            ALTER TABLE toy_items RENAME TO toy_things;
            ALTER TABLE toy_things RENAME COLUMN note TO body;
            DROP TABLE IF EXISTS toy_log;
        "#;
        assert_eq!(check("toy_", sql), Ok(()));
    }

    #[test]
    fn a_module_may_not_reach_outside_its_prefix() {
        for sql in [
            "ALTER TABLE users ADD COLUMN x TEXT",
            "DROP TABLE settings",
            "DROP TRIGGER audit_events_no_update",
            "DROP INDEX IF EXISTS audit_events_entity",
            "CREATE TABLE items (id INTEGER)",
            "CREATE TABLE \"users\" (id INTEGER)",
            "CREATE TABLE [toy_x] (a INTEGER REFERENCES device_keys(id))",
            "CREATE INDEX toy_i ON users (name)",
            "CREATE TRIGGER toy_t BEFORE DELETE ON audit_events BEGIN SELECT 1; END",
            "CREATE TRIGGER toy_t AFTER INSERT ON toy_x BEGIN DELETE FROM events; END",
            "CREATE TRIGGER toy_t AFTER INSERT ON toy_x BEGIN UPDATE OR REPLACE users SET name = 'x'; END",
            "INSERT INTO settings VALUES (1)",
            "INSERT INTO toy_x SELECT * FROM device_keys",
            "INSERT INTO toy_x SELECT key_hash FROM toy_a, device_keys",
            "CREATE TABLE toy_x (events TEXT)",
            "INSERT INTO main.toy_x VALUES (1)",
            "CREATE TABLE toy_x AS SELECT * FROM (SELECT 1) JOIN push_cursor",
            "ALTER TABLE toy_x RENAME TO users",
            "UPDATE events SET kind = 'x'",
            "ATTACH DATABASE 'other.db' AS toy_other",
            "PRAGMA foreign_keys = OFF",
            "COMMIT; DROP TABLE users",
            "CREATE TEMP TABLE toy_x (a)",
            "SELECT load_extension('x')",
            "CREATE TABLE toy_x (a TEXT DEFAULT 'unterminated)",
            "CREATE TABLE toy_x (a) /* unterminated",
            "CREATE TABLE",
        ] {
            assert!(check("toy_", sql).is_err(), "must refuse: {sql}");
        }
    }
}
