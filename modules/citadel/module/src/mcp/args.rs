//! Tool arguments and errors: what an agent sent, checked at the boundary.

use std::fmt;

use rmcp::model::JsonObject;
use serde_json::Value;

/// Why a tool call did nothing. The message goes back to the agent.
#[derive(Debug)]
pub(super) enum ToolError {
    /// Outside the run's scope, or not allowed by the rules.
    Refused(String),
    /// A missing or malformed argument.
    Invalid(String),
    /// The server failed; the detail is logged, not shown.
    Failed(String),
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Invalid(why) => write!(f, "invalid arguments: {why}"),
            Self::Failed(_) => f.write_str("internal error; try again later"),
        }
    }
}

impl From<sqlx::Error> for ToolError {
    fn from(e: sqlx::Error) -> Self {
        Self::Failed(e.to_string())
    }
}

pub(super) type Result<T> = std::result::Result<T, ToolError>;

/// The largest text an agent may write in one field.
pub(super) const MAX_TEXT: usize = 32 * 1024;
/// The largest title.
pub(super) const MAX_TITLE: usize = 200;

/// An optional integer argument.
pub(super) fn int(args: &JsonObject, key: &str) -> Result<Option<i64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| ToolError::Invalid(format!("{key} must be an integer"))),
    }
}

/// An optional text argument of at most `max` bytes.
pub(super) fn text<'a>(args: &'a JsonObject, key: &str, max: usize) -> Result<Option<&'a str>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.len() > max => Err(ToolError::Invalid(format!(
            "{key} is {} bytes; the most is {max}",
            s.len()
        ))),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(ToolError::Invalid(format!("{key} must be a string"))),
    }
}

/// A required, non-blank text argument of at most `max` bytes.
pub(super) fn required<'a>(args: &'a JsonObject, key: &str, max: usize) -> Result<&'a str> {
    match text(args, key, max)? {
        Some(s) if !s.trim().is_empty() => Ok(s),
        _ => Err(ToolError::Invalid(format!("{key} is required"))),
    }
}

/// `s` cut to at most `max` bytes on a character boundary, and whether it was cut.
pub(super) fn clip(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_owned(), false);
    }
    (s[..s.floor_char_boundary(max)].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn object(v: Value) -> JsonObject {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn reads_and_checks_arguments() {
        let a = object(json!({"n": 3, "s": "hi", "blank": " ", "bad": "x"}));
        assert_eq!(int(&a, "n").unwrap(), Some(3));
        assert_eq!(int(&a, "missing").unwrap(), None);
        assert!(int(&a, "bad").is_err());
        assert_eq!(required(&a, "s", 10).unwrap(), "hi");
        assert!(required(&a, "blank", 10).is_err());
        assert!(required(&a, "missing", 10).is_err());
        assert!(text(&a, "s", 1).is_err(), "too long");
        assert!(text(&a, "n", 10).is_err(), "not a string");
    }

    #[test]
    fn clips_on_a_character_boundary() {
        assert_eq!(clip("héllo", 2), ("h".to_owned(), true));
        assert_eq!(clip("hi", 2), ("hi".to_owned(), false));
    }
}
