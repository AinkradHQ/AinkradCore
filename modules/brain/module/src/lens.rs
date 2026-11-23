//! Brain redesign helpers shared by the area routes: the rule kind, the area filter in SQL, the
//! rules that live in more than one place, and the Core's local days.

use std::collections::HashMap;

use ainkrad_core_server::api::App;
use serde::Serialize;
use sqlx::Row;
use utoipa::ToSchema;

use crate::areas::{Area, RoomRef, in_list, types_for};
use crate::rooms::RoomAccess;

/// A profile answer (`me_profile`): a `preference` whose id starts `me-`. It is the person
/// describing themselves, so it is About you (`me`), not a rule.
const ME_ANSWER: &str = "(type = 'preference' AND substr(id, 1, 3) = 'me-')";

/// The SQL condition over `memory` for the records of `area` in a room of `room_kind`, narrowed to
/// one record type when `only` is set; None when nothing of that area can match.
pub(crate) fn area_cond(area: Area, room_kind: &str, only: Option<&str>) -> Option<String> {
    let own = matches!(room_kind, "personal" | "global-safe");
    let types: Vec<&str> = types_for(area, room_kind)
        .iter()
        .copied()
        .filter(|t| only.is_none_or(|o| o == *t))
        .collect();
    let list = in_list(&types);
    let answers = own && only.is_none_or(|o| o == "preference");
    match (area, own) {
        (Area::Me, true) if answers && types.is_empty() => Some(ME_ANSWER.to_owned()),
        (Area::Me, true) if answers => Some(format!("(type IN ({list}) OR {ME_ANSWER})")),
        (Area::Rules, true) if !types.is_empty() => {
            Some(format!("(type IN ({list}) AND NOT {ME_ANSWER})"))
        }
        _ if types.is_empty() => None,
        _ => Some(format!("type IN ({list})")),
    }
}

/// `always`, `never` or `prefer`, derived from the record's type and text, never stored. A rule the
/// person wrote (`POST /areas/rules`) carries the kind they chose as a `kind:<name>` tag, which wins.
pub(crate) fn rule_kind(kind: &str, body: &str, tags: &str) -> &'static str {
    if kind == "preference" {
        return "prefer";
    }
    for chosen in ["never", "always"] {
        if tags.contains(&format!("\"kind:{chosen}\"")) {
            return chosen;
        }
    }
    const NEG: [&str; 14] = [
        "never",
        "don't",
        "dont",
        "avoid",
        "no",
        "cannot",
        "can't",
        "won't",
        "shouldn't",
        "mustn't",
        "doesn't",
        "stop",
        "ban",
        "banned",
    ];
    const NOT_AFTER: [&str; 4] = ["do", "must", "should", "will"];
    let low = body.to_lowercase().replace('\u{2019}', "'");
    let w: Vec<&str> = low
        .split(|c: char| !c.is_alphanumeric() && c != '\'')
        .filter(|x| !x.is_empty())
        .collect();
    let never = w.iter().any(|x| NEG.contains(x))
        || w.windows(2)
            .any(|p| p[1] == "not" && NOT_AFTER.contains(&p[0]));
    if never { "never" } else { "always" }
}

pub(crate) fn is_rule(kind: &str) -> bool {
    matches!(kind, "rule" | "preference")
}

#[derive(Serialize, ToSchema, Clone)]
pub struct PlaceRef {
    pub room: String,
    pub name: String,
}

/// For every open room: the normalised bodies of its current rules, so a rule worded the same in
/// two or more rooms is "everywhere". Returns the rooms of each body that appears in 2+ rooms.
pub(crate) async fn rule_places(
    rooms: &[(RoomRef, RoomAccess)],
) -> Result<HashMap<String, Vec<PlaceRef>>, sqlx::Error> {
    let mut by: HashMap<String, Vec<PlaceRef>> = HashMap::new();
    for (room, a) in rooms {
        let rows = sqlx::query(
            "SELECT DISTINCT coalesce(body_norm, lower(trim(body))) AS n FROM memory \
             WHERE type IN ('rule','preference')",
        )
        .fetch_all(a.pool())
        .await?;
        for r in rows {
            by.entry(r.try_get("n")?).or_default().push(PlaceRef {
                room: room.id.clone(),
                name: room.name.clone(),
            });
        }
    }
    by.retain(|_, v| v.len() > 1);
    Ok(by)
}

/// The Core's local days ending today, oldest first, as `YYYY-MM-DD`.
pub(crate) async fn local_days(app: &App, n: u32) -> Result<Vec<String>, sqlx::Error> {
    let back: Vec<String> = (0..n).rev().map(|i| i.to_string()).collect();
    sqlx::query_scalar(
        "SELECT date(?1, 'localtime', '-' || value || ' days') FROM json_each(?2) ORDER BY 1",
    )
    .bind(app.clock.now())
    .bind(format!("[{}]", back.join(",")))
    .fetch_all(&app.pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_kind_is_derived_from_type_and_words() {
        assert_eq!(rule_kind("preference", "never use tabs", "[]"), "prefer");
        assert_eq!(rule_kind("rule", "Never push to main", "[]"), "never");
        assert_eq!(
            rule_kind("rule", "Don\u{2019}t commit secrets", "[]"),
            "never"
        );
        assert_eq!(
            rule_kind("rule", "Do not merge without review", "[]"),
            "never"
        );
        assert_eq!(rule_kind("rule", "Avoid mocks in tests", "[]"), "never");
        assert_eq!(rule_kind("rule", "No force pushes", "[]"), "never");
        assert_eq!(
            rule_kind("rule", "Run make test before a PR", "[]"),
            "always"
        );
        assert_eq!(
            rule_kind("rule", "Notes go in the Docs folder", "[]"),
            "always"
        );
    }

    #[test]
    fn the_kind_the_person_chose_wins() {
        assert_eq!(
            rule_kind("rule", "Use tabs", r#"["you","kind:never"]"#),
            "never"
        );
        assert_eq!(
            rule_kind("rule", "Never use tabs", r#"["kind:always"]"#),
            "always"
        );
    }

    #[test]
    fn profile_answers_are_about_you_not_rules() {
        let me = area_cond(Area::Me, "personal", None).unwrap();
        assert!(me.contains("me-"), "{me}");
        let rules = area_cond(Area::Rules, "personal", None).unwrap();
        assert!(rules.contains("NOT"), "{rules}");
        assert!(area_cond(Area::Me, "product", None).is_none());
        assert!(area_cond(Area::Me, "personal", Some("rule")).is_none());
        assert_eq!(
            area_cond(Area::Me, "personal", Some("preference")).unwrap(),
            ME_ANSWER
        );
    }
}
