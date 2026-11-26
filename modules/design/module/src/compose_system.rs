//! `mode: "system"` of the Design composer: the AI draws ONE design system for a `system` doc, answered as JSON
//! (colours in day and night, a type scale, spacing, radii, two shadows). The Core never trusts the answer: every
//! colour is checked, every number clamped, and the result becomes `token` ops, written in one edit with the same
//! validators as any other batch. No frames are drawn.

use design_model::validate::{self, Cx};
use design_model::{Token, TokenKind};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use utoipa::ToSchema;

pub(crate) const COLORS: [&str; 11] = [
    "primary",
    "secondary",
    "accent",
    "background",
    "surface",
    "text",
    "muted",
    "border",
    "success",
    "warning",
    "danger",
];
const TYPES: [(&str, f64, i64, f64); 5] = [
    ("display", 40.0, 700, 48.0),
    ("title", 28.0, 700, 34.0),
    ("heading", 20.0, 600, 26.0),
    ("body", 16.0, 400, 24.0),
    ("caption", 12.0, 400, 16.0),
];
const SPACES: [(&str, f64); 5] = [("xs", 4.0), ("sm", 8.0), ("md", 16.0), ("lg", 24.0), ("xl", 40.0)];
const RADII: [(&str, f64); 3] = [("sm", 6.0), ("md", 10.0), ("lg", 16.0)];
const SHADOWS: [&str; 2] = ["sm", "md"];
const MAX_BRAND_COLORS: usize = 12;

/// A brand kit the app sends: its colours (`#rrggbb`) and name.
#[derive(Deserialize, ToSchema)]
pub struct Brand {
    /// Up to 12 colours, each `#rrggbb`.
    #[serde(default)]
    pub colors: Vec<String>,
    /// The brand's name, up to 60 characters.
    #[serde(default)]
    #[schema(required = false)]
    pub name: Option<String>,
}

/// The brand kit checked: colours are plain `#rrggbb`, at most 12; the name is clipped.
pub(crate) fn check_brand(b: &Brand) -> Result<(), &'static str> {
    let hex6 = |s: &str| {
        s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|c| c.is_ascii_hexdigit())
    };
    if b.colors.len() > MAX_BRAND_COLORS || !b.colors.iter().all(|c| hex6(c)) {
        return Err("brand colours are up to 12 values like #2F7BEF");
    }
    Ok(())
}

pub(crate) fn prompt(user: &str, brand: Option<&Brand>) -> String {
    let brand = match brand {
        Some(b) if !b.colors.is_empty() || b.name.is_some() => {
            let name = b.name.as_deref().unwrap_or("").chars().take(60).filter(|c| !c.is_control()).collect::<String>();
            format!(
                "\nThe brand{}: its colours are {}. Build the palette from them (primary, secondary and accent come \
                 from the brand colours; invent the rest to match).\n",
                if name.is_empty() { String::new() } else { format!(" is \"{name}\"") },
                b.colors.join(", ")
            )
        }
        _ => String::new(),
    };
    format!(
        "You are a design-system designer. Create ONE design system for this request:\n\n\"{user}\"\n{brand}\n\
         Reply with ONLY one JSON object, no prose and no code fence, in this shape:\n\
         {{\"name\":\"Aurora\",\"summary\":\"one short sentence\",\
         \"colors\":{{\"primary\":{{\"day\":\"#2F7BEF\",\"night\":\"#5B9BFF\"}}, ...}},\
         \"type\":{{\"display\":{{\"size\":40,\"weight\":700,\"line\":48}}, ...}},\
         \"space\":{{\"xs\":4,\"sm\":8,\"md\":16,\"lg\":24,\"xl\":40}},\
         \"radius\":{{\"sm\":6,\"md\":10,\"lg\":16}},\
         \"shadows\":{{\"sm\":{{\"x\":0,\"y\":1,\"blur\":3,\"spread\":0,\"color\":\"#00000026\"}},\"md\":{{...}}}}}}\n\
         Rules: `colors` has exactly these keys, each with a `day` and a `night` colour (#rrggbb): {colors}. Night \
         colours suit a dark screen (background and surface dark, text light). `type` has display, title, heading, \
         body and caption, each with size (8 to 96), weight (100 to 900) and line (8 to 120). `space` has xs, sm, md, \
         lg and xl (points, growing). `radius` has sm, md and lg. `shadows` has sm and md. Use plain words a normal \
         person understands in the name and summary.",
        colors = COLORS.join(", ")
    )
}

/// What the answer became: a name and a summary for the picker, and the `token` ops.
#[derive(Debug)]
pub(crate) struct Made {
    pub name: String,
    pub summary: String,
    pub ops: Vec<Value>,
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

fn num(v: Option<&Value>, lo: f64, hi: f64, default: f64) -> f64 {
    match v.and_then(Value::as_f64) {
        Some(x) if x.is_finite() => x.clamp(lo, hi),
        _ => default,
    }
}

fn color(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    validate::color(&json!(s), &mut Cx::resolved()).ok()?;
    Some(s.to_owned())
}

fn token_op(name: String, kind: TokenKind, day: Value, night: Value) -> Result<Value, String> {
    let t = Token { kind, day, night };
    validate::token(&t).map_err(|e| format!("{name}: {e}"))?;
    Ok(json!({"op": "token", "name": name, "value": t}))
}

/// The first `{` to the last `}` of the answer, turned into token ops. Colours must all be there and valid (the
/// brand is the point); the scales fall back to a standard value where the AI left one out or sent nonsense.
pub(crate) fn parse(answer: &str) -> Result<Made, String> {
    let (a, b) = (answer.find('{'), answer.rfind('}'));
    let (a, b) = match (a, b) {
        (Some(a), Some(b)) if a < b => (a, b),
        _ => return Err("the AI did not answer with a design system".into()),
    };
    let v: Value = serde_json::from_str(&answer[a..=b])
        .map_err(|_| "the AI's answer was not in the expected shape".to_owned())?;
    let empty = Map::new();
    let section = |k: &str| v.get(k).and_then(Value::as_object).unwrap_or(&empty);
    let mut ops = vec![];
    let colors = section("colors");
    for c in COLORS {
        let one = colors.get(c);
        let (Some(day), Some(night)) = (
            color(one.and_then(|o| o.get("day"))),
            color(one.and_then(|o| o.get("night"))),
        ) else {
            return Err(format!("the AI's colour {c} is missing or not a #rrggbb colour"));
        };
        ops.push(token_op(format!("color.{c}"), TokenKind::Color, json!(day), json!(night))?);
    }
    let types = section("type");
    for (name, size, weight, line) in TYPES {
        let t = types.get(name);
        let get = |k: &str| t.and_then(|t| t.get(k));
        let size = num(get("size"), 8.0, 96.0, size);
        let val = json!({
            "size": size,
            "weight": num(get("weight"), 100.0, 900.0, weight as f64).round() as i64,
            "line": num(get("line"), 8.0, 120.0, line),
        });
        ops.push(token_op(format!("type.{name}"), TokenKind::Type, val.clone(), val)?);
    }
    for (kind, key, scale) in [
        (TokenKind::Space, "space", &SPACES[..]),
        (TokenKind::Radius, "radius", &RADII[..]),
    ] {
        let m = section(key);
        for (name, default) in scale {
            let n = json!(num(m.get(*name), 0.0, 400.0, *default));
            ops.push(token_op(format!("{key}.{name}"), kind, n.clone(), n)?);
        }
    }
    let shadows = section("shadows");
    for (i, name) in SHADOWS.iter().enumerate() {
        let s = shadows.get(*name);
        let get = |k: &str| s.and_then(|s| s.get(k));
        let (dy, blur) = if i == 0 { (1.0, 3.0) } else { (6.0, 16.0) };
        let val = json!([{
            "x": num(get("x"), -200.0, 200.0, 0.0),
            "y": num(get("y"), -200.0, 200.0, dy),
            "blur": num(get("blur"), 0.0, 200.0, blur),
            "spread": num(get("spread"), -200.0, 200.0, 0.0),
            "color": color(get("color")).unwrap_or_else(|| "#00000026".into()),
        }]);
        ops.push(token_op(format!("shadow.{name}"), TokenKind::Shadow, val.clone(), val)?);
    }
    let text = |k: &str, n: usize| v.get(k).and_then(Value::as_str).map(|s| clip(s, n)).unwrap_or_default();
    Ok(Made {
        name: match text("name", 40).trim() {
            "" => "Design system".into(),
            s => s.to_owned(),
        },
        summary: text("summary", 120),
        ops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer() -> String {
        let colors: Vec<String> = COLORS
            .iter()
            .map(|c| format!(r##""{c}":{{"day":"#2F7BEF","night":"#5B9BFF"}}"##))
            .collect();
        format!(
            r##"Sure!
            {{"name":"Aurora","summary":"Calm and clear","colors":{{{}}},
              "type":{{"display":{{"size":44,"weight":800,"line":52}},"body":{{"size":1e9,"weight":"x"}}}},
              "space":{{"xs":2,"md":18}},"radius":{{"sm":4}},
              "shadows":{{"sm":{{"x":0,"y":2,"blur":4,"spread":0,"color":"#00000033"}}}}}}"##,
            colors.join(",")
        )
    }

    #[test]
    fn a_good_answer_becomes_valid_token_ops() {
        let m = parse(&answer()).unwrap();
        assert_eq!((m.name.as_str(), m.summary.as_str()), ("Aurora", "Calm and clear"));
        // 11 colours + 5 type + 5 space + 3 radius + 2 shadows
        assert_eq!(m.ops.len(), 26);
        let by = |n: &str| m.ops.iter().find(|o| o["name"] == n).unwrap()["value"].clone();
        assert_eq!(by("color.primary")["day"], "#2F7BEF");
        assert_eq!(by("type.display")["day"]["size"], 44.0);
        assert_eq!(by("type.body")["day"]["size"], 96.0, "clamped");
        assert_eq!(by("type.body")["day"]["weight"], 400, "nonsense falls back");
        assert_eq!(by("space.xs")["day"], 2.0);
        assert_eq!(by("space.xl")["day"], 40.0, "left out: the standard value");
        assert_eq!(by("shadow.md")["day"][0]["y"], 6.0);
        // every op parses as the engine's typed op and passes the model's token rules
        let ops: Vec<design_doc::Op> =
            serde_json::from_value(Value::Array(m.ops.clone())).unwrap();
        let mut live = design_doc::Live::new();
        live.apply_ops(&ops).unwrap();
        assert_eq!(live.read().tokens.len(), 26);
    }

    #[test]
    fn bad_answers_are_refused_with_a_reason() {
        assert!(parse("no json").is_err());
        assert!(parse("{\"name\":1}").unwrap_err().contains("colour primary"));
        let bad = answer().replace("\"night\":\"#5B9BFF\"", "\"night\":\"blue\"");
        assert!(parse(&bad).unwrap_err().contains("not a #rrggbb"));
        let missing = answer().replace("\"danger\"", "\"dangerous\"");
        assert!(parse(&missing).unwrap_err().contains("danger"));
    }

    #[test]
    fn the_prompt_names_the_brand_and_the_tokens() {
        let b = Brand {
            colors: vec!["#112233".into(), "#AABBCC".into()],
            name: Some("Acme".into()),
        };
        let p = prompt("a bank app", Some(&b));
        assert!(p.contains("#112233, #AABBCC") && p.contains("\"Acme\"") && p.contains("danger"));
        assert!(!prompt("x", None).contains("The brand"));
        assert!(check_brand(&b).is_ok());
        let bad = |c: &str| Brand { colors: vec![c.into()], name: None };
        assert!(check_brand(&bad("red")).is_err() && check_brand(&bad("#12345")).is_err());
        let many = Brand { colors: vec!["#112233".into(); 13], name: None };
        assert!(check_brand(&many).is_err());
    }
}
