//! The project profile (E15.13, pain #14: configuring a project meant writing workarounds into
//! an agent's instructions). One profile per project says how work is done there: its stack, the
//! definition of done, branch and PR rules, environments (who may deploy where; configuration
//! only, there is no deploy action), conventions, linked docs and a default model per role. It
//! is stored as one JSON object (`store::work::project_profile`), edited whole or a field at a
//! time (`ProfilePatch`), and every run is given it in its instructions (`fit`), within the
//! `profile.budget_bytes` setting: what does not fit is named, never dropped silently.
//!
//! Agents propose changes to one field as knowledge proposals (`target: profile.<field>`, the
//! body the new value); a human accepts or rejects them, and only an accepted one is applied
//! (decision #48).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// How a PR is merged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MergeMethod {
    #[default]
    Merge,
    Squash,
    Rebase,
}

/// Who merges a PR.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Merger {
    #[default]
    Owner,
    ProductOwner,
    Lead,
}

/// Who may deploy to an environment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Deploy {
    /// Agents deploy on their own.
    Agents,
    /// Agents ask first.
    #[default]
    Ask,
    /// Only the owner deploys.
    Owner,
}

/// Network access for runs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    #[default]
    Off,
    Ask,
    On,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub name: String,
    /// Empty when it has none; never holding credentials.
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub deploy: Deploy,
}

/// The model agents of `role` (their role, any case) run on in this project when they have
/// none of their own, and for their small and large tiers when they have none (E15.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleModel {
    pub role: String,
    pub model: String,
    #[serde(default)]
    pub small: Option<String>,
    #[serde(default)]
    pub large: Option<String>,
}

/// One definition-of-done rule and whether it is on (API minor 18).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DodRule {
    pub text: String,
    #[serde(default = "on")]
    pub on: bool,
}

fn on() -> bool {
    true
}

macro_rules! profile {
    ($($(#[$doc:meta])* $field:ident: $ty:ty,)*) => {
        /// A project's profile. Every field may be empty.
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
        #[serde(default, deny_unknown_fields)]
        pub struct Profile { $($(#[$doc])* pub $field: $ty,)* }

        /// Fields to change; absent ones stay. The approval policy and permission mode live on
        /// the project and are changed through the same call.
        #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
        #[serde(default, deny_unknown_fields)]
        pub struct ProfilePatch {
            $($(#[$doc])* #[serde(skip_serializing_if = "Option::is_none")]
              pub $field: Option<$ty>,)*
            #[serde(skip_serializing_if = "Option::is_none")]
            pub sprint_approval: Option<crate::api::v1::types::SprintApproval>,
            #[serde(skip_serializing_if = "Option::is_none")]
            pub permission_mode: Option<crate::api::v1::types::PermissionMode>,
        }

        /// The fields a proposal may target (`profile.<field>`).
        pub const FIELDS: &[&str] = &[$(stringify!($field)),*];

        impl ProfilePatch {
            /// Applies the profile fields to `p`; the names of those it changed.
            pub fn apply(&self, p: &mut Profile) -> Vec<&'static str> {
                let mut changed = vec![];
                $(if let Some(v) = &self.$field && *v != p.$field {
                    p.$field = v.clone();
                    changed.push(stringify!($field));
                })*
                self.sync_rules(p, &mut changed);
                changed
            }
        }
    };
}

profile! {
    /// Languages, frameworks, versions.
    stack: String,
    /// Rules an issue meets before it is done.
    definition_of_done: Vec<String>,
    /// Branches nobody pushes to directly.
    protected_branches: Vec<String>,
    /// How branches are named, e.g. `<type>/<key>-<slug>`.
    branch_pattern: String,
    merge_method: MergeMethod,
    merged_by: Merger,
    environments: Vec<Environment>,
    /// Commit, code and review conventions.
    conventions: String,
    /// Linked docs: paths or URLs.
    docs: Vec<String>,
    models: Vec<RoleModel>,
    network: Network,
    /// Hosts runs may reach when `network` is not off (API minor 18).
    #[schema(required = false)]
    network_hosts: Vec<String>,
    /// `definition_of_done` with each rule's switch (API minor 18): the rules are the source, and
    /// `definition_of_done` is the text of those that are on. A patch of `definition_of_done`
    /// alone replaces the rules, all on.
    #[schema(required = false)]
    definition_of_done_rules: Vec<DodRule>,
}

impl ProfilePatch {
    /// Keeps `definition_of_done` and its rules one list after the patch's fields are in.
    fn sync_rules(&self, p: &mut Profile, changed: &mut Vec<&'static str>) {
        let mut note = |f: &'static str| {
            if !changed.contains(&f) {
                changed.push(f);
            }
        };
        if self.definition_of_done_rules.is_some() {
            let enabled = p.enabled_rules();
            if p.definition_of_done != enabled {
                p.definition_of_done = enabled;
                note("definition_of_done");
            }
        } else if self.definition_of_done.is_some() {
            let rules = Profile::rules_of(&p.definition_of_done);
            if p.definition_of_done_rules != rules {
                p.definition_of_done_rules = rules;
                note("definition_of_done_rules");
            }
        }
    }
}

impl Profile {
    fn rules_of(list: &[String]) -> Vec<DodRule> {
        list.iter()
            .map(|t| DodRule {
                text: t.clone(),
                on: true,
            })
            .collect()
    }

    fn enabled_rules(&self) -> Vec<String> {
        let on = self.definition_of_done_rules.iter().filter(|r| r.on);
        on.map(|r| r.text.clone()).collect()
    }

    /// A profile stored before the rules existed has its list as rules, all on.
    pub fn with_rules(mut self) -> Self {
        if self.definition_of_done_rules.is_empty() && !self.definition_of_done.is_empty() {
            self.definition_of_done_rules = Self::rules_of(&self.definition_of_done);
        }
        self
    }
}

const MAX_TEXT: usize = 4000;
const MAX_ITEM: usize = 500;
const MAX_ITEMS: usize = 50;

fn text_problem(name: &str, s: &str, max: usize) -> Option<String> {
    (s.len() > max || s.contains('\0')).then(|| format!("{name} is longer than {max} bytes"))
}

fn list_problem(name: &str, items: &[String]) -> Option<String> {
    if items.len() > MAX_ITEMS {
        return Some(format!("{name} has more than {MAX_ITEMS} entries"));
    }
    items.iter().find_map(|i| {
        if i.trim().is_empty() {
            Some(format!("{name} has an empty entry"))
        } else {
            text_problem(name, i, MAX_ITEM)
        }
    })
}

/// A URL with credentials in it, or not http(s).
fn url_problem(url: &str) -> Option<String> {
    let rest = ["https://", "http://"]
        .iter()
        .find_map(|s| url.strip_prefix(s));
    match rest {
        _ if url.is_empty() => None,
        Some(rest) if !rest.split('/').next().unwrap_or("").contains('@') => {
            text_problem("an environment URL", url, MAX_ITEM)
        }
        _ => Some(format!(
            "environment URL {url:?} must be http(s) and hold no credentials"
        )),
    }
}

impl Profile {
    /// Why it cannot be stored: an over-long text or list, an empty list entry, a duplicate
    /// environment or role, an environment URL that is not http(s) or holds credentials.
    pub fn problem(&self) -> Option<String> {
        let texts = [
            ("stack", &self.stack),
            ("branch_pattern", &self.branch_pattern),
            ("conventions", &self.conventions),
        ];
        if let Some(why) = texts.iter().find_map(|(n, t)| text_problem(n, t, MAX_TEXT)) {
            return Some(why);
        }
        let rule_texts: Vec<String> = self
            .definition_of_done_rules
            .iter()
            .map(|r| r.text.clone())
            .collect();
        let lists = [
            ("definition_of_done", &self.definition_of_done),
            ("definition_of_done_rules", &rule_texts),
            ("network_hosts", &self.network_hosts),
            ("protected_branches", &self.protected_branches),
            ("docs", &self.docs),
        ];
        if let Some(why) = lists.iter().find_map(|(n, l)| list_problem(n, l)) {
            return Some(why);
        }
        if let Some(h) = self
            .network_hosts
            .iter()
            .find(|h| h.contains("://") || h.contains('/') || h.contains(char::is_whitespace))
        {
            return Some(format!("network host {h:?} is a host name, not a URL"));
        }
        let names: Vec<String> = self.environments.iter().map(|e| e.name.clone()).collect();
        let roles: Vec<String> = self.models.iter().map(|m| m.role.clone()).collect();
        for (what, all) in [("environment", &names), ("role", &roles)] {
            if let Some(why) = list_problem(what, all) {
                return Some(why);
            }
            let lower: Vec<String> = all.iter().map(|n| n.trim().to_lowercase()).collect();
            if let Some(dupe) = lower
                .iter()
                .enumerate()
                .find(|(i, n)| lower[..*i].contains(n))
            {
                return Some(format!("{what} {:?} is given twice", dupe.1));
            }
        }
        if let Some(why) = self.environments.iter().find_map(|e| url_problem(&e.url)) {
            return Some(why);
        }
        self.models.iter().find_map(|m| {
            let models = [Some(&m.model), m.small.as_ref(), m.large.as_ref()];
            models
                .into_iter()
                .flatten()
                .any(|s| s.trim().is_empty() || s.len() > MAX_ITEM)
                .then(|| format!("role {:?} has an empty or over-long model", m.role))
        })
    }

    /// The models of `role` (any case), if it has an entry.
    pub fn role_model(&self, role: &str) -> Option<&RoleModel> {
        let role = role.trim().to_lowercase();
        self.models
            .iter()
            .find(|m| m.role.trim().to_lowercase() == role)
    }
}

/// A one-field patch from a proposal of `field`: `body` as JSON, or as a string when it is not
/// JSON (a text field's plain text). Why not, for an unknown field or a value of the wrong shape.
pub fn field_patch(field: &str, body: &str) -> Result<ProfilePatch, String> {
    if !FIELDS.contains(&field) {
        return Err(format!(
            "no profile field {field:?}; one of {}",
            FIELDS.join(", ")
        ));
    }
    let value = serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_owned()));
    let mut one = serde_json::Map::new();
    one.insert(field.to_owned(), value);
    serde_json::from_value(Value::Object(one)).map_err(|e| format!("profile.{field}: {e}"))
}

/// The project settings a run is told alongside the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policies {
    pub sprint_approval: &'static str,
    pub permission_mode: &'static str,
}

/// What a run is given of the profile: the markdown, the sections it holds, and those the budget
/// left out (named at the end of the text).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fitted {
    pub text: Option<String>,
    pub kept: Vec<&'static str>,
    pub dropped: Vec<&'static str>,
}

fn bullets(items: &[String]) -> String {
    items.iter().map(|i| format!("- {}\n", i.trim())).collect()
}

impl Profile {
    /// The sections a run is told, most important first; empty ones are left out. `before` (the
    /// project's repositories, E15.16) comes first.
    pub fn sections(
        &self,
        before: Vec<(&'static str, String)>,
        p: &Policies,
    ) -> Vec<(&'static str, String)> {
        if *self == Self::default() && before.is_empty() {
            return vec![];
        }
        let mut out = before;
        out.push(("definition_of_done", bullets(&self.definition_of_done)));
        let mut rules = String::new();
        if !self.protected_branches.is_empty() {
            let protected = self.protected_branches.join(", ");
            rules.push_str(&format!("- Protected (never push to them): {protected}\n"));
        }
        if !self.branch_pattern.trim().is_empty() {
            rules.push_str(&format!("- Branch names: {}\n", self.branch_pattern.trim()));
        }
        let merge = serde_json::to_value(self.merge_method).unwrap_or_default();
        let by = serde_json::to_value(self.merged_by).unwrap_or_default();
        rules.push_str(&format!(
            "- PRs merge by {}, merged by the {}\n",
            merge.as_str().unwrap_or(""),
            by.as_str().unwrap_or("").replace('_', " ")
        ));
        out.push(("branches", rules));
        out.push(("stack", self.stack.trim().to_owned()));
        out.push(("conventions", self.conventions.trim().to_owned()));
        let envs: Vec<String> = self
            .environments
            .iter()
            .map(|e| {
                let who = match e.deploy {
                    Deploy::Agents => "agents may deploy",
                    Deploy::Ask => "ask before deploying",
                    Deploy::Owner => "only the owner deploys",
                };
                let at = if e.url.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", e.url)
                };
                format!("{}{at}: {who}", e.name)
            })
            .collect();
        out.push(("environments", bullets(&envs)));
        let network = serde_json::to_value(self.network).unwrap_or_default();
        let mut policies = format!(
            "- Plan approval: {}\n- Permission mode: {}\n- Network: {}\n",
            p.sprint_approval,
            p.permission_mode,
            network.as_str().unwrap_or("")
        );
        if !self.network_hosts.is_empty() {
            let hosts = self.network_hosts.join(", ");
            policies.push_str(&format!("- Network hosts: {hosts}\n"));
        }
        out.push(("policies", policies));
        out.push(("docs", bullets(&self.docs)));
        out.retain(|(_, body)| !body.trim().is_empty());
        out
    }
}

/// Keeps each section, in order, that still fits in `budget` bytes (a smaller one after a
/// dropped one may still fit) and names the rest at the end.
pub fn fit(sections: Vec<(&'static str, String)>, budget: usize) -> Fitted {
    let mut out = Fitted::default();
    let mut text = String::from("# Project profile\n\n");
    let mut left = budget;
    for (name, body) in sections {
        let section = format!("## {}\n\n{}\n\n", name.replace('_', " "), body.trim_end());
        match left.checked_sub(section.len()) {
            Some(rest) => {
                left = rest;
                text.push_str(&section);
                out.kept.push(name);
            }
            None => out.dropped.push(name),
        }
    }
    if !out.dropped.is_empty() {
        text.push_str(&format!(
            "Left out for size (read them with get_context): {}.\n",
            out.dropped.join(", ")
        ));
    }
    if !out.kept.is_empty() || !out.dropped.is_empty() {
        out.text = Some(text);
    }
    out
}

#[cfg(test)]
mod tests;
