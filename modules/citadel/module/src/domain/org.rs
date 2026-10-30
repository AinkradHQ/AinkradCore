//! Org model: company → departments → teams → agents (brainstorm §4).

use std::fmt;
use std::str::FromStr;

macro_rules! id {
    ($($name:ident),*) => {$(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub i64);
    )*};
}
pub(crate) use id;

id!(CompanyId, DepartmentId, TeamId, AgentId);

/// A string that is not one of an enum's known values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVariant(pub String);

impl fmt::Display for UnknownVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown variant `{}`", self.0)
    }
}

impl std::error::Error for UnknownVariant {}

/// A closed enum with a stable snake_case text form (used as the storage value).
macro_rules! text_enum {
    ($name:ident { $($variant:ident => $text:literal),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),* }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),* }
            }
        }

        impl FromStr for $name {
            type Err = UnknownVariant;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($text => Ok(Self::$variant),)*
                    other => Err(UnknownVariant(other.to_owned())),
                }
            }
        }
    };
}
pub(crate) use text_enum;

text_enum!(TeamRole {
    ProductOwner => "product_owner",
    TeamLead => "team_lead",
    Member => "member",
});

text_enum!(OrgRole {
    Ceo => "ceo",
    Cto => "cto",
    None => "none",
});

text_enum!(Harness {
    Claude => "claude",
    Codex => "codex",
    Opencode => "opencode",
    Agy => "agy",
});

impl Harness {
    pub const ALL: [Self; 4] = [Self::Claude, Self::Codex, Self::Opencode, Self::Agy];
}

text_enum!(Effort {
    Low => "low",
    Medium => "medium",
    High => "high",
});

text_enum!(Sandbox {
    ReadOnly => "read-only",
    WorkspaceWrite => "workspace-write",
    FullAccess => "full-access",
});

text_enum!(AgentStatus {
    Active => "active",
    Paused => "paused",
    PendingApproval => "pending_approval",
    Terminated => "terminated",
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Company {
    pub id: CompanyId,
    pub name: String,
    /// The admin's own company, or a client's (E15.14).
    pub kind: CompanyKind,
    pub profile: CompanyProfile,
}

/// How a company presents itself and when it works (API minor 17); every field optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompanyProfile {
    /// `#rrggbb`.
    pub color: Option<String>,
    pub description: String,
    pub industries: Vec<String>,
    pub website: Option<String>,
    /// An IANA time zone, e.g. `Europe/Berlin`.
    pub timezone: Option<String>,
    /// Minutes from midnight, 0..=1440.
    pub work_start: Option<u16>,
    pub work_end: Option<u16>,
    /// Working days as a bitmask: bit 0 Monday … bit 6 Sunday.
    pub work_days: Option<u8>,
    /// An uploaded logo: its SHA-256.
    pub logo_sha256: Option<String>,
}

impl CompanyProfile {
    /// Why the profile is refused, if it is.
    pub fn invalid(&self) -> Option<String> {
        let hex = |c: &str| {
            c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
        };
        if let Some(c) = self.color.as_deref().filter(|c| !hex(c)) {
            return Some(format!("color {c:?} is not #rrggbb"));
        }
        if self.description.chars().count() > 4000 {
            return Some("a description is at most 4000 characters".to_owned());
        }
        let bad_industry = |i: &String| i.trim().is_empty() || i.chars().count() > 64;
        if self.industries.len() > 20 || self.industries.iter().any(bad_industry) {
            return Some("at most 20 industries, each 1-64 characters".to_owned());
        }
        if let Some(w) = self.website.as_deref() {
            let web = (w.starts_with("https://") || w.starts_with("http://")) && w.len() <= 2048;
            if !web || w.chars().any(char::is_whitespace) {
                return Some(format!("website {w:?} is not an http(s) URL"));
            }
        }
        // ponytail: the shape of an IANA name only (`Area/City`, `UTC`), not the tz database;
        // check against the database if a wrong zone ever matters server side.
        if let Some(tz) = self.timezone.as_deref() {
            let ok = tz.len() <= 64
                && !tz.starts_with('/')
                && !tz.ends_with('/')
                && !tz.contains("//")
                && tz
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b))
                && tz.bytes().next().is_some_and(|b| b.is_ascii_uppercase());
            if !ok {
                return Some(format!("timezone {tz:?} is not an IANA zone name"));
            }
        }
        if [self.work_start, self.work_end]
            .iter()
            .flatten()
            .any(|m| *m > 1440)
        {
            return Some("work_start and work_end are minutes from midnight, 0-1440".to_owned());
        }
        if self.work_days.is_some_and(|d| d > 127) {
            return Some("work_days is a bitmask of 7 days, 0-127".to_owned());
        }
        None
    }
}

text_enum!(CompanyKind {
    Own => "own",
    Client => "client",
});

/// Free-form (Engineering, Marketing, Ops…); name is unique within its company.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Department {
    pub id: DepartmentId,
    pub company_id: CompanyId,
    pub name: String,
    /// What it does, in the admin's words (API minor 17).
    pub about: String,
    /// The agent that heads it, one of the company's.
    pub head_agent_id: Option<AgentId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    pub id: TeamId,
    pub department_id: DepartmentId,
    pub name: String,
}

/// An agent's seat on a team. A team has at most one product owner and one team lead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamMembership {
    pub team_id: TeamId,
    pub agent_id: AgentId,
    pub team_role: TeamRole,
}

/// An agent before it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAgent {
    pub company_id: CompanyId,
    pub name: String,
    /// Free-text job title ("QA", "DevOps", "Designer"…).
    pub role: String,
    /// At most one CEO and one CTO per company.
    pub org_role: OrgRole,
    pub reports_to: Option<AgentId>,
    pub harness: Harness,
    pub model: String,
    /// Capabilities a runner must offer, e.g. `macos`.
    pub runner_tags: Vec<String>,
    pub status: AgentStatus,
}

/// An agent's editable profile (API minor 17). Stored and shown; `effort` and `sandbox` are the
/// admin's intent (`None`: the harness default), not yet applied by dispatch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentProfile {
    pub description: String,
    pub effort: Option<Effort>,
    pub sandbox: Option<Sandbox>,
    /// The agent's standing instructions.
    pub instructions: String,
    /// Short rules, in order.
    pub guidelines: Vec<String>,
}

/// A change to an agent: `None` leaves a field as it is; `Some(None)` clears an optional one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentChange {
    pub role: Option<String>,
    pub description: Option<String>,
    pub harness: Option<Harness>,
    pub model: Option<String>,
    pub effort: Option<Option<Effort>>,
    pub sandbox: Option<Option<Sandbox>>,
    pub runner_tags: Option<Vec<String>>,
    pub reports_to: Option<Option<AgentId>>,
    pub instructions: Option<String>,
    pub guidelines: Option<Vec<String>>,
}

/// Why `tags` are refused: at most 20, each 1-64 characters without whitespace.
pub fn invalid_runner_tags(tags: &[String]) -> Option<String> {
    let bad =
        |t: &String| t.is_empty() || t.chars().count() > 64 || t.chars().any(char::is_whitespace);
    (tags.len() > 20 || tags.iter().any(bad))
        .then(|| "at most 20 runner tags, each 1-64 characters without spaces".to_owned())
}

impl AgentProfile {
    /// Why the profile is refused, if it is.
    pub fn invalid(&self) -> Option<String> {
        if self.description.chars().count() > 4000 {
            return Some("a description is at most 4000 characters".to_owned());
        }
        if self.instructions.chars().count() > 20_000 {
            return Some("instructions are at most 20000 characters".to_owned());
        }
        let bad = |g: &String| g.trim().is_empty() || g.chars().count() > 500;
        (self.guidelines.len() > 50 || self.guidelines.iter().any(bad))
            .then(|| "at most 50 guidelines, each 1-500 characters".to_owned())
    }
}

impl AgentChange {
    /// Why the change is refused, if it is (nothing to change, a blank role or model, a bad
    /// profile or runner tags).
    pub fn invalid(&self) -> Option<String> {
        let blank = |v: &Option<String>, max: usize| {
            v.as_deref()
                .is_some_and(|v| v.trim().is_empty() || v.chars().count() > max)
        };
        if *self == Self::default() {
            return Some("nothing to change".to_owned());
        }
        if blank(&self.role, 100) {
            return Some("a role is 1-100 characters".to_owned());
        }
        if blank(&self.model, 200) {
            return Some("a model is 1-200 characters".to_owned());
        }
        if let Some(why) = self.runner_tags.as_deref().and_then(invalid_runner_tags) {
            return Some(why);
        }
        AgentProfile {
            description: self.description.clone().unwrap_or_default(),
            instructions: self.instructions.clone().unwrap_or_default(),
            guidelines: self.guidelines.clone().unwrap_or_default(),
            ..Default::default()
        }
        .invalid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub id: AgentId,
    pub company_id: CompanyId,
    pub name: String,
    pub role: String,
    pub org_role: OrgRole,
    pub reports_to: Option<AgentId>,
    pub harness: Harness,
    pub model: String,
    pub runner_tags: Vec<String>,
    pub status: AgentStatus,
    /// What the admin wrote about it (API minor 17).
    pub profile: AgentProfile,
    /// How the client draws it (decision #61): the figure's version and its palette.
    pub figure_version: String,
    pub palette_id: String,
    /// An uploaded image shown instead of the figure: its SHA-256.
    pub avatar_sha256: Option<String>,
    /// When the admin paused it (decision #34); `None` unless paused by the admin.
    pub paused_at: Option<String>,
    /// When it was hired (created).
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_round_trip_through_text() {
        for r in [TeamRole::ProductOwner, TeamRole::TeamLead, TeamRole::Member] {
            assert_eq!(r.as_str().parse::<TeamRole>(), Ok(r));
        }
        for s in [AgentStatus::PendingApproval, AgentStatus::Terminated] {
            assert_eq!(s.as_str().parse::<AgentStatus>(), Ok(s));
        }
        assert_eq!("agy".parse::<Harness>(), Ok(Harness::Agy));
        assert_eq!("ceo".parse::<OrgRole>(), Ok(OrgRole::Ceo));
        assert!("gemini".parse::<Harness>().is_err());
    }

    #[test]
    fn an_agent_change_is_checked() {
        let ok = AgentChange {
            role: Some("QA".into()),
            guidelines: Some(vec!["Be brief".into()]),
            effort: Some(None),
            ..Default::default()
        };
        assert_eq!(ok.invalid(), None);
        assert!(AgentChange::default().invalid().is_some());
        let bad = |f: fn(&mut AgentChange)| {
            let mut c = ok.clone();
            f(&mut c);
            c.invalid()
        };
        assert!(bad(|c| c.role = Some(" ".into())).is_some());
        assert!(bad(|c| c.model = Some(String::new())).is_some());
        assert!(bad(|c| c.runner_tags = Some(vec!["a b".into()])).is_some());
        assert!(bad(|c| c.guidelines = Some(vec![String::new()])).is_some());
        assert!(bad(|c| c.guidelines = Some(vec!["x".into(); 51])).is_some());
        assert!(bad(|c| c.description = Some("x".repeat(4001))).is_some());
        assert_eq!("read-only".parse::<Sandbox>(), Ok(Sandbox::ReadOnly));
        assert!("max".parse::<Effort>().is_err());
    }

    #[test]
    fn a_company_profile_is_checked() {
        let ok = CompanyProfile {
            color: Some("#a855f7".into()),
            timezone: Some("America/Argentina/Buenos_Aires".into()),
            website: Some("https://acme.example/x".into()),
            work_start: Some(0),
            work_end: Some(1440),
            work_days: Some(127),
            ..Default::default()
        };
        assert_eq!(ok.invalid(), None);
        assert_eq!(CompanyProfile::default().invalid(), None);
        let bad = |f: fn(&mut CompanyProfile)| {
            let mut p = ok.clone();
            f(&mut p);
            p.invalid()
        };
        assert!(bad(|p| p.color = Some("#12345".into())).is_some());
        assert!(bad(|p| p.timezone = Some("utc/x".into())).is_some());
        assert!(bad(|p| p.timezone = Some("Etc/".into())).is_some());
        assert!(bad(|p| p.website = Some("https://a b".into())).is_some());
        assert!(bad(|p| p.work_end = Some(1441)).is_some());
        assert!(bad(|p| p.work_days = Some(128)).is_some());
        assert!(bad(|p| p.industries = vec!["x".repeat(65)]).is_some());
    }
}

/// One entry of an agent's model fallback chain (E15.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelRoute {
    pub harness: Harness,
    pub model: String,
}

text_enum!(Tier {
    Small => "small",
    Standard => "standard",
    Large => "large",
});
