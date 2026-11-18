//! The gate's policy (T10): who may do what on a host, in one table. Pure: no store, no I/O.

use ainkrad_core::audit::{AuditOrigin, OriginKind};
use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::ops_catalog::SESSION_PREFIX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Who {
    /// A person, by device id.
    Person(String),
    /// An AI session, by session id.
    Session(String),
    /// The health prober.
    Health,
}

/// Who asks. The inner type is private: outside the gate a principal can only come from the
/// authenticated request ([`Principal::of`]); `Health` is built only by the module's own prober.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal(pub(crate) Who);

impl Principal {
    /// The principal of an authenticated request: a Code Mode call (its session id carries the
    /// `code_mode:` prefix, which only the Core sets) is that AI session, even with an empty id (it fails closed: no such live session), anything else is the
    /// person behind the device.
    pub fn of(me: &Caller) -> Self {
        match me.session.strip_prefix(SESSION_PREFIX) {
            Some(s) => Self(Who::Session(s.to_owned())),
            None => Self(Who::Person(me.device.id.clone())),
        }
    }

    /// The health prober (Y5). Not public: a route cannot claim it.
    #[allow(dead_code)] // first caller arrives with Y5-01
    pub(crate) fn health() -> Self {
        Self(Who::Health)
    }

    pub(crate) fn label(&self) -> String {
        match &self.0 {
            Who::Person(d) => format!("person:{d}"),
            Who::Session(s) => format!("session:{s}"),
            Who::Health => "system:health".to_owned(),
        }
    }

    pub(crate) fn origin(&self) -> AuditOrigin {
        match &self.0 {
            Who::Person(d) => AuditOrigin::new(OriginKind::Person, Some(d.clone())),
            Who::Session(s) => AuditOrigin::new(OriginKind::AiSession, Some(s.clone())),
            Who::Health => AuditOrigin::new(OriginKind::System, None),
        }
    }
}

/// What is to be done on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Terminal,
    /// An ad-hoc command.
    Exec(String),
    /// A pre-set command or runbook step, by command id.
    Preset {
        id: String,
        read_only: bool,
    },
    FileList(String),
    FileRead(String),
    FileWrite(String),
    Tunnel(String),
    /// A health probe.
    Probe,
    /// A Mac-direct lease. Person only.
    Direct,
    /// Trusting a host key. Person only.
    Trust,
    /// Installing a runner on the host (Y8-01). Person only.
    MakeRunner,
}

impl Action {
    /// The Code Mode op name (T11) this action is shown as on an approval card.
    pub(crate) fn op(&self) -> &'static str {
        match self {
            Self::Terminal => "leylineTerminal",
            Self::Exec(_) => "leylineExec",
            Self::Preset { .. } => "leylineRunCommand",
            Self::FileList(_) => "leylineListFiles",
            Self::FileRead(_) => "leylineReadFile",
            Self::FileWrite(_) => "leylineWriteFile",
            Self::Tunnel(_) => "leylineOpenTunnel",
            Self::Probe => "leylineHostHealth",
            Self::Direct => "leylineDirect",
            Self::Trust => "leylineTrust",
            Self::MakeRunner => "leylineMakeRunner",
        }
    }

    pub(crate) fn detail(&self) -> &str {
        match self {
            Self::Exec(s)
            | Self::FileList(s)
            | Self::FileRead(s)
            | Self::FileWrite(s)
            | Self::Tunnel(s) => s,
            Self::Preset { id, .. } => id,
            _ => "",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    ReadOnly,
    Ask,
    Allowed,
}

impl Rule {
    /// Anything unknown is the strictest.
    pub(crate) fn of(s: &str) -> Self {
        match s {
            "allowed" => Self::Allowed,
            "ask" => Self::Ask,
            _ => Self::ReadOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    Ask,
    Deny(&'static str),
}

/// The whole policy, in one table.
pub(crate) fn verdict(who: &Principal, rule: Rule, action: &Action) -> Verdict {
    use Action::{Direct, FileList, FileRead, MakeRunner, Preset, Probe, Trust};
    match &who.0 {
        Who::Person(_) => Verdict::Allow,
        Who::Health if *action == Probe => Verdict::Allow,
        Who::Health => Verdict::Deny("health may only probe"),
        Who::Session(_) => match (action, rule) {
            (Direct | Trust | MakeRunner, _) => Verdict::Deny("only a person may do that"),
            (_, Rule::Allowed) => Verdict::Allow,
            (_, Rule::Ask) => Verdict::Ask,
            (Probe | FileList(_) | FileRead(_), Rule::ReadOnly)
            | (
                Preset {
                    read_only: true, ..
                },
                Rule::ReadOnly,
            ) => Verdict::Allow,
            _ => Verdict::Deny("this host is read-only for AI"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every (principal x rule x action): the policy of T10, written out.
    #[test]
    fn the_policy_table() {
        use Rule::{Allowed, Ask as AskR, ReadOnly};
        use Verdict::{Allow, Ask, Deny};
        let person = Principal(Who::Person("d_1".into()));
        let ai = Principal(Who::Session("as_1".into()));
        let health = Principal::health();
        let ro_cmd = Action::Preset {
            id: "c".into(),
            read_only: true,
        };
        let rw_cmd = Action::Preset {
            id: "c".into(),
            read_only: false,
        };
        let all = [
            Action::Terminal,
            Action::Exec("ls".into()),
            ro_cmd.clone(),
            rw_cmd.clone(),
            Action::FileList("/".into()),
            Action::FileRead("/a".into()),
            Action::FileWrite("/a".into()),
            Action::Tunnel("80".into()),
            Action::Probe,
            Action::Direct,
            Action::Trust,
            Action::MakeRunner,
        ];
        for rule in [ReadOnly, AskR, Allowed] {
            for a in &all {
                // A person is always allowed; the person-only actions still need their routes' step-up.
                assert_eq!(verdict(&person, rule, a), Allow, "{rule:?} {a:?}");
                // Health probes and nothing else, on every rule.
                let h = verdict(&health, rule, a);
                assert_eq!(h == Allow, *a == Action::Probe, "{rule:?} {a:?}");
                // An AI never trusts a key or leases Mac-direct, on any rule.
                let v = verdict(&ai, rule, a);
                if matches!(a, Action::Direct | Action::Trust | Action::MakeRunner) {
                    assert!(matches!(v, Deny(_)), "{rule:?} {a:?}");
                    continue;
                }
                let want = match rule {
                    Allowed => Allow,
                    AskR => Ask,
                    ReadOnly => {
                        let reads =
                            matches!(a, Action::Probe | Action::FileList(_) | Action::FileRead(_))
                                || *a == ro_cmd;
                        if reads {
                            Allow
                        } else {
                            Deny("this host is read-only for AI")
                        }
                    }
                };
                assert_eq!(v, want, "{rule:?} {a:?}");
            }
        }
    }

    #[test]
    fn an_unknown_rule_is_read_only() {
        assert_eq!(Rule::of("allowed"), Rule::Allowed);
        assert_eq!(Rule::of("ask"), Rule::Ask);
        assert_eq!(Rule::of("anything"), Rule::ReadOnly);
        assert_eq!(Rule::of(""), Rule::ReadOnly);
    }
}
