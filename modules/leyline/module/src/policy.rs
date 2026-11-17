//! The gate's policy (T10): who may do what on a host, in one table. Pure: no store, no I/O.

use ainkrad_core::audit::{AuditOrigin, OriginKind};

/// Who asks. Built by the Core from the authenticated request, never from its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// A person, by device id.
    Person(String),
    /// An AI session, by session id.
    Session(String),
    /// The health prober.
    Health,
}

impl Principal {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Person(d) => format!("person:{d}"),
            Self::Session(s) => format!("session:{s}"),
            Self::Health => "system:health".to_owned(),
        }
    }

    pub(crate) fn origin(&self) -> AuditOrigin {
        match self {
            Self::Person(d) => AuditOrigin::new(OriginKind::Person, Some(d.clone())),
            Self::Session(s) => AuditOrigin::new(OriginKind::AiSession, Some(s.clone())),
            Self::Health => AuditOrigin::new(OriginKind::System, None),
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
    use Action::{Direct, FileList, FileRead, Preset, Probe, Trust};
    match who {
        Principal::Person(_) => Verdict::Allow,
        Principal::Health if *action == Probe => Verdict::Allow,
        Principal::Health => Verdict::Deny("health may only probe"),
        Principal::Session(_) => match (action, rule) {
            (Direct | Trust, _) => Verdict::Deny("only a person may do that"),
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
        let person = Principal::Person("d_1".into());
        let ai = Principal::Session("as_1".into());
        let health = Principal::Health;
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
                if matches!(a, Action::Direct | Action::Trust) {
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
