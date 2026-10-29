//! Per-run tokens (E4.1, brainstorm §7): what a run's harness presents to call back into
//! Citadel, and the scope it grants. No I/O.
//!
//! A token is opaque random text, shown once, stored only as its SHA-256. It is scoped to
//! one run, and through it to that run's agent, issue and company; the scope comes from the
//! stored run, never from the caller. It dies with the run, or `RUN_TOKEN_TTL_SECS` after it
//! was issued, whichever is first. Tokens travel in a header, never in a query string.

use std::fmt;

use crate::exec::RunId;
use crate::org::{AgentId, CompanyId};
use crate::work::IssueId;

/// A token's hard expiry after it is issued; a run's end revokes it sooner.
pub const RUN_TOKEN_TTL_SECS: i64 = 12 * 60 * 60;

/// A raw run token. Its `Debug` is redacted and it has no `Display`, so it never reaches a
/// log by accident; `expose` is the one way to read it (to hand it to the harness).
#[derive(Clone, PartialEq, Eq)]
pub struct RunToken(String);

impl RunToken {
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RunToken(<redacted>)")
    }
}

/// What a valid token lets its bearer act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunScope {
    pub run_id: RunId,
    pub agent_id: AgentId,
    /// `None` for a run on no issue: such a token reaches no issue.
    pub issue_id: Option<IssueId>,
    pub company_id: CompanyId,
}

/// A valid token used outside its scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    OtherIssue {
        allowed: Option<IssueId>,
        asked: IssueId,
    },
    OtherCompany {
        allowed: CompanyId,
        asked: CompanyId,
    },
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherIssue { asked, .. } => {
                write!(f, "run token is not scoped to issue {}", asked.0)
            }
            Self::OtherCompany { asked, .. } => {
                write!(f, "run token is not scoped to company {}", asked.0)
            }
        }
    }
}

impl std::error::Error for ScopeError {}

impl RunScope {
    /// Ok only for the run's own issue.
    pub fn require_issue(&self, issue: IssueId) -> Result<(), ScopeError> {
        match self.issue_id {
            Some(own) if own == issue => Ok(()),
            allowed => Err(ScopeError::OtherIssue {
                allowed,
                asked: issue,
            }),
        }
    }

    /// Ok only for the run's own company.
    pub fn require_company(&self, company: CompanyId) -> Result<(), ScopeError> {
        if self.company_id == company {
            return Ok(());
        }
        Err(ScopeError::OtherCompany {
            allowed: self.company_id,
            asked: company,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPE: RunScope = RunScope {
        run_id: RunId(1),
        agent_id: AgentId(2),
        issue_id: Some(IssueId(3)),
        company_id: CompanyId(4),
    };

    #[test]
    fn a_scope_allows_only_its_own_issue_and_company() {
        assert_eq!(SCOPE.require_issue(IssueId(3)), Ok(()));
        assert!(SCOPE.require_issue(IssueId(9)).is_err());
        let none = RunScope {
            issue_id: None,
            ..SCOPE
        };
        assert!(none.require_issue(IssueId(3)).is_err());
        assert_eq!(SCOPE.require_company(CompanyId(4)), Ok(()));
        assert!(SCOPE.require_company(CompanyId(5)).is_err());
    }

    #[test]
    fn debug_never_shows_the_token() {
        let t = RunToken::new("cit_run_secret".to_owned());
        assert_eq!(format!("{t:?}"), "RunToken(<redacted>)");
        assert_eq!(t.expose(), "cit_run_secret");
    }
}
