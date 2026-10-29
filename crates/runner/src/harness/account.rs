//! Provider accounts on the runner host (E15.1). A job's account names its harness config dir
//! (under the config root) and, optionally, a token file (under the credentials dir) and the
//! harness variable the token goes in. The file is read when the run starts, held only in
//! memory for the child's environment, redacted from everything the run reports, and never put
//! in argv or a log. Every name from the server is checked before it touches the disk.

use std::path::PathBuf;

use ainkrad_proto::runner::relative_path_ok;

use super::HarnessExecutor;
use crate::Job;

/// The account's token: the variable it goes in, and its value.
pub(super) struct Credential {
    pub var: String,
    pub value: String,
}

impl HarnessExecutor {
    /// The harness config dir `job` works with: its account's, or this runner's own.
    pub(super) fn config_dir(&self, job: &Job) -> Result<PathBuf, String> {
        match &job.account {
            None => Ok(self.config_root.join(&job.harness)),
            Some(a) if relative_path_ok(&a.config_dir) => Ok(self.config_root.join(&a.config_dir)),
            Some(a) => Err(format!(
                "account {}: bad config dir {:?}",
                a.label, a.config_dir
            )),
        }
    }

    /// `job`'s account token, read now from the credentials dir; `None` for no account or
    /// an account that logs in through its config dir. A missing, unreadable or empty file
    /// fails the run with a reason that names the file, never its contents.
    pub(super) fn read_credential(&self, job: &Job) -> Result<Option<Credential>, String> {
        let Some(a) = &job.account else {
            return Ok(None);
        };
        let (file, var) = match (&a.credential_ref, &a.credential_env) {
            (None, None) => return Ok(None),
            (Some(file), Some(var)) => (file, var),
            _ => {
                return Err(format!(
                    "account {}: a credential needs its variable",
                    a.label
                ));
            }
        };
        if !relative_path_ok(file) {
            return Err(format!(
                "account {}: bad credential reference {file:?}",
                a.label
            ));
        }
        if !ainkrad_harness::auth_env(&job.harness).contains(&var.as_str()) {
            return Err(format!(
                "account {}: {var:?} is not a {} auth variable",
                a.label, job.harness
            ));
        }
        let path = self.credentials_dir.join(file);
        let value = std::fs::read_to_string(&path).map_err(|e| {
            format!(
                "account {}: cannot read its credential file {}: {e}",
                a.label,
                path.display()
            )
        })?;
        let value = value.trim().to_owned();
        if value.is_empty() {
            return Err(format!(
                "account {}: its credential file {} is empty",
                a.label,
                path.display()
            ));
        }
        Ok(Some(Credential {
            var: var.clone(),
            value,
        }))
    }
}
