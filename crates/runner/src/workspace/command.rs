//! Hermetic, bounded runner git. Session repositories are never reopened after handoff.
use super::*;
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Also terminates descendants on cancellation, failure or panic.
pub(crate) struct Group(pub(crate) u32);
impl Drop for Group {
    fn drop(&mut self) {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", self.0)])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

impl Workspaces {
    pub(super) fn command(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.git);
        cmd.args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "protocol.ssh.allow=always",
            "-c",
            "http.followRedirects=false",
            "-c",
            "submodule.recurse=false",
            "-c",
            "fetch.recurseSubmodules=false",
            "-c",
            "init.templateDir=",
            "-c",
            "core.sshCommand=ssh -F /dev/null -oBatchMode=yes -oStrictHostKeyChecking=yes",
            "-c",
            "credential.helper=",
            "-c",
            "http.lowSpeedLimit=1024",
            "-c",
            "http.lowSpeedTime=20",
        ]);
        // Legacy issue tests use local fixture repos; the production transport policy stays closed.
        if cfg!(test) {
            cmd.args(["-c", "protocol.file.allow=always"]);
        }
        cmd.args(args)
            .current_dir(dir)
            .env_clear()
            .env("HOME", "/dev/null")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_TEMPLATE_DIR", "")
            .env(
                "GIT_ALLOW_PROTOCOL",
                if cfg!(test) {
                    "https:ssh:file"
                } else {
                    "https:ssh"
                },
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd.as_std_mut().process_group(0);
        for name in ["PATH", "LANG"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd
    }

    pub(super) async fn git(&self, dir: &Path, args: &[&str]) -> Result<String, String> {
        self.git_with_credentials(dir, args, None).await
    }

    pub(super) async fn git_with_credentials(
        &self,
        dir: &Path,
        args: &[&str],
        helper: Option<&Path>,
    ) -> Result<String, String> {
        let out = self.git_output(dir, args, helper).await?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "git {} failed: {}",
                args.first().unwrap_or(&"command"),
                tail(&String::from_utf8_lossy(&out.stderr), 500)
            ))
        }
    }

    pub(super) async fn git_output(
        &self,
        dir: &Path,
        args: &[&str],
        helper: Option<&Path>,
    ) -> Result<std::process::Output, String> {
        let mut cmd = self.command(dir, &[]);
        if let Some(helper) = helper {
            // Only the path is passed, never the credential. The broker helper verifies host.
            let path = helper
                .to_str()
                .filter(|p| !p.contains('\''))
                .ok_or("invalid credential helper path")?;
            cmd.args(["-c", &format!("credential.helper=!'{path}'")]);
        }
        cmd.args(args);
        let mut child = cmd.spawn().map_err(|e| format!("git spawn: {e}"))?;
        let _group = Group(child.id().ok_or("git has no pid")?);
        let stdout = child.stdout.take().ok_or("git stdout missing")?;
        let stderr = child.stderr.take().ok_or("git stderr missing")?;
        let read = |stream: tokio::process::ChildStdout| async move {
            let mut bytes = Vec::new();
            stream.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
            if bytes.len() > 1024 * 1024 {
                return Err(std::io::Error::other("git output limit"));
            }
            Ok(bytes)
        };
        let task = async {
            let err = async {
                let mut bytes = Vec::new();
                stderr.take(1024 * 1024 + 1).read_to_end(&mut bytes).await?;
                if bytes.len() > 1024 * 1024 {
                    return Err(std::io::Error::other("git output limit"));
                }
                Ok(bytes)
            };
            tokio::try_join!(child.wait(), read(stdout), err)
        };
        let deadline = if args
            .first()
            .is_some_and(|a| ["clone", "fetch", "push"].contains(a))
        {
            self.git_timeout
        } else {
            self.git_timeout.min(Duration::from_secs(30))
        };
        // Check disk during transfer, not only after an unbounded clone has filled it.
        let watched = async {
            tokio::pin!(task);
            loop {
                tokio::select! {
                    result = &mut task => return result.map_err(|e| e.to_string()),
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {
                        if super::disk::size(&self.root) > self.git_size_cap { return Err("git disk size limit".to_owned()); }
                    }
                }
            }
        };
        let result = tokio::time::timeout(deadline, watched).await;
        match result {
            Ok(Ok((status, stdout, stderr))) => {
                if super::disk::size(&self.root) > self.git_size_cap {
                    return Err("git disk size limit".into());
                }
                Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                })
            }
            other => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                match other {
                    Err(_) => Err("git timeout".into()),
                    Ok(Err(why)) => Err(why),
                    _ => unreachable!(),
                }
            }
        }
    }
}
