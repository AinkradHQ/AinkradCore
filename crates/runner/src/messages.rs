//! What the daemon does with each server message and each report of its run's task.

use super::*;

impl<E: Executor> Daemon<E> {
    pub(crate) fn on_server(&mut self, msg: ServerMessage) -> Vec<RunnerMessage> {
        match msg {
            ServerMessage::Assign {
                run,
                agent,
                issue,
                harness,
                model,
                context_ref,
                workspace,
                token_cap,
                token_caps,
                policy,
                issue_key,
                instructions,
                account,
                fallbacks,
                limits,
                resume_session,
                prompt,
            } => {
                if let Some(busy) = self.run_id() {
                    tracing::error!(run, busy, "assigned a run while busy; it will expire");
                    return vec![];
                }
                let job = Job {
                    run,
                    agent,
                    issue,
                    harness,
                    model,
                    context_ref,
                    // The first repo here, every repo in `repos` when there are several.
                    repos: match workspace.as_deref() {
                        Some(w) if !w.also.is_empty() => {
                            let first = ainkrad_proto::runner::Workspace {
                                also: vec![],
                                ..w.clone()
                            };
                            std::iter::once(first)
                                .chain(w.also.iter().cloned())
                                .collect()
                        }
                        _ => vec![],
                    },
                    workspace: workspace
                        .map(|w| ainkrad_proto::runner::Workspace { also: vec![], ..*w }),
                    token_cap,
                    token_caps: token_caps.map(|c| *c),
                    policy,
                    issue_key,
                    instructions: instructions.map(|i| *i),
                    account: account.map(|a| *a),
                    fallbacks,
                    limits: limits.map(|l| *l),
                    resume_session: resume_session.map(|s| *s),
                    prompt: prompt.map(|p| *p),
                };
                let (token_tx, token_rx) = oneshot::channel();
                let (executor, out) = (self.executor.clone(), self.out_tx.clone());
                let redactor = self.redactor.clone();
                let task = tokio::spawn(work::work(
                    executor,
                    job.clone(),
                    out,
                    token_rx,
                    redactor.clone(),
                ));
                self.current = Some(Current {
                    job,
                    task,
                    token: Some(token_tx),
                    redactor,
                    started: None,
                    ended: None,
                    sent: VecDeque::new(),
                    asking: HashMap::new(),
                });
                vec![]
            }
            ServerMessage::Token { run, token } => {
                if let Some(c) = self.current.as_mut().filter(|c| c.job.run == run)
                    && let Some(tx) = c.token.take()
                {
                    c.redactor.known("run_token", token.expose());
                    let _ = tx.send(token);
                }
                vec![]
            }
            ServerMessage::Cancel { run, reason } => {
                tracing::warn!(run, %reason, "run cancelled by the server");
                self.finish(run)
            }
            ServerMessage::Approval {
                run,
                id,
                approved,
                reply,
            } => {
                let asked = self.current.as_mut().filter(|c| c.job.run == run);
                match asked.and_then(|c| c.asking.remove(&id)) {
                    Some((_, to)) => to.send(Answer { approved, reply }),
                    None => tracing::debug!(run, %id, "an answer nobody waits for"),
                }
                vec![]
            }
            ServerMessage::Pause { run } => {
                self.control(run, Control::Pause);
                vec![]
            }
            ServerMessage::Message { run, id, text } => {
                self.control(run, Control::Message { id, text });
                vec![]
            }
            ServerMessage::Prune { mut issues } => {
                // The current run's worktree stays, whatever the server thinks of its issue.
                let busy = self.current.as_ref().and_then(|c| c.job.issue);
                issues.retain(|i| Some(*i) != busy);
                let executor = self.executor.clone();
                tokio::spawn(async move { executor.prune(issues).await });
                vec![]
            }
            ServerMessage::Ack { run } => match &self.current {
                Some(c) if c.job.run == run && c.ended.is_some() => self.finish(run),
                _ => vec![],
            },
            ServerMessage::ReadFile {
                run,
                request,
                path,
                max_bytes,
            } => {
                let current = self.current.as_ref().filter(|c| c.job.run == run);
                let Some(c) = current else {
                    let error = Some(format!("run {run} is not running here"));
                    let content = None;
                    return vec![RunnerMessage::FileRead {
                        request,
                        content,
                        error,
                    }];
                };
                let (issue, mut redactor) = (c.job.issue, c.redactor.clone());
                for (name, value) in self.executor.run_secrets(&c.job) {
                    redactor.known(&name, &value);
                }
                let (executor, out) = (self.executor.clone(), self.out_tx.clone());
                tokio::spawn(async move {
                    // A text file leaves the runner redacted; the server redacts it again.
                    let result = executor
                        .read_file(issue, &path, max_bytes)
                        .await
                        .map(|bytes| redactor.file(&path, bytes).0);
                    let _ = out.send(Out::FileRead { request, result }).await;
                });
                vec![]
            }
            ServerMessage::ReadLog { request, lines } => {
                let (log, redactor, out) = (
                    self.config.log.clone(),
                    self.redactor.clone(),
                    self.out_tx.clone(),
                );
                tokio::spawn(async move {
                    let result = state::tail(log.as_deref(), lines, &redactor);
                    let _ = out.send(Out::LogTail { request, result }).await;
                });
                vec![]
            }
            ServerMessage::Probe { request } => {
                let (executor, out) = (self.executor.clone(), self.out_tx.clone());
                tokio::spawn(async move {
                    let harnesses = executor.reprobe().await;
                    let _ = out.send(Out::Probed { request, harnesses }).await;
                });
                vec![]
            }
            ServerMessage::PolicyUpdate { run, policy } => {
                tracing::info!(run, "the run's permission policy changed");
                self.control(run, Control::Policy(policy));
                vec![]
            }
            ServerMessage::Prefs { power_nap } => {
                tracing::info!(power_nap, "the admin's Power Nap preference");
                self.power_nap = Some(power_nap);
                vec![self.status()]
            }
            // A refused `RunEnded` (storage error) is resent on the next heartbeat tick.
            ServerMessage::Error { message } => {
                tracing::error!(%message, "server error");
                vec![]
            }
            ServerMessage::Welcome { .. } => vec![],
        }
    }

    /// Hands `control` to the current run if it is `run`.
    fn control(&self, run: i64, control: Control) {
        match self.run_id() == Some(run) {
            true => self.executor.control(run, control),
            false => tracing::debug!(run, ?control, "a control for a run not here"),
        }
    }

    pub(crate) fn on_out(&mut self, out: Out) -> Vec<RunnerMessage> {
        if let Out::FileRead { request, result } = out {
            use base64::Engine;
            let (content, error) = match result {
                Ok(bytes) => (
                    Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
                    None,
                ),
                Err(why) => (None, Some(why)),
            };
            return vec![RunnerMessage::FileRead {
                request,
                content,
                error,
            }];
        }
        if let Out::LogTail { request, result } = out {
            let (lines, error) = match result {
                Ok(lines) => (lines, None),
                Err(why) => (vec![], Some(why)),
            };
            return vec![RunnerMessage::LogTail {
                request,
                lines,
                error,
            }];
        }
        if let Out::Probed { request, harnesses } = out {
            return vec![RunnerMessage::Probed {
                request,
                harnesses: harnesses.unwrap_or_else(|| self.config.harnesses.clone()),
                info: Box::new(self.info()),
                os: Some(std::env::consts::OS.to_owned()),
                arch: Some(std::env::consts::ARCH.to_owned()),
                error: None,
            }];
        }
        if let Out::Disk(report) = out {
            self.housekeeping = false;
            let mut msgs = vec![];
            if let Some(report) = report {
                self.disk = Some(report.clone());
                msgs.push(RunnerMessage::Disk {
                    report: Box::new(report),
                });
            }
            msgs.push(self.status());
            return msgs;
        }
        let run = match &out {
            Out::Started { run, .. }
            | Out::Event { run, .. }
            | Out::Ended { run, .. }
            | Out::Usage { run, .. }
            | Out::Approval { run, .. }
            | Out::Fallback { run, .. }
            | Out::Dropped { run, .. }
            | Out::Progress { run, .. } => *run,
            Out::Disk(_) | Out::FileRead { .. } | Out::LogTail { .. } | Out::Probed { .. } => {
                unreachable!("handled above")
            }
        };
        let Some(c) = self.current.as_mut().filter(|c| c.job.run == run) else {
            return vec![];
        };
        vec![match out {
            Out::Started { run, session } => {
                c.started = Some(session.clone());
                RunnerMessage::RunStarted { run, session }
            }
            Out::Event { run, seq, payload } => {
                let msg = RunnerMessage::RunEvent { run, seq, payload };
                if c.sent.len() == RESEND_WINDOW {
                    c.sent.pop_front();
                }
                c.sent.push_back(msg.clone());
                msg
            }
            Out::Usage { run, seq, usage } => RunnerMessage::RunUsage { run, seq, usage },
            Out::Dropped { run, reason } => RunnerMessage::ProviderDrop { run, reason },
            Out::Progress {
                run,
                diff_files,
                repos,
            } => RunnerMessage::Progress {
                run,
                diff_files,
                repos,
            },
            Out::Fallback {
                run,
                harness,
                model,
                account,
                class,
                reason,
            } => {
                let msg = RunnerMessage::RunFallback {
                    run,
                    harness,
                    model,
                    account,
                    class,
                    reason,
                };
                if c.sent.len() == RESEND_WINDOW {
                    c.sent.pop_front();
                }
                c.sent.push_back(msg.clone());
                msg
            }
            Out::Approval {
                run,
                id,
                tool,
                input,
                timeout_secs,
                reply,
            } => {
                let msg = RunnerMessage::ApprovalRequest {
                    run,
                    id: id.clone(),
                    tool,
                    input,
                    timeout_secs: Some(timeout_secs),
                };
                c.asking.insert(id, (msg.clone(), reply));
                msg
            }
            Out::Ended { run, outcome } => {
                c.ended = Some(outcome.clone());
                RunnerMessage::RunEnded { run, outcome }
            }
            Out::Disk(_) | Out::FileRead { .. } | Out::LogTail { .. } | Out::Probed { .. } => {
                unreachable!("handled above")
            }
        }]
    }
}
