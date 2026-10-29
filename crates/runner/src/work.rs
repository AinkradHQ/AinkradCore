//! A run's task (E3.1, E3.9): it outlives connections, and redacts what it reports.

use std::sync::Arc;

use ainkrad_proto::redact::Redactor;
use ainkrad_proto::runner::{Outcome, RunToken};
use tokio::sync::{mpsc, oneshot};

use crate::{Executor, Job, Out, Report};

/// The outcome with its reason redacted.
fn redacted(outcome: Outcome, redactor: &Redactor) -> Outcome {
    match outcome {
        Outcome::Failed {
            reason,
            fingerprint,
        } => Outcome::Failed {
            reason: redactor.text(&reason),
            fingerprint,
        },
        Outcome::Cancelled { reason } => Outcome::Cancelled {
            reason: redactor.text(&reason),
        },
        other => other,
    }
}

/// A run's task: start the harness, wait for the token, work, report the outcome. Every
/// chunk and reason it reports is redacted first.
pub(crate) async fn work<E: Executor>(
    executor: Arc<E>,
    job: Job,
    out: mpsc::Sender<Out>,
    token: oneshot::Receiver<RunToken>,
    mut redactor: Redactor,
) {
    let run = job.run;
    let outcome = match executor.start(&job).await {
        Err(reason) => Outcome::Failed {
            reason,
            fingerprint: Some("harness_start".to_owned()),
        },
        Ok(session) => {
            for (name, value) in executor.run_secrets(&job) {
                redactor.known(&name, &value);
            }
            if out.send(Out::Started { run, session }).await.is_err() {
                return;
            }
            let Ok(token) = token.await else {
                return;
            };
            redactor.known("run_token", token.expose());
            let redactor = &redactor;
            let (reports, mut chunks) = mpsc::channel(64);
            let forward = async {
                let (mut seq, mut useq) = (0, 0);
                while let Some(report) = chunks.recv().await {
                    let msg = match report {
                        Report::Event(mut payload) => {
                            redactor.json(&mut payload);
                            seq += 1;
                            Out::Event { run, seq, payload }
                        }
                        Report::Approval {
                            id,
                            tool,
                            mut input,
                            timeout_secs,
                            reply,
                        } => {
                            redactor.json(&mut input);
                            Out::Approval {
                                run,
                                id,
                                tool,
                                input,
                                timeout_secs,
                                reply,
                            }
                        }
                        Report::Fallback {
                            harness,
                            model,
                            account,
                            class,
                            reason,
                        } => Out::Fallback {
                            run,
                            harness,
                            model,
                            account,
                            class,
                            reason: redactor.text(&reason),
                        },
                        Report::Progress { diff_files, repos } => Out::Progress {
                            run,
                            diff_files,
                            repos,
                        },
                        Report::Dropped { reason } => Out::Dropped {
                            run,
                            reason: redactor.text(&reason),
                        },
                        Report::Usage(usage) => {
                            useq += 1;
                            Out::Usage {
                                run,
                                seq: useq,
                                usage,
                            }
                        }
                    };
                    if out.send(msg).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(executor.run(&job, token, reports), forward).0
        }
    };
    let outcome = redacted(outcome, &redactor);
    let _ = out.send(Out::Ended { run, outcome }).await;
}
