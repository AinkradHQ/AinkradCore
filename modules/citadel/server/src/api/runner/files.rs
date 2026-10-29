//! Reading published files from the runner (E15.12): pending reads of this runner's runs go out
//! as `ReadFile`; each `FileRead` answer is left in the artifacts dir's `incoming/` for the MCP
//! call waiting on it, or marks the read failed with the runner's reason.

use ainkrad_proto::runner::ServerMessage;
use base64::Engine;

use super::Session;
use crate::store::artifacts::{FileRead, finish_read, incoming_path, take_reads};

impl Session {
    /// The pending reads of this runner's runs, as `ReadFile`s; an older runner's fail at once.
    pub(super) async fn reads(&mut self) -> Vec<ServerMessage> {
        let taken: Vec<FileRead> = match take_reads(&self.app.pool, self.runner.id).await {
            Ok(taken) => taken,
            Err(e) => {
                tracing::error!(error = %e, "reading pending file reads failed");
                return vec![];
            }
        };
        let mut out = vec![];
        for (request, run, path, max_bytes) in taken {
            if !self.reads_files {
                let why = "the run's runner is too old to read files (protocol 1.17); publish \
                           the content instead";
                self.finished(request, Err(why.to_owned())).await;
                continue;
            }
            out.push(ServerMessage::ReadFile {
                run,
                request,
                path,
                max_bytes,
            });
        }
        out
    }

    /// The runner's answer to read `request`.
    pub(super) async fn file_read(
        &mut self,
        request: i64,
        content: Option<String>,
        error: Option<String>,
    ) -> Vec<ServerMessage> {
        let outcome = match (content, error) {
            (_, Some(why)) => Err(self.redactor.text(&why)),
            (Some(b64), None) => match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(bytes) => {
                    let to = incoming_path(&self.app.artifacts, request);
                    let written = to
                        .parent()
                        .map_or(Ok(()), std::fs::create_dir_all)
                        .and_then(|()| std::fs::write(&to, bytes));
                    written.map_err(|e| {
                        tracing::error!(error = %e, path = %to.display(), "keeping a read failed");
                        "the server could not keep the file".to_owned()
                    })
                }
                Err(_) => Err("the runner sent bad base64".to_owned()),
            },
            (None, None) => Err("the runner sent neither content nor a reason".to_owned()),
        };
        self.finished(request, outcome).await;
        vec![]
    }

    async fn finished(&self, request: i64, outcome: Result<(), String>) {
        if let Err(e) = finish_read(&self.app.pool, request, outcome).await {
            tracing::error!(request, error = %e, "recording a file read failed");
        }
    }
}
