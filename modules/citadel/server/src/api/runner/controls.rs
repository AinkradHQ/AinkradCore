//! The admin's controls of this runner's runs (1.19, decision #34): a stop goes as `Cancel`, a
//! pause as `Pause`, a message as `Message`.

use ainkrad_proto::runner::ServerMessage;

use super::{Session, cancel};
use crate::store::exec::take_controls;

impl Session {
    /// The unsent controls of this runner's runs; only stops for a runner older than 1.19.
    pub(super) async fn controls(&mut self) -> Vec<ServerMessage> {
        let kinds: &[&str] = match self.takes_controls {
            true => &["stop", "pause", "message"],
            false => &["stop"],
        };
        let now = self.now();
        let taken = match take_controls(&self.app.pool, self.runner.id, kinds, &now).await {
            Ok(taken) => taken,
            Err(e) => {
                tracing::error!(error = %e, "reading the runs' controls failed");
                return vec![];
            }
        };
        taken
            .into_iter()
            .map(|(id, run, kind, body)| match kind.as_str() {
                "pause" => ServerMessage::Pause { run },
                "message" => ServerMessage::Message {
                    run,
                    id,
                    text: body,
                },
                _ => cancel(run, body),
            })
            .collect()
    }
}
