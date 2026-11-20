//! Runners as hardware (E15-1): placement ([`place`], pure), the live view the rules read
//! ([`view`]) and the debounced `hardware.changed` events.

pub mod place;
pub mod view;

use std::time::Duration;

use crate::api::App;

/// `hardware.changed` is sent at most once per device per this long.
const DEBOUNCE: Duration = Duration::from_secs(5);

/// Writes `hardware.changed {id}` for every device whose view changed, once per [`DEBOUNCE`]
/// (a heartbeat every 15 s must not become an event every 15 s per watcher).
pub async fn changed_loop(app: App) {
    loop {
        app.hub.hw_changed().await;
        tokio::time::sleep(DEBOUNCE).await;
        for id in app.hub.hw_take() {
            let written = async {
                let mut tx = crate::store::begin_write(&app.pool).await?;
                crate::store::events::append(
                    &mut tx,
                    "hardware.changed",
                    &serde_json::json!({ "id": id }),
                )
                .await?;
                tx.commit().await
            };
            if let Err(e) = written.await {
                tracing::error!(error = %e, "writing hardware.changed failed");
            }
        }
    }
}
