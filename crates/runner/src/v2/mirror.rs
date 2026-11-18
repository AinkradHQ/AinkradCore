//! The runner's signed reads of the Core's repo copies (P3-02): what `workspace::relay` calls to
//! reach `/api/v1/mirrors/{repo}/…`, signed with this runner's own key like a lease redeem. The
//! Core answers only while this device holds a lease for the repo.

use std::sync::{Arc, Mutex};

use super::client::{Client, Signer};
use super::key::{Enrolment, Key};
use crate::workspace::relay::{Call, Reply, Upstream};

pub fn http_upstream(
    client: Arc<Client>,
    key: Arc<Key>,
    enrolment: Arc<Mutex<Enrolment>>,
) -> Upstream {
    Arc::new(move |call: Call| {
        let (client, key, enrolment) = (
            Arc::clone(&client),
            Arc::clone(&key),
            Arc::clone(&enrolment),
        );
        Box::pin(async move {
            let (device, core_fp) = {
                let e = enrolment.lock().unwrap();
                (e.device_id.clone(), e.core_fp.clone())
            };
            let signer = Signer {
                key: &key,
                device: &device,
                core_fp: &core_fp,
            };
            let why = |e: super::client::LinkError| format!("reading a repo copy: {e}");
            let session = client.session(signer).await.map_err(why)?;
            let mut res = client
                .raw(
                    signer,
                    &session,
                    call.method,
                    (&call.path, &call.query),
                    &call.headers,
                    call.body,
                )
                .await
                .map_err(why)?;
            let status = res.status().as_u16();
            let content_type = res
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_owned();
            let (tx, body) = tokio::sync::mpsc::channel(8);
            tokio::spawn(async move {
                loop {
                    match res.chunk().await {
                        Ok(Some(c)) => {
                            if tx.send(Ok(c.to_vec())).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => return,
                        Err(e) => {
                            let _ = tx.send(Err(e.to_string())).await;
                            return;
                        }
                    }
                }
            });
            Ok(Reply {
                status,
                content_type,
                body,
            })
        })
    })
}
