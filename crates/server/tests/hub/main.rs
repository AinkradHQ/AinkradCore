//! The runner hub (E1-11.2, E1-11.3) through a real gateway: a fake runner (`Fake`) speaks
//! protocol v2 by hand, so every frame the Core sends is seen and every frame it gets is chosen.
//! `routing` covers commands, capabilities, backpressure and connection ends; `proof` the
//! upgrade's authentication and the channel-bound proof, over loopback and over TLS.

mod agents;
use ainkrad_core_server::agents::AgentsConfig;
mod fault;
mod health;
mod proof;
mod resume;
mod routing;
mod runner;
mod sandbox;
mod terminals;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::crypto::{b64, unb64};
use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::gateway::{Gateway, Limits, Listen};
use ainkrad_core_server::hub::HubConfig;
use ainkrad_core_server::hub::connect::PATH;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store;
use ainkrad_proto::v2::*;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Every log line of this test binary (the server's at TRACE), for `proof::no_proof_material_is_logged`.
#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Log {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn log() -> &'static Log {
    static LOG: OnceLock<Log> = OnceLock::new();
    LOG.get_or_init(|| {
        let log = Log::default();
        let w = log.clone();
        // The server's own lines at every level; others at INFO, the level a server runs at
        // (`ops::logging`): tungstenite dumps whole frames at TRACE.
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let targets = tracing_subscriber::filter::Targets::new()
            .with_default(tracing::Level::INFO)
            .with_target("ainkrad_core_server", tracing::Level::TRACE);
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(move || w.clone()))
            .with(targets)
            .init();
        log
    })
}

/// A Core on loopback with a fresh database, serving until dropped.
pub struct Core {
    pub app: App,
    pub port: u16,
    pub host: String,
    dir: std::path::PathBuf,
}

impl Drop for Core {
    fn drop(&mut self) {
        self.app.closing.send_replace(true);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub fn quick() -> HubConfig {
    HubConfig {
        heartbeat: Duration::from_secs(1),
        handshake: Duration::from_secs(2),
        // The fakes and the real runner dial plain loopback (`--allow-plain-runner`).
        allow_plain_loopback: true,
        // Real runners report the host's real load, which a busy test machine must not turn
        // into `busy`; the load test sets its own threshold.
        max_host_load: 1e9,
        ..HubConfig::default()
    }
}

impl Core {
    pub async fn start(name: &str, hub: HubConfig) -> Self {
        Self::start_on(name, hub, Listen::Tcp("127.0.0.1:0".to_owned()), None, None).await
    }

    /// [`Core::start`] with the agent supervisors paced by `agents`.
    pub async fn start_agents(name: &str, hub: HubConfig, agents: AgentsConfig) -> Self {
        let listen = Listen::Tcp("127.0.0.1:0".to_owned());
        Self::start_with(name, hub, listen, None, None, agents).await
    }

    /// Serves `listen`; `host` overrides the Host clients send (TLS: `localhost:<port>`).
    pub async fn start_on(
        name: &str,
        hub: HubConfig,
        listen: Listen,
        dir: Option<&std::path::Path>,
        host: Option<&str>,
    ) -> Self {
        Self::start_with(name, hub, listen, dir, host, agents::quick()).await
    }

    async fn start_with(
        name: &str,
        hub: HubConfig,
        listen: Listen,
        dir: Option<&std::path::Path>,
        host: Option<&str>,
        agents: AgentsConfig,
    ) -> Self {
        log();
        let dir = dir.map(ToOwned::to_owned).unwrap_or_else(|| {
            let d = std::env::temp_dir().join(format!("core-hub-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        });
        let pool = store::connect(&dir.join("core.db")).await.unwrap();
        let identity = Arc::new(Identity::load_or_create(&dir).unwrap());
        let tls = matches!(listen, Listen::Public { .. });
        let gateway = Gateway::bind(listen, Limits::default()).await.unwrap();
        let port = gateway.local_addr().unwrap().port();
        let host = if let Some(h) = host {
            h.to_owned()
        } else if tls {
            format!("localhost:{port}")
        } else {
            format!("127.0.0.1:{port}")
        };
        let mut app = App::new(pool, Arc::new(SystemClock), host.clone(), identity);
        app.hub = Arc::new(ainkrad_core_server::hub::Hub::new(hub));
        // The secrets broker's master key and quick agent supervisors (`agents`).
        let master = ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]);
        app.secrets = Some(Arc::new(master));
        app.agents = ainkrad_core_server::agents::Agents::new(agents);
        let closing = Arc::clone(&app.closing);
        tokio::spawn(gateway.serve(router(app.clone()), closing, Duration::from_secs(2)));
        Self {
            app,
            port,
            host,
            dir,
        }
    }

    /// A runner device enrolled with a session (`kind`, `scopes`).
    pub async fn device(&self, kind: &str, scopes: &[&str]) -> TestDevice {
        let d = TestDevice::enroll(
            &self.app.pool,
            "runner-1",
            kind,
            scopes,
            &self.app.auth.identity.fp,
            Arc::new(SystemClock),
        )
        .await;
        let s = self.app.auth.issue_session(&d.id, SystemClock.unix());
        d.set_session(Some(s.id));
        d
    }

    pub async fn runner(&self) -> TestDevice {
        self.device("runner", &["runner"]).await
    }
}

pub type Ws = WebSocketStream<Box<dyn Io>>;

/// The upgrade to `PATH` over `io`, signed by `dev` (unsigned with `None`): the socket, or the
/// HTTP status and body of a refusal.
pub async fn upgrade(
    io: Box<dyn Io>,
    host: &str,
    dev: Option<&TestDevice>,
) -> Result<Ws, (u16, String)> {
    let mut req = format!("ws://{host}{PATH}").into_client_request().unwrap();
    for (n, v) in dev.map(|d| d.headers("GET", PATH, b"")).unwrap_or_default() {
        req.headers_mut()
            .insert(n, HeaderValue::from_str(&v).unwrap());
    }
    match tokio_tungstenite::client_async(req, io).await {
        Ok((ws, _)) => Ok(ws),
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => {
            let body = r
                .body()
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned());
            Err((r.status().as_u16(), body.unwrap_or_default()))
        }
        Err(e) => panic!("upgrade: {e}"),
    }
}

/// The runner side of a connection, by hand.
pub struct Fake {
    pub ws: Ws,
    seq: u64,
    /// What `hello` claims for resume (E1-11.4).
    pub boot: Option<String>,
    pub streams: Vec<StreamState>,
    /// Load to advertise in `hello` (E2-15.2).
    pub load: Option<HostLoad>,
}

pub fn exec_driver(commands: &[&str], capacity: u32) -> DriverInfo {
    DriverInfo {
        name: "exec".to_owned(),
        commands: commands.iter().map(|c| (*c).to_owned()).collect(),
        capacity,
        ..DriverInfo::default()
    }
}

impl Fake {
    pub async fn plain(core: &Core, dev: &TestDevice) -> Self {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", core.port))
            .await
            .unwrap();
        let ws = upgrade(Box::new(tcp), &core.host, Some(dev))
            .await
            .expect("upgraded");
        Self::new(ws)
    }

    pub fn new(ws: Ws) -> Self {
        Self {
            ws,
            seq: 0,
            boot: None,
            streams: Vec::new(),
            load: None,
        }
    }

    /// Connected and welcomed, with `drivers`, over loopback.
    pub async fn welcomed(core: &Core, dev: &TestDevice, drivers: Vec<DriverInfo>) -> Self {
        let mut f = Self::plain(core, dev).await;
        let auth = f.hello(dev, drivers, &random32()).await;
        f.prove(dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
            .await;
        f.welcome().await;
        f
    }

    pub async fn send(&mut self, stream: u64, body: Body) {
        let frame = Frame::new(stream, self.seq, body);
        self.seq += 1;
        self.send_frame(&frame).await;
    }

    pub async fn send_frame(&mut self, frame: &Frame) {
        let text = serde_json::to_string(frame).unwrap();
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    /// `hello` as `dev` with nonce `nonce_r`, answered by the Core's `auth`.
    pub async fn hello(
        &mut self,
        dev: &TestDevice,
        drivers: Vec<DriverInfo>,
        nonce_r: &[u8; 32],
    ) -> CoreAuth {
        let hello = RunnerHello {
            protocol: PROTOCOL_VERSION.to_owned(),
            runner_version: "test".to_owned(),
            drivers,
            os: None,
            arch: None,
            device_id: Some(dev.id.clone()),
            nonce: Some(b64(nonce_r)),
            boot: self.boot.clone(),
            streams: self.streams.clone(),
            terminals: vec![],
            load: self.load,
        };
        self.send(CONTROL_STREAM, Body::Control(Control::Hello(hello)))
            .await;
        match self.next().await.body().unwrap() {
            Some(Body::Control(Control::Auth(a))) => a,
            other => panic!("expected auth, got {other:?}"),
        }
    }

    /// The runner's proof for `auth` under exporter `x`.
    pub async fn prove(&mut self, dev: &TestDevice, auth: &CoreAuth, x: &[u8], core_fp: &str) {
        let nonce_c = unb64(&auth.nonce, 43).unwrap();
        let sig = dev.sign(&runner_auth_message(x, &nonce_c, core_fp));
        let proof = Control::Proof(RunnerProof { sig: b64(&sig) });
        self.send(CONTROL_STREAM, Body::Control(proof)).await;
    }

    pub async fn welcome(&mut self) -> CoreWelcome {
        match self.next().await.body().unwrap() {
            Some(Body::Control(Control::Welcome(w))) => w,
            other => panic!("expected welcome, got {other:?}"),
        }
    }

    /// Sends a heartbeat frame on the control stream with `load`.
    pub async fn heartbeat(&mut self, load: Option<HostLoad>) {
        self.send(CONTROL_STREAM, Body::Heartbeat(Heartbeat { load }))
            .await;
    }

    /// The next frame that is not a heartbeat.
    pub async fn next(&mut self) -> Frame {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), self.ws.next())
                .await
                .expect("a frame in time")
                .expect("open")
                .expect("ok");
            match msg {
                Message::Text(t) => {
                    let f: Frame = serde_json::from_str(&t).unwrap();
                    if f.kind != FrameKind::Heartbeat {
                        return f;
                    }
                }
                Message::Close(c) => panic!("closed: {c:?}"),
                _ => {}
            }
        }
    }

    /// Reads until the Core closes: its close code (heartbeats answered meanwhile).
    pub async fn closed(&mut self) -> u16 {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), self.ws.next())
                .await
                .expect("closed in time");
            match msg {
                Some(Ok(Message::Close(Some(c)))) => return c.code.into(),
                Some(Ok(Message::Text(_))) => {
                    let beat = serde_json::to_string(&Frame::new(
                        0,
                        0,
                        Body::Heartbeat(Heartbeat::default()),
                    ))
                    .unwrap();
                    let _ = self.ws.send(Message::Text(beat.into())).await;
                }
                Some(Ok(_)) => {}
                other => panic!("ended without a close frame: {other:?}"),
            }
        }
    }
}

pub fn random32() -> [u8; 32] {
    ainkrad_core_server::auth::crypto::random::<32>()
}
