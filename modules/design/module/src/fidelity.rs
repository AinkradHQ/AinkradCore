//! The export fidelity check (V6-03, plan T15): a screen is exported to HTML/CSS, Chromium shoots the export, the
//! helper draws the same screen with Skia, and the helper compares the two PNGs. The Core only sequences the four
//! runner ops and carries bytes; it parses no image, font or HTML (R7). Advisory: the score is recorded, it never
//! blocks an approval.
//!
//! Called with the design, system, fonts and images the approval freezes (V6-02 stores the result on the approval
//! row); this module has no table of its own.

use std::time::Duration;

use ainkrad_core_server::api::App;
use ainkrad_proto::v2::{
    Body, Command, DesignDoc, DesignExport, DesignFidelity, DesignRender, DesignShot,
    DesignShotFile, OP_DESIGN_EXPORT, OP_DESIGN_FIDELITY, OP_DESIGN_RENDER, OP_DESIGN_SHOT, Reply,
};

/// Above this share of changed pixels the export is flagged (plan T15: 1 % for fidelity).
pub const FLAG_PERCENT: f64 = 1.0;
const WAIT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq)]
pub struct Measured {
    /// The resolved id of the screen measured.
    pub screen: String,
    pub theme: String,
    pub percent: f64,
    pub changed: u64,
    pub total: u64,
    pub width: u32,
    pub height: u32,
    /// Text used a font other than the library file it names: the number is a fallback's, not the font's.
    pub metrics_differ: bool,
    pub flagged: bool,
}

/// The online runner offering every op the check needs (Chromium included), most free slots first.
fn place(app: &App) -> Option<String> {
    let need = [
        OP_DESIGN_EXPORT,
        OP_DESIGN_SHOT,
        OP_DESIGN_RENDER,
        OP_DESIGN_FIDELITY,
    ];
    let mut all: Vec<_> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(_, r)| {
            r.online
                && need
                    .iter()
                    .all(|op| r.drivers.iter().any(|d| d.commands.iter().any(|c| c == op)))
        })
        .collect();
    all.sort_by(|a, b| {
        let free = |r: &ainkrad_core_server::hub::RunnerState| r.capacity.saturating_sub(r.load);
        free(&b.1).cmp(&free(&a.1)).then(a.0.cmp(&b.0))
    });
    all.into_iter().next().map(|(id, _)| id)
}

async fn call(app: &App, runner: &str, command: Command) -> Result<Reply, String> {
    let sent = app
        .hub
        .dispatch_design(runner, command)
        .map_err(|e| e.message)?;
    match tokio::time::timeout(WAIT, sent.outcome()).await {
        Ok(Ok(Body::Result(r))) => Ok(r),
        Ok(Ok(_)) => Err("the runner answered with something else".into()),
        Ok(Err(e)) => Err(e.message),
        Err(_) => Err("no answer in time".into()),
    }
}

/// The package's files: the page and sheet from the export, the library files from the job's own bytes.
fn package(
    doc: &DesignDoc,
    html: String,
    css: String,
    fonts: &[String],
    images: &[String],
) -> Vec<DesignShotFile> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    let file = |path: String, data: String| DesignShotFile { path, data };
    let mut files = vec![
        file("index.html".into(), STANDARD.encode(html)),
        file("style.css".into(), STANDARD.encode(css)),
    ];
    for (dir, want, have) in [
        ("fonts", fonts, &doc.fonts),
        ("assets", images, &doc.images),
    ] {
        for f in have.iter().filter(|f| want.contains(&f.sha256)) {
            files.push(file(format!("{dir}/{}", f.sha256), f.data.clone()));
        }
    }
    files
}

/// Measures one screen (`None`: the page's first) of `doc` in the theme `doc.theme`.
pub async fn measure(
    app: &App,
    doc: DesignDoc,
    screen: Option<String>,
) -> Result<Measured, String> {
    let runner = place(app).ok_or("no runner offers design export, shots and fidelity")?;
    let theme = doc.theme.clone();
    let Reply::DesignExport(x) = call(
        app,
        &runner,
        Command::DesignExport(DesignExport {
            doc: doc.clone(),
            screen,
        }),
    )
    .await?
    else {
        return Err("the export answer is not an export".into());
    };
    let files = package(&doc, x.html, x.css, &x.fonts, &x.images);
    let Reply::DesignShot(shot) = call(
        app,
        &runner,
        Command::DesignShot(DesignShot {
            files,
            entry: "index.html".into(),
            width: x.width,
            height: x.height,
            scale: 1.0,
        }),
    )
    .await?
    else {
        return Err("the shot answer is not an image".into());
    };
    let Reply::DesignRender(frame) = call(
        app,
        &runner,
        Command::DesignRender(DesignRender {
            doc,
            node: Some(x.screen.clone()),
            scale: 1.0,
        }),
    )
    .await?
    else {
        return Err("the render answer is not an image".into());
    };
    let Reply::DesignFidelity(s) = call(
        app,
        &runner,
        Command::DesignFidelity(DesignFidelity {
            a: frame.png,
            b: shot.png,
        }),
    )
    .await?
    else {
        return Err("the fidelity answer is not a score".into());
    };
    Ok(Measured {
        screen: x.screen,
        theme,
        percent: s.percent,
        changed: s.changed,
        total: s.total,
        width: s.width,
        height: s.height,
        metrics_differ: x.metrics_differ || frame.metrics_differ,
        flagged: s.percent > FLAG_PERCENT,
    })
}
