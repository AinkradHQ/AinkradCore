//! The `design` driver's ops (Design V6-01, plan T7): the runner hands a design job to its own
//! `ainkrad-design` helper (CPU Skia) or to headless Chromium, each in a sandbox with no network, a
//! read-only input and resource limits. Fonts, images, SVG and HTML from a library are untrusted and
//! are parsed only there, never in the Core and never in the runner process.
//!
//! Every byte travels inline as standard base64, so one job and one answer each stay under the
//! Core's 8 MiB message cap: at most [`DESIGN_MAX_INPUT`] bytes of job in, a [`DESIGN_MAX_PNG`] PNG out.
//! A helper that fails, crashes or is stopped at a limit is answered `design_failed`; the runner
//! itself never parses the job's files.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const OP_DESIGN_RENDER: &str = "design.render";
pub const OP_DESIGN_MEASURE: &str = "design.measure";
pub const OP_DESIGN_REVIEW: &str = "design.review";
pub const OP_DESIGN_CHECK: &str = "design.check";
pub const OP_DESIGN_SHOT: &str = "design.shot";
pub const OP_DESIGN_EXPORT: &str = "design.export";
pub const OP_DESIGN_FIDELITY: &str = "design.fidelity";

/// The largest job, as its command JSON (base64 included): under the Core's 8 MiB message cap, so
/// about 5 MiB of files. ponytail: inline bytes; a bigger font is refused by the check. Stream the
/// input as `output` frames (as `ssh.sftp.write` does) if real libraries need more.
pub const DESIGN_MAX_INPUT: usize = 7 << 20;
/// The largest PNG an answer carries.
pub const DESIGN_MAX_PNG: usize = 5 << 20;
/// The largest image side in pixels, and the most pixels in all.
pub const DESIGN_MAX_SIDE: u32 = 8192;
pub const DESIGN_MAX_PIXELS: u64 = 32 << 20;
/// Files in one `design.shot` (plan T10).
pub const DESIGN_MAX_FILES: usize = 200;

/// A file by its library hash: `sha256` (lowercase hex) and its bytes, standard base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignFile {
    pub sha256: String,
    pub data: String,
}

/// What every document op carries: the design (model JSON, `design_model::Doc`), the system it
/// names, the library fonts and images it uses, and which page and theme.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignDoc {
    pub doc_id: String,
    pub doc: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<Value>,
    /// `day` or `night`.
    pub theme: String,
    #[serde(default)]
    pub page: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fonts: Vec<DesignFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<DesignFile>,
    /// The hash of one of `fonts` that `system` text falls back to (plan Q2: Linux has no SF Pro).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_font: Option<String>,
}

/// `design.render`: one screen or node (or the whole page) as a PNG, CPU Skia.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignRender {
    #[serde(flatten)]
    pub doc: DesignDoc,
    /// A resolved node id; absent, every screen of the page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Pixels per point, 0.25 to 4.
    #[serde(default = "one")]
    pub scale: f32,
}

fn one() -> f32 {
    1.0
}

/// `design.measure`: every laid-out node's box.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignMeasure {
    #[serde(flatten)]
    pub doc: DesignDoc,
}

/// `design.review`: geometry findings (what needs real text metrics and layout).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignReview {
    #[serde(flatten)]
    pub doc: DesignDoc,
}

/// `design.check`: is this upload a font, or an Icon Composer `.icon` zip, the helper can use?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignCheck {
    /// `font` or `icon_composer`.
    pub kind: String,
    /// Standard base64.
    pub data: String,
}

/// One file of a `design.shot` site: a relative path (no `..`, no leading `/`, no NUL or `\`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignShotFile {
    pub path: String,
    pub data: String,
}

/// `design.shot`: headless Chromium opens `entry` of `files` (an HTML export or a mockup package)
/// with no network and screenshots the viewport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignShot {
    pub files: Vec<DesignShotFile>,
    pub entry: String,
    pub width: u32,
    pub height: u32,
    #[serde(default = "one")]
    pub scale: f32,
}

/// The answer to `design.render` and `design.shot`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignImage {
    /// Standard base64 PNG.
    pub png: String,
    pub width: u32,
    pub height: u32,
    /// Some text used a font other than the library file it names (plan Q2: "metrics differ").
    #[serde(default)]
    pub metrics_differ: bool,
}

/// One node's absolute box, in points.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignBox {
    pub id: String,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignBoxes {
    pub nodes: Vec<DesignBox>,
}

/// A geometry finding: `rule` (`geometry.outside`, `geometry.text_overflow`), the node, a sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignFinding {
    pub rule: String,
    pub node: String,
    pub msg: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignFindings {
    pub findings: Vec<DesignFinding>,
}

/// The answer to `design.check`: `ok`, or a fixed sentence why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignChecked {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `design.export` (V6-03): one screen as an inert HTML/CSS package. The answer carries the page and
/// its stylesheet; the fonts and images it names are the job's own files, which the caller already
/// holds, so they are not sent back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignExport {
    #[serde(flatten)]
    pub doc: DesignDoc,
    /// A resolved id of a top-level node of the page; absent, the page's first screen. `doc.theme`
    /// is only the theme the page opens in: the package carries both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<String>,
}

/// The answer to `design.export`. Files of the package: `index.html`, `style.css`, and for each
/// hash in `fonts` / `images` the file `fonts/<sha256>` / `assets/<sha256>` (the job's bytes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignExported {
    /// The resolved id of the screen exported (what `design.render`'s `node` takes).
    pub screen: String,
    pub html: String,
    pub css: String,
    pub fonts: Vec<String>,
    pub images: Vec<String>,
    /// The screen's size in points, as the engine lays it out: the viewport a shot of it needs.
    pub width: u32,
    pub height: u32,
    /// Some text used a font other than the library file it names (plan Q2).
    #[serde(default)]
    pub metrics_differ: bool,
}

/// `design.fidelity`: how far two PNGs of one screen are apart (the engine's frame, Chromium's shot
/// of the export). Both are decoded only in the helper's sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignFidelity {
    pub a: String,
    pub b: String,
}

/// The answer to `design.fidelity`: the share of pixels that differ by more than the tolerance
/// (CIE76 delta E), in percent. Sizes that differ are a score of 100.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignFidelityScore {
    pub percent: f64,
    pub changed: u64,
    pub total: u64,
    pub width: u32,
    pub height: u32,
}
