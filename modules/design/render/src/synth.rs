//! A generated app design for the bench and the tests: real model documents (tokens, a design system, nested
//! auto-layout frames, images by hash, glass material), not a hand-built draw list. One screen is ~100 nodes:
//! 40 text runs, 4 glass panels, 30 images (the first of the T5 scene, `screens` times).

use design_model::Doc;
use serde_json::{Value, json};
use skia_safe::{Color, Paint, Point, surfaces};

pub const SYSTEM_ID: &str = "dd_sys";
pub const DOC_ID: &str = "dd_synth";
pub const SCREEN_W: f32 = 390.0;
pub const SCREEN_H: f32 = 1040.0;

pub struct Synth {
    pub doc: Doc,
    pub system: Doc,
    /// (asset hash, encoded PNG)
    pub images: Vec<(String, Vec<u8>)>,
}

const WORDS: &[&str] = &[
    "Wallet", "Orders", "Profile", "Settings", "Checkout", "Delivery", "Invoice", "Payment",
    "Account", "Activity", "Messages", "Calendar", "Garden", "Studio", "Journal", "Travel",
    "Coffee", "Market", "Design", "Review", "Summary", "Balance", "Security", "Support",
];

struct Gen {
    n: usize,
    nodes: serde_json::Map<String, Value>,
    rng: u64,
    asset: Vec<String>,
}

fn base32(mut v: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut s = vec![b'a'; 12];
    for i in (0..12).rev() {
        s[i] = A[v % 32];
        v /= 32;
    }
    String::from_utf8(s).unwrap_or_default()
}

fn base36(mut v: usize) -> String {
    let mut s = vec![b'0'; 5];
    for i in (0..5).rev() {
        s[i] = char::from_digit((v % 36) as u32, 36).unwrap_or('0') as u8;
        v /= 36;
    }
    String::from_utf8(s).unwrap_or_default() + "1"
}

fn color(token: &str) -> Value {
    json!([{"type": "solid", "color": {"token": token}}])
}

impl Gen {
    fn pick(&mut self) -> usize {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 32) as usize
    }

    fn words(&mut self) -> String {
        let (a, b) = (self.pick(), self.pick());
        format!("{} {}", WORDS[a % WORDS.len()], WORDS[b % WORDS.len()])
    }

    fn add(
        &mut self,
        parent: Option<&str>,
        ty: &str,
        name: &str,
        props: Value,
        text: Option<String>,
    ) -> String {
        self.n += 1;
        let id = format!("n_{}", base32(self.n));
        let mut node = json!({
            "type": ty, "parent": parent, "order": base36(self.n), "clock": 1, "name": name, "props": props,
        });
        if let Some(t) = text {
            node["text"] = Value::String(t);
        }
        self.nodes.insert(id.clone(), node);
        id
    }

    fn text(&mut self, parent: &str, ty: &str, tok: &str) -> String {
        let t = self.words();
        self.add(
            Some(parent),
            "text",
            "label",
            json!({"type": {"token": ty}, "fill": color(tok)}),
            Some(t),
        )
    }

    fn image(&mut self, parent: &str, w: f32, h: f32, r: f32) {
        let k = self.pick() % self.asset.len();
        let a = self.asset[k].clone();
        self.add(
            Some(parent),
            "image",
            "img",
            json!({"asset": a, "fit": "fill", "w": w, "h": h, "radius": r}),
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn glass(
        &mut self,
        parent: &str,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        r: f32,
        row_pad: [f32; 4],
    ) -> String {
        self.add(
            Some(parent),
            "frame",
            "glass",
            json!({"x": x, "y": y, "w": w, "h": h, "radius": r, "material": {"token": "material.glass"},
                   "fill": color("color.glass"),
                   "layout": {"dir": "row", "pad": row_pad, "gap": 8, "align": "center", "justify": "between"}}),
            None,
        )
    }

    fn screen(&mut self, page: &str, x: f32, y: f32) {
        let s = self.add(
            Some(page),
            "frame",
            "Screen",
            json!({"x": x, "y": y, "w": SCREEN_W, "h": SCREEN_H, "clip": true, "fill": color("color.bg")}),
            None,
        );
        let c = self.add(
            Some(&s),
            "frame",
            "Content",
            json!({"x": 0, "y": 0, "w": SCREEN_W, "h": SCREEN_H,
                   "layout": {"dir": "column", "gap": 8, "pad": [24, 16, 16, 16]}}),
            None,
        );
        let head = self.add(
            Some(&c),
            "frame",
            "Header",
            json!({"sizing": {"w": "fill"}, "layout": {"dir": "row", "gap": 8, "align": "center"}}),
            None,
        );
        let col = self.add(
            Some(&head),
            "frame",
            "Titles",
            json!({"sizing": {"w": "fill"}, "layout": {"dir": "column"}}),
            None,
        );
        self.text(&col, "type.title", "color.text");
        self.text(&col, "type.caption", "color.dim");
        for _ in 0..2 {
            self.add(
                Some(&head),
                "rect",
                "icon",
                json!({"w": 28, "h": 28, "radius": 8, "fill": color("color.accent")}),
                None,
            );
        }
        self.image(&c, 358.0, 160.0, 14.0);
        for k in 0..2 {
            let row = self.add(
                Some(&c),
                "frame",
                "Strip",
                json!({"layout": {"dir": "row", "gap": 4}}),
                None,
            );
            for _ in 0..(9 + k) {
                self.image(&row, 24.0, 36.0, 5.0);
            }
        }
        for _ in 0..10 {
            let card = self.add(
                Some(&c),
                "frame",
                "Card",
                json!({"sizing": {"w": "fill"}, "radius": {"token": "radius.card"}, "fill": color("color.card"),
                       "shadow": {"token": "shadow.card"},
                       "layout": {"dir": "row", "gap": 10, "pad": [6, 8, 6, 8], "align": "center"}}),
                None,
            );
            self.image(&card, 32.0, 32.0, 8.0);
            let mid = self.add(
                Some(&card),
                "frame",
                "Copy",
                json!({"sizing": {"w": "fill"}, "layout": {"dir": "column"}}),
                None,
            );
            self.text(&mid, "type.body", "color.text");
            self.text(&mid, "type.caption", "color.dim");
            self.text(&card, "type.caption", "color.accent");
        }
        for (x, y, w, h, r) in [
            (150.0, 420.0, 190.0, 40.0, 20.0),
            (310.0, 880.0, 56.0, 56.0, 18.0),
            (24.0, 130.0, 342.0, 46.0, 14.0),
        ] {
            let g = self.glass(&s, x, y, w, h, r, [6.0, 14.0, 6.0, 14.0]);
            self.text(&g, "type.caption", "color.text");
        }
        let tab = self.glass(&s, 16.0, 956.0, 358.0, 68.0, 22.0, [10.0, 12.0, 10.0, 12.0]);
        for _ in 0..5 {
            let c = self.add(
                Some(&tab),
                "frame",
                "Tab",
                json!({"layout": {"dir": "column", "align": "center", "gap": 2}}),
                None,
            );
            self.add(
                Some(&c),
                "rect",
                "icon",
                json!({"w": 22, "h": 22, "radius": 7, "fill": color("color.accent")}),
                None,
            );
            self.text(&c, "type.caption", "color.text");
        }
    }
}

fn system() -> Doc {
    let tok =
        |kind: &str, day: Value, night: Value| json!({"kind": kind, "day": day, "night": night});
    let ty = |size: f32, weight: u32| json!({"font": "system", "size": size, "weight": weight});
    let shadow = |a: &str| json!([{"x": 0, "y": 2, "blur": 8, "spread": 0, "color": a}]);
    serde_json::from_value(json!({
        "meta": {"version": 1},
        "nodes": {},
        "tokens": {
            "color.bg": tok("color", json!("#f6f7fb"), json!("#14151a")),
            "color.card": tok("color", json!("#ffffff"), json!("#1f2128")),
            "color.text": tok("color", json!("#16181f"), json!("#f2f3f7")),
            "color.dim": tok("color", json!("#6b7385"), json!("#9aa1b2")),
            "color.accent": tok("color", json!("#2f6fed"), json!("#6f9cff")),
            "color.glass": tok("color", json!("#ffffff22"), json!("#ffffff0f")),
            "radius.card": tok("radius", json!(12), json!(12)),
            "shadow.card": tok("shadow", shadow("#0f172a22"), shadow("#00000088")),
            "material.glass": tok("material", json!("glass"), json!("glass")),
            "type.title": tok("type", ty(22.0, 700), ty(22.0, 700)),
            "type.body": tok("type", ty(15.0, 400), ty(15.0, 400)),
            "type.caption": tok("type", ty(12.0, 400), ty(12.0, 400)),
        }
    }))
    .unwrap_or_default()
}

/// A 256x256 gradient PNG, different per `i`.
pub fn png(i: usize) -> Vec<u8> {
    let mut s = surfaces::raster_n32_premul((256, 256)).expect("raster surface");
    let h = (i * 47) % 255;
    let (a, b) = (
        Color::from_rgb(h as u8, 120, (255 - h) as u8),
        Color::from_rgb(40, (h / 2 + 100) as u8, 200),
    );
    let mut p = Paint::default();
    p.set_shader(crate::draw::linear_gradient(
        (Point::new(0.0, 0.0), Point::new(256.0, 256.0)),
        &[(0.0, a), (1.0, b)],
    ));
    s.canvas().draw_paint(&p);
    crate::cpu::png(&mut s)
}

/// `screens` app screens in a grid `cols` wide, one page.
pub fn app(screens: usize, cols: usize) -> Synth {
    let images: Vec<(String, Vec<u8>)> = (0..8)
        .map(|i| (format!("{:0>64}", format!("{:x}", 0xabc000 + i)), png(i)))
        .collect();
    let mut g = Gen {
        n: 0,
        nodes: serde_json::Map::new(),
        rng: 0x9E37_79B9_7F4A_7C15,
        asset: images.iter().map(|i| i.0.clone()).collect(),
    };
    let page = g.add(None, "page", "Screens", json!({}), None);
    for i in 0..screens {
        let (c, r) = (i % cols.max(1), i / cols.max(1));
        g.screen(
            &page,
            c as f32 * (SCREEN_W + 80.0),
            r as f32 * (SCREEN_H + 80.0),
        );
    }
    let doc = serde_json::from_value(json!({
        "meta": {"system": SYSTEM_ID, "version": 1},
        "nodes": Value::Object(g.nodes),
    }))
    .unwrap_or_default();
    Synth {
        doc,
        system: system(),
        images,
    }
}
