//! Other people and AI sessions on the canvas (V2-06): their cursors, selections and viewports, and follow mode.
//!
//! Input is the Core's relayed presence message (`ws.rs` there stamps `peer` and `conn`; the App adds a `label`):
//! `{"peer":"person:d_..."|"session:as_...","conn":n,"label":"...","cursor":[x,y]?,"selection":[ids]?,"view":[x,y,w,h]?}`
//! or `{"conn":n,"gone":true}`. Everything in it is hostile: sizes, counts, ids and floats are checked, the label is
//! cut and stripped of control characters, `kind` comes from the `peer` prefix only, and a peer silent for
//! `TTL_MS` is dropped (T13: an AI's presence lives 30 s). Presence is never stored and never touches the document.

use std::collections::BTreeMap;

use design_model::ids::is_node_id;
use design_render::{Camera, PeerMark, Rect};
use serde_json::{Value, json};

use crate::ffi::{DE_ERR_ARG, DE_ERR_INVALID};
use crate::host::{Host, MAX_COORD, MAX_VIEW};

pub(crate) const MAX_PEERS: usize = 64;
pub(crate) const MAX_MESSAGE: usize = 8192;
/// The relay's input limit (`ws.rs` `MAX_PRESENCE_BYTES`); the relay adds `peer`, `conn` and escapes, so what reaches
/// the engine can be larger than what was sent, hence `MAX_MESSAGE` above.
#[cfg(test)]
const RELAY_INPUT: usize = 4096;
pub(crate) const MAX_SELECTION: usize = 256;
pub(crate) const MAX_LABEL: usize = 40;
pub(crate) const TTL_MS: u64 = 30_000;

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub(crate) struct Peer {
    peer: String,
    label: String,
    ai: bool,
    slot: usize,
    cursor: Option<(f32, f32)>,
    selection: Vec<String>,
    /// The peer's visible world rect `[x, y, w, h]`.
    view: Option<[f32; 4]>,
    seen: u64,
}

#[derive(Default)]
pub(crate) struct Peers {
    by_conn: BTreeMap<u64, Peer>,
    /// The `conn` being followed.
    follow: Option<u64>,
    next_slot: usize,
    /// The last local state handed out by `local_json`, so an unchanged one is not sent again.
    sent: Option<String>,
}

fn finite(v: &[f64], lim: f64) -> bool {
    v.iter().all(|x| x.is_finite() && x.abs() <= lim)
}

fn pair(v: &Value) -> Option<[f64; 2]> {
    let a = v.as_array().filter(|a| a.len() == 2)?;
    let p = [a[0].as_f64()?, a[1].as_f64()?];
    finite(&p, MAX_COORD as f64).then_some(p)
}

fn view_of(v: &Value) -> Option<[f32; 4]> {
    let a = v.as_array().filter(|a| a.len() == 4)?;
    let r = [
        a[0].as_f64()?,
        a[1].as_f64()?,
        a[2].as_f64()?,
        a[3].as_f64()?,
    ];
    (finite(&r, MAX_COORD as f64) && r[2] > 0.0 && r[3] > 0.0).then_some([
        r[0] as f32,
        r[1] as f32,
        r[2] as f32,
        r[3] as f32,
    ])
}

fn peer_ok(p: &str) -> bool {
    p.len() <= 64
        && (p.starts_with("person:") || p.starts_with("session:"))
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-'))
}

/// Unicode format characters that reorder or hide text: bidi controls, zero-width marks, the BOM.
fn is_format(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

fn label_of(v: Option<&Value>, peer: &str) -> String {
    let l: String = v
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control() && !is_format(*c))
        .take(MAX_LABEL)
        .collect();
    let l = l.trim();
    if l.is_empty() {
        // the id's tail, never empty
        peer.rsplit(':')
            .next()
            .unwrap_or("?")
            .chars()
            .take(8)
            .collect()
    } else {
        l.to_owned()
    }
}

impl Peers {
    /// One relayed message. Anything out of bounds is refused whole (`false`), nothing partly applied.
    pub(crate) fn apply(&mut self, text: &str, now: u64) -> bool {
        if text.len() > MAX_MESSAGE {
            return false;
        }
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return false;
        };
        let Some(conn) = v.get("conn").and_then(Value::as_u64) else {
            return false;
        };
        if v.get("gone").and_then(Value::as_bool) == Some(true) {
            self.by_conn.remove(&conn);
            if self.follow == Some(conn) {
                self.follow = None;
            }
            return true;
        }
        let Some(peer) = v.get("peer").and_then(Value::as_str).filter(|p| peer_ok(p)) else {
            return false;
        };
        let cursor = match v.get("cursor") {
            None | Some(Value::Null) => None,
            Some(c) => match pair(c) {
                Some(p) => Some((p[0] as f32, p[1] as f32)),
                None => return false,
            },
        };
        let selection: Vec<String> = match v.get("selection") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => {
                let ids: Option<Vec<String>> = a
                    .iter()
                    .map(|s| s.as_str().filter(|s| is_node_id(s)).map(str::to_owned))
                    .collect();
                match ids {
                    Some(ids) if ids.len() <= MAX_SELECTION => ids,
                    _ => return false,
                }
            }
            _ => return false,
        };
        let view = match v.get("view") {
            None | Some(Value::Null) => None,
            Some(w) => match view_of(w) {
                Some(w) => Some(w),
                None => return false,
            },
        };
        self.expire(now);
        if !self.by_conn.contains_key(&conn) && self.by_conn.len() >= MAX_PEERS {
            return false;
        }
        let slot = match self.by_conn.get(&conn) {
            Some(p) => p.slot,
            None => {
                self.next_slot += 1;
                self.next_slot
            }
        };
        self.by_conn.insert(
            conn,
            Peer {
                peer: peer.to_owned(),
                label: label_of(v.get("label"), peer),
                ai: peer.starts_with("session:"),
                slot,
                cursor,
                selection,
                view,
                seen: now,
            },
        );
        true
    }

    pub(crate) fn expire(&mut self, now: u64) {
        self.by_conn
            .retain(|_, p| now.saturating_sub(p.seen) <= TTL_MS);
        if self.follow.is_some_and(|c| !self.by_conn.contains_key(&c)) {
            self.follow = None;
        }
    }

    /// Follow a peer by its Core `peer` id (empty = stop). `false` when no such peer is here.
    pub(crate) fn set_follow(&mut self, peer: &str) -> bool {
        if peer.is_empty() {
            self.follow = None;
            return true;
        }
        match self.by_conn.iter().find(|(_, p)| p.peer == peer) {
            Some((c, _)) => {
                self.follow = Some(*c);
                true
            }
            None => false,
        }
    }

    pub(crate) fn stop_follow(&mut self) {
        self.follow = None;
    }

    pub(crate) fn following(&self) -> bool {
        self.follow.is_some()
    }

    /// The followed peer's viewport, once it has sent one.
    pub(crate) fn followed_view(&self) -> Option<[f32; 4]> {
        self.by_conn.get(&self.follow?)?.view
    }

    /// `[{"peer","label","kind":"person"|"ai","following"}]`, oldest first.
    pub(crate) fn list(&mut self, now: u64) -> Vec<u8> {
        self.expire(now);
        let mut v: Vec<_> = self.by_conn.iter().collect();
        v.sort_by_key(|(_, p)| p.slot);
        let out: Vec<Value> = v
            .iter()
            .map(|(c, p)| {
                json!({"peer": p.peer, "label": p.label, "kind": if p.ai { "ai" } else { "person" },
                       "following": self.follow == Some(**c)})
            })
            .collect();
        Value::Array(out).to_string().into_bytes()
    }

    /// Markers for the overlay: `rect` gives a node's world rect (a node that is gone has none and is skipped).
    pub(crate) fn marks(&self, now: u64, rect: impl Fn(&str) -> Option<Rect>) -> Vec<PeerMark> {
        let mut v: Vec<&Peer> = self
            .by_conn
            .values()
            .filter(|p| now.saturating_sub(p.seen) <= TTL_MS)
            .collect();
        v.sort_by_key(|p| p.slot);
        v.into_iter()
            .map(|p| PeerMark {
                label: p.label.clone(),
                ai: p.ai,
                slot: p.slot,
                cursor: p.cursor,
                selected: p.selection.iter().filter_map(|id| rect(id)).collect(),
            })
            .collect()
    }

    /// This device's state to send, in the shape the Core's socket takes; `None` when it has not changed since the
    /// last one marked sent.
    pub(crate) fn local_json(
        &self,
        cursor: Option<(f32, f32)>,
        selection: &[String],
        cam: &Camera,
    ) -> Option<String> {
        let w = cam.visible();
        let s = json!({"cursor": cursor.map(|c| [c.0, c.1]),
                       "selection": selection.iter().take(MAX_SELECTION).collect::<Vec<_>>(),
                       "view": [w.left, w.top, w.width(), w.height()]})
        .to_string();
        (self.sent.as_deref() != Some(&s)).then_some(s)
    }

    pub(crate) fn mark_sent(&mut self, s: String) {
        self.sent = Some(s);
    }
}

/// The camera that shows `view` (a world rect) in a view of the same shape as `cam`'s: centred on it, zoomed to fit
/// it whole. `None` when the numbers cannot make a camera.
pub(crate) fn follow_camera(view: [f32; 4], cam: Camera) -> Option<Camera> {
    let [x, y, w, h] = view;
    let z = (cam.view.0 / w).min(cam.view.1 / h);
    if !z.is_finite() || z <= 0.0 || cam.view.0 > MAX_VIEW {
        return None;
    }
    let z = z.clamp(
        design_render::camera::MIN_ZOOM,
        design_render::camera::MAX_ZOOM,
    );
    let (cx, cy) = (x + w / 2.0, y + h / 2.0);
    let pan = (cam.view.0 / 2.0 - cx * z, cam.view.1 / 2.0 - cy * z);
    (pan.0.abs() <= MAX_COORD && pan.1.abs() <= MAX_COORD).then_some(Camera {
        zoom: z,
        pan,
        ..cam
    })
}

impl Host {
    /// A presence message relayed by the Core (see the top of this file). A refused one changes nothing.
    pub fn presence_remote(&mut self, json: &str) -> Result<(), i32> {
        if !self.peers.apply(json, now_ms()) {
            return Err(DE_ERR_INVALID);
        }
        self.follow_step();
        Ok(())
    }

    /// This device's presence for the Core's socket, or empty when nothing changed since the last call that took it.
    pub fn presence_local(&mut self, take: bool) -> Vec<u8> {
        match self
            .peers
            .local_json(self.local_cursor, &self.selection, &self.camera)
        {
            Some(s) => {
                if take {
                    self.peers.mark_sent(s.clone());
                }
                s.into_bytes()
            }
            None => vec![],
        }
    }

    pub fn presence_list(&mut self) -> Vec<u8> {
        self.peers.list(now_ms())
    }

    /// Follow a peer by its Core id (`person:d_...` / `session:as_...`); empty stops.
    pub fn follow(&mut self, peer: &str) -> Result<(), i32> {
        if peer.len() > 64 || !self.peers.set_follow(peer) {
            return Err(DE_ERR_ARG);
        }
        self.settle = None;
        self.follow_step();
        Ok(())
    }

    /// The viewer took the camera (pan, zoom, fit, a press on the canvas): following ends.
    pub(crate) fn stop_follow(&mut self) {
        self.peers.stop_follow();
    }

    /// Put the camera on the followed peer's viewport.
    fn follow_step(&mut self) {
        if let Some(c) = self
            .peers
            .followed_view()
            .and_then(|v| follow_camera(v, self.camera))
        {
            self.camera = c;
        }
    }

    /// Markers of the other peers for the overlay.
    pub(crate) fn remote_marks(&self) -> Vec<PeerMark> {
        self.peers.marks(now_ms(), |id| self.rect(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(conn: u64, peer: &str, extra: &str) -> String {
        format!(r#"{{"peer":"{peer}","conn":{conn},"label":"Ana"{extra}}}"#)
    }

    #[test]
    fn peers_come_go_expire_and_cap() {
        let mut p = Peers::default();
        assert!(p.apply(
            &msg(
                1,
                "person:d_a",
                r#","cursor":[1,2],"selection":["n_aaaaaaaaaaaa"]"#
            ),
            0
        ));
        assert!(p.apply(&msg(2, "session:as_1", ""), 0));
        let marks = p.marks(0, |_| Some(Rect::from_xywh(0.0, 0.0, 1.0, 1.0)));
        assert_eq!((marks.len(), marks[0].ai, marks[1].ai), (2, false, true));
        assert_eq!(marks[0].selected.len(), 1);
        // gone, and silent past the TTL
        assert!(p.apply(r#"{"conn":1,"gone":true}"#, 1));
        assert_eq!(p.marks(1, |_| None).len(), 1);
        assert_eq!(p.marks(TTL_MS + 1, |_| None).len(), 0);
        // the table is capped
        for c in 0..MAX_PEERS as u64 {
            assert!(p.apply(&msg(c, "person:d_a", ""), TTL_MS + 5));
        }
        assert!(!p.apply(&msg(999, "person:d_a", ""), TTL_MS + 5));
        assert!(
            p.apply(&msg(3, "person:d_b", ""), TTL_MS + 5),
            "a known conn updates"
        );
    }

    #[test]
    fn a_message_at_the_relay_limit_survives_reserialising() {
        // a relay-sized selection, as the relay re-serialises it (ids escaped, peer and conn added)
        let ids = vec![r#""n_aaaaaaaaaaaa""#; 200].join(",");
        let sent = format!(
            r#"{{"label":"Ana","selection":[{ids}],"pad":"{}"}}"#,
            "x".repeat(RELAY_INPUT - 3500)
        );
        assert!(sent.len() <= RELAY_INPUT);
        let mut v: Value = serde_json::from_str(&sent).unwrap();
        v["peer"] = json!("session:as_aaaaaaaaaaaaaaaaaaaa");
        v["conn"] = json!(18446744073709551615u64);
        let text = v.to_string();
        assert!(Peers::default().apply(&text, 0));
        assert!(MAX_MESSAGE >= 2 * RELAY_INPUT);
    }

    #[test]
    fn labels_lose_format_characters() {
        let mut p = Peers::default();
        let m = msg(1, "person:d_a", "")
            .replace("Ana", "A\\u202Eb\\u200Bc\\u2066d\\u2069e\\uFEFFf\\u200Fg");
        assert!(p.apply(&m, 0));
        assert_eq!(p.marks(0, |_| None)[0].label, "Abcdefg");
    }

    #[test]
    fn hostile_messages_are_refused_whole() {
        let mut p = Peers::default();
        for bad in [
            "not json".to_owned(),
            r#"{"conn":1}"#.to_owned(),
            r#"{"conn":"x","peer":"person:d_a"}"#.to_owned(),
            msg(1, "admin:root", ""),
            msg(1, "person:d a", ""),
            msg(1, "person:d_a", r#","cursor":[1e300,0]"#),
            msg(1, "person:d_a", r#","cursor":[1]"#),
            msg(1, "person:d_a", r#","selection":["nope"]"#),
            msg(1, "person:d_a", r#","selection":"n_aaaaaaaaaaaa""#),
            msg(1, "person:d_a", r#","view":[0,0,0,10]"#),
            msg(1, "person:d_a", r#","view":[0,0,-5,10]"#),
            "x".repeat(MAX_MESSAGE + 1),
        ] {
            assert!(!p.apply(&bad, 0), "{bad}");
        }
        let many = format!(
            "[{}]",
            vec![r#""n_aaaaaaaaaaaa""#; MAX_SELECTION + 1].join(",")
        );
        assert!(!p.apply(&msg(1, "person:d_a", &format!(r#","selection":{many}"#)), 0));
        assert_eq!(p.marks(0, |_| None).len(), 0, "nothing was partly applied");
    }

    #[test]
    fn kind_and_label_never_come_from_the_sender() {
        let mut p = Peers::default();
        // claiming `ai` in the body does nothing; the prefix decides
        let m = r#"{"peer":"person:d_a","conn":1,"kind":"ai","ai":true,"label":"  \u0007Evil name that is far too long to ever fit a chip   "}"#;
        assert!(p.apply(m, 0));
        let k = p.marks(0, |_| None);
        assert!(
            !k[0].ai && k[0].label.chars().count() <= MAX_LABEL && !k[0].label.contains('\u{7}')
        );
        // no label: the id's tail
        assert!(p.apply(r#"{"peer":"session:as_xyz","conn":2}"#, 0));
        assert_eq!(p.marks(0, |_| None)[1].label, "as_xyz");
    }

    #[test]
    fn follow_tracks_one_peer_and_stops_when_it_goes() {
        let mut p = Peers::default();
        assert!(!p.set_follow("person:d_a"), "nobody to follow yet");
        p.apply(&msg(1, "person:d_a", r#","view":[100,100,400,200]"#), 0);
        assert!(p.set_follow("person:d_a") && p.following());
        assert_eq!(p.followed_view(), Some([100.0, 100.0, 400.0, 200.0]));
        let l: Value = serde_json::from_slice(&p.list(0)).unwrap();
        assert_eq!(
            (&l[0]["following"], &l[0]["kind"]),
            (&json!(true), &json!("person"))
        );
        p.apply(r#"{"conn":1,"gone":true}"#, 1);
        assert!(!p.following());
        assert!(p.set_follow(""));
    }

    #[test]
    fn follow_camera_centres_and_fits_the_peers_view() {
        let cam = Camera {
            view: (800.0, 400.0),
            ..Camera::default()
        };
        let c = follow_camera([100.0, 100.0, 400.0, 200.0], cam).unwrap();
        assert!((c.zoom - 2.0).abs() < 1e-4);
        let (sx, sy) = c.to_screen(300.0, 200.0);
        assert!(
            (sx - 400.0).abs() < 1e-3 && (sy - 200.0).abs() < 1e-3,
            "the peer's centre is the view's centre"
        );
        assert!(follow_camera([0.0, 0.0, 0.0, 10.0], cam).is_none());
    }

    #[test]
    fn local_state_is_sent_only_when_it_changed() {
        let mut p = Peers::default();
        let cam = Camera::default();
        let s = p.local_json(Some((1.0, 2.0)), &[], &cam).unwrap();
        p.mark_sent(s);
        assert!(p.local_json(Some((1.0, 2.0)), &[], &cam).is_none());
        assert!(p.local_json(Some((3.0, 2.0)), &[], &cam).is_some());
    }
}
