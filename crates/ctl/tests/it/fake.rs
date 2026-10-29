//! A fake Core on a Unix socket, for what the real one cannot be made to do (serve another
//! identity, answer past retention): it answers from a table and records every request, so a
//! test can prove what ctl did *not* send.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use ainkrad_ctl::proto::{Key, b64, fp, unb64};

/// `answer(method, path, body)`.
pub type Answer = fn(&str, &str, &str) -> (u16, String);

/// `fp` of the throwaway TEST Core key of the committed vectors (`handshake-v1.json`): the fake
/// Core's identity, so it can prove it on `POST /handshake`.
pub const PINNED: &str = "EpGb6nSf7oTkVNn4nFAi3_4oofCpfpiRXxLVfDw8FQM";

/// The TEST Core key whose fingerprint is `PINNED`.
pub fn test_core() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(|| {
        let path = format!(
            "{}/../server/tests/vectors/handshake-v1.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let key = Key::from_pkcs8(&unb64(v["core_pkcs8"].as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(fp(&key.spki()), PINNED);
        key
    })
}

/// `POST /handshake`'s 200 from `key`: its SPKI and its signature over the request's nonce, for
/// a Core on a Unix socket (Host `localhost`), as spec §4 has it.
pub fn proof(key: &Key, body: &str) -> (u16, String) {
    let v: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let nonce = v["nonce"].as_str().unwrap_or_default();
    let sig = key.sign(format!("AINKRAD-CORE-V1\nlocalhost\n{nonce}").as_bytes());
    let spki = key.spki();
    let answer = serde_json::json!({
        "server_version": "0.1.0",
        "api_minor": 11,
        "identity_fingerprint": fp(&spki),
        "core_spki": b64(&spki),
        "core_sig": b64(&sig),
    });
    (200, answer.to_string())
}

pub struct Fake {
    pub sock: PathBuf,
    /// Each request's head (request line and headers, lower-cased) and body.
    pub seen: Arc<Mutex<Vec<String>>>,
}

impl Fake {
    /// Serves `answer(method, path)` on `sock` until the test ends.
    pub fn start(sock: PathBuf, answer: Answer) -> Self {
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { break };
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line.to_ascii_lowercase());
                }
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .and_then(|n| n.trim().parse().ok())
                    .unwrap_or(0);
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let mut words = head.split_whitespace();
                let (method, target) = (
                    words.next().unwrap_or("").to_uppercase(),
                    words.next().unwrap_or("").to_owned(),
                );
                let path = target.split('?').next().unwrap_or("").to_owned();
                log.lock()
                    .unwrap()
                    .push(format!("{head}{}", String::from_utf8_lossy(&body)));
                let (status, text) = answer(&method, &path, &String::from_utf8_lossy(&body));
                let _ = write!(
                    conn,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        Self { sock, seen }
    }

    pub fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}
