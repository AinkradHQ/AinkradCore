//! A fake Core on a Unix socket, for what the real one cannot be made to do (serve another
//! identity, answer past retention): it answers from a table and records every request, so a
//! test can prove what ctl did *not* send.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type Answer = fn(&str, &str) -> (u16, String);

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
                let (status, text) = answer(&method, &path);
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
