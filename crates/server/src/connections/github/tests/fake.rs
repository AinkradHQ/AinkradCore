//! A scripted HTTP/1.1 server on loopback: it answers each request with the next canned reply
//! and records what it was sent.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::connections::github::Transport;

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// Lower-cased names.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        let h = self.headers.iter().find(|(n, _)| n == name);
        h.map(|(_, v)| v.as_str())
    }
}

struct Canned {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Clone)]
pub struct Fake {
    pub base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    script: Arc<Mutex<VecDeque<Canned>>>,
}

impl Fake {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let fake = Self {
            base,
            seen: Arc::default(),
            script: Arc::default(),
        };
        let me = fake.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let me = me.clone();
                tokio::spawn(async move {
                    let _ = me.serve(sock).await;
                });
            }
        });
        fake
    }

    pub fn transport(&self) -> Transport {
        Transport::local(&self.base)
    }

    pub fn push(&self, status: u16, headers: &[(&str, &str)], body: &str) {
        self.push_bytes(status, headers, body.as_bytes().to_vec());
    }

    pub fn push_bytes(&self, status: u16, headers: &[(&str, &str)], body: Vec<u8>) {
        let headers = headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        let c = Canned {
            status,
            headers,
            body,
        };
        self.script.lock().unwrap().push_back(c);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    async fn serve(&self, mut sock: tokio::net::TcpStream) -> std::io::Result<()> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap_or("").split(' ');
        let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let len = headers
            .iter()
            .find(|(n, _)| n == "content-length")
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(0);
        while buf.len() < end + 4 + len {
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&buf[end + 4..]).into_owned();
        self.seen.lock().unwrap().push(Seen {
            method: method.to_owned(),
            path: path.to_owned(),
            headers,
            body,
        });
        let canned = self.script.lock().unwrap().pop_front();
        let c = canned.unwrap_or(Canned {
            status: 599,
            headers: vec![],
            body: b"no script".to_vec(),
        });
        let mut out = format!("HTTP/1.1 {} X\r\n", c.status);
        for (n, v) in &c.headers {
            out.push_str(&format!("{n}: {v}\r\n"));
        }
        out.push_str(&format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            c.body.len()
        ));
        sock.write_all(out.as_bytes()).await?;
        sock.write_all(&c.body).await?;
        sock.shutdown().await
    }
}
