//! A cuttable TCP proxy between a real runner and a real Core (E1-14.4): `hold` stops delivering
//! the Core's bytes to the runner (a command stays in flight), `cut` drops every open connection
//! both ways at once (later ones go through).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Proxy {
    pub port: u16,
    hold: Arc<AtomicBool>,
    open: Arc<Mutex<Vec<TcpStream>>>,
}

fn pump(mut from: TcpStream, mut to: TcpStream, hold: Option<Arc<AtomicBool>>) {
    let mut buf = [0u8; 16 * 1024];
    while let Ok(n) = from.read(&mut buf) {
        if n == 0 {
            break;
        }
        while hold.as_ref().is_some_and(|h| h.load(Ordering::SeqCst)) {
            std::thread::sleep(Duration::from_millis(10));
        }
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Both);
    let _ = from.shutdown(Shutdown::Both);
}

impl Proxy {
    /// Listens on `port` and forwards to `127.0.0.1:upstream`.
    pub fn start(port: u16, upstream: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let hold = Arc::new(AtomicBool::new(false));
        let open: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
        let (h, o) = (Arc::clone(&hold), Arc::clone(&open));
        std::thread::spawn(move || {
            for down in listener.incoming() {
                let Ok(down) = down else { break };
                let Ok(up) = TcpStream::connect(("127.0.0.1", upstream)) else {
                    continue;
                };
                {
                    let mut open = o.lock().unwrap();
                    open.push(down.try_clone().unwrap());
                    open.push(up.try_clone().unwrap());
                }
                let (d2, u2) = (down.try_clone().unwrap(), up.try_clone().unwrap());
                std::thread::spawn(move || pump(down, up, None));
                let h = Arc::clone(&h);
                std::thread::spawn(move || pump(u2, d2, Some(h)));
            }
        });
        Self { port, hold, open }
    }

    pub fn hold(&self, on: bool) {
        self.hold.store(on, Ordering::SeqCst);
    }

    /// Drops every open connection; how many sockets it closed.
    pub fn cut(&self) -> usize {
        let open: Vec<TcpStream> = self.open.lock().unwrap().drain(..).collect();
        for s in &open {
            let _ = s.shutdown(Shutdown::Both);
        }
        open.len()
    }
}
