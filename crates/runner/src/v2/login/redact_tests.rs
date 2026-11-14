//! KAN-441 L2: the token and the code in no log line, error or Debug.

use std::sync::{Arc, Mutex};

use ainkrad_proto::v2::LoginUrl;

use super::tests::{CODE, TOKEN, Tmp, URL, code, done, driver, good, start};

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = Sink;
    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

#[tokio::test]
async fn the_token_and_the_code_are_in_no_log_error_or_debug() {
    let sink = Sink::default();
    // With one live dispatcher, tracing-core caches each callsite's interest from whichever
    // thread hits it first; a parallel test with no subscriber would cache `never` and drop our
    // lines. A second registered dispatcher makes the cache ask every live one instead.
    let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let _g = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(sink.clone())
            .finish(),
    );
    let mut shown = Vec::new();
    // A failing sign-in whose child echoes the code and a token back in its last words.
    let t = Tmp::new();
    let body = format!(
        "printf '{URL}\\r\\ncode: '\nread -r c\nprintf \"bad code: $c key sk-ant-api03-LEAKLEAKLEAK\\r\\n\"\nexit 1"
    );
    let d = driver(&t, &body);
    d.start(start("l_1")).await.unwrap();
    let r = done(&d, "l_1", CODE).await;
    shown.push(format!("{r:?}"));
    shown.push(r.error.clone().unwrap());
    assert!(r.error.as_deref().unwrap().contains("exited with code 1"));
    // A good one, with the token only in its result.
    let t = Tmp::new();
    let d = driver(&t, &good("code: "));
    d.start(start("l_2")).await.unwrap();
    let r = done(&d, "l_2", CODE).await;
    assert!(r.token.is_some());
    shown.push(format!("{r:?} {:?}", code("l_2", CODE)));
    shown.push(format!("{:?}", start("l_2")));
    shown.push(format!(
        "{:?}",
        LoginUrl {
            login_id: "l".into(),
            url: URL.into()
        }
    ));
    shown.push(String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned());
    for s in shown {
        assert!(
            !s.contains(TOKEN) && !s.contains(CODE) && !s.contains("sk-ant-"),
            "{s}"
        );
    }
}
