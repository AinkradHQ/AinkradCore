//! T-RUN-3/T-RUN-7: the runner v2 frame decoder, the first parse of anything a runner sends.
#![no_main]
use ainkrad_proto::v2::Frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = serde_json::from_slice::<Frame>(data) else {
        return;
    };
    // The typed payload is a second stage: it may refuse, never panic.
    if let Ok(Some(body)) = frame.body() {
        // What decodes re-encodes into a frame that decodes to the same body.
        let again = Frame::new(frame.stream_id, frame.seq, body.clone());
        assert_eq!(again.body().ok().flatten(), Some(body));
    }
});
