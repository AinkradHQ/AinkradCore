//! The parsers on each wire's real shapes (field names from the providers' API references), in
//! pieces cut at awkward places.

use super::*;

fn sse(wire: Wire, text: &str, cut: usize) -> Scan {
    let mut s = Scan::new(wire, Some("text/event-stream; charset=utf-8"));
    for piece in text.as_bytes().chunks(cut) {
        s.feed(piece);
    }
    s.finish();
    s
}

fn json(wire: Wire, text: &str) -> Scan {
    let mut s = Scan::new(wire, Some("application/json"));
    for piece in text.as_bytes().chunks(7) {
        s.feed(piece);
    }
    s.finish();
    s
}

const ANTHROPIC_SSE: &str = "event: message_start\r\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"usage\":{\"input_tokens\":25,\"cache_creation_input_tokens\":7,\"cache_read_input_tokens\":100,\"output_tokens\":1}}}\r\n\r\n\
event: content_block_delta\r\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello there\"}}\r\n\r\n\
event: message_delta\r\n\
data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\r\n\r\n\
event: message_stop\r\n\
data: {\"type\":\"message_stop\"}\r\n\r\n";

#[test]
fn anthropic_streams_and_bodies_read_the_same_whichever_way_they_are_cut() {
    for cut in [1, 3, 17, 64, 4096] {
        let s = sse(Wire::AnthropicMessages, ANTHROPIC_SSE, cut);
        assert_eq!(
            s.reported(),
            Some(Usage {
                input: 25,
                output: 15,
                cache_read: 100,
                cache_write: 7
            }),
            "cut {cut}"
        );
        assert!(!s.overflowed());
        assert_eq!(
            s.exact().map(|u| u.output),
            Some(15),
            "closed by message_stop"
        );
        assert_eq!(s.chars, "Hello there".len() as u64);
    }
    let body = r#"{"id":"m","type":"message","usage":{"input_tokens":9,"output_tokens":4,"cache_read_input_tokens":0}}"#;
    let s = json(Wire::AnthropicMessages, body);
    assert_eq!(
        s.reported(),
        Some(Usage {
            input: 9,
            output: 4,
            ..Usage::default()
        })
    );
}

#[test]
fn openai_input_excludes_what_the_cache_served() {
    let done = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"abcd\"}\n\n\
data: {\"type\":\"response.output_text.done\",\"text\":\"abcd\"}\n\n\
data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"content\":[{\"text\":\"abcd\"}]}],\"usage\":{\"input_tokens\":120,\"input_tokens_details\":{\"cached_tokens\":100},\"output_tokens\":30,\"output_tokens_details\":{\"reasoning_tokens\":10}}}}\n\n\
data: [DONE]\n\n";
    let s = sse(Wire::OpenaiResponses, done, 5);
    assert_eq!(
        s.reported(),
        Some(Usage {
            input: 20,
            output: 30,
            cache_read: 100,
            cache_write: 0
        })
    );
    // The restated text of `.done` and `completed` is not counted again.
    assert_eq!(s.chars, 4);
    let chat = r#"{"choices":[],"usage":{"prompt_tokens":50,"completion_tokens":8,"prompt_tokens_details":{"cached_tokens":10}}}"#;
    assert_eq!(
        json(Wire::OpenaiResponses, chat).reported(),
        Some(Usage {
            input: 40,
            output: 8,
            cache_read: 10,
            cache_write: 0
        })
    );
}

#[test]
fn gemini_counts_are_cumulative_so_the_largest_wins_and_thoughts_are_output() {
    let stream = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ab\"}]}}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":2,\"cachedContentTokenCount\":4}}\n\n\
data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"cd\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":5,\"thoughtsTokenCount\":3,\"cachedContentTokenCount\":4}}\n\n";
    let s = sse(Wire::GeminiGenerate, stream, 11);
    assert_eq!(
        s.reported(),
        Some(Usage {
            input: 6,
            output: 8,
            cache_read: 4,
            cache_write: 0
        })
    );
    assert_eq!(s.chars, 4);
    // Without `alt=sse` a stream is one JSON array of chunks.
    let array = r#"[{"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":1}},{"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":6}}]"#;
    assert_eq!(
        json(Wire::GeminiGenerate, array).reported(),
        Some(Usage {
            input: 3,
            output: 6,
            ..Usage::default()
        })
    );
}

#[test]
fn a_reply_with_no_usage_is_estimated_and_a_partial_one_keeps_what_it_reported() {
    // Nothing reported: the output is the streamed characters / 4, the input is the floor given.
    let s = sse(
        Wire::AnthropicMessages,
        "data: {\"delta\":{\"text\":\"12345678901\"}}\n\n",
        4,
    );
    assert_eq!(s.reported(), None);
    assert_eq!(s.running(77).input, 77);
    assert_eq!(s.running(77).output, 3);
    // Cut after `message_start` (no final event): the reported input stays, the output is the
    // larger of the report and the estimate.
    let cut = &ANTHROPIC_SSE[..ANTHROPIC_SSE.find("event: message_delta").unwrap()];
    let s = sse(Wire::AnthropicMessages, cut, 9);
    let u = s.running(1);
    assert_eq!((u.input, u.cache_read, u.cache_write), (25, 100, 7));
    assert_eq!(
        u.output, 3,
        "11 chars of text is 3 tokens, over the reported 1"
    );
}

#[test]
fn junk_and_oversized_input_never_panics_and_marks_the_scan_inexact() {
    for junk in [
        "",
        "data: {",
        "data: [1,2",
        "\n\n\n",
        "data:",
        ": comment\n\n",
    ] {
        let s = sse(Wire::OpenaiResponses, junk, 2);
        assert_eq!(s.reported(), None, "{junk:?}");
    }
    let mut s = Scan::new(Wire::AnthropicMessages, Some("text/event-stream"));
    let long = vec![b'x'; MAX_LINE + 10];
    s.feed(b"data: ");
    s.feed(&long);
    s.feed(b"\n\ndata: {\"usage\":{\"output_tokens\":3}}\n\n");
    s.finish();
    assert!(s.overflowed());
    // The line after the long one is still read.
    assert_eq!(s.reported().map(|u| u.output), Some(3));
    let mut s = Scan::new(Wire::AnthropicMessages, None);
    s.feed(&vec![b' '; MAX_BODY + 1]);
    s.finish();
    assert!(s.overflowed());
    assert_eq!(s.reported(), None);
}

const RESPONSES_STREAM: &str = "event: response.created\n\
data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"status\":\"in_progress\",\"usage\":null}}\n\n\
event: response.in_progress\n\
data: {\"type\":\"response.in_progress\",\"response\":{\"id\":\"r\",\"usage\":null}}\n\n\
event: response.output_text.delta\n\
data: {\"type\":\"response.output_text.delta\",\"delta\":\"twelve chars\"}\n\n\
event: response.completed\n\
data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"usage\":{\"input_tokens\":200,\"input_tokens_details\":{\"cached_tokens\":50},\"output_tokens\":9}}}\n\n";

#[test]
fn a_null_usage_is_not_a_report_so_a_responses_stream_cut_before_completion_reports_nothing() {
    let whole = sse(Wire::OpenaiResponses, RESPONSES_STREAM, 13);
    assert_eq!(
        whole.exact(),
        Some(Usage {
            input: 150,
            output: 9,
            cache_read: 50,
            cache_write: 0
        })
    );
    // Cut after the deltas, before `response.completed`: `usage: null` was all it said.
    let cut = &RESPONSES_STREAM[..RESPONSES_STREAM.find("event: response.completed").unwrap()];
    let s = sse(Wire::OpenaiResponses, cut, 13);
    assert_eq!(s.reported(), None, "a null usage counted as a report");
    assert_eq!(s.exact(), None);
    let running = s.running(321);
    assert_eq!(
        (running.input, running.output),
        (321, 3),
        "the input floor, the text / 4"
    );
}

#[test]
fn chat_chunks_with_include_usage_report_only_in_the_last_one() {
    let chunks = "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}],\"usage\":null}\n\n\
data: {\"choices\":[{\"delta\":{\"content\":\"hello there!\"}}],\"usage\":null}\n\n\
data: {\"choices\":[],\"usage\":{\"prompt_tokens\":30,\"completion_tokens\":6,\"prompt_tokens_details\":{\"cached_tokens\":10}}}\n\n\
data: [DONE]\n\n";
    let s = sse(Wire::OpenaiResponses, chunks, 7);
    assert_eq!(
        s.exact(),
        Some(Usage {
            input: 20,
            output: 6,
            cache_read: 10,
            cache_write: 0
        })
    );
    let cut = &chunks[..chunks.find("data: {\"choices\":[],").unwrap()];
    let s = sse(Wire::OpenaiResponses, cut, 7);
    assert_eq!(s.reported(), None);
    assert_eq!(s.running(40).input, 40);
}

#[test]
fn a_report_with_no_input_is_partial_and_the_floor_stands_in() {
    // Gemini metadata before the counts are in; Anthropic's delta before a start was read.
    let gemini = "data: {\"candidates\":[],\"usageMetadata\":{\"trafficType\":\"ON_DEMAND\"}}\n\n";
    let s = sse(Wire::GeminiGenerate, gemini, 5);
    assert!(s.reported().is_some(), "an object is a report");
    assert_eq!(s.exact(), None, "but with no input it is not the count");
    assert_eq!(s.running(77).input, 77);
    let delta = "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":4}}\n\n";
    let s = sse(Wire::AnthropicMessages, delta, 5);
    assert_eq!(s.exact(), None);
    let u = s.running(55);
    assert_eq!((u.input, u.output), (55, 4));
    // A non-object usage of any kind is no report, on any wire.
    for (wire, line) in [
        (Wire::AnthropicMessages, "data: {\"usage\":null}\n\n"),
        (
            Wire::AnthropicMessages,
            "data: {\"message\":{\"usage\":[]}}\n\n",
        ),
        (
            Wire::OpenaiResponses,
            "data: {\"response\":{\"usage\":\"x\"}}\n\n",
        ),
        (Wire::GeminiGenerate, "data: {\"usageMetadata\":null}\n\n"),
    ] {
        assert_eq!(sse(wire, line, 3).reported(), None, "{line}");
    }
}

#[test]
fn usage_is_exact_only_after_the_closing_event() {
    // Anthropic: a start, some output, an `error` event, and a clean close: not a finished reply.
    let errored = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":9,\"output_tokens\":1}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"0123456789012345678901234567890123456789\"}}\n\n\
event: error\n\
data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n";
    let s = sse(Wire::AnthropicMessages, errored, 6);
    assert!(s.reported().is_some());
    assert_eq!(s.exact(), None, "no message_stop: not exact");
    let u = s.running(1);
    assert_eq!(
        (u.input, u.output),
        (9, 10),
        "the reported input, the larger output"
    );
    // The same, closed: exact.
    let closed = format!("{errored}event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n");
    assert!(sse(Wire::AnthropicMessages, &closed, 6).exact().is_some());
    // OpenAI Responses without `response.completed`, chat without `[DONE]`.
    let partial = RESPONSES_STREAM.replace("response.completed", "response.something");
    assert_eq!(sse(Wire::OpenaiResponses, &partial, 9).exact(), None);
    let chat = "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n";
    assert_eq!(sse(Wire::OpenaiResponses, chat, 9).exact(), None);
    assert!(
        sse(Wire::OpenaiResponses, &format!("{chat}data: [DONE]\n\n"), 9)
            .exact()
            .is_some()
    );
    // Gemini: a chunk with usage but no finishReason is not the last.
    let g = "data: {\"candidates\":[{\"content\":{}}],\"usageMetadata\":{\"promptTokenCount\":4,\"candidatesTokenCount\":1}}\n\n";
    assert_eq!(sse(Wire::GeminiGenerate, g, 9).exact(), None);
}
