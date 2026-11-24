use bytes::{Bytes, BytesMut};
use serde_json::{Value, json};
use ttt_core::{GatewayError, ProtocolFamily};

pub(crate) fn sse_data_bytes(val: &Value) -> Bytes {
    Bytes::from(format!("data: {val}\n\n"))
}

pub(crate) fn sse_event_bytes(event: &str, val: &Value) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {val}\n\n"))
}

/// Deliver a completed JSON reply to a client that requested streaming.
pub fn json_response_to_sse(
    protocol: ProtocolFamily,
    json_bytes: &[u8],
) -> Result<Bytes, GatewayError> {
    let mut response: Value = serde_json::from_slice(json_bytes).map_err(|err| {
        GatewayError::Internal(format!("invalid translated JSON response: {err}"))
    })?;
    let mut body = BytesMut::new();
    match protocol {
        ProtocolFamily::OpenAi => {
            let usage = response
                .as_object_mut()
                .and_then(|response| response.remove("usage"));
            let mut final_choices = Vec::new();
            if let Some(choices) = response["choices"].as_array_mut() {
                for (i, choice) in choices.iter_mut().enumerate() {
                    let mut message = std::mem::take(&mut choice["message"]);
                    if let Some(calls) = message.get_mut("tool_calls").and_then(Value::as_array_mut)
                    {
                        for (index, call) in calls.iter_mut().enumerate() {
                            call["index"] = json!(index);
                        }
                    }
                    let index = choice["index"].as_u64().unwrap_or(i as u64);
                    final_choices.push(json!({
                        "index": index, "delta": {}, "finish_reason": choice["finish_reason"],
                    }));
                    *choice = json!({"index": index, "delta": message, "finish_reason": null});
                }
            }
            response["object"] = json!("chat.completion.chunk");
            body.extend_from_slice(&sse_data_bytes(&response));
            response["choices"] = json!(final_choices);
            if let Some(usage) = usage {
                response["usage"] = usage;
            }
            body.extend_from_slice(&sse_data_bytes(&response));
            body.extend_from_slice(b"data: [DONE]\n\n");
        }
        ProtocolFamily::Anthropic => {
            let content = std::mem::replace(&mut response["content"], json!([]));
            let stop_reason = std::mem::take(&mut response["stop_reason"]);
            let stop_sequence = std::mem::take(&mut response["stop_sequence"]);
            let output_tokens = response
                .pointer("/usage/output_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            response["usage"]["output_tokens"] = json!(0);
            body.extend_from_slice(&sse_event_bytes(
                "message_start",
                &json!({
                    "type": "message_start", "message": response,
                }),
            ));
            if let Value::Array(blocks) = content {
                for (index, mut block) in blocks.into_iter().enumerate() {
                    let delta = match block["type"].as_str() {
                        Some("text") => Some(json!({
                            "type": "text_delta", "text": std::mem::replace(&mut block["text"], json!("")),
                        })),
                        Some("tool_use") => Some(json!({
                            "type": "input_json_delta",
                            "partial_json": std::mem::replace(&mut block["input"], json!({})).to_string(),
                        })),
                        _ => None,
                    };
                    body.extend_from_slice(&sse_event_bytes(
                        "content_block_start",
                        &json!({
                            "type": "content_block_start", "index": index, "content_block": block,
                        }),
                    ));
                    if let Some(delta) = delta {
                        body.extend_from_slice(&sse_event_bytes(
                            "content_block_delta",
                            &json!({
                                "type": "content_block_delta", "index": index, "delta": delta,
                            }),
                        ));
                    }
                    body.extend_from_slice(&sse_event_bytes(
                        "content_block_stop",
                        &json!({
                            "type": "content_block_stop", "index": index,
                        }),
                    ));
                }
            }
            body.extend_from_slice(&sse_event_bytes("message_delta", &json!({
                "type": "message_delta", "delta": { "stop_reason": stop_reason, "stop_sequence": stop_sequence },
                "usage": { "output_tokens": output_tokens },
            })));
            body.extend_from_slice(&sse_event_bytes(
                "message_stop",
                &json!({ "type": "message_stop" }),
            ));
        }
        _ => {
            return Err(GatewayError::Internal(format!(
                "unsupported SSE response protocol: {protocol:?}"
            )));
        }
    }
    Ok(body.freeze())
}

#[derive(Default)]
pub(crate) struct SseDecoder {
    line: Vec<u8>,
    event: Vec<u8>,
    data: Vec<u8>,
    seen_line: bool,
    skip_lf: bool,
}

impl SseDecoder {
    pub(crate) fn push(&mut self, mut bytes: &[u8], mut dispatch: impl FnMut(&str, &str)) {
        while !bytes.is_empty() {
            if std::mem::take(&mut self.skip_lf) && bytes[0] == b'\n' {
                bytes = &bytes[1..];
            }
            let Some(pos) = memchr::memchr2(b'\r', b'\n', bytes) else {
                self.line.extend_from_slice(bytes);
                break;
            };
            self.skip_lf = bytes[pos] == b'\r';
            if self.line.is_empty() {
                self.on_line(&bytes[..pos], &mut dispatch);
            } else {
                let mut line = std::mem::take(&mut self.line);
                line.extend_from_slice(&bytes[..pos]);
                self.on_line(&line, &mut dispatch);
                line.clear();
                self.line = line;
            }
            bytes = &bytes[pos + 1..];
        }
    }

    fn on_line(&mut self, mut line: &[u8], dispatch: &mut impl FnMut(&str, &str)) {
        if !std::mem::replace(&mut self.seen_line, true) {
            line = line.strip_prefix(b"\xef\xbb\xbf").unwrap_or(line);
        }
        if line.is_empty() {
            if let Some(data) = self.data.strip_suffix(b"\n") {
                dispatch(
                    &String::from_utf8_lossy(&self.event),
                    &String::from_utf8_lossy(data),
                );
                self.data.clear();
            }
            self.event.clear();
            return;
        }

        let (field, value) = match memchr::memchr(b':', line) {
            Some(pos) => (&line[..pos], &line[pos + 1..]),
            None => (line, &[][..]),
        };
        let value = value.strip_prefix(b" ").unwrap_or(value);
        match field {
            b"data" => {
                self.data.extend_from_slice(value);
                self.data.push(b'\n');
            }
            b"event" => {
                self.event.clear();
                self.event.extend_from_slice(value);
            }
            _ => {}
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeSseState {
    Open,
    Complete,
    ReportedIncomplete,
    Error,
    Unchecked,
}

/// Observe native SSE event boundaries without changing the forwarded payload.
pub struct NativeSse {
    protocol: ProtocolFamily,
    decoder: SseDecoder,
    state: NativeSseState,
}

impl NativeSse {
    pub fn new(protocol: ProtocolFamily) -> Option<Self> {
        matches!(
            protocol,
            ProtocolFamily::OpenAi | ProtocolFamily::OpenAiResponses | ProtocolFamily::Anthropic
        )
        .then(|| Self {
            protocol,
            decoder: SseDecoder::default(),
            state: NativeSseState::Open,
        })
    }

    pub fn push(&mut self, bytes: &[u8]) {
        let Self {
            protocol,
            decoder,
            state,
        } = self;
        if matches!(*state, NativeSseState::Error | NativeSseState::Unchecked) {
            return;
        }
        // Keep validation memory bounded even if an upstream never ends its SSE event.
        for chunk in bytes.chunks(8192) {
            decoder.push(chunk, |event, data| {
                if *state == NativeSseState::Error {
                    return;
                }
                if event == "error" || has_error_payload(data) {
                    *state = NativeSseState::Error;
                } else if let Some(terminal) = native_terminal(*protocol, event, data) {
                    *state = terminal;
                }
            });
            if decoder.line.len() + decoder.data.len() + decoder.event.len() > 1024 * 1024 {
                if *state == NativeSseState::Open {
                    *state = NativeSseState::Unchecked;
                }
                *decoder = SseDecoder::default();
                break;
            }
        }
    }

    pub fn is_open(&self) -> bool {
        self.state == NativeSseState::Open
    }

    pub fn is_incomplete(&self) -> bool {
        matches!(
            self.state,
            NativeSseState::Open | NativeSseState::ReportedIncomplete
        )
    }

    pub fn has_error(&self) -> bool {
        self.state == NativeSseState::Error
    }

    pub fn incomplete_event(&self) -> Bytes {
        match self.protocol {
            ProtocolFamily::OpenAiResponses => Bytes::from_static(
                b"\n\nevent: error\ndata: {\"type\":\"error\",\"code\":\"upstream_stream_incomplete\",\"message\":\"Upstream Responses stream ended before a terminal response event\",\"param\":null}\n\n",
            ),
            ProtocolFamily::Anthropic => Bytes::from_static(
                b"\n\nevent: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"Upstream stream ended without message_stop\"}}\n\n",
            ),
            _ => Bytes::from_static(
                b"\n\ndata: {\"error\":{\"type\":\"upstream_error\",\"code\":\"upstream_stream_incomplete\",\"message\":\"Upstream stream ended without [DONE]\"}}\n\n",
            ),
        }
    }
}

fn native_terminal(protocol: ProtocolFamily, event: &str, data: &str) -> Option<NativeSseState> {
    let has_type = |name: &str| {
        event == name
            || (event.is_empty()
                && memchr::memmem::find(data.as_bytes(), name.as_bytes()).is_some()
                && serde_json::from_str::<Value>(data).is_ok_and(|value| value["type"] == name))
    };
    match protocol {
        ProtocolFamily::OpenAi if data.trim() == "[DONE]" => Some(NativeSseState::Complete),
        ProtocolFamily::Anthropic if has_type("message_stop") => Some(NativeSseState::Complete),
        ProtocolFamily::OpenAiResponses
            if has_type("response.completed") || has_type("response.done") =>
        {
            Some(NativeSseState::Complete)
        }
        ProtocolFamily::OpenAiResponses if has_type("response.incomplete") => {
            Some(NativeSseState::ReportedIncomplete)
        }
        ProtocolFamily::OpenAiResponses if has_type("response.failed") => {
            Some(NativeSseState::Error)
        }
        _ => None,
    }
}

fn has_error_payload(data: &str) -> bool {
    memchr::memmem::find(data.as_bytes(), b"\"error\"").is_some()
        && serde_json::from_str::<Value>(data).is_ok_and(|value| {
            value.get("error").is_some_and(|error| !error.is_null()) || value["type"] == "error"
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_streams_require_complete_terminal_events_across_frames() {
        for (protocol, terminal) in [
            (ProtocolFamily::OpenAi, "data: [DONE]\r\n\r\n"),
            (
                ProtocolFamily::OpenAiResponses,
                "event: response.completed\r\ndata: {\"type\":\"response.completed\"}\r\n\r\n",
            ),
            (
                ProtocolFamily::Anthropic,
                "event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n",
            ),
        ] {
            let mut sse = NativeSse::new(protocol).unwrap();
            sse.push(b"data: {\"text\":\"partial\"}\n\n");
            assert!(sse.is_incomplete());
            for byte in terminal.as_bytes().chunks(1) {
                sse.push(byte);
            }
            assert!(!sse.is_incomplete());
            assert!(!sse.has_error());
            sse.push(b"data: {\"error\":{\"message\":\"provider error\"}}\n\n");
            assert!(sse.has_error());
        }
    }

    #[test]
    fn responses_distinguishes_provider_failure_and_reported_incomplete_events() {
        let mut sse = NativeSse::new(ProtocolFamily::OpenAiResponses).unwrap();
        sse.push(b"data: {\"type\":\"response.incomplete\"}\n\n");
        assert!(sse.is_incomplete());
        assert!(!sse.is_open());
        assert!(!sse.has_error());

        let mut sse = NativeSse::new(ProtocolFamily::OpenAiResponses).unwrap();
        sse.push(b"event: response.failed\ndata: {\"type\":\"response.failed\"}\n\n");
        assert!(sse.has_error());
        assert!(!sse.is_open());

        let mut sse = NativeSse::new(ProtocolFamily::OpenAiResponses).unwrap();
        sse.push(b"data: {\"type\":\"response.done\"}\n\n");
        assert!(!sse.is_incomplete());
        assert!(!sse.has_error());
    }

    #[test]
    fn decodes_multiline_events_across_utf8_and_crlf_boundaries() {
        let wire = "\u{feff}:ping\r\nevent: delta\r\ndata: {\"text\":\r\ndata: \"中文🙂\"}\r\n\r\n\
                    data: second\r\rdata: incomplete";
        let mut decoder = SseDecoder::default();
        let mut events = Vec::new();
        for byte in wire.as_bytes().chunks(1) {
            decoder.push(byte, |event, payload| {
                events.push((event.to_owned(), payload.to_owned()))
            });
        }
        assert_eq!(
            events,
            [
                ("delta".into(), "{\"text\":\n\"中文🙂\"}".into()),
                ("".into(), "second".into())
            ]
        );
    }

    #[test]
    fn encodes_json_fallback_with_text_tools_and_termination() {
        let chat = br#"{"id":"chat_1","choices":[{"index":0,"message":{"role":"assistant","content":"answer","tool_calls":[{"id":"f0","type":"function","function":{"name":"lookup","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"total_tokens":4}}"#;
        let bytes = json_response_to_sse(ProtocolFamily::OpenAi, chat).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(r#""content":"answer""#));
        assert!(text.contains(r#""id":"f0","index":0"#));
        assert!(text.contains(r#""finish_reason":"tool_calls""#));
        assert!(text.ends_with("data: [DONE]\n\n"));

        let anthropic = br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"answer"},{"type":"tool_use","id":"f0","name":"lookup","input":{"foo":3}}],"stop_reason":"tool_use","usage":{"input_tokens":4,"output_tokens":3}}"#;
        let bytes = json_response_to_sse(ProtocolFamily::Anthropic, anthropic).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains(r#""text":"answer""#));
        assert!(text.contains(r#""type":"input_json_delta""#));
        assert!(text.contains(r#""stop_reason":"tool_use""#));
        assert!(text.ends_with("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"));
    }
}
