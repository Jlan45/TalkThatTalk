use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use serde_json::{json, Value};

use crate::openai_anthropic::{map_anthropic_stop_reason, map_openai_finish_reason};
use crate::openai_gemini::{extract_gemini_text, map_gemini_finish_reason};

/// Static-dispatch incremental SSE protocol state machine.
pub enum SseTranslator {
    AnthropicToOpenAi {
        model: String,
        msg_id: String,
        input_tokens: u64,
        sent_role: bool,
        sent_done: bool,
    },
    GeminiToOpenAi {
        model: String,
        sent_role: bool,
        sent_done: bool,
    },
    OpenAiToAnthropic {
        model: String,
        msg_id: String,
        started: bool,
        finished: bool,
        last_finish_reason: Option<String>,
        output_tokens: u64,
    },
    ResponsesToOpenAi {
        model: String,
        resp_id: String,
        sent_role: bool,
        sent_done: bool,
        tool_call_index: usize,
        has_tool_calls: bool,
    },
    ResponsesToAnthropic {
        model: String,
        msg_id: String,
        started: bool,
        finished: bool,
        output_tokens: u64,
    },
}

impl SseTranslator {
    pub fn anthropic_to_openai(model: String) -> Self {
        Self::AnthropicToOpenAi {
            model,
            msg_id: "chatcmpl-ttt".to_string(),
            input_tokens: 0,
            sent_role: false,
            sent_done: false,
        }
    }

    pub fn gemini_to_openai(model: String) -> Self {
        Self::GeminiToOpenAi {
            model,
            sent_role: false,
            sent_done: false,
        }
    }

    pub fn openai_to_anthropic(model: String) -> Self {
        Self::OpenAiToAnthropic {
            model,
            msg_id: "msg_ttt".to_string(),
            started: false,
            finished: false,
            last_finish_reason: None,
            output_tokens: 0,
        }
    }

    pub fn responses_to_openai(model: String) -> Self {
        Self::ResponsesToOpenAi {
            model,
            resp_id: "chatcmpl-ttt".to_string(),
            sent_role: false,
            sent_done: false,
            tool_call_index: 0,
            has_tool_calls: false,
        }
    }

    pub fn responses_to_anthropic(model: String) -> Self {
        Self::ResponsesToAnthropic {
            model,
            msg_id: "msg_ttt".to_string(),
            started: false,
            finished: false,
            output_tokens: 0,
        }
    }

    /// Process a single `data: ...` payload line and push translated SSE chunks to `out`.
    pub fn on_data_line(&mut self, data: &str, out: &mut VecDeque<Bytes>) {
        match self {
            Self::AnthropicToOpenAi {
                model,
                msg_id,
                input_tokens,
                sent_role,
                sent_done,
            } => {
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    return;
                };
                match v.get("type").and_then(Value::as_str) {
                    Some("message_start") => {
                        if let Some(id) = v.pointer("/message/id").and_then(Value::as_str) {
                            *msg_id = id.to_string();
                        }
                        if let Some(m) = v.pointer("/message/model").and_then(Value::as_str)
                            && !m.is_empty()
                        {
                            *model = m.to_string();
                        }
                        if let Some(inp) = v
                            .pointer("/message/usage/input_tokens")
                            .and_then(Value::as_u64)
                        {
                            *input_tokens = inp;
                        }
                        if !*sent_role {
                            *sent_role = true;
                            let chunk = json!({
                                "id": msg_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": { "role": "assistant", "content": "" },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    Some("content_block_delta") => {
                        if let Some(text) = v.pointer("/delta/text").and_then(Value::as_str) {
                            let chunk = json!({
                                "id": msg_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": { "content": text },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    Some("message_delta") => {
                        let finish = map_anthropic_stop_reason(
                            v.pointer("/delta/stop_reason").and_then(Value::as_str),
                        );
                        let out_toks = v
                            .pointer("/usage/output_tokens")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        let chunk = json!({
                            "id": msg_id,
                            "object": "chat.completion.chunk",
                            "created": 0,
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {},
                                "finish_reason": finish,
                            }],
                            "usage": {
                                "prompt_tokens": *input_tokens,
                                "completion_tokens": out_toks,
                                "total_tokens": *input_tokens + out_toks,
                            }
                        });
                        out.push_back(sse_data_bytes(&chunk));
                    }
                    Some("message_stop") if !*sent_done => {
                        *sent_done = true;
                        out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
                    }
                    _ => {}
                }
            }

            Self::GeminiToOpenAi {
                model,
                sent_role,
                sent_done,
            } => {
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    return;
                };
                if !*sent_role {
                    *sent_role = true;
                    let role_chunk = json!({
                        "id": "chatcmpl-gemini",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": model,
                        "choices": [{
                            "index": 0,
                            "delta": { "role": "assistant" },
                            "finish_reason": Value::Null,
                        }]
                    });
                    out.push_back(sse_data_bytes(&role_chunk));
                }

                let text = extract_gemini_text(&v);
                let finish_raw = v
                    .pointer("/candidates/0/finishReason")
                    .and_then(Value::as_str);

                if !text.is_empty() {
                    let chunk = json!({
                        "id": "chatcmpl-gemini",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": model,
                        "choices": [{
                            "index": 0,
                            "delta": { "content": text },
                            "finish_reason": Value::Null,
                        }]
                    });
                    out.push_back(sse_data_bytes(&chunk));
                }

                if let Some(fr) = finish_raw {
                    let prompt_tokens = v
                        .pointer("/usageMetadata/promptTokenCount")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let completion_tokens = v
                        .pointer("/usageMetadata/candidatesTokenCount")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let chunk = json!({
                        "id": "chatcmpl-gemini",
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": model,
                        "choices": [{
                            "index": 0,
                            "delta": {},
                            "finish_reason": map_gemini_finish_reason(Some(fr)),
                        }],
                        "usage": {
                            "prompt_tokens": prompt_tokens,
                            "completion_tokens": completion_tokens,
                            "total_tokens": prompt_tokens + completion_tokens,
                        }
                    });
                    out.push_back(sse_data_bytes(&chunk));
                    if !*sent_done {
                        *sent_done = true;
                        out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
                    }
                }
            }

            Self::OpenAiToAnthropic {
                model,
                msg_id,
                started,
                finished,
                last_finish_reason,
                output_tokens,
            } => {
                if data == "[DONE]" {
                    emit_anthropic_finish(finished, last_finish_reason.as_deref(), *output_tokens, out);
                    return;
                }
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    return;
                };
                if let Some(id) = v.get("id").and_then(Value::as_str) {
                    *msg_id = id.to_string();
                }
                if let Some(m) = v.get("model").and_then(Value::as_str)
                    && !m.is_empty()
                {
                    *model = m.to_string();
                }
                if let Some(out_tok) = v
                    .pointer("/usage/completion_tokens")
                    .and_then(Value::as_u64)
                {
                    *output_tokens = out_tok;
                }
                if !*started {
                    *started = true;
                    let input_tokens = v
                        .pointer("/usage/prompt_tokens")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let start_ev = json!({
                        "type": "message_start",
                        "message": {
                            "id": msg_id,
                            "type": "message",
                            "role": "assistant",
                            "model": model,
                            "content": [],
                            "stop_reason": Value::Null,
                            "usage": { "input_tokens": input_tokens, "output_tokens": 0 },
                        }
                    });
                    out.push_back(sse_event_bytes("message_start", &start_ev));
                    let block_start = json!({
                        "type": "content_block_start",
                        "index": 0,
                        "content_block": { "type": "text", "text": "" },
                    });
                    out.push_back(sse_event_bytes("content_block_start", &block_start));
                }

                if let Some(text) = v
                    .pointer("/choices/0/delta/content")
                    .and_then(Value::as_str)
                    && !text.is_empty()
                {
                    let delta_ev = json!({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": { "type": "text_delta", "text": text },
                    });
                    out.push_back(sse_event_bytes("content_block_delta", &delta_ev));
                }

                if let Some(fr) = v
                    .pointer("/choices/0/finish_reason")
                    .and_then(Value::as_str)
                {
                    *last_finish_reason = Some(fr.to_string());
                }
            }

            Self::ResponsesToOpenAi {
                model,
                resp_id,
                sent_role,
                sent_done,
                tool_call_index,
                has_tool_calls,
            } => {
                if data == "[DONE]" {
                    if !*sent_done {
                        *sent_done = true;
                        out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
                    }
                    return;
                }
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    return;
                };
                match v.get("type").and_then(Value::as_str) {
                    Some("response.created") => {
                        if let Some(id) = v.pointer("/response/id").and_then(Value::as_str) {
                            *resp_id = id.to_string();
                        }
                        if let Some(m) = v.pointer("/response/model").and_then(Value::as_str)
                            && !m.is_empty()
                        {
                            *model = m.to_string();
                        }
                        if !*sent_role {
                            *sent_role = true;
                            let chunk = json!({
                                "id": resp_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": { "role": "assistant", "content": "" },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    Some("response.output_text.delta") => {
                        if !*sent_role {
                            *sent_role = true;
                            let role_chunk = json!({
                                "id": resp_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": { "role": "assistant" },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&role_chunk));
                        }
                        if let Some(delta) = v.get("delta").and_then(Value::as_str) {
                            let chunk = json!({
                                "id": resp_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": { "content": delta },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    Some("response.reasoning_summary_text.delta") => {
                        if let Some(delta) = v.get("delta").and_then(Value::as_str) {
                            let chunk = json!({
                                "id": resp_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": { "reasoning_content": delta },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    Some("response.output_item.added") => {
                        if v.pointer("/item/type").and_then(Value::as_str) == Some("function_call") {
                            let idx = *tool_call_index;
                            *tool_call_index += 1;
                            *has_tool_calls = true;
                            let call_id = v
                                .pointer("/item/call_id")
                                .or_else(|| v.pointer("/item/id"))
                                .and_then(Value::as_str)
                                .unwrap_or("call_0");
                            let name = v.pointer("/item/name").and_then(Value::as_str).unwrap_or("");
                            let chunk = json!({
                                "id": resp_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [{
                                            "index": idx,
                                            "id": call_id,
                                            "type": "function",
                                            "function": { "name": name, "arguments": "" }
                                        }]
                                    },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    Some("response.function_call_arguments.delta") => {
                        if let Some(delta) = v.get("delta").and_then(Value::as_str) {
                            let idx = tool_call_index.saturating_sub(1);
                            let chunk = json!({
                                "id": resp_id,
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": model,
                                "choices": [{
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [{
                                            "index": idx,
                                            "function": { "arguments": delta }
                                        }]
                                    },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    Some("response.completed") => {
                        let input_tokens = v
                            .pointer("/response/usage/input_tokens")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        let output_tokens = v
                            .pointer("/response/usage/output_tokens")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        let total_tokens = v
                            .pointer("/response/usage/total_tokens")
                            .and_then(Value::as_u64)
                            .unwrap_or(input_tokens + output_tokens);
                        let finish_reason = if *has_tool_calls { "tool_calls" } else { "stop" };
                        let chunk = json!({
                            "id": resp_id,
                            "object": "chat.completion.chunk",
                            "created": 0,
                            "model": model,
                            "choices": [{
                                "index": 0,
                                "delta": {},
                                "finish_reason": finish_reason,
                            }],
                            "usage": {
                                "prompt_tokens": input_tokens,
                                "completion_tokens": output_tokens,
                                "total_tokens": total_tokens,
                            }
                        });
                        out.push_back(sse_data_bytes(&chunk));
                        if !*sent_done {
                            *sent_done = true;
                            out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
                        }
                    }
                    _ => {}
                }
            }

            Self::ResponsesToAnthropic {
                model,
                msg_id,
                started,
                finished,
                output_tokens,
            } => {
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    return;
                };
                match v.get("type").and_then(Value::as_str) {
                    Some("response.created") => {
                        if let Some(id) = v.pointer("/response/id").and_then(Value::as_str) {
                            *msg_id = id.to_string();
                        }
                        if let Some(m) = v.pointer("/response/model").and_then(Value::as_str)
                            && !m.is_empty()
                        {
                            *model = m.to_string();
                        }
                        if !*started {
                            *started = true;
                            let start_ev = json!({
                                "type": "message_start",
                                "message": {
                                    "id": msg_id,
                                    "type": "message",
                                    "role": "assistant",
                                    "model": model,
                                    "content": [],
                                    "stop_reason": Value::Null,
                                    "usage": { "input_tokens": 0, "output_tokens": 0 },
                                }
                            });
                            out.push_back(sse_event_bytes("message_start", &start_ev));
                            let block_start = json!({
                                "type": "content_block_start",
                                "index": 0,
                                "content_block": { "type": "text", "text": "" },
                            });
                            out.push_back(sse_event_bytes("content_block_start", &block_start));
                        }
                    }
                    Some("response.output_text.delta") => {
                        if !*started {
                            *started = true;
                            let start_ev = json!({
                                "type": "message_start",
                                "message": {
                                    "id": msg_id,
                                    "type": "message",
                                    "role": "assistant",
                                    "model": model,
                                    "content": [],
                                    "stop_reason": Value::Null,
                                    "usage": { "input_tokens": 0, "output_tokens": 0 },
                                }
                            });
                            out.push_back(sse_event_bytes("message_start", &start_ev));
                            let block_start = json!({
                                "type": "content_block_start",
                                "index": 0,
                                "content_block": { "type": "text", "text": "" },
                            });
                            out.push_back(sse_event_bytes("content_block_start", &block_start));
                        }
                        if let Some(text) = v.get("delta").and_then(Value::as_str)
                            && !text.is_empty()
                        {
                            let delta_ev = json!({
                                "type": "content_block_delta",
                                "index": 0,
                                "delta": { "type": "text_delta", "text": text },
                            });
                            out.push_back(sse_event_bytes("content_block_delta", &delta_ev));
                        }
                    }
                    Some("response.completed") => {
                        if let Some(out_tok) = v
                            .pointer("/response/usage/output_tokens")
                            .and_then(Value::as_u64)
                        {
                            *output_tokens = out_tok;
                        }
                        emit_anthropic_finish(finished, Some("stop"), *output_tokens, out);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Emit terminal SSE events when the upstream stream ends.
    pub fn finish(&mut self, out: &mut VecDeque<Bytes>) {
        match self {
            Self::AnthropicToOpenAi { sent_done, .. }
            | Self::GeminiToOpenAi { sent_done, .. }
            | Self::ResponsesToOpenAi { sent_done, .. } => {
                if !*sent_done {
                    *sent_done = true;
                    out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
                }
            }
            Self::OpenAiToAnthropic {
                finished,
                last_finish_reason,
                output_tokens,
                ..
            } => {
                emit_anthropic_finish(finished, last_finish_reason.as_deref(), *output_tokens, out);
            }
            Self::ResponsesToAnthropic {
                finished,
                output_tokens,
                ..
            } => {
                emit_anthropic_finish(finished, Some("stop"), *output_tokens, out);
            }
        }
    }
}

fn emit_anthropic_finish(
    finished: &mut bool,
    last_finish_reason: Option<&str>,
    output_tokens: u64,
    out: &mut VecDeque<Bytes>,
) {
    if *finished {
        return;
    }
    *finished = true;
    out.push_back(sse_event_bytes(
        "content_block_stop",
        &json!({ "type": "content_block_stop", "index": 0 }),
    ));
    out.push_back(sse_event_bytes(
        "message_delta",
        &json!({
            "type": "message_delta",
            "delta": { "stop_reason": map_openai_finish_reason(last_finish_reason) },
            "usage": { "output_tokens": output_tokens },
        }),
    ));
    out.push_back(sse_event_bytes(
        "message_stop",
        &json!({ "type": "message_stop" }),
    ));
}

fn sse_data_bytes(val: &Value) -> Bytes {
    Bytes::from(format!("data: {val}\n\n"))
}

fn sse_event_bytes(event: &str, val: &Value) -> Bytes {
    Bytes::from(format!("event: {event}\ndata: {val}\n\n"))
}

pin_project! {
    /// Incremental streaming HTTP Body that translates SSE chunks on the fly
    /// with zero full-response buffering.
    pub struct TranslatedStreamBody<B> {
        #[pin]
        inner: B,
        translator: SseTranslator,
        line_buf: Vec<u8>,
        pending_out: VecDeque<Bytes>,
        upstream_eof: bool,
    }
}

impl<B> TranslatedStreamBody<B> {
    pub fn new(inner: B, translator: SseTranslator) -> Self {
        Self {
            inner,
            translator,
            line_buf: Vec::with_capacity(1024),
            pending_out: VecDeque::with_capacity(8),
            upstream_eof: false,
        }
    }
}

impl<B> Body for TranslatedStreamBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();

        loop {
            if let Some(chunk) = this.pending_out.pop_front() {
                return Poll::Ready(Some(Ok(Frame::data(chunk))));
            }
            if *this.upstream_eof {
                return Poll::Ready(None);
            }

            match this.inner.as_mut().poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        this.line_buf.extend_from_slice(data);
                        while let Some(pos) = memchr::memchr(b'\n', this.line_buf) {
                            let raw_line: Vec<u8> = this.line_buf.drain(..=pos).collect();
                            if let Ok(s) = std::str::from_utf8(&raw_line) {
                                let trimmed = s.trim();
                                if let Some(payload) = trimmed.strip_prefix("data:") {
                                    this.translator.on_data_line(payload.trim(), this.pending_out);
                                }
                            }
                        }
                    }
                }
                Poll::Ready(Some(Err(err))) => return Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => {
                    *this.upstream_eof = true;
                    if !this.line_buf.is_empty() {
                        let tail = std::mem::take(this.line_buf);
                        if let Ok(s) = std::str::from_utf8(&tail)
                            && let Some(payload) = s.trim().strip_prefix("data:")
                        {
                            this.translator.on_data_line(payload.trim(), this.pending_out);
                        }
                    }
                    this.translator.finish(this.pending_out);
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.upstream_eof && self.pending_out.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
