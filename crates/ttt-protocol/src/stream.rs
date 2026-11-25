use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use serde_json::{Value, json};

use crate::openai_anthropic::{map_anthropic_stop_reason, map_openai_finish_reason};
use crate::openai_gemini::{
    google_candidate_delta, google_completion_id, google_finish_reason, google_usage,
};
use crate::sse::{SseDecoder, sse_data_bytes, sse_event_bytes};

/// Static-dispatch incremental SSE protocol state machine.
pub enum SseTranslator {
    AnthropicToOpenAi {
        model: String,
        msg_id: String,
        input_tokens: u64,
        tool_blocks: HashMap<u64, (usize, bool)>,
        sent_role: bool,
        sent_done: bool,
    },
    GeminiToOpenAi {
        model: String,
        response_id: Option<String>,
        next_call: usize,
        pending_finish: Option<&'static str>,
        usage: Option<Value>,
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
        tools_by_item: HashMap<String, usize>,
        tools_by_output: HashMap<u64, usize>,
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
            tool_blocks: HashMap::new(),
            sent_role: false,
            sent_done: false,
        }
    }

    pub fn gemini_to_openai(model: String) -> Self {
        Self::GeminiToOpenAi {
            model,
            response_id: None,
            next_call: 0,
            pending_finish: None,
            usage: None,
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
            tools_by_item: HashMap::new(),
            tools_by_output: HashMap::new(),
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

    /// Translate a complete SSE data payload.
    pub fn on_data_line(&mut self, data: &str, out: &mut VecDeque<Bytes>) {
        self.on_event("", data, out);
    }

    fn on_event(&mut self, event: &str, data: &str, out: &mut VecDeque<Bytes>) {
        if self.is_finished() || event == "ping" || (data.trim().is_empty() && event != "error") {
            return;
        }
        if data.trim() == "[DONE]" {
            match self {
                Self::OpenAiToAnthropic {
                    finished,
                    last_finish_reason,
                    output_tokens,
                    ..
                } => {
                    emit_anthropic_finish(
                        finished,
                        last_finish_reason.as_deref(),
                        *output_tokens,
                        out,
                    );
                }
                Self::ResponsesToOpenAi { sent_done, .. } => {
                    *sent_done = true;
                    out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
                }
                Self::GeminiToOpenAi {
                    pending_finish: Some(_),
                    ..
                } => self.finish(out),
                _ => self.fail("Upstream sent an unexpected stream terminator", out),
            }
            return;
        }

        let Ok(v) = serde_json::from_str::<Value>(data) else {
            self.fail("Upstream sent an invalid SSE payload", out);
            return;
        };
        let event_type = v.get("type").and_then(Value::as_str).unwrap_or(event);
        if event == "error"
            || matches!(
                event_type,
                "error" | "response.failed" | "response.incomplete"
            )
            || v.get("error")
                .or_else(|| v.pointer("/response/error"))
                .is_some_and(|error| error.is_object())
        {
            let message = v
                .pointer("/error/message")
                .or_else(|| v.pointer("/response/error/message"))
                .or_else(|| v.get("message"))
                .or_else(|| v.pointer("/response/incomplete_details/reason"))
                .and_then(Value::as_str)
                .unwrap_or("Upstream stream failed");
            self.fail(message, out);
            return;
        }

        match self {
            Self::AnthropicToOpenAi {
                model,
                msg_id,
                input_tokens,
                tool_blocks,
                sent_role,
                sent_done,
            } => {
                match event_type {
                    "message_start" => {
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
                    "content_block_start" => {
                        let block = &v["content_block"];
                        match block["type"].as_str() {
                            Some("tool_use") => {
                                if let Some(index) = v["index"].as_u64() {
                                    let tool_index = tool_blocks.len();
                                    let arguments = block["input"]
                                        .as_object()
                                        .filter(|input| !input.is_empty())
                                        .map_or_else(String::new, |_| block["input"].to_string());
                                    let (index, _) = *tool_blocks
                                        .entry(index)
                                        .or_insert((tool_index, !arguments.is_empty()));
                                    out.push_back(chat_delta(msg_id, model, json!({
                                            "tool_calls": [{
                                                "index": index,
                                                "id": block["id"],
                                                "type": "function",
                                                "function": { "name": block["name"], "arguments": arguments }
                                            }]
                                        })));
                                }
                            }
                            Some("text" | "thinking") => {
                                emit_anthropic_text_delta(msg_id, model, block, out);
                            }
                            _ => {}
                        }
                    }
                    "content_block_delta" => {
                        let delta = &v["delta"];
                        if delta["type"].as_str() == Some("input_json_delta") {
                            if let Some((index, has_arguments)) = v["index"].as_u64().and_then(|i| tool_blocks.get_mut(&i))
                                && let Some(arguments) = delta["partial_json"].as_str()
                            {
                                *has_arguments |= !arguments.is_empty();
                                out.push_back(chat_delta(msg_id, model, json!({
                                        "tool_calls": [{"index": index, "function": {"arguments": arguments}}]
                                    })));
                            }
                        } else {
                            emit_anthropic_text_delta(msg_id, model, delta, out);
                        }
                    }
                    "content_block_stop" => {
                        if let Some((index, has_arguments)) = v["index"].as_u64().and_then(|i| tool_blocks.get_mut(&i))
                            && !*has_arguments
                        {
                            *has_arguments = true;
                            out.push_back(chat_delta(msg_id, model, json!({
                                "tool_calls": [{"index": index, "function": {"arguments": "{}"}}]
                            })));
                        }
                    }
                    "message_delta" => {
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
                    "message_stop" if !*sent_done => {
                        *sent_done = true;
                        out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
                    }
                    _ => {}
                }
            }

            Self::GeminiToOpenAi {
                model,
                response_id,
                next_call,
                pending_finish,
                usage,
                sent_done,
            } => {
                let v = v.get("response").unwrap_or(&v);
                if response_id.is_none() {
                    let id = google_completion_id(v);
                    out.push_back(chat_delta(&id, model, json!({"role": "assistant"})));
                    *response_id = Some(id);
                }
                let id = response_id.as_deref().expect("completion ID initialized");
                let delta = google_candidate_delta(v, id, next_call, true);
                if delta.as_object().is_some_and(|fields| !fields.is_empty()) {
                    out.push_back(chat_delta(id, model, delta));
                }
                if let Some(reason) = google_finish_reason(v, *next_call > 0) {
                    *pending_finish = Some(reason);
                }
                if let Some(metadata) = v["usageMetadata"].as_object() {
                    if let Some(existing) = usage.as_mut().and_then(Value::as_object_mut) {
                        existing.extend(metadata.clone());
                    } else {
                        *usage = Some(Value::Object(metadata.clone()));
                    }
                    if let Some(reason) = *pending_finish {
                        emit_google_finish(id, model, reason, usage.as_ref(), out);
                        *sent_done = true;
                    }
                }
            }

            Self::OpenAiToAnthropic {
                model,
                msg_id,
                started,
                last_finish_reason,
                output_tokens,
                ..
            } => {
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
                tools_by_item,
                tools_by_output,
            } => {
                match event_type {
                    "response.created" => {
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
                    "response.output_text.delta" => {
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
                    "response.reasoning_summary_text.delta" => {
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
                    "response.output_item.added" => {
                        if v.pointer("/item/type").and_then(Value::as_str) == Some("function_call") {
                            let idx = *tool_call_index;
                            *tool_call_index += 1;
                            if let Some(item) = v.pointer("/item/id").and_then(Value::as_str) {
                                tools_by_item.insert(item.to_owned(), idx);
                            }
                            if let Some(index) = v.get("output_index").and_then(Value::as_u64) {
                                tools_by_output.insert(index, idx);
                            }
                            let call_id = v
                                .pointer("/item/call_id")
                                .or_else(|| v.pointer("/item/id"))
                                .and_then(Value::as_str)
                                .unwrap_or("call_0");
                            let name = v
                                .pointer("/item/name")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let arguments = v
                                .pointer("/item/arguments")
                                .and_then(Value::as_str)
                                .unwrap_or("");
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
                                            "function": { "name": name, "arguments": arguments }
                                        }]
                                    },
                                    "finish_reason": Value::Null,
                                }]
                            });
                            out.push_back(sse_data_bytes(&chunk));
                        }
                    }
                    "response.function_call_arguments.delta" => {
                        let item = v.get("item_id").and_then(Value::as_str);
                        let output = v.get("output_index").and_then(Value::as_u64);
                        let index = item
                            .and_then(|item| tools_by_item.get(item))
                            .or_else(|| output.and_then(|index| tools_by_output.get(&index)))
                            .copied()
                            .or_else(|| {
                                (item.is_none() && output.is_none() && *tool_call_index == 1)
                                    .then_some(0)
                            });
                        if let Some(delta) = v.get("delta").and_then(Value::as_str) {
                            let Some(idx) = index else {
                                self.fail(
                                    "Upstream tool arguments did not identify a known tool call",
                                    out,
                                );
                                return;
                            };
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
                    "response.completed" => {
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
                        let finish_reason = if *tool_call_index > 0 {
                            "tool_calls"
                        } else {
                            "stop"
                        };
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
                match event_type {
                    "response.created" => {
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
                    "response.output_text.delta" => {
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
                    "response.completed" => {
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

    fn is_finished(&self) -> bool {
        match self {
            Self::AnthropicToOpenAi { sent_done, .. }
            | Self::GeminiToOpenAi { sent_done, .. }
            | Self::ResponsesToOpenAi { sent_done, .. } => *sent_done,
            Self::OpenAiToAnthropic { finished, .. }
            | Self::ResponsesToAnthropic { finished, .. } => *finished,
        }
    }

    fn fail(&mut self, message: &str, out: &mut VecDeque<Bytes>) {
        match self {
            Self::AnthropicToOpenAi { sent_done, .. }
            | Self::GeminiToOpenAi { sent_done, .. }
            | Self::ResponsesToOpenAi { sent_done, .. } => {
                *sent_done = true;
                out.push_back(sse_data_bytes(&json!({
                    "error": { "message": message, "type": "upstream_error", "code": "upstream_stream_error" }
                })));
            }
            Self::OpenAiToAnthropic { finished, .. }
            | Self::ResponsesToAnthropic { finished, .. } => {
                *finished = true;
                out.push_back(sse_event_bytes(
                    "error",
                    &json!({
                        "type": "error",
                        "error": { "type": "api_error", "message": message }
                    }),
                ));
            }
        }
    }

    /// Finish streams that reached a protocol terminator and report unexpected EOF.
    pub fn finish(&mut self, out: &mut VecDeque<Bytes>) {
        if self.is_finished() {
            return;
        }
        match self {
            Self::OpenAiToAnthropic {
                finished,
                last_finish_reason,
                output_tokens,
                ..
            } if last_finish_reason.is_some() => {
                emit_anthropic_finish(finished, last_finish_reason.as_deref(), *output_tokens, out);
            }
            Self::GeminiToOpenAi {
                model,
                response_id: Some(id),
                pending_finish: Some(reason),
                usage,
                sent_done,
                ..
            } => {
                emit_google_finish(id, model, reason, usage.as_ref(), out);
                *sent_done = true;
            }
            _ => self.fail("Upstream stream ended without a completion event", out),
        }
    }
}

fn emit_anthropic_text_delta(id: &str, model: &str, block: &Value, out: &mut VecDeque<Bytes>) {
    if let Some(text) = block
        .get("text")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        out.push_back(chat_delta(id, model, json!({ "content": text })));
    }
    if let Some(thinking) = block
        .get("thinking")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        out.push_back(chat_delta(
            id,
            model,
            json!({ "reasoning_content": thinking }),
        ));
    }
}

fn chat_delta(id: &str, model: &str, delta: Value) -> Bytes {
    sse_data_bytes(&json!({
        "id": id, "object": "chat.completion.chunk", "created": 0, "model": model,
        "choices": [{ "index": 0, "delta": delta, "finish_reason": null }]
    }))
}

fn emit_google_finish(
    id: &str,
    model: &str,
    reason: &str,
    usage: Option<&Value>,
    out: &mut VecDeque<Bytes>,
) {
    let mut chunk = json!({
        "id": id, "object": "chat.completion.chunk", "created": 0, "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
    });
    if let Some(usage) = usage {
        chunk["usage"] = google_usage(usage);
    }
    out.push_back(sse_data_bytes(&chunk));
    out.push_back(Bytes::from_static(b"data: [DONE]\n\n"));
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

pin_project! {
    /// Incremental streaming HTTP Body that translates SSE chunks on the fly
    /// with zero full-response buffering.
    pub struct TranslatedStreamBody<B> {
        #[pin]
        inner: B,
        translator: SseTranslator,
        decoder: SseDecoder,
        pending_out: VecDeque<Bytes>,
        upstream_eof: bool,
    }
}

impl<B> TranslatedStreamBody<B> {
    pub fn new(inner: B, translator: SseTranslator) -> Self {
        Self {
            inner,
            translator,
            decoder: SseDecoder::default(),
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
                        this.decoder.push(data, |event, payload| {
                            this.translator.on_event(event, payload, this.pending_out);
                        });
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    *this.upstream_eof = true;
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(None) => {
                    *this.upstream_eof = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn translate(translator: &mut SseTranslator, wire: &str) -> Vec<Value> {
        let mut decoder = SseDecoder::default();
        let mut out = VecDeque::new();
        for chunk in wire.as_bytes().chunks(7) {
            decoder.push(chunk, |event, payload| translator.on_event(event, payload, &mut out));
        }
        translator.finish(&mut out);
        out.into_iter()
            .filter_map(|chunk| {
                let chunk = std::str::from_utf8(&chunk).unwrap();
                let payload = chunk.lines().find_map(|line| line.strip_prefix("data: ")).unwrap();
                (payload != "[DONE]").then(|| serde_json::from_str(payload).unwrap())
            })
            .collect()
    }

    #[test]
    fn reports_upstream_error_and_unexpected_eof() {
        let partial = "data: {\"type\":\"content_block_delta\",\ndata: \"delta\":{\"text\":\"保留正文\"}}\n\n";
        for (tail, message) in [
            ("", "Upstream stream ended without a completion event"),
            ("event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"overloaded\"}}\n\n", "overloaded"),
        ] {
            let mut translator = SseTranslator::anthropic_to_openai("claude".into());
            let out = translate(&mut translator, &format!("{partial}{tail}"));
            assert_eq!(out.len(), 2);
            assert_eq!(out[0]["choices"][0]["delta"]["content"], "保留正文");
            assert_eq!(out[1]["error"]["message"], message);
            let mut tail = VecDeque::new();
            translator.finish(&mut tail);
            assert!(tail.is_empty());
        }
    }

    #[test]
    fn preserves_anthropic_reasoning_and_indexed_tool_arguments() {
        let mut translator = SseTranslator::anthropic_to_openai("claude".into());
        let wire = concat!(
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"reason\"}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"a\",\"name\":\"first\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":4,\"content_block\":{\"type\":\"tool_use\",\"id\":\"b\",\"name\":\"second\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"value\\\":1}\"}}\n\n",
            "data: {\"type\":\"content_block_stop\",\"index\":4}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        let out = translate(&mut translator, wire);
        assert_eq!(out[0]["choices"][0]["delta"]["reasoning_content"], "reason");
        let first = &out[3]["choices"][0]["delta"]["tool_calls"][0];
        let second = &out[4]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(first["index"], 0);
        assert_eq!(first["function"]["arguments"], r#"{"value":1}"#);
        assert_eq!(second["index"], 1);
        assert_eq!(second["function"]["arguments"], "{}");
    }

    #[test]
    fn routes_interleaved_responses_arguments_to_the_corresponding_tool() {
        let mut translator = SseTranslator::responses_to_openai("responses".into());
        let wire = concat!(
            "data: {\"type\":\"response.output_item.added\",\"output_index\":1,\"item\":{\"type\":\"function_call\",\"id\":\"a\",\"name\":\"first\"}}\n\n",
            "data: {\"type\":\"response.output_item.added\",\"output_index\":3,\"item\":{\"type\":\"function_call\",\"id\":\"b\",\"name\":\"second\"}}\n\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"a\",\"delta\":\"first arguments\"}\n\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":3,\"delta\":\"second arguments\"}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{}}\n\n",
        );
        let out = translate(&mut translator, wire);
        let first = &out[2]["choices"][0]["delta"]["tool_calls"][0];
        let second = &out[3]["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(first["index"], 0);
        assert_eq!(first["function"]["arguments"], "first arguments");
        assert_eq!(second["index"], 1);
        assert_eq!(second["function"]["arguments"], "second arguments");
    }
}
