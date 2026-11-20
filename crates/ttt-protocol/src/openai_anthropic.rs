use bytes::Bytes;
use serde_json::{json, Map, Value};
use ttt_core::GatewayError;

use crate::TranslatedRequest;

/// Translate an OpenAI Chat Completions JSON request into an Anthropic Messages JSON request.
pub fn openai_to_anthropic_request(
    raw: &[u8],
    model_override: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::InvalidRequest(format!("invalid OpenAI JSON body: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| GatewayError::InvalidRequest("request body must be a JSON object".into()))?;

    let model = model_override
        .map(ToOwned::to_owned)
        .or_else(|| obj.get("model").and_then(Value::as_str).map(ToOwned::to_owned))
        .unwrap_or_default();

    let mut system_parts: Vec<String> = Vec::new();
    let mut anthropic_messages: Vec<Value> = Vec::new();

    if let Some(messages) = obj.get("messages").and_then(Value::as_array) {
        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            match role {
                "system" | "developer" => {
                    if let Some(text) = extract_text_content(msg.get("content"))
                        && !text.is_empty()
                    {
                        system_parts.push(text);
                    }
                }
                "tool" => {
                    let tool_use_id = msg
                        .get("tool_call_id")
                        .and_then(Value::as_str)
                        .unwrap_or("tool_call");
                    let content = extract_text_content(msg.get("content")).unwrap_or_default();
                    anthropic_messages.push(json!({
                        "role": "user",
                        "content": [{
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": content,
                        }]
                    }));
                }
                "assistant" => {
                    let mut blocks = Vec::new();
                    if let Some(text) = extract_text_content(msg.get("content"))
                        && !text.is_empty()
                    {
                        blocks.push(json!({ "type": "text", "text": text }));
                    }
                    if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
                        for tc in tool_calls {
                            let id = tc.get("id").and_then(Value::as_str).unwrap_or("toolu_0");
                            let name = tc
                                .pointer("/function/name")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let args_str = tc
                                .pointer("/function/arguments")
                                .and_then(Value::as_str)
                                .unwrap_or("{}");
                            let input: Value =
                                serde_json::from_str(args_str).unwrap_or_else(|_| json!({}));
                            blocks.push(json!({
                                "type": "tool_use",
                                "id": id,
                                "name": name,
                                "input": input,
                            }));
                        }
                    }
                    if !blocks.is_empty() {
                        anthropic_messages.push(json!({
                            "role": "assistant",
                            "content": blocks,
                        }));
                    }
                }
                _ => {
                    let text = extract_text_content(msg.get("content")).unwrap_or_default();
                    anthropic_messages.push(json!({
                        "role": "user",
                        "content": text,
                    }));
                }
            }
        }
    }

    let max_tokens = obj
        .get("max_completion_tokens")
        .or_else(|| obj.get("max_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(4096);

    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let mut out = Map::new();
    out.insert("model".into(), Value::String(model.clone()));
    out.insert("max_tokens".into(), json!(max_tokens));
    out.insert("messages".into(), Value::Array(anthropic_messages));
    if !system_parts.is_empty() {
        out.insert("system".into(), Value::String(system_parts.join("\n\n")));
    }
    if stream {
        out.insert("stream".into(), Value::Bool(true));
    }
    if let Some(temp) = obj.get("temperature") {
        out.insert("temperature".into(), temp.clone());
    }
    if let Some(top_p) = obj.get("top_p") {
        out.insert("top_p".into(), top_p.clone());
    }
    if let Some(stop) = obj.get("stop") {
        let seqs = match stop {
            Value::String(s) => vec![Value::String(s.clone())],
            Value::Array(arr) => arr.clone(),
            _ => Vec::new(),
        };
        if !seqs.is_empty() {
            out.insert("stop_sequences".into(), Value::Array(seqs));
        }
    }
    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let func = t.get("function")?;
                let name = func.get("name")?.as_str()?;
                let mut tool = Map::new();
                tool.insert("name".into(), Value::String(name.to_string()));
                if let Some(desc) = func.get("description") {
                    tool.insert("description".into(), desc.clone());
                }
                tool.insert(
                    "input_schema".into(),
                    func.get("parameters")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
                );
                Some(Value::Object(tool))
            })
            .collect();
        if !converted.is_empty() {
            out.insert("tools".into(), Value::Array(converted));
        }
    }

    let bytes = serde_json::to_vec(&Value::Object(out))
        .map_err(|e| GatewayError::Internal(format!("failed to encode Anthropic request: {e}")))?;

    Ok(TranslatedRequest {
        target_path_and_query: "/messages".to_string(),
        body: Bytes::from(bytes),
        extra_headers: vec![("anthropic-version", "2023-06-01".to_string())],
        model,
        is_stream: stream,
    })
}

/// Translate an Anthropic Messages JSON response into an OpenAI Chat Completions JSON response.
pub fn anthropic_to_openai_response(raw: &[u8]) -> Result<Bytes, GatewayError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::Internal(format!("invalid Anthropic response JSON: {e}")))?;

    let id = v
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("chatcmpl-ttt");
    let model = v.get("model").and_then(Value::as_str).unwrap_or("");
    let stop_reason = v.get("stop_reason").and_then(Value::as_str);

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();

    if let Some(blocks) = v.get("content").and_then(Value::as_array) {
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(Value::as_str) {
                        text_parts.push(t);
                    }
                }
                Some("tool_use") => {
                    let call_id = block.get("id").and_then(Value::as_str).unwrap_or("call_0");
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                    let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
                    tool_calls.push(json!({
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": input.to_string(),
                        }
                    }));
                }
                _ => {}
            }
        }
    }

    let finish_reason = map_anthropic_stop_reason(stop_reason);
    let input_tokens = v
        .pointer("/usage/input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = v
        .pointer("/usage/output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let mut message = Map::new();
    message.insert("role".into(), Value::String("assistant".into()));
    if text_parts.is_empty() && !tool_calls.is_empty() {
        message.insert("content".into(), Value::Null);
    } else {
        message.insert("content".into(), Value::String(text_parts.concat()));
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".into(), Value::Array(tool_calls));
    }

    let out = json!({
        "id": id,
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
    });

    serde_json::to_vec(&out)
        .map(Bytes::from)
        .map_err(|e| GatewayError::Internal(format!("failed to encode OpenAI response: {e}")))
}

/// Translate an Anthropic Messages JSON request (e.g. from Claude Code) into an OpenAI Chat Completions JSON request.
pub fn anthropic_to_openai_request(
    raw: &[u8],
    model_override: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::InvalidRequest(format!("invalid Anthropic JSON body: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| GatewayError::InvalidRequest("request body must be a JSON object".into()))?;

    let model = model_override
        .map(ToOwned::to_owned)
        .or_else(|| obj.get("model").and_then(Value::as_str).map(ToOwned::to_owned))
        .unwrap_or_default();
    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let mut openai_messages: Vec<Value> = Vec::new();

    if let Some(sys) = obj.get("system")
        && let Some(sys_text) = extract_text_content(Some(sys))
        && !sys_text.is_empty()
    {
        openai_messages.push(json!({
            "role": "system",
            "content": sys_text,
        }));
    }

    if let Some(messages) = obj.get("messages").and_then(Value::as_array) {
        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            if let Some(blocks) = msg.get("content").and_then(Value::as_array) {
                let mut text_parts = Vec::new();
                let mut tool_calls = Vec::new();
                let mut tool_results = Vec::new();

                for block in blocks {
                    match block.get("type").and_then(Value::as_str) {
                        Some("text") => {
                            if let Some(t) = block.get("text").and_then(Value::as_str) {
                                text_parts.push(t.to_string());
                            }
                        }
                        Some("tool_use") => {
                            let id = block.get("id").and_then(Value::as_str).unwrap_or("call_0");
                            let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                            let input = block.get("input").cloned().unwrap_or_else(|| json!({}));
                            tool_calls.push(json!({
                                "id": id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": input.to_string(),
                                }
                            }));
                        }
                        Some("tool_result") => {
                            let id = block
                                .get("tool_use_id")
                                .and_then(Value::as_str)
                                .unwrap_or("call_0");
                            let content =
                                extract_text_content(block.get("content")).unwrap_or_default();
                            tool_results.push(json!({
                                "role": "tool",
                                "tool_call_id": id,
                                "content": content,
                            }));
                        }
                        _ => {}
                    }
                }

                if !text_parts.is_empty() || !tool_calls.is_empty() {
                    let mut m = Map::new();
                    m.insert("role".into(), Value::String(role.to_string()));
                    m.insert("content".into(), Value::String(text_parts.join("")));
                    if !tool_calls.is_empty() {
                        m.insert("tool_calls".into(), Value::Array(tool_calls));
                    }
                    openai_messages.push(Value::Object(m));
                }
                openai_messages.extend(tool_results);
            } else {
                let text = extract_text_content(msg.get("content")).unwrap_or_default();
                openai_messages.push(json!({
                    "role": role,
                    "content": text,
                }));
            }
        }
    }

    let mut out = Map::new();
    out.insert("model".into(), Value::String(model.clone()));
    out.insert("messages".into(), Value::Array(openai_messages));
    if let Some(max_tokens) = obj.get("max_tokens") {
        out.insert("max_tokens".into(), max_tokens.clone());
    }
    if stream {
        out.insert("stream".into(), Value::Bool(true));
        out.insert("stream_options".into(), json!({"include_usage": true}));
    }
    if let Some(temp) = obj.get("temperature") {
        out.insert("temperature".into(), temp.clone());
    }
    if let Some(top_p) = obj.get("top_p") {
        out.insert("top_p".into(), top_p.clone());
    }
    if let Some(stops) = obj.get("stop_sequences") {
        out.insert("stop".into(), stops.clone());
    }

    let bytes = serde_json::to_vec(&Value::Object(out))
        .map_err(|e| GatewayError::Internal(format!("failed to encode OpenAI request: {e}")))?;

    Ok(TranslatedRequest {
        target_path_and_query: "/chat/completions".to_string(),
        body: Bytes::from(bytes),
        extra_headers: Vec::new(),
        model,
        is_stream: stream,
    })
}

/// Translate an OpenAI Chat Completions JSON response into an Anthropic Messages JSON response.
pub fn openai_to_anthropic_response(raw: &[u8]) -> Result<Bytes, GatewayError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::Internal(format!("invalid OpenAI response JSON: {e}")))?;

    let id = v.get("id").and_then(Value::as_str).unwrap_or("msg_ttt");
    let model = v.get("model").and_then(Value::as_str).unwrap_or("");
    let choice = v.pointer("/choices/0");

    let mut content = Vec::new();
    if let Some(text) = choice
        .and_then(|c| c.pointer("/message/content"))
        .and_then(Value::as_str)
        && !text.is_empty()
    {
        content.push(json!({ "type": "text", "text": text }));
    }
    if let Some(tcs) = choice
        .and_then(|c| c.pointer("/message/tool_calls"))
        .and_then(Value::as_array)
    {
        for tc in tcs {
            let tc_id = tc.get("id").and_then(Value::as_str).unwrap_or("toolu_0");
            let name = tc
                .pointer("/function/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let args = tc
                .pointer("/function/arguments")
                .and_then(Value::as_str)
                .unwrap_or("{}");
            let input: Value = serde_json::from_str(args).unwrap_or_else(|_| json!({}));
            content.push(json!({
                "type": "tool_use",
                "id": tc_id,
                "name": name,
                "input": input,
            }));
        }
    }

    let stop_reason = map_openai_finish_reason(
        choice
            .and_then(|c| c.get("finish_reason"))
            .and_then(Value::as_str),
    );
    let input_tokens = v
        .pointer("/usage/prompt_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = v
        .pointer("/usage/completion_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let out = json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }
    });

    serde_json::to_vec(&out)
        .map(Bytes::from)
        .map_err(|e| GatewayError::Internal(format!("failed to encode Anthropic response: {e}")))
}

pub(crate) fn map_anthropic_stop_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("end_turn") | Some("stop_sequence") => "stop",
        Some("max_tokens") => "length",
        Some("tool_use") => "tool_calls",
        _ => "stop",
    }
}

pub(crate) fn map_openai_finish_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("length") => "max_tokens",
        Some("tool_calls") => "tool_use",
        _ => "end_turn",
    }
}

pub(crate) fn extract_text_content(val: Option<&Value>) -> Option<String> {
    let val = val?;
    if let Some(s) = val.as_str() {
        return Some(s.to_string());
    }
    if let Some(arr) = val.as_array() {
        let mut out = String::new();
        for item in arr {
            if let Some(t) = item.get("text").and_then(Value::as_str) {
                out.push_str(t);
            }
        }
        return Some(out);
    }
    None
}
