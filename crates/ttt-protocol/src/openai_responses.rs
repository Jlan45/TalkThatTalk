use bytes::Bytes;
use serde_json::{json, Value};
use ttt_core::GatewayError;

use crate::TranslatedRequest;
use crate::openai_anthropic::{
    anthropic_function_tools, anthropic_image_url, anthropic_tool_choice, anthropic_tool_id,
    anthropic_tool_output, unsupported_anthropic_block,
};

/// Translate an OpenAI Chat Completions (`/v1/chat/completions`) request
/// into an OpenAI Responses API (`/responses`) request (compatible with
/// both OpenAI Responses API and ChatGPT Codex backend).
pub fn openai_to_responses_request(
    raw_body: &[u8],
    model_override: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    openai_to_responses_request_with_session(raw_body, model_override, None)
}

/// Same as `openai_to_responses_request`, propagating/injecting `prompt_cache_key`
/// from the request body or `session_hint`.
pub fn openai_to_responses_request_with_session(
    raw_body: &[u8],
    model_override: Option<&str>,
    session_hint: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    let req: Value = serde_json::from_slice(raw_body)
        .map_err(|e| GatewayError::InvalidRequest(format!("invalid OpenAI JSON body: {e}")))?;

    let model = model_override
        .map(ToOwned::to_owned)
        .or_else(|| req.get("model").and_then(Value::as_str).map(ToOwned::to_owned))
        .unwrap_or_else(|| "gpt-5-codex".to_string());

    let is_stream = req.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let mut system_parts: Vec<String> = Vec::new();
    let mut input_items: Vec<Value> = Vec::new();

    if let Some(messages) = req.get("messages").and_then(Value::as_array) {
        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            match role {
                "system" | "developer" => {
                    let text = extract_text_content(msg.get("content"));
                    if !text.is_empty() {
                        system_parts.push(text);
                    }
                }
                "user" => {
                    let content = convert_user_content(msg.get("content"));
                    input_items.push(json!({
                        "type": "message",
                        "role": "user",
                        "content": content,
                    }));
                }
                "assistant" => {
                    let text = extract_text_content(msg.get("content"));
                    if !text.is_empty() {
                        input_items.push(json!({
                            "type": "message",
                            "role": "assistant",
                            "content": [{
                                "type": "output_text",
                                "text": text,
                            }],
                        }));
                    }
                    if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
                        for tc in tool_calls {
                            let call_id = tc.get("id").and_then(Value::as_str).unwrap_or("call_0");
                            let name = tc
                                .pointer("/function/name")
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            let arguments = tc
                                .pointer("/function/arguments")
                                .and_then(Value::as_str)
                                .unwrap_or("{}");
                            input_items.push(json!({
                                "type": "function_call",
                                "call_id": call_id,
                                "name": name,
                                "arguments": arguments,
                            }));
                        }
                    }
                }
                "tool" => {
                    let call_id = msg
                        .get("tool_call_id")
                        .and_then(Value::as_str)
                        .unwrap_or("call_0");
                    let output = extract_text_content(msg.get("content"));
                    input_items.push(json!({
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": output,
                    }));
                }
                _ => {
                    let text = extract_text_content(msg.get("content"));
                    if !text.is_empty() {
                        input_items.push(json!({
                            "type": "message",
                            "role": "user",
                            "content": [{ "type": "input_text", "text": text }],
                        }));
                    }
                }
            }
        }
    }

    let instructions = if system_parts.is_empty() {
        "You are a helpful assistant.".to_string()
    } else {
        system_parts.join("\n\n")
    };

    let mut out = json!({
        "model": model,
        "instructions": instructions,
        "input": input_items,
        "stream": is_stream,
        "store": false,
    });

    if let Some(tools) = req.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let func = t.get("function")?;
                let name = func.get("name")?.as_str()?;
                let mut item = json!({
                    "type": "function",
                    "name": name,
                });
                if let Some(desc) = func.get("description") {
                    item["description"] = desc.clone();
                }
                if let Some(params) = func.get("parameters") {
                    item["parameters"] = params.clone();
                }
                Some(item)
            })
            .collect();
        if !converted.is_empty() {
            out["tools"] = Value::Array(converted);
        }
    }

    if let Some(tc) = req.get("tool_choice") {
        out["tool_choice"] = tc.clone();
    }

    if let Some(effort) = req.get("reasoning_effort").and_then(Value::as_str) {
        out["reasoning"] = json!({ "effort": effort });
    }

    let cache_key = req
        .get("prompt_cache_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| session_hint.map(str::trim).filter(|s| !s.is_empty()));
    if let Some(key) = cache_key {
        out["prompt_cache_key"] = Value::String(key.to_string());
    }

    let body = serde_json::to_vec(&out)
        .map_err(|e| GatewayError::Internal(format!("serialize Responses request failed: {e}")))?;

    Ok(TranslatedRequest {
        target_path_and_query: "/responses".to_string(),
        body: Bytes::from(body),
        extra_headers: vec![("user-agent", "codex_cli_rs/0.1.0".to_string())],
        model,
        is_stream,
    })
}

/// Translate an Anthropic Messages (`/v1/messages`) request into an OpenAI Responses API
/// (`/responses`) request.
pub fn anthropic_to_responses_request(
    raw_body: &[u8],
    model_override: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    anthropic_to_responses_request_with_session(raw_body, model_override, None)
}

/// Same as `anthropic_to_responses_request`, propagating `metadata.user_id` (or `session_hint`)
/// into `prompt_cache_key`.
pub fn anthropic_to_responses_request_with_session(
    raw_body: &[u8],
    model_override: Option<&str>,
    session_hint: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    let req: Value = serde_json::from_slice(raw_body)
        .map_err(|e| GatewayError::InvalidRequest(format!("invalid Anthropic JSON body: {e}")))?;

    let model = model_override
        .map(ToOwned::to_owned)
        .or_else(|| req.get("model").and_then(Value::as_str).map(ToOwned::to_owned))
        .unwrap_or_else(|| "gpt-5-codex".to_string());

    let is_stream = req.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let instructions = match req.get("system") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::Array(arr)) => {
            let joined = arr
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n\n");
            if joined.is_empty() {
                "You are a helpful assistant.".to_string()
            } else {
                joined
            }
        }
        _ => "You are a helpful assistant.".to_string(),
    };

    let mut input_items = Vec::new();
    for message in req["messages"].as_array().into_iter().flatten() {
        let role = message["role"].as_str().unwrap_or("user");
        let text_type = if role == "assistant" {
            "output_text"
        } else {
            "input_text"
        };
        let mut content = Vec::new();
        let flush = |items: &mut Vec<Value>, content: &mut Vec<Value>| {
            if !content.is_empty() {
                items.push(
                    json!({"type": "message", "role": role, "content": std::mem::take(content)}),
                );
            }
        };
        match &message["content"] {
            Value::String(text) => content.push(json!({"type": text_type, "text": text})),
            Value::Array(blocks) => {
                for block in blocks {
                    match block["type"].as_str() {
                    Some("text") => content.push(json!({"type": text_type, "text": block["text"]})),
                    Some("image") => content.push(json!({"type": "input_image", "image_url": anthropic_image_url(block)?})),
                    Some("tool_use") => {
                        flush(&mut input_items, &mut content);
                        input_items.push(json!({
                            "type": "function_call", "call_id": anthropic_tool_id(block, "id")?,
                            "name": block["name"], "arguments": block["input"].to_string(),
                        }));
                    }
                    Some("tool_result") => {
                        flush(&mut input_items, &mut content);
                        input_items.push(json!({
                            "type": "function_call_output", "call_id": anthropic_tool_id(block, "tool_use_id")?,
                            "output": anthropic_tool_output(block)?,
                        }));
                    }
                    Some("thinking" | "redacted_thinking") => {}
                    kind => return Err(unsupported_anthropic_block(kind)),
                }
                }
            }
            _ => {}
        }
        flush(&mut input_items, &mut content);
    }

    let mut out = json!({
        "model": model,
        "instructions": instructions,
        "input": input_items,
        "stream": is_stream,
        "store": false,
    });

    let mut tools = anthropic_function_tools(&req)?;
    if !tools.is_empty() {
        for tool in &mut tools {
            tool["type"] = json!("function");
        }
        out["tools"] = json!(tools);
        let (choice, parallel) = anthropic_tool_choice(&req, true);
        if let Some(choice) = choice {
            out["tool_choice"] = choice;
        }
        if let Some(parallel) = parallel {
            out["parallel_tool_calls"] = json!(parallel);
        }
    }

    let claude_session = req
        .pointer("/metadata/user_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|uid| {
            if let Some(pos) = uid.find("_session_") {
                &uid[pos + 1..]
            } else {
                uid
            }
        });
    let cache_key = claude_session
        .or_else(|| session_hint.map(str::trim).filter(|s| !s.is_empty()));
    if let Some(key) = cache_key {
        out["prompt_cache_key"] = Value::String(key.to_string());
    }

    let body = serde_json::to_vec(&out)
        .map_err(|e| GatewayError::Internal(format!("serialize Responses request failed: {e}")))?;

    Ok(TranslatedRequest {
        target_path_and_query: "/responses".to_string(),
        body: Bytes::from(body),
        extra_headers: vec![("user-agent", "codex_cli_rs/0.1.0".to_string())],
        model,
        is_stream,
    })
}

/// Translate a non-streaming OpenAI Responses API JSON response into an OpenAI Chat Completions JSON response.
pub fn responses_to_openai_response(raw_body: &[u8], fallback_model: &str) -> Result<Bytes, GatewayError> {
    let resp = parse_responses_payload(raw_body)?;

    let id = resp
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("chatcmpl-ttt");
    let model = resp
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(fallback_model);

    let (text, tool_calls) = extract_responses_output(&resp);

    let input_tokens = resp
        .pointer("/usage/input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = resp
        .pointer("/usage/output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total_tokens = resp
        .pointer("/usage/total_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(input_tokens + output_tokens);

    let finish_reason = if !tool_calls.is_empty() {
        "tool_calls"
    } else {
        "stop"
    };

    let mut message = json!({
        "role": "assistant",
        "content": if text.is_empty() && !tool_calls.is_empty() { Value::Null } else { Value::String(text) },
    });
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(tool_calls);
    }

    let out = json!({
        "id": id,
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": total_tokens,
        }
    });

    serde_json::to_vec(&out)
        .map(Bytes::from)
        .map_err(|e| GatewayError::Internal(format!("serialize OpenAI response failed: {e}")))
}

/// Translate a non-streaming OpenAI Responses API JSON response into an Anthropic Messages JSON response.
pub fn responses_to_anthropic_response(raw_body: &[u8], fallback_model: &str) -> Result<Bytes, GatewayError> {
    let resp = parse_responses_payload(raw_body)?;

    let id = resp.get("id").and_then(Value::as_str).unwrap_or("msg_ttt");
    let model = resp
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(fallback_model);

    let (text, tool_calls) = extract_responses_output(&resp);
    let mut content = Vec::new();
    if !text.is_empty() {
        content.push(json!({ "type": "text", "text": text }));
    }
    for tc in &tool_calls {
        let tc_id = tc.get("id").and_then(Value::as_str).unwrap_or("toolu_0");
        let name = tc.pointer("/function/name").and_then(Value::as_str).unwrap_or("");
        let args_str = tc
            .pointer("/function/arguments")
            .and_then(Value::as_str)
            .unwrap_or("{}");
        let input: Value = serde_json::from_str(args_str).unwrap_or_else(|_| json!({}));
        content.push(json!({
            "type": "tool_use",
            "id": tc_id,
            "name": name,
            "input": input,
        }));
    }
    if content.is_empty() {
        content.push(json!({ "type": "text", "text": "" }));
    }

    let input_tokens = resp
        .pointer("/usage/input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = resp
        .pointer("/usage/output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let out = json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": if !tool_calls.is_empty() { "tool_use" } else { "end_turn" },
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }
    });

    serde_json::to_vec(&out)
        .map(Bytes::from)
        .map_err(|e| GatewayError::Internal(format!("serialize Anthropic response failed: {e}")))
}

fn parse_responses_payload(raw_body: &[u8]) -> Result<Value, GatewayError> {
    if let Ok(val) = serde_json::from_slice::<Value>(raw_body) {
        return Ok(val);
    }

    // Fallback: some Responses backends (e.g. Codex) may return SSE even for non-streaming requests.
    if let Ok(text) = std::str::from_utf8(raw_body) {
        let mut completed: Option<Value> = None;
        let mut acc_text = String::new();
        let mut resp_id = String::new();
        let mut model = String::new();
        for line in text.lines() {
            let trimmed = line.trim();
            let Some(payload) = trimmed.strip_prefix("data:") else {
                continue;
            };
            let payload = payload.trim();
            if payload.is_empty() || payload == "[DONE]" {
                continue;
            }
            let Ok(ev) = serde_json::from_str::<Value>(payload) else {
                continue;
            };
            match ev.get("type").and_then(Value::as_str) {
                Some("response.created") => {
                    if let Some(id) = ev.pointer("/response/id").and_then(Value::as_str) {
                        resp_id = id.to_string();
                    }
                    if let Some(m) = ev.pointer("/response/model").and_then(Value::as_str) {
                        model = m.to_string();
                    }
                }
                Some("response.output_text.delta") => {
                    if let Some(d) = ev.get("delta").and_then(Value::as_str) {
                        acc_text.push_str(d);
                    }
                }
                Some("response.completed") => {
                    if let Some(r) = ev.get("response") {
                        completed = Some(r.clone());
                    }
                }
                _ => {}
            }
        }
        if let Some(r) = completed {
            return Ok(r);
        }
        if !acc_text.is_empty() {
            return Ok(json!({
                "id": if resp_id.is_empty() { "resp_ttt" } else { &resp_id },
                "model": model,
                "output_text": acc_text,
            }));
        }
    }

    Err(GatewayError::Internal(
        "invalid Responses JSON response: failed to parse JSON or SSE payload".into(),
    ))
}

fn extract_responses_output(resp: &Value) -> (String, Vec<Value>) {
    let mut text = String::new();
    let mut tool_calls = Vec::new();

    if let Some(output) = resp.get("output").and_then(Value::as_array) {
        for item in output {
            match item.get("type").and_then(Value::as_str) {
                Some("message") => {
                    if let Some(parts) = item.get("content").and_then(Value::as_array) {
                        for p in parts {
                            if let Some(t) = p.get("text").and_then(Value::as_str) {
                                text.push_str(t);
                            }
                        }
                    }
                }
                Some("function_call") => {
                    let call_id = item
                        .get("call_id")
                        .or_else(|| item.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or("call_0");
                    let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                    let arguments = item.get("arguments").and_then(Value::as_str).unwrap_or("{}");
                    tool_calls.push(json!({
                        "id": call_id,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": arguments,
                        }
                    }));
                }
                _ => {}
            }
        }
    } else if let Some(out_text) = resp.get("output_text").and_then(Value::as_str) {
        text.push_str(out_text);
    }

    (text, tool_calls)
}

fn extract_text_content(val: Option<&Value>) -> String {
    match val {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|p| {
                p.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| p.as_str())
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn convert_user_content(val: Option<&Value>) -> Vec<Value> {
    match val {
        Some(Value::String(s)) => vec![json!({ "type": "input_text", "text": s })],
        Some(Value::Array(arr)) => {
            let mut out = Vec::new();
            for p in arr {
                match p.get("type").and_then(Value::as_str) {
                    Some("text") | Some("input_text") => {
                        if let Some(t) = p.get("text").and_then(Value::as_str) {
                            out.push(json!({ "type": "input_text", "text": t }));
                        }
                    }
                    Some("image_url") => {
                        if let Some(url) = p.pointer("/image_url/url").and_then(Value::as_str) {
                            out.push(json!({ "type": "input_image", "image_url": url }));
                        }
                    }
                    _ => {
                        if let Some(t) = p.get("text").and_then(Value::as_str) {
                            out.push(json!({ "type": "input_text", "text": t }));
                        }
                    }
                }
            }
            if out.is_empty() {
                out.push(json!({ "type": "input_text", "text": "" }));
            }
            out
        }
        _ => vec![json!({ "type": "input_text", "text": "" })],
    }
}
