use std::collections::HashMap;

use bytes::Bytes;
use serde_json::{Map, Value, json};
use ttt_core::{GatewayError, RequestId};

use crate::TranslatedRequest;
use crate::openai_anthropic::extract_text_content;

/// Translate an OpenAI Chat Completions JSON request into a Google Gemini JSON request.
pub fn openai_to_gemini_request(
    raw: &[u8],
    model_override: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    let (model, stream, body) = openai_to_google_request(raw, model_override, false)?;
    let target_path_and_query = if stream {
        format!("/models/{model}:streamGenerateContent?alt=sse")
    } else {
        format!("/models/{model}:generateContent")
    };
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| GatewayError::Internal(format!("failed to encode Gemini request: {e}")))?;
    Ok(TranslatedRequest {
        target_path_and_query,
        body: Bytes::from(bytes),
        extra_headers: Vec::new(),
        model,
        is_stream: stream,
    })
}

pub(crate) fn openai_to_google_request(
    raw: &[u8],
    model_override: Option<&str>,
    antigravity: bool,
) -> Result<(String, bool, Value), GatewayError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::InvalidRequest(format!("invalid OpenAI JSON body: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| GatewayError::InvalidRequest("request body must be a JSON object".into()))?;

    let model = model_override
        .map(ToOwned::to_owned)
        .or_else(|| {
            obj.get("model")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "gemini-2.5-flash".to_string());
    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let messages = obj
        .get("messages")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let (contents, system_parts) = google_contents(messages, antigravity)?;
    let mut out = Map::new();
    out.insert("contents".into(), Value::Array(contents));
    if !system_parts.is_empty() {
        let mut system = json!({ "parts": system_parts });
        if antigravity {
            system["role"] = json!("user");
        }
        out.insert("systemInstruction".into(), system);
    }

    apply_google_tools(obj, antigravity, &mut out);

    let mut gen_cfg = Map::new();
    if let Some(max_tok) = obj
        .get("max_completion_tokens")
        .or_else(|| obj.get("max_tokens"))
    {
        gen_cfg.insert("maxOutputTokens".into(), max_tok.clone());
    }
    if let Some(temp) = obj.get("temperature") {
        gen_cfg.insert("temperature".into(), temp.clone());
    }
    if let Some(top_p) = obj.get("top_p") {
        gen_cfg.insert("topP".into(), top_p.clone());
    }
    if let Some(stop) = obj.get("stop") {
        let seqs = match stop {
            Value::String(s) => vec![Value::String(s.clone())],
            Value::Array(arr) => arr.clone(),
            _ => Vec::new(),
        };
        if !seqs.is_empty() {
            gen_cfg.insert("stopSequences".into(), Value::Array(seqs));
        }
    }
    if let Some(thinking) = v
        .pointer("/extra_body/google/thinking_config")
        .and_then(Value::as_object)
    {
        let config: Map<_, _> = [
            ("include_thoughts", "includeThoughts"),
            ("thinking_budget", "thinkingBudget"),
            ("thinking_level", "thinkingLevel"),
        ]
        .into_iter()
        .filter_map(|(from, to)| thinking.get(from).map(|value| (to.into(), value.clone())))
        .collect();
        if !config.is_empty() {
            gen_cfg.insert("thinkingConfig".into(), Value::Object(config));
        }
    }
    if !gen_cfg.is_empty() {
        out.insert("generationConfig".into(), Value::Object(gen_cfg));
    }

    Ok((model, stream, Value::Object(out)))
}

fn google_contents(
    messages: &[Value],
    antigravity: bool,
) -> Result<(Vec<Value>, Vec<Value>), GatewayError> {
    let mut system_parts: Vec<Value> = Vec::new();
    let mut contents: Vec<Value> = Vec::new();
    let mut tool_names = HashMap::new();
    let mut previous_was_tool = false;

    for msg in messages {
        let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
        let text = extract_text_content(msg.get("content")).unwrap_or_default();
        match role {
            "system" | "developer" => {
                if !text.is_empty() {
                    system_parts.push(json!({ "text": text }));
                }
            }
            "assistant" => {
                let mut parts = Vec::new();
                if !text.is_empty() {
                    parts.push(json!({ "text": text }));
                }
                for call in msg["tool_calls"].as_array().into_iter().flatten() {
                    let name = call
                        .pointer("/function/name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            GatewayError::InvalidRequest(
                                "tool call is missing a function name".into(),
                            )
                        })?;
                    let args = match call.pointer("/function/arguments").and_then(Value::as_str) {
                        Some(args) if !args.trim().is_empty() => {
                            serde_json::from_str::<Map<String, Value>>(args).map_err(|e| {
                                GatewayError::InvalidRequest(format!(
                                    "invalid arguments for function '{name}': {e}"
                                ))
                            })?
                        }
                        _ => Map::new(),
                    };
                    let mut part = json!({"functionCall": {"name": name, "args": args}});
                    if let Some(id) = call["id"].as_str() {
                        tool_names.insert(id, name);
                        part["functionCall"]["id"] = json!(id);
                    }
                    if let Some(signature) = call
                        .pointer("/extra_content/google/thought_signature")
                        .and_then(Value::as_str)
                    {
                        part["thoughtSignature"] = json!(signature);
                    }
                    parts.push(part);
                }
                if parts.is_empty() {
                    parts.push(json!({ "text": text }));
                }
                contents.push(json!({
                    "role": "model",
                    "parts": parts,
                }));
            }
            "tool" => {
                let id = msg["tool_call_id"].as_str();
                let name = id
                    .and_then(|id| tool_names.get(id).copied())
                    .or_else(|| msg["name"].as_str())
                    .ok_or_else(|| {
                        GatewayError::InvalidRequest(
                            "tool result is missing its matching function call".into(),
                        )
                    })?;
                let mut part =
                    json!({"functionResponse": {"name": name, "response": {"output": text}}});
                if let Some(id) = id {
                    part["functionResponse"]["id"] = json!(id);
                }
                if let Some(parts) = contents
                    .last_mut()
                    .and_then(|turn| turn["parts"].as_array_mut())
                    && previous_was_tool
                {
                    parts.push(part);
                } else {
                    let tool_result_role = if antigravity { "model" } else { "user" };
                    contents.push(json!({"role": tool_result_role, "parts": [part]}));
                }
            }
            _ => {
                contents.push(json!({
                    "role": "user",
                    "parts": [{ "text": text }],
                }));
            }
        }
        previous_was_tool = role == "tool";
    }
    Ok((contents, system_parts))
}

fn apply_google_tools(obj: &Map<String, Value>, antigravity: bool, out: &mut Map<String, Value>) {
    let declarations: Vec<_> = obj
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|tool| {
            let function = tool.get("function")?;
            let name = function["name"].as_str()?;
            let mut declaration = json!({"name": name});
            if let Some(description) = function["description"].as_str() {
                declaration["description"] = json!(description);
            }
            if let Some(parameters) = function
                .get("parameters")
                .filter(|schema| schema.is_object())
            {
                if antigravity {
                    declaration["parameters"] = antigravity_tool_schema(parameters);
                } else {
                    declaration["parametersJsonSchema"] = parameters.clone();
                }
            }
            Some(declaration)
        })
        .collect();
    if declarations.is_empty() {
        return;
    }
    out.insert(
        "tools".into(),
        json!([{"functionDeclarations": declarations}]),
    );
    let tool_choice = obj.get("tool_choice").unwrap_or(&Value::Null);
    let config = match tool_choice.as_str() {
        Some("none") => Some(json!({"mode": "NONE"})),
        Some("auto") => Some(json!({"mode": "AUTO"})),
        Some("required") => Some(json!({"mode": "ANY"})),
        _ => tool_choice
            .pointer("/function/name")
            .and_then(Value::as_str)
            .map(|name| json!({"mode": "ANY", "allowedFunctionNames": [name]})),
    };
    if let Some(config) = config {
        out.insert(
            "toolConfig".into(),
            json!({"functionCallingConfig": config}),
        );
    }
}

fn antigravity_tool_schema(schema: &Value) -> Value {
    let Some(fields) = schema.as_object() else {
        return json!({});
    };
    let mut mapped = Map::new();
    for (key, value) in fields {
        match key.as_str() {
            "type" => {
                if let Some(kind) = value.as_str() {
                    mapped.insert(key.clone(), json!(kind.to_ascii_uppercase()));
                } else if let Some(kinds) = value.as_array() {
                    mapped.insert(
                        "anyOf".into(),
                        json!(
                            kinds
                                .iter()
                                .filter_map(Value::as_str)
                                .map(|kind| json!({"type": kind.to_ascii_uppercase()}))
                                .collect::<Vec<_>>()
                        ),
                    );
                }
            }
            "properties" => {
                if let Some(properties) = value.as_object() {
                    mapped.insert(
                        key.clone(),
                        Value::Object(
                            properties
                                .iter()
                                .map(|(name, schema)| {
                                    (name.clone(), antigravity_tool_schema(schema))
                                })
                                .collect(),
                        ),
                    );
                }
            }
            "items" if value.is_object() => {
                mapped.insert(key.clone(), antigravity_tool_schema(value));
            }
            "anyOf" | "oneOf" if value.is_array() => {
                mapped.insert(
                    "anyOf".into(),
                    json!(
                        value
                            .as_array()
                            .into_iter()
                            .flatten()
                            .map(antigravity_tool_schema)
                            .collect::<Vec<_>>()
                    ),
                );
            }
            "description" | "title" | "format" | "enum" | "required" | "nullable" | "default"
            | "minimum" | "maximum" | "minItems" | "maxItems" | "minLength" | "maxLength"
            | "minProperties" | "maxProperties" | "pattern" => {
                mapped.insert(key.clone(), value.clone());
            }
            _ => {}
        }
    }
    if mapped.contains_key("items") {
        mapped.insert("type".into(), json!("ARRAY"));
    } else if mapped.contains_key("properties") {
        mapped.entry("type").or_insert(json!("OBJECT"));
    }
    Value::Object(mapped)
}

/// Translate a Google Gemini JSON response into an OpenAI Chat Completions JSON response.
pub fn gemini_to_openai_response(raw: &[u8], model: &str) -> Result<Bytes, GatewayError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::Internal(format!("invalid Gemini response JSON: {e}")))?;
    google_to_openai_response(&v, model)
}

pub(crate) fn google_to_openai_response(v: &Value, model: &str) -> Result<Bytes, GatewayError> {
    if let Some(error) = v.get("error") {
        let message = error["message"].as_str().or_else(|| error.as_str());
        return Err(GatewayError::UpstreamConnect(
            message
                .unwrap_or("Google returned an error response")
                .into(),
        ));
    }
    let id = google_completion_id(v);
    let mut next_call = 0;
    let mut message = google_candidate_delta(v, &id, &mut next_call, false);
    message["role"] = json!("assistant");
    if message.get("content").is_none() {
        message["content"] = if next_call == 0 {
            json!("")
        } else {
            Value::Null
        };
    }
    let finish_reason = google_finish_reason(v, next_call != 0).unwrap_or(if next_call != 0 {
        "tool_calls"
    } else {
        "stop"
    });

    let out = json!({
        "id": id,
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": google_usage(&v["usageMetadata"]),
    });

    serde_json::to_vec(&out)
        .map(Bytes::from)
        .map_err(|e| GatewayError::Internal(format!("failed to encode OpenAI response: {e}")))
}

pub(crate) fn google_completion_id(v: &Value) -> String {
    v["responseId"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(|id| format!("chatcmpl-{id}"))
        .unwrap_or_else(|| format!("chatcmpl-google-{}", RequestId::next().0))
}

pub(crate) fn google_usage(metadata: &Value) -> Value {
    let prompt_tokens = metadata["promptTokenCount"].as_u64().unwrap_or(0);
    let answer_tokens = metadata["candidatesTokenCount"].as_u64().unwrap_or(0);
    let reasoning_tokens = metadata["thoughtsTokenCount"].as_u64();
    let completion_tokens = answer_tokens.saturating_add(reasoning_tokens.unwrap_or(0));
    let total_tokens = metadata["totalTokenCount"]
        .as_u64()
        .unwrap_or_else(|| prompt_tokens.saturating_add(completion_tokens));
    let mut usage = json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    });
    if let Some(cached) = metadata["cachedContentTokenCount"].as_u64() {
        usage["prompt_tokens_details"] = json!({"cached_tokens": cached});
    }
    if let Some(reasoning) = reasoning_tokens {
        usage["completion_tokens_details"] = json!({"reasoning_tokens": reasoning});
    }
    usage
}

pub(crate) fn google_candidate_delta(
    v: &Value,
    id: &str,
    next_call: &mut usize,
    streaming: bool,
) -> Value {
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut tool_calls = Vec::new();
    if let Some(parts) = v
        .pointer("/candidates/0/content/parts")
        .and_then(Value::as_array)
    {
        for part in parts {
            if let Some(text) = part["text"].as_str() {
                if part["thought"].as_bool() == Some(true) {
                    reasoning.push_str(text);
                } else {
                    content.push_str(text);
                }
            }
            let call = &part["functionCall"];
            if let Some(name) = call["name"].as_str() {
                let call_id = call["id"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("call_{id}_{next_call}"));
                let arguments = call
                    .get("args")
                    .map(Value::to_string)
                    .unwrap_or_else(|| "{}".to_owned());
                let mut tool_call = json!({
                    "id": call_id, "type": "function",
                    "function": {"name": name, "arguments": arguments},
                });
                if let Some(signature) = part["thoughtSignature"]
                    .as_str()
                    .or_else(|| part["thought_signature"].as_str())
                {
                    tool_call["extra_content"] =
                        json!({"google": {"thought_signature": signature}});
                }
                if streaming {
                    tool_call["index"] = json!(*next_call);
                }
                *next_call += 1;
                tool_calls.push(tool_call);
            }
        }
    }
    let mut delta = json!({});
    if !content.is_empty() {
        delta["content"] = json!(content);
    }
    if !reasoning.is_empty() {
        delta["reasoning_content"] = json!(reasoning);
    }
    if !tool_calls.is_empty() {
        delta["tool_calls"] = json!(tool_calls);
    }
    delta
}

pub(crate) fn google_finish_reason(v: &Value, has_tools: bool) -> Option<&'static str> {
    if v.pointer("/promptFeedback/blockReason")
        .and_then(Value::as_str)
        .is_some_and(|reason| reason != "BLOCK_REASON_UNSPECIFIED")
    {
        return Some("content_filter");
    }
    let reason = v
        .pointer("/candidates/0/finishReason")
        .and_then(Value::as_str)?;
    match reason {
        "FINISH_REASON_UNSPECIFIED" => None,
        "MAX_TOKENS" => Some("length"),
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" => {
            Some("content_filter")
        }
        "STOP" if has_tools => Some("tool_calls"),
        _ => Some("stop"),
    }
}
