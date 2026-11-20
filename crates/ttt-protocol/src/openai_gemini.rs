use bytes::Bytes;
use serde_json::{json, Map, Value};
use ttt_core::GatewayError;

use crate::openai_anthropic::extract_text_content;
use crate::TranslatedRequest;

/// Translate an OpenAI Chat Completions JSON request into a Google Gemini JSON request.
pub fn openai_to_gemini_request(
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
        .unwrap_or_else(|| "gemini-2.5-flash".to_string());
    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let mut system_parts: Vec<Value> = Vec::new();
    let mut contents: Vec<Value> = Vec::new();

    if let Some(messages) = obj.get("messages").and_then(Value::as_array) {
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
                    contents.push(json!({
                        "role": "model",
                        "parts": [{ "text": text }],
                    }));
                }
                _ => {
                    contents.push(json!({
                        "role": "user",
                        "parts": [{ "text": text }],
                    }));
                }
            }
        }
    }

    let mut out = Map::new();
    out.insert("contents".into(), Value::Array(contents));
    if !system_parts.is_empty() {
        out.insert(
            "systemInstruction".into(),
            json!({ "parts": system_parts }),
        );
    }

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
    if !gen_cfg.is_empty() {
        out.insert("generationConfig".into(), Value::Object(gen_cfg));
    }

    let target_path_and_query = if stream {
        format!("/models/{model}:streamGenerateContent?alt=sse")
    } else {
        format!("/models/{model}:generateContent")
    };

    let bytes = serde_json::to_vec(&Value::Object(out))
        .map_err(|e| GatewayError::Internal(format!("failed to encode Gemini request: {e}")))?;

    Ok(TranslatedRequest {
        target_path_and_query,
        body: Bytes::from(bytes),
        extra_headers: Vec::new(),
        model,
        is_stream: stream,
    })
}

/// Translate a Google Gemini JSON response into an OpenAI Chat Completions JSON response.
pub fn gemini_to_openai_response(raw: &[u8], model: &str) -> Result<Bytes, GatewayError> {
    let v: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::Internal(format!("invalid Gemini response JSON: {e}")))?;

    let text = extract_gemini_text(&v);
    let finish_reason = map_gemini_finish_reason(
        v.pointer("/candidates/0/finishReason")
            .and_then(Value::as_str),
    );

    let prompt_tokens = v
        .pointer("/usageMetadata/promptTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let completion_tokens = v
        .pointer("/usageMetadata/candidatesTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total_tokens = v
        .pointer("/usageMetadata/totalTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(prompt_tokens + completion_tokens);

    let out = json!({
        "id": "chatcmpl-gemini",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": text,
            },
            "finish_reason": finish_reason,
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }
    });

    serde_json::to_vec(&out)
        .map(Bytes::from)
        .map_err(|e| GatewayError::Internal(format!("failed to encode OpenAI response: {e}")))
}

pub(crate) fn extract_gemini_text(v: &Value) -> String {
    let mut out = String::new();
    if let Some(parts) = v
        .pointer("/candidates/0/content/parts")
        .and_then(Value::as_array)
    {
        for p in parts {
            if let Some(t) = p.get("text").and_then(Value::as_str) {
                out.push_str(t);
            }
        }
    }
    out
}

pub(crate) fn map_gemini_finish_reason(reason: Option<&str>) -> &'static str {
    match reason {
        Some("MAX_TOKENS") => "length",
        Some("SAFETY") | Some("RECITATION") => "content_filter",
        _ => "stop",
    }
}
