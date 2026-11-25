use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde_json::{Value, json};
use ttt_core::{ANTIGRAVITY_USER_AGENT, GatewayError, RequestId};

use crate::TranslatedRequest;
use crate::openai_gemini;

/// Translate an OpenAI Chat Completions request into a Google Antigravity `v1internal` request.
pub fn openai_to_antigravity_request(
    raw: &[u8],
    model_override: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    openai_to_antigravity_project_request(raw, model_override, "")
}

pub fn openai_to_antigravity_project_request(
    raw: &[u8],
    model_override: Option<&str>,
    project_id: &str,
) -> Result<TranslatedRequest, GatewayError> {
    openai_to_antigravity_session_request(raw, model_override, project_id, None)
}

pub fn openai_to_antigravity_session_request(
    raw: &[u8],
    model_override: Option<&str>,
    project_id: &str,
    session_id: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    let (model, stream, mut request) =
        openai_gemini::openai_to_google_request(raw, model_override, true)?;
    let session = session_id.filter(|id| !id.is_empty()).map(|id| {
        let mut hash = DefaultHasher::new();
        (project_id, id).hash(&mut hash);
        let hash = hash.finish();
        request["sessionId"] = json!((hash as i64).to_string());
        hash
    });
    let is_agent = request.get("tools").is_some()
        || request["contents"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|turn| turn["parts"].as_array().into_iter().flatten())
            .any(|part| {
                part.get("functionCall").is_some() || part.get("functionResponse").is_some()
            });
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let sequence = RequestId::next().0;
    let conversation = session.unwrap_or(sequence);
    let step = request["contents"].as_array().map_or(0, Vec::len);

    let mut wrapped = json!({
        "project": project_id,
        "model": model,
        "userAgent": "antigravity",
        "requestId": format!("agent/{conversation:016x}/{time}/{sequence:x}/{step}"),
        "request": request,
    });
    if is_agent {
        wrapped["requestType"] = json!("agent");
    }
    let body = Bytes::from(serde_json::to_vec(&wrapped).map_err(|e| {
        GatewayError::Internal(format!("failed to encode antigravity request: {e}"))
    })?);

    let target_path_and_query = if stream {
        "/v1internal:streamGenerateContent?alt=sse".to_string()
    } else {
        "/v1internal:generateContent".to_string()
    };

    Ok(TranslatedRequest {
        target_path_and_query,
        body,
        extra_headers: vec![("user-agent", ANTIGRAVITY_USER_AGENT.to_string())],
        model,
        is_stream: stream,
    })
}

/// Translate a non-streaming Antigravity `v1internal:generateContent` JSON response to OpenAI format.
pub fn antigravity_to_openai_response(raw: &[u8], model: &str) -> Result<Bytes, GatewayError> {
    let val: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::Internal(format!("invalid antigravity JSON response: {e}")))?;
    openai_gemini::google_to_openai_response(val.get("response").unwrap_or(&val), model)
}
