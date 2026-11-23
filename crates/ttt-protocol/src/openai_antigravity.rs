use bytes::Bytes;
use serde_json::{json, Value};
use ttt_core::{ANTIGRAVITY_USER_AGENT, GatewayError};

use crate::openai_gemini;
use crate::TranslatedRequest;

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
    let gemini_req = openai_gemini::openai_to_gemini_request(raw, model_override)?;
    let inner: Value = serde_json::from_slice(&gemini_req.body)
        .map_err(|e| GatewayError::Internal(format!("invalid translated gemini body: {e}")))?;

    let wrapped = json!({
        "project": project_id,
        "model": gemini_req.model,
        "userAgent": "antigravity",
        "requestType": "agent",
        "request": inner,
    });
    let body = Bytes::from(serde_json::to_vec(&wrapped).map_err(|e| {
        GatewayError::Internal(format!("failed to encode antigravity request: {e}"))
    })?);

    let target_path_and_query = if gemini_req.is_stream {
        "/v1internal:streamGenerateContent?alt=sse".to_string()
    } else {
        "/v1internal:generateContent".to_string()
    };

    Ok(TranslatedRequest {
        target_path_and_query,
        body,
        extra_headers: vec![
            ("user-agent", ANTIGRAVITY_USER_AGENT.to_string()),
            (
                "x-goog-api-client",
                "google-cloud-sdk vscode_cloudshelleditor/0.1".to_string(),
            ),
        ],
        model: gemini_req.model,
        is_stream: gemini_req.is_stream,
    })
}

/// Translate a non-streaming Antigravity `v1internal:generateContent` JSON response to OpenAI format.
pub fn antigravity_to_openai_response(raw: &[u8], model: &str) -> Result<Bytes, GatewayError> {
    let val: Value = serde_json::from_slice(raw)
        .map_err(|e| GatewayError::Internal(format!("invalid antigravity JSON response: {e}")))?;
    if let Some(inner) = val.get("response") {
        let inner_bytes = serde_json::to_vec(inner)
            .map_err(|e| GatewayError::Internal(format!("failed to re-encode response: {e}")))?;
        openai_gemini::gemini_to_openai_response(&inner_bytes, model)
    } else {
        openai_gemini::gemini_to_openai_response(raw, model)
    }
}
