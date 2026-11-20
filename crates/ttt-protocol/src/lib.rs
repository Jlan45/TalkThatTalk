pub mod openai_anthropic;
pub mod openai_gemini;
pub mod openai_responses;
pub mod stream;

use bytes::Bytes;
use ttt_core::{GatewayError, ProtocolFamily};

pub use stream::{SseTranslator, TranslatedStreamBody};

/// Output of translating a client request into a different upstream protocol family.
#[derive(Debug, Clone)]
pub struct TranslatedRequest {
    pub target_path_and_query: String,
    pub body: Bytes,
    pub extra_headers: Vec<(&'static str, String)>,
    pub model: String,
    pub is_stream: bool,
}

/// Detect the incoming client protocol family from the request path.
#[inline]
pub fn detect_ingress_protocol(path: &str) -> Option<ProtocolFamily> {
    if path.ends_with("/chat/completions") {
        Some(ProtocolFamily::OpenAi)
    } else if path.ends_with("/responses") {
        Some(ProtocolFamily::OpenAiResponses)
    } else if path.ends_with("/messages") {
        Some(ProtocolFamily::Anthropic)
    } else if path.contains(":generateContent") || path.contains(":streamGenerateContent") {
        Some(ProtocolFamily::Gemini)
    } else {
        None
    }
}

/// Returns true if a cross-protocol translation pair is supported by `ttt-protocol`.
#[inline]
pub fn needs_translation(ingress: ProtocolFamily, upstream: ProtocolFamily) -> bool {
    ingress != upstream
}

/// Translate a client request body from `ingress` protocol family to `upstream` protocol family.
pub fn translate_request(
    ingress: ProtocolFamily,
    upstream: ProtocolFamily,
    raw_body: &[u8],
    model_override: Option<&str>,
) -> Result<TranslatedRequest, GatewayError> {
    match (ingress, upstream) {
        (ProtocolFamily::OpenAi, ProtocolFamily::Anthropic) => {
            openai_anthropic::openai_to_anthropic_request(raw_body, model_override)
        }
        (ProtocolFamily::OpenAi, ProtocolFamily::Gemini) => {
            openai_gemini::openai_to_gemini_request(raw_body, model_override)
        }
        (ProtocolFamily::OpenAi, ProtocolFamily::OpenAiResponses) => {
            openai_responses::openai_to_responses_request(raw_body, model_override)
        }
        (ProtocolFamily::Anthropic, ProtocolFamily::OpenAiResponses) => {
            openai_responses::anthropic_to_responses_request(raw_body, model_override)
        }
        (ProtocolFamily::Anthropic, ProtocolFamily::OpenAi) => {
            openai_anthropic::anthropic_to_openai_request(raw_body, model_override)
        }
        _ => Err(GatewayError::InvalidRequest(format!(
            "unsupported cross-protocol translation: {:?} -> {:?}",
            ingress, upstream
        ))),
    }
}

/// Translate a non-streaming upstream JSON response back into `ingress` protocol family.
pub fn translate_response_json(
    ingress: ProtocolFamily,
    upstream: ProtocolFamily,
    raw_body: &[u8],
    model: &str,
) -> Result<Bytes, GatewayError> {
    match (ingress, upstream) {
        (ProtocolFamily::OpenAi, ProtocolFamily::Anthropic) => {
            openai_anthropic::anthropic_to_openai_response(raw_body)
        }
        (ProtocolFamily::OpenAi, ProtocolFamily::Gemini) => {
            openai_gemini::gemini_to_openai_response(raw_body, model)
        }
        (ProtocolFamily::OpenAi, ProtocolFamily::OpenAiResponses) => {
            openai_responses::responses_to_openai_response(raw_body, model)
        }
        (ProtocolFamily::Anthropic, ProtocolFamily::OpenAiResponses) => {
            openai_responses::responses_to_anthropic_response(raw_body, model)
        }
        (ProtocolFamily::Anthropic, ProtocolFamily::OpenAi) => {
            openai_anthropic::openai_to_anthropic_response(raw_body)
        }
        _ => Err(GatewayError::Internal(format!(
            "unsupported cross-protocol response translation: {:?} <- {:?}",
            ingress, upstream
        ))),
    }
}

/// Create an incremental SSE state-machine translator for streaming cross-protocol responses.
pub fn create_sse_translator(
    ingress: ProtocolFamily,
    upstream: ProtocolFamily,
    model: String,
) -> Result<SseTranslator, GatewayError> {
    match (ingress, upstream) {
        (ProtocolFamily::OpenAi, ProtocolFamily::Anthropic) => {
            Ok(SseTranslator::anthropic_to_openai(model))
        }
        (ProtocolFamily::OpenAi, ProtocolFamily::Gemini) => {
            Ok(SseTranslator::gemini_to_openai(model))
        }
        (ProtocolFamily::OpenAi, ProtocolFamily::OpenAiResponses) => {
            Ok(SseTranslator::responses_to_openai(model))
        }
        (ProtocolFamily::Anthropic, ProtocolFamily::OpenAiResponses) => {
            Ok(SseTranslator::responses_to_anthropic(model))
        }
        (ProtocolFamily::Anthropic, ProtocolFamily::OpenAi) => {
            Ok(SseTranslator::openai_to_anthropic(model))
        }
        _ => Err(GatewayError::Internal(format!(
            "unsupported cross-protocol SSE translation: {:?} <- {:?}",
            ingress, upstream
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn openai_to_anthropic_roundtrip() {
        let req = br#"{"model":"claude-sonnet-4","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi"}],"max_tokens":128}"#;
        let translated = translate_request(
            ProtocolFamily::OpenAi,
            ProtocolFamily::Anthropic,
            req,
            Some("claude-sonnet-4-20250514"),
        )
        .unwrap();
        assert_eq!(translated.target_path_and_query, "/messages");
        let parsed: serde_json::Value = serde_json::from_slice(&translated.body).unwrap();
        assert_eq!(parsed["model"], "claude-sonnet-4-20250514");
        assert_eq!(parsed["system"], "be brief");
        assert_eq!(parsed["max_tokens"], 128);

        let ant_resp = br#"{"id":"msg_1","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"hello!"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":5}}"#;
        let oai_resp = translate_response_json(
            ProtocolFamily::OpenAi,
            ProtocolFamily::Anthropic,
            ant_resp,
            "claude-sonnet-4-20250514",
        )
        .unwrap();
        let oai_val: serde_json::Value = serde_json::from_slice(&oai_resp).unwrap();
        assert_eq!(oai_val["choices"][0]["message"]["content"], "hello!");
        assert_eq!(oai_val["usage"]["total_tokens"], 15);
    }

    #[test]
    fn openai_to_gemini_roundtrip() {
        let req = br#"{"model":"gemini-2.5-flash","messages":[{"role":"user","content":"ping"}],"stream":true}"#;
        let translated =
            translate_request(ProtocolFamily::OpenAi, ProtocolFamily::Gemini, req, None).unwrap();
        assert_eq!(
            translated.target_path_and_query,
            "/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );
        assert!(translated.is_stream);

        let mut tr =
            create_sse_translator(ProtocolFamily::OpenAi, ProtocolFamily::Gemini, "gemini-2.5-flash".into())
                .unwrap();
        let mut out = VecDeque::new();
        tr.on_data_line(
            r#"{"candidates":[{"content":{"parts":[{"text":"pong"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":2}}"#,
            &mut out,
        );
        let joined: String = out
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert!(joined.contains("pong"));
        assert!(joined.contains("[DONE]"));
    }

    #[test]
    fn anthropic_to_openai_sse_translation() {
        let mut tr = create_sse_translator(
            ProtocolFamily::Anthropic,
            ProtocolFamily::OpenAi,
            "gpt-4o".into(),
        )
        .unwrap();
        let mut out = VecDeque::new();
        tr.on_data_line(
            r#"{"id":"chatcmpl-1","model":"gpt-4o","choices":[{"delta":{"content":"hi"},"finish_reason":null}]}"#,
            &mut out,
        );
        tr.on_data_line("[DONE]", &mut out);
        let joined: String = out
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert!(joined.contains("event: message_start"));
        assert!(joined.contains("event: content_block_delta"));
        assert!(joined.contains("event: message_stop"));
    }

    #[test]
    fn openai_to_responses_roundtrip_and_sse() {
        let req = br#"{"model":"gpt-5-codex","messages":[{"role":"system","content":"be concise"},{"role":"user","content":"hello"}],"stream":true}"#;
        let translated = translate_request(
            ProtocolFamily::OpenAi,
            ProtocolFamily::OpenAiResponses,
            req,
            None,
        )
        .unwrap();
        assert_eq!(translated.target_path_and_query, "/responses");
        assert!(translated.is_stream);
        let parsed: serde_json::Value = serde_json::from_slice(&translated.body).unwrap();
        assert_eq!(parsed["model"], "gpt-5-codex");
        assert_eq!(parsed["instructions"], "be concise");
        assert_eq!(parsed["store"], false);
        assert_eq!(parsed["input"][0]["role"], "user");

        let mut tr = create_sse_translator(
            ProtocolFamily::OpenAi,
            ProtocolFamily::OpenAiResponses,
            "gpt-5-codex".into(),
        )
        .unwrap();
        let mut out = VecDeque::new();
        tr.on_data_line(
            r#"{"type":"response.created","response":{"id":"resp_1","model":"gpt-5-codex"}}"#,
            &mut out,
        );
        tr.on_data_line(
            r#"{"type":"response.output_text.delta","delta":"world"}"#,
            &mut out,
        );
        tr.on_data_line(
            r#"{"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":5,"output_tokens":3,"total_tokens":8}}}"#,
            &mut out,
        );
        let joined: String = out
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert!(joined.contains("world"));
        assert!(joined.contains("total_tokens"));
        assert!(joined.contains("[DONE]"));
    }
}
