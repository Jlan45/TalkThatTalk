use serde::Deserialize;

/// Unified token usage extracted off the hot path by the async Tap worker.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TokenUsage {
    /// Normalized total input tokens (for Anthropic, already includes cache_read + cache_write).
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

impl TokenUsage {
    pub fn is_empty(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.total_tokens == 0
            && self.cache_read_tokens == 0
            && self.cache_write_tokens == 0
    }
}

/// Incremental line-based SSE / JSON usage extractor supporting:
/// - OpenAI Chat / DeepSeek / Volcengine / Qwen / OpenRouter
///   (`usage.prompt_tokens`, `prompt_tokens_details.cached_tokens`, `prompt_cache_hit_tokens`)
/// - OpenAI Responses / Codex (`usage.input_tokens`, `input_tokens_details.cached_tokens`)
/// - Anthropic / Claude Code (`message_start` / `message_delta`, normalizing additive
///   `input_tokens + cache_read_input_tokens + cache_creation_input_tokens`)
/// - Google Gemini / Antigravity (`usageMetadata.promptTokenCount`, `cachedContentTokenCount`)
#[derive(Debug, Default)]
pub struct UsageAccumulator {
    buf: Vec<u8>,
    base_input_tokens: u64,
    is_anthropic_additive: bool,
    pub usage: TokenUsage,
}

impl UsageAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a raw `Bytes` chunk from `TapEvent::ResponseChunk`.
    /// Only inspects lines that contain `"usage"` or `"usageMetadata"` to keep CPU overhead near zero.
    pub fn push_chunk(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);

        while let Some(pos) = memchr::memchr(b'\n', &self.buf) {
            let line = self.buf[..pos].to_vec();
            self.buf.drain(..=pos);
            self.inspect_line(&line);
        }
    }

    /// Flush any remaining buffered JSON (e.g. non-streaming responses without trailing newline)
    /// and finalize normalized token counts.
    pub fn finish(&mut self) -> TokenUsage {
        if !self.buf.is_empty() {
            let tail = std::mem::take(&mut self.buf);
            self.inspect_line(&tail);
        }

        if self.is_anthropic_additive {
            self.usage.input_tokens = self
                .base_input_tokens
                .saturating_add(self.usage.cache_read_tokens)
                .saturating_add(self.usage.cache_write_tokens);
        } else {
            self.usage.input_tokens = self.base_input_tokens;
            self.usage.cache_read_tokens = self.usage.cache_read_tokens.min(self.usage.input_tokens);
        }

        let io_sum = self.usage.input_tokens.saturating_add(self.usage.output_tokens);
        if (self.usage.total_tokens == 0 && io_sum > 0)
            || (self.is_anthropic_additive && self.usage.total_tokens < io_sum)
        {
            self.usage.total_tokens = io_sum;
        }

        self.usage.clone()
    }

    fn inspect_line(&mut self, raw_line: &[u8]) {
        // Fast reject: skip ~99% of SSE delta chunks that don't mention "usage" or "usageMetadata".
        if memchr::memmem::find(raw_line, b"\"usage\"").is_none()
            && memchr::memmem::find(raw_line, b"\"usageMetadata\"").is_none()
        {
            return;
        }

        let Ok(line_str) = std::str::from_utf8(raw_line) else {
            return;
        };
        let trimmed = line_str.trim();
        let json_str = trimmed.strip_prefix("data:").map(str::trim).unwrap_or(trimmed);
        if json_str.is_empty() || json_str == "[DONE]" {
            return;
        }

        if let Ok(envelope) = serde_json::from_str::<UsageEnvelope>(json_str) {
            if let Some(u) = envelope.usage {
                self.merge(u);
            }
            if let Some(gm) = envelope.usage_metadata {
                self.merge_gemini(gm);
            }
            if let Some(msg) = envelope.message {
                if let Some(u) = msg.usage {
                    self.merge(u);
                }
                if let Some(gm) = msg.usage_metadata {
                    self.merge_gemini(gm);
                }
            }
            if let Some(resp) = envelope.response {
                if let Some(u) = resp.usage {
                    self.merge(u);
                }
                if let Some(gm) = resp.usage_metadata {
                    self.merge_gemini(gm);
                }
            }
        }
    }

    fn merge(&mut self, u: RawUsage) {
        if let Some(v) = u.prompt_tokens.or(u.input_tokens) {
            self.base_input_tokens = v;
        }
        if let Some(v) = u.completion_tokens.or(u.output_tokens) {
            self.usage.output_tokens = v;
        }
        if let Some(v) = u.total_tokens {
            self.usage.total_tokens = v;
        }
        if let Some(v) = u
            .prompt_tokens_details
            .and_then(|d| d.cached_tokens)
            .or_else(|| u.input_tokens_details.and_then(|d| d.cached_tokens))
            .or(u.prompt_cache_hit_tokens)
        {
            self.usage.cache_read_tokens = v;
        }
        if let Some(v) = u.cache_read_input_tokens {
            self.is_anthropic_additive = true;
            self.usage.cache_read_tokens = v;
        }
        if let Some(v) = u.cache_creation_input_tokens {
            self.is_anthropic_additive = true;
            self.usage.cache_write_tokens = v;
        }
    }

    fn merge_gemini(&mut self, g: GeminiUsageMetadata) {
        if let Some(v) = g.prompt_token_count {
            self.base_input_tokens = v;
        }
        if let Some(v) = g.candidates_token_count {
            self.usage.output_tokens = v;
        }
        if let Some(v) = g.total_token_count {
            self.usage.total_tokens = v;
        }
        if let Some(v) = g.cached_content_token_count {
            self.usage.cache_read_tokens = v;
        }
    }
}

#[derive(Deserialize)]
struct UsageEnvelope {
    usage: Option<RawUsage>,
    #[serde(rename = "usageMetadata")]
    usage_metadata: Option<GeminiUsageMetadata>,
    message: Option<NestedUsage>,
    response: Option<NestedUsage>,
}

#[derive(Deserialize)]
struct NestedUsage {
    usage: Option<RawUsage>,
    #[serde(rename = "usageMetadata")]
    usage_metadata: Option<GeminiUsageMetadata>,
}

#[derive(Deserialize)]
struct TokenDetails {
    cached_tokens: Option<u64>,
}

#[derive(Deserialize)]
struct RawUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    prompt_tokens_details: Option<TokenDetails>,
    input_tokens_details: Option<TokenDetails>,
    prompt_cache_hit_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeminiUsageMetadata {
    prompt_token_count: Option<u64>,
    candidates_token_count: Option<u64>,
    total_token_count: Option<u64>,
    cached_content_token_count: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_openai_and_codex_sse_usage() {
        let mut acc = UsageAccumulator::new();
        acc.push_chunk(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n");
        acc.push_chunk(
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":120,\"completion_tokens\":45,\"total_tokens\":165}}\n\n",
        );
        acc.push_chunk(b"data: [DONE]\n\n");

        let usage = acc.finish();
        assert_eq!(
            usage,
            TokenUsage {
                input_tokens: 120,
                output_tokens: 45,
                total_tokens: 165,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            }
        );
    }

    #[test]
    fn extracts_claude_code_anthropic_sse_usage() {
        let mut acc = UsageAccumulator::new();
        acc.push_chunk(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":200,\"output_tokens\":1}}}\n\n",
        );
        acc.push_chunk(
            b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hello\"}}\n\n",
        );
        acc.push_chunk(
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":88}}\n\n",
        );

        let usage = acc.finish();
        assert_eq!(
            usage,
            TokenUsage {
                input_tokens: 200,
                output_tokens: 88,
                total_tokens: 288,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            }
        );
    }

    #[test]
    fn extracts_openai_chat_responses_and_deepseek_cached_tokens() {
        // OpenAI Chat: prompt_tokens already includes cached_tokens (80%)
        let mut oai = UsageAccumulator::new();
        oai.push_chunk(
            br#"{"usage":{"prompt_tokens":100000,"completion_tokens":500,"total_tokens":100500,"prompt_tokens_details":{"cached_tokens":80000}}}"#,
        );
        assert_eq!(
            oai.finish(),
            TokenUsage {
                input_tokens: 100_000,
                output_tokens: 500,
                total_tokens: 100_500,
                cache_read_tokens: 80_000,
                cache_write_tokens: 0,
            }
        );

        // OpenAI Responses / Codex SSE: input_tokens_details.cached_tokens (90%)
        let mut resp = UsageAccumulator::new();
        resp.push_chunk(
            b"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":50000,\"output_tokens\":300,\"total_tokens\":50300,\"input_tokens_details\":{\"cached_tokens\":45000}}}}\n\n",
        );
        assert_eq!(
            resp.finish(),
            TokenUsage {
                input_tokens: 50_000,
                output_tokens: 300,
                total_tokens: 50_300,
                cache_read_tokens: 45_000,
                cache_write_tokens: 0,
            }
        );

        // DeepSeek legacy prompt_cache_hit_tokens
        let mut ds = UsageAccumulator::new();
        ds.push_chunk(
            br#"{"usage":{"prompt_tokens":10000,"completion_tokens":100,"total_tokens":10100,"prompt_cache_hit_tokens":7500}}"#,
        );
        assert_eq!(
            ds.finish(),
            TokenUsage {
                input_tokens: 10_000,
                output_tokens: 100,
                total_tokens: 10_100,
                cache_read_tokens: 7_500,
                cache_write_tokens: 0,
            }
        );
    }

    #[test]
    fn normalizes_anthropic_additive_cache_tokens() {
        let mut acc = UsageAccumulator::new();
        acc.push_chunk(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":2000,\"cache_creation_input_tokens\":3000,\"cache_read_input_tokens\":95000,\"output_tokens\":1}}}\n\n",
        );
        acc.push_chunk(
            b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":500}}\n\n",
        );
        assert_eq!(
            acc.finish(),
            TokenUsage {
                input_tokens: 100_000,
                output_tokens: 500,
                total_tokens: 100_500,
                cache_read_tokens: 95_000,
                cache_write_tokens: 3_000,
            }
        );
    }

    #[test]
    fn extracts_gemini_and_antigravity_cached_content_tokens() {
        let mut gem = UsageAccumulator::new();
        gem.push_chunk(
            br#"{"usageMetadata":{"promptTokenCount":20000,"candidatesTokenCount":200,"totalTokenCount":20200,"cachedContentTokenCount":15000}}"#,
        );
        assert_eq!(
            gem.finish(),
            TokenUsage {
                input_tokens: 20_000,
                output_tokens: 200,
                total_tokens: 20_200,
                cache_read_tokens: 15_000,
                cache_write_tokens: 0,
            }
        );

        let mut anti = UsageAccumulator::new();
        anti.push_chunk(
            b"data: {\"response\":{\"usageMetadata\":{\"promptTokenCount\":4000,\"candidatesTokenCount\":50,\"totalTokenCount\":4050,\"cachedContentTokenCount\":3200}}}\n\n",
        );
        assert_eq!(
            anti.finish(),
            TokenUsage {
                input_tokens: 4_000,
                output_tokens: 50,
                total_tokens: 4_050,
                cache_read_tokens: 3_200,
                cache_write_tokens: 0,
            }
        );
    }
}
