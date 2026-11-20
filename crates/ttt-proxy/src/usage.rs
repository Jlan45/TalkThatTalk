use serde::Deserialize;

/// Unified token usage extracted off the hot path by the async Tap worker.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}

impl TokenUsage {
    pub fn is_empty(&self) -> bool {
        self.input_tokens == 0 && self.output_tokens == 0 && self.total_tokens == 0
    }
}

/// Incremental line-based SSE / JSON usage extractor supporting both:
/// - OpenAI / Codex (`usage.prompt_tokens`, `usage.completion_tokens`, `usage.total_tokens`,
///   and Responses API `usage.input_tokens` / `usage.output_tokens`)
/// - Anthropic / Claude Code (`message_start` -> `message.usage.input_tokens`,
///   `message_delta` -> `usage.output_tokens`)
#[derive(Debug, Default)]
pub struct UsageAccumulator {
    buf: Vec<u8>,
    pub usage: TokenUsage,
}

impl UsageAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a raw `Bytes` chunk from `TapEvent::ResponseChunk`.
    /// Only inspects lines that contain `"usage"` to keep CPU overhead near zero.
    pub fn push_chunk(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);

        while let Some(pos) = memchr::memchr(b'\n', &self.buf) {
            let line = self.buf[..pos].to_vec();
            self.buf.drain(..=pos);
            self.inspect_line(&line);
        }
    }

    /// Flush any remaining buffered JSON (e.g. non-streaming responses without trailing newline).
    pub fn finish(&mut self) -> TokenUsage {
        if !self.buf.is_empty() {
            let tail = std::mem::take(&mut self.buf);
            self.inspect_line(&tail);
        }
        if self.usage.total_tokens == 0
            && (self.usage.input_tokens > 0 || self.usage.output_tokens > 0)
        {
            self.usage.total_tokens = self.usage.input_tokens + self.usage.output_tokens;
        }
        self.usage.clone()
    }

    fn inspect_line(&mut self, raw_line: &[u8]) {
        // Fast reject: skip 99% of SSE delta chunks that don't mention "usage".
        if memchr::memmem::find(raw_line, b"\"usage\"").is_none() {
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
            if let Some(msg) = envelope.message
                && let Some(u) = msg.usage
            {
                self.merge(u);
            }
            if let Some(resp) = envelope.response
                && let Some(u) = resp.usage
            {
                self.merge(u);
            }
        }
    }

    fn merge(&mut self, u: RawUsage) {
        if let Some(v) = u.prompt_tokens.or(u.input_tokens) {
            self.usage.input_tokens = v;
        }
        if let Some(v) = u.completion_tokens.or(u.output_tokens) {
            self.usage.output_tokens = v;
        }
        if let Some(v) = u.total_tokens {
            self.usage.total_tokens = v;
        }
    }
}

#[derive(Deserialize)]
struct UsageEnvelope {
    usage: Option<RawUsage>,
    message: Option<NestedUsage>,
    response: Option<NestedUsage>,
}

#[derive(Deserialize)]
struct NestedUsage {
    usage: Option<RawUsage>,
}

#[derive(Deserialize)]
struct RawUsage {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
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
            }
        );
    }
}
