use std::ops::Range;

use memchr::memchr2;

/// Span of the `"model"` string value inside raw JSON bytes (excluding surrounding quotes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSpan {
    pub value_range: Range<usize>,
}

impl ModelSpan {
    #[inline]
    pub fn as_str<'a>(&self, raw: &'a [u8]) -> Option<&'a str> {
        std::str::from_utf8(&raw[self.value_range.clone()]).ok()
    }
}

/// Fast, zero-deserialization extraction of the top-level `"model"` field value span
/// from a JSON object.
///
/// Tracks JSON brace/bracket nesting depth and skips over JSON string literals using
/// SIMD-accelerated `memchr::memchr2` so `"model"` inside nested objects (such as
/// `messages` or `extra`) is never falsely matched.
pub fn find_model_span(raw: &[u8]) -> Option<ModelSpan> {
    let mut i = skip_ws(raw, 0);
    if raw.get(i).copied() != Some(b'{') {
        return None;
    }
    i += 1;
    let mut depth: usize = 1;

    while i < raw.len() {
        let b = raw[i];
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => {
                i += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return None;
                }
                i += 1;
            }
            b'"' => {
                let str_start = i + 1;
                let str_end = find_json_string_end(raw, str_start)?;
                let after_str = skip_ws(raw, str_end + 1);
                if depth == 1 && raw.get(after_str).copied() == Some(b':') {
                    let is_model_key = &raw[str_start..str_end] == b"model";
                    let val_pos = skip_ws(raw, after_str + 1);
                    if is_model_key && raw.get(val_pos).copied() == Some(b'"') {
                        let val_start = val_pos + 1;
                        let val_end = find_json_string_end(raw, val_start)?;
                        return Some(ModelSpan {
                            value_range: val_start..val_end,
                        });
                    }
                    i = val_pos;
                    continue;
                }
                i = after_str;
            }
            _ => {
                i += 1;
            }
        }
    }

    None
}

#[inline]
fn skip_ws(raw: &[u8], mut idx: usize) -> usize {
    while let Some(&b) = raw.get(idx) {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            idx += 1;
        } else {
            break;
        }
    }
    idx
}

#[inline]
fn find_json_string_end(raw: &[u8], mut idx: usize) -> Option<usize> {
    while idx < raw.len() {
        let rel = memchr2(b'"', b'\\', &raw[idx..])?;
        let pos = idx + rel;
        if raw[pos] == b'"' {
            return Some(pos);
        }
        // Skip escaped byte.
        idx = pos + 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_standard_model_field() {
        let body = br#"{"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}"#;
        let span = find_model_span(body).unwrap();
        assert_eq!(span.as_str(body), Some("gpt-4o"));
    }

    #[test]
    fn extracts_model_after_other_fields_and_whitespace() {
        let body = b"{\n  \"stream\" : true ,\n  \"model\" \t : \n \"claude-sonnet-4\" }";
        let span = find_model_span(body).unwrap();
        assert_eq!(span.as_str(body), Some("claude-sonnet-4"));
    }

    #[test]
    fn ignores_model_mention_inside_prompt_text() {
        let body = br#"{"messages":[{"role":"user","content":"talk about \"model\" here"}],"model":"gemini-2.5-pro"}"#;
        let span = find_model_span(body).unwrap();
        assert_eq!(span.as_str(body), Some("gemini-2.5-pro"));
    }

    #[test]
    fn ignores_nested_model_keys_at_deeper_depth() {
        let body = br#"{"extra":{"model":"wrong-nested"},"messages":[{"model":"also-wrong"}],"model":"right-top"}"#;
        let span = find_model_span(body).unwrap();
        assert_eq!(span.as_str(body), Some("right-top"));
    }

    #[test]
    fn returns_none_when_missing() {
        let body = br#"{"messages": []}"#;
        assert!(find_model_span(body).is_none());
    }
}
