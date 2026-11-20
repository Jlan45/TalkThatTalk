use std::ops::Range;

use memchr::memmem;

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

/// Fast, zero-deserialization extraction of the `"model"` field value span from a JSON object.
///
/// Uses SIMD-accelerated `memchr::memmem` to locate `"model"` keys without parsing
/// potentially huge `messages` arrays or base64 image payloads.
///
/// To avoid matching `"model"` inside user prompt text, this verifies that:
/// 1. The byte immediately before `"model"` (ignoring ASCII whitespace) is `{` or `,`.
/// 2. The byte immediately after `"model"` (ignoring ASCII whitespace) is `:`.
/// 3. The value after `:` (ignoring ASCII whitespace) is a double-quoted JSON string.
pub fn find_model_span(raw: &[u8]) -> Option<ModelSpan> {
    let finder = memmem::Finder::new(b"\"model\"");
    let mut search_from = 0;

    while let Some(rel) = finder.find(&raw[search_from..]) {
        let key_start = search_from + rel;
        let key_end = key_start + b"\"model\"".len();
        search_from = key_end;

        // 1. Check preceding non-whitespace byte is '{' or ','.
        if !preceded_by_object_delimiter(raw, key_start) {
            continue;
        }

        // 2. Skip whitespace and expect ':'.
        let mut i = skip_ws(raw, key_end);
        if raw.get(i).copied() != Some(b':') {
            continue;
        }
        i = skip_ws(raw, i + 1);

        // 3. Expect opening '"' of string value.
        if raw.get(i).copied() != Some(b'"') {
            continue;
        }
        let val_start = i + 1;

        // 4. Scan to closing '"' respecting backslash escapes.
        if let Some(val_end) = find_json_string_end(raw, val_start) {
            return Some(ModelSpan {
                value_range: val_start..val_end,
            });
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
fn preceded_by_object_delimiter(raw: &[u8], mut idx: usize) -> bool {
    while idx > 0 {
        idx -= 1;
        let b = raw[idx];
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        return matches!(b, b'{' | b',');
    }
    false
}

#[inline]
fn find_json_string_end(raw: &[u8], mut idx: usize) -> Option<usize> {
    while let Some(&b) = raw.get(idx) {
        if b == b'\\' {
            idx += 2;
            continue;
        }
        if b == b'"' {
            return Some(idx);
        }
        idx += 1;
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
    fn returns_none_when_missing() {
        let body = br#"{"messages": []}"#;
        assert!(find_model_span(body).is_none());
    }
}
