use http::header::HeaderName;
use http::HeaderMap;
use memchr::{memchr2, memmem};
use ttt_core::{ProtocolFamily, RoutingConfig};

/// Built-in session header priority list covering major coding agents and clients.
static BUILTIN_SESSION_HEADERS: &[&str] = &[
    "x-ttt-session-id",
    "session_id",
    "conversation_id",
    "x-session-id",
    "x-conversation-id",
    "x-thread-id",
    "x-claude-code-session-id",
    "x-opencode-session",
    "x-opencode-session-id",
    "x-cline-task-id",
    "x-roo-task-id",
    "x-cursor-session-id",
    "x-grok-conv-id",
    "x-chat-id",
    "x-client-session-id",
];

const BOUNDED_META_WINDOW_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinityContext {
    pub hash: u64,
    pub source: String,
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct AffinityExtractor {
    enabled: bool,
    custom_headers: Vec<HeaderName>,
    prefix_fallback_enabled: bool,
    prefix_max_bytes: usize,
    prefix_min_bytes: usize,
}

impl AffinityExtractor {
    pub fn from_config(cfg: &RoutingConfig) -> Self {
        let mut custom_headers = Vec::new();
        for raw in &cfg.session_headers {
            let trimmed = raw.trim().to_ascii_lowercase();
            if trimmed.is_empty() || is_anti_pattern_header(&trimmed) {
                continue;
            }
            if let Ok(hn) = HeaderName::from_bytes(trimmed.as_bytes())
                && !custom_headers.contains(&hn)
            {
                custom_headers.push(hn);
            }
        }
        Self {
            enabled: cfg.affinity_enabled,
            custom_headers,
            prefix_fallback_enabled: cfg.prefix_fallback_enabled,
            prefix_max_bytes: cfg.prefix_max_bytes.max(128),
            prefix_min_bytes: cfg.prefix_min_bytes,
        }
    }

    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns true if `name` matches any configured or built-in incoming session header.
    pub fn is_session_header(&self, name: &HeaderName) -> bool {
        if self.custom_headers.contains(name) {
            return true;
        }
        let s = name.as_str();
        BUILTIN_SESSION_HEADERS.contains(&s)
    }

    /// Header-only affinity extraction for the pure zero-copy streaming path.
    pub fn extract_headers_only(
        &self,
        headers: &HeaderMap,
        owner_user_id: Option<i64>,
        model: Option<&str>,
    ) -> Option<AffinityContext> {
        if !self.enabled {
            return None;
        }
        self.extract_from_headers(headers, owner_user_id, model)
    }

    /// Full four-tier waterfall extraction (Tier 0 stateful body -> Tier 1 session headers ->
    /// Tier 2 protocol-native body session fields -> Tier 3 bounded context-prefix fingerprint).
    pub fn extract(
        &self,
        headers: &HeaderMap,
        raw_body: &[u8],
        ingress_proto: Option<ProtocolFamily>,
        owner_user_id: Option<i64>,
        model: Option<&str>,
    ) -> Option<AffinityContext> {
        if !self.enabled {
            return None;
        }

        // Tier 0: Strong stateful body fields (must win over generic headers so stateful chains never split).
        if !raw_body.is_empty() {
            match ingress_proto {
                Some(ProtocolFamily::OpenAiResponses) | None => {
                    if let Some(val) = scan_bounded_top_string(raw_body, b"\"previous_response_id\"")
                        && let Some(norm) = normalize_session_value(&val)
                    {
                        return Some(build_context(
                            owner_user_id,
                            model,
                            "body:previous_response_id".to_string(),
                            norm.as_bytes(),
                        ));
                    }
                }
                _ => {}
            }
            match ingress_proto {
                Some(ProtocolFamily::Gemini) | None => {
                    if let Some(val) = scan_bounded_top_string(raw_body, b"\"cachedContent\"")
                        && let Some(norm) = normalize_session_value(&val)
                    {
                        return Some(build_context(
                            owner_user_id,
                            model,
                            "body:cached_content".to_string(),
                            norm.as_bytes(),
                        ));
                    }
                }
                _ => {}
            }
        }

        // Tier 1: Explicit session headers (custom overrides first, then built-in multi-agent headers).
        if let Some(ctx) = self.extract_from_headers(headers, owner_user_id, model) {
            return Some(ctx);
        }

        if raw_body.is_empty() {
            return None;
        }

        // Tier 2: Protocol-native body session fields (head 8KB + tail 8KB bounded scan).
        match ingress_proto {
            Some(ProtocolFamily::OpenAi) | Some(ProtocolFamily::OpenAiResponses) | None => {
                if let Some(val) = scan_bounded_top_string(raw_body, b"\"prompt_cache_key\"")
                    && let Some(norm) = normalize_session_value(&val)
                {
                    return Some(build_context(
                        owner_user_id,
                        model,
                        "body:prompt_cache_key".to_string(),
                        norm.as_bytes(),
                    ));
                }
                if matches!(ingress_proto, Some(ProtocolFamily::OpenAiResponses) | None)
                    && let Some(val) = scan_bounded_top_string(raw_body, b"\"conversation\"")
                    && let Some(norm) = normalize_session_value(&val)
                {
                    return Some(build_context(
                        owner_user_id,
                        model,
                        "body:conversation".to_string(),
                        norm.as_bytes(),
                    ));
                }
                if let Some(val) = scan_bounded_top_string(raw_body, b"\"session_id\"")
                    && let Some(norm) = normalize_session_value(&val)
                {
                    return Some(build_context(
                        owner_user_id,
                        model,
                        "body:session_id".to_string(),
                        norm.as_bytes(),
                    ));
                }
            }
            _ => {}
        }

        if matches!(ingress_proto, Some(ProtocolFamily::Anthropic) | None)
            && let Some(val) = scan_bounded_claude_metadata_user_id(raw_body)
            && let Some(norm) = normalize_session_value(&val)
        {
            return Some(build_context(
                owner_user_id,
                model,
                "body:claude_metadata".to_string(),
                norm.as_bytes(),
            ));
        }

        // Tier 3: Bounded context-prefix fingerprint (zero full DOM deserialization).
        if self.prefix_fallback_enabled
            && let Some(prefix_bytes) =
                extract_prefix_fingerprint(raw_body, ingress_proto, self.prefix_max_bytes)
            && prefix_bytes.len() >= self.prefix_min_bytes
        {
            return Some(build_context(
                owner_user_id,
                model,
                "prefix_hash".to_string(),
                &prefix_bytes,
            ));
        }

        None
    }

    fn extract_from_headers(
        &self,
        headers: &HeaderMap,
        owner_user_id: Option<i64>,
        model: Option<&str>,
    ) -> Option<AffinityContext> {
        for name in &self.custom_headers {
            if let Some(ctx) = try_header_affinity(headers, name.as_str(), owner_user_id, model) {
                return Some(ctx);
            }
        }
        for &name in BUILTIN_SESSION_HEADERS {
            if is_anti_pattern_header(name) {
                continue;
            }
            if let Some(ctx) = try_header_affinity(headers, name, owner_user_id, model) {
                return Some(ctx);
            }
        }
        None
    }
}

fn try_header_affinity(
    headers: &HeaderMap,
    name: &str,
    owner_user_id: Option<i64>,
    model: Option<&str>,
) -> Option<AffinityContext> {
    let raw = headers.get(name)?.to_str().ok()?;
    let norm = normalize_session_value(raw)?;
    Some(build_context(
        owner_user_id,
        model,
        format!("header:{name}"),
        norm.as_bytes(),
    ))
}

#[inline]
fn is_anti_pattern_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "x-request-id"
            | "x-correlation-id"
            | "traceparent"
            | "authorization"
            | "user-agent"
            | "x-forwarded-for"
            | "x-opencode-request"
            | "x-opencode-request-id"
    ) || lower_name.starts_with("x-stainless-")
}

#[inline]
fn normalize_session_value(raw: &str) -> Option<&str> {
    let v = raw.trim();
    if !(4..=256).contains(&v.len()) {
        return None;
    }
    if v.eq_ignore_ascii_case("null")
        || v.eq_ignore_ascii_case("undefined")
        || v.eq_ignore_ascii_case("none")
        || v.eq_ignore_ascii_case("default")
        || v.eq_ignore_ascii_case("unknown")
    {
        return None;
    }
    Some(v)
}

fn build_context(
    owner_user_id: Option<i64>,
    model: Option<&str>,
    source: String,
    raw_key: &[u8],
) -> AffinityContext {
    let mut h = FastHasher::new();
    match owner_user_id {
        Some(uid) => {
            h.update(&[1]);
            h.update(&uid.to_le_bytes());
        }
        None => {
            h.update(&[0]);
        }
    }
    h.update(&[0x00]);
    h.update(model.unwrap_or("").as_bytes());
    h.update(&[0x00]);
    h.update(source.as_bytes());
    h.update(&[0x00]);
    h.update(raw_key);

    let hash = h.finish();
    let session_id = if source == "prefix_hash" {
        format!("ttt-pfx-{hash:016x}")
    } else {
        String::from_utf8_lossy(raw_key).into_owned()
    };

    AffinityContext {
        hash,
        source,
        session_id,
    }
}

/// Fast non-cryptographic 64-bit FNV-1a + SplitMix64 finalizer (zero external dependencies).
struct FastHasher {
    state: u64,
}

impl FastHasher {
    #[inline]
    fn new() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }

    #[inline]
    fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state ^= b as u64;
            self.state = self.state.wrapping_mul(0x0100_0000_01b3);
        }
    }

    #[inline]
    fn finish(self) -> u64 {
        mix64(self.state)
    }
}

#[inline]
pub(crate) fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Hash an arbitrary string deterministically into 64 bits (used to pre-hash upstream node names).
#[inline]
pub(crate) fn hash_str_64(s: &str) -> u64 {
    let mut h = FastHasher::new();
    h.update(s.as_bytes());
    h.finish()
}

/// Scan only bounded head (8KB) + tail (8KB) windows of `raw_body` for a JSON string field.
fn scan_bounded_top_string(raw_body: &[u8], quoted_key: &[u8]) -> Option<String> {
    if raw_body.len() <= BOUNDED_META_WINDOW_BYTES * 2 {
        return find_json_string_field_in_slice(raw_body, quoted_key);
    }
    let head = &raw_body[..BOUNDED_META_WINDOW_BYTES];
    if let Some(v) = find_json_string_field_in_slice(head, quoted_key) {
        return Some(v);
    }
    let tail = &raw_body[raw_body.len() - BOUNDED_META_WINDOW_BYTES..];
    find_json_string_field_in_slice(tail, quoted_key)
}

fn find_json_string_field_in_slice(slice: &[u8], quoted_key: &[u8]) -> Option<String> {
    let finder = memmem::Finder::new(quoted_key);
    let mut from = 0;
    while let Some(rel) = finder.find(&slice[from..]) {
        let key_start = from + rel;
        let key_end = key_start + quoted_key.len();
        from = key_end;

        if !preceded_by_object_delimiter(slice, key_start) {
            continue;
        }
        let mut i = skip_ws(slice, key_end);
        if slice.get(i).copied() != Some(b':') {
            continue;
        }
        i = skip_ws(slice, i + 1);
        if slice.get(i).copied() != Some(b'"') {
            continue;
        }
        let val_start = i + 1;
        if let Some(val_end) = find_json_string_end(slice, val_start) {
            return decode_json_string_slice(&slice[val_start..val_end]);
        }
    }
    None
}

/// Scan bounded head/tail windows for `"metadata": { ... "user_id": "..." ... }`.
/// For Claude Code `user_<hash>_account_<id>_session_<uuid>`, extracts `session_<uuid>`
/// so concurrent sessions under the same user account distribute independently.
fn scan_bounded_claude_metadata_user_id(raw_body: &[u8]) -> Option<String> {
    let raw = if raw_body.len() <= BOUNDED_META_WINDOW_BYTES * 2 {
        find_claude_user_id_in_slice(raw_body)
    } else {
        find_claude_user_id_in_slice(&raw_body[..BOUNDED_META_WINDOW_BYTES]).or_else(|| {
            find_claude_user_id_in_slice(&raw_body[raw_body.len() - BOUNDED_META_WINDOW_BYTES..])
        })
    }?;

    if let Some(pos) = raw.find("_session_") {
        return Some(raw[pos + 1..].to_string());
    }
    Some(raw)
}

fn find_claude_user_id_in_slice(slice: &[u8]) -> Option<String> {
    let finder = memmem::Finder::new(b"\"metadata\"");
    let mut from = 0;
    while let Some(rel) = finder.find(&slice[from..]) {
        let key_start = from + rel;
        let key_end = key_start + b"\"metadata\"".len();
        from = key_end;

        if !preceded_by_object_delimiter(slice, key_start) {
            continue;
        }
        let mut i = skip_ws(slice, key_end);
        if slice.get(i).copied() != Some(b':') {
            continue;
        }
        i = skip_ws(slice, i + 1);
        if slice.get(i).copied() != Some(b'{') {
            continue;
        }
        if let Some(obj_end) = find_matching_container_end(slice, i) {
            let obj_slice = &slice[i..=obj_end];
            if let Some(uid) = find_json_string_field_in_slice(obj_slice, b"\"user_id\"") {
                return Some(uid);
            }
        }
    }
    None
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
    // At the very start of a tail window, allow match only if immediately preceded by delimiter;
    // when idx == 0 inside a truncated tail slice we avoid false positives inside strings.
    false
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
        idx = pos + 2;
    }
    None
}

fn find_matching_container_end(raw: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut depth = 0usize;
    while i < raw.len() {
        match raw[i] {
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            b'"' => {
                i = find_json_string_end(raw, i + 1)? + 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn decode_json_string_slice(bytes: &[u8]) -> Option<String> {
    if !bytes.contains(&b'\\') {
        return std::str::from_utf8(bytes).ok().map(ToOwned::to_owned);
    }
    let mut wrapped = Vec::with_capacity(bytes.len() + 2);
    wrapped.push(b'"');
    wrapped.extend_from_slice(bytes);
    wrapped.push(b'"');
    serde_json::from_slice::<String>(&wrapped).ok()
}

/// Bounded streaming JSON prefix extractor (never builds a full DOM).
///
/// Extracts canonical `system`/`instructions` text + first `user` message text up to `max_bytes`,
/// scanning at most `max(max_bytes * 4, 16384)` bytes of `raw_body`.
fn extract_prefix_fingerprint(
    raw_body: &[u8],
    ingress_proto: Option<ProtocolFamily>,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let scan_limit = max_bytes.saturating_mul(4).max(16384).min(raw_body.len());
    let slice = &raw_body[..scan_limit];

    let mut scanner = JsonCursor::new(slice);
    scanner.skip_ws();
    if scanner.peek() != Some(b'{') {
        return None;
    }
    scanner.pos += 1;

    let mut system_buf = Vec::with_capacity(max_bytes.min(2048));
    let mut user_buf = Vec::with_capacity(max_bytes.min(2048));
    let mut got_first_user = false;

    loop {
        scanner.skip_ws();
        match scanner.peek() {
            Some(b'}') | None => break,
            Some(b',') => {
                scanner.pos += 1;
                continue;
            }
            _ => {}
        }

        let Some(key) = scanner.read_raw_string_bytes() else {
            break;
        };
        scanner.skip_ws();
        if scanner.peek() != Some(b':') {
            break;
        }
        scanner.pos += 1;
        scanner.skip_ws();

        match (ingress_proto, key) {
            (Some(ProtocolFamily::OpenAi) | None, b"messages") => {
                if !got_first_user {
                    extract_messages_prefix(
                        &mut scanner,
                        &mut system_buf,
                        &mut user_buf,
                        &mut got_first_user,
                        max_bytes,
                    );
                } else {
                    scanner.skip_value();
                }
            }
            (Some(ProtocolFamily::Anthropic), b"messages") => {
                if !got_first_user {
                    extract_messages_prefix(
                        &mut scanner,
                        &mut system_buf,
                        &mut user_buf,
                        &mut got_first_user,
                        max_bytes,
                    );
                } else {
                    scanner.skip_value();
                }
            }
            (Some(ProtocolFamily::Anthropic) | None, b"system") => {
                if system_buf.len() < max_bytes {
                    extract_text_into(&mut scanner, &mut system_buf, max_bytes);
                } else {
                    scanner.skip_value();
                }
            }
            (Some(ProtocolFamily::OpenAiResponses) | None, b"instructions") => {
                if system_buf.len() < max_bytes {
                    extract_text_into(&mut scanner, &mut system_buf, max_bytes);
                } else {
                    scanner.skip_value();
                }
            }
            (Some(ProtocolFamily::OpenAiResponses) | None, b"input") => {
                if !got_first_user {
                    extract_responses_input_prefix(
                        &mut scanner,
                        &mut user_buf,
                        &mut got_first_user,
                        max_bytes,
                    );
                } else {
                    scanner.skip_value();
                }
            }
            (Some(ProtocolFamily::Gemini) | None, b"systemInstruction") => {
                if system_buf.len() < max_bytes {
                    extract_gemini_parts_into(&mut scanner, &mut system_buf, max_bytes);
                } else {
                    scanner.skip_value();
                }
            }
            (Some(ProtocolFamily::Gemini) | None, b"contents") if !got_first_user => {
                extract_gemini_contents_first(&mut scanner, &mut user_buf, &mut got_first_user, max_bytes);
            }
            (Some(ProtocolFamily::Gemini) | None, b"contents") => {
                scanner.skip_value();
            }
            _ => {
                scanner.skip_value();
            }
        }

        if system_buf.len() + user_buf.len() >= max_bytes && got_first_user {
            break;
        }
    }

    if system_buf.is_empty() && user_buf.is_empty() {
        return None;
    }

    let mut combined = Vec::with_capacity((system_buf.len() + user_buf.len() + 1).min(max_bytes));
    let sys_take = system_buf.len().min(max_bytes);
    combined.extend_from_slice(&system_buf[..sys_take]);
    if combined.len() < max_bytes && !user_buf.is_empty() {
        if !combined.is_empty() {
            combined.push(b'\n');
        }
        let remain = max_bytes.saturating_sub(combined.len());
        let usr_take = user_buf.len().min(remain);
        combined.extend_from_slice(&user_buf[..usr_take]);
    }
    Some(combined)
}

fn extract_messages_prefix(
    scanner: &mut JsonCursor<'_>,
    system_buf: &mut Vec<u8>,
    user_buf: &mut Vec<u8>,
    got_first_user: &mut bool,
    max_bytes: usize,
) {
    if scanner.peek() != Some(b'[') {
        scanner.skip_value();
        return;
    }
    scanner.pos += 1;

    loop {
        scanner.skip_ws();
        match scanner.peek() {
            Some(b']') | None => {
                if scanner.peek() == Some(b']') {
                    scanner.pos += 1;
                }
                break;
            }
            Some(b',') => {
                scanner.pos += 1;
                continue;
            }
            _ => {}
        }

        if *got_first_user {
            // Stop reading further messages once the first user message is captured.
            scanner.skip_remaining_array();
            break;
        }

        if scanner.peek() != Some(b'{') {
            scanner.skip_value();
            continue;
        }
        scanner.pos += 1;

        let mut role_is_system = false;
        let mut role_is_user = false;
        let mut msg_text = Vec::new();

        loop {
            scanner.skip_ws();
            match scanner.peek() {
                Some(b'}') | None => {
                    if scanner.peek() == Some(b'}') {
                        scanner.pos += 1;
                    }
                    break;
                }
                Some(b',') => {
                    scanner.pos += 1;
                    continue;
                }
                _ => {}
            }
            let Some(field) = scanner.read_raw_string_bytes() else {
                break;
            };
            scanner.skip_ws();
            if scanner.peek() != Some(b':') {
                break;
            }
            scanner.pos += 1;
            scanner.skip_ws();

            match field {
                b"role" => {
                    if let Some(role) = scanner.read_raw_string_bytes() {
                        role_is_system = role == b"system" || role == b"developer";
                        role_is_user = role == b"user";
                    } else {
                        scanner.skip_value();
                    }
                }
                b"content" => {
                    extract_text_into(scanner, &mut msg_text, max_bytes);
                }
                _ => scanner.skip_value(),
            }
        }

        if role_is_system {
            append_capped(system_buf, &msg_text, max_bytes);
        } else if role_is_user || (!role_is_system && !msg_text.is_empty()) {
            append_capped(user_buf, &msg_text, max_bytes);
            *got_first_user = true;
            scanner.skip_remaining_array();
            break;
        }
    }
}

fn extract_responses_input_prefix(
    scanner: &mut JsonCursor<'_>,
    user_buf: &mut Vec<u8>,
    got_first_user: &mut bool,
    max_bytes: usize,
) {
    match scanner.peek() {
        Some(b'"') => {
            extract_text_into(scanner, user_buf, max_bytes);
            *got_first_user = !user_buf.is_empty();
        }
        Some(b'[') => {
            scanner.pos += 1;
            loop {
                scanner.skip_ws();
                match scanner.peek() {
                    Some(b']') | None => {
                        if scanner.peek() == Some(b']') {
                            scanner.pos += 1;
                        }
                        break;
                    }
                    Some(b',') => {
                        scanner.pos += 1;
                        continue;
                    }
                    _ => {}
                }
                if scanner.peek() == Some(b'"') {
                    extract_text_into(scanner, user_buf, max_bytes);
                    *got_first_user = true;
                    scanner.skip_remaining_array();
                    break;
                }
                if scanner.peek() != Some(b'{') {
                    scanner.skip_value();
                    continue;
                }
                scanner.pos += 1;
                let mut is_user_or_unset = true;
                let mut item_text = Vec::new();
                loop {
                    scanner.skip_ws();
                    match scanner.peek() {
                        Some(b'}') | None => {
                            if scanner.peek() == Some(b'}') {
                                scanner.pos += 1;
                            }
                            break;
                        }
                        Some(b',') => {
                            scanner.pos += 1;
                            continue;
                        }
                        _ => {}
                    }
                    let Some(field) = scanner.read_raw_string_bytes() else {
                        break;
                    };
                    scanner.skip_ws();
                    if scanner.peek() != Some(b':') {
                        break;
                    }
                    scanner.pos += 1;
                    scanner.skip_ws();
                    match field {
                        b"role" => {
                            if let Some(r) = scanner.read_raw_string_bytes() {
                                is_user_or_unset = r == b"user";
                            } else {
                                scanner.skip_value();
                            }
                        }
                        b"content" | b"text" => {
                            extract_text_into(scanner, &mut item_text, max_bytes);
                        }
                        _ => scanner.skip_value(),
                    }
                }
                if is_user_or_unset && !item_text.is_empty() {
                    append_capped(user_buf, &item_text, max_bytes);
                    *got_first_user = true;
                    scanner.skip_remaining_array();
                    break;
                }
            }
        }
        _ => scanner.skip_value(),
    }
}

fn extract_gemini_contents_first(
    scanner: &mut JsonCursor<'_>,
    user_buf: &mut Vec<u8>,
    got_first_user: &mut bool,
    max_bytes: usize,
) {
    if scanner.peek() != Some(b'[') {
        scanner.skip_value();
        return;
    }
    scanner.pos += 1;
    scanner.skip_ws();
    if scanner.peek() != Some(b']') && scanner.peek().is_some() {
        extract_gemini_parts_into(scanner, user_buf, max_bytes);
        *got_first_user = !user_buf.is_empty();
    }
    scanner.skip_remaining_array();
}

fn extract_gemini_parts_into(scanner: &mut JsonCursor<'_>, out: &mut Vec<u8>, max_bytes: usize) {
    if scanner.peek() != Some(b'{') {
        scanner.skip_value();
        return;
    }
    scanner.pos += 1;
    loop {
        scanner.skip_ws();
        match scanner.peek() {
            Some(b'}') | None => {
                if scanner.peek() == Some(b'}') {
                    scanner.pos += 1;
                }
                break;
            }
            Some(b',') => {
                scanner.pos += 1;
                continue;
            }
            _ => {}
        }
        let Some(field) = scanner.read_raw_string_bytes() else {
            break;
        };
        scanner.skip_ws();
        if scanner.peek() != Some(b':') {
            break;
        }
        scanner.pos += 1;
        scanner.skip_ws();
        if field == b"parts" {
            extract_text_into(scanner, out, max_bytes);
        } else {
            scanner.skip_value();
        }
    }
}

/// Extract text from a JSON string or an array of content-block objects (`{"type":"text","text":"..."}`).
fn extract_text_into(scanner: &mut JsonCursor<'_>, out: &mut Vec<u8>, max_bytes: usize) {
    match scanner.peek() {
        Some(b'"') => {
            if let Some(s) = scanner.read_raw_string_bytes() {
                append_capped(out, s, max_bytes);
            }
        }
        Some(b'[') => {
            scanner.pos += 1;
            loop {
                scanner.skip_ws();
                match scanner.peek() {
                    Some(b']') | None => {
                        if scanner.peek() == Some(b']') {
                            scanner.pos += 1;
                        }
                        break;
                    }
                    Some(b',') => {
                        scanner.pos += 1;
                        continue;
                    }
                    _ => {}
                }
                if out.len() >= max_bytes {
                    scanner.skip_remaining_array();
                    break;
                }
                match scanner.peek() {
                    Some(b'"') => {
                        if let Some(s) = scanner.read_raw_string_bytes() {
                            append_capped(out, s, max_bytes);
                        }
                    }
                    Some(b'{') => {
                        scanner.pos += 1;
                        loop {
                            scanner.skip_ws();
                            match scanner.peek() {
                                Some(b'}') | None => {
                                    if scanner.peek() == Some(b'}') {
                                        scanner.pos += 1;
                                    }
                                    break;
                                }
                                Some(b',') => {
                                    scanner.pos += 1;
                                    continue;
                                }
                                _ => {}
                            }
                            let Some(field) = scanner.read_raw_string_bytes() else {
                                break;
                            };
                            scanner.skip_ws();
                            if scanner.peek() != Some(b':') {
                                break;
                            }
                            scanner.pos += 1;
                            scanner.skip_ws();
                            if field == b"text" || field == b"input_text" {
                                if let Some(s) = scanner.read_raw_string_bytes() {
                                    append_capped(out, s, max_bytes);
                                } else {
                                    scanner.skip_value();
                                }
                            } else {
                                scanner.skip_value();
                            }
                        }
                    }
                    _ => scanner.skip_value(),
                }
            }
        }
        _ => scanner.skip_value(),
    }
}

#[inline]
fn append_capped(dst: &mut Vec<u8>, src: &[u8], max_bytes: usize) {
    if src.is_empty() || dst.len() >= max_bytes {
        return;
    }
    if !dst.is_empty() {
        dst.push(b' ');
    }
    let remain = max_bytes.saturating_sub(dst.len());
    let take = src.len().min(remain);
    dst.extend_from_slice(&src[..take]);
}

struct JsonCursor<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> JsonCursor<'a> {
    #[inline]
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, pos: 0 }
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.raw.get(self.pos).copied()
    }

    #[inline]
    fn skip_ws(&mut self) {
        while let Some(&b) = self.raw.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    #[inline]
    fn read_raw_string_bytes(&mut self) -> Option<&'a [u8]> {
        if self.peek() != Some(b'"') {
            return None;
        }
        let start = self.pos + 1;
        if let Some(end) = find_json_string_end(self.raw, start) {
            self.pos = end + 1;
            Some(&self.raw[start..end])
        } else {
            // Truncated string at scan_limit: return available bytes and move cursor to end.
            let slice = &self.raw[start..];
            self.pos = self.raw.len();
            Some(slice)
        }
    }

    fn skip_value(&mut self) {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => {
                let _ = self.read_raw_string_bytes();
            }
            Some(b'{') | Some(b'[') => {
                let mut depth = 0usize;
                while self.pos < self.raw.len() {
                    match self.raw[self.pos] {
                        b'{' | b'[' => {
                            depth += 1;
                            self.pos += 1;
                        }
                        b'}' | b']' => {
                            depth = depth.saturating_sub(1);
                            self.pos += 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        b'"' => {
                            let _ = self.read_raw_string_bytes();
                        }
                        _ => self.pos += 1,
                    }
                }
            }
            Some(_) => {
                while let Some(&b) = self.raw.get(self.pos) {
                    if matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                        break;
                    }
                    self.pos += 1;
                }
            }
            None => {}
        }
    }

    fn skip_remaining_array(&mut self) {
        let mut depth = 1usize;
        while self.pos < self.raw.len() && depth > 0 {
            match self.raw[self.pos] {
                b'[' | b'{' => {
                    depth += 1;
                    self.pos += 1;
                }
                b']' | b'}' => {
                    depth -= 1;
                    self.pos += 1;
                }
                b'"' => {
                    let _ = self.read_raw_string_bytes();
                }
                _ => self.pos += 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_extractor() -> AffinityExtractor {
        AffinityExtractor::from_config(&RoutingConfig::default())
    }

    #[test]
    fn extracts_heterogeneous_agent_session_headers() {
        let ext = default_extractor();

        // Codex CLI: bare `session_id`
        let mut h = HeaderMap::new();
        h.insert("session_id", "codex-sess-9988".parse().unwrap());
        let c1 = ext
            .extract(&h, br#"{"model":"gpt-5-codex"}"#, Some(ProtocolFamily::OpenAiResponses), None, Some("gpt-5-codex"))
            .unwrap();
        assert_eq!(c1.source, "header:session_id");
        assert_eq!(c1.session_id, "codex-sess-9988");

        // OpenCode / Cline / Cursor / Grok headers
        for (hdr, expected) in [
            ("x-opencode-session", "header:x-opencode-session"),
            ("x-opencode-session-id", "header:x-opencode-session-id"),
            ("x-cline-task-id", "header:x-cline-task-id"),
            ("x-cursor-session-id", "header:x-cursor-session-id"),
            ("x-grok-conv-id", "header:x-grok-conv-id"),
        ] {
            let mut map = HeaderMap::new();
            map.insert(hdr, "task-abcdef1234".parse().unwrap());
            let c = ext.extract(&map, b"{}", None, None, Some("claude-sonnet-4")).unwrap();
            assert_eq!(c.source, expected);
        }

        // Custom configured header takes precedence over built-ins
        let cfg = RoutingConfig {
            session_headers: vec!["x-my-agent-sid".to_string()],
            ..Default::default()
        };
        let custom_ext = AffinityExtractor::from_config(&cfg);
        let mut both = HeaderMap::new();
        both.insert("session_id", "built-in-id-123".parse().unwrap());
        both.insert("x-my-agent-sid", "custom-id-456".parse().unwrap());
        let chosen = custom_ext.extract(&both, b"{}", None, None, Some("gpt-4o")).unwrap();
        assert_eq!(chosen.source, "header:x-my-agent-sid");
    }

    #[test]
    fn rejects_anti_pattern_headers_and_placeholder_values() {
        let ext = default_extractor();
        let mut h = HeaderMap::new();
        h.insert("x-request-id", "req-unique-12345".parse().unwrap());
        h.insert("x-opencode-request", "opencode-req-999".parse().unwrap());
        h.insert("x-opencode-request-id", "opencode-req-888".parse().unwrap());
        h.insert("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse().unwrap());
        h.insert("user-agent", "claude-cli/2.1.0".parse().unwrap());
        h.insert("x-session-id", "null".parse().unwrap());
        h.insert("x-conversation-id", "abc".parse().unwrap()); // too short (< 4)

        assert!(ext.extract(&h, br#"{"model":"gpt-4o"}"#, None, None, Some("gpt-4o")).is_none());
    }

    #[test]
    fn extracts_claude_code_metadata_and_isolates_sessions_for_same_user() {
        let ext = default_extractor();
        let h = HeaderMap::new();

        let body1 = br#"{"model":"claude-sonnet-4","metadata":{"user_id":"user_abc_account_1_session_uuid-1111"},"messages":[{"role":"user","content":"hi"}]}"#;
        let body2 = br#"{"model":"claude-sonnet-4","metadata":{"user_id":"user_abc_account_1_session_uuid-2222"},"messages":[{"role":"user","content":"hi"}]}"#;

        let c1 = ext
            .extract(&h, body1, Some(ProtocolFamily::Anthropic), None, Some("claude-sonnet-4"))
            .unwrap();
        let c2 = ext
            .extract(&h, body2, Some(ProtocolFamily::Anthropic), None, Some("claude-sonnet-4"))
            .unwrap();

        assert_eq!(c1.source, "body:claude_metadata");
        assert_eq!(c1.session_id, "session_uuid-1111");
        assert_eq!(c2.source, "body:claude_metadata");
        assert_eq!(c2.session_id, "session_uuid-2222");
        assert_ne!(c1.hash, c2.hash);
        assert!(ext.is_session_header(&HeaderName::from_static("x-cline-task-id")));
        assert!(!ext.is_session_header(&HeaderName::from_static("content-type")));
    }

    #[test]
    fn tier0_stateful_fields_and_tier2_prompt_cache_key() {
        let ext = default_extractor();
        let mut h = HeaderMap::new();
        h.insert("x-session-id", "sess-generic-1234".parse().unwrap());

        // Tier 0 previous_response_id beats Tier 1 header
        let resp_body = br#"{"model":"gpt-5-codex","previous_response_id":"resp_99887766"}"#;
        let c0 = ext
            .extract(&h, resp_body, Some(ProtocolFamily::OpenAiResponses), None, Some("gpt-5-codex"))
            .unwrap();
        assert_eq!(c0.source, "body:previous_response_id");

        // Gemini cachedContent beats Tier 1 header
        let gem_body = br#"{"cachedContent":"cachedContents/1234567890"}"#;
        let cg = ext
            .extract(&h, gem_body, Some(ProtocolFamily::Gemini), None, Some("gemini-2.5-pro"))
            .unwrap();
        assert_eq!(cg.source, "body:cached_content");

        // Tier 2 prompt_cache_key when no header is present
        let empty_h = HeaderMap::new();
        let chat_body = br#"{"model":"gpt-4o","prompt_cache_key":"cache-key-alpha-1","messages":[{"role":"user","content":"hi"}]}"#;
        let c2 = ext
            .extract(&empty_h, chat_body, Some(ProtocolFamily::OpenAi), None, Some("gpt-4o"))
            .unwrap();
        assert_eq!(c2.source, "body:prompt_cache_key");

        // OpenRouter body-level `session_id`
        let or_body = br#"{"model":"openai/gpt-4o","session_id":"or-session-9911","messages":[{"role":"user","content":"hi"}]}"#;
        let cor = ext
            .extract(&empty_h, or_body, Some(ProtocolFamily::OpenAi), None, Some("openai/gpt-4o"))
            .unwrap();
        assert_eq!(cor.source, "body:session_id");
        assert_eq!(cor.session_id, "or-session-9911");
    }

    #[test]
    fn multiturn_prefix_fingerprint_is_stable_and_disperses_sessions() {
        let ext = default_extractor();
        let h = HeaderMap::new();

        let sys = "You are a senior Rust systems engineer reviewing memory safety and lock-free concurrency.";
        let turn1 = serde_json::json!({
            "model": "claude-sonnet-4",
            "messages": [
                {"role": "system", "content": sys},
                {"role": "user", "content": "Help me optimize the lock-free ring buffer in router.rs for low latency."}
            ]
        })
        .to_string();
        let turn3 = serde_json::json!({
            "model": "claude-sonnet-4",
            "messages": [
                {"role": "system", "content": sys},
                {"role": "user", "content": "Help me optimize the lock-free ring buffer in router.rs for low latency."},
                {"role": "assistant", "content": "Sure, let's check atomic orderings..."},
                {"role": "user", "content": "Now how should we benchmark tail latency under 10k RPS?"}
            ]
        })
        .to_string();
        let other_session = serde_json::json!({
            "model": "claude-sonnet-4",
            "messages": [
                {"role": "system", "content": sys},
                {"role": "user", "content": "Write a Python script to migrate SQLite rows to PostgreSQL safely."}
            ]
        })
        .to_string();

        let c1 = ext
            .extract(&h, turn1.as_bytes(), Some(ProtocolFamily::OpenAi), None, Some("claude-sonnet-4"))
            .unwrap();
        let c3 = ext
            .extract(&h, turn3.as_bytes(), Some(ProtocolFamily::OpenAi), None, Some("claude-sonnet-4"))
            .unwrap();
        let co = ext
            .extract(&h, other_session.as_bytes(), Some(ProtocolFamily::OpenAi), None, Some("claude-sonnet-4"))
            .unwrap();

        assert_eq!(c1.source, "prefix_hash");
        assert!(c1.session_id.starts_with("ttt-pfx-"));
        assert_eq!(c1.session_id, c3.session_id);
        assert_eq!(c1.hash, c3.hash);
        assert_ne!(c1.hash, co.hash);
    }

    #[test]
    fn short_messages_bypass_prefix_affinity_and_large_bodies_stay_bounded() {
        let ext = default_extractor();
        let h = HeaderMap::new();

        // Short message (< 64 bytes) -> None
        let short = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(ext.extract(&h, short, Some(ProtocolFamily::OpenAi), None, Some("gpt-4o")).is_none());

        // 2MB body with prompt_cache_key near end + huge middle padding
        let big_pad = "x".repeat(2 * 1024 * 1024);
        let big_body = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{big_pad}"}}],"prompt_cache_key":"tail-cache-key-77"}}"#
        );
        let c = ext
            .extract(&h, big_body.as_bytes(), Some(ProtocolFamily::OpenAi), None, Some("gpt-4o"))
            .unwrap();
        assert_eq!(c.source, "body:prompt_cache_key");

        // 2MB body without explicit key still computes bounded prefix_hash
        let big_prefix_body = format!(
            r#"{{"model":"gpt-4o","messages":[{{"role":"system","content":"System prompt long enough for affinity fingerprinting."}},{{"role":"user","content":"{big_pad}"}}]}}"#
        );
        let cp = ext
            .extract(&h, big_prefix_body.as_bytes(), Some(ProtocolFamily::OpenAi), None, Some("gpt-4o"))
            .unwrap();
        assert_eq!(cp.source, "prefix_hash");
    }

    #[test]
    fn namespace_isolates_models_and_tenants() {
        let ext = default_extractor();
        let mut h = HeaderMap::new();
        h.insert("session_id", "shared-session-123".parse().unwrap());

        let opus = ext.extract(&h, b"{}", None, Some(1), Some("claude-opus-4")).unwrap();
        let haiku = ext.extract(&h, b"{}", None, Some(1), Some("claude-haiku-4")).unwrap();
        let tenant2 = ext.extract(&h, b"{}", None, Some(2), Some("claude-opus-4")).unwrap();

        assert_ne!(opus.hash, haiku.hash);
        assert_ne!(opus.hash, tenant2.hash);
    }
}
