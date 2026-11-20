# TalkThatTalk

High-performance, zero-copy AI unified gateway written in Rust, natively supporting both **API Base** and **OAuth 2.0** (Codex & Claude Code compatible) upstream authentication modes.

## Features (Phase 1 + Phase 2)

- **Zero-Copy Data Plane (`ttt-proxy`)**:
  - Built on `Tokio` + `Hyper 1.x` + `hyper-util` + `rustls` (HTTP/1.1 & HTTP/2 multiplexing, `TCP_NODELAY`, pooled keep-alive connections).
  - **Pure Streaming Fast Path**: Streams `hyper::body::Incoming` directly to upstream without buffering or JSON parsing when no model routing/mapping is needed.
  - **Zero-Deserialization Model Routing & Slice Rewriting**: Uses SIMD `memchr::memmem` to locate `"model"` in raw JSON bytes without full DOM parsing; rewrites mapped model aliases via 3-segment zero-copy `SegmentedBody`.
  - **Zero-Copy SSE Tap & Async Usage Accounting**: `TapBody` emits O(1) `Bytes::clone()` slices and TTFT metrics to a bounded async channel; `UsageAccumulator` extracts OpenAI/Codex & Anthropic/Claude Code token usage completely off the hot path.
  - **Pre-First-Byte Retry & Transparent 401 OAuth Refresh**: Automatically refreshes expired OAuth tokens via Singleflight on `401` and retries transparently, and fails over to healthy upstreams on `429`/`502`/`503`/`504`.
- **Dual Upstream Auth (`ttt-auth`)**:
  - **API Base Mode**: Lock-free round-robin key pool with pre-encoded `HeaderValue` (zero allocation on hot path) and per-key 429 cooldown.
  - **Native OAuth 2.0 Mode (Codex & Claude Code Presets)**:
    - Authorization Code + PKCE (RFC 7636, supports both local callback server and Claude Code `code#state` paste).
    - Device Code Flow (RFC 8628) & Client Credentials (RFC 6749 §4.4).
    - Dual wire-format token client (`form` for Codex / RFC 6749, `json` for Claude Code).
    - Lock-free `ArcSwap` token reads, background proactive pre-refresh, `Singleflight` 401 coalescing, and **AES-256-GCM encrypted atomic persistence** (`EncryptedTokenStore`).
- **Production Server & CLI (`ttt-server`)**:
  - `talkthattalk serve --config config.toml`
  - `talkthattalk auth login --upstream <name> --config config.toml [--device | --manual]`
  - `talkthattalk auth status --config config.toml`
  - `/healthz` & `/readyz` probes, optional ingress API key auth, `X-Accel-Buffering: no` for SSE, and graceful shutdown draining active SSE streams.

## Workspace Layout

```text
├── Cargo.toml
├── config.example.toml
└── crates/
    ├── ttt-core/      # Config (Codex/ClaudeCode presets), error envelope, TapEvent
    ├── ttt-auth/      # ApiKeyPool, OAuthTokenManager, PKCE, OAuthHttpClient, AES-256-GCM Store
    ├── ttt-proxy/     # Zero-copy proxy engine, TapBody, SegmentedBody, Router, UsageAccumulator
    └── ttt-server/    # Binary entrypoint (talkthattalk), auth CLI & graceful shutdown
```

## Quick Start

```bash
cp config.example.toml config.toml

# 1. Authenticate OAuth upstreams (Codex / Claude Code)
cargo run --release --bin talkthattalk -- auth login --upstream codex-oauth --config config.toml
cargo run --release --bin talkthattalk -- auth login --upstream claude-code-oauth --config config.toml

# 2. Check OAuth token status
cargo run --release --bin talkthattalk -- auth status --config config.toml

# 3. Start the gateway
cargo run --release --bin talkthattalk -- serve --config config.toml
```

## Run Tests

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
