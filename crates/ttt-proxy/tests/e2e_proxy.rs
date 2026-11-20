use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream;
use http::{header, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use ttt_auth::{EncryptedTokenStore, TokenStore};
use ttt_core::{
    ClientKeyConfig, GatewayConfig, OAuthPreset, OAuthStorageConfig, PoolConfig, ProtocolFamily,
    ServerConfig, TapEvent, TelemetryConfig, UpstreamAuthConfig, UpstreamConfig,
};
use ttt_proxy::ProxyEngine;

async fn spawn_gateway(
    cfg: GatewayConfig,
    token_store: Option<Arc<dyn TokenStore>>,
) -> (SocketAddr, mpsc::Receiver<TapEvent>, tokio::task::JoinHandle<()>) {
    let (tap_tx, tap_rx) = mpsc::channel(256);
    let engine = Arc::new(ProxyEngine::new(&cfg, Some(tap_tx), token_store).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let engine = Arc::clone(&engine);
                    async move { engine.handle(req).await }
                });
                let _ = AutoConnBuilder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    (addr, tap_rx, handle)
}

async fn spawn_mock_upstream<F, Fut>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<BoxedBody>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let handler = Arc::clone(&handler);
                    async move { Ok::<_, std::convert::Infallible>(handler(req).await) }
                });
                let _ = AutoConnBuilder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    (addr, handle)
}

type BoxedBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

fn full_body(data: impl Into<Bytes>) -> BoxedBody {
    Full::new(data.into()).boxed()
}

#[tokio::test]
async fn e2e_api_key_rewrite_oauth_sse_tap_and_retry() {
    let (up_api_addr, _h1) = spawn_mock_upstream(|req| async move {
        let auth = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if req.uri().path() == "/v1/stream" {
            let chunks = vec![
                Ok(Frame::data(Bytes::from_static(
                    b"data: {\"delta\":\"hello\"}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"data: {\"delta\":\" world\"}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(b"data: [DONE]\n\n"))),
            ];
            let stream_body = StreamBody::new(stream::iter(chunks)).boxed();
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .header("x-seen-auth", auth)
                .body(stream_body)
                .unwrap();
        }

        let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-auth", auth)
            .body(full_body(body_bytes))
            .unwrap()
    })
    .await;

    let (up_oauth_addr, _h2) = spawn_mock_upstream(|req| async move {
        let auth = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let extra = req
            .headers()
            .get("x-custom-oauth")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(format!(
                r#"{{"auth":"{auth}","extra":"{extra}"}}"#
            )))
            .unwrap()
    })
    .await;

    let flaky_hits = Arc::new(AtomicUsize::new(0));
    let flaky_hits_clone = Arc::clone(&flaky_hits);
    let (up_flaky_addr, _h3) = spawn_mock_upstream(move |_req| {
        let hits = Arc::clone(&flaky_hits_clone);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(full_body("overloaded"))
                .unwrap()
        }
    })
    .await;

    let mut model_mapping = HashMap::new();
    model_mapping.insert("gpt-4-alias".to_string(), "gpt-4o-real".to_string());

    let mut oauth_extra = HashMap::new();
    oauth_extra.insert("x-custom-oauth".to_string(), "enabled".to_string());

    let cfg = GatewayConfig {
        server: ServerConfig {
            client_api_keys: vec!["gw-secret".to_string()],
            ..Default::default()
        },
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "api-base-up".into(),
                base_url: format!("http://{up_api_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-upstream-1".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["gpt-4-alias".into(), "*".into()],
                model_mapping,
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 1,
                owner_user_id: None,
                proxy: None,
            },
            UpstreamConfig {
                name: "oauth-up".into(),
                base_url: format!("http://{up_oauth_addr}"),
                protocol: ProtocolFamily::Anthropic,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::OAuth {
                    preset: Some(OAuthPreset::ClaudeCode),
                    access_token: Some("oauth-tok-999".into()),
                    refresh_token: Some("rt-999".into()),
                    expires_at: None,
                    authorize_url: None,
                    device_code_url: None,
                    token_url: None,
                    client_id: None,
                    client_secret: None,
                    scopes: vec![],
                    redirect_uri: None,
                    token_request_format: None,
                    account_id: None,
                    proactive_refresh_leeway_secs: 300,
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["claude-sonnet-4".into()],
                model_mapping: HashMap::new(),
                extra_headers: oauth_extra,
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
            UpstreamConfig {
                name: "flaky-primary".into(),
                base_url: format!("http://{up_flaky_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-flaky".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["retry-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 1,
                owner_user_id: None,
                proxy: None,
            },
            UpstreamConfig {
                name: "healthy-backup".into(),
                base_url: format!("http://{up_api_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-backup".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["retry-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 1,
                owner_user_id: None,
                proxy: None,
            },
        ],
    };

    let (gw_addr, mut tap_rx, _gw_handle) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1. Health check bypasses auth.
    let resp = client
        .request(
            Request::get(format!("http://{gw_addr}/healthz"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Unauthorized client rejected with 401.
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(br#"{"model":"gpt-4-alias"}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. API Base mode + zero-copy model rewrite + client key stripped.
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer gw-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"gpt-4-alias","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-seen-auth").unwrap().to_str().unwrap(),
        "Bearer sk-upstream-1"
    );
    let echoed = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        std::str::from_utf8(&echoed).unwrap(),
        r#"{"model":"gpt-4o-real","messages":[{"role":"user","content":"hi"}]}"#
    );

    // 4. Native OAuth mode routing + header injection.
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/messages"))
                .header("x-api-key", "gw-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"claude-sonnet-4"}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"auth":"Bearer oauth-tok-999","extra":"enabled"}"#
    );

    // 5. SSE zero-copy streaming + X-Accel-Buffering + Tap side-channel events.
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/stream"))
                .header(header::AUTHORIZATION, "Bearer gw-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"gpt-4-alias","stream":true}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-accel-buffering")
            .unwrap()
            .to_str()
            .unwrap(),
        "no"
    );
    let sse_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let sse_text = std::str::from_utf8(&sse_bytes).unwrap();
    assert!(sse_text.contains("hello"));
    assert!(sse_text.contains("world"));
    assert!(sse_text.contains("[DONE]"));

    let mut saw_first_byte = false;
    let mut saw_chunk = false;
    let mut saw_end = false;
    while let Ok(ev) = tap_rx.try_recv() {
        match ev {
            TapEvent::ResponseFirstByte { .. } => saw_first_byte = true,
            TapEvent::ResponseChunk { .. } => saw_chunk = true,
            TapEvent::ResponseEnd { .. } => saw_end = true,
            _ => {}
        }
    }
    assert!(saw_first_byte && saw_chunk && saw_end);

    // 6. Pre-first-byte retry on 503 automatically fails over to healthy backup.
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer gw-secret")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"retry-model"}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-ttt-upstream")
            .unwrap()
            .to_str()
            .unwrap(),
        "healthy-backup"
    );
    assert_eq!(flaky_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn e2e_oauth_401_singleflight_refresh_rotation_and_persistence() {
    let claude_refresh_calls = Arc::new(AtomicUsize::new(0));
    let codex_refresh_calls = Arc::new(AtomicUsize::new(0));

    let claude_calls = Arc::clone(&claude_refresh_calls);
    let codex_calls = Arc::clone(&codex_refresh_calls);

    // Mock OAuth token server supporting both Claude Code (JSON) and Codex (Form) endpoints.
    let (oauth_server_addr, _h_oauth) = spawn_mock_upstream(move |req| {
        let claude_calls = Arc::clone(&claude_calls);
        let codex_calls = Arc::clone(&codex_calls);
        async move {
            let path = req.uri().path().to_string();
            let ct = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let body_str = String::from_utf8_lossy(&body);

            // Simulate slight network latency so concurrent 401s pile up on the Singleflight lock.
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;

            if path == "/claude/token" {
                assert!(ct.contains("application/json"));
                assert!(body_str.contains(r#""grant_type":"refresh_token""#));
                assert!(body_str.contains(r#""refresh_token":"claude-rt-v1""#));
                let n = claude_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(n, 0, "Singleflight must coalesce concurrent refreshes into 1 call");
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(full_body(
                        r#"{"access_token":"claude-at-v2","refresh_token":"claude-rt-v2","expires_in":3600,"token_type":"Bearer"}"#,
                    ))
                    .unwrap();
            }

            if path == "/codex/token" {
                assert!(ct.contains("application/x-www-form-urlencoded"));
                assert!(body_str.contains("grant_type=refresh_token"));
                assert!(body_str.contains("refresh_token=codex-rt-v1"));
                codex_calls.fetch_add(1, Ordering::SeqCst);
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(full_body(
                        r#"{"access_token":"codex-at-v2","refresh_token":"codex-rt-v2","expires_in":3600,"token_type":"Bearer"}"#,
                    ))
                    .unwrap();
            }

            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(full_body("not found"))
                .unwrap()
        }
    })
    .await;

    // Mock LLM upstream that rejects v1 tokens with 401 and accepts v2 tokens with 200.
    let (llm_addr, _h_llm) = spawn_mock_upstream(|req| async move {
        let auth = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if auth == "Bearer claude-at-v2" || auth == "Bearer codex-at-v2" {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(full_body(format!(r#"{{"ok":true,"token":"{auth}"}}"#)))
                .unwrap();
        }
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(full_body(r#"{"error":"token_expired"}"#))
            .unwrap()
    })
    .await;

    let tmp_store_path = std::env::temp_dir().join(format!(
        "ttt-e2e-oauth-{}.enc",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp_store_path);
    let token_store = Arc::new(EncryptedTokenStore::with_key(&tmp_store_path, [42u8; 32]));

    let cfg = GatewayConfig {
        server: ServerConfig::default(),
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "claude-code-up".into(),
                base_url: format!("http://{llm_addr}"),
                protocol: ProtocolFamily::Anthropic,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::OAuth {
                    preset: Some(OAuthPreset::ClaudeCode),
                    access_token: Some("claude-at-v1-expired".into()),
                    refresh_token: Some("claude-rt-v1".into()),
                    expires_at: None,
                    authorize_url: None,
                    device_code_url: None,
                    token_url: Some(format!("http://{oauth_server_addr}/claude/token")),
                    client_id: Some("claude-cid".into()),
                    client_secret: None,
                    scopes: vec!["user:inference".into()],
                    redirect_uri: None,
                    token_request_format: None,
                    account_id: Some("claude-acct".into()),
                    proactive_refresh_leeway_secs: 300,
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["claude-sonnet-4".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
            UpstreamConfig {
                name: "codex-up".into(),
                base_url: format!("http://{llm_addr}"),
                protocol: ProtocolFamily::OpenAiResponses,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::OAuth {
                    preset: Some(OAuthPreset::Codex),
                    access_token: Some("codex-at-v1-expired".into()),
                    refresh_token: Some("codex-rt-v1".into()),
                    expires_at: None,
                    authorize_url: None,
                    device_code_url: None,
                    token_url: Some(format!("http://{oauth_server_addr}/codex/token")),
                    client_id: Some("codex-cid".into()),
                    client_secret: None,
                    scopes: vec!["openid".into()],
                    redirect_uri: None,
                    token_request_format: None,
                    account_id: Some("codex-acct".into()),
                    proactive_refresh_leeway_secs: 300,
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["gpt-5-codex".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
        ],
    };

    let (gw_addr, _tap_rx, _gw_handle) = spawn_gateway(
        cfg,
        Some(Arc::clone(&token_store) as Arc<dyn TokenStore>),
    )
    .await;

    // Fire 10 concurrent requests to Claude Code upstream with an expired token.
    // All 10 hit 401 -> Singleflight triggers exactly 1 JSON refresh -> all 10 transparently succeed!
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(tokio::spawn(async move {
            let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
            let resp = client
                .request(
                    Request::post(format!("http://{gw_addr}/v1/messages"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from_static(
                            br#"{"model":"claude-sonnet-4"}"#,
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(String::from_utf8_lossy(&body).contains("claude-at-v2"));
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(claude_refresh_calls.load(Ordering::SeqCst), 1);

    // Verify Codex upstream refreshes via form-urlencoded and transparently succeeds.
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/responses"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(br#"{"model":"gpt-5-codex"}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("codex-at-v2"));
    assert_eq!(codex_refresh_calls.load(Ordering::SeqCst), 1);

    // Verify rotated refresh tokens were atomically persisted encrypted on disk.
    let claude_persisted = token_store.get("claude-acct").unwrap().unwrap();
    assert_eq!(claude_persisted.access_token, "claude-at-v2");
    assert_eq!(
        claude_persisted.refresh_token.as_deref(),
        Some("claude-rt-v2")
    );

    let codex_persisted = token_store.get("codex-acct").unwrap().unwrap();
    assert_eq!(codex_persisted.access_token, "codex-at-v2");
    assert_eq!(
        codex_persisted.refresh_token.as_deref(),
        Some("codex-rt-v2")
    );

    let _ = std::fs::remove_file(&tmp_store_path);
}

#[tokio::test]
async fn e2e_cross_protocol_translation_streaming_and_non_streaming() {
    // Mock Anthropic upstream
    let (anthropic_addr, _h_ant) = spawn_mock_upstream(|req| async move {
        assert_eq!(req.uri().path(), "/v1/messages");
        assert!(req.headers().contains_key("anthropic-version"));
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false) {
            let chunks = vec![
                Ok(Frame::data(Bytes::from_static(
                    b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_s1\",\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":12}}}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello from claude\"}}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                ))),
            ];
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(StreamBody::new(stream::iter(chunks)).boxed())
                .unwrap();
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(
                r#"{"id":"msg_1","model":"claude-sonnet-4","content":[{"type":"text","text":"sync claude"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}"#,
            ))
            .unwrap()
    })
    .await;

    // Mock Gemini upstream
    let (gemini_addr, _h_gem) = spawn_mock_upstream(|req| async move {
        let pq = req.uri().path_and_query().unwrap().as_str().to_string();
        if pq.contains(":streamGenerateContent") {
            let chunks = vec![
                Ok(Frame::data(Bytes::from_static(
                    b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello from gemini\"}]}}]}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"!\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":4}}\n\n",
                ))),
            ];
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(StreamBody::new(stream::iter(chunks)).boxed())
                .unwrap();
        }
        assert!(pq.contains(":generateContent"));
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(
                r#"{"candidates":[{"content":{"parts":[{"text":"sync gemini"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":6,"candidatesTokenCount":2,"totalTokenCount":8}}"#,
            ))
            .unwrap()
    })
    .await;

    // Mock OpenAI upstream (to verify reverse Anthropic/Claude Code -> OpenAI translation)
    let (openai_addr, _h_oai) = spawn_mock_upstream(|req| async move {
        assert_eq!(req.uri().path(), "/v1/chat/completions");
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false) {
            let chunks = vec![
                Ok(Frame::data(Bytes::from_static(
                    b"data: {\"id\":\"chatcmpl-1\",\"model\":\"deepseek-chat\",\"choices\":[{\"delta\":{\"content\":\"from deepseek\"},\"finish_reason\":null}]}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"data: {\"id\":\"chatcmpl-1\",\"model\":\"deepseek-chat\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":4}}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(b"data: [DONE]\n\n"))),
            ];
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(StreamBody::new(stream::iter(chunks)).boxed())
                .unwrap();
        }
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(
                r#"{"id":"chatcmpl-1","model":"deepseek-chat","choices":[{"message":{"role":"assistant","content":"sync deepseek"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":3}}"#,
            ))
            .unwrap()
    })
    .await;

    let cfg = GatewayConfig {
        server: ServerConfig::default(),
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "anthropic-up".into(),
                base_url: format!("http://{anthropic_addr}/v1"),
                protocol: ProtocolFamily::Anthropic,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-ant".into()],
                    header_name: "x-api-key".into(),
                    prefix: None,
                },
                models: vec!["claude-sonnet-4".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
            UpstreamConfig {
                name: "gemini-up".into(),
                base_url: format!("http://{gemini_addr}/v1beta"),
                protocol: ProtocolFamily::Gemini,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["AIza-test".into()],
                    header_name: "x-goog-api-key".into(),
                    prefix: None,
                },
                models: vec!["gemini-2.5-flash".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
            UpstreamConfig {
                name: "deepseek-openai-up".into(),
                base_url: format!("http://{openai_addr}/v1"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-ds".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["deepseek-chat".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
        ],
    };

    let (gw_addr, _tap_rx, _gw) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1. OpenAI client -> Anthropic upstream (non-streaming + streaming)
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "sync claude");

    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"claude-sonnet-4","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sse = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(sse.contains("hello from claude"));
    assert!(sse.contains("[DONE]"));

    // 2. OpenAI client -> Gemini upstream (streaming)
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"gemini-2.5-flash","stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sse = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(sse.contains("hello from gemini"));
    assert!(sse.contains("[DONE]"));

    // 3. Anthropic/Claude Code client -> OpenAI/DeepSeek upstream (streaming)
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/messages"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"deepseek-chat","max_tokens":100,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sse = String::from_utf8(
        resp.into_body().collect().await.unwrap().to_bytes().to_vec(),
    )
    .unwrap();
    assert!(sse.contains("event: message_start"));
    assert!(sse.contains("from deepseek"));
    assert!(sse.contains("event: message_stop"));
}

#[tokio::test]
async fn e2e_client_key_provider_and_model_restrictions() {
    let (up_a_addr, _ha) = spawn_mock_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(r#"{"provider":"a"}"#))
            .unwrap()
    })
    .await;

    let (up_b_addr, _hb) = spawn_mock_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(full_body(r#"{"provider":"b"}"#))
            .unwrap()
    })
    .await;

    let cfg = GatewayConfig {
        server: ServerConfig {
            client_keys: vec![
                ClientKeyConfig {
                    key: "sk-model-only".into(),
                    name: "model-limited".into(),
                    enabled: true,
                    restrict_upstreams: false,
                    allowed_upstreams: vec![],
                    restrict_models: true,
                    allowed_models: vec!["gpt-4o".into()],
                    owner_user_id: None,
                },
                ClientKeyConfig {
                    key: "sk-provider-only".into(),
                    name: "provider-limited".into(),
                    enabled: true,
                    restrict_upstreams: true,
                    allowed_upstreams: vec!["provider-a".into()],
                    restrict_models: false,
                    allowed_models: vec![],
                    owner_user_id: None,
                },
                ClientKeyConfig {
                    key: "sk-disabled".into(),
                    name: "disabled".into(),
                    enabled: false,
                    restrict_upstreams: false,
                    allowed_upstreams: vec![],
                    restrict_models: false,
                    allowed_models: vec![],
                    owner_user_id: None,
                },
            ],
            ..Default::default()
        },
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "provider-a".into(),
                base_url: format!("http://{up_a_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-a".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["gpt-4o".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
            UpstreamConfig {
                name: "provider-b".into(),
                base_url: format!("http://{up_b_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-b".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["deepseek-chat".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
            },
        ],
    };

    let (gw_addr, _tap_rx, _gw) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // Disabled key -> 401
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-disabled")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(br#"{"model":"gpt-4o"}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Model-restricted key: allowed model -> 200, disallowed model -> 403
    let ok_resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-model-only")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(br#"{"model":"gpt-4o"}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);

    let denied_model = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-model-only")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"deepseek-chat"}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_model.status(), StatusCode::FORBIDDEN);

    // Provider-restricted key: provider-a -> 200, provider-b -> 403
    let ok_provider = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-provider-only")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(br#"{"model":"gpt-4o"}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_provider.status(), StatusCode::OK);

    let denied_provider = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-provider-only")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"deepseek-chat"}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_provider.status(), StatusCode::FORBIDDEN);

    // `/v1/models` filtered by key scope
    let models_resp = client
        .request(
            Request::get(format!("http://{gw_addr}/v1/models"))
                .header(header::AUTHORIZATION, "Bearer sk-provider-only")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(models_resp.status(), StatusCode::OK);
    let models_body = String::from_utf8(
        models_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(models_body.contains("gpt-4o"));
    assert!(!models_body.contains("deepseek-chat"));
}

#[tokio::test]
async fn e2e_multi_protocol_endpoints_zero_copy_routing() {
    // A single mock upstream simulating Volcengine Agent Plan serving both
    // Anthropic (/api/plan/v1/messages) and OpenAI (/api/plan/v3/chat/completions) natively.
    let (multi_addr, _hm) = spawn_mock_upstream(|req| async move {
        let path = req.uri().path().to_string();
        let ant_ver = req
            .headers()
            .get("anthropic-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-hit-path", path)
            .header("x-seen-ant-ver", ant_ver)
            .body(full_body(body))
            .unwrap()
    })
    .await;

    let mut protocol_endpoints = HashMap::new();
    protocol_endpoints.insert(
        ProtocolFamily::Anthropic,
        format!("http://{multi_addr}/api/plan/v1"),
    );
    protocol_endpoints.insert(
        ProtocolFamily::OpenAi,
        format!("http://{multi_addr}/api/plan/v3"),
    );

    let mut ant_headers = HashMap::new();
    ant_headers.insert("anthropic-version".to_string(), "2023-06-01".to_string());
    let mut protocol_headers = HashMap::new();
    protocol_headers.insert(ProtocolFamily::Anthropic, ant_headers);

    let cfg = GatewayConfig {
        server: ServerConfig::default(),
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        upstreams: vec![UpstreamConfig {
            name: "volcengine-agent-plan".into(),
            base_url: String::new(),
            protocol: ProtocolFamily::Anthropic,
            protocol_endpoints,
            auth: UpstreamAuthConfig::ApiKey {
                keys: vec!["sk-ark".into()],
                header_name: "authorization".into(),
                prefix: Some("Bearer ".into()),
            },
            models: vec!["ark-code-latest".into()],
            model_mapping: HashMap::new(),
            extra_headers: HashMap::new(),
            protocol_headers,
            weight: 1,
            default_cooldown_secs: 10,
            max_retries: 0,
            owner_user_id: None,
            proxy: None,
        }],
    };

    let (gw_addr, _tap_rx, _gw) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1. Anthropic client -> zero-copy pass-through to /api/plan/v1/messages + anthropic-version header
    let raw_ant = br#"{"model":"ark-code-latest","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}"#;
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/messages"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(raw_ant)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-hit-path").unwrap().to_str().unwrap(),
        "/api/plan/v1/messages"
    );
    assert_eq!(
        resp.headers()
            .get("x-seen-ant-ver")
            .unwrap()
            .to_str()
            .unwrap(),
        "2023-06-01"
    );
    assert_eq!(
        resp.into_body().collect().await.unwrap().to_bytes().as_ref(),
        raw_ant
    );

    // 2. OpenAI client -> zero-copy pass-through to /api/plan/v3/chat/completions WITHOUT anthropic-version
    let raw_oai = br#"{"model":"ark-code-latest","messages":[{"role":"user","content":"hi"}]}"#;
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(raw_oai)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-hit-path").unwrap().to_str().unwrap(),
        "/api/plan/v3/chat/completions"
    );
    assert_eq!(
        resp.headers()
            .get("x-seen-ant-ver")
            .unwrap()
            .to_str()
            .unwrap(),
        ""
    );
    assert_eq!(
        resp.into_body().collect().await.unwrap().to_bytes().as_ref(),
        raw_oai
    );
}

#[tokio::test]
async fn e2e_claude_code_oauth_compat_mode() {
    let (mock_addr, _hm) = spawn_mock_upstream(|req| async move {
        let pq = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let beta = req
            .headers()
            .get("anthropic-beta")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let ua = req
            .headers()
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let x_app = req
            .headers()
            .get("x-app")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body).into_owned();
        let resp_json = serde_json::json!({
            "id": "msg_cc",
            "model": "claude-sonnet-4-20250514",
            "content": [{"type": "text", "text": body_str}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 3}
        });
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-pq", pq)
            .header("x-seen-beta", beta)
            .header("x-seen-ua", ua)
            .header("x-seen-xapp", x_app)
            .body(full_body(resp_json.to_string()))
            .unwrap()
    })
    .await;

    let mut protocol_endpoints = HashMap::new();
    protocol_endpoints.insert(ProtocolFamily::Anthropic, "/v1/messages".to_string());

    let cfg = GatewayConfig {
        server: ServerConfig::default(),
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        upstreams: vec![UpstreamConfig {
            name: "claude-code-oauth".into(),
            base_url: format!("http://{mock_addr}"),
            protocol: ProtocolFamily::Anthropic,
            protocol_endpoints,
            auth: UpstreamAuthConfig::OAuth {
                preset: Some(OAuthPreset::ClaudeCode),
                access_token: Some("sk-ant-oat-test".into()),
                refresh_token: None,
                expires_at: None,
                authorize_url: None,
                device_code_url: None,
                token_url: None,
                client_id: None,
                client_secret: None,
                scopes: vec![],
                redirect_uri: None,
                token_request_format: None,
                account_id: Some("cc-acct".into()),
                proactive_refresh_leeway_secs: 300,
                header_name: "authorization".into(),
                prefix: Some("Bearer ".into()),
            },
            models: vec!["claude-sonnet-4-20250514".into()],
            model_mapping: HashMap::new(),
            extra_headers: HashMap::new(),
            protocol_headers: HashMap::new(),
            weight: 1,
            default_cooldown_secs: 10,
            max_retries: 0,
            owner_user_id: None,
            proxy: None,
        }],
    };

    let (gw_addr, _tap_rx, _gw) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1. OpenAI client calling Claude Code OAuth -> gets ?beta=true, CLI headers, merged beta, system identity block
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"claude-sonnet-4-20250514","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-seen-pq").unwrap().to_str().unwrap(),
        "/v1/messages?beta=true"
    );
    let beta = resp.headers().get("x-seen-beta").unwrap().to_str().unwrap();
    assert!(beta.contains("claude-code-20250219"));
    assert!(beta.contains("oauth-2025-04-20"));
    assert!(
        resp.headers()
            .get("x-seen-ua")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("claude-cli/")
    );
    assert_eq!(
        resp.headers().get("x-seen-xapp").unwrap().to_str().unwrap(),
        "cli"
    );
    let oai_resp: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let sent_body: serde_json::Value =
        serde_json::from_str(oai_resp["choices"][0]["message"]["content"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        sent_body["system"][0]["text"],
        "You are Claude Code, Anthropic's official CLI for Claude."
    );
    assert_eq!(sent_body["system"][1]["text"], "be brief");

    // 2. Real Claude Code CLI client -> preserves its UA, merges beta flags, and does NOT mutate body
    let raw_cli = br#"{"model":"claude-sonnet-4-20250514","system":[{"type":"text","text":"You are Claude Code, Anthropic's official CLI for Claude."}],"max_tokens":64,"messages":[{"role":"user","content":"hi"}]}"#;
    let resp = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/messages"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::USER_AGENT, "claude-cli/2.1.300 (external, cli)")
                .header("anthropic-beta", "prompt-caching-2024-07-31")
                .body(Full::new(Bytes::from_static(raw_cli)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-seen-ua").unwrap().to_str().unwrap(),
        "claude-cli/2.1.300 (external, cli)"
    );
    let beta2 = resp.headers().get("x-seen-beta").unwrap().to_str().unwrap();
    assert!(beta2.contains("prompt-caching-2024-07-31"));
    assert!(beta2.contains("oauth-2025-04-20"));
    let ant_resp: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        ant_resp["content"][0]["text"].as_str().unwrap().as_bytes(),
        raw_cli
    );
}
