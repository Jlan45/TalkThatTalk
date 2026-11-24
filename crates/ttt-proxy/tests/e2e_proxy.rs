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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use ttt_auth::{EncryptedTokenStore, OAuthHttpClient, StoredOAuthToken, TokenStore};
use ttt_core::{
    ClientKeyConfig, GatewayConfig, GatewayError, OAuthPreset, OAuthStorageConfig, PoolConfig,
    ProtocolFamily, ProxyConfig, ServerConfig, StreamFailure, TapEvent, TelemetryConfig,
    TokenRequestFormat, UpstreamAuthConfig, UpstreamConfig,
};
use ttt_proxy::ProxyEngine;

async fn spawn_gateway(
    cfg: GatewayConfig,
    token_store: Option<Arc<dyn TokenStore>>,
) -> (SocketAddr, mpsc::Receiver<TapEvent>, tokio::task::JoinHandle<()>) {
    let (tap_tx, tap_rx) = mpsc::channel(256);
    let engine = Arc::new(ProxyEngine::new(&cfg, Some(tap_tx), token_store).unwrap());
    let (addr, handle) = serve_gateway(engine).await;
    (addr, tap_rx, handle)
}

async fn serve_gateway(engine: Arc<ProxyEngine>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

    (addr, handle)
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
async fn ttft_starts_after_the_outbound_upload_finishes() {
    use std::time::Duration;
    use tokio::sync::{Notify, oneshot};

    let first_frame_read = Arc::new(Notify::new());
    let notify = Arc::clone(&first_frame_read);
    let (upstream, _upstream_task) = spawn_mock_upstream(move |req| {
        let notify = Arc::clone(&notify);
        async move {
            let mut body = req.into_body();
            assert!(body.frame().await.unwrap().unwrap().is_data());
            notify.notify_one();
            body.collect().await.unwrap();
            Response::new(full_body("answer"))
        }
    })
    .await;
    let cfg = serde_json::from_value(serde_json::json!({
        "server": { "max_inspect_body_bytes": 1 },
        "upstreams": [{
            "name": "mock",
            "base_url": format!("http://{upstream}"),
            "auth": { "type": "api_key", "keys": ["mock-key"] }
        }]
    }))
    .unwrap();
    let (gateway, mut tap, _gateway_task) = spawn_gateway(cfg, None).await;

    let head = Bytes::from_static(br#"{"model":"mock","messages":"#);
    let tail = Bytes::from_static(b"[]}");
    let content_len = head.len() + tail.len();
    let (finish_upload, wait_for_tail) = oneshot::channel();
    let chunks = futures_util::StreamExt::chain(
        stream::iter([Ok(Frame::data(head))]),
        stream::once(async move {
            wait_for_tail.await.unwrap();
            Ok(Frame::data(tail))
        }),
    );
    let client: Client<_, BoxedBody> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::post(format!("http://{gateway}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, content_len)
        .body(StreamBody::new(chunks).boxed())
        .unwrap();
    let response = client.request(req);
    let verify = tokio::spawn(async move {
        let resp = response.await.unwrap();
        assert_eq!(resp.into_body().collect().await.unwrap().to_bytes(), "answer");
        loop {
            if let TapEvent::ResponseEnd { ttft_ms, duration_ms, .. } = tap.recv().await.unwrap() {
                assert!(duration_ms.saturating_sub(ttft_ms.unwrap()) >= 225);
                break;
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(5), first_frame_read.notified()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    finish_upload.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), verify).await.unwrap().unwrap();
}

#[tokio::test]
async fn clash_routes_named_proxy_and_preserves_it_on_failed_update() {
    let (upstream, _upstream_task) = spawn_mock_upstream(|_| async {
        Response::new(full_body(r#"{"proxied":true}"#))
    })
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let socks_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            client.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            client.write_all(&[5, 2]).await.unwrap();

            let mut credentials = [0; 11];
            client.read_exact(&mut credentials).await.unwrap();
            assert_eq!(&credentials, b"\x01\x04user\x04pass");
            client.write_all(&[1, 0]).await.unwrap();

            let expected = b"\x05\x01\x00\x03\x0froute-only.test\x00\x50";
            let mut target = vec![0; expected.len()];
            client.read_exact(&mut target).await.unwrap();
            assert_eq!(target, expected);
            let mut upstream = TcpStream::connect(upstream).await.unwrap();
            client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });

    let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
        "server": { "client_api_keys": ["gateway-key"] },
        "upstreams": [{
            "name": "routed",
            "base_url": "http://route-only.test",
            "auth": { "type": "api_key", "keys": ["upstream-key"] },
            "proxy": "named-proxy"
        }]
    }))
    .unwrap();
    let proxy: ProxyConfig = serde_json::from_value(serde_json::json!({
        "name": "named-proxy",
        "protocol": "socks5",
        "server": "127.0.0.1",
        "port": port,
        "username": "user",
        "password": "pass"
    }))
    .unwrap();
    let engine = Arc::new(ProxyEngine::new(&cfg, None, None).unwrap());
    engine.reload_proxies(&[proxy]).unwrap();
    let manager = engine.clash_manager();
    assert!(
        manager.update("named-proxy", None, || {
            Err(GatewayError::Internal("simulated database failure".into()))
        })
        .is_err()
    );
    assert_eq!(
        manager.test_proxy("named-proxy", "http://route-only.test/").await.unwrap().0,
        200
    );

    let (gw_addr, _gateway_task) = serve_gateway(Arc::clone(&engine)).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::post(format!("http://{gw_addr}/v1/chat/completions"))
        .header(header::AUTHORIZATION, "Bearer gateway-key")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(br#"{"model":"routed"}"#)))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.into_body().collect().await.unwrap().to_bytes(),
        br#"{"proxied":true}"#.as_slice()
    );
    socks_task.await.unwrap();
    manager.update("named-proxy", None, || Ok(())).unwrap();
    assert!(!manager.is_active("named-proxy"));
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
        routing: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
    let mut saw_stream_end = false;
    let mut saw_json_end = false;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !(saw_first_byte && saw_chunk && saw_stream_end && saw_json_end) {
            match tap_rx.recv().await.unwrap() {
                TapEvent::ResponseFirstByte { .. } => saw_first_byte = true,
                TapEvent::ResponseChunk { .. } => saw_chunk = true,
                TapEvent::ResponseEnd { is_stream: true, .. } => saw_stream_end = true,
                TapEvent::ResponseEnd { is_stream: false, .. } => saw_json_end = true,
                _ => {}
            }
        }
    })
    .await
    .expect("missing JSON or SSE tap events");

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
        routing: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
async fn antigravity_discovers_project_and_preserves_it_on_refresh() {
    let discovery_calls = Arc::new(AtomicUsize::new(0));
    let (upstream, _task) = spawn_mock_upstream({
        let discovery_calls = Arc::clone(&discovery_calls);
        move |request| {
            let discovery_calls = Arc::clone(&discovery_calls);
            async move {
                let (parts, body) = request.into_parts();
                let body = body.collect().await.unwrap().to_bytes();
                let authorization = parts.headers.get(header::AUTHORIZATION);
                match parts.uri.path() {
                    "/v1internal:loadCodeAssist" => {
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(body["metadata"]["ideType"], "ANTIGRAVITY");
                        let previous_calls = discovery_calls.fetch_add(1, Ordering::SeqCst);
                        let response = match authorization.unwrap().to_str().unwrap() {
                            "Bearer legacy-access" => r#"{"cloudaicompanionProject":{"id":"legacy-project"}}"#,
                            "Bearer new-access" if previous_calls == 1 => "{}",
                            "Bearer new-access" => r#"{"cloudaicompanionProject":"new-project"}"#,
                            _ => panic!("unexpected discovery credential"),
                        };
                        Response::new(full_body(response))
                    }
                    "/v1internal:listCloudAICompanionProjects" => {
                        assert_eq!(authorization.unwrap(), "Bearer new-access");
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(full_body(""))
                            .unwrap()
                    }
                    "/token" => {
                        let form = std::str::from_utf8(&body).unwrap();
                        assert!(form.contains("client_id=test-client"));
                        assert!(form.contains("client_secret=test-secret"));
                        if form.contains("grant_type=authorization_code") {
                            assert!(form.contains("code=test-code"));
                            assert!(form.contains("code_verifier=test-verifier"));
                            return Response::new(full_body(
                                r#"{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}"#,
                            ));
                        }
                        assert!(form.contains("grant_type=refresh_token"));
                        assert!(form.contains("refresh_token=legacy-refresh"));
                        Response::new(full_body(
                            r#"{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}"#,
                        ))
                    }
                    "/v1internal:generateContent" => {
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let expected = match authorization.unwrap().to_str().unwrap() {
                            "Bearer legacy-access" | "Bearer rotated-access" => "legacy-project",
                            "Bearer new-access" => "new-project",
                            _ => panic!("unexpected model credential"),
                        };
                        assert_eq!(body["project"], expected);
                        if authorization.unwrap() == "Bearer legacy-access" {
                            return Response::builder()
                                .status(StatusCode::UNAUTHORIZED)
                                .body(full_body(""))
                                .unwrap();
                        }
                        Response::new(full_body(
                            r#"{"response":{"candidates":[{"content":{"parts":[{"text":"ok"}]},"finishReason":"STOP"}]}}"#,
                        ))
                    }
                    path => panic!("unexpected upstream path {path}"),
                }
            }
        }
    })
    .await;
    let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
        "upstreams": [{
            "name": "antigravity",
            "base_url": format!("http://{upstream}"),
            "protocol": "antigravity",
            "auth": {
                "type": "oauth",
                "preset": "antigravity",
                "token_url": format!("http://{upstream}/token"),
                "client_id": "test-client",
                "client_secret": "test-secret"
            }
        }]
    }))
    .unwrap();
    let path = std::env::temp_dir().join(format!("ttt-e2e-antigravity-{}.enc", std::process::id()));
    let store = Arc::new(EncryptedTokenStore::with_key(&path, [42; 32]));
    store
        .put(
            "antigravity",
            StoredOAuthToken {
                access_token: "legacy-access".into(),
                refresh_token: Some("legacy-refresh".into()),
                expires_at: None,
                token_type: None,
                scope: None,
                extra: HashMap::new(),
            },
        )
        .unwrap();
    let engine = Arc::new(ProxyEngine::new(&cfg, None, Some(store.clone())).unwrap());
    let (gateway, _task) = serve_gateway(engine.clone()).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let generate = || async {
        let resp = client
            .request(
                Request::post(format!("http://{gateway}/v1/chat/completions"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from_static(
                        br#"{"model":"test","messages":[{"role":"user","content":"Hello"}]}"#,
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["choices"][0]["message"]["content"], "ok");
    };

    generate().await;
    let stored = store.get("antigravity").unwrap().unwrap();
    assert_eq!(stored.access_token, "rotated-access");
    assert_eq!(stored.antigravity_project_id(), Some("legacy-project"));
    engine.router().reload(&cfg.upstreams).unwrap();
    generate().await;
    assert_eq!(discovery_calls.load(Ordering::SeqCst), 1);

    let oauth = OAuthHttpClient::new();
    let token = oauth
        .exchange_code(
            &format!("http://{upstream}/token"),
            TokenRequestFormat::Form,
            "test-code",
            "test-verifier",
            "http://localhost:51121/oauth-callback",
            "test-client",
            Some("test-secret"),
            None,
        )
        .await
        .unwrap();
    let record = oauth
        .complete_login(&cfg.upstreams[0], token)
        .await
        .unwrap();
    assert_eq!(record.access_token, "new-access");
    assert_eq!(record.antigravity_project_id(), None);
    let node = &engine.router().all_nodes()[0];
    node.auth
        .oauth_manager()
        .unwrap()
        .install_login(record)
        .await
        .unwrap();
    assert_eq!(store.get("antigravity").unwrap().unwrap().access_token, "new-access");
    engine.router().reload(&cfg.upstreams).unwrap();
    generate().await;
    assert_eq!(discovery_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        store
            .get("antigravity")
            .unwrap()
            .unwrap()
            .antigravity_project_id(),
        Some("new-project")
    );
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn e2e_cross_protocol_translation_streaming_and_non_streaming() {
    // Mock Anthropic upstream
    let (anthropic_addr, _h_ant) = spawn_mock_upstream(|req| async move {
        assert_eq!(req.uri().path(), "/v1/messages");
        assert!(req.headers().contains_key("anthropic-version"));
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let scenario = v.pointer("/messages/0/content").and_then(|v| v.as_str());
        if scenario == Some("json-error") {
            return Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(full_body(r#"{"type":"error","error":{"message":"upstream rejected request"}}"#))
                .unwrap();
        }
        if v["stream"] == true && scenario != Some("json-fallback") {
            let mut chunks = vec![
                Ok(Frame::data(Bytes::from_static(
                    b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_s1\",\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":12}}}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\r",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"\ndata: \"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello from claude\"}}\r\n\r\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
                ))),
                Ok(Frame::data(Bytes::from_static(
                    b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                ))),
            ];
            if scenario == Some("early-eof") {
                chunks.truncate(3);
            }
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(StreamBody::new(stream::iter(chunks)).boxed())
                .unwrap();
        }
        let chunks = futures_util::StreamExt::chain(
            stream::iter([Ok(Frame::data(Bytes::from_static(br#"{"id":"msg_1","model":"claude-sonnet-4","#)))]),
            stream::once(async {
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                Ok(Frame::data(Bytes::from_static(br#""content":[{"type":"text","text":"sync claude"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}"#)))
            }),
        );
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(StreamBody::new(chunks).boxed())
            .unwrap()
    })
    .await;

    // Mock Gemini upstream
    let (gemini_addr, _h_gem) = spawn_mock_upstream(|req| async move {
        let pq = req.uri().path_and_query().unwrap().as_str().to_string();
        if pq.contains(":streamGenerateContent") {
            if !pq.contains("alt=sse") {
                let chunks = vec![
                    Ok(Frame::data(Bytes::from_static(b"[{}"))),
                    Ok(Frame::data(Bytes::from_static(b",{}]"))),
                ];
                return Response::builder()
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(StreamBody::new(stream::iter(chunks)).boxed())
                    .unwrap();
            }
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
        routing: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
        ],
    };

    let (gw_addr, mut tap_rx, _gw) = spawn_gateway(cfg, None).await;
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

    let stream_statuses = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut statuses = Vec::new();
        while statuses.len() < 2 {
            if let TapEvent::ResponseEnd { is_stream, ttft_ms, duration_ms, .. } = tap_rx.recv().await.unwrap() {
                if !is_stream {
                    assert!(duration_ms.saturating_sub(ttft_ms.unwrap()) >= 70);
                }
                statuses.push(is_stream);
            }
        }
        statuses
    })
    .await
    .expect("missing translated response tap events");
    assert_eq!(stream_statuses, [false, true]);

    for scenario in ["json-fallback", "early-eof", "json-error"] {
        let request = serde_json::json!({
            "model": "claude-sonnet-4", "stream": true,
            "messages": [{"role": "user", "content": scenario}],
        });
        let resp = client
            .request(
                Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(request.to_string())))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let content_type = resp.headers()[header::CONTENT_TYPE].clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&body).unwrap();
        if scenario == "json-error" {
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert!(text.contains("upstream rejected request"));
            continue;
        }
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type, "text/event-stream; charset=utf-8");
        if scenario == "json-fallback" {
            assert!(text.contains("sync claude") && text.contains("[DONE]"));
        } else {
            assert!(text.contains("hello from claude"));
            assert!(text.contains("upstream_stream_error"));
            assert!(!text.contains("[DONE]"));
        }
    }

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

    let resp = client
        .request(
            Request::post(format!(
                "http://{gw_addr}/v1beta/models/gemini-2.5-flash:streamGenerateContent"
            ))
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-ttt-model", "gemini-2.5-flash")
            .body(Full::new(Bytes::from_static(b"{}")))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let native_req_id = resp.headers()["x-ttt-request-id"].to_str().unwrap().to_owned();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"[{},{}]");
    let is_stream = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let TapEvent::ResponseEnd { req_id, is_stream, .. } = tap_rx.recv().await.unwrap()
                && req_id.to_string() == native_req_id
            {
                return is_stream;
            }
        }
    })
    .await
    .expect("missing native Gemini response tap event");
    assert!(is_stream);
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
        routing: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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
    const CHAT_DELTA: &str =
        "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"},\"finish_reason\":null}]}\n\n";
    const MESSAGES_DELTA: &str = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n";
    const CHAT_END: &str = "data: [DONE]\n\n";
    const MESSAGES_END: &str = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    const STREAM_ERROR: &str =
        "event: error\ndata: {\"type\":\"error\",\"error\":{\"message\":\"provider error\"}}\n\n";

    // A single mock upstream simulating Volcengine Agent Plan serving both
    // Anthropic (/api/plan/v1/messages) and OpenAI (/api/plan/v3/chat/completions) natively.
    let stream_calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&stream_calls);
    let (multi_addr, _hm) = spawn_mock_upstream(move |req| {
        let counter = Arc::clone(&counter);
        async move {
            let path = req.uri().path().to_string();
            assert_eq!(req.headers()[header::AUTHORIZATION], "Bearer sk-ark");
            let stream_case = req.uri().query().map(str::to_owned);
            let ant_ver = req
                .headers()
                .get("anthropic-version")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = req.into_body().collect().await.unwrap().to_bytes();
            if let Some(stream_case) = stream_case {
                counter.fetch_add(1, Ordering::SeqCst);
                let (delta, end) = match path.as_str() {
                    "/api/plan/v3/chat/completions" => (CHAT_DELTA, CHAT_END),
                    "/api/plan/v1/messages" => (MESSAGES_DELTA, MESSAGES_END),
                    _ => panic!("unexpected Agent Plan path {path}"),
                };
                let body = match stream_case.as_str() {
                    "complete" => full_body(format!("{delta}{end}")),
                    "truncated" => full_body(delta),
                    "error" => full_body(format!("{delta}{STREAM_ERROR}")),
                    "disconnect" => StreamBody::new(futures_util::StreamExt::chain(
                        stream::iter([Ok(Frame::data(Bytes::from_static(delta.as_bytes())))]),
                        stream::pending(),
                    ))
                    .boxed(),
                    _ => panic!("unexpected stream case"),
                };
                return Response::builder()
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(body)
                    .unwrap();
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-hit-path", path)
                .header("x-seen-ant-ver", ant_ver)
                .body(full_body(body))
                .unwrap()
        }
    })
    .await;

    let mut protocol_endpoints = HashMap::new();
    protocol_endpoints.insert(
        ProtocolFamily::Anthropic,
        format!("http://{multi_addr}/api/plan/v1/messages"),
    );
    protocol_endpoints.insert(
        ProtocolFamily::OpenAi,
        format!("http://{multi_addr}/api/plan/v3/chat/completions"),
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
        routing: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
        }],
    };

    let (gw_addr, mut tap_rx, _gw) = spawn_gateway(cfg, None).await;
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

    for (path, delta, end, marker) in [
        (
            "/v1/messages",
            MESSAGES_DELTA,
            MESSAGES_END,
            "without message_stop",
        ),
        (
            "/v1/chat/completions",
            CHAT_DELTA,
            CHAT_END,
            "without [DONE]",
        ),
    ] {
        let mut previous_id = None;
        for (scenario, expected_failure) in [
            ("disconnect", Some(StreamFailure::ClientDisconnected)),
            ("complete", None),
            ("truncated", Some(StreamFailure::Incomplete)),
            ("error", Some(StreamFailure::UpstreamError)),
        ] {
            let response = client
                .request(
                    Request::post(format!("http://{gw_addr}{path}?{scenario}"))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from_static(
                            br#"{"model":"ark-code-latest","stream":true,"max_tokens":64,"messages":[{"role":"user","content":"hi"}]}"#,
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let id = response.headers()["x-ttt-request-id"]
                .to_str()
                .unwrap()
                .to_owned();
            assert_ne!(previous_id.replace(id.clone()).as_ref(), Some(&id));
            let mut body = response.into_body();
            if scenario == "disconnect" {
                let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
                assert_eq!(data.as_ref(), delta.as_bytes());
                drop(body);
            } else {
                let data = body.collect().await.unwrap().to_bytes();
                let text = std::str::from_utf8(&data).unwrap();
                match scenario {
                    "complete" => assert_eq!(text, format!("{delta}{end}")),
                    "error" => assert_eq!(text, format!("{delta}{STREAM_ERROR}")),
                    "truncated" => {
                        assert!(text.starts_with(delta));
                        assert!(text[delta.len()..].contains(marker));
                    }
                    _ => unreachable!(),
                }
            }
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while let Some(event) = tap_rx.recv().await {
                    if let TapEvent::ResponseEnd {
                        req_id,
                        stream_failure,
                        ..
                    } = event
                        && req_id.to_string() == id
                    {
                        assert_eq!(stream_failure, expected_failure, "{path} {scenario}");
                        return;
                    }
                }
                panic!("missing completion telemetry");
            })
            .await
            .unwrap();
        }
    }
    assert_eq!(stream_calls.load(Ordering::SeqCst), 8);
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
        routing: Default::default(),
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
        quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
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

#[tokio::test]
async fn e2e_multi_agent_session_and_prefix_affinity_and_failover() {
    let make_echo_upstream = |label: &'static str| async move {
        spawn_mock_upstream(move |req| async move {
            let auth = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let _ = req.into_body().collect().await;
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-seen-auth", auth)
                .body(full_body(format!(r#"{{"up":"{label}"}}"#)))
                .unwrap()
        })
        .await
    };

    let (up_a_addr, _ha) = make_echo_upstream("up-a").await;
    let (up_b_addr, _hb) = make_echo_upstream("up-b").await;

    let fail_once = Arc::new(AtomicUsize::new(0));
    let fail_once_ref = Arc::clone(&fail_once);
    let (flaky_addr, _hf) = spawn_mock_upstream(move |req| {
        let counter = Arc::clone(&fail_once_ref);
        async move {
            let _ = req.into_body().collect().await;
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .header(header::RETRY_AFTER, "1")
                    .body(full_body(r#"{"error":"rate_limited"}"#))
                    .unwrap()
            } else {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(full_body(r#"{"up":"flaky-recovered"}"#))
                    .unwrap()
            }
        }
    })
    .await;

    let (priv_addr, _hp) = make_echo_upstream("priv-u1").await;

    let cfg = GatewayConfig {
        server: ServerConfig {
            client_keys: vec![
                ClientKeyConfig {
                    key: "sk-user-2".into(),
                    name: "u2".into(),
                    enabled: true,
                    restrict_upstreams: false,
                    allowed_upstreams: vec![],
                    restrict_models: false,
                    allowed_models: vec![],
                    owner_user_id: Some(2),
                },
            ],
            ..Default::default()
        },
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        routing: Default::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "up-a".into(),
                base_url: format!("http://{up_a_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::from([
                    (ProtocolFamily::OpenAi, format!("http://{up_a_addr}/v1")),
                    (ProtocolFamily::Anthropic, format!("http://{up_a_addr}/v1")),
                ]),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-a-0".into(), "sk-a-1".into(), "sk-a-2".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["shared-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 1,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
            UpstreamConfig {
                name: "up-b".into(),
                base_url: format!("http://{up_b_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::from([
                    (ProtocolFamily::OpenAi, format!("http://{up_b_addr}/v1")),
                    (ProtocolFamily::Anthropic, format!("http://{up_b_addr}/v1")),
                ]),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-b-0".into(), "sk-b-1".into(), "sk-b-2".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["shared-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 1,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
            UpstreamConfig {
                name: "flaky-up".into(),
                base_url: format!("http://{flaky_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-flaky".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["failover-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1000,
                default_cooldown_secs: 1,
                max_retries: 1,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
            UpstreamConfig {
                name: "backup-up".into(),
                base_url: format!("http://{up_b_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-backup".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["failover-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 1,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
            UpstreamConfig {
                name: "priv-u1".into(),
                base_url: format!("http://{priv_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-priv".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["priv-only-exact".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: Some(1),
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
            UpstreamConfig {
                name: "global-wild".into(),
                base_url: format!("http://{up_a_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-wild".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["*".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
        ],
    };

    let (gw_addr, _tap_rx, _gw) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1. Codex `session_id` header pins repeated requests to same upstream AND same API key slot.
    let mut first_up = None;
    let mut first_auth = None;
    for _ in 0..6 {
        let resp = client
            .request(
                Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                    .header(header::AUTHORIZATION, "Bearer sk-user-2")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("session_id", "codex-session-pinned-77")
                    .body(Full::new(Bytes::from_static(
                        br#"{"model":"shared-model","messages":[{"role":"user","content":"hi"}]}"#,
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-ttt-affinity-source").unwrap().to_str().unwrap(),
            "header:session_id"
        );
        let up = resp.headers().get("x-ttt-upstream").unwrap().to_str().unwrap().to_string();
        let auth = resp.headers().get("x-seen-auth").unwrap().to_str().unwrap().to_string();
        if let Some(prev) = &first_up {
            assert_eq!(&up, prev);
            assert_eq!(&auth, first_auth.as_ref().unwrap());
        } else {
            first_up = Some(up);
            first_auth = Some(auth);
        }
    }

    // 2. Claude Code `metadata.user_id` on `/v1/messages` pins repeated requests.
    let mut cc_up = None;
    for _ in 0..5 {
        let resp = client
            .request(
                Request::post(format!("http://{gw_addr}/v1/messages"))
                    .header(header::AUTHORIZATION, "Bearer sk-user-2")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from_static(
                        br#"{"model":"shared-model","max_tokens":64,"metadata":{"user_id":"user_x_account_y_session_claude-999"},"messages":[{"role":"user","content":"hi"}]}"#,
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-ttt-affinity-source").unwrap().to_str().unwrap(),
            "body:claude_metadata"
        );
        let up = resp.headers().get("x-ttt-upstream").unwrap().to_str().unwrap().to_string();
        if let Some(prev) = &cc_up {
            assert_eq!(&up, prev);
        } else {
            cc_up = Some(up);
        }
    }

    // 3. Headless multi-turn OpenAI requests with growing messages stay pinned via `prefix_hash`.
    let turn1 = br#"{"model":"shared-model","messages":[{"role":"system","content":"You are a careful database architect helping design indexes."},{"role":"user","content":"Analyze why our Postgres B-tree index on user_events(created_at) is bloated."}]}"#;
    let turn2 = br#"{"model":"shared-model","messages":[{"role":"system","content":"You are a careful database architect helping design indexes."},{"role":"user","content":"Analyze why our Postgres B-tree index on user_events(created_at) is bloated."},{"role":"assistant","content":"High update churn causes page splits."},{"role":"user","content":"Should we switch to BRIN or partial indexes?"}]}"#;
    let r1 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-user-2")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(turn1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(
        r1.headers().get("x-ttt-affinity-source").unwrap().to_str().unwrap(),
        "prefix_hash"
    );
    let r1_up = r1.headers().get("x-ttt-upstream").unwrap().to_str().unwrap().to_string();

    let r2 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-user-2")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(turn2)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(
        r2.headers().get("x-ttt-affinity-source").unwrap().to_str().unwrap(),
        "prefix_hash"
    );
    assert_eq!(r2.headers().get("x-ttt-upstream").unwrap().to_str().unwrap(), r1_up);

    // 4. 429 Failover pins next turn to backup-up via Soft-Sticky cache even after 1s cooldown expires.
    let f1 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-user-2")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-session-id", "sticky-failover-session-01")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"failover-model","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(f1.status(), StatusCode::OK);
    assert_eq!(
        f1.headers().get("x-ttt-upstream").unwrap().to_str().unwrap(),
        "backup-up"
    );

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let f2 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-user-2")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-session-id", "sticky-failover-session-01")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"failover-model","messages":[{"role":"user","content":"next"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(f2.status(), StatusCode::OK);
    assert_eq!(
        f2.headers().get("x-ttt-upstream").unwrap().to_str().unwrap(),
        "backup-up"
    );

    // 5. Private exact upstream owned by user 1 falls back to global wildcard for user 2.
    let fb = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::AUTHORIZATION, "Bearer sk-user-2")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"priv-only-exact","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fb.status(), StatusCode::OK);
    assert_eq!(
        fb.headers().get("x-ttt-upstream").unwrap().to_str().unwrap(),
        "global-wild"
    );
}

#[tokio::test]
async fn e2e_outbound_provider_session_header_translation() {
    let (plain_addr, _hp) = spawn_mock_upstream(|req| async move {
        let has_ttt_sid = req.headers().contains_key("x-ttt-session-id");
        let _ = req.into_body().collect().await;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-ttt-sid", if has_ttt_sid { "1" } else { "0" })
            .body(full_body(r#"{"ok":true}"#))
            .unwrap()
    })
    .await;

    let (custom_addr, _hc) = spawn_mock_upstream(|req| async move {
        let sticky = req
            .headers()
            .get("x-upstream-sticky")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let has_cline = req.headers().contains_key("x-cline-task-id");
        let _ = req.into_body().collect().await;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-sticky", sticky)
            .header("x-seen-cline", if has_cline { "1" } else { "0" })
            .body(full_body(r#"{"ok":true}"#))
            .unwrap()
    })
    .await;

    let (responses_addr, _hr) = spawn_mock_upstream(|req| async move {
        let sid_hdr = req
            .headers()
            .get("session_id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let cache_key = parsed
            .get("prompt_cache_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-session-id", sid_hdr)
            .header("x-seen-cache-key", cache_key)
            .body(full_body(
                r#"{"id":"resp_1","model":"gpt-5-codex","output":[{"type":"message","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":5,"output_tokens":2,"total_tokens":7}}"#,
            ))
            .unwrap()
    })
    .await;

    let cfg = GatewayConfig {
        server: ServerConfig::default(),
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        routing: Default::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "plain-up".into(),
                base_url: format!("http://{plain_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-plain".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["plain-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
            UpstreamConfig {
                name: "custom-mapped-up".into(),
                base_url: format!("http://{custom_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-custom".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["mapped-model".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: Some("x-upstream-sticky".into()),
                strip_other_session_headers: true,
                prompt_cache_mode: Default::default(),
            },
            UpstreamConfig {
                name: "codex-responses-up".into(),
                base_url: format!("http://{responses_addr}"),
                protocol: ProtocolFamily::OpenAiResponses,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-codex".into()],
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
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: Default::default(),
            },
        ],
    };

    let (gw_addr, _tap_rx, _gw) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1. Private `x-ttt-session-id` header is always stripped before reaching plain upstreams.
    let resp1 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-ttt-session-id", "internal-ttt-sid-99")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"plain-model","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    assert_eq!(resp1.headers().get("x-seen-ttt-sid").unwrap().to_str().unwrap(), "0");

    // 2. Custom `session_header_out` + `strip_other_session_headers`:
    //    maps `x-cline-task-id` -> `x-upstream-sticky` and strips `x-cline-task-id`.
    let resp2 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-cline-task-id", "cline-task-4242")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"mapped-model","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    assert_eq!(
        resp2.headers().get("x-seen-sticky").unwrap().to_str().unwrap(),
        "cline-task-4242"
    );
    assert_eq!(resp2.headers().get("x-seen-cline").unwrap().to_str().unwrap(), "0");

    // 3. Headless multi-turn prefix fingerprint maps to stable `ttt-pfx-...` outbound header.
    let t1 = br#"{"model":"mapped-model","messages":[{"role":"system","content":"You are a careful Rust engineer reviewing code for safety."},{"role":"user","content":"Review this lock-free queue implementation for ABA bugs."}]}"#;
    let t2 = br#"{"model":"mapped-model","messages":[{"role":"system","content":"You are a careful Rust engineer reviewing code for safety."},{"role":"user","content":"Review this lock-free queue implementation for ABA bugs."},{"role":"assistant","content":"Looks safe with epoch reclamation."},{"role":"user","content":"What about memory ordering?"}]}"#;
    let r_pfx1 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(t1)))
                .unwrap(),
        )
        .await
        .unwrap();
    let r_pfx2 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(t2)))
                .unwrap(),
        )
        .await
        .unwrap();
    let pfx_sid1 = r_pfx1.headers().get("x-seen-sticky").unwrap().to_str().unwrap().to_string();
    let pfx_sid2 = r_pfx2.headers().get("x-seen-sticky").unwrap().to_str().unwrap().to_string();
    assert!(pfx_sid1.starts_with("ttt-pfx-"));
    assert_eq!(pfx_sid1, pfx_sid2);

    // 4. Claude Code `/v1/messages` -> OpenAiResponses upstream automatically injects BOTH
    //    `session_id` HTTP header AND `prompt_cache_key` in translated JSON body.
    let resp4 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/messages"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"gpt-5-codex","max_tokens":64,"metadata":{"user_id":"user_1_account_2_session_cc-abc123"},"messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp4.status(), StatusCode::OK);
    assert_eq!(
        resp4.headers().get("x-seen-session-id").unwrap().to_str().unwrap(),
        "session_cc-abc123"
    );
    assert_eq!(
        resp4.headers().get("x-seen-cache-key").unwrap().to_str().unwrap(),
        "session_cc-abc123"
    );
}

#[tokio::test]
async fn e2e_provider_builtin_cache_profiles() {
    use ttt_core::PromptCacheMode;

    let (grok_addr, _hg) = spawn_mock_upstream(|req| async move {
        let conv = req
            .headers()
            .get("x-grok-conv-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let _ = req.into_body().collect().await;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-grok-conv", conv)
            .body(full_body(r#"{"ok":true}"#))
            .unwrap()
    })
    .await;

    let (or_addr, _ho) = spawn_mock_upstream(|req| async move {
        let sid = req
            .headers()
            .get("x-session-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let _ = req.into_body().collect().await;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-or-sid", sid)
            .body(full_body(r#"{"ok":true}"#))
            .unwrap()
    })
    .await;

    let (strict_addr, _hs) = spawn_mock_upstream(|req| async move {
        let body = req.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        let has_key = parsed.get("prompt_cache_key").is_some();
        let has_ret = parsed.get("prompt_cache_retention").is_some();
        let model = parsed
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-cache-key", if has_key { "1" } else { "0" })
            .header("x-seen-cache-ret", if has_ret { "1" } else { "0" })
            .header("x-seen-model", model)
            .body(full_body(r#"{"ok":true}"#))
            .unwrap()
    })
    .await;

    let (opencode_addr, _hoc) = spawn_mock_upstream(|req| async move {
        let sid = req
            .headers()
            .get("x-opencode-session")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let _ = req.into_body().collect().await;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-seen-oc-sid", sid)
            .body(full_body(r#"{"ok":true}"#))
            .unwrap()
    })
    .await;

    let mut strict_map = HashMap::new();
    strict_map.insert("deepseek-alias".to_string(), "deepseek-chat".to_string());

    let cfg = GatewayConfig {
        server: ServerConfig::default(),
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        routing: Default::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "xai-grok".into(),
                base_url: format!("http://{grok_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-xai".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["grok-4".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: PromptCacheMode::XaiGrok,
            },
            UpstreamConfig {
                name: "openrouter".into(),
                base_url: format!("http://{or_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-or".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["openai/gpt-4o".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: PromptCacheMode::OpenRouter,
            },
            UpstreamConfig {
                name: "strict-deepseek".into(),
                base_url: format!("http://{strict_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-ds".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["deepseek-alias".into()],
                model_mapping: strict_map,
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: PromptCacheMode::StripOpenAiCacheFields,
            },
            UpstreamConfig {
                name: "opencode-go".into(),
                base_url: format!("http://{opencode_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::from([
                    (ProtocolFamily::OpenAi, format!("http://{opencode_addr}/v1/chat/completions")),
                    (ProtocolFamily::OpenAiResponses, format!("http://{opencode_addr}/v1/responses")),
                    (ProtocolFamily::Anthropic, format!("http://{opencode_addr}/v1/messages")),
                ]),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-oc".into()],
                    header_name: "authorization".into(),
                    prefix: Some("Bearer ".into()),
                },
                models: vec!["kimi-k3".into()],
                model_mapping: HashMap::new(),
                extra_headers: HashMap::new(),
                protocol_headers: HashMap::new(),
                weight: 1,
                default_cooldown_secs: 10,
                max_retries: 0,
                owner_user_id: None,
                proxy: None,
                quota: None,
                session_header_out: None,
                strip_other_session_headers: false,
                prompt_cache_mode: PromptCacheMode::OpenCode,
            },
        ],
    };

    let (gw_addr, _tap_rx, _gw) = spawn_gateway(cfg, None).await;
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    // 1. XaiGrok profile maps incoming `x-session-id` -> `x-grok-conv-id`.
    let r1 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-session-id", "grok-thread-101")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"grok-4","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    assert_eq!(
        r1.headers().get("x-seen-grok-conv").unwrap().to_str().unwrap(),
        "grok-thread-101"
    );

    // 2. OpenRouter profile maps OpenRouter body `session_id` -> `x-session-id` header.
    let r2 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"openai/gpt-4o","session_id":"or-body-sess-88","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    assert_eq!(
        r2.headers().get("x-seen-or-sid").unwrap().to_str().unwrap(),
        "or-body-sess-88"
    );

    // 3. StripOpenAiCacheFields still uses `prompt_cache_key` for gateway routing affinity
    //    while stripping `prompt_cache_key` & `prompt_cache_retention` AND preserving `model_mapping`.
    let r3 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"deepseek-alias","prompt_cache_key":"sdk-cache-key-55","prompt_cache_retention":"24h","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r3.status(), StatusCode::OK);
    assert_eq!(
        r3.headers().get("x-ttt-affinity-source").unwrap().to_str().unwrap(),
        "body:prompt_cache_key"
    );
    assert_eq!(r3.headers().get("x-seen-cache-key").unwrap().to_str().unwrap(), "0");
    assert_eq!(r3.headers().get("x-seen-cache-ret").unwrap().to_str().unwrap(), "0");
    assert_eq!(r3.headers().get("x-seen-model").unwrap().to_str().unwrap(), "deepseek-chat");

    // 4. OpenCode Go: Claude Code `/v1/messages` -> `x-opencode-session: session_...`
    let r4 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/messages"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"kimi-k3","max_tokens":64,"metadata":{"user_id":"user_1_account_2_session_oc-55"},"messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r4.status(), StatusCode::OK);
    assert_eq!(
        r4.headers().get("x-seen-oc-sid").unwrap().to_str().unwrap(),
        "session_oc-55"
    );

    // 5. OpenCode Go: short stateless request without session header gets `ses_ttt-req-...` fallback
    let r5 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"kimi-k3","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r5.status(), StatusCode::OK);
    assert!(
        r5.headers()
            .get("x-seen-oc-sid")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("ses_ttt-req-")
    );

    // 6. OpenCode Go: explicit incoming `x-opencode-session` is preserved intact
    let r6 = client
        .request(
            Request::post(format!("http://{gw_addr}/v1/chat/completions"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-opencode-session", "ses_client_owned_999")
                .body(Full::new(Bytes::from_static(
                    br#"{"model":"kimi-k3","messages":[{"role":"user","content":"hi"}]}"#,
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r6.status(), StatusCode::OK);
    assert_eq!(
        r6.headers().get("x-seen-oc-sid").unwrap().to_str().unwrap(),
        "ses_client_owned_999"
    );
}
