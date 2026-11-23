use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream;
use http::{header, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use ttt_core::{
    ClientKeyConfig, GatewayConfig, OAuthStorageConfig, PoolConfig, ProtocolFamily, ServerConfig,
    TapEvent, TelemetryConfig, UpstreamAuthConfig, UpstreamConfig,
};
use ttt_proxy::ProxyEngine;

type BoxedBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

fn full_body(data: impl Into<Bytes>) -> BoxedBody {
    Full::new(data.into()).boxed()
}

async fn spawn_mock_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let path = req.uri().path().to_string();
                    let _ = req.into_body().collect().await;

                    if path.ends_with("/messages") {
                        let chunks = vec![
                            Ok(Frame::data(Bytes::from_static(
                                b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":10}}}\n\n",
                            ))),
                            Ok(Frame::data(Bytes::from_static(
                                b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
                            ))),
                            Ok(Frame::data(Bytes::from_static(
                                b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
                            ))),
                            Ok(Frame::data(Bytes::from_static(
                                b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
                            ))),
                        ];
                        return Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "text/event-stream")
                                .body(StreamBody::new(stream::iter(chunks)).boxed())
                                .unwrap(),
                        );
                    }

                    if path.contains("stream") {
                        let chunks = vec![
                            Ok(Frame::data(Bytes::from_static(
                                b"data: {\"id\":\"1\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
                            ))),
                            Ok(Frame::data(Bytes::from_static(
                                b"data: {\"id\":\"1\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n",
                            ))),
                            Ok(Frame::data(Bytes::from_static(b"data: [DONE]\n\n"))),
                        ];
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/event-stream")
                            .body(StreamBody::new(stream::iter(chunks)).boxed())
                            .unwrap());
                    }

                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(full_body(
                            br#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}"#.as_slice(),
                        ))
                        .unwrap())
                });
                let _ = AutoConnBuilder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    addr
}

async fn spawn_gateway(upstream_addr: SocketAddr) -> SocketAddr {
    let (tap_tx, mut tap_rx) = mpsc::channel::<TapEvent>(4096);
    tokio::spawn(async move {
        while tap_rx.recv().await.is_some() {}
    });

    let cfg = GatewayConfig {
        server: ServerConfig {
            client_keys: vec![ClientKeyConfig {
                key: "sk-bench-key".into(),
                name: "bench".into(),
                enabled: true,
                restrict_upstreams: false,
                allowed_upstreams: vec![],
                restrict_models: false,
                allowed_models: vec![],
                owner_user_id: Some(1),
            }],
            ..Default::default()
        },
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        routing: Default::default(),
        upstreams: vec![
            UpstreamConfig {
                name: "oai-native".into(),
                base_url: format!("http://{upstream_addr}"),
                protocol: ProtocolFamily::OpenAi,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-up-1".into()],
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
                name: "ant-cross".into(),
                base_url: format!("http://{upstream_addr}"),
                protocol: ProtocolFamily::Anthropic,
                protocol_endpoints: HashMap::new(),
                auth: UpstreamAuthConfig::ApiKey {
                    keys: vec!["sk-ant-1".into()],
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
        ],
    };

    let engine = Arc::new(ProxyEngine::new(&cfg, Some(tap_tx), None).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
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

    addr
}

async fn run_bench(
    label: &str,
    url: String,
    payload: Bytes,
    concurrency: usize,
    total_reqs: usize,
) {
    let mut http = HttpConnector::new();
    http.set_nodelay(true);
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(concurrency * 2)
        .build(http);

    // Warmup
    for _ in 0..50 {
        let req = Request::post(&url)
            .header(header::AUTHORIZATION, "Bearer sk-bench-key")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(payload.clone()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let _ = resp.into_body().collect().await.unwrap();
    }

    let per_worker = total_reqs / concurrency;
    let started = Instant::now();
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let client = client.clone();
        let url = url.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let mut latencies_us = Vec::with_capacity(per_worker);
            for _ in 0..per_worker {
                let t0 = Instant::now();
                let req = Request::post(&url)
                    .header(header::AUTHORIZATION, "Bearer sk-bench-key")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(payload.clone()))
                    .unwrap();
                let resp = client.request(req).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let _ = resp.into_body().collect().await.unwrap();
                latencies_us.push(t0.elapsed().as_micros() as u64);
            }
            latencies_us
        }));
    }

    let mut all_lat = Vec::with_capacity(total_reqs);
    for h in handles {
        all_lat.extend(h.await.unwrap());
    }
    let elapsed = started.elapsed();
    all_lat.sort_unstable();

    let rps = all_lat.len() as f64 / elapsed.as_secs_f64();
    let p50 = all_lat[all_lat.len() / 2] as f64 / 1000.0;
    let p95 = all_lat[(all_lat.len() * 95) / 100] as f64 / 1000.0;
    let p99 = all_lat[(all_lat.len() * 99) / 100] as f64 / 1000.0;

    println!(
        "{label:<36} | RPS: {rps:>8.1} req/s | P50: {p50:>6.2} ms | P95: {p95:>6.2} ms | P99: {p99:>6.2} ms"
    );
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let upstream_addr = spawn_mock_upstream().await;
    let gw_addr = spawn_gateway(upstream_addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let concurrency = 32;
    let total_reqs = 4000;

    println!("Benchmarking TalkThatTalk (concurrency={concurrency}, requests={total_reqs})");
    println!("{}", "-".repeat(92));

    run_bench(
        "Direct Mock Baseline (JSON)",
        format!("http://{upstream_addr}/v1/chat/completions"),
        Bytes::from_static(br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#),
        concurrency,
        total_reqs,
    )
    .await;

    run_bench(
        "TTT Zero-Copy Pass-Through (JSON)",
        format!("http://{gw_addr}/v1/chat/completions"),
        Bytes::from_static(br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#),
        concurrency,
        total_reqs,
    )
    .await;

    run_bench(
        "TTT Zero-Copy Stream (SSE)",
        format!("http://{gw_addr}/v1/stream"),
        Bytes::from_static(br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}"#),
        concurrency,
        total_reqs,
    )
    .await;

    run_bench(
        "TTT Cross-Proto OAI->Ant (SSE)",
        format!("http://{gw_addr}/v1/chat/completions"),
        Bytes::from_static(br#"{"model":"claude-sonnet-4","stream":true,"messages":[{"role":"user","content":"hi"}]}"#),
        concurrency,
        total_reqs,
    )
    .await;
}
