mod auth_cli;
mod web_assets;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use ttt_auth::TokenStore;
use ttt_control::{ControlPlane, GatewayDb, MetricsStore};
use ttt_core::{
    GatewayConfig, OAuthStorageConfig, PoolConfig, RequestId, RoutingConfig, ServerConfig,
    TapEvent, TelemetryConfig,
};
use ttt_proxy::{ProxyEngine, UsageAccumulator};

enum CliCommand {
    Version,
    Serve {
        config_path: Option<PathBuf>,
        listen_override: Option<String>,
        db_override: Option<String>,
    },
    AuthLogin {
        config_path: Option<PathBuf>,
        db_override: Option<String>,
        upstream: String,
        device: bool,
        manual: bool,
    },
    AuthStatus {
        config_path: Option<PathBuf>,
        db_override: Option<String>,
    },
}

fn load_bootstrap_config(
    config_path: Option<PathBuf>,
    listen_override: Option<String>,
    db_override: Option<String>,
) -> Result<GatewayConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut cfg = if let Some(path) = config_path {
        if path.exists() {
            info!(path = %path.display(), "loading TalkThatTalk bootstrap config");
            GatewayConfig::from_file(&path)?
        } else {
            default_bootstrap_config()
        }
    } else if PathBuf::from("config.toml").exists() {
        info!(path = "config.toml", "loading TalkThatTalk bootstrap config");
        GatewayConfig::from_file("config.toml")?
    } else {
        info!("no config.toml found, booting directly with SQLite defaults");
        default_bootstrap_config()
    };

    if let Ok(env_listen) = std::env::var("TTT_LISTEN")
        && !env_listen.trim().is_empty()
    {
        cfg.server.listen_addr = env_listen;
    }
    if let Ok(env_db) = std::env::var("TTT_DB_PATH")
        && !env_db.trim().is_empty()
    {
        cfg.oauth_storage.db_path = env_db;
    }
    if let Some(listen) = listen_override {
        cfg.server.listen_addr = listen;
    }
    if let Some(db) = db_override {
        cfg.oauth_storage.db_path = db;
    }
    Ok(cfg)
}

fn default_bootstrap_config() -> GatewayConfig {
    GatewayConfig {
        server: ServerConfig::default(),
        pool: PoolConfig::default(),
        telemetry: TelemetryConfig::default(),
        oauth_storage: OAuthStorageConfig::default(),
        routing: RoutingConfig::default(),
        upstreams: Vec::new(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing();

    match parse_cli()? {
        CliCommand::Version => {
            println!("talkthattalk {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        CliCommand::Serve {
            config_path,
            listen_override,
            db_override,
        } => {
            let config = load_bootstrap_config(config_path, listen_override, db_override)?;
            run_server(config).await
        }
        CliCommand::AuthLogin {
            config_path,
            db_override,
            upstream,
            device,
            manual,
        } => {
            let config = load_bootstrap_config(config_path, None, db_override)?;
            auth_cli::run_auth_login(&config, &upstream, device, manual).await?;
            Ok(())
        }
        CliCommand::AuthStatus {
            config_path,
            db_override,
        } => {
            let config = load_bootstrap_config(config_path, None, db_override)?;
            auth_cli::run_auth_status(&config)?;
            Ok(())
        }
    }
}

async fn run_server(
    mut config: GatewayConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = Arc::new(GatewayDb::open_from_config(&config.oauth_storage)?);
    let token_store: Arc<dyn TokenStore> = db.clone();

    // One-time migration: if SQLite is empty and legacy TOML had upstreams/keys, seed SQLite once.
    let mut upstreams = db.list_upstreams()?;
    if upstreams.is_empty() && !config.upstreams.is_empty() {
        let mut seeded = config.upstreams.clone();
        for up in &mut seeded {
            if up.id.is_empty() {
                up.id = GatewayDb::new_upstream_id();
            }
        }
        for up in &seeded {
            db.upsert_upstream(up)?;
        }
        upstreams = db.list_upstreams()?;
    }

    let mut client_keys = db.list_client_keys()?;
    let legacy_keys = config.server.effective_client_keys();
    if client_keys.is_empty() && !legacy_keys.is_empty() {
        for mut key in legacy_keys {
            key.allowed_upstreams.retain_mut(|selector| {
                if upstreams.iter().any(|up| up.id == *selector) {
                    return true;
                }
                let mut matches = upstreams.iter().filter(|up| up.name == *selector);
                if let Some(up) = matches.next()
                    && matches.next().is_none()
                {
                    *selector = up.id.clone();
                    return true;
                }
                false
            });
            db.upsert_client_key(&key)?;
        }
        client_keys = db.list_client_keys()?;
    }

    config.upstreams = upstreams;
    config.server.client_keys = client_keys;
    config.server.client_api_keys.clear();

    let metrics = Arc::new(MetricsStore::new());
    RequestId::resume_after(db.restore_request_metrics(&metrics)?);

    let (tap_tx, tap_rx) = mpsc::channel::<TapEvent>(config.telemetry.tap_channel_capacity);
    let tap_worker = tokio::spawn(run_tap_worker(
        tap_rx,
        Arc::clone(&metrics),
        Arc::clone(&db),
    ));

    let engine = Arc::new(ProxyEngine::new(
        &config,
        Some(tap_tx),
        Some(token_store),
    )?);
    let control = Arc::new(ControlPlane::new(
        config.server.admin_api_key.clone(),
        Arc::clone(&db),
        Arc::clone(&engine),
        Arc::clone(&metrics),
    ));
    let refresher_task = engine.spawn_proactive_oauth_refresher(Duration::from_secs(30));
    let reload_task = spawn_sighup_reloader(Arc::clone(&db), Arc::clone(&engine));

    let listen_addr: SocketAddr = config.server.listen_addr.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    let tcp_nodelay = config.server.tcp_nodelay;
    let shutdown_timeout = Duration::from_secs(config.server.graceful_shutdown_secs);

    info!(
        %listen_addr,
        db_path = %config.oauth_storage.db_path,
        upstreams = config.upstreams.len(),
        tcp_nodelay,
        "TalkThatTalk AI gateway listening"
    );

    let graceful = GracefulShutdown::new();
    let mut shutdown_signal = std::pin::pin!(shutdown_signal());

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, peer_addr)) => {
                        if tcp_nodelay {
                            let _ = stream.set_nodelay(true);
                        }
                        let io = TokioIo::new(stream);
                        let engine = Arc::clone(&engine);
                        let control = Arc::clone(&control);
                        let service = service_fn(move |req| {
                            let engine = Arc::clone(&engine);
                            let control = Arc::clone(&control);
                            async move {
                                let path = req.uri().path();
                                if path.starts_with("/api/v1/") {
                                    control.handle(req).await
                                } else if web_assets::is_api_or_gateway_path(req.method(), path) {
                                    engine.handle(req).await
                                } else {
                                    Ok(web_assets::serve_embedded_web(&req))
                                }
                            }
                        });

                        let conn_builder = AutoConnBuilder::new(TokioExecutor::new());
                        let conn = conn_builder.serve_connection(io, service);
                        let fut = graceful.watch(conn.into_owned());

                        tokio::spawn(async move {
                            if let Err(err) = fut.await {
                                // Ignore benign client disconnects during SSE streaming.
                                tracing::debug!(%peer_addr, error = %err, "connection closed");
                            }
                        });
                    }
                    Err(err) => {
                        error!(error = %err, "failed to accept TCP connection");
                    }
                }
            }
            _ = &mut shutdown_signal => {
                info!("shutdown signal received, draining in-flight connections...");
                break;
            }
        }
    }

    // Drop the listener to stop accepting new connections immediately.
    drop(listener);
    refresher_task.abort();
    reload_task.abort();

    tokio::select! {
        _ = graceful.shutdown() => {
            info!("all in-flight connections drained cleanly");
        }
        _ = tokio::time::sleep(shutdown_timeout) => {
            warn!(
                timeout_secs = shutdown_timeout.as_secs(),
                "graceful shutdown timed out with active connections"
            );
        }
    }

    drop(control);
    drop(engine);
    let _ = tokio::time::timeout(Duration::from_secs(2), tap_worker).await;
    info!("TalkThatTalk gateway stopped");
    Ok(())
}

async fn run_tap_worker(
    mut rx: mpsc::Receiver<TapEvent>,
    metrics: Arc<MetricsStore>,
    db: Arc<GatewayDb>,
) {
    let mut active_usage: HashMap<RequestId, UsageAccumulator> = HashMap::new();
    let mut cleanup = tokio::time::interval(Duration::from_secs(15));
    cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    const BATCH_SIZE: usize = 64;
    let mut events = Vec::with_capacity(BATCH_SIZE);
    loop {
        tokio::select! {
            biased;
            _ = cleanup.tick() => {
                for req_id in metrics.prune_inactive_requests() {
                    active_usage.remove(&req_id);
                }
            }
            count = rx.recv_many(&mut events, BATCH_SIZE) => {
                if count == 0 {
                    break;
                }
            }
        }
        for event in events.drain(..) {
            match event {
                TapEvent::RequestStart {
                    req_id,
                    lifetime,
                    user_id,
                    upstream,
                    upstream_id,
                    model,
                    path,
                } => {
                    active_usage.insert(req_id, UsageAccumulator::new());
                    let username = user_id
                        .and_then(|id| db.get_user_by_id(id).ok().flatten())
                        .map(|user| user.username);
                    tracing::debug!(
                        %req_id,
                        user_id,
                        username = username.as_deref(),
                        %upstream,
                        model = model.as_deref().unwrap_or("-"),
                        %path,
                        "proxy request started"
                    );
                    metrics.record_start(
                        req_id,
                        lifetime,
                        user_id,
                        username,
                        upstream,
                        Some(upstream_id),
                        model,
                        path,
                    );
                }
                TapEvent::ResponseFirstByte {
                    req_id,
                    status,
                    is_stream,
                    ttft_ms,
                } => {
                    metrics.record_first_byte(req_id, is_stream);
                    tracing::debug!(%req_id, %status, ttft_ms, "first upstream response data received");
                }
                TapEvent::ResponseChunk { req_id, data } => {
                    if let Some(acc) = active_usage.get_mut(&req_id) {
                        acc.push_chunk(&data);
                    }
                }
                TapEvent::ResponseEnd {
                    req_id,
                    lifetime: _lifetime,
                    status,
                    is_stream,
                    stream_failure,
                    total_bytes,
                    ttft_ms,
                    duration_ms,
                } => {
                    let usage = active_usage
                        .remove(&req_id)
                        .map(|mut acc| acc.finish())
                        .unwrap_or_default();
                    let entry = metrics.record_end(
                        req_id,
                        status.as_u16(),
                        is_stream,
                        stream_failure,
                        total_bytes,
                        ttft_ms,
                        duration_ms,
                        usage.clone(),
                    );
                    if let Some(entry) = &entry
                        && let Err(err) = db.insert_request_log(entry)
                    {
                        warn!(%req_id, error = %err, "failed to persist request log to SQLite");
                    }
                    info!(
                        %req_id,
                        %status,
                        user_id = entry.as_ref().and_then(|entry| entry.user_id),
                        username = entry.as_ref().and_then(|entry| entry.username.as_deref()),
                        is_stream,
                        stream_failure = stream_failure.map(|failure| failure.as_str()),
                        total_bytes,
                        ttft_ms,
                        duration_ms,
                        input_tokens = usage.input_tokens,
                        output_tokens = usage.output_tokens,
                        total_tokens = usage.total_tokens,
                        cache_read_tokens = usage.cache_read_tokens,
                        cache_write_tokens = usage.cache_write_tokens,
                        "proxy request ended"
                    );
                }
            }
        }
    }
}

fn parse_cli() -> Result<CliCommand, Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.as_slice(), [arg] if arg == "--version" || arg == "-V") {
        return Ok(CliCommand::Version);
    }
    let env_cfg = std::env::var("TTT_CONFIG").ok().map(PathBuf::from);

    if args.first().map(String::as_str) == Some("auth") {
        let sub = args.get(1).map(String::as_str).unwrap_or("");
        let mut config_path = env_cfg;
        let mut db_override = None;
        let mut upstream = None;
        let mut device = false;
        let mut manual = false;

        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--config" | "-c" => {
                    i += 1;
                    if let Some(p) = args.get(i) {
                        config_path = Some(PathBuf::from(p));
                    }
                }
                "--db" => {
                    i += 1;
                    db_override = args.get(i).cloned();
                }
                "--upstream" | "-u" => {
                    i += 1;
                    upstream = args.get(i).cloned();
                }
                "--device" => device = true,
                "--manual" => manual = true,
                arg if arg.starts_with("--config=") => {
                    config_path = Some(PathBuf::from(&arg["--config=".len()..]));
                }
                arg if arg.starts_with("--db=") => {
                    db_override = Some(arg["--db=".len()..].to_string());
                }
                arg if arg.starts_with("--upstream=") => {
                    upstream = Some(arg["--upstream=".len()..].to_string());
                }
                _ => {}
            }
            i += 1;
        }

        return match sub {
            "login" => {
                let upstream = upstream.ok_or("missing --upstream <name> for `auth login`")?;
                Ok(CliCommand::AuthLogin {
                    config_path,
                    db_override,
                    upstream,
                    device,
                    manual,
                })
            }
            "status" => Ok(CliCommand::AuthStatus {
                config_path,
                db_override,
            }),
            _ => Err("usage: talkthattalk auth <login --upstream NAME [--device|--manual] | status> [--db FILE]".into()),
        };
    }

    // Default / `serve` subcommand
    let mut config_path = env_cfg;
    let mut listen_override = None;
    let mut db_override = None;
    let mut i = if args.first().map(String::as_str) == Some("serve") {
        1
    } else {
        0
    };
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    config_path = Some(PathBuf::from(p));
                }
            }
            "--listen" | "-l" => {
                i += 1;
                listen_override = args.get(i).cloned();
            }
            "--db" => {
                i += 1;
                db_override = args.get(i).cloned();
            }
            arg if arg.starts_with("--config=") => {
                config_path = Some(PathBuf::from(&arg["--config=".len()..]));
            }
            arg if arg.starts_with("--listen=") => {
                listen_override = Some(arg["--listen=".len()..].to_string());
            }
            arg if arg.starts_with("--db=") => {
                db_override = Some(arg["--db=".len()..].to_string());
            }
            _ => {}
        }
        i += 1;
    }

    Ok(CliCommand::Serve {
        config_path,
        listen_override,
        db_override,
    })
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,ttt_proxy=info,ttt_server=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(unix)]
fn spawn_sighup_reloader(
    db: Arc<GatewayDb>,
    engine: Arc<ProxyEngine>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(mut sig) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };
        while sig.recv().await.is_some() {
            info!("SIGHUP received, reloading upstreams and client keys from SQLite");
            match (db.list_upstreams(), db.list_client_keys()) {
                (Ok(ups), Ok(keys)) => match engine.router().reload(&ups) {
                    Ok(()) => {
                        engine.reload_client_keys(&keys);
                        info!(
                            upstreams = ups.len(),
                            keys = keys.len(),
                            "hot-reloaded routing table and client keys from SQLite"
                        );
                    }
                    Err(err) => error!(error = %err, "failed to apply reloaded routing table"),
                },
                (Err(err), _) | (_, Err(err)) => {
                    error!(error = %err, "failed to read SQLite during SIGHUP reload")
                }
            }
        }
    })
}

#[cfg(not(unix))]
fn spawn_sighup_reloader(
    _db: Arc<GatewayDb>,
    _engine: Arc<ProxyEngine>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {})
}
