use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, oneshot};
use ttt_auth::{
    OAuthHttpClient, PkceChallenge, TokenStore, build_authorize_url, generate_state,
    parse_authorization_input,
};
use ttt_control::GatewayDb;
use ttt_core::{GatewayConfig, GatewayError, OAuthPreset, UpstreamAuthConfig};
use url::Url;

pub async fn run_auth_login(
    cfg: &GatewayConfig,
    upstream_name: &str,
    use_device_flow: bool,
    force_manual: bool,
) -> Result<(), GatewayError> {
    let db = GatewayDb::open_from_config(&cfg.oauth_storage)?;
    let upstreams = db.list_upstreams()?;
    let mut matches = upstreams.iter().filter(|u| u.name == upstream_name);
    let upstream = upstreams
        .iter()
        .find(|u| u.id == upstream_name)
        .or_else(|| {
            let found = matches.next()?;
            matches.next().is_none().then_some(found)
        })
        .ok_or_else(|| {
            GatewayError::Config(format!(
                "upstream '{upstream_name}' not found or ambiguous; use the channel ID"
            ))
        })?;

    let UpstreamAuthConfig::OAuth {
        preset,
        authorize_url,
        device_code_url,
        token_url,
        scopes,
        redirect_uri,
        token_request_format,
        ..
    } = &upstream.auth
    else {
        return Err(GatewayError::Config(format!(
            "upstream '{upstream_name}' is not configured in oauth mode"
        )));
    };

    let defaults = preset.and_then(OAuthPreset::defaults);
    let (client_id, client_secret) = upstream.auth.oauth_credentials();
    let client_secret = UpstreamAuthConfig::oauth_client_secret(*preset, client_secret.as_deref())?;
    let format = UpstreamAuthConfig::effective_token_format(*preset, *token_request_format);
    let token_url = token_url
        .as_deref()
        .or_else(|| defaults.map(|d| d.token_url))
        .ok_or_else(|| {
            GatewayError::Config(format!(
                "upstream '{upstream_name}' missing oauth token_url"
            ))
        })?;
    let client_id = client_id
        .as_deref()
        .ok_or_else(|| {
            GatewayError::Config(format!(
                "upstream '{upstream_name}' missing oauth client_id"
            ))
        })?;
    let resolved_scopes: Vec<String> = if scopes.is_empty() {
        defaults
            .map(|d| d.scopes.iter().map(|s| (*s).to_string()).collect())
            .unwrap_or_default()
    } else {
        scopes.clone()
    };
    let acct_id = upstream.oauth_storage_key();
    let client = OAuthHttpClient::new();

    let token = if use_device_flow {
        let device_url = device_code_url.as_deref().ok_or_else(|| {
            GatewayError::Config(format!(
                "upstream '{upstream_name}' missing device_code_url for --device flow"
            ))
        })?;
        let device = client
            .request_device_code(device_url, format, client_id, &resolved_scopes)
            .await?;

        println!("\n=== TalkThatTalk OAuth Device Login ({upstream_name}) ===");
        if let Some(complete) = &device.verification_uri_complete {
            println!("Open URL:  {complete}");
        } else {
            println!("Open URL:  {}", device.verification_uri);
            println!("User Code: {}", device.user_code);
        }
        println!("Waiting for authorization...\n");

        client
            .poll_device_token(token_url, format, client_id, &device)
            .await?
    } else {
        let authorize_url = authorize_url
            .as_deref()
            .or_else(|| defaults.map(|d| d.authorize_url))
            .ok_or_else(|| {
                GatewayError::Config(format!(
                    "upstream '{upstream_name}' missing authorize_url for PKCE flow"
                ))
            })?;
        let redirect_uri = redirect_uri
            .as_deref()
            .or_else(|| defaults.map(|d| d.redirect_uri))
            .ok_or_else(|| {
                GatewayError::Config(format!(
                    "upstream '{upstream_name}' missing redirect_uri for PKCE flow"
                ))
            })?;

        let pkce = PkceChallenge::generate();
        let state = generate_state();
        let auth_url = build_authorize_url(
            authorize_url,
            client_id,
            redirect_uri,
            &resolved_scopes,
            &state,
            &pkce,
            preset.map_or(&[][..], OAuthPreset::authorization_params),
        )?;

        println!("\n=== TalkThatTalk OAuth PKCE Login ({upstream_name}) ===");
        println!("Preset:    {:?} (token wire format: {:?})", preset, format);
        println!("Open this URL in your browser:\n\n  {auth_url}\n");

        let code = if !force_manual
            && let Some(local_addr) = parse_local_callback_addr(redirect_uri)
        {
            println!("Listening for OAuth callback on http://{local_addr} ...");
            wait_for_local_callback(local_addr, &state).await?
        } else {
            print!("Paste the callback URL or code#state here: ");
            let _ = io::stdout().flush();
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(|e| GatewayError::Auth(format!("failed to read stdin: {e}")))?;
            parse_authorization_input(&input, &state)?
        };

        // Claude Code token endpoints expect `state` alongside `code` in JSON payload.
        let state_param = match preset {
            Some(OAuthPreset::ClaudeCode) => Some(state.as_str()),
            _ => None,
        };

        client
            .exchange_code(
                token_url,
                format,
                &code,
                &pkce.verifier,
                redirect_uri,
                client_id,
                client_secret,
                state_param,
            )
            .await?
    };

    let record = client.complete_login(upstream, token).await?;
    let has_refresh = record.refresh_token.is_some();
    let expires_at = record.expires_at;
    let project_id_pending = *preset == Some(OAuthPreset::Antigravity)
        && record.antigravity_project_id().is_none();
    TokenStore::put(&db, &acct_id, record)?;

    println!(
        "Successfully authenticated '{upstream_name}' (account_id='{acct_id}', refresh_token={}, expires_at={:?}).",
        has_refresh,
        expires_at
    );
    if project_id_pending {
        println!("Antigravity Project ID 尚未发现，模型请求会重新查询。");
    }
    Ok(())
}

pub fn run_auth_status(cfg: &GatewayConfig) -> Result<(), GatewayError> {
    let db = GatewayDb::open_from_config(&cfg.oauth_storage)?;
    let upstreams = db.list_upstreams()?;
    let stored = TokenStore::list(&db)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("SQLite DB: {}", cfg.oauth_storage.db_path);
    for up in &upstreams {
        if let UpstreamAuthConfig::OAuth {
            preset,
            token_request_format,
            access_token,
            refresh_token,
            expires_at,
            ..
        } = &up.auth
        {
            let acct = up.oauth_storage_key();
            let fmt = UpstreamAuthConfig::effective_token_format(*preset, *token_request_format);
            let rec = stored.get(&acct);
            let has_token = rec
                .map(|r| !r.access_token.is_empty())
                .unwrap_or_else(|| access_token.as_deref().map(|s| !s.is_empty()).unwrap_or(false));
            let has_refresh = rec
                .and_then(|r| r.refresh_token.as_ref())
                .or(refresh_token.as_ref())
                .is_some();
            let exp = rec.and_then(|r| r.expires_at).or(*expires_at);
            let ttl = exp.map(|e| {
                if e > now {
                    format!("expires in {}s", e - now)
                } else {
                    format!("expired {}s ago", now - e)
                }
            });

            println!(
                "- upstream={} id={} preset={:?} format={:?} token={} refresh_token={} status={}",
                up.name,
                up.id,
                preset.unwrap_or(OAuthPreset::Custom),
                fmt,
                if has_token { "present" } else { "missing" },
                if has_refresh { "present" } else { "none" },
                ttl.as_deref().unwrap_or("unknown_ttl")
            );
        }
    }
    Ok(())
}

fn parse_local_callback_addr(redirect_uri: &str) -> Option<SocketAddr> {
    let url = Url::parse(redirect_uri).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?;
    if host != "127.0.0.1" && host != "localhost" {
        return None;
    }
    let port = url.port_or_known_default()?;
    format!("127.0.0.1:{port}").parse().ok()
}

async fn wait_for_local_callback(
    addr: SocketAddr,
    expected_state: &str,
) -> Result<String, GatewayError> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        GatewayError::Auth(format!(
            "failed to bind local OAuth callback listener on {addr}: {e}"
        ))
    })?;

    let (tx, rx) = oneshot::channel::<Result<String, GatewayError>>();
    let tx = Arc::new(Mutex::new(Some(tx)));
    let expected = expected_state.to_string();

    let server_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let tx = Arc::clone(&tx);
            let expected = expected.clone();
            let svc = service_fn(move |req| {
                let tx = Arc::clone(&tx);
                let expected = expected.clone();
                async move {
                    let full_url = format!(
                        "http://127.0.0.1{}",
                        req.uri()
                            .path_and_query()
                            .map(|pq| pq.as_str())
                            .unwrap_or("/")
                    );
                    let parsed = parse_authorization_input(&full_url, &expected);
                    let (status, html) = match &parsed {
                        Ok(_) => (
                            StatusCode::OK,
                            "<html><body><h2>TalkThatTalk OAuth login succeeded.</h2><p>You may close this tab.</p></body></html>",
                        ),
                        Err(_) => (
                            StatusCode::BAD_REQUEST,
                            "<html><body><h2>TalkThatTalk OAuth login failed.</h2><p>Check your terminal for details.</p></body></html>",
                        ),
                    };
                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send(parsed);
                    }
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .status(status)
                            .header("content-type", "text/html; charset=utf-8")
                            .body(Full::new(Bytes::from_static(html.as_bytes())))
                            .unwrap(),
                    )
                }
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        }
    });

    let res = tokio::time::timeout(std::time::Duration::from_secs(300), rx)
        .await
        .map_err(|_| GatewayError::Auth("timed out waiting for OAuth callback".into()))?
        .map_err(|_| GatewayError::Auth("OAuth callback channel closed".into()))?;
    server_task.abort();
    res
}
