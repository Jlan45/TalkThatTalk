use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use http::{Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};
use tracing::{info, warn};
use ttt_core::{GatewayError, ProxyConfig, ProxyProtocol};

use crate::client::TunnelConnector;

/// Resolved runtime endpoint for a configured proxy node.
#[derive(Debug, Clone)]
pub enum ResolvedProxy {
    /// Local loopback SOCKS5 inbound hosted in-process by `eycorsican/leaf`.
    Socks5 { addr: SocketAddr },
    /// Direct HTTP CONNECT proxy tunnel.
    Http {
        addr: String,
        auth_header: Option<String>,
    },
}

/// Manages an in-process `eycorsican/leaf` proxy runtime for all configured proxy nodes.
/// Each enabled non-HTTP proxy gets its own local loopback SOCKS5 inbound inside `leaf`,
/// allowing per-upstream proxy routing with lock-free hot-path lookups.
pub struct LeafProxyManager {
    active: ArcSwap<HashMap<String, ResolvedProxy>>,
    current_rt_id: Mutex<Option<u16>>,
    next_rt_id: AtomicU16,
}

impl Default for LeafProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LeafProxyManager {
    pub fn new() -> Self {
        Self {
            active: ArcSwap::from_pointee(HashMap::new()),
            current_rt_id: Mutex::new(None),
            next_rt_id: AtomicU16::new(1),
        }
    }

    #[inline]
    pub fn get(&self, name: &str) -> Option<ResolvedProxy> {
        self.active.load().get(name).cloned()
    }

    #[inline]
    pub fn is_active(&self, name: &str) -> bool {
        self.active.load().contains_key(name)
    }

    /// Snapshot all currently active resolved proxies.
    pub fn snapshot(&self) -> HashMap<String, ResolvedProxy> {
        self.active.load().as_ref().clone()
    }

    /// Reload all proxies: shuts down any previous `leaf` runtime, builds a fresh
    /// JSON config for enabled proxies, and starts a new in-process `leaf` runtime.
    pub fn reload(&self, proxies: &[ProxyConfig]) -> Result<(), GatewayError> {
        let mut rt_guard = self
            .current_rt_id
            .lock()
            .map_err(|_| GatewayError::Internal("leaf runtime mutex poisoned".into()))?;

        if let Some(old_id) = rt_guard.take() {
            let _ = leaf::shutdown(old_id);
        }

        let mut resolved = HashMap::new();
        let mut inbounds: Vec<Value> = Vec::new();
        let mut outbounds: Vec<Value> = Vec::new();
        let mut rules: Vec<Value> = Vec::new();

        for (idx, p) in proxies.iter().enumerate() {
            if !p.enabled {
                continue;
            }
            if let Err(e) = p.validate() {
                warn!(proxy = %p.name, error = %e, "skipping invalid proxy config");
                continue;
            }

            if p.protocol == ProxyProtocol::Http {
                let auth_header = match (p.username.as_deref(), p.password.as_deref()) {
                    (Some(u), Some(pw)) if !u.is_empty() => {
                        Some(format!("Basic {}", B64.encode(format!("{u}:{pw}"))))
                    }
                    _ => None,
                };
                resolved.insert(
                    p.name.clone(),
                    ResolvedProxy::Http {
                        addr: format!("{}:{}", p.server.trim(), p.port),
                        auth_header,
                    },
                );
                continue;
            }

            let port = allocate_loopback_port()?;
            let in_tag = format!("in_{idx}");
            let out_tag = build_leaf_outbound(idx, p, &mut outbounds);

            inbounds.push(json!({
                "protocol": "socks",
                "tag": in_tag,
                "address": "127.0.0.1",
                "port": port,
            }));
            rules.push(json!({
                "inboundTag": [in_tag],
                "target": out_tag,
            }));

            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|e| {
                GatewayError::Internal(format!("invalid loopback addr for leaf: {e}"))
            })?;
            resolved.insert(p.name.clone(), ResolvedProxy::Socks5 { addr });
        }

        if !inbounds.is_empty() {
            outbounds.push(json!({
                "protocol": "direct",
                "tag": "direct",
            }));

            let leaf_cfg = json!({
                "log": { "level": "warn" },
                "dns": { "servers": ["8.8.8.8", "1.1.1.1"] },
                "inbounds": inbounds,
                "outbounds": outbounds,
                "router": { "rules": rules },
            });
            let cfg_str = serde_json::to_string(&leaf_cfg).map_err(|e| {
                GatewayError::Internal(format!("failed to serialize leaf config: {e}"))
            })?;

            let rt_id = self.next_rt_id.fetch_add(1, Ordering::Relaxed);
            *rt_guard = Some(rt_id);

            let count = inbounds.len();
            std::thread::Builder::new()
                .name(format!("ttt-leaf-{rt_id}"))
                .spawn(move || {
                    let opts = leaf::StartOptions {
                        config: leaf::Config::Str(cfg_str),
                        runtime_opt: leaf::RuntimeOption::SingleThread,
                    };
                    info!(rt_id, proxies = count, "starting embedded eycorsican/leaf proxy runtime");
                    if let Err(err) = leaf::start(rt_id, opts) {
                        warn!(rt_id, error = %err, "embedded leaf runtime exited with error");
                    }
                })
                .map_err(|e| {
                    GatewayError::Internal(format!("failed to spawn leaf runtime thread: {e}"))
                })?;

            // Brief yield so leaf binds its local loopback SOCKS5 sockets before first request.
            std::thread::sleep(Duration::from_millis(60));
        }

        self.active.store(Arc::new(resolved));
        Ok(())
    }

    /// Test real HTTPS connectivity & latency through a named proxy.
    pub async fn test_proxy(
        &self,
        name: &str,
        target_url: &str,
    ) -> Result<(u16, u64), GatewayError> {
        let proxy = self.get(name).ok_or_else(|| {
            GatewayError::InvalidRequest(format!("代理 '{name}' 未启用或未加载"))
        })?;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let connector = TunnelConnector::new(proxy, Duration::from_secs(8));
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(connector);
        let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

        let uri: http::Uri = target_url
            .parse()
            .map_err(|e| GatewayError::InvalidRequest(format!("无效测速 URL: {e}")))?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(http::header::USER_AGENT, "TalkThatTalk/0.1")
            .body(Empty::new())
            .map_err(|e| GatewayError::InvalidRequest(format!("构造测速请求失败: {e}")))?;

        let started = Instant::now();
        let resp = tokio::time::timeout(Duration::from_secs(10), client.request(req))
            .await
            .map_err(|_| GatewayError::UpstreamTimeout)?
            .map_err(|e| GatewayError::UpstreamConnect(format!("代理连接失败: {e}")))?;

        let status = resp.status().as_u16();
        let _ = resp.into_body().collect().await;
        let latency_ms = started.elapsed().as_millis() as u64;
        Ok((status, latency_ms))
    }
}

impl Drop for LeafProxyManager {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.current_rt_id.lock()
            && let Some(rt_id) = guard.take()
        {
            let _ = leaf::shutdown(rt_id);
        }
    }
}

fn allocate_loopback_port() -> Result<u16, GatewayError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| GatewayError::Internal(format!("failed to bind ephemeral port: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| GatewayError::Internal(format!("failed to read local_addr: {e}")))?
        .port();
    drop(listener);
    Ok(port)
}

/// Build `leaf` JSON outbound(s) for a proxy config and return the target outbound tag.
fn build_leaf_outbound(idx: usize, p: &ProxyConfig, outbounds: &mut Vec<Value>) -> String {
    let base_tag = format!("out_{idx}");
    let server = p.server.trim();
    let password = p.password.as_deref().unwrap_or("").trim();

    match p.protocol {
        ProxyProtocol::Socks5 => {
            let mut settings = json!({
                "address": server,
                "port": p.port,
            });
            if let Some(u) = p.username.as_deref().filter(|s| !s.is_empty()) {
                settings["username"] = json!(u);
            }
            if !password.is_empty() {
                settings["password"] = json!(password);
            }
            outbounds.push(json!({
                "protocol": "socks",
                "tag": base_tag,
                "settings": settings,
            }));
            base_tag
        }
        ProxyProtocol::Shadowsocks => {
            let cipher = p
                .cipher
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("aes-256-gcm");
            outbounds.push(json!({
                "protocol": "shadowsocks",
                "tag": base_tag,
                "settings": {
                    "address": server,
                    "port": p.port,
                    "method": cipher,
                    "password": password,
                },
            }));
            base_tag
        }
        ProxyProtocol::Trojan => {
            let trojan_tag = format!("trojan_{idx}");
            outbounds.push(json!({
                "protocol": "trojan",
                "tag": trojan_tag,
                "settings": {
                    "address": server,
                    "port": p.port,
                    "password": password,
                },
            }));
            build_transport_chain(idx, p, trojan_tag, true, outbounds)
        }
        ProxyProtocol::Vmess => {
            let vmess_tag = format!("vmess_{idx}");
            let security = p
                .cipher
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("auto");
            outbounds.push(json!({
                "protocol": "vmess",
                "tag": vmess_tag,
                "settings": {
                    "address": server,
                    "port": p.port,
                    "uuid": password,
                    "security": security,
                },
            }));
            build_transport_chain(idx, p, vmess_tag, p.tls, outbounds)
        }
        ProxyProtocol::Vless => {
            let vless_tag = format!("vless_{idx}");
            outbounds.push(json!({
                "protocol": "vless",
                "tag": vless_tag,
                "settings": {
                    "address": server,
                    "port": p.port,
                    "uuid": password,
                },
            }));
            build_transport_chain(idx, p, vless_tag, p.tls, outbounds)
        }
        ProxyProtocol::Http => base_tag,
    }
}

/// Optionally wrap a protocol outbound with TLS / REALITY and WebSocket transport layers using `leaf` chain.
fn build_transport_chain(
    idx: usize,
    p: &ProxyConfig,
    proto_tag: String,
    use_tls: bool,
    outbounds: &mut Vec<Value>,
) -> String {
    let mut actors: Vec<String> = Vec::new();

    if let Some(pbk) = p.reality_public_key.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let reality_tag = format!("reality_{idx}");
        let sni = p
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(p.server.trim());
        let mut settings = json!({
            "serverName": sni,
            "publicKey": pbk,
        });
        if let Some(sid) = p.reality_short_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            settings["shortId"] = json!(sid);
        }
        outbounds.push(json!({
            "protocol": "reality",
            "tag": reality_tag,
            "settings": settings,
        }));
        actors.push(reality_tag);
    } else if use_tls {
        let tls_tag = format!("tls_{idx}");
        let sni = p
            .sni
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(p.server.trim());
        outbounds.push(json!({
            "protocol": "tls",
            "tag": tls_tag,
            "settings": {
                "serverName": sni,
            },
        }));
        actors.push(tls_tag);
    }

    if let Some(ws_path) = p.ws_path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let ws_tag = format!("ws_{idx}");
        let ws_host = p
            .ws_host
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(p.server.trim());
        outbounds.push(json!({
            "protocol": "ws",
            "tag": ws_tag,
            "settings": {
                "path": ws_path,
                "headers": {
                    "Host": ws_host,
                },
            },
        }));
        actors.push(ws_tag);
    }

    if actors.is_empty() {
        return proto_tag;
    }

    actors.push(proto_tag);
    let chain_tag = format!("chain_{idx}");
    outbounds.push(json!({
        "protocol": "chain",
        "tag": chain_tag,
        "settings": {
            "actors": actors,
        },
    }));
    chain_tag
}
