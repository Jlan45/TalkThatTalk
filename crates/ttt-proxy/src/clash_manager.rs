use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::Ipv6Addr;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use clash_lib::app::dispatcher::{BoxedInstrumentedStream, Dispatcher};
use clash_lib::app::dns::{SystemResolver, ThreadSafeDNSResolver};
use clash_lib::app::outbound::manager::OutboundManager;
use clash_lib::config::internal::proxy::{
    CommonConfigOptions, OutboundAnytls, OutboundHysteria2, OutboundProxyProtocol,
    OutboundShadowsocks, OutboundSocks5, OutboundTrojan, OutboundVless, OutboundVmess, RealityOpt,
    WsOpt,
};
use http::{Method, Request};
use http_body_util::{BodyExt, Empty};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::warn;
use ttt_core::{GatewayError, PoolConfig, ProxyConfig, ProxyProtocol};

use crate::client::{ProxiedHttpClient, TunnelConnector, build_proxied_client};

type ClashDial = dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = io::Result<BoxedInstrumentedStream>> + Send>>
    + Send
    + Sync;

#[derive(Clone)]
pub enum ResolvedProxy {
    Clash(Arc<ClashDial>),
    Http {
        addr: String,
        auth_header: Option<String>,
    },
}

#[derive(Clone)]
struct ActiveProxy {
    resolved: ResolvedProxy,
    client: ProxiedHttpClient,
}

/// In-process Clash outbounds and their HTTP client pools.
pub struct ClashProxyManager {
    active: ArcSwap<HashMap<String, ActiveProxy>>,
    pool: PoolConfig,
    resolver: ThreadSafeDNSResolver,
    updates: Mutex<()>,
}

impl ClashProxyManager {
    pub(crate) fn new(pool: PoolConfig) -> Result<Self, GatewayError> {
        let resolver = SystemResolver::new(true)
            .map_err(|err| GatewayError::Internal(format!("initializing Clash resolver: {err}")))?;
        Ok(Self {
            active: ArcSwap::from_pointee(HashMap::new()),
            pool,
            resolver: Arc::new(resolver),
            updates: Mutex::new(()),
        })
    }

    pub fn get(&self, name: &str) -> Option<ResolvedProxy> {
        self.active
            .load()
            .get(name)
            .map(|proxy| proxy.resolved.clone())
    }

    pub fn is_active(&self, name: &str) -> bool {
        self.active.load().contains_key(name)
    }

    pub(crate) fn get_client(&self, name: &str) -> Option<ProxiedHttpClient> {
        self.active
            .load()
            .get(name)
            .map(|proxy| proxy.client.clone())
    }

    /// Publish the proxy only after its configuration has been persisted.
    pub fn update(
        &self,
        name: &str,
        proxy: Option<&ProxyConfig>,
        persist: impl FnOnce() -> Result<(), GatewayError>,
    ) -> Result<(), GatewayError> {
        let _guard = self
            .updates
            .lock()
            .map_err(|_| GatewayError::Internal("proxy update lock poisoned".into()))?;
        let entry = proxy
            .filter(|proxy| proxy.enabled)
            .map(|proxy| self.build_entry(proxy))
            .transpose()?;
        persist()?;

        let mut active = self.active.load().as_ref().clone();
        if let Some(entry) = entry {
            active.insert(name.to_owned(), entry);
        } else {
            active.remove(name);
        }
        self.active.store(Arc::new(active));
        Ok(())
    }

    pub(crate) fn reload(&self, proxies: &[ProxyConfig]) -> Result<(), GatewayError> {
        let _guard = self
            .updates
            .lock()
            .map_err(|_| GatewayError::Internal("proxy update lock poisoned".into()))?;
        let mut active = HashMap::new();
        for proxy in proxies.iter().filter(|proxy| proxy.enabled) {
            match self.build_entry(proxy) {
                Ok(entry) => {
                    active.insert(proxy.name.clone(), entry);
                }
                Err(err) => {
                    warn!(proxy = %proxy.name, error = %err, "failed to restore saved proxy")
                }
            }
        }
        self.active.store(Arc::new(active));
        Ok(())
    }

    /// Add usable nodes and publish them together after the database transaction commits.
    pub fn import(
        &self,
        proxies: &[ProxyConfig],
        persist: impl FnOnce(&[&ProxyConfig]) -> Result<(), GatewayError>,
    ) -> Result<usize, GatewayError> {
        let _guard = self
            .updates
            .lock()
            .map_err(|_| GatewayError::Internal("proxy update lock poisoned".into()))?;
        let mut active = self.active.load().as_ref().clone();
        let mut added = Vec::new();
        for proxy in proxies {
            match self.build_entry(proxy) {
                Ok(entry) => {
                    active.insert(proxy.name.clone(), entry);
                    added.push(proxy);
                }
                Err(GatewayError::Config(_)) => {}
                Err(err) => return Err(err),
            }
        }
        persist(&added)?;
        self.active.store(Arc::new(active));
        Ok(added.len())
    }

    fn build_entry(&self, proxy: &ProxyConfig) -> Result<ActiveProxy, GatewayError> {
        let resolved = resolve(proxy, Arc::clone(&self.resolver))?;
        let client = build_proxied_client(&self.pool, resolved.clone())?;
        Ok(ActiveProxy { resolved, client })
    }

    /// Test connectivity and latency through a named proxy.
    pub async fn test_proxy(
        &self,
        name: &str,
        target_url: &str,
    ) -> Result<(u16, u64), GatewayError> {
        let proxy = self
            .get(name)
            .ok_or_else(|| GatewayError::InvalidRequest(format!("代理 '{name}' 未启用或未加载")))?;

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
        let status = tokio::time::timeout(Duration::from_secs(10), async {
            let resp = client
                .request(req)
                .await
                .map_err(|e| GatewayError::UpstreamConnect(format!("代理连接失败: {e}")))?;
            let status = resp.status().as_u16();
            resp.into_body()
                .collect()
                .await
                .map_err(|e| GatewayError::UpstreamConnect(format!("读取测速响应失败: {e}")))?;
            Ok::<_, GatewayError>(status)
        })
        .await
        .map_err(|_| GatewayError::UpstreamTimeout)??;

        Ok((status, started.elapsed().as_millis() as u64))
    }
}

fn resolve(
    proxy: &ProxyConfig,
    resolver: ThreadSafeDNSResolver,
) -> Result<ResolvedProxy, GatewayError> {
    proxy.validate()?;
    let server = proxy.server.trim();
    if proxy.protocol == ProxyProtocol::Http {
        let auth_header = match (proxy.username.as_deref(), proxy.password.as_deref()) {
            (Some(user), Some(password)) if !user.is_empty() => Some(format!(
                "Basic {}",
                B64.encode(format!("{user}:{password}"))
            )),
            _ => None,
        };
        let addr = if server.parse::<Ipv6Addr>().is_ok() {
            format!("[{server}]:{}", proxy.port)
        } else {
            format!("{server}:{}", proxy.port)
        };
        return Ok(ResolvedProxy::Http { addr, auth_header });
    }

    let protocol = clash_outbound(proxy)?;
    let handler = OutboundManager::load_plain_outbounds(vec![protocol], Path::new("."))
        .pop()
        .ok_or_else(|| {
            GatewayError::Config(format!("Clash could not load proxy '{}'", proxy.name))
        })?;

    Ok(ResolvedProxy::Clash(Arc::new(move |host, port| {
        let handler = Arc::clone(&handler);
        let resolver = Arc::clone(&resolver);
        Box::pin(async move {
            let mut session = default_clash_session(Dispatcher::dispatch_stream);
            session.destination = format!("{host}:{port}")
                .parse()
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            handler.connect_stream(&session, resolver).await
        })
    })))
}

// ClashRS exposes Session in public signatures through a private module.
fn default_clash_session<S: Default, Stream, Fut>(
    _: fn(&'static Dispatcher, S, Stream) -> Fut,
) -> S {
    S::default()
}

fn clash_outbound(proxy: &ProxyConfig) -> Result<OutboundProxyProtocol, GatewayError> {
    let server = proxy.server.trim();
    let common_opts = CommonConfigOptions {
        name: proxy.name.clone(),
        server: server.to_owned(),
        port: proxy.port,
        ..Default::default()
    };
    let password = trimmed(proxy.password.as_deref()).unwrap_or_default();
    let cipher = trimmed(proxy.cipher.as_deref());
    let sni = trimmed(proxy.sni.as_deref()).unwrap_or(server);
    let defaults = Default::default();
    let options = proxy.clash_options.as_ref().unwrap_or(&defaults);

    let ws_opts = trimmed(proxy.ws_path.as_deref()).map(|path| WsOpt {
        path: Some(path.to_owned()),
        headers: Some(HashMap::from([(
            "Host".to_owned(),
            trimmed(proxy.ws_host.as_deref())
                .unwrap_or(server)
                .to_owned(),
        )])),
        max_early_data: options.ws_max_early_data.map(i32::from),
        early_data_header_name: options.ws_early_data_header.clone(),
    });
    let network = ws_opts.as_ref().map(|_| "ws".to_owned());

    let reality_key = trimmed(proxy.reality_public_key.as_deref());
    if reality_key.is_some()
        && matches!(proxy.protocol, ProxyProtocol::Vmess | ProxyProtocol::Trojan)
    {
        return Err(GatewayError::Config(format!(
            "Clash supports REALITY only for VLESS (proxy '{}')",
            proxy.name
        )));
    }

    Ok(match proxy.protocol {
        ProxyProtocol::Socks5 => OutboundProxyProtocol::Socks5(OutboundSocks5 {
            common_opts,
            username: proxy.username.clone().filter(|user| !user.is_empty()),
            password: (!password.is_empty()).then(|| password.to_owned()),
            tls: proxy.tls,
            sni: Some(sni.to_owned()),
            skip_cert_verify: options.skip_cert_verify,
            ..Default::default()
        }),
        ProxyProtocol::Shadowsocks => OutboundProxyProtocol::Ss(OutboundShadowsocks {
            common_opts,
            cipher: cipher.unwrap_or("aes-256-gcm").to_owned(),
            password: password.to_owned(),
            ..Default::default()
        }),
        ProxyProtocol::Trojan => OutboundProxyProtocol::Trojan(OutboundTrojan {
            common_opts,
            password: password.to_owned(),
            sni: Some(sni.to_owned()),
            skip_cert_verify: Some(options.skip_cert_verify),
            network,
            ws_opts,
            ..Default::default()
        }),
        ProxyProtocol::Vmess => OutboundProxyProtocol::Vmess(OutboundVmess {
            common_opts,
            uuid: password.to_owned(),
            alter_id: options.alter_id,
            cipher: Some(cipher.unwrap_or("auto").to_owned()),
            tls: Some(proxy.tls),
            skip_cert_verify: Some(options.skip_cert_verify),
            server_name: Some(sni.to_owned()),
            network,
            ws_opts,
            ..Default::default()
        }),
        ProxyProtocol::Vless => OutboundProxyProtocol::Vless(OutboundVless {
            common_opts,
            uuid: password.to_owned(),
            tls: Some(proxy.tls),
            skip_cert_verify: Some(options.skip_cert_verify),
            server_name: Some(sni.to_owned()),
            network,
            ws_opts,
            flow: options.flow.clone(),
            reality_opts: reality_key.map(|key| RealityOpt {
                public_key: key.to_owned(),
                short_id: trimmed(proxy.reality_short_id.as_deref())
                    .unwrap_or_default()
                    .to_owned(),
            }),
            ..Default::default()
        }),
        ProxyProtocol::Anytls => OutboundProxyProtocol::Anytls(OutboundAnytls {
            common_opts,
            password: password.to_owned(),
            sni: Some(sni.to_owned()),
            skip_cert_verify: Some(options.skip_cert_verify),
            ..Default::default()
        }),
        ProxyProtocol::Hysteria2 => OutboundProxyProtocol::Hysteria2(OutboundHysteria2 {
            name: proxy.name.clone(),
            server: server.to_owned(),
            port: proxy.port,
            password: password.to_owned(),
            sni: Some(sni.to_owned()),
            skip_cert_verify: options.skip_cert_verify,
            up: options.up,
            down: options.down,
            ..Default::default()
        }),
        ProxyProtocol::Http => unreachable!("HTTP CONNECT is built by resolve"),
    })
}

fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}
