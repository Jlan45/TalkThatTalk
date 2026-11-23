use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Uri, header};
use http_body_util::{BodyExt, Empty, Limited};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{HttpConnector, dns::Name};
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use tower_service::Service;
use ttt_core::{ClashProxyOptions, GatewayError, ProxyConfig, ProxyProtocol};
use url::{Host, Url};
use yaml_serde::Value;

const MAX_SUBSCRIPTION_BYTES: usize = 2 * 1024 * 1024;
const MAX_SUBSCRIPTION_NODES: usize = 2_000;
const MAX_REDIRECTS: usize = 3;

pub(crate) struct Subscription {
    pub nodes: Vec<ProxyConfig>,
    pub skipped: usize,
}

pub(crate) async fn fetch_subscription(address: &str) -> Result<Subscription, GatewayError> {
    let url = Url::parse(address.trim()).map_err(|_| invalid_url())?;
    let body = tokio::time::timeout(Duration::from_secs(15), download(url))
        .await
        .map_err(|_| GatewayError::UpstreamTimeout)??;
    parse_subscription(&body)
}

async fn download(mut url: Url) -> Result<Bytes, GatewayError> {
    validate_url(&url)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut http = HttpConnector::new_with_resolver(PublicDns);
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    for _ in 0..=MAX_REDIRECTS {
        let uri: Uri = url.as_str().parse().map_err(|_| invalid_url())?;
        let request = Request::get(uri)
            .header(header::USER_AGENT, "Clash.Meta")
            .body(Empty::new())
            .map_err(|_| invalid_url())?;
        let response = client.request(request).await.map_err(|_| {
            GatewayError::UpstreamConnect("无法连接订阅服务器，请检查地址和网络".into())
        })?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(invalid_url)?;
            let next = url.join(location).map_err(|_| invalid_url())?;
            validate_url(&next)?;
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err(invalid_url());
            }
            url = next;
            continue;
        }
        if !response.status().is_success() {
            return Err(GatewayError::UpstreamConnect(format!(
                "订阅服务器返回 HTTP {}",
                response.status().as_u16()
            )));
        }
        return Limited::new(response.into_body(), MAX_SUBSCRIPTION_BYTES)
            .collect()
            .await
            .map(|body| body.to_bytes())
            .map_err(|_| GatewayError::UpstreamConnect("读取订阅失败或订阅超过 2 MiB".into()));
    }
    Err(GatewayError::UpstreamConnect(
        "订阅服务器重定向次数过多".into(),
    ))
}

fn validate_url(url: &Url) -> Result<(), GatewayError> {
    let valid_host = match url.host() {
        Some(Host::Domain(_)) => true,
        Some(Host::Ipv4(ip)) => is_public(ip.into()),
        Some(Host::Ipv6(ip)) => is_public(ip.into()),
        None => false,
    };
    if !matches!(url.scheme(), "http" | "https")
        || !valid_host
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str().len() > 8192
    {
        return Err(invalid_url());
    }
    Ok(())
}

fn invalid_url() -> GatewayError {
    GatewayError::InvalidRequest("请输入公网 HTTP 或 HTTPS 订阅地址".into())
}

#[derive(Clone, Copy)]
struct PublicDns;

impl Service<Name> for PublicDns {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        // Filter the addresses passed to the connector so each connection uses the checked DNS result.
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no public address",
                ));
            }
            Ok(addresses.into_iter())
        })
    }
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            a != 0
                && a < 224
                && !matches!((a, b), (100, 64..=127) | (198, 18..=19))
                && (a, b, c) != (192, 0, 0)
                && !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_documentation()
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            a & 0xe000 == 0x2000 && a != 0x2002 && (a, b) != (0x2001, 0x0db8)
        }
    }
}

#[derive(Deserialize)]
struct ClashSubscription {
    proxies: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ClashNode {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    uuid: Option<String>,
    cipher: Option<String>,
    #[serde(default)]
    tls: bool,
    sni: Option<String>,
    servername: Option<String>,
    network: Option<String>,
    ws_opts: Option<WebSocketOptions>,
    reality_opts: Option<RealityOptions>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default, alias = "alterId")]
    alter_id: u16,
    flow: Option<String>,
    encryption: Option<String>,
    up: Option<u64>,
    down: Option<u64>,
    plugin: Option<String>,
    dialer_proxy: Option<String>,
    obfs: Option<String>,
    ports: Option<String>,
}

#[derive(Deserialize)]
struct WebSocketOptions {
    path: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(rename = "max-early-data")]
    max_early_data: Option<u16>,
    #[serde(rename = "early-data-header-name")]
    early_data_header_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RealityOptions {
    public_key: String,
    short_id: Option<String>,
}

fn parse_subscription(body: &[u8]) -> Result<Subscription, GatewayError> {
    let config: ClashSubscription = yaml_serde::from_slice(body).map_err(|_| {
        GatewayError::InvalidRequest("订阅须为包含 proxies 列表的 Clash YAML".into())
    })?;
    let count = config.proxies.len();
    if count == 0 || count > MAX_SUBSCRIPTION_NODES {
        return Err(GatewayError::InvalidRequest(
            "订阅须包含 1–2000 个代理节点".into(),
        ));
    }
    let nodes: Vec<_> = config
        .proxies
        .into_iter()
        .filter_map(|entry| yaml_serde::from_value::<ClashNode>(entry).ok())
        .filter_map(ClashNode::into_proxy)
        .collect();
    Ok(Subscription {
        skipped: count - nodes.len(),
        nodes,
    })
}

impl ClashNode {
    fn into_proxy(self) -> Option<ProxyConfig> {
        let protocol = match self.kind.as_str() {
            "http" if !self.tls => ProxyProtocol::Http,
            "socks5" => ProxyProtocol::Socks5,
            "ss" => ProxyProtocol::Shadowsocks,
            "trojan" => ProxyProtocol::Trojan,
            "vmess" => ProxyProtocol::Vmess,
            "vless" => ProxyProtocol::Vless,
            "anytls" => ProxyProtocol::Anytls,
            "hysteria2" => ProxyProtocol::Hysteria2,
            _ => return None,
        };
        if self.plugin.is_some()
            || self.dialer_proxy.is_some()
            || self.obfs.is_some()
            || self.ports.is_some()
            || !matches!(self.encryption.as_deref(), None | Some("none" | ""))
            || !matches!(self.flow.as_deref(), None | Some("xtls-rprx-vision" | ""))
        {
            return None;
        }
        let mut options = ClashProxyOptions {
            skip_cert_verify: self.skip_cert_verify,
            alter_id: self.alter_id,
            flow: self.flow.filter(|flow| !flow.is_empty()),
            up: self.up,
            down: self.down,
            ..Default::default()
        };
        let (ws_path, ws_host) = match self.network.as_deref() {
            None | Some("tcp" | "") => (None, None),
            Some("ws")
                if matches!(
                    protocol,
                    ProxyProtocol::Trojan | ProxyProtocol::Vmess | ProxyProtocol::Vless
                ) =>
            {
                let websocket = self.ws_opts?;
                let host = websocket
                    .headers
                    .into_iter()
                    .find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(value));
                let mut path = websocket.path.unwrap_or_else(|| "/".into());
                if let Some((normalized_path, size)) = split_early_data(&path) {
                    path = normalized_path;
                    options.ws_max_early_data = Some(size);
                    options.ws_early_data_header = Some("Sec-WebSocket-Protocol".into());
                } else {
                    options.ws_max_early_data = websocket.max_early_data;
                    options.ws_early_data_header = websocket.early_data_header_name;
                    if options.ws_max_early_data.is_some_and(|size| size > 0)
                        && options
                            .ws_early_data_header
                            .as_deref()
                            .is_none_or(str::is_empty)
                    {
                        return None;
                    }
                }
                (Some(path), host)
            }
            _ => return None,
        };
        let (reality_public_key, reality_short_id) = match self.reality_opts {
            Some(options) if protocol == ProxyProtocol::Vless => {
                (Some(options.public_key), options.short_id)
            }
            Some(_) => return None,
            None => (None, None),
        };
        let password = match protocol {
            ProxyProtocol::Vless | ProxyProtocol::Vmess => self.uuid,
            _ => self.password,
        };
        let proxy = ProxyConfig {
            name: self.name.trim().to_owned(),
            protocol,
            server: self.server.trim().to_owned(),
            port: self.port,
            username: self.username,
            password,
            cipher: self.cipher,
            tls: self.tls
                || reality_public_key.is_some()
                || matches!(
                    protocol,
                    ProxyProtocol::Anytls | ProxyProtocol::Hysteria2 | ProxyProtocol::Trojan
                ),
            sni: self.servername.or(self.sni),
            ws_path,
            ws_host,
            reality_public_key,
            reality_short_id,
            clash_options: Some(options),
            enabled: true,
        };
        proxy.validate().ok()?;
        Some(proxy)
    }
}

fn split_early_data(path: &str) -> Option<(String, u16)> {
    let (base, query) = path.split_once('?')?;
    let params: Vec<_> = url::form_urlencoded::parse(query.as_bytes()).collect();
    let size = params.iter().find(|(key, _)| key == "ed")?.1.parse().ok()?;
    let remaining: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter().filter(|(key, _)| key != "ed"))
        .finish();
    let path = if remaining.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{remaining}")
    };
    Some((path, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_clash_nodes_and_preserves_transport_settings() {
        let body = br#"
proxies:
  - name: vision
    type: vless
    server: proxy.example
    port: 443
    uuid: 71ce993b-8823-468c-8013-49f8c4d27842
    servername: tls.example
    flow: xtls-rprx-vision
    reality-opts:
      public-key: sample
      short-id: "0012"
  - name: websocket
    type: vmess
    server: proxy.example
    port: 443
    uuid: 71ce993b-8823-468c-8013-49f8c4d27842
    network: ws
    ws-opts:
      path: /proxy?ed=2048&version=2
      headers: { host: ws.example }
  - name: quic
    type: hysteria2
    server: proxy.example
    port: 443
    password: sample
    up: 30
    down: 200
  - name: unsupported
    type: wireguard
    server: proxy.example
    port: 443
  - invalid
rules: ["MATCH,unsupported"]
"#;
        let result = parse_subscription(body).unwrap();
        assert_eq!(result.skipped, 2);
        let [vless, vmess, quic] = result.nodes.as_slice() else {
            panic!("expected three importable nodes");
        };
        assert!(vless.tls);
        assert_eq!(vless.sni.as_deref(), Some("tls.example"));
        assert_eq!(vless.reality_short_id.as_deref(), Some("0012"));
        assert_eq!(
            vless.clash_options.as_ref().unwrap().flow.as_deref(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(vmess.ws_path.as_deref(), Some("/proxy?version=2"));
        assert_eq!(vmess.ws_host.as_deref(), Some("ws.example"));
        assert_eq!(
            vmess.clash_options.as_ref().unwrap().ws_max_early_data,
            Some(2048)
        );
        assert_eq!(quic.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(quic.clash_options.as_ref().unwrap().down, Some(200));
    }

    #[test]
    fn rejects_non_public_literal_subscription_hosts() {
        for url in [
            "http://127.1/resource",
            "http://169.254.169.254/resource",
            "http://[::ffff:10.0.0.1]/resource",
            "http://[fc00::1]/resource",
            "https://user:secret@example.com/resource",
        ] {
            assert!(validate_url(&Url::parse(url).unwrap()).is_err());
        }
        assert!(validate_url(&Url::parse("https://example.com/resource").unwrap()).is_ok());
    }
}
