use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tower_service::Service;
use ttt_core::{GatewayError, PoolConfig};

use crate::body::ProxyBody;
use crate::leaf_manager::ResolvedProxy;

pub type UpstreamHttpClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;
pub type ProxiedHttpClient = Client<HttpsConnector<TunnelConnector>, ProxyBody>;

/// Build a high-performance pooled HTTP/1.1 + HTTP/2 client with rustls and TCP_NODELAY.
pub fn build_upstream_client(cfg: &PoolConfig) -> Result<UpstreamHttpClient, GatewayError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(60)));
    http_connector.set_connect_timeout(Some(Duration::from_millis(cfg.connect_timeout_ms)));

    let https_connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .pool_max_idle_per_host(cfg.max_idle_per_host)
        .http2_adaptive_window(cfg.http2_adaptive_window);

    Ok(builder.build(https_connector))
}

/// Build a pooled HTTP/1.1 + HTTP/2 client tunneling through an embedded `leaf` SOCKS5
/// inbound or a direct HTTP CONNECT proxy.
pub fn build_proxied_client(
    cfg: &PoolConfig,
    proxy: ResolvedProxy,
) -> Result<ProxiedHttpClient, GatewayError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tunnel = TunnelConnector::new(proxy, Duration::from_millis(cfg.connect_timeout_ms));
    let https_connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(tunnel);

    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_idle_timeout(Duration::from_secs(cfg.idle_timeout_secs))
        .pool_max_idle_per_host(cfg.max_idle_per_host)
        .http2_adaptive_window(cfg.http2_adaptive_window);

    Ok(builder.build(https_connector))
}

/// Hyper 1.x compatible TCP tunnel connector supporting:
/// - RFC 1928 SOCKS5 (connecting to embedded `eycorsican/leaf` loopback inbound)
/// - HTTP `CONNECT` proxy tunnels (with optional Basic auth)
#[derive(Debug, Clone)]
pub struct TunnelConnector {
    proxy: ResolvedProxy,
    connect_timeout: Duration,
}

impl TunnelConnector {
    pub fn new(proxy: ResolvedProxy, connect_timeout: Duration) -> Self {
        Self {
            proxy,
            connect_timeout,
        }
    }
}

impl Service<Uri> for TunnelConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let proxy = self.proxy.clone();
        let timeout = self.connect_timeout;

        Box::pin(async move {
            let host = dst
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URI missing host"))?
                .to_string();
            let port = dst.port_u16().unwrap_or_else(|| {
                if dst.scheme_str() == Some("https") {
                    443
                } else {
                    80
                }
            });

            let fut = async move {
                match proxy {
                    ResolvedProxy::Socks5 { addr } => {
                        let mut stream = TcpStream::connect(addr).await?;
                        let _ = stream.set_nodelay(true);
                        socks5_handshake(&mut stream, &host, port).await?;
                        Ok(TokioIo::new(stream))
                    }
                    ResolvedProxy::Http { addr, auth_header } => {
                        let mut stream = TcpStream::connect(&addr).await?;
                        let _ = stream.set_nodelay(true);
                        http_connect_handshake(&mut stream, &host, port, auth_header.as_deref())
                            .await?;
                        Ok(TokioIo::new(stream))
                    }
                }
            };

            tokio::time::timeout(timeout, fut)
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy tunnel connect timeout"))?
        })
    }
}

/// Minimal RFC 1928 SOCKS5 no-auth handshake (to our local in-process `leaf` SOCKS5 listener).
async fn socks5_handshake(stream: &mut TcpStream, host: &str, port: u16) -> io::Result<()> {
    // Greeting: VER=5, NMETHODS=1, METHOD=0x00 (No Auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greet_resp = [0u8; 2];
    stream.read_exact(&mut greet_resp).await?;
    if greet_resp[0] != 0x05 || greet_resp[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("SOCKS5 greeting rejected: {:?}", greet_resp),
        ));
    }

    // CONNECT request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=3 (DOMAINNAME)
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target hostname exceeds 255 bytes",
        ));
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.push(0x05);
    req.push(0x01);
    req.push(0x00);
    req.push(0x03);
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    // Reply header: VER, REP, RSV, ATYP
    let mut rep = [0u8; 4];
    stream.read_exact(&mut rep).await?;
    if rep[0] != 0x05 || rep[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed with reply code 0x{:02x}", rep[1]),
        ));
    }

    // Drain BND.ADDR + BND.PORT
    match rep[3] {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 unknown ATYP 0x{other:02x}"),
            ));
        }
    }
    Ok(())
}

/// Minimal HTTP/1.1 CONNECT tunnel handshake.
async fn http_connect_handshake(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    auth_header: Option<&str>,
) -> io::Result<()> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(auth) = auth_header {
        req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response header too large",
            ));
        }
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
    }

    let first_line = std::str::from_utf8(&buf)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    if !first_line.contains(" 200") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP CONNECT rejected: {first_line}"),
        ));
    }
    Ok(())
}
