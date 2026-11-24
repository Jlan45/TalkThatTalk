use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use clash_lib::app::dispatcher::{BoxedInstrumentedStream, InstrumentedStreamWrapper};
use http::Uri;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tower_service::Service;
use ttt_core::{GatewayError, PoolConfig};

use crate::body::UpstreamBody;
use crate::clash_manager::ResolvedProxy;

pub type UpstreamHttpClient = Client<HttpsConnector<HttpConnector>, UpstreamBody>;
pub type ProxiedHttpClient = Client<HttpsConnector<TunnelConnector>, UpstreamBody>;

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

/// Build a pooled HTTP/1.1 + HTTP/2 client through a configured proxy.
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

/// Hyper connector for Clash outbounds and HTTP CONNECT tunnels.
#[derive(Clone)]
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
    type Response = TokioIo<TunnelStream>;
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
                let stream: BoxedInstrumentedStream = match proxy {
                    ResolvedProxy::Clash(connect) => connect(host, port).await?,
                    ResolvedProxy::Http { addr, auth_header } => {
                        let mut stream = TcpStream::connect(&addr).await?;
                        let _ = stream.set_nodelay(true);
                        http_connect_handshake(&mut stream, &host, port, auth_header.as_deref())
                            .await?;
                        Box::new(InstrumentedStreamWrapper::new(stream))
                    }
                };
                Ok(TokioIo::new(TunnelStream(stream)))
            };

            tokio::time::timeout(timeout, fut).await.map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "proxy tunnel connect timeout")
            })?
        })
    }
}

pub struct TunnelStream(BoxedInstrumentedStream);

impl Connection for TunnelStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
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
