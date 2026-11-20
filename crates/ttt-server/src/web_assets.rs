use bytes::Bytes;
use http::{header, Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use ttt_proxy::ProxyBody;

include!(concat!(env!("OUT_DIR"), "/embedded_web.rs"));

/// Returns true if the request path belongs to the gateway data plane or control API
/// rather than the embedded Web Console SPA.
#[inline]
pub fn is_api_or_gateway_path(method: &Method, path: &str) -> bool {
    if path == "/healthz"
        || path.starts_with("/api/v1/")
        || path.starts_with("/v1/")
        || path.starts_with("/v1beta/")
    {
        return true;
    }
    // Non-GET/HEAD requests on any other path are forwarded to the proxy engine.
    !matches!(*method, Method::GET | Method::HEAD)
}

/// Serve static assets from the embedded `web/dist` bundle with SPA fallback to `index.html`.
pub fn serve_embedded_web(req: &Request<Incoming>) -> Response<ProxyBody> {
    let raw_path = req.uri().path().trim_start_matches('/');
    let is_head = *req.method() == Method::HEAD;

    // 1. Exact asset match (e.g. "assets/index-xxx.js", "index.html")
    if !raw_path.is_empty()
        && let Some((bytes, mime)) = get_asset(raw_path)
    {
        let cache = if raw_path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return build_asset_response(StatusCode::OK, mime, cache, bytes, is_head);
    }

    // 2. SPA fallback to index.html for client-side routes (e.g. "/", "/upstreams", "/proxies", ...)
    if let Some((bytes, mime)) = get_asset("index.html") {
        return build_asset_response(StatusCode::OK, mime, "no-cache", bytes, is_head);
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(ProxyBody::full(Bytes::from_static(
            b"Web UI not embedded (run `cd web && pnpm build` before cargo build)",
        )))
        .unwrap()
}

fn build_asset_response(
    status: StatusCode,
    mime: &'static str,
    cache_control: &'static str,
    bytes: &'static [u8],
    is_head: bool,
) -> Response<ProxyBody> {
    let body = if is_head {
        ProxyBody::empty()
    } else {
        ProxyBody::full(Bytes::from_static(bytes))
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(body)
        .unwrap()
}
