use http::StatusCode;
use serde_json::json;
use thiserror::Error;

/// Unified gateway error type.
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("no available upstream route for model: {0}")]
    NoRoute(String),

    #[error("authentication provider error: {0}")]
    Auth(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("upstream connection error: {0}")]
    UpstreamConnect(String),

    #[error("upstream timeout")]
    UpstreamTimeout,

    #[error("internal gateway error: {0}")]
    Internal(String),
}

impl GatewayError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Config(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NoRoute(_) => StatusCode::BAD_GATEWAY,
            Self::Auth(_) => StatusCode::BAD_GATEWAY,
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::UpstreamConnect(_) => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    pub fn error_type(&self) -> &'static str {
        match self {
            Self::Config(_) | Self::Internal(_) => "gateway_internal_error",
            Self::Unauthorized(_) => "authentication_error",
            Self::Forbidden(_) => "permission_error",
            Self::NoRoute(_) => "no_upstream_route",
            Self::Auth(_) => "upstream_auth_error",
            Self::InvalidRequest(_) => "invalid_request_error",
            Self::UpstreamConnect(_) => "upstream_connection_error",
            Self::UpstreamTimeout => "upstream_timeout_error",
        }
    }

    /// Format error in OpenAI-compatible JSON error envelope.
    pub fn to_json_bytes(&self) -> bytes::Bytes {
        let payload = json!({
            "error": {
                "message": self.to_string(),
                "type": self.error_type(),
                "code": self.status_code().as_u16(),
            }
        });
        bytes::Bytes::from(payload.to_string())
    }
}
