use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use ttt_core::GatewayError;
use url::Url;

/// RFC 7636 PKCE (S256) challenge pair.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    pub verifier: String,
    pub challenge: String,
}

impl PkceChallenge {
    /// Generate a cryptographically random 32-byte verifier and its S256 challenge.
    pub fn generate() -> Self {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let verifier = URL_SAFE_NO_PAD.encode(raw);
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        Self {
            verifier,
            challenge,
        }
    }

    pub fn method(&self) -> &'static str {
        "S256"
    }
}

/// Generate a cryptographically random CSRF `state` token.
pub fn generate_state() -> String {
    let mut raw = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Build an RFC 6749 + RFC 7636 Authorization Code + PKCE URL.
pub fn build_authorize_url(
    authorize_url: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    state: &str,
    pkce: &PkceChallenge,
    extra_params: &[(&str, &str)],
) -> Result<String, GatewayError> {
    let mut url = Url::parse(authorize_url)
        .map_err(|e| GatewayError::Config(format!("invalid authorize_url '{authorize_url}': {e}")))?;

    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("response_type", "code");
        qp.append_pair("client_id", client_id);
        qp.append_pair("redirect_uri", redirect_uri);
        if !scopes.is_empty() {
            qp.append_pair("scope", &scopes.join(" "));
        }
        qp.append_pair("state", state);
        qp.append_pair("code_challenge", &pkce.challenge);
        qp.append_pair("code_challenge_method", pkce.method());
        for (k, v) in extra_params {
            qp.append_pair(k, v);
        }
    }

    Ok(url.to_string())
}

/// Parse an authorization response from either:
/// - A full redirect URL (`http://127.0.0.1:.../callback?code=...&state=...`)
/// - Claude Code style `code#state`
/// - A raw authorization `code`
///
/// Verifies `state` when present against `expected_state`.
pub fn parse_authorization_input(
    input: &str,
    expected_state: &str,
) -> Result<String, GatewayError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(GatewayError::Auth("empty authorization code input".into()));
    }

    // 1. Full callback URL
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let parsed = Url::parse(trimmed)
            .map_err(|e| GatewayError::Auth(format!("invalid callback URL: {e}")))?;
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                _ => {}
            }
        }
        if let Some(err) = error {
            return Err(GatewayError::Auth(format!("oauth provider returned error: {err}")));
        }
        if let Some(st) = state
            && st != expected_state
        {
            return Err(GatewayError::Auth("oauth state mismatch (CSRF check failed)".into()));
        }
        return code.ok_or_else(|| GatewayError::Auth("callback URL missing 'code' parameter".into()));
    }

    // 2. Claude Code `code#state` format
    if let Some((code, state)) = trimmed.split_once('#') {
        if state != expected_state {
            return Err(GatewayError::Auth("oauth state mismatch (CSRF check failed)".into()));
        }
        if code.is_empty() {
            return Err(GatewayError::Auth("empty code before '#'".into()));
        }
        return Ok(code.to_string());
    }

    // 3. Raw code
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_sha256_s256() {
        let pkce = PkceChallenge::generate();
        let digest = Sha256::digest(pkce.verifier.as_bytes());
        assert_eq!(pkce.challenge, URL_SAFE_NO_PAD.encode(digest));
        assert_eq!(pkce.method(), "S256");
    }

    #[test]
    fn parses_callback_url_and_claude_code_hash_format() {
        let state = "state-123";
        let code1 = parse_authorization_input(
            "http://127.0.0.1:1455/auth/callback?code=abc_1&state=state-123",
            state,
        )
        .unwrap();
        assert_eq!(code1, "abc_1");

        let code2 = parse_authorization_input("claude_code_xyz#state-123", state).unwrap();
        assert_eq!(code2, "claude_code_xyz");

        let err = parse_authorization_input("claude_code_xyz#wrong", state);
        assert!(err.is_err());
    }
}
