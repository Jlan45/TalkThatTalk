use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use ttt_core::{GatewayError, OAuthStorageConfig};

/// Persistent OAuth token record stored encrypted on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOAuthToken {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

impl StoredOAuthToken {
    pub fn antigravity_project_id(&self) -> Option<&str> {
        self.extra.get("project_id").map(String::as_str)
    }

    pub(crate) fn set_antigravity_project_id(&mut self, project_id: String) {
        self.extra.insert("project_id".into(), project_id);
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedEnvelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

/// Pluggable persistent store for OAuth tokens (implemented by SQLite `GatewayDb` or file store).
pub trait TokenStore: Send + Sync {
    fn get(&self, account_id: &str) -> Result<Option<StoredOAuthToken>, GatewayError>;
    fn list(&self) -> Result<HashMap<String, StoredOAuthToken>, GatewayError>;
    fn put(&self, account_id: &str, token: StoredOAuthToken) -> Result<(), GatewayError>;
}

/// Thread-safe AES-256-GCM encrypted file token store with atomic file replacement.
pub struct EncryptedTokenStore {
    store_path: PathBuf,
    key: [u8; 32],
    io_lock: Mutex<()>,
}

impl TokenStore for EncryptedTokenStore {
    fn get(&self, account_id: &str) -> Result<Option<StoredOAuthToken>, GatewayError> {
        EncryptedTokenStore::get(self, account_id)
    }

    fn list(&self) -> Result<HashMap<String, StoredOAuthToken>, GatewayError> {
        EncryptedTokenStore::list(self)
    }

    fn put(&self, account_id: &str, token: StoredOAuthToken) -> Result<(), GatewayError> {
        EncryptedTokenStore::put(self, account_id, token)
    }
}

impl EncryptedTokenStore {
    pub fn from_config(cfg: &OAuthStorageConfig) -> Result<Self, GatewayError> {
        let store_path = PathBuf::from(&cfg.store_path);
        let key = resolve_or_create_master_key(&store_path, &cfg.master_key_env)?;
        Ok(Self {
            store_path,
            key,
            io_lock: Mutex::new(()),
        })
    }

    pub fn with_key(store_path: impl Into<PathBuf>, key: [u8; 32]) -> Self {
        Self {
            store_path: store_path.into(),
            key,
            io_lock: Mutex::new(()),
        }
    }

    pub fn get(&self, account_id: &str) -> Result<Option<StoredOAuthToken>, GatewayError> {
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| GatewayError::Internal("token store mutex poisoned".into()))?;
        let map = self.load_map_locked()?;
        Ok(map.get(account_id).cloned())
    }

    pub fn list(&self) -> Result<HashMap<String, StoredOAuthToken>, GatewayError> {
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| GatewayError::Internal("token store mutex poisoned".into()))?;
        self.load_map_locked()
    }

    pub fn put(&self, account_id: &str, token: StoredOAuthToken) -> Result<(), GatewayError> {
        let _guard = self
            .io_lock
            .lock()
            .map_err(|_| GatewayError::Internal("token store mutex poisoned".into()))?;
        let mut map = self.load_map_locked()?;
        map.insert(account_id.to_string(), token);
        self.save_map_locked(&map)
    }

    fn load_map_locked(&self) -> Result<HashMap<String, StoredOAuthToken>, GatewayError> {
        if !self.store_path.exists() {
            return Ok(HashMap::new());
        }
        let raw = fs::read_to_string(&self.store_path)
            .map_err(|e| GatewayError::Auth(format!("failed to read token store: {e}")))?;
        if raw.trim().is_empty() {
            return Ok(HashMap::new());
        }
        let envelope: EncryptedEnvelope = serde_json::from_str(&raw)
            .map_err(|e| GatewayError::Auth(format!("corrupted token store envelope: {e}")))?;
        if envelope.version != 1 {
            return Err(GatewayError::Auth(format!(
                "unsupported token store version: {}",
                envelope.version
            )));
        }
        let nonce_bytes = BASE64
            .decode(&envelope.nonce)
            .map_err(|e| GatewayError::Auth(format!("invalid nonce base64: {e}")))?;
        if nonce_bytes.len() != 12 {
            return Err(GatewayError::Auth("invalid AES-GCM nonce length".into()));
        }
        let ciphertext = BASE64
            .decode(&envelope.ciphertext)
            .map_err(|e| GatewayError::Auth(format!("invalid ciphertext base64: {e}")))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| {
                GatewayError::Auth(
                    "failed to decrypt token store (wrong master key or tampered file)".into(),
                )
            })?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| GatewayError::Auth(format!("invalid decrypted token store JSON: {e}")))
    }

    fn save_map_locked(&self, map: &HashMap<String, StoredOAuthToken>) -> Result<(), GatewayError> {
        let plaintext = serde_json::to_vec(map)
            .map_err(|e| GatewayError::Internal(format!("failed to serialize tokens: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| GatewayError::Internal("AES-256-GCM encryption failed".into()))?;

        let envelope = EncryptedEnvelope {
            version: 1,
            nonce: BASE64.encode(nonce_bytes),
            ciphertext: BASE64.encode(ciphertext),
        };
        let serialized = serde_json::to_vec_pretty(&envelope)
            .map_err(|e| GatewayError::Internal(format!("failed to serialize envelope: {e}")))?;

        if let Some(parent) = self.store_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|e| GatewayError::Auth(format!("failed to create store dir: {e}")))?;
        }

        let tmp_path = self.store_path.with_extension("tmp");
        fs::write(&tmp_path, &serialized)
            .map_err(|e| GatewayError::Auth(format!("failed to write temp token store: {e}")))?;
        restrict_file_permissions(&tmp_path);
        fs::rename(&tmp_path, &self.store_path)
            .map_err(|e| GatewayError::Auth(format!("failed to commit token store: {e}")))?;
        Ok(())
    }
}

fn resolve_or_create_master_key(
    store_path: &Path,
    env_name: &str,
) -> Result<[u8; 32], GatewayError> {
    if !env_name.is_empty()
        && let Ok(val) = std::env::var(env_name)
    {
        return decode_32_byte_key(&val, env_name);
    }

    let key_path = PathBuf::from(format!("{}.key", store_path.display()));
    if key_path.exists() {
        let raw = fs::read_to_string(&key_path)
            .map_err(|e| GatewayError::Auth(format!("failed to read local master key: {e}")))?;
        return decode_32_byte_key(raw.trim(), &key_path.display().to_string());
    }

    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    if let Some(parent) = key_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| GatewayError::Auth(format!("failed to create key dir: {e}")))?;
    }
    fs::write(&key_path, BASE64.encode(key))
        .map_err(|e| GatewayError::Auth(format!("failed to write local master key: {e}")))?;
    restrict_file_permissions(&key_path);
    Ok(key)
}

fn decode_32_byte_key(b64: &str, source: &str) -> Result<[u8; 32], GatewayError> {
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| GatewayError::Config(format!("invalid base64 master key in {source}: {e}")))?;
    if bytes.len() != 32 {
        return Err(GatewayError::Config(format!(
            "master key in {source} must decode to exactly 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_persists_and_detects_wrong_key() {
        let tmp = std::env::temp_dir().join(format!(
            "ttt-store-test-{}.enc",
            rand::thread_rng().next_u64()
        ));
        let key = [7u8; 32];
        let store = EncryptedTokenStore::with_key(&tmp, key);

        store
            .put(
                "claude-acct",
                StoredOAuthToken {
                    access_token: "at-secret".into(),
                    refresh_token: Some("rt-secret".into()),
                    expires_at: Some(1_900_000_000),
                    token_type: Some("Bearer".into()),
                    scope: Some("user:inference".into()),
                    extra: HashMap::new(),
                },
            )
            .unwrap();

        // Ensure ciphertext on disk does not contain plaintext tokens.
        let disk = fs::read_to_string(&tmp).unwrap();
        assert!(!disk.contains("at-secret"));
        assert!(!disk.contains("rt-secret"));

        // Correct key reads back cleanly.
        let loaded = store.get("claude-acct").unwrap().unwrap();
        assert_eq!(loaded.access_token, "at-secret");
        assert_eq!(loaded.refresh_token.as_deref(), Some("rt-secret"));

        // Wrong key fails authentication tag verification.
        let wrong_store = EncryptedTokenStore::with_key(&tmp, [9u8; 32]);
        assert!(wrong_store.get("claude-acct").is_err());

        let _ = fs::remove_file(&tmp);
    }
}
