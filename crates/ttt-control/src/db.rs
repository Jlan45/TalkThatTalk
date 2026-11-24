use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use ttt_auth::{StoredOAuthToken, TokenStore};
use ttt_core::{
    ClientKeyConfig, GatewayError, OAuthStorageConfig, ProxyConfig, QuotaSnapshot, UpstreamConfig,
};

use crate::metrics::RequestLogEntry;

pub type OwnedClientKey = (ClientKeyConfig, Option<i64>, Option<String>);

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub enabled: bool,
    pub allow_private_upstreams: bool,
    pub restrict_upstreams: bool,
    pub allowed_upstreams: Vec<String>,
    pub restrict_models: bool,
    pub allowed_models: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Embedded SQLite store (WAL mode) persisting upstreams (AES-256-GCM encrypted),
/// scoped client API keys, and request logs.
pub struct GatewayDb {
    conn: Mutex<Connection>,
    master_key: [u8; 32],
}

impl GatewayDb {
    pub fn open_from_config(cfg: &OAuthStorageConfig) -> Result<Self, GatewayError> {
        let db_path = PathBuf::from(&cfg.db_path);
        let key = resolve_or_create_master_key(&db_path, &cfg.master_key_env)?;
        Self::open(&db_path, key)
    }

    pub fn open(db_path: &Path, master_key: [u8; 32]) -> Result<Self, GatewayError> {
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)
                .map_err(|e| GatewayError::Config(format!("failed to create db dir: {e}")))?;
        }

        let conn = Connection::open(db_path)
            .map_err(|e| GatewayError::Config(format!("failed to open SQLite db: {e}")))?;
        init_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            master_key,
        })
    }

    pub fn open_in_memory(master_key: [u8; 32]) -> Result<Self, GatewayError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| GatewayError::Config(format!("failed to open in-memory SQLite: {e}")))?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            master_key,
        })
    }

    // =========================================================================
    // Upstreams (AES-256-GCM encrypted JSON blobs)
    // =========================================================================

    pub fn list_upstreams(&self) -> Result<Vec<UpstreamConfig>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare("SELECT nonce, ciphertext FROM upstreams ORDER BY created_at ASC, name ASC")
            .map_err(db_err)?;

        let rows = stmt
            .query_map([], |row| {
                let nonce: Vec<u8> = row.get(0)?;
                let ct: Vec<u8> = row.get(1)?;
                Ok((nonce, ct))
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            let (nonce, ct) = row.map_err(db_err)?;
            let plain = decrypt_bytes(&self.master_key, &nonce, &ct)?;
            let up: UpstreamConfig = serde_json::from_slice(&plain).map_err(|e| {
                GatewayError::Internal(format!("corrupted upstream record in db: {e}"))
            })?;
            out.push(up);
        }
        Ok(out)
    }

    pub fn upsert_upstream(&self, up: &UpstreamConfig) -> Result<(), GatewayError> {
        let plain = serde_json::to_vec(up)
            .map_err(|e| GatewayError::Internal(format!("failed to encode upstream: {e}")))?;
        let (nonce, ct) = encrypt_bytes(&self.master_key, &plain)?;
        let now = now_secs() as i64;

        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO upstreams (name, nonce, ciphertext, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(name) DO UPDATE SET
               nonce = excluded.nonce,
               ciphertext = excluded.ciphertext,
               updated_at = excluded.updated_at",
            params![up.name, nonce, ct, now],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn delete_upstream(&self, name: &str) -> Result<bool, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let affected = conn
            .execute("DELETE FROM upstreams WHERE name = ?1", params![name])
            .map_err(db_err)?;
        Ok(affected > 0)
    }

    // =========================================================================
    // Outbound Proxies (AES-256-GCM encrypted JSON blobs)
    // =========================================================================

    pub fn list_proxies(&self) -> Result<Vec<ProxyConfig>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare("SELECT nonce, ciphertext FROM proxies ORDER BY created_at ASC, name ASC")
            .map_err(db_err)?;

        let rows = stmt
            .query_map([], |row| {
                let nonce: Vec<u8> = row.get(0)?;
                let ct: Vec<u8> = row.get(1)?;
                Ok((nonce, ct))
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            let (nonce, ct) = row.map_err(db_err)?;
            let plain = decrypt_bytes(&self.master_key, &nonce, &ct)?;
            let proxy: ProxyConfig = serde_json::from_slice(&plain).map_err(|e| {
                GatewayError::Internal(format!("corrupted proxy record in db: {e}"))
            })?;
            out.push(proxy);
        }
        Ok(out)
    }

    pub fn upsert_proxy(&self, proxy: &ProxyConfig) -> Result<(), GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        self.write_proxy(&conn, proxy, true)
    }

    pub(crate) fn insert_proxies(&self, proxies: &[&ProxyConfig]) -> Result<(), GatewayError> {
        if proxies.is_empty() {
            return Ok(());
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let tx = conn.transaction().map_err(db_err)?;
        for proxy in proxies {
            self.write_proxy(&tx, proxy, false)?;
        }
        tx.commit().map_err(db_err)
    }

    fn write_proxy(
        &self,
        conn: &Connection,
        proxy: &ProxyConfig,
        overwrite: bool,
    ) -> Result<(), GatewayError> {
        let plain = serde_json::to_vec(proxy)
            .map_err(|e| GatewayError::Internal(format!("failed to encode proxy: {e}")))?;
        let (nonce, ct) = encrypt_bytes(&self.master_key, &plain)?;
        let written = conn.execute(
            "INSERT INTO proxies (name, nonce, ciphertext, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(name) DO UPDATE SET
               nonce = excluded.nonce,
               ciphertext = excluded.ciphertext,
               updated_at = excluded.updated_at
             WHERE ?5",
            params![proxy.name, nonce, ct, now_secs() as i64, overwrite],
        )
        .map_err(db_err)?;
        if written == 0 {
            return Err(GatewayError::Internal("代理名称在导入期间被占用".into()));
        }
        Ok(())
    }

    pub fn delete_proxy(&self, name: &str) -> Result<bool, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let affected = conn
            .execute("DELETE FROM proxies WHERE name = ?1", params![name])
            .map_err(db_err)?;
        Ok(affected > 0)
    }

    // =========================================================================
    // Client API Keys (with Provider & Model restriction switches)
    // =========================================================================

    /// Load all client keys with their effective runtime policies inherited from their owning user.
    pub fn list_client_keys(&self) -> Result<Vec<ClientKeyConfig>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT ck.key, ck.name, ck.enabled, ck.restrict_upstreams, ck.allowed_upstreams,
                        ck.restrict_models, ck.allowed_models, ck.owner_user_id,
                        u.enabled, u.role, u.restrict_upstreams, u.allowed_upstreams,
                        u.restrict_models, u.allowed_models
                 FROM client_keys ck
                 LEFT JOIN users u ON u.id = ck.owner_user_id
                 ORDER BY ck.created_at ASC, ck.key ASC",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)? != 0,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            let (
                key,
                name,
                key_enabled,
                k_ru,
                k_au_json,
                k_rm,
                k_am_json,
                owner_user_id,
                u_enabled,
                u_role,
                u_ru,
                u_au_json,
                u_rm,
                u_am_json,
            ) = row.map_err(db_err)?;

            // When owned by a user, enforce user-level enabled/provider/model restrictions.
            let (enabled, ru, au_json, rm, am_json) = if let Some(ue) = u_enabled {
                let is_admin = u_role.as_deref() == Some("admin");
                if is_admin {
                    (key_enabled && ue != 0, false, "[]".to_string(), false, "[]".to_string())
                } else {
                    (
                        key_enabled && ue != 0,
                        u_ru.unwrap_or(0) != 0,
                        u_au_json.unwrap_or_else(|| "[]".to_string()),
                        u_rm.unwrap_or(0) != 0,
                        u_am_json.unwrap_or_else(|| "[]".to_string()),
                    )
                }
            } else {
                (key_enabled, k_ru, k_au_json, k_rm, k_am_json)
            };

            let allowed_upstreams: Vec<String> =
                serde_json::from_str(&au_json).unwrap_or_default();
            let allowed_models: Vec<String> = serde_json::from_str(&am_json).unwrap_or_default();
            out.push(ClientKeyConfig {
                key,
                name,
                enabled,
                restrict_upstreams: ru,
                allowed_upstreams,
                restrict_models: rm,
                allowed_models,
                owner_user_id,
            });
        }
        Ok(out)
    }

    pub fn upsert_client_key(&self, item: &ClientKeyConfig) -> Result<(), GatewayError> {
        self.upsert_client_key_with_owner(item, None)
    }

    pub fn upsert_client_key_with_owner(
        &self,
        item: &ClientKeyConfig,
        owner_user_id: Option<i64>,
    ) -> Result<(), GatewayError> {
        let au = serde_json::to_string(&item.allowed_upstreams).unwrap_or_else(|_| "[]".into());
        let am = serde_json::to_string(&item.allowed_models).unwrap_or_else(|_| "[]".into());
        let now = now_secs() as i64;

        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO client_keys
               (key, name, enabled, restrict_upstreams, allowed_upstreams, restrict_models, allowed_models, owner_user_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
             ON CONFLICT(key) DO UPDATE SET
               name = excluded.name,
               enabled = excluded.enabled,
               restrict_upstreams = excluded.restrict_upstreams,
               allowed_upstreams = excluded.allowed_upstreams,
               restrict_models = excluded.restrict_models,
               allowed_models = excluded.allowed_models,
               owner_user_id = COALESCE(client_keys.owner_user_id, excluded.owner_user_id),
               updated_at = excluded.updated_at",
            params![
                item.key,
                item.name,
                i64::from(item.enabled),
                i64::from(item.restrict_upstreams),
                au,
                i64::from(item.restrict_models),
                am,
                owner_user_id,
                now
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn list_client_keys_with_owner(&self) -> Result<Vec<OwnedClientKey>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT ck.key, ck.name, ck.enabled, ck.restrict_upstreams, ck.allowed_upstreams,
                        ck.restrict_models, ck.allowed_models, ck.owner_user_id, u.username
                 FROM client_keys ck
                 LEFT JOIN users u ON u.id = ck.owner_user_id
                 ORDER BY ck.created_at ASC, ck.key ASC",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, i64>(3)? != 0,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)? != 0,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            let (key, name, enabled, ru, au_json, rm, am_json, owner_id, owner_name) =
                row.map_err(db_err)?;
            let allowed_upstreams: Vec<String> =
                serde_json::from_str(&au_json).unwrap_or_default();
            let allowed_models: Vec<String> = serde_json::from_str(&am_json).unwrap_or_default();
            out.push((
                ClientKeyConfig {
                    key,
                    name,
                    enabled,
                    restrict_upstreams: ru,
                    allowed_upstreams,
                    restrict_models: rm,
                    allowed_models,
                    owner_user_id: owner_id,
                },
                owner_id,
                owner_name,
            ));
        }
        Ok(out)
    }

    pub fn get_client_key_owner(&self, key: &str) -> Result<Option<i64>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let res = conn
            .query_row(
                "SELECT owner_user_id FROM client_keys WHERE key = ?1",
                params![key],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(db_err)?;
        Ok(res.flatten())
    }

    pub fn delete_client_key(&self, key: &str) -> Result<bool, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let affected = conn
            .execute("DELETE FROM client_keys WHERE key = ?1", params![key])
            .map_err(db_err)?;
        Ok(affected > 0)
    }

    // =========================================================================
    // Request Logs (async Tap worker persistence)
    // =========================================================================

    pub fn insert_request_log(&self, entry: &RequestLogEntry) -> Result<(), GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.execute(
            "INSERT OR REPLACE INTO request_logs
               (req_id, user_id, timestamp_secs, upstream, model, path, status, ttft_ms, duration_ms,
                total_bytes, input_tokens, output_tokens, total_tokens, cache_read_tokens,
                cache_write_tokens, username, is_stream, ttft_measured)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                entry.req_id,
                entry.user_id,
                entry.timestamp_secs as i64,
                entry.upstream,
                entry.model,
                entry.path,
                i64::from(entry.status),
                entry.ttft_ms as i64,
                entry.duration_ms as i64,
                entry.total_bytes as i64,
                entry.input_tokens as i64,
                entry.output_tokens as i64,
                entry.total_tokens as i64,
                entry.cache_read_tokens as i64,
                entry.cache_write_tokens as i64,
                entry.username,
                entry.is_stream,
                entry.ttft_measured,
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn load_recent_logs(&self, limit: usize) -> Result<Vec<RequestLogEntry>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT req_id, user_id, timestamp_secs, upstream, model, path, status, ttft_ms,
                        duration_ms, total_bytes, input_tokens, output_tokens, total_tokens,
                        cache_read_tokens, cache_write_tokens, COALESCE(log.username, users.username),
                        is_stream, ttft_measured
                 FROM request_logs AS log
                 LEFT JOIN users ON users.id = log.user_id
                 ORDER BY log.id DESC
                 LIMIT ?1",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![limit as i64], read_request_log)
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db_err)?);
        }
        Ok(out)
    }

    pub fn load_recent_logs_for_user(
        &self,
        user_id: i64,
        limit: usize,
    ) -> Result<Vec<RequestLogEntry>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT req_id, user_id, timestamp_secs, upstream, model, path, status, ttft_ms,
                        duration_ms, total_bytes, input_tokens, output_tokens, total_tokens,
                        cache_read_tokens, cache_write_tokens, COALESCE(log.username, users.username),
                        is_stream, ttft_measured
                 FROM request_logs AS log
                 LEFT JOIN users ON users.id = log.user_id
                 WHERE log.user_id = ?1
                 ORDER BY log.id DESC
                 LIMIT ?2",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![user_id, limit as i64], read_request_log)
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db_err)?);
        }
        Ok(out)
    }

    // =========================================================================
    // Settings (key-value store in SQLite)
    // =========================================================================

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(db_err)
    }

    pub fn set_setting(&self, key: &str, value: Option<&str>) -> Result<(), GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        match value {
            Some(v) if !v.is_empty() => {
                conn.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    params![key, v, now_secs() as i64],
                )
                .map_err(db_err)?;
            }
            _ => {
                conn.execute("DELETE FROM settings WHERE key = ?1", params![key])
                    .map_err(db_err)?;
            }
        }
        Ok(())
    }

    // =========================================================================
    // Users (multi-user RBAC: 'admin' | 'user')
    // =========================================================================

    pub fn count_users(&self) -> Result<usize, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let cnt: i64 = conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(db_err)?;
        Ok(cnt.max(0) as usize)
    }

    pub fn count_enabled_admins(&self) -> Result<usize, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        Ok(cnt.max(0) as usize)
    }

    pub fn list_users(&self) -> Result<Vec<(UserRecord, usize)>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare(
                "SELECT u.id, u.username, u.password_hash, u.role, u.enabled, u.allow_private_upstreams,
                        u.restrict_upstreams, u.allowed_upstreams, u.restrict_models, u.allowed_models,
                        u.created_at, u.updated_at,
                        (SELECT COUNT(*) FROM client_keys ck WHERE ck.owner_user_id = u.id) AS key_cnt
                 FROM users u
                 ORDER BY u.id ASC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |row| {
                let au_json: String = row.get(7)?;
                let am_json: String = row.get(9)?;
                Ok((
                    UserRecord {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        role: row.get(3)?,
                        enabled: row.get::<_, i64>(4)? != 0,
                        allow_private_upstreams: row.get::<_, i64>(5)? != 0,
                        restrict_upstreams: row.get::<_, i64>(6)? != 0,
                        allowed_upstreams: serde_json::from_str(&au_json).unwrap_or_default(),
                        restrict_models: row.get::<_, i64>(8)? != 0,
                        allowed_models: serde_json::from_str(&am_json).unwrap_or_default(),
                        created_at: row.get::<_, i64>(10)? as u64,
                        updated_at: row.get::<_, i64>(11)? as u64,
                    },
                    row.get::<_, i64>(12)?.max(0) as usize,
                ))
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(db_err)?);
        }
        Ok(out)
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<UserRecord>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.query_row(
            "SELECT id, username, password_hash, role, enabled, allow_private_upstreams,
                    restrict_upstreams, allowed_upstreams, restrict_models, allowed_models,
                    created_at, updated_at
             FROM users WHERE username = ?1",
            params![username],
            |row| {
                let au_json: String = row.get(7)?;
                let am_json: String = row.get(9)?;
                Ok(UserRecord {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    role: row.get(3)?,
                    enabled: row.get::<_, i64>(4)? != 0,
                    allow_private_upstreams: row.get::<_, i64>(5)? != 0,
                    restrict_upstreams: row.get::<_, i64>(6)? != 0,
                    allowed_upstreams: serde_json::from_str(&au_json).unwrap_or_default(),
                    restrict_models: row.get::<_, i64>(8)? != 0,
                    allowed_models: serde_json::from_str(&am_json).unwrap_or_default(),
                    created_at: row.get::<_, i64>(10)? as u64,
                    updated_at: row.get::<_, i64>(11)? as u64,
                })
            },
        )
        .optional()
        .map_err(db_err)
    }

    pub fn get_user_by_id(&self, id: i64) -> Result<Option<UserRecord>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.query_row(
            "SELECT id, username, password_hash, role, enabled, allow_private_upstreams,
                    restrict_upstreams, allowed_upstreams, restrict_models, allowed_models,
                    created_at, updated_at
             FROM users WHERE id = ?1",
            params![id],
            |row| {
                let au_json: String = row.get(7)?;
                let am_json: String = row.get(9)?;
                Ok(UserRecord {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    role: row.get(3)?,
                    enabled: row.get::<_, i64>(4)? != 0,
                    allow_private_upstreams: row.get::<_, i64>(5)? != 0,
                    restrict_upstreams: row.get::<_, i64>(6)? != 0,
                    allowed_upstreams: serde_json::from_str(&au_json).unwrap_or_default(),
                    restrict_models: row.get::<_, i64>(8)? != 0,
                    allowed_models: serde_json::from_str(&am_json).unwrap_or_default(),
                    created_at: row.get::<_, i64>(10)? as u64,
                    updated_at: row.get::<_, i64>(11)? as u64,
                })
            },
        )
        .optional()
        .map_err(db_err)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_user(
        &self,
        username: &str,
        password_hash: &str,
        role: &str,
        enabled: bool,
        allow_private_upstreams: bool,
        restrict_upstreams: bool,
        allowed_upstreams: &[String],
        restrict_models: bool,
        allowed_models: &[String],
    ) -> Result<UserRecord, GatewayError> {
        let now = now_secs() as i64;
        let au = serde_json::to_string(allowed_upstreams).unwrap_or_else(|_| "[]".into());
        let am = serde_json::to_string(allowed_models).unwrap_or_else(|_| "[]".into());
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO users
               (username, password_hash, role, enabled, allow_private_upstreams,
                restrict_upstreams, allowed_upstreams, restrict_models, allowed_models,
                created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                username,
                password_hash,
                role,
                i64::from(enabled),
                i64::from(allow_private_upstreams),
                i64::from(restrict_upstreams),
                au,
                i64::from(restrict_models),
                am,
                now
            ],
        )
        .map_err(db_err)?;
        let id = conn.last_insert_rowid();
        Ok(UserRecord {
            id,
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            role: role.to_string(),
            enabled,
            allow_private_upstreams,
            restrict_upstreams,
            allowed_upstreams: allowed_upstreams.to_vec(),
            restrict_models,
            allowed_models: allowed_models.to_vec(),
            created_at: now as u64,
            updated_at: now as u64,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_user(
        &self,
        id: i64,
        role: &str,
        enabled: bool,
        allow_private_upstreams: bool,
        restrict_upstreams: bool,
        allowed_upstreams: &[String],
        restrict_models: bool,
        allowed_models: &[String],
        new_password_hash: Option<&str>,
    ) -> Result<bool, GatewayError> {
        let now = now_secs() as i64;
        let au = serde_json::to_string(allowed_upstreams).unwrap_or_else(|_| "[]".into());
        let am = serde_json::to_string(allowed_models).unwrap_or_else(|_| "[]".into());
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let affected = if let Some(hash) = new_password_hash {
            conn.execute(
                "UPDATE users
                 SET role = ?1, enabled = ?2, allow_private_upstreams = ?3,
                     restrict_upstreams = ?4, allowed_upstreams = ?5,
                     restrict_models = ?6, allowed_models = ?7,
                     password_hash = ?8, updated_at = ?9
                 WHERE id = ?10",
                params![
                    role,
                    i64::from(enabled),
                    i64::from(allow_private_upstreams),
                    i64::from(restrict_upstreams),
                    au,
                    i64::from(restrict_models),
                    am,
                    hash,
                    now,
                    id
                ],
            )
            .map_err(db_err)?
        } else {
            conn.execute(
                "UPDATE users
                 SET role = ?1, enabled = ?2, allow_private_upstreams = ?3,
                     restrict_upstreams = ?4, allowed_upstreams = ?5,
                     restrict_models = ?6, allowed_models = ?7,
                     updated_at = ?8
                 WHERE id = ?9",
                params![
                    role,
                    i64::from(enabled),
                    i64::from(allow_private_upstreams),
                    i64::from(restrict_upstreams),
                    au,
                    i64::from(restrict_models),
                    am,
                    now,
                    id
                ],
            )
            .map_err(db_err)?
        };
        Ok(affected > 0)
    }

    pub fn update_user_password(&self, id: i64, new_password_hash: &str) -> Result<bool, GatewayError> {
        let now = now_secs() as i64;
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let affected = conn
            .execute(
                "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                params![new_password_hash, now, id],
            )
            .map_err(db_err)?;
        Ok(affected > 0)
    }

    pub fn delete_user(&self, id: i64) -> Result<bool, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let _ = conn.execute(
            "DELETE FROM client_keys WHERE owner_user_id = ?1",
            params![id],
        );
        let affected = conn
            .execute("DELETE FROM users WHERE id = ?1", params![id])
            .map_err(db_err)?;
        Ok(affected > 0)
    }

    pub fn upsert_quota_snapshot(&self, snap: &QuotaSnapshot) -> Result<(), GatewayError> {
        let json = serde_json::to_string(snap)
            .map_err(|e| GatewayError::Internal(format!("failed to encode quota snapshot: {e}")))?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO quota_snapshots (upstream, payload_json, fetched_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(upstream) DO UPDATE SET
               payload_json = excluded.payload_json,
               fetched_at = excluded.fetched_at",
            params![snap.upstream, json, snap.fetched_at],
        )
        .map_err(db_err)?;
        Ok(())
    }

    pub fn list_quota_snapshots(&self) -> Result<HashMap<String, QuotaSnapshot>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare("SELECT upstream, payload_json FROM quota_snapshots")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(db_err)?;
        let mut map = HashMap::new();
        for row in rows {
            let (name, json) = row.map_err(db_err)?;
            if let Ok(snap) = serde_json::from_str::<QuotaSnapshot>(&json) {
                map.insert(name, snap);
            }
        }
        Ok(map)
    }

    pub fn delete_quota_snapshot(&self, upstream: &str) -> Result<(), GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.execute(
            "DELETE FROM quota_snapshots WHERE upstream = ?1",
            params![upstream],
        )
        .map_err(db_err)?;
        Ok(())
    }
}

/// Implement `ttt_auth::TokenStore` directly on SQLite (`oauth_tokens` table, AES-256-GCM encrypted).
impl TokenStore for GatewayDb {
    fn get(&self, account_id: &str) -> Result<Option<StoredOAuthToken>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let row: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT nonce, ciphertext FROM oauth_tokens WHERE account_id = ?1",
                params![account_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;

        match row {
            Some((nonce, ct)) => {
                let plain = decrypt_bytes(&self.master_key, &nonce, &ct)?;
                let tok: StoredOAuthToken = serde_json::from_slice(&plain).map_err(|e| {
                    GatewayError::Auth(format!("corrupted oauth token in SQLite: {e}"))
                })?;
                Ok(Some(tok))
            }
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<HashMap<String, StoredOAuthToken>, GatewayError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        let mut stmt = conn
            .prepare("SELECT account_id, nonce, ciphertext FROM oauth_tokens")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(db_err)?;

        let mut map = HashMap::new();
        for row in rows {
            let (acct, nonce, ct) = row.map_err(db_err)?;
            let plain = decrypt_bytes(&self.master_key, &nonce, &ct)?;
            let tok: StoredOAuthToken = serde_json::from_slice(&plain).map_err(|e| {
                GatewayError::Auth(format!("corrupted oauth token in SQLite: {e}"))
            })?;
            map.insert(acct, tok);
        }
        Ok(map)
    }

    fn put(&self, account_id: &str, token: StoredOAuthToken) -> Result<(), GatewayError> {
        let plain = serde_json::to_vec(&token)
            .map_err(|e| GatewayError::Internal(format!("failed to encode oauth token: {e}")))?;
        let (nonce, ct) = encrypt_bytes(&self.master_key, &plain)?;
        let now = now_secs() as i64;

        let conn = self
            .conn
            .lock()
            .map_err(|_| GatewayError::Internal("db mutex poisoned".into()))?;
        conn.execute(
            "INSERT INTO oauth_tokens (account_id, nonce, ciphertext, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id) DO UPDATE SET
               nonce = excluded.nonce,
               ciphertext = excluded.ciphertext,
               updated_at = excluded.updated_at",
            params![account_id, nonce, ct, now],
        )
        .map_err(db_err)?;
        Ok(())
    }
}

fn init_schema(conn: &Connection) -> Result<(), GatewayError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;

         CREATE TABLE IF NOT EXISTS upstreams (
             name TEXT PRIMARY KEY,
             nonce BLOB NOT NULL,
             ciphertext BLOB NOT NULL,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS proxies (
             name TEXT PRIMARY KEY,
             nonce BLOB NOT NULL,
             ciphertext BLOB NOT NULL,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS oauth_tokens (
             account_id TEXT PRIMARY KEY,
             nonce BLOB NOT NULL,
             ciphertext BLOB NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS settings (
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS users (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT NOT NULL UNIQUE,
             password_hash TEXT NOT NULL,
             role TEXT NOT NULL DEFAULT 'user',
             enabled INTEGER NOT NULL DEFAULT 1,
             allow_private_upstreams INTEGER NOT NULL DEFAULT 1,
             restrict_upstreams INTEGER NOT NULL DEFAULT 0,
             allowed_upstreams TEXT NOT NULL DEFAULT '[]',
             restrict_models INTEGER NOT NULL DEFAULT 0,
             allowed_models TEXT NOT NULL DEFAULT '[]',
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS client_keys (
             key TEXT PRIMARY KEY,
             name TEXT NOT NULL DEFAULT '',
             enabled INTEGER NOT NULL DEFAULT 1,
             restrict_upstreams INTEGER NOT NULL DEFAULT 0,
             allowed_upstreams TEXT NOT NULL DEFAULT '[]',
             restrict_models INTEGER NOT NULL DEFAULT 0,
             allowed_models TEXT NOT NULL DEFAULT '[]',
             owner_user_id INTEGER,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );

         CREATE TABLE IF NOT EXISTS request_logs (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             req_id TEXT NOT NULL,
             user_id INTEGER,
             timestamp_secs INTEGER NOT NULL,
             upstream TEXT NOT NULL,
             model TEXT,
             path TEXT NOT NULL,
             status INTEGER NOT NULL,
             ttft_ms INTEGER NOT NULL,
             ttft_measured INTEGER NOT NULL DEFAULT 0,
             duration_ms INTEGER NOT NULL,
             total_bytes INTEGER NOT NULL,
             input_tokens INTEGER NOT NULL,
             output_tokens INTEGER NOT NULL,
             total_tokens INTEGER NOT NULL,
             cache_read_tokens INTEGER NOT NULL DEFAULT 0,
             cache_write_tokens INTEGER NOT NULL DEFAULT 0,
             username TEXT,
             is_stream INTEGER
         );

         CREATE TABLE IF NOT EXISTS quota_snapshots (
             upstream TEXT PRIMARY KEY,
             payload_json TEXT NOT NULL,
             fetched_at INTEGER NOT NULL
         );",
    )
    .map_err(db_err)?;

    // Idempotent migrations for existing databases.
    let _ = conn.execute("ALTER TABLE client_keys ADD COLUMN owner_user_id INTEGER", []);
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN allow_private_upstreams INTEGER NOT NULL DEFAULT 1",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN restrict_upstreams INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN allowed_upstreams TEXT NOT NULL DEFAULT '[]'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN restrict_models INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN allowed_models TEXT NOT NULL DEFAULT '[]'",
        [],
    );
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN user_id INTEGER", []);
    let _ = conn.execute(
        "ALTER TABLE request_logs ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE request_logs ADD COLUMN cache_write_tokens INTEGER NOT NULL DEFAULT 0",
        [],
    );
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN username TEXT", []);
    let _ = conn.execute("ALTER TABLE request_logs ADD COLUMN is_stream INTEGER", []);
    if let Err(err) = conn.execute(
        "ALTER TABLE request_logs ADD COLUMN ttft_measured INTEGER NOT NULL DEFAULT 0",
        [],
    ) && conn.prepare("SELECT ttft_measured FROM request_logs LIMIT 0").is_err()
    {
        return Err(db_err(err));
    }
    Ok(())
}

fn read_request_log(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestLogEntry> {
    let ttft_measured = row.get(17)?;
    Ok(RequestLogEntry {
        req_id: row.get(0)?,
        user_id: row.get(1)?,
        timestamp_secs: row.get::<_, i64>(2)? as u64,
        upstream: row.get(3)?,
        model: row.get(4)?,
        path: row.get(5)?,
        status: row.get::<_, i64>(6)? as u16,
        ttft_ms: if ttft_measured { row.get::<_, i64>(7)? as u64 } else { 0 },
        ttft_measured,
        duration_ms: row.get::<_, i64>(8)? as u64,
        total_bytes: row.get::<_, i64>(9)? as u64,
        input_tokens: row.get::<_, i64>(10)? as u64,
        output_tokens: row.get::<_, i64>(11)? as u64,
        total_tokens: row.get::<_, i64>(12)? as u64,
        cache_read_tokens: row.get::<_, i64>(13)? as u64,
        cache_write_tokens: row.get::<_, i64>(14)? as u64,
        username: row.get(15)?,
        is_stream: row.get(16)?,
    })
}

fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), GatewayError> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| GatewayError::Internal("AES-256-GCM encryption failed".into()))?;
    Ok((nonce_bytes.to_vec(), ct))
}

fn decrypt_bytes(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, GatewayError> {
    if nonce.len() != 12 {
        return Err(GatewayError::Internal("invalid AES-GCM nonce length".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            GatewayError::Config(
                "failed to decrypt upstream record from SQLite (check master key)".into(),
            )
        })
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
            .map_err(|e| GatewayError::Config(format!("failed to read master key file: {e}")))?;
        return decode_32_byte_key(raw.trim(), &key_path.display().to_string());
    }

    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    if let Some(parent) = key_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|e| GatewayError::Config(format!("failed to create key dir: {e}")))?;
    }
    fs::write(&key_path, BASE64.encode(key))
        .map_err(|e| GatewayError::Config(format!("failed to write master key file: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
    }
    Ok(key)
}

fn decode_32_byte_key(b64: &str, source: &str) -> Result<[u8; 32], GatewayError> {
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| GatewayError::Config(format!("invalid base64 master key in {source}: {e}")))?;
    if bytes.len() != 32 {
        return Err(GatewayError::Config(format!(
            "master key in {source} must decode to 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn db_err(e: rusqlite::Error) -> GatewayError {
    GatewayError::Internal(format!("SQLite error: {e}"))
}

#[inline]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use ttt_core::{ProtocolFamily, UpstreamAuthConfig};

    #[test]
    fn sqlite_crud_for_encrypted_upstreams_keys_and_logs() {
        let db = GatewayDb::open_in_memory([11u8; 32]).unwrap();

        let up = UpstreamConfig {
            name: "deepseek".into(),
            base_url: "https://api.deepseek.com/v1".into(),
            protocol: ProtocolFamily::OpenAi,
            protocol_endpoints: HashMap::new(),
            auth: UpstreamAuthConfig::ApiKey {
                keys: vec!["sk-secret-1".into()],
                header_name: "authorization".into(),
                prefix: Some("Bearer ".into()),
            },
            models: vec!["deepseek-chat".into()],
            model_mapping: HashMap::new(),
            extra_headers: HashMap::new(),
            protocol_headers: HashMap::new(),
            weight: 1,
            default_cooldown_secs: 30,
            max_retries: 1,
            owner_user_id: None,
            proxy: None,
            quota: None,
            session_header_out: None,
            strip_other_session_headers: false,
            prompt_cache_mode: Default::default(),
        };
        db.upsert_upstream(&up).unwrap();
        let list = db.list_upstreams().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "deepseek");
        assert!(db.delete_upstream("deepseek").unwrap());
        assert!(db.list_upstreams().unwrap().is_empty());

        let key = ClientKeyConfig {
            key: "sk-ttt-1".into(),
            name: "prod".into(),
            enabled: true,
            restrict_upstreams: true,
            allowed_upstreams: vec!["deepseek".into()],
            restrict_models: true,
            allowed_models: vec!["deepseek-chat".into()],
            owner_user_id: None,
        };
        db.upsert_client_key(&key).unwrap();
        let keys = db.list_client_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].allowed_models, vec!["deepseek-chat"]);
        assert!(db.delete_client_key("sk-ttt-1").unwrap());

        // Verify encrypted OAuth TokenStore on SQLite
        TokenStore::put(
            &db,
            "codex-main",
            StoredOAuthToken {
                access_token: "at-123".into(),
                refresh_token: Some("rt-456".into()),
                expires_at: Some(2_000_000_000),
                token_type: Some("Bearer".into()),
                scope: None,
                extra: HashMap::new(),
            },
        )
        .unwrap();
        let tok = TokenStore::get(&db, "codex-main").unwrap().unwrap();
        assert_eq!(tok.access_token, "at-123");
        assert_eq!(tok.refresh_token.as_deref(), Some("rt-456"));

        // Verify SQLite settings table
        db.set_setting("admin_api_key", Some("secret-admin")).unwrap();
        assert_eq!(
            db.get_setting("admin_api_key").unwrap().as_deref(),
            Some("secret-admin")
        );

        // Verify request log persistence
        db.insert_request_log(&RequestLogEntry {
            req_id: "req-cache-1".into(),
            user_id: Some(7),
            username: Some("alice".into()),
            timestamp_secs: 1_700_000_000,
            upstream: "deepseek".into(),
            model: Some("deepseek-chat".into()),
            path: "/v1/chat/completions".into(),
            status: 200,
            is_stream: Some(true),
            ttft_ms: 95,
            ttft_measured: true,
            duration_ms: 420,
            total_bytes: 512,
            input_tokens: 10_000,
            output_tokens: 200,
            total_tokens: 10_200,
            cache_read_tokens: 8_000,
            cache_write_tokens: 500,
        })
        .unwrap();
        let logs = db.load_recent_logs_for_user(7, 10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].username.as_deref(), Some("alice"));
        assert_eq!(logs[0].is_stream, Some(true));
        assert_eq!(logs[0].ttft_ms, 95);
        assert!(logs[0].ttft_measured);
        assert_eq!(logs[0].cache_read_tokens, 8_000);
        assert_eq!(logs[0].cache_write_tokens, 500);
        assert!(db.load_recent_logs_for_user(8, 10).unwrap().is_empty());
    }

    #[test]
    fn migrates_legacy_request_logs_without_mixing_ttft_measurements() {
        let db = GatewayDb::open_in_memory([11u8; 32]).unwrap();
        let user = db
            .create_user("alice", "hash", "user", true, true, false, &[], false, &[])
            .unwrap();
        {
            let conn = db.conn.lock().unwrap();
            conn.execute_batch(
                "ALTER TABLE request_logs DROP COLUMN username;
                 ALTER TABLE request_logs DROP COLUMN is_stream;
                 ALTER TABLE request_logs DROP COLUMN ttft_measured;",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO request_logs
                   (req_id, user_id, timestamp_secs, upstream, path, status, ttft_ms, duration_ms,
                    total_bytes, input_tokens, output_tokens, total_tokens)
                 VALUES ('req-legacy', ?1, 0, 'upstream', '/v1/messages', 200, 123, 0, 0, 0, 0, 0)",
                [user.id],
            )
            .unwrap();
            init_schema(&conn).unwrap();
        }

        let logs = db.load_recent_logs(10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].user_id, Some(user.id));
        assert_eq!(logs[0].username.as_deref(), Some("alice"));
        assert_eq!(logs[0].is_stream, None);
        assert!(!logs[0].ttft_measured);
    }
}
