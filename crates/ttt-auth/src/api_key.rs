use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{HeaderName, HeaderValue};
use ttt_core::GatewayError;

use crate::Credential;

struct KeySlot {
    /// Pre-formatted header value (e.g., "Bearer sk-...") for O(1) zero-alloc cloning on hot path.
    header_value: HeaderValue,
    /// Epoch milliseconds until which this key is cooled down (0 = active).
    cooldown_until_ms: AtomicU64,
}

/// Lock-free round-robin API Key pool with per-key cooldown support.
pub struct ApiKeyPool {
    header_name: HeaderName,
    slots: Vec<KeySlot>,
    cursor: AtomicUsize,
}

impl ApiKeyPool {
    pub fn new(
        header_name: &str,
        prefix: Option<&str>,
        keys: &[String],
    ) -> Result<Self, GatewayError> {
        if keys.is_empty() {
            return Err(GatewayError::Auth("api key pool cannot be empty".into()));
        }

        let header_name = HeaderName::from_bytes(header_name.as_bytes()).map_err(|e| {
            GatewayError::Config(format!("invalid auth header name '{header_name}': {e}"))
        })?;

        let mut slots = Vec::with_capacity(keys.len());
        for raw_key in keys {
            let formatted = match prefix {
                Some(p) => format!("{p}{raw_key}"),
                None => raw_key.clone(),
            };
            let mut hv = HeaderValue::from_str(&formatted).map_err(|e| {
                GatewayError::Config(format!("invalid characters in API key header value: {e}"))
            })?;
            hv.set_sensitive(true);
            slots.push(KeySlot {
                header_value: hv,
                cooldown_until_ms: AtomicU64::new(0),
            });
        }

        Ok(Self {
            header_name,
            slots,
            cursor: AtomicUsize::new(0),
        })
    }

    /// Pick the next active API key in lock-free round-robin order.
    /// Returns `(slot_index, Credential)`.
    #[inline]
    pub fn acquire(&self) -> (usize, Credential) {
        self.acquire_with_affinity(None)
    }

    /// Pick an active API key slot, deterministically pinned when `affinity_hash` is provided,
    /// or in lock-free round-robin order when `None`.
    #[inline]
    pub fn acquire_with_affinity(&self, affinity_hash: Option<u64>) -> (usize, Credential) {
        let len = self.slots.len();
        let start = match affinity_hash {
            Some(h) if len > 1 => (mix64(h) as usize) % len,
            Some(_) => 0,
            None => self.cursor.fetch_add(1, Ordering::Relaxed) % len,
        };
        let now = now_epoch_ms();

        // Try to find a key that is not in cooldown.
        for offset in 0..len {
            let idx = (start + offset) % len;
            let slot = &self.slots[idx];
            let until = slot.cooldown_until_ms.load(Ordering::Relaxed);
            if until == 0 || now >= until {
                return (
                    idx,
                    Credential {
                        header_name: self.header_name.clone(),
                        header_value: slot.header_value.clone(),
                    },
                );
            }
        }

        // All keys are cooling down: fall back to the starting slot
        // rather than failing immediately.
        let slot = &self.slots[start];
        (
            start,
            Credential {
                header_name: self.header_name.clone(),
                header_value: slot.header_value.clone(),
            },
        )
    }

    /// Put a specific key slot into cooldown (e.g., on upstream 429).
    pub fn mark_cooldown(&self, slot_idx: usize, cooldown_secs: u64) {
        if let Some(slot) = self.slots.get(slot_idx) {
            let until = now_epoch_ms().saturating_add(cooldown_secs.saturating_mul(1000));
            slot.cooldown_until_ms.store(until, Ordering::Relaxed);
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[inline]
fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_and_cooldown() {
        let pool = ApiKeyPool::new(
            "authorization",
            Some("Bearer "),
            &["k1".to_string(), "k2".to_string()],
        )
        .unwrap();

        let (i1, c1) = pool.acquire();
        let (i2, c2) = pool.acquire();
        assert_eq!(i1, 0);
        assert_eq!(i2, 1);
        assert_eq!(c1.header_value.to_str().unwrap(), "Bearer k1");
        assert_eq!(c2.header_value.to_str().unwrap(), "Bearer k2");

        // Cooldown slot 0; next acquisitions should pick slot 1.
        pool.mark_cooldown(0, 60);
        let (i3, c3) = pool.acquire();
        assert_eq!(i3, 1);
        assert_eq!(c3.header_value.to_str().unwrap(), "Bearer k2");
    }

    #[test]
    fn affinity_pins_key_slot_and_recovers_after_cooldown() {
        let pool = ApiKeyPool::new(
            "authorization",
            Some("Bearer "),
            &[
                "k0".to_string(),
                "k1".to_string(),
                "k2".to_string(),
                "k3".to_string(),
            ],
        )
        .unwrap();

        let aff = Some(0x1234_5678_9abc_def0_u64);
        let (pinned_idx, pinned_cred) = pool.acquire_with_affinity(aff);
        for _ in 0..8 {
            let (idx, cred) = pool.acquire_with_affinity(aff);
            assert_eq!(idx, pinned_idx);
            assert_eq!(cred.header_value, pinned_cred.header_value);
        }

        // Cool down pinned slot -> falls back deterministically to another slot.
        pool.mark_cooldown(pinned_idx, 60);
        let (fallback_idx, _) = pool.acquire_with_affinity(aff);
        assert_ne!(fallback_idx, pinned_idx);

        // Recover pinned slot -> returns to original pinned slot.
        pool.slots[pinned_idx].cooldown_until_ms.store(0, Ordering::Relaxed);
        let (recovered_idx, _) = pool.acquire_with_affinity(aff);
        assert_eq!(recovered_idx, pinned_idx);
    }
}
