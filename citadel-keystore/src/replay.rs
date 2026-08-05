// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! # ⚠️ DEPRECATED MODULE (P397)
//!
//! This module contains the V2 replay cache types (`ReplayCacheBackend`,
//! `InMemoryReplayCache`, `FileReplayCache`). They are **deprecated** and will
//! be removed in 0.4.0.
//!
//! **Use instead:**
//! - `citadel_keystore::MemoryReplayStore` (was `InMemoryReplayCache`)
//! - `citadel_keystore::FileReplayStore` (was `FileReplayCache`)
//! - `citadel_keystore::ReplayStore` trait with `claim()`/`release()` semantics
//!
//! The V3 replay model (P319) provides atomic, fail-closed, anti-poisoning guarantees
//! that the V2 `seen()`/`mark_seen()` model could not provide.

//! # Deprecated replay cache module
//!
//! P379: This module contains the V2 replay cache types superseded by `ReplayStore::claim()/release()`.
//! Use `citadel_keystore::ReplayStore`, `MemoryReplayStore`, `FileReplayStore` instead.
//!
//! These types remain exported for backward compatibility but are marked `#[deprecated]`.

//! Replay cache backend (V2).
//!
//! Provides a pluggable `ReplayCacheBackend` trait so deployments can
//! choose between in-memory (default), file-backed (single-instance
//! persistence), or custom (Redis, database) backends.
//!
//! # Scope and limitations of all provided backends
//!
//! - **Cross-instance replays are NOT caught** regardless of backend.
//!   A multi-instance deployment needs a shared backend (Redis, DB).
//! - **`InMemoryReplayCache`**: replays across server restart are NOT caught.
//! - **`FileReplayCache`**: replays across restart ARE caught on the same
//!   instance, as long as the cache file is preserved. Cross-instance
//!   replays are still not caught.
//! - True distributed replay protection (V3) requires a shared store
//!   like Redis with TTL across all instances.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Pluggable backend for the nonce replay cache.
///
/// Implementors persist the set of seen composite cache keys
/// (key_id + key_version + AES-GCM nonce) within a rolling TTL window.
#[deprecated(since = "0.3.0", note = "Use ReplayStore::claim()/release() instead")]
pub trait ReplayCacheBackend: Send + Sync {
    /// Returns `true` if `key` was seen within the TTL window (replay detected).
    ///
    /// MUST also evict expired entries before checking, so that the in-memory
    /// footprint stays bounded. Does NOT insert — call `insert` after
    /// successful decryption.
    fn contains(&mut self, key: &[u8]) -> bool;

    /// Record a successfully-decrypted nonce. Call ONLY after decryption
    /// succeeds to prevent the poisoning attack where a corrupted ciphertext
    /// blocks the legitimate one.
    fn insert(&mut self, key: Vec<u8>);
}

// ---------------------------------------------------------------------------
// In-memory backend (default — same behaviour as V1 ReplayCache)
// ---------------------------------------------------------------------------

/// In-memory nonce replay cache. Suitable for single-process use.
///
/// # Limitations
///
/// - Lost on server restart (replays from before restart are NOT caught).
/// - Not shared across instances (per-instance memory only).
/// - Suitable for development, testing, and single-instance deployments
///   where restart-window replays are acceptable.
#[deprecated(
    since = "0.3.0",
    note = "Use FileReplayStore / MemoryReplayStore with claim()/release() instead"
)]
pub struct InMemoryReplayCache {
    seen: HashMap<Vec<u8>, Instant>,
    ttl: Duration,
}

#[allow(deprecated)]
impl InMemoryReplayCache {
    /// Create with the given TTL (typically 24 hours).
    pub fn new(ttl: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            ttl,
        }
    }

    fn evict_expired(&mut self) {
        let now = Instant::now();
        self.seen
            .retain(|_, seen_at| now.duration_since(*seen_at) < self.ttl);
    }
}

#[allow(deprecated)]
impl Default for InMemoryReplayCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(86400))
    }
}

#[allow(deprecated)]
impl ReplayCacheBackend for InMemoryReplayCache {
    fn contains(&mut self, key: &[u8]) -> bool {
        self.evict_expired();
        self.seen.contains_key(key)
    }

    fn insert(&mut self, key: Vec<u8>) {
        self.seen.insert(key, Instant::now());
    }
}

// ---------------------------------------------------------------------------
// File-backed backend (single-instance persistence)
// ---------------------------------------------------------------------------

/// On-disk entry for the file-backed cache.
#[derive(Serialize, Deserialize, Clone)]
struct CacheEntry {
    /// Hex-encoded composite cache key.
    key_hex: String,
    /// Unix timestamp (seconds) when this entry was inserted.
    seen_at_unix: u64,
}

/// File-backed nonce replay cache. Persists across server restarts.
///
/// Serializes the cache to a JSON file on every `insert()`. On construction,
/// loads the file and evicts entries that have exceeded the TTL.
///
/// # Performance note
///
/// Writes the entire cache to disk on every insert. This is correct and
/// simple but not optimal for high-throughput deployments. For > 1000
/// decryptions/second, use a Redis-backed backend (V3).
///
/// # Limitations
///
/// - Replays ACROSS instances are NOT caught (no shared state).
/// - If the cache file is deleted or corrupted, protection is lost for
///   nonces seen before the deletion (fail-open: returns false on parse error).
/// - SSD wear-leveling may preserve deleted nonce data (same caveat as
///   key material — forensic-grade deletion requires HSM or FDE).
#[deprecated(
    since = "0.3.0",
    note = "Use FileReplayStore / MemoryReplayStore with claim()/release() instead"
)]
pub struct FileReplayCache {
    path: PathBuf,
    ttl_secs: u64,
    /// In-memory mirror of the on-disk state, rebuilt on construction and
    /// updated on every insert. Avoids reading the file on every `contains` call.
    mirror: HashMap<Vec<u8>, u64>, // key → unix_timestamp
}

#[allow(deprecated)]
impl FileReplayCache {
    /// Create or load an existing file cache.
    ///
    /// If the file exists, loads it and evicts expired entries.
    /// If the file doesn't exist, starts with an empty cache.
    pub fn new(path: impl Into<PathBuf>, ttl: Duration) -> Self {
        let path = path.into();
        let ttl_secs = ttl.as_secs();
        let now_unix = unix_now();
        let cutoff = now_unix.saturating_sub(ttl_secs);

        let mut mirror: HashMap<Vec<u8>, u64> = HashMap::new();

        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(entries) = serde_json::from_str::<Vec<CacheEntry>>(&data) {
                    for entry in entries {
                        if entry.seen_at_unix >= cutoff {
                            if let Ok(k) = hex::decode(&entry.key_hex) {
                                mirror.insert(k, entry.seen_at_unix);
                            }
                        }
                    }
                }
                // Failed parse = start empty (fail-open — see doc comment)
            }
        }

        Self {
            path,
            ttl_secs,
            mirror,
        }
    }

    fn flush(&self) {
        let now_unix = unix_now();
        let cutoff = now_unix.saturating_sub(self.ttl_secs);

        let entries: Vec<CacheEntry> = self
            .mirror
            .iter()
            .filter(|(_, &ts)| ts >= cutoff)
            .map(|(k, &ts)| CacheEntry {
                key_hex: hex::encode(k),
                seen_at_unix: ts,
            })
            .collect();

        if let Ok(json) = serde_json::to_string(&entries) {
            // Best-effort write: if it fails, we lose this entry's persistence
            // but the in-memory mirror still catches replays in this process.
            let _ = std::fs::write(&self.path, json);
        }
    }

    fn evict_expired(&mut self) {
        let cutoff = unix_now().saturating_sub(self.ttl_secs);
        self.mirror.retain(|_, &mut ts| ts >= cutoff);
    }
}

#[allow(deprecated)]
impl ReplayCacheBackend for FileReplayCache {
    fn contains(&mut self, key: &[u8]) -> bool {
        self.evict_expired();
        self.mirror.contains_key(key)
    }

    fn insert(&mut self, key: Vec<u8>) {
        let now = unix_now();
        self.mirror.insert(key, now);
        self.flush();
    }
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
