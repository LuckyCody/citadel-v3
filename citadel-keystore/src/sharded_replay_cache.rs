// P006: Sharded replay cache for 256x parallelism
// This file provides the sharded implementation that can replace single-mutex replay cache

use crate::replay_store::{ReplayError, ReplayStore};
use std::sync::Mutex;
use std::time::Duration;

const SHARD_COUNT: usize = 256;

/// P006: Sharded replay cache for high-concurrency decrypt operations.
///
/// Replaces single `Mutex<Box<dyn ReplayStore>>` with 256 independent shards.
/// Each shard is locked independently, allowing 256 concurrent decrypt operations
/// on different ciphertexts without contention.
///
/// Replay protection atomicity is maintained within each shard - concurrent requests
/// for the SAME ciphertext still serialize (correct behavior), but requests for
/// DIFFERENT ciphertexts can proceed in parallel.
pub struct ShardedReplayCache {
    shards: Vec<Mutex<Box<dyn ReplayStore>>>,
}

impl ShardedReplayCache {
    /// Create sharded cache from a template replay store.
    ///
    /// For MemoryReplayStore: creates 256 independent in-memory stores
    /// For RedisReplayStore: creates 256 connections (Redis handles sharding)
    /// For FileReplayStore: NOT RECOMMENDED (256 files on disk)
    pub fn new<F>(store_factory: F) -> Result<Self, ReplayError>
    where
        F: Fn() -> Result<Box<dyn ReplayStore>, ReplayError>,
    {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(store_factory()?));
        }
        Ok(Self { shards })
    }

    /// Get shard index for a given replay key.
    ///
    /// Uses first byte of key for sharding (keys are SHA-256 hashes, uniform distribution).
    fn shard_index(&self, key: &[u8]) -> usize {
        if key.is_empty() {
            0
        } else {
            key[0] as usize
        }
    }

    /// Get the shard for a given key.
    fn get_shard(&self, key: &[u8]) -> &Mutex<Box<dyn ReplayStore>> {
        &self.shards[self.shard_index(key)]
    }

    /// Claim a replay slot (same semantics as ReplayStore::claim).
    pub fn claim(&self, key: &[u8], ttl: Duration) -> Result<bool, ReplayError> {
        let shard = self.get_shard(key);
        let cache = shard
            .lock()
            .map_err(|e| ReplayError::new(format!("shard lock poisoned: {}", e)))?;
        cache.claim(key, ttl)
    }

    /// Release a replay slot (same semantics as ReplayStore::release).
    pub fn release(&self, key: &[u8]) -> Result<(), ReplayError> {
        let shard = self.get_shard(key);
        let cache = shard
            .lock()
            .map_err(|e| ReplayError::new(format!("shard lock poisoned: {}", e)))?;
        cache.release(key)
    }

    /// Get total entry count across all shards.
    pub fn total_entry_count(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|shard| shard.lock().ok())
            .map(|cache| cache.entry_count())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay_store::MemoryReplayStore;

    #[test]
    fn test_sharding_distribution() {
        let cache =
            ShardedReplayCache::new(|| Ok(Box::new(MemoryReplayStore::with_defaults()))).unwrap();

        // Different keys should go to different shards
        let key1 = vec![0u8; 32];
        let key2 = vec![128u8; 32];

        assert_eq!(cache.shard_index(&key1), 0);
        assert_eq!(cache.shard_index(&key2), 128);
    }

    #[test]
    fn test_replay_detection_across_shards() {
        let cache =
            ShardedReplayCache::new(|| Ok(Box::new(MemoryReplayStore::with_defaults()))).unwrap();

        let key = vec![42u8; 32];
        let ttl = Duration::from_secs(3600);

        // First claim succeeds
        assert_eq!(cache.claim(&key, ttl).unwrap(), true);

        // Second claim fails (replay detected)
        assert_eq!(cache.claim(&key, ttl).unwrap(), false);
    }
}
