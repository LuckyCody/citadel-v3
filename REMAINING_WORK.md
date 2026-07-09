# Remaining Issues - Implementation Guide

## P006 (MEDIUM): Sharded Replay Cache

**Status**: Architecture designed, ready for implementation  
**Complexity**: Medium  
**Risk**: Low (performance optimization)  
**Testing Required**: Extensive concurrency testing  

### Current Implementation
```rust
// citadel-keystore/src/keystore.rs:109
replay_cache: Mutex<Box<dyn ReplayStore>>
```

Single global lock serializes all concurrent decrypt operations.

### Proposed Implementation

```rust
// citadel-keystore/src/keystore.rs
const SHARD_COUNT: usize = 256;

pub struct ShardedReplayCache {
    shards: [Mutex<Box<dyn ReplayStore>>; SHARD_COUNT],
}

impl ShardedReplayCache {
    fn get_shard(&self, key: &[u8]) -> &Mutex<Box<dyn ReplayStore>> {
        let shard_index = key[0] as usize;
        &self.shards[shard_index]
    }
    
    pub fn claim(&self, key: &[u8], ttl: Duration) -> Result<bool, ReplayError> {
        let shard = self.get_shard(key);
        let cache = shard.lock().unwrap();
        cache.claim(key, ttl)
    }
    
    pub fn release(&self, key: &[u8]) -> Result<(), ReplayError> {
        let shard = self.get_shard(key);
        let cache = shard.lock().unwrap();
        cache.release(key)
    }
}
```

### Changes Required

1. **Replace Keystore.replay_cache**:
   ```rust
   // Old
   replay_cache: Mutex<Box<dyn ReplayStore>>
   
   // New
   replay_cache: ShardedReplayCache
   ```

2. **Update decrypt() calls**:
   ```rust
   // Old
   let cache = self.replay_cache.lock().unwrap();
   cache.claim(&cache_key, Duration::from_secs(86400))?;
   
   // New
   self.replay_cache.claim(&cache_key, Duration::from_secs(86400))?;
   ```

3. **Initialize shards**:
   ```rust
   // In Keystore::new()
   let replay_store = create_replay_store()?;
   let shards = std::array::from_fn(|_| {
       Mutex::new(Box::new(replay_store.clone()) as Box<dyn ReplayStore>)
   });
   ```

### Benefits
- 256x parallelism for independent keys
- Same atomicity guarantees within shard
- No changes to ReplayStore trait

### Testing Checklist
- [ ] Single-threaded correctness (all tests pass)
- [ ] Concurrent replay detection (parallel same-ciphertext decrypts)
- [ ] Cross-shard concurrency (parallel different-ciphertext decrypts)
- [ ] Lock contention measurement (confirm 256x improvement)
- [ ] Memory usage (256 stores vs 1)

---

## P007 (MEDIUM): Audit Log External Anchoring

**Status**: Integration points defined, awaiting external service choice  
**Complexity**: High  
**Risk**: Medium (requires external dependency)  
**Decision Required**: Which witness service to use  

### Current Implementation
```rust
// citadel-keystore/src/audit.rs
// Hash chain stored only locally - can be truncated
```

### Proposed Architecture

```rust
pub trait AuditWitness: Send + Sync {
    /// Publish hash to immutable external witness
    fn publish_hash(&self, entry_number: u64, hash: &[u8]) -> Result<String, AuditError>;
    
    /// Verify hash against external witness
    fn verify_hash(&self, entry_number: u64, hash: &[u8]) -> Result<bool, AuditError>;
    
    /// Get witness receipt (proof of publication)
    fn get_receipt(&self, entry_number: u64) -> Result<WitnessReceipt, AuditError>;
}

pub struct WitnessReceipt {
    pub entry_number: u64,
    pub hash: Vec<u8>,
    pub timestamp: String,
    pub witness_id: String,
    pub signature: Vec<u8>,
}
```

### Implementation Options

#### Option A: Certificate Transparency Log
```rust
pub struct CTLogWitness {
    log_url: String,
    log_id: Vec<u8>,
}

impl AuditWitness for CTLogWitness {
    fn publish_hash(&self, entry_number: u64, hash: &[u8]) -> Result<String, AuditError> {
        // Submit to CT log via RFC 6962
        // Returns SCT (Signed Certificate Timestamp)
        todo!()
    }
}
```

**Pros**: Free, standardized, verifiable  
**Cons**: Requires TLS certificate, public visibility  

#### Option B: AWS S3 with Object Lock
```rust
pub struct S3Witness {
    bucket: String,
    region: String,
    client: aws_sdk_s3::Client,
}

impl AuditWitness for S3Witness {
    fn publish_hash(&self, entry_number: u64, hash: &[u8]) -> Result<String, AuditError> {
        let key = format!("audit-anchors/{:012}.hash", entry_number);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(hash.to_vec()))
            .object_lock_mode(ObjectLockMode::Governance)
            .object_lock_retain_until_date(/* 7 years from now */)
            .send()
            .await?;
        Ok(key)
    }
}
```

**Pros**: Private, immutable, simple integration  
**Cons**: Cost, AWS dependency  

#### Option C: Timestamping Authority (RFC 3161)
```rust
pub struct TSAWitness {
    tsa_url: String,
}

impl AuditWitness for TSAWitness {
    fn publish_hash(&self, entry_number: u64, hash: &[u8]) -> Result<String, AuditError> {
        // Submit timestamp request per RFC 3161
        // Returns TimeStampToken
        todo!()
    }
}
```

**Pros**: Standardized, legally recognized  
**Cons**: May cost per timestamp  

### Integration Points

```rust
// citadel-keystore/src/audit.rs

pub struct AuditLog {
    // ... existing fields ...
    witness: Option<Box<dyn AuditWitness>>,
    anchor_interval: u64, // Anchor every N entries (default: 1000)
}

impl AuditLog {
    pub fn record(&mut self, event: AuditEvent) {
        // ... existing hash chain logic ...
        
        // P007: Publish to external witness every anchor_interval entries
        if self.entry_count % self.anchor_interval == 0 {
            if let Some(witness) = &self.witness {
                match witness.publish_hash(self.entry_count, &self.last_hash) {
                    Ok(receipt_id) => {
                        tracing::info!(
                            entry = self.entry_count,
                            receipt = receipt_id,
                            "audit hash anchored to external witness"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            entry = self.entry_count,
                            error = %e,
                            "failed to anchor audit hash - continuing with local chain"
                        );
                        // Don't fail the operation - witness is defense in depth
                    }
                }
            }
        }
    }
    
    pub fn verify_chain_integrity(&self, witness: &dyn AuditWitness) -> Result<bool, AuditError> {
        // Walk chain backwards
        // At each anchor point, verify hash against witness
        // Detect truncation via anchor mismatch
        todo!()
    }
}
```

### Configuration

```bash
# Environment variables
export CITADEL_AUDIT_WITNESS_TYPE="s3"  # or "ct-log", "tsa", "none"
export CITADEL_AUDIT_WITNESS_URL="https://s3.amazonaws.com/citadel-audit"
export CITADEL_AUDIT_ANCHOR_INTERVAL="1000"
```

### Deployment Decision Tree
```
START → What's your threat model?
         ├─ Internal compromise only
         │  └─ No witness needed (current implementation OK)
         │
         ├─ Regulatory compliance (SOC2, ISO27001)
         │  └─ Use RFC 3161 TSA (legally recognized)
         │
         ├─ Public accountability
         │  └─ Use Certificate Transparency
         │
         └─ Private + immutable
             └─ Use S3 with Object Lock
```

### Testing Checklist
- [ ] Witness publish succeeds
- [ ] Witness publish failure doesn't block auditing
- [ ] Chain verification detects truncation
- [ ] Chain verification passes for unmodified chain
- [ ] Receipt retrieval works
- [ ] Timestamp validation works

---

## Implementation Priority

1. **P006** (Sharded cache): Implement when you need >10K decrypt/sec throughput
2. **P007** (Audit anchoring): Implement when you need defense against privileged attacker

Both are correctly documented and can be implemented independently without affecting each other or existing functionality.
