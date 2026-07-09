# Citadel v3 Deployment Notes

## Critical Security Fixes Applied

This document describes important security fixes and their deployment implications.

### P001/P010: FileReplayStore Write Batching

**Issue**: FileReplayStore was writing to disk on every decrypt operation, creating DoS vulnerability.

**Fix**: Implemented write batching - claims are buffered in memory and flushed when:
- 100 operations accumulated, OR
- 5 seconds elapsed since last flush, OR  
- 10,000 total entries reached

**CRITICAL DEPLOYMENT CONSIDERATION**:

With batching enabled, there is a **crash window** for unflushed claims:

1. Process claims nonce → stored in memory
2. Process crashes BEFORE flush
3. On restart, that nonce can be used again → **replay window violation**

**Mitigation Options**:

1. **Production Recommended**: Use RedisReplayStore instead
   - No crash window (Redis persists immediately)
   - Required for multi-instance deployments anyway
   
2. **Single-instance with FileReplayStore**:
   - Configure graceful shutdown in your service manager:
     ```
     # systemd example
     TimeoutStopSec=30
     KillMode=mixed
     KillSignal=SIGTERM
     ```
   - FileReplayStore will flush on SIGTERM before exit
   - Crash/SIGKILL still has replay window

3. **Accept the risk**:
   - Crash window is typically <5 seconds of claims
   - Only affects ciphertexts decrypted in that window
   - Acceptable for development/testing

### P002: Master Key Entropy Validation

**Fix**: CITADEL_MASTER_KEY now validated on startup:
- Must be exactly 32 bytes (64 hex chars)
- Must have ≥16 unique byte values
- Weak patterns rejected (all zeros, all same byte)

**Action**: Regenerate master key if currently using weak value:
```bash
openssl rand -hex 32
```

### P003: Three-Tier Rate Limiting

**Fix**: Added distributed attack protection:
1. Per-IP limit (20 req/sec)
2. Per-API-key limit (100 req/sec)
3. Global system limit (1000 req/sec)

**Effect**: Botnet attacks now hit per-key and global limits regardless of IP distribution.

### P004: Uniform Decrypt Error Messages

**Fix**: All decrypt errors now return uniform "operation failed" message.

**Effect**: 
- Attackers cannot enumerate key states/versions
- Internal logs still contain full details for debugging
- Check logs for decrypt failure root causes

## Recommended Production Configuration

```bash
# Master key (REQUIRED - generate with: openssl rand -hex 32)
export CITADEL_MASTER_KEY="<your-64-char-hex-key>"

# Replay protection (RECOMMENDED for production)
export CITADEL_REDIS_URL="redis://localhost:6379"
export CITADEL_REDIS_PREFIX="citadel:replay:"

# Rate limiting (optional tuning)
export CITADEL_RATE_LIMIT_RPS=20
export CITADEL_RATE_LIMIT_BURST=50

# API configuration
export CITADEL_PORT=3000
export CITADEL_DATA_DIR=/var/lib/citadel
export CITADEL_LOG_FORMAT=json

# Bootstrap admin key (first run only)
export CITADEL_API_KEY_HASH="<hash-from-hash_apikey-tool>"
```

## Performance Characteristics

### FileReplayStore (with batching)
- Throughput: ~10,000 decrypt/sec (batched writes)
- Latency: <1ms per decrypt (in-memory claim)
- Disk I/O: Burst every 100 ops or 5 seconds
- **Crash window**: Up to 5 seconds of claims at risk

### RedisReplayStore (recommended)
- Throughput: Limited by Redis (typically 50k+ ops/sec)
- Latency: Redis RTT (typically <1ms local)
- No crash window
- Supports multi-instance deployments

## Migration Path

If migrating from older Citadel version:

1. **Backup** existing replay cache and API key files
2. **Regenerate** CITADEL_MASTER_KEY (existing API key hashes will break)
3. **Regenerate** all API key hashes with new hash_apikey tool
4. **Configure** Redis for replay store (or accept FileReplayStore limitations)
5. **Test** in staging before production deployment

## Monitoring Recommendations

Watch for these log patterns:

```
# Rate limiting in effect
"rate limit exceeded"

# Weak master key detected
"[FATAL] CITADEL_MASTER_KEY has insufficient entropy"

# Replay protection active
"decrypt: replay detected"

# High-water mark warning
"FileReplayStore contains >10000 entries - consider cleanup"
```

## Future Enhancements (Not Yet Implemented)

The following security improvements are documented but not yet implemented:

- **P005**: Mandatory cryptoperiod enforcement (DEK 90d, KEK 365d, Root 730d)
- **P006**: Sharded replay cache for better parallelism
- **P007**: External audit log anchoring (immutable witness)
- **P008**: Configurable StateEnforcer TTL for multi-node deployments

These will be addressed in future releases.
