# Replay Protection Trust Boundaries

## Overview

Citadel v3 provides replay protection with **backend-dependent durability guarantees**.
Understanding these trust boundaries is critical for threat modeling.

## Replay Backends and Their Guarantees

### 1. MemoryReplayStore (Development Only)

**Durability**: None  
**Crash Behavior**: All claims lost on restart  
**Trust Model**: Development/testing only

```rust
CITADEL_REPLAY_BACKEND=memory
```

**Use For**:
- Local development
- Unit testing
- Integration testing

**Do NOT Use For**:
- Any production deployment
- Any system requiring restart safety

---

### 2. FileReplayStore (Batched Mode - Default)

**Durability**: After flush only  
**Crash Window**: Up to 5 seconds OR 100 operations  
**Trust Model**: Best-effort durability with bounded crash window

```rust
CITADEL_REPLAY_BACKEND=file
CITADEL_REPLAY_FLUSH_MODE=batched  # default
```

**Guarantees**:
- ✅ Replay protection during normal operation
- ✅ Replay claims survive graceful shutdown (force_flush())
- ✅ Replay claims survive after periodic flush
- ⚠️ Recent claims (< flush interval) lost on hard crash
- ⚠️ Crash before flush creates replay window

**Crash Window**:
- Time: 5 seconds maximum
- Operations: 100 claims maximum
- Whichever threshold is reached first triggers flush

**Use For**:
- Production systems with acceptable small crash window
- High-throughput deployments (10K+ ops/sec)
- Systems with monitoring and alerting

**Mitigation**:
- Call `force_flush()` in SIGTERM handler
- Monitor replay backend health
- Log flush failures

---

### 3. FileReplayStore (Strict Mode)

**Durability**: Immediate  
**Crash Window**: None  
**Trust Model**: Strong durability, lower throughput

```rust
CITADEL_REPLAY_BACKEND=file
CITADEL_REPLAY_FLUSH_MODE=immediate
```

**Guarantees**:
- ✅ Every claim immediately fsynced to disk
- ✅ No crash window
- ✅ Replay protection survives any failure
- ⚠️ Significantly slower (100-1000x write amplification)

**Use For**:
- Low-throughput production systems
- High-assurance deployments
- Compliance-critical systems

**Trade-offs**:
- Throughput: ~100 ops/sec (vs 10K+ batched)
- Latency: +5-20ms per operation
- Disk wear: Significant

---

### 4. Distributed Backends (Future)

**Examples**: Redis, DynamoDB, PostgreSQL  
**Durability**: Depends on backend configuration  
**Trust Model**: Inherits backend guarantees

**Redis Example**:
```rust
CITADEL_REPLAY_BACKEND=redis
```

**Guarantees depend on Redis persistence**:
- AOF with fsync=always → strong durability
- AOF with fsync=everysec → 1-second window
- RDB only → last snapshot window
- No persistence → memory-only

**DynamoDB Example**:
- Immediately durable (service guarantee)
- Cross-region replication available
- Higher latency (~10-50ms)

---

## Choosing the Right Backend

| Requirement | Recommended Backend | Config |
|-------------|-------------------|--------|
| Development | Memory | `CITADEL_REPLAY_BACKEND=memory` |
| Testing | File (batched) | `CITADEL_REPLAY_BACKEND=file` |
| High-throughput prod | File (batched) + monitoring | Default + force_flush handler |
| High-assurance prod | File (strict) | `CITADEL_REPLAY_FLUSH_MODE=immediate` |
| Distributed prod | Redis/DynamoDB | `CITADEL_REPLAY_BACKEND=redis` |

---

## Threat Model Implications

### Attack: Crash-before-flush replay window

**Applies To**: FileReplayStore (batched), Redis (fsync=everysec)  
**Attack Scenario**:
1. Attacker observes ciphertext C1
2. Attacker forces crash before flush (power failure, kill -9)
3. System restarts, replay claim lost
4. Attacker replays C1

**Mitigations**:
- Use strict mode for critical systems
- Implement graceful shutdown with force_flush()
- Monitor for abnormal restarts
- Alert on replay backend failures

### Attack: Local file tampering

**Applies To**: FileReplayStore (both modes)  
**Attack Scenario**:
1. Attacker gains filesystem access
2. Attacker truncates/modifies replay.db
3. Replay protection bypassed

**Mitigations**:
- File integrity monitoring (AIDE, Tripwire)
- Encrypted filesystem
- Immutable infrastructure
- External witness (future)

### Attack: Distributed backend compromise

**Applies To**: Redis, DynamoDB, etc.  
**Attack Scenario**:
1. Attacker compromises backend credentials
2. Attacker flushes replay database
3. Replay protection bypassed

**Mitigations**:
- Strong backend authentication
- Network isolation
- Audit logging
- Backend-level access controls

---

## Production Deployment Checklist

**For Batched Mode**:
- [ ] Implement SIGTERM handler calling force_flush()
- [ ] Monitor replay backend health metrics
- [ ] Alert on flush failures
- [ ] Document acceptable crash window in threat model
- [ ] Test crash recovery procedures

**For Strict Mode**:
- [ ] Validate acceptable throughput (< 1K ops/sec recommended)
- [ ] Monitor disk I/O and wear
- [ ] Consider SSD with power-loss protection
- [ ] Test failure recovery

**For Distributed Backends**:
- [ ] Configure backend persistence appropriately
- [ ] Implement connection retry logic
- [ ] Monitor backend latency
- [ ] Document backend trust assumptions
- [ ] Plan for backend unavailability

---

## Trust Statement

**Replay protection guarantees are ONLY as strong as the backend durability mode.**

If you configure:
- Memory backend → No restart safety
- Batched file → Bounded crash window
- Strict file → Strong durability
- Redis without AOF → Memory-only

**Choose based on your threat model, not convenience.**

---

## Future Enhancements

Planned improvements to strengthen replay trust:

1. **External Witness Integration**
   - Certificate Transparency logs
   - RFC 3161 timestamping
   - Object-lock storage (S3 Glacier)

2. **Crash Consistency Testing**
   - Chaos monkey for crash simulation
   - Automated recovery validation
   - Fuzzing of crash scenarios

3. **Distributed Consensus**
   - Raft/Paxos-based replay store
   - Multi-region replication
   - Byzantine fault tolerance

---

**Last Updated**: Round 4 security audit  
**Reviewer Feedback**: "Replay persistence semantics still oversell reality"  
**Resolution**: Complete trust boundary documentation (P024)
