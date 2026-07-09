# P026 - NoOpWitness Weakens Audit Trust Model

**Layer:** citadel-keystore | **Severity:** MEDIUM  
**Files:** citadel-keystore/src/audit_witness.rs, documentation

**Evidence (from independent security review - Round 4):**
```
"The system architecture is good.

But `NoOpWitness` still risks confusing:
* audit presence
  with:
* audit integrity

A reviewer will immediately ask:
> 'What external immutable anchor exists?'

Right now:
* local append-only file
* optional witness abstraction

is not enough for high-assurance audit guarantees."
```

**Root cause:**
NoOpWitness allows audit system to run without external anchoring.
Good for development, but can create false confidence in production.

**Required fix:**
Update documentation to clarify witness modes:

```rust
/// Audit witness modes and their trust properties:
///
/// - `NoOpWitness`: No external anchoring (development only)
///   - Trust: None - logs can be modified
///   - Use: Local testing only
///
/// - `FileWitness`: Local append-only file
///   - Trust: Weak - local attacker can truncate
///   - Use: Single-node dev/staging
///
/// - Future: Transparency log, timestamping, object-lock storage
///   - Trust: Strong - external immutable anchor
///   - Use: Production high-assurance deployments
```

Eventually implement real external witness:
- Certificate Transparency log
- RFC 3161 timestamping
- S3 with Object Lock

**Status:** OPEN
