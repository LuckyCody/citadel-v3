# Documentation Index — Authority Map

One canonical document per topic. If two documents disagree, the canon column wins.

| Topic | Canonical doc | Supporting / superseded |
|-------|---------------|-------------------------|
| Wire format (current) | [docs/spec/WIRE_SPEC_V2.md](spec/WIRE_SPEC_V2.md) | [SPEC.md](spec/SPEC.md) (legacy v1, normative for decrypt path), [WIRE_SPEC.md](spec/WIRE_SPEC.md) (historical, do not implement), [FORMAT.md](spec/FORMAT.md) (non-normative overview) |
| Replay durability | [docs/security/REPLAY_TRUST_BOUNDARIES.md](security/REPLAY_TRUST_BOUNDARIES.md) | [REPLAY_STORE_GUARANTEES.md](security/REPLAY_STORE_GUARANTEES.md) (per-backend ops) |
| Security posture | [docs/security/SECURITY_MATURITY.md](security/SECURITY_MATURITY.md) | [THREAT_MODEL.md](security/THREAT_MODEL.md) (attacker model), [SECURITY_GUARANTEES.md](security/SECURITY_GUARANTEES.md) (design claims) |
| Validation evidence | [/VALIDATION_MATRIX.md](../VALIDATION_MATRIX.md) (root) | [gauntlet/receipts](../gauntlet/receipts/SUMMARY.md), [tools/validation](../tools/validation/README.md) |
| Timing | [docs/security/TIMING.md](security/TIMING.md) | [SIDE_CHANNEL_NOTES.md](security/SIDE_CHANNEL_NOTES.md) (superseded) |
| FIPS wording | [docs/security/SUPPLY_CHAIN.md](security/SUPPLY_CHAIN.md) §AWS-LC | [SECURITY_MATURITY.md](security/SECURITY_MATURITY.md), [whitepaper §5](../whitepaper/CITADEL_WHITEPAPER.md) |
| Compliance | [docs/security/COMPLIANCE_MATRIX.md](security/COMPLIANCE_MATRIX.md) | — |
| Deployment | [QUICKSTART.md](../QUICKSTART.md) (golden path, root) + [docs/ops/DEPLOYMENT.md](ops/DEPLOYMENT.md) (reference) | — |
| SDK/FFI stability | [/API_FREEZE.md](../API_FREEZE.md) (root) | — |
| HTTP API | [scripts/security/openapi.yaml](../scripts/security/openapi.yaml) (machine-readable; 24 of 27 routes) + [README endpoint table](../README.md#api-endpoints) (complete) | — |
| Provider history | [docs/history/PROVIDER_DECISION_LOG.md](history/PROVIDER_DECISION_LOG.md) | [PROVIDER_BAKEOFF_2026.md](history/PROVIDER_BAKEOFF_2026.md) (preregistered scorecard) |
