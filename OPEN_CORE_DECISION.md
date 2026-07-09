# Open-Core vs Closed-Core Decision

## The Question

Should Citadel be:

1. **Open-Core** — core library open, premium features closed
2. **Source-Available** — readable but not truly "open source"

## Recommendation: **Fully Open Source with Commercial Support**

### Why Open Source Wins for Crypto Libraries

**Trust is your moat.**

Cryptographic libraries live or die by trust. A closed-source crypto library is:
- Inherently suspect (could have backdoors)
- Harder to audit
- Less likely to get community review
- More work to maintain (no PRs)

Companies that pay for crypto support want:
1. Confidence the code is correct
2. Someone to call when things break
3. Audit preparation help

They do NOT want:
- Secret algorithms
- Vendor lock-in on crypto
- Uncertainty about what's running in production

### Revenue Model That Works

| Tier | What You Sell | Price |
|------|---------------|-------|
| Free | Code | $0 |
| Pro | Stability + Security contact | $5-15k/yr |
| Enterprise | SLA + Audit assistance + Training | $25k+/yr |

You're selling **insurance and expertise**, not code.

### What Open-Core Would Look Like (If You Did It)

If you went open-core, the split would be:

- Core library (seal/open)
- Wire format
- Basic CLI

**Closed (Commercial License):**
- Advanced CLI (batch operations, key management integration)
- WASM builds
- Platform-specific optimizations
- HSM/KMS integrations
- Audit documentation package

**Why this is harder:**
- You have to maintain two codebases
- Paying customers expect more features over time
- Community won't contribute to closed parts
- Crypto audits become complicated

### The Practical Path

1. **Now:** 
2. **First revenue:** Consulting/integration work
3. **As you grow:** Support tiers
4. **Maybe later:** Consider closed add-ons (but probably don't need them)

### Competitive Landscape

| Project | Model | Revenue |
|---------|-------|---------|
| libsodium | Fully open | Consulting |
| AWS Encryption SDK | Open | AWS services |
| Google Tink | Open | GCP services |
| HashiCorp Vault | Open-core | Enterprise features |

Note: HashiCorp is the only open-core example, and their closed features are enterprise management (policies, namespaces), not crypto.

### Decision Matrix

| Factor | Open Source | Open-Core | Closed |
|--------|-------------|-----------|--------|
| Trust | ✓✓✓ | ✓✓ | ✗ |
| Community contributions | ✓✓✓ | ✓ | ✗ |
| Maintenance burden | Low | High | Medium |
| Audit simplicity | ✓✓✓ | ✓✓ | ✓ |
| Revenue ceiling | Medium | High | High |
| Time to first revenue | Slow | Medium | Fast |

### Final Recommendation

**Go fully open source.**

- It's the right choice for crypto
- It's simpler to execute
- It builds trust faster
- It doesn't preclude adding closed components later if needed

Your revenue comes from:
1. Integration consulting (immediate)
2. Support contracts (medium-term)
3. Audit assistance (medium-term)
4. Training (long-term)

None of that requires closing the source.

---

## If You Disagree

If you want to explore open-core, the cleanest split would be:

**Open:** Core library + basic CLI
**Closed:** Enterprise CLI (batch ops, key rotation tooling, audit prep scripts)

But honestly? Just make it all open and charge for support. It's simpler and more honest.
