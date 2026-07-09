# P012 - V3 Stream Header Does Not Validate Suite/Flags

**Layer:** citadel-envelope | **Severity:** CRITICAL  
**Files:** citadel-envelope/src/stream_v3.rs (lines 318-320)

**Evidence (from independent security review):**
```
Review finding: "V3 streaming header validation has a real bug. In 
`citadel-envelope/src/stream_v3.rs`, `from_header()` reads `flags`, 
`suite_kem`, and `suite_aead`, but does not reject invalid flags or 
suite bytes. It returns them in `StreamV3Header`. That contradicts 
the fixed-suite/no-downgrade posture."

Code at lines 318-320:
let _flags = header[5]; // reserved
let suite_kem = header[6];
let suite_aead = header[7];

These values are READ but NEVER VALIDATED.
```

**Root cause:**
`from_header()` extracts suite_kem and suite_aead from wire format but does 
not check them against expected values:
- Expected suite_kem: `SUITE_KEM_HYBRID_X25519_MLKEM768` (0xA3)
- Expected suite_aead: `SUITE_AEAD_AES256GCM` (0xB1)
- Expected flags: `0x00` (reserved, must be zero)

Attacker can send arbitrary bytes in these fields and they are accepted.

This violates Citadel's fixed-suite posture. The ciphersuites are defined as 
constants at the top of the file, implying they should be enforced.

**Attack scenario:**
1. Attacker sends header with suite_kem=0xFF, suite_aead=0xFF
2. Header parses successfully
3. Code uses hardcoded suite anyway (doesn't use the parsed values)
4. But header_tag is computed over those bytes
5. This could enable downgrade attacks if suite negotiation is ever added

**Required fix:**
Add validation immediately after reading:
```rust
let flags = header[5];
if flags != STREAM_V3_FLAGS {
    return Err(DecryptionError); // reject non-zero flags
}

let suite_kem = header[6];
if suite_kem != STREAM_V3_SUITE_KEM {
    return Err(DecryptionError); // reject wrong KEM suite
}

let suite_aead = header[7];
if suite_aead != STREAM_V3_SUITE_AEAD {
    return Err(DecryptionError); // reject wrong AEAD suite
}
```

**Status:** OPEN
