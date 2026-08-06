# Citadel white paper — references

Bibliography for `CITADEL_WHITEPAPER.md`. Entries are grouped: A-series for standards and government
publications, B-series for academic and archival cryptography literature, and C-series for
implementation and tooling. The CMVP certificate and security-policy entries (A19-A21) and any draft
standards are time-sensitive and should be rechecked against their live sources immediately before
publication.

---

## Section A — Standards, specifications, and government publications

A1. NIST, **FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)**, Aug 2024.
    https://csrc.nist.gov/pubs/fips/203/final — *the PQ KEM in both suites.*
A2. NIST, **FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)**, Aug 2024.
    https://csrc.nist.gov/pubs/fips/204/final — *citadel-signer.*
A3. NIST, **FIPS 197: Advanced Encryption Standard (AES)**, 2001.
    https://csrc.nist.gov/pubs/fips/197/final — *AES-256 block cipher.*
A4. NIST, **FIPS 186-5: Digital Signature Standard (DSS)**, Feb 2023.
    https://csrc.nist.gov/pubs/fips/186-5/final — *P-384 / ECDSA parameters (0xA4 classical KEM).*
A5. NIST, **FIPS 140-3: Security Requirements for Cryptographic Modules**, Mar 2019.
    https://csrc.nist.gov/pubs/fips/140-3/final — *the validation regime the AWS-LC backend targets.*
A6. M. Dworkin, **NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: GCM and GMAC**,
    Nov 2007. https://csrc.nist.gov/pubs/sp/800/38/d/final — *AES-GCM; the IV-uniqueness requirement
    (Sec. 8.2) that drives our Scenario-2 nonce choice.*
A7. E. Barker et al., **NIST SP 800-56A Rev. 3: Pair-Wise Key-Establishment Using Discrete Logarithm
    Cryptography**, Apr 2018. https://csrc.nist.gov/pubs/sp/800/56/a/r3/final — *ECC Diffie-Hellman key
    establishment (P-384); the approved-curve table does not include X25519, for which see A13.*
A8. NIST, **SP 800-56C Rev. 2: Recommendation for Key-Derivation Methods in Key-Establishment
    Schemes**, Aug 2020. https://csrc.nist.gov/pubs/sp/800/56/c/r2/final — *HKDF as the combiner KDF.*
A9. E. Barker, **NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management, Part 1: General**,
    May 2020. https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final — *general key-role and lifecycle
    guidance; it does not prescribe Citadel's specific Root/Domain/KEK/DEK hierarchy.*
A10. L. Chen et al., **NIST SP 800-186: Recommendations for Discrete Logarithm-Based Cryptography:
    Elliptic Curve Domain Parameters**, Feb 2023. https://csrc.nist.gov/pubs/sp/800/186/final —
    *approved curves incl. P-384 and Curve25519.*
A11. NIST, **IR 8547 (initial public draft): Transition to Post-Quantum Cryptography Standards**,
    Nov 2024. https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf — *draft transition
    guidance that accommodates hybrid key-establishment approaches subject to construction-specific
    analysis (still a draft; check for a final publication at publish time).*
A12. NSA, **Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)** Cybersecurity Advisory,
    Sep 2022. https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF —
    *the category-5 / CNSA rationale for the 0xA4 suite.*
A13. A. Langley, M. Hamburg, S. Turner, **RFC 7748: Elliptic Curves for Security (X25519/X448)**,
    Jan 2016. https://www.rfc-editor.org/rfc/rfc7748 — *X25519 (0xA3 classical KEM).*
A14. H. Krawczyk, P. Eronen, **RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function
    (HKDF)**, May 2010. https://www.rfc-editor.org/rfc/rfc5869 — *the deployed KDF.*
A15. D. McGrew, **RFC 5116: An Interface and Algorithms for Authenticated Encryption**, Jan 2008.
    https://www.rfc-editor.org/rfc/rfc5116 — *AEAD interface / nonce discipline.*
A16. ISO/IEC, **19790:2012, Security requirements for cryptographic modules**.
    https://www.iso.org/standard/52906.html — *international basis underlying FIPS 140-3.*
A17. NIST CMVP, **Implementation Guidance for FIPS 140-3 and the Cryptographic Module Validation
    Program** (see IG C.H, AES-GCM IV generation).
    https://csrc.nist.gov/projects/cryptographic-module-validation-program — *the approved GCM IV
    scenarios; our Scenario-2 (RandomizedNonceKey) remediation is grounded here.*
A18. S. Connolly et al., **draft-connolly-cfrg-xwing-kem (X-Wing: general-purpose hybrid post-quantum
    KEM)**, IETF Internet-Draft `draft-connolly-cfrg-xwing-kem-10`, 2 Mar 2026, work in progress.
    https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ — *contemporary X25519+ML-KEM-768
    hybrid design comparator.*
A19. NIST CMVP, **Certificate #5298, AWS-LC FIPS (dynamic)**, module build AWS-LC FIPS 3.1.0.
    https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298 —
    *the dynamic-library certificate for the same 3.1.0 module version.* Time-sensitive; verify
    status/dates at publication.
A20. NIST CMVP, **Certificate #5314, AWS-LC FIPS (static)**, module build AWS-LC FIPS 3.1.0.
    https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314 —
    *the static-library certificate, which is the one the statically linked fips build corresponds
    to.* Time-sensitive; verify at publication.
A21. NIST CMVP, **AWS-LC FIPS 3.1.0 Security Policy** (`140sp5314.pdf`), tables for software version,
    approved services, GCM IV scenarios, and tested operating environments.
    https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5314.pdf
    — *the primary source for the approved-algorithm, IV-scenario, and OE claims in Section 5.*
    Time-sensitive; confirm the exact tables at publication.

## Section B — Academic and archival literature (web-verified 2026-08-05)

Item types are mixed and are labeled where they are not a conference or journal paper. Most B-series
items are peer-reviewed conference or journal papers; B5 (X-Wing) is an archival preprint (IACR
ePrint), and A18 is an IETF Internet-Draft. Do not treat every entry as peer-reviewed.

B1. J. Bos, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, J. Schanck, P. Schwabe, G. Seiler,
    D. Stehlé, **"CRYSTALS – Kyber: A CCA-Secure Module-Lattice-Based KEM,"** IEEE EuroS&P 2018.
    ePrint 2017/634, https://eprint.iacr.org/2017/634 — *the algorithm standardized as ML-KEM.*
B2. D. J. Bernstein, **"Curve25519: New Diffie-Hellman Speed Records,"** PKC 2006, LNCS 3958,
    pp. 207-228. https://cr.yp.to/ecdh.html — *the X25519 curve and its timing-attack posture.*
B3. F. Giacon, F. Heuer, B. Poettering, **"KEM Combiners,"** PKC 2018, LNCS 10769, pp. 190-218.
    ePrint 2018/024, https://eprint.iacr.org/2018/024 — *the security basis for concatenating two KEM
    secrets through a KDF; core justification of the hybrid combiner.*
B4. N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila, **"Hybrid Key Encapsulation
    Mechanisms and Authenticated Key Exchange,"** PQCrypto 2019, LNCS 11505, pp. 206-226.
    ePrint 2018/903, https://eprint.iacr.org/2018/903 — *formal hybrid-KEM security models.*
B5. M. Barbosa, D. Connolly, J. Duarte, A. Kaiser, P. Schwabe, K. Varner, B. Westerbaan,
    **"X-Wing: The Hybrid KEM You've Been Looking For,"** IACR ePrint 2024/039.
    https://eprint.iacr.org/2024/039 — *a concrete X25519+ML-KEM-768 hybrid and its proof.*
B6. H. Krawczyk, **"Cryptographic Extraction and Key Derivation: The HKDF Scheme,"** CRYPTO 2010,
    LNCS 6223, pp. 631-648. ePrint 2010/264, https://eprint.iacr.org/2010/264 — *the extract-then-
    expand analysis underlying our KDF transcript.*
B7. D. McGrew, J. Viega, **"The Security and Performance of the Galois/Counter Mode (GCM) of
    Operation,"** INDOCRYPT 2004. ePrint 2004/193, https://eprint.iacr.org/2004/193 — *GCM security
    proof and its IV assumptions.*
B8. A. Joux, **"Authentication Failures in NIST Version of GCM"** (the "forbidden attack"), NIST
    public comment, 2006. https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/800-38-series-drafts/gcm/joux_comments.pdf
    — *why nonce reuse is catastrophic for GCM; motivates module-generated IVs.*
B9. H. Böck, A. Zauner, S. Devlin, J. Somorovsky, P. Jovanovic, **"Nonce-Disrespecting Adversaries:
    Practical Forgery Attacks on GCM in TLS,"** USENIX WOOT 2016. ePrint 2016/475,
    https://eprint.iacr.org/2016/475 — *real-world GCM nonce-reuse forgeries; reinforces B8.*
B10. O. Reparaz, J. Balasch, I. Verbauwhede, **"Dude, is my code constant time?,"** DATE 2017.
    ePrint 2016/1123, https://eprint.iacr.org/2016/1123 — *the leakage-detection method behind our
    timing evaluation (and its one-sided limits).*
B11. B. Blanchet, **"A Computationally Sound Mechanized Prover for Security Protocols,"** IEEE S&P
    2006 (CryptoVerif). https://bblanche.gitlabpages.inria.fr/CryptoVerif/ — *the tool used for the
    0xA4 combiner secrecy proofs.*

## Section C — Implementation / tooling references (cite as software, with commit/version)

C1. **AWS-LC** and **aws-lc-rs** (FIPS module + Rust bindings), AWS.
    https://github.com/aws/aws-lc-rs and https://github.com/aws/aws-lc — *Versions used: `aws-lc-rs`
    1.17.1 and `aws-lc-fips-sys` 0.13.11, linking AWS-LC-FIPS 3.1.0; CMVP certificates #5298/#5314.*
C2. **RustCrypto** crates (pure-Rust default backend), exact versions pinned in `Cargo.lock`:
    `ml-kem` 0.3.2, `p384` 0.14.0, `elliptic-curve` 0.14.1, `aes-gcm`, `hkdf`, `sha3`, `x25519-dalek`.
    Immutable per-version source browsers: https://docs.rs/crate/p384/0.14.0/source/ and
    https://docs.rs/crate/elliptic-curve/0.14.1/source/ . — *For the P-384 constant-time claim
    (Section 6.5) the shipped path is `elliptic_curve::ecdh::diffie_hellman`, which multiplies the
    recipient public `ProjectivePoint` by the secret scalar through the crate's constant-time `Mul`
    (no `_vartime` on the path), with `subtle` for secret-dependent selection and `from_sec1_bytes`
    rejecting off-curve and identity points before the multiply. The matching source-inspection record
    is `TIMING.md`.*
C3. **dudect** reference implementation, O. Reparaz. https://github.com/oreparaz/dudect — *tool used;
    pairs with B10.*
