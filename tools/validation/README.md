# Validation Tools

End-to-end and black-box validation harnesses. All harnesses assume the current working
directory is the repository root (binary paths like `target\debug\citadel-api.exe` are
CWD-relative), e.g. `powershell -ExecutionPolicy Bypass -File tools\validation\citadel_full_validation.ps1`.
Evidence rows these tools feed live in [`VALIDATION_MATRIX.md`](../../VALIDATION_MATRIX.md).

| Tool | What it does | Status |
|------|--------------|--------|
| `citadel_full_validation.ps1` | Full Windows E2E run: cargo fmt/test/clippy across the workspace, then live-server API checks (auth, tamper, AAD/context rejection, replay before/after restart) | **Live evidence source** — the Windows E2E run cited by VALIDATION_MATRIX PASS rows |
| `citadel_abuse_harness.ps1` | 100x adversarial abuse storm: replay, wrong-AAD, wrong-context, malformed JSON, wrong-auth attacks against a running server | Evidence tool for VALIDATION_MATRIX's ⏳ PENDING abuse-storm row |
| `citadel_multiprocess_replay_harness.ps1` | Two API instances sharing one data dir; proves only one decrypt may succeed, documents the FileReplayStore single-process limitation | Evidence tool for VALIDATION_MATRIX's ⏳ PENDING multi-process rows |
| `citadel_long_run_load.ps1` | 10 minutes of continuous encrypt/decrypt, rotation, invalid traffic, and replay attempts | Evidence tool for the PENDING long-run row |
| `citadel_crash_harness.ps1` | Crash durability: force-kills the server under continuous load and verifies replay-store recovery | Evidence tool for SECURITY_MATURITY's open chaos-testing item |
| `citadel_api_security_test.py` | HTTP-level security boundary tests: auth rejection, scope enforcement, rate limiting, input validation | Superseded by in-crate tests + `scripts/security/`; kept as an HTTP black-box reference |
| `citadel_cross_verify.py` | Independent Python reimplementation of the SHA3-256 → HKDF-SHA256 → AES-256-GCM construction; checks primitives against NIST/RFC KATs and can decrypt a real Citadel ciphertext | Independent reimplementation check — usage per its header (`python tools/validation/citadel_cross_verify.py`, optionally `--vector`) |

Operational smoke check (running server health, not validation evidence):
`tools/ops/Validate-Citadel.ps1`.
