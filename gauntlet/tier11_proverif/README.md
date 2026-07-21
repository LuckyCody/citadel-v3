# Tier 11 — ProVerif symbolic protocol model

Machine-checked (Dolev-Yao) analysis of Citadel's envelope flow.

## Run
```bash
# ProVerif CLI (no GUI needed). If not installed, build it userspace:
#   opam switch create proverif ocaml-base-compiler.4.14.2 && eval $(opam env)
#   curl -fsSL https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz | tar xz
#   cd proverif2.05 && ./build && cp proverif ~/.local/bin/
proverif citadel_envelope.pv
```

## What it proves
Against an attacker who fully controls the network (intercept / modify / inject /
replay / attempt downgrade):
- **Secrecy** — the plaintext stays secret (attacker lacks the recipient sk).
- **No-downgrade + binding** — the receiver only outputs the honest plaintext
  under the exact suite/context/aad the sender used; a v2→v1 downgrade cannot
  make it accept.

Replay-injectivity is inconclusive in ProVerif (a tool limitation reasoning about
a stateful atomic claim); replay atomicity is assured by `ReplayStore::claim` and
verified concurrently in Tier 6 (Loom). See `../receipts/tier11_proverif.txt`.

## Caveats
Symbolic model → primitives are perfect; this proves *protocol* properties, not
the computational crypto (Tier 9 combiner analysis + Tier 1 vectors cover that).
The AEAD/KDF binding is encoded as a property of `open`. No sender-authentication
is claimed (encryption, not signcryption; ML-DSA signing is separate).
