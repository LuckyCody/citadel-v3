// Tier 1 — Google Project Wycheproof known-attack vectors run through the
// EXACT primitive crate versions Citadel pins in its production Cargo.lock:
//   aes-gcm 0.10.3, x25519-dalek 2.0.1, hkdf 0.12.4 (+ sha2 0.10.9).
//
// Upstream RustCrypto passes these; the value here is supply-chain regression
// detection — proof that the *specific versions Citadel ships* still resist the
// documented attacks. A failure means Citadel's pinned primitive is affected.

use wycheproof::TestResult;

/// AES-256-GCM (96-bit nonce, 128-bit tag) — the exact AEAD Citadel uses.
#[test]
fn wycheproof_aes_256_gcm() {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

    let set = wycheproof::aead::TestSet::load(wycheproof::aead::TestName::AesGcm)
        .expect("load AES-GCM vectors");

    let (mut pass, mut skip, mut acceptable) = (0u32, 0u32, 0u32);
    let mut failures: Vec<String> = Vec::new();

    for group in set.test_groups {
        // Only the parameters Citadel actually uses.
        if group.key_size != 256 || group.nonce_size != 96 || group.tag_size != 128 {
            skip += group.tests.len() as u32;
            continue;
        }
        for t in group.tests {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&t.key));
            let nonce = Nonce::from_slice(&t.nonce);
            let mut ct_tag = t.ct.to_vec();
            ct_tag.extend_from_slice(&t.tag);
            let dec = cipher.decrypt(nonce, Payload { msg: &ct_tag, aad: &t.aad });

            match t.result {
                TestResult::Valid => {
                    match dec {
                        Ok(pt) if pt == t.pt.as_slice() => pass += 1,
                        Ok(_) => failures.push(format!("tc{}: valid vector decrypted to wrong plaintext", t.tc_id)),
                        Err(_) => failures.push(format!("tc{}: valid vector failed to decrypt", t.tc_id)),
                    }
                }
                TestResult::Invalid => {
                    if dec.is_ok() {
                        failures.push(format!("tc{}: INVALID vector accepted (forgery)", t.tc_id));
                    } else {
                        pass += 1;
                    }
                }
                TestResult::Acceptable => acceptable += 1,
            }
        }
    }

    eprintln!("[wycheproof AES-256-GCM] pass={pass} acceptable={acceptable} skipped(other params)={skip} failures={}", failures.len());
    assert!(failures.is_empty(), "AES-256-GCM Wycheproof failures:\n{}", failures.join("\n"));
    // Wycheproof's AES-GCM set holds 66 vectors at Citadel's exact params
    // (256-bit key / 96-bit nonce / 128-bit tag). Floor guards against the
    // vector load silently returning nothing, not a specific count.
    assert!(pass >= 60, "suspiciously few AES-256-GCM vectors executed ({pass}); vector load likely broken");
}

/// X25519 — the classical half of Citadel's hybrid KEM.
#[test]
fn wycheproof_x25519() {
    use x25519_dalek::{PublicKey, StaticSecret};

    let set = wycheproof::xdh::TestSet::load(wycheproof::xdh::TestName::X25519)
        .expect("load X25519 vectors");

    let (mut pass, mut informational) = (0u32, 0u32);
    let mut failures: Vec<String> = Vec::new();

    for group in set.test_groups {
        for t in group.tests {
            let priv_arr: [u8; 32] = match t.private_key[..].try_into() {
                Ok(a) => a,
                Err(_) => { informational += 1; continue; }
            };
            let pub_arr: [u8; 32] = match t.public_key[..].try_into() {
                Ok(a) => a,
                Err(_) => { informational += 1; continue; }
            };
            let shared = StaticSecret::from(priv_arr).diffie_hellman(&PublicKey::from(pub_arr));

            match t.result {
                TestResult::Valid => {
                    if shared.as_bytes() == t.shared_secret.as_slice() {
                        pass += 1;
                    } else {
                        failures.push(format!("tc{}: valid X25519 vector produced wrong shared secret", t.tc_id));
                    }
                }
                // Low-order / non-contributory points: the raw dalek primitive does
                // not error (Citadel enforces was_contributory() one layer up). We
                // only assert the Valid cases here; tally the rest.
                TestResult::Invalid | TestResult::Acceptable => informational += 1,
            }
        }
    }

    eprintln!("[wycheproof X25519] pass(valid)={pass} informational(low-order/acceptable)={informational} failures={}", failures.len());
    assert!(failures.is_empty(), "X25519 Wycheproof failures:\n{}", failures.join("\n"));
    assert!(pass > 100, "suspiciously few X25519 vectors executed ({pass})");
}

/// HKDF-SHA256 — Citadel's key-derivation primitive.
#[test]
fn wycheproof_hkdf_sha256() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let set = wycheproof::hkdf::TestSet::load(wycheproof::hkdf::TestName::HkdfSha256)
        .expect("load HKDF-SHA256 vectors");

    let (mut pass, mut acceptable) = (0u32, 0u32);
    let mut failures: Vec<String> = Vec::new();

    for group in set.test_groups {
        for t in group.tests {
            let hk = Hkdf::<Sha256>::new(Some(&t.salt), &t.ikm);
            let mut okm = vec![0u8; t.size];
            let derived = hk.expand(&t.info, &mut okm);

            match t.result {
                TestResult::Valid => match derived {
                    Ok(()) if okm == t.okm.as_slice() => pass += 1,
                    Ok(()) => failures.push(format!("tc{}: valid HKDF vector wrong OKM", t.tc_id)),
                    Err(_) => failures.push(format!("tc{}: valid HKDF vector errored", t.tc_id)),
                },
                TestResult::Invalid => {
                    if derived.is_ok() && okm == t.okm.as_slice() {
                        failures.push(format!("tc{}: INVALID HKDF vector accepted", t.tc_id));
                    } else {
                        pass += 1;
                    }
                }
                TestResult::Acceptable => acceptable += 1,
            }
        }
    }

    eprintln!("[wycheproof HKDF-SHA256] pass={pass} acceptable={acceptable} failures={}", failures.len());
    assert!(failures.is_empty(), "HKDF-SHA256 Wycheproof failures:\n{}", failures.join("\n"));
    assert!(pass > 10, "suspiciously few HKDF vectors executed ({pass})");
}
