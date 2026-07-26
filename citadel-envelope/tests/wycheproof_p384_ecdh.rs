// SPDX-License-Identifier: Apache-2.0
//! Google Wycheproof P-384 ECDH vectors.
//!
//! Source: C2SP/wycheproof `ecdh_secp384r1_test.json`, commit
//! b61843a9a5115bb758134b6a1f5d5e502d445342, vector version 0.9rc5.

use p384::{ecdh::diffie_hellman, PublicKey, SecretKey};

#[derive(serde::Deserialize)]
struct Vectors {
    source_url: String,
    source_commit: String,
    source_name: String,
    source_version: String,
    curve: String,
    encoding: String,
    selection: String,
    tests: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    flags: Vec<String>,
    public: String,
    private: String,
    shared: String,
    result: String,
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn read_len(input: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *input.get(*pos)?;
    *pos += 1;
    if first & 0x80 == 0 {
        return Some(usize::from(first));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > std::mem::size_of::<usize>() || *pos + count > input.len() {
        return None;
    }
    let mut len = 0usize;
    for &byte in &input[*pos..*pos + count] {
        len = len.checked_mul(256)?.checked_add(usize::from(byte))?;
    }
    *pos += count;
    Some(len)
}

fn read_tlv<'a>(input: &'a [u8], pos: &mut usize, tag: u8) -> Option<&'a [u8]> {
    if *input.get(*pos)? != tag {
        return None;
    }
    *pos += 1;
    let len = read_len(input, pos)?;
    let end = (*pos).checked_add(len)?;
    let value = input.get(*pos..end)?;
    *pos = end;
    Some(value)
}

fn spki_sec1_point(der: &[u8]) -> Option<&[u8]> {
    let mut outer_pos = 0;
    let sequence = read_tlv(der, &mut outer_pos, 0x30)?;
    if outer_pos != der.len() {
        return None;
    }

    let mut sequence_pos = 0;
    let algorithm = read_tlv(sequence, &mut sequence_pos, 0x30)?;
    // id-ecPublicKey followed by secp384r1.
    const P384_ALGORITHM: &[u8] = &[
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00,
        0x22,
    ];
    if algorithm != P384_ALGORITHM {
        return None;
    }
    let bit_string = read_tlv(sequence, &mut sequence_pos, 0x03)?;
    if sequence_pos != sequence.len() || bit_string.first() != Some(&0) {
        return None;
    }
    bit_string.get(1..)
}

fn secret_key(raw: &[u8]) -> Option<SecretKey> {
    let significant = raw
        .iter()
        .position(|&byte| byte != 0)
        .map_or(&[][..], |i| &raw[i..]);
    if significant.is_empty() || significant.len() > 48 {
        return None;
    }
    let mut scalar = [0u8; 48];
    scalar[48 - significant.len()..].copy_from_slice(significant);
    SecretKey::from_slice(&scalar).ok()
}

#[test]
fn wycheproof_p384_ecdh_matches_authoritative_vectors() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors/wycheproof_p384_ecdh.json")).unwrap();
    assert_eq!(
        vectors.source_url,
        "https://raw.githubusercontent.com/C2SP/wycheproof/\
b61843a9a5115bb758134b6a1f5d5e502d445342/testvectors_v1/ecdh_secp384r1_test.json"
    );
    assert_eq!(
        vectors.source_commit,
        "b61843a9a5115bb758134b6a1f5d5e502d445342"
    );
    assert_eq!(vectors.source_name, "google-wycheproof");
    assert_eq!(vectors.source_version, "0.9rc5");
    assert_eq!(vectors.curve, "secp384r1");
    assert_eq!(vectors.encoding, "asn");
    assert!(vectors.selection.contains("all valid"));

    let mut valid = 0;
    let mut invalid = 0;
    let mut acceptable = 0;
    for case in vectors.tests {
        let public_der = from_hex(&case.public);
        let private = from_hex(&case.private);
        let parsed = spki_sec1_point(&public_der)
            .and_then(|point| PublicKey::from_sec1_bytes(point).ok())
            .zip(secret_key(&private));
        match case.result.as_str() {
            "valid" => {
                valid += 1;
                let (peer, secret) = parsed
                    .unwrap_or_else(|| panic!("valid tc{} rejected: {}", case.tc_id, case.comment));
                let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
                assert_eq!(
                    shared.raw_secret_bytes().as_slice(),
                    from_hex(&case.shared),
                    "shared secret tc{}: {}",
                    case.tc_id,
                    case.comment
                );
            }
            "invalid" => {
                invalid += 1;
                assert!(
                    parsed.is_none(),
                    "invalid tc{} accepted: {} {:?}",
                    case.tc_id,
                    case.comment,
                    case.flags
                );
            }
            "acceptable" => {
                acceptable += 1;
                // Wycheproof permits either rejection or the specified result for
                // these encoding/parameter edge cases; never silently skip them.
                if let Some((peer, secret)) = parsed {
                    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
                    assert_eq!(
                        shared.raw_secret_bytes().as_slice(),
                        from_hex(&case.shared),
                        "acceptable shared secret tc{}: {} {:?}",
                        case.tc_id,
                        case.comment,
                        case.flags
                    );
                }
            }
            other => panic!("unknown result {other} for tc{}", case.tc_id),
        }
    }
    assert_eq!(valid, 771);
    assert_eq!(invalid, 12);
    assert_eq!(acceptable, 10);
}
