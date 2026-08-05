// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Packet 042 differential gate: AWS-LC P-384 ECDH vs RustCrypto `p384`.
//!
//! ECDH is deterministic given (scalar, point), so the static-arm gate is **exact
//! x-coordinate equality** across implementations, 200 rounds. The ephemeral arm is
//! cross-checked (AWS-LC generates; RustCrypto recomputes the same secret from the
//! exported ephemeral point). The frozen, checked-in Wycheproof `secp384r1` vectors
//! are replayed through the AWS-LC component: valid **uncompressed** cases must agree
//! exactly; every non-uncompressed encoding is REJECTED by the component — that is
//! decision D2's policy enforced in our code, tested here as negative cases, not
//! skipped. Compiles empty without `--features fips`.

#![cfg(feature = "fips")]

use citadel_envelope::backend_awslc::AwsLcEcdhP384;
use p384::elliptic_curve::sec1::ToSec1Point;
use p384::{ecdh::diffie_hellman, PublicKey as RcPublicKey, SecretKey as RcSecretKey};
use rand::RngCore;

const STATIC_ROUNDS: usize = 200;
const EPHEMERAL_ROUNDS: usize = 100;

fn random_scalar_key() -> RcSecretKey {
    loop {
        let mut bytes = [0u8; 48];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        if let Ok(key) = RcSecretKey::from_slice(&bytes) {
            return key;
        }
    }
}

fn uncompressed(pk: &RcPublicKey) -> [u8; 97] {
    pk.as_affine()
        .to_sec1_point(false)
        .to_bytes()
        .as_ref()
        .try_into()
        .unwrap()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// L2: static-arm exact x-coordinate identity, 200 rounds.
#[test]
fn static_arm_byte_identical_200_rounds() {
    for round in 0..STATIC_ROUNDS {
        let secret = random_scalar_key();
        let peer_secret = random_scalar_key();
        let peer_point = uncompressed(&peer_secret.public_key());

        let rc = diffie_hellman(
            secret.to_nonzero_scalar(),
            peer_secret.public_key().as_affine(),
        );
        let lc =
            AwsLcEcdhP384::ecdh(secret.to_bytes().as_slice(), &peer_point).expect("awslc ecdh");
        assert_eq!(
            rc.raw_secret_bytes().as_slice(),
            lc.as_slice(),
            "x-coordinate mismatch, round {round}"
        );
    }
}

/// L2: ephemeral arm — AWS-LC generates; RustCrypto recomputes the same secret.
#[test]
fn ephemeral_arm_cross_checked_100_rounds() {
    for round in 0..EPHEMERAL_ROUNDS {
        let recipient = random_scalar_key();
        let recipient_point = uncompressed(&recipient.public_key());

        let (eph_pub, lc_shared) =
            AwsLcEcdhP384::ephemeral_ecdh(&recipient_point).expect("awslc ephemeral");

        let eph_parsed = RcPublicKey::from_sec1_bytes(&eph_pub)
            .expect("awslc ephemeral public parses in rustcrypto");
        let rc_shared = diffie_hellman(recipient.to_nonzero_scalar(), eph_parsed.as_affine());
        assert_eq!(
            rc_shared.raw_secret_bytes().as_slice(),
            &lc_shared[..],
            "ephemeral cross-check mismatch, round {round}"
        );
    }
}

/// L2/L3: rejection battery — lengths, tags, off-curve, identity encodings.
#[test]
fn rejection_battery() {
    let secret = random_scalar_key();
    let scalar = secret.to_bytes();
    let peer = random_scalar_key();
    let good_point = uncompressed(&peer.public_key());

    // Control: the good case works.
    assert!(AwsLcEcdhP384::ecdh(scalar.as_slice(), &good_point).is_ok());

    // Wrong scalar lengths.
    assert!(AwsLcEcdhP384::ecdh(&scalar.as_slice()[..47], &good_point).is_err());
    assert!(AwsLcEcdhP384::ecdh(&[0u8; 49], &good_point).is_err());

    // Wrong point lengths.
    assert!(AwsLcEcdhP384::ecdh(scalar.as_slice(), &good_point[..96]).is_err());
    assert!(AwsLcEcdhP384::ecdh(scalar.as_slice(), &[]).is_err());

    // Non-uncompressed tags at correct length (D2: only 0x04 is legal).
    for tag in [0x00u8, 0x02, 0x03, 0x05, 0x06, 0x07] {
        let mut mistagged = good_point;
        mistagged[0] = tag;
        assert!(
            AwsLcEcdhP384::ecdh(scalar.as_slice(), &mistagged).is_err(),
            "tag {tag:#04x} must be rejected"
        );
    }

    // Correctly tagged but off-curve (x = y = 0).
    let mut off_curve = [0u8; 97];
    off_curve[0] = 0x04;
    assert!(AwsLcEcdhP384::ecdh(scalar.as_slice(), &off_curve).is_err());
    assert!(AwsLcEcdhP384::ephemeral_ecdh(&off_curve).is_err());
}

// ---------------------------------------------------------------------------
// Wycheproof replay (frozen vectors, read-only include). Parsing helpers are
// replicated from tests/wycheproof_p384_ecdh.rs — integration tests are separate
// crates and the frozen original may not be edited to export them.
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct Vectors {
    source_commit: String,
    tests: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    public: String,
    private: String,
    shared: String,
    result: String,
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

fn normalized_scalar(raw: &[u8]) -> Option<[u8; 48]> {
    let significant = raw
        .iter()
        .position(|&byte| byte != 0)
        .map_or(&[][..], |i| &raw[i..]);
    if significant.is_empty() || significant.len() > 48 {
        return None;
    }
    let mut scalar = [0u8; 48];
    scalar[48 - significant.len()..].copy_from_slice(significant);
    Some(scalar)
}

/// L3: Wycheproof secp384r1 vectors through the AWS-LC component.
///
/// - valid + uncompressed point: exact shared-secret agreement required;
/// - valid/acceptable but NOT uncompressed (compressed etc.): the COMPONENT must
///   reject — D2 policy negative tests;
/// - invalid: rejected (by SPKI parse, scalar normalization, or the component).
#[test]
fn wycheproof_p384_replay_on_awslc() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("vectors/wycheproof_p384_ecdh.json")).unwrap();
    assert_eq!(
        vectors.source_commit, "b61843a9a5115bb758134b6a1f5d5e502d445342",
        "frozen vector provenance changed"
    );

    let mut agreed = 0u32;
    let mut policy_rejected = 0u32;
    let mut invalid_rejected = 0u32;
    for case in vectors.tests {
        let public_der = from_hex(&case.public);
        let private = from_hex(&case.private);
        let point = spki_sec1_point(&public_der);
        let scalar = normalized_scalar(&private);

        match (case.result.as_str(), point, scalar) {
            ("valid" | "acceptable", Some(point), Some(scalar))
                if point.len() == 97 && point[0] == 0x04 =>
            {
                let shared = AwsLcEcdhP384::ecdh(&scalar, point).unwrap_or_else(|_| {
                    panic!(
                        "valid uncompressed tc{} rejected: {}",
                        case.tc_id, case.comment
                    )
                });
                assert_eq!(
                    shared.as_slice(),
                    from_hex(&case.shared).as_slice(),
                    "shared secret tc{}: {}",
                    case.tc_id,
                    case.comment
                );
                agreed += 1;
            }
            ("valid" | "acceptable", Some(point), Some(scalar)) => {
                // Encodings our wire format never emits (D2): component must reject.
                assert!(
                    AwsLcEcdhP384::ecdh(&scalar, point).is_err(),
                    "non-uncompressed tc{} accepted against D2 policy: {}",
                    case.tc_id,
                    case.comment
                );
                policy_rejected += 1;
            }
            _ => {
                // Invalid vectors, unparseable SPKI, or out-of-range scalars: if
                // anything reaches the component, it must still reject.
                if let (Some(point), Some(scalar)) = (point, scalar) {
                    assert!(
                        AwsLcEcdhP384::ecdh(&scalar, point).is_err(),
                        "invalid tc{} accepted: {}",
                        case.tc_id,
                        case.comment
                    );
                }
                invalid_rejected += 1;
            }
        }
    }
    println!("wycheproof-on-awslc: agreed={agreed} policy_rejected={policy_rejected} invalid_class={invalid_rejected}");
    assert!(agreed >= 700, "too few exact agreements: {agreed}");
    assert!(policy_rejected > 0, "no D2 policy cases exercised");
    assert!(invalid_rejected > 0, "no invalid cases exercised");
}
