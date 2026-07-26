#![cfg(feature = "kat")]

use std::{fs, path::PathBuf};

use citadel_envelope::inspect;
use citadel_envelope::v2_test_vectors::deterministic_envelope_a4;
use sha2::{Digest, Sha256};

const PLAINTEXT: &[u8] = b"Citadel envelope v2 deterministic interoperability vector";
const AAD: &[u8] = b"vector/aad/2026-07-15";
const CONTEXT: &[u8] = b"vector/context/envelope-v2";
const A4_SHA256: &str = "7bd16285a951570eccfece79c28a8501c40474f715f0feb2371924d3f220b574";

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/decode_envelope_v2")
}

#[test]
#[ignore = "explicitly regenerate the deterministic A4 fuzz corpus"]
fn gen_a4_fuzz_seeds() {
    let (_pk, _sk, _shared_secret, _kem_ct, envelope) = deterministic_envelope_a4(
        [0x11; 48], [0x22; 32], [0x33; 32], [0x44; 48], [0x55; 32], [0x66; 12], PLAINTEXT, AAD,
        CONTEXT,
    )
    .expect("deterministic A4 construction");

    assert_eq!(envelope.len(), 1836);
    assert_eq!(hex::encode(Sha256::digest(&envelope)), A4_SHA256);
    let info = inspect(&envelope).expect("canonical A4 seed must inspect");
    assert_eq!(info.kem_suite, "P-384+ML-KEM-1024");

    let mut suite_flipped = envelope.clone();
    assert_eq!(suite_flipped[6], 0xA4);
    suite_flipped[6] = 0xA3;
    let truncated = envelope[..1234].to_vec();

    let corpus = corpus_dir();
    fs::write(corpus.join("a4_valid_1836"), &envelope).expect("write valid A4 seed");
    fs::write(corpus.join("a4_suite_flipped_to_a3"), &suite_flipped)
        .expect("write suite-flipped seed");
    fs::write(corpus.join("a4_truncated_to_a3_total"), &truncated).expect("write truncated seed");
}
