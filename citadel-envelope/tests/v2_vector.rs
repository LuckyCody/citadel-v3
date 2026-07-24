use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use citadel_envelope::v2_test_vectors::deterministic_envelope;
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

const PLAINTEXT: &[u8] = b"Citadel envelope v2 deterministic interoperability vector";
const AAD: &[u8] = b"vector/aad/2026-07-15";
const CONTEXT: &[u8] = b"vector/context/envelope-v2";

#[derive(Deserialize)]
struct CheckedVector {
    name: String,
    recipient_x25519_secret_hex: String,
    mlkem_d_hex: String,
    mlkem_z_hex: String,
    ephemeral_x25519_secret_hex: String,
    mlkem_m_hex: String,
    nonce_hex: String,
    plaintext_hex: String,
    aad_hex: String,
    context_hex: String,
    envelope_bytes: usize,
    envelope_sha256: String,
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().ok().unwrap()
}

fn be16(value: usize) -> [u8; 2] {
    (value as u16).to_be_bytes()
}
fn be32(value: usize) -> [u8; 4] {
    (value as u32).to_be_bytes()
}

#[test]
fn deterministic_vector_matches_independent_transcript_reconstruction() {
    let vector: CheckedVector =
        serde_json::from_str(include_str!("vectors/envelope_v2.json")).unwrap();
    assert_eq!(vector.name, "envelope-v2-deterministic-001");
    assert_eq!(hex::decode(&vector.plaintext_hex).unwrap(), PLAINTEXT);
    assert_eq!(hex::decode(&vector.aad_hex).unwrap(), AAD);
    assert_eq!(hex::decode(&vector.context_hex).unwrap(), CONTEXT);
    let (pk, sk, shared_secret, kem_ct, envelope) = deterministic_envelope(
        array(&vector.recipient_x25519_secret_hex),
        array(&vector.mlkem_d_hex),
        array(&vector.mlkem_z_hex),
        array(&vector.ephemeral_x25519_secret_hex),
        array(&vector.mlkem_m_hex),
        array(&vector.nonce_hex),
        PLAINTEXT,
        AAD,
        CONTEXT,
    )
    .expect("deterministic construction");

    let mut header = [0u8; 98];
    header[..4].copy_from_slice(b"CTD2");
    header[4..10].copy_from_slice(&[2, 0, 0xA3, 0xC1, 0xB1, 0]);
    header[10..12].copy_from_slice(&be16(98));
    header[12..14].copy_from_slice(&be16(1120));
    header[14..22].copy_from_slice(&(PLAINTEXT.len() as u64).to_be_bytes());
    header[22..54].copy_from_slice(&Sha3_256::digest(pk.to_bytes()));
    header[54..86].copy_from_slice(&Sha3_256::digest(CONTEXT));
    header[86..98].fill(0x66);

    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"citadel-envelope-v2/kdf\0");
    transcript.extend_from_slice(&be16(header.len()));
    transcript.extend_from_slice(&header);
    transcript.extend_from_slice(&be16(kem_ct.len()));
    transcript.extend_from_slice(&kem_ct);
    transcript.extend_from_slice(&be32(CONTEXT.len()));
    transcript.extend_from_slice(CONTEXT);

    let salt = Sha256::digest(b"citadel-envelope-v2/extract-salt");
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(&transcript, &mut key).unwrap();

    let mut bound_aad = Vec::new();
    bound_aad.extend_from_slice(b"citadel-envelope-v2/aad\0");
    bound_aad.extend_from_slice(&be16(header.len()));
    bound_aad.extend_from_slice(&header);
    bound_aad.extend_from_slice(&be16(kem_ct.len()));
    bound_aad.extend_from_slice(&kem_ct);
    bound_aad.extend_from_slice(&be32(CONTEXT.len()));
    bound_aad.extend_from_slice(CONTEXT);
    bound_aad.extend_from_slice(&be32(AAD.len()));
    bound_aad.extend_from_slice(AAD);

    let aead = Aes256Gcm::new_from_slice(&key).unwrap();
    let sealed = aead
        .encrypt(
            &Nonce::try_from(&[0x66u8; 12][..]).unwrap(),
            Payload {
                msg: PLAINTEXT,
                aad: &bound_aad,
            },
        )
        .unwrap();
    let mut independent = header.to_vec();
    independent.extend_from_slice(&kem_ct);
    independent.extend_from_slice(&sealed);

    assert_eq!(
        envelope, independent,
        "implementation and independent reconstruction differ"
    );
    assert_eq!(envelope.len(), vector.envelope_bytes);
    assert_eq!(
        hex::encode(Sha256::digest(&envelope)),
        vector.envelope_sha256
    );
    let opened = citadel_envelope::Citadel::new()
        .open(
            &sk,
            &envelope,
            &citadel_envelope::Aad::raw(AAD),
            &citadel_envelope::Context::raw(CONTEXT),
        )
        .unwrap();
    assert_eq!(opened, PLAINTEXT);
}
