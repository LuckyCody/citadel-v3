use citadel_envelope::{inspect, Aad, Citadel, Context};

const V2_MAGIC: &[u8; 4] = b"CTD2";

#[test]
fn default_seal_emits_v2_and_round_trips() {
    let engine = Citadel::new();
    let (pk, sk) = engine.generate_keypair();
    let aad = Aad::raw(b"packet-007/aad");
    let context = Context::raw(b"packet-007/context");
    let plaintext = b"Citadel envelope v2 convergence baseline";

    let ciphertext = engine
        .seal(&pk, plaintext, &aad, &context)
        .expect("v2 seal");

    assert_eq!(&ciphertext[..4], V2_MAGIC, "default seal must emit v2");
    assert_eq!(ciphertext[4], 2, "v2 version byte");

    let info = inspect(&ciphertext).expect("inspect v2");
    assert_eq!(info.version, 2);
    assert!(!info.streaming);
    assert_eq!(info.plaintext_bytes, plaintext.len());

    let opened = engine
        .open(&sk, &ciphertext, &aad, &context)
        .expect("v2 open");
    assert_eq!(opened, plaintext);
}

fn fixture() -> (
    Citadel,
    citadel_envelope::PublicKey,
    citadel_envelope::SecretKey,
    Aad,
    Context,
    Vec<u8>,
) {
    let engine = Citadel::new();
    let (pk, sk) = engine.generate_keypair();
    let aad = Aad::raw(b"packet-007/bound-aad");
    let context = Context::raw(b"packet-007/bound-context");
    let ciphertext = engine
        .seal(
            &pk,
            b"the entire transcript is authenticated",
            &aad,
            &context,
        )
        .unwrap();
    (engine, pk, sk, aad, context, ciphertext)
}

#[test]
fn every_v2_region_is_bound_or_strictly_parsed() {
    let (engine, _pk, sk, aad, context, ciphertext) = fixture();
    let mutation_offsets = [
        0usize,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        12,
        14,
        21,
        22,
        53,
        54,
        85,
        86,
        97,
        98,
        129,
        130,
        1217,
        1218,
        ciphertext.len() - 1,
    ];

    for offset in mutation_offsets {
        let mut changed = ciphertext.clone();
        changed[offset] ^= 0x01;
        assert!(
            engine.open(&sk, &changed, &aad, &context).is_err(),
            "mutation at offset {offset} was accepted"
        );
    }
}

#[test]
fn caller_inputs_recipient_and_boundaries_fail_closed() {
    let (engine, _pk, sk, aad, context, ciphertext) = fixture();
    let (_, wrong_sk) = engine.generate_keypair();

    assert!(engine
        .open(
            &sk,
            &ciphertext,
            &Aad::raw(b"packet-007/wrong-aad"),
            &context
        )
        .is_err());
    assert!(engine
        .open(
            &sk,
            &ciphertext,
            &aad,
            &Context::raw(b"packet-007/wrong-context")
        )
        .is_err());
    assert!(engine.open(&wrong_sk, &ciphertext, &aad, &context).is_err());

    let mut trailing = ciphertext.clone();
    trailing.push(0);
    assert!(engine.open(&sk, &trailing, &aad, &context).is_err());

    for end in [0usize, 1, 4, 14, 97, 98, 1217, 1218, ciphertext.len() - 1] {
        assert!(
            engine
                .open(&sk, &ciphertext[..end], &aad, &context)
                .is_err(),
            "truncation at {end} was accepted"
        );
    }
}

#[test]
fn downgrade_confusion_and_noncontributory_x25519_are_rejected() {
    let (engine, _pk, sk, aad, context, ciphertext) = fixture();

    let mut stripped_magic = ciphertext.clone();
    stripped_magic[0] = 1;
    assert!(engine.open(&sk, &stripped_magic, &aad, &context).is_err());

    let mut version_substitution = ciphertext.clone();
    version_substitution[4] = 1;
    assert!(engine
        .open(&sk, &version_substitution, &aad, &context)
        .is_err());

    let mut legacy_stream_prefix = ciphertext.clone();
    legacy_stream_prefix[..4].copy_from_slice(&[2, 1, 0xA3, 0xB1]);
    assert!(engine
        .open(&sk, &legacy_stream_prefix, &aad, &context)
        .is_err());

    // Non-contributory X25519: every entry of the standard Curve25519 low-order
    // encoded-input blacklist, spliced into the ephemeral slot (bytes 98..130), must be
    // rejected end-to-end by open(). Isolation of the contributory guard itself is
    // covered by the KEM-level unit tests in kem.rs; this is envelope-level
    // defense-in-depth that also pins the wire offsets.
    let hex32 = |s: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    };
    for point in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ] {
        let mut bad = ciphertext.clone();
        bad[98..130].copy_from_slice(&hex32(point));
        assert!(
            engine.open(&sk, &bad, &aad, &context).is_err(),
            "low-order X25519 ephemeral {point} must be rejected end-to-end"
        );
    }
}

#[test]
fn input_limits_are_enforced_before_sealing() {
    let engine = Citadel::new();
    let (pk, _) = engine.generate_keypair();
    let too_much_aad = Aad::raw(&vec![0u8; 65_537]);
    let too_much_context = Context::raw(&vec![0u8; 4_097]);

    assert!(engine
        .seal(&pk, b"data", &too_much_aad, &Context::empty())
        .is_err());
    assert!(engine
        .seal(&pk, b"data", &Aad::empty(), &too_much_context)
        .is_err());
}

#[test]
fn deterministic_property_campaign_rejects_truncation_and_random_mutation() {
    let (engine, _pk, sk, aad, context, ciphertext) = fixture();

    // Every strict prefix is invalid. The parser must reject from length data
    // alone and must never accept an attacker-selected shorter representation.
    for end in 0..ciphertext.len() {
        assert!(engine
            .open(&sk, &ciphertext[..end], &aad, &context)
            .is_err());
    }

    // Reproducible mutation campaign spanning the complete envelope. Multiple
    // byte flips model parser and authentication mutations beyond hand-picked
    // offsets without introducing a network-fetched property-test dependency.
    let mut state = 0x4d595df4d0f33173u64;
    for case in 0..2_048usize {
        let mut changed = ciphertext.clone();
        let flips = 1 + case % 4;
        for _ in 0..flips {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let offset = (state as usize) % changed.len();
            let bit = 1u8 << ((state >> 61) as u8);
            changed[offset] ^= bit;
        }
        assert!(
            engine.open(&sk, &changed, &aad, &context).is_err(),
            "mutation campaign case {case} was accepted"
        );
    }
}
