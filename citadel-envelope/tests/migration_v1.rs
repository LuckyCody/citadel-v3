use citadel_envelope::{inspect, Aad, Citadel, Context};

#[test]
fn v1_decryption_survives_while_default_seal_is_v2() {
    let engine = Citadel::new();
    let (pk, sk) = engine.generate_keypair();

    for i in 0..64u16 {
        let plaintext = vec![(i & 0xff) as u8; usize::from(i) * 17];
        let aad_bytes = format!("historical-aad-{i}").into_bytes();
        let context_bytes = format!("historical-context-{i}").into_bytes();
        let aad = Aad::raw(&aad_bytes);
        let context = Context::raw(&context_bytes);

        let v1 = engine
            .seal_v1_compat(&pk, &plaintext, &aad, &context)
            .expect("explicit v1 fixture");
        assert_eq!(v1[0], 1);
        assert_eq!(inspect(&v1).expect("inspect v1").version, 1);
        assert_eq!(
            engine.open(&sk, &v1, &aad, &context).expect("migrate v1"),
            plaintext
        );

        let v2 = engine
            .seal(&pk, &plaintext, &aad, &context)
            .expect("default v2");
        assert!(v2.starts_with(b"CTD2"));
        assert_eq!(
            engine.open(&sk, &v2, &aad, &context).expect("open v2"),
            plaintext
        );
    }
}

#[test]
fn malformed_v2_never_falls_back_to_v1() {
    let engine = Citadel::new();
    let (pk, sk) = engine.generate_keypair();
    let aad = Aad::raw(b"aad");
    let context = Context::raw(b"context");
    let mut v2 = engine.seal(&pk, b"data", &aad, &context).unwrap();

    v2[4] = 1;
    assert!(v2.starts_with(b"CTD2"));
    assert!(engine.open(&sk, &v2, &aad, &context).is_err());
}
