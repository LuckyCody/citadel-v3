#![cfg(target_os = "linux")]

use citadel_keystore::{
    create_backup_with_provider, restore_backup_with_provider, InMemoryAuditSink, InMemoryBackend,
    KeyType, Keystore, LinuxFileRootKeyProvider, LocalPilotConfig, RootKeyProvider,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::Arc;

fn secure_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod dir");
    dir
}

#[test]
fn creates_owner_only_key_and_round_trips_provider_load() {
    let dir = secure_dir();
    let path = dir.path().join("root.key");
    let provider = LinuxFileRootKeyProvider::create(&path).expect("create provider");
    let first = provider.load_root_key().expect("load key");
    let reopened = LinuxFileRootKeyProvider::open(&path).expect("reopen provider");
    let second = reopened.load_root_key().expect("reload key");

    assert_eq!(first.as_ref(), second.as_ref());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(LinuxFileRootKeyProvider::create(&path).is_err());
}

#[test]
fn rejects_insecure_permissions_symlink_and_wrong_length() {
    let dir = secure_dir();

    let insecure = dir.path().join("insecure.key");
    fs::write(&insecure, [7u8; 32]).unwrap();
    fs::set_permissions(&insecure, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(LinuxFileRootKeyProvider::open(&insecure).is_err());

    let short = dir.path().join("short.key");
    fs::write(&short, [9u8; 31]).unwrap();
    fs::set_permissions(&short, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(LinuxFileRootKeyProvider::open(&short).is_err());

    let link = dir.path().join("root.link");
    symlink(&short, &link).unwrap();
    assert!(LinuxFileRootKeyProvider::open(&link).is_err());

    let weak = dir.path().join("weak.key");
    fs::write(&weak, [0u8; 32]).unwrap();
    fs::set_permissions(&weak, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(LinuxFileRootKeyProvider::open(&weak).is_err());

    let read_only = dir.path().join("read-only.key");
    fs::write(
        &read_only,
        [
            0x91, 0x12, 0x73, 0x44, 0x35, 0xa6, 0x27, 0x58, 0x49, 0xba, 0x6b, 0x7c, 0x8d, 0x1e,
            0x2f, 0x30, 0x41, 0x52, 0x63, 0x74, 0x85, 0x96, 0xa7, 0xb8, 0xc9, 0xda, 0xeb, 0xfc,
            0x0d, 0x2e, 0x4f, 0x60,
        ],
    )
    .unwrap();
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(LinuxFileRootKeyProvider::open(&read_only).is_ok());

    let hard_link = dir.path().join("hard-link.key");
    fs::hard_link(&read_only, &hard_link).unwrap();
    assert!(LinuxFileRootKeyProvider::open(&read_only).is_err());
    assert!(LinuxFileRootKeyProvider::open(&hard_link).is_err());
}

#[tokio::test]
async fn provider_backed_keystore_wraps_root_material() {
    let dir = secure_dir();
    let provider = LinuxFileRootKeyProvider::create(dir.path().join("root.key")).unwrap();
    let storage = Arc::new(InMemoryBackend::new());
    let audit = Arc::new(InMemoryAuditSink::new());
    let keystore = Keystore::with_root_key_provider(storage, audit, &provider).unwrap();

    assert_eq!(keystore.root_key_provider_name(), Some("linux-file-v1"));

    let root = keystore
        .generate("pilot-root", KeyType::Root, None, None)
        .await
        .expect("generate root");
    keystore.activate(&root).await.expect("activate root");
    keystore.rotate(&root).await.expect("rotate logical root");
    let metadata = keystore.get(&root).await.expect("read root");
    assert_eq!(metadata.current_version, 2);
    assert!(metadata.versions.iter().all(|version| matches!(
        &version.secret_key_material,
        citadel_keystore::SecretKeyMaterial::Encrypted(_)
    )));

    let backup = create_backup_with_provider(&[metadata], &provider).expect("create backup");
    let restored = restore_backup_with_provider(&backup, &provider).expect("restore backup");
    assert_eq!(restored.len(), 1);

    let wrong_provider = LinuxFileRootKeyProvider::create(dir.path().join("wrong.key")).unwrap();
    assert!(restore_backup_with_provider(&backup, &wrong_provider).is_err());
}

#[test]
fn local_pilot_rejects_environment_root_and_development_escapes() {
    let valid = LocalPilotConfig::validate_pairs([
        ("CITADEL_PROFILE", "local-pilot"),
        ("CITADEL_ROOT_KEY_FILE", "/var/lib/citadel/root.key"),
        ("CITADEL_REPLAY_STORE", "file"),
    ])
    .expect("valid local pilot config");
    assert_eq!(
        valid.root_key_file.to_string_lossy(),
        "/var/lib/citadel/root.key"
    );

    for forbidden in [
        "CITADEL_MASTER_KEY",
        "CITADEL_ALLOW_PLAINTEXT_KEYS",
        "CITADEL_ALLOW_FLAT_DEKS",
        "CITADEL_API_KEY",
    ] {
        let result = LocalPilotConfig::validate_pairs([
            ("CITADEL_PROFILE", "local-pilot"),
            ("CITADEL_ROOT_KEY_FILE", "/var/lib/citadel/root.key"),
            ("CITADEL_REPLAY_STORE", "file"),
            (forbidden, "1"),
        ]);
        assert!(result.is_err(), "{forbidden} must fail closed");
    }

    assert!(LocalPilotConfig::validate_pairs([
        ("CITADEL_PROFILE", "local-pilot"),
        ("CITADEL_ROOT_KEY_FILE", "/var/lib/citadel/root.key"),
        ("CITADEL_REPLAY_STORE", "file"),
        ("CITADEL_ENV", "development"),
    ])
    .is_err());
}
