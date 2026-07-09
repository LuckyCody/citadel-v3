// SPDX-License-Identifier: AGPL-3.0-or-later
//! Storage backends: where key metadata and material live.

use crate::error::KeystoreError;
use crate::types::{KeyId, KeyMetadata, KeyState};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

/// Backend for persisting key metadata.
///
/// Implement this for your infrastructure:
/// - InMemoryBackend (testing)
/// - FileBackend (development)
/// - Your database (production)
/// - HSM wrapper (compliance)
pub trait StorageBackend: Send + Sync {
    fn get(&self, id: &KeyId) -> Result<Option<KeyMetadata>, KeystoreError>;
    fn put(&self, meta: &KeyMetadata) -> Result<(), KeystoreError>;
    fn delete(&self, id: &KeyId) -> Result<(), KeystoreError>;
    fn list(&self) -> Result<Vec<KeyMetadata>, KeystoreError>;
    fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError>;
    fn list_by_parent(&self, parent_id: &KeyId) -> Result<Vec<KeyMetadata>, KeystoreError>;

    /// Overwrite the key file with zeros before writing the Destroyed marker.
    ///
    /// This is a best-effort measure against forensic recovery from disk.
    /// It does not protect against SSD wear-leveling, filesystem journals,
    /// snapshots, or backups — those require HSM or full-disk encryption.
    /// Default implementation is a no-op (correct for in-memory backends).
    fn overwrite_key_file(&self, _id: &KeyId) -> Result<(), KeystoreError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

/// In-memory storage (for testing and ephemeral use).
pub struct InMemoryBackend {
    keys: RwLock<HashMap<String, KeyMetadata>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn get(&self, id: &KeyId) -> Result<Option<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys.get(id.as_str()).cloned())
    }

    fn put(&self, meta: &KeyMetadata) -> Result<(), KeystoreError> {
        let mut keys = self.keys.write().unwrap();
        keys.insert(meta.id.as_str().to_string(), meta.clone());
        Ok(())
    }

    fn delete(&self, id: &KeyId) -> Result<(), KeystoreError> {
        let mut keys = self.keys.write().unwrap();
        keys.remove(id.as_str());
        Ok(())
    }

    fn list(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys.values().cloned().collect())
    }

    fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys
            .values()
            .filter(|k| k.state == state)
            .cloned()
            .collect())
    }

    fn list_by_parent(&self, parent_id: &KeyId) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let keys = self.keys.read().unwrap();
        Ok(keys
            .values()
            .filter(|k| k.parent_id.as_ref() == Some(parent_id))
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// File backend
// ---------------------------------------------------------------------------

/// Write `data` to `path` with owner-only read/write permissions (0600 on Unix).
///
/// Uses `OpenOptions` with an explicit mode to avoid the umask-dependent default
/// of `std::fs::write()`. On non-Unix platforms falls back to default OS permissions.
/// Always calls `sync_all()` before returning to ensure durability.
fn write_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // owner read+write only - key material must not be world-readable
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }
}

/// File-based storage (one JSON file per key).
///
/// Directory layout:
/// ```text
/// keys/
///   {key_id}.json
/// ```
pub struct FileBackend {
    dir: PathBuf,
}

impl FileBackend {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, KeystoreError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| KeystoreError::StorageError(format!("create dir: {}", e)))?;

        // Restrict the directory to owner-only access (0700) so that key file
        // names are not visible to other users even before individual files are
        // written. This complements the 0600 file permissions on each key file.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&dir, perms)
                .map_err(|e| KeystoreError::StorageError(format!("set dir permissions: {}", e)))?;
        }

        Ok(Self { dir })
    }

    fn key_path(&self, id: &KeyId) -> PathBuf {
        self.dir.join(format!("{}.json", id.as_str()))
    }

    fn read_key_file(&self, path: &Path) -> Result<KeyMetadata, KeystoreError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| KeystoreError::StorageError(format!("read: {}", e)))?;
        serde_json::from_str(&data)
            .map_err(|e| KeystoreError::StorageError(format!("parse: {}", e)))
    }
}

impl StorageBackend for FileBackend {
    fn get(&self, id: &KeyId) -> Result<Option<KeyMetadata>, KeystoreError> {
        let path = self.key_path(id);
        if !path.exists() {
            return Ok(None);
        }
        self.read_key_file(&path).map(Some)
    }

    fn put(&self, meta: &KeyMetadata) -> Result<(), KeystoreError> {
        let path = self.key_path(&meta.id);
        let json = serde_json::to_string_pretty(meta)
            .map_err(|e| KeystoreError::StorageError(format!("serialize: {}", e)))?;
        // Atomic write: write to temp file with restricted permissions (0600), then rename.
        // This ensures the final file is never visible to other users in a partial state.
        let tmp = path.with_extension("tmp");
        write_restricted(&tmp, json.as_bytes())
            .map_err(|e| KeystoreError::StorageError(format!("write: {}", e)))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| KeystoreError::StorageError(format!("rename: {}", e)))?;

        // fsync the parent directory so the rename (directory entry change) is
        // durable on crash. Without this, the rename may not survive a power failure.
        #[cfg(unix)]
        {
            if let Some(parent) = path.parent() {
                let dir_file = std::fs::File::open(parent)
                    .map_err(|e| KeystoreError::StorageError(format!("open dir: {}", e)))?;
                dir_file
                    .sync_all()
                    .map_err(|e| KeystoreError::StorageError(format!("dir fsync: {}", e)))?;
            }
        }

        Ok(())
    }

    fn delete(&self, id: &KeyId) -> Result<(), KeystoreError> {
        let path = self.key_path(id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| KeystoreError::StorageError(format!("delete: {}", e)))?;
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let mut keys = Vec::new();
        let entries = std::fs::read_dir(&self.dir)
            .map_err(|e| KeystoreError::StorageError(format!("readdir: {}", e)))?;
        for entry in entries {
            let entry = entry.map_err(|e| KeystoreError::StorageError(format!("entry: {}", e)))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                keys.push(self.read_key_file(&path)?);
            }
        }
        Ok(keys)
    }

    fn list_by_state(&self, state: KeyState) -> Result<Vec<KeyMetadata>, KeystoreError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|k| k.state == state)
            .collect())
    }

    fn list_by_parent(&self, parent_id: &KeyId) -> Result<Vec<KeyMetadata>, KeystoreError> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|k| k.parent_id.as_ref() == Some(parent_id))
            .collect())
    }

    fn overwrite_key_file(&self, id: &KeyId) -> Result<(), KeystoreError> {
        let path = self.key_path(id);
        if !path.exists() {
            return Ok(());
        }
        let file_len = std::fs::metadata(&path)
            .map_err(|e| KeystoreError::StorageError(format!("metadata: {}", e)))?
            .len() as usize;
        if file_len == 0 {
            return Ok(());
        }
        // Overwrite with zeros — best-effort against forensic recovery.
        // Does not protect against SSD wear-leveling or filesystem journals.
        write_restricted(&path, &vec![0u8; file_len])
            .map_err(|e| KeystoreError::StorageError(format!("overwrite: {}", e)))?;
        // fsync parent directory so the overwrite is durable before we continue.
        #[cfg(unix)]
        {
            if let Some(parent) = path.parent() {
                let dir_file = std::fs::File::open(parent)
                    .map_err(|e| KeystoreError::StorageError(format!("open dir: {}", e)))?;
                dir_file
                    .sync_all()
                    .map_err(|e| KeystoreError::StorageError(format!("dir fsync: {}", e)))?;
            }
        }
        Ok(())
    }
}
