use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use lantern_types::{Hash32, NetworkId};
use rocksdb::checkpoint::Checkpoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CommitMetadataV1, Error, Result, RocksStore, STORE_SCHEMA_VERSION, StoreIdentityV1};

/// Version of the external checkpoint manifest format.
pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const CHECKPOINT_DIRECTORY: &str = "db";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 1024 * 1024;
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Digest entry for one regular file in a `RocksDB` checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFileDigestV1 {
    /// UTF-8 path relative to the checkpoint's `db/` directory.
    pub path: String,
    /// Exact file size in bytes.
    pub size: u64,
    /// Lower-case SHA-256 digest.
    pub sha256: String,
}

/// Self-contained manifest binding a physical `RocksDB` checkpoint to Lantern state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifestV1 {
    /// External manifest format version.
    pub snapshot_format_version: u32,
    /// M1 database schema version.
    pub store_schema_version: u32,
    /// Chain identifier bound by the database identity.
    pub chain_id: String,
    /// Last committed application height.
    pub app_height: u64,
    /// `AppHash` returned to `CometBFT`.
    pub app_hash: String,
    /// Latest authenticated-map root.
    pub latest_root: String,
    /// Append-only history root.
    pub history_root: String,
    /// Number of history leaves.
    pub history_size: u64,
    /// Last closed epoch.
    pub last_closed_epoch: u64,
    /// Head ID for the last closed epoch, if one exists.
    pub last_closed_head_id: Option<String>,
    /// Active validator-configuration hash.
    pub validator_config_hash: String,
    /// Deterministic application configuration hash.
    pub config_hash: String,
    /// Sorted digests of every regular `RocksDB` checkpoint file.
    pub files: Vec<SnapshotFileDigestV1>,
}

impl SnapshotManifestV1 {
    fn from_state(
        identity: &StoreIdentityV1,
        metadata: &CommitMetadataV1,
        files: Vec<SnapshotFileDigestV1>,
    ) -> Self {
        Self {
            snapshot_format_version: SNAPSHOT_FORMAT_VERSION,
            store_schema_version: STORE_SCHEMA_VERSION,
            chain_id: identity.chain_id().as_str().to_owned(),
            app_height: metadata.app_height,
            app_hash: metadata.app_hash.to_hex(),
            latest_root: metadata.latest_root.to_hex(),
            history_root: metadata.history_root.to_hex(),
            history_size: metadata.history_size,
            last_closed_epoch: metadata.last_closed_epoch,
            last_closed_head_id: metadata.last_closed_head_id.map(Hash32::to_hex),
            validator_config_hash: metadata.validator_config_hash.to_hex(),
            config_hash: metadata.config_hash.to_hex(),
            files,
        }
    }

    /// Serializes the deterministic, human-readable manifest representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory manifest cannot be serialized.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|error| Error::Json(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns a height-key suitable for the `snapshots_manifest` column family.
    #[must_use]
    pub const fn archive_key(&self) -> [u8; 8] {
        self.app_height.to_be_bytes()
    }

    fn validate(&self, expected: &StoreIdentityV1) -> Result<()> {
        if self.snapshot_format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(Error::Checkpoint(format!(
                "snapshot format {} is not supported",
                self.snapshot_format_version
            )));
        }
        if self.store_schema_version != STORE_SCHEMA_VERSION {
            return Err(Error::Checkpoint(format!(
                "store schema {} is not supported",
                self.store_schema_version
            )));
        }
        let chain_id = NetworkId::new(self.chain_id.clone())
            .map_err(|error| Error::Checkpoint(format!("invalid chain ID: {error}")))?;
        if &chain_id != expected.chain_id() {
            return Err(Error::Checkpoint(format!(
                "snapshot chain ID {chain_id} does not match expected {}",
                expected.chain_id()
            )));
        }
        validate_hash("AppHash", &self.app_hash)?;
        validate_hash("latest root", &self.latest_root)?;
        validate_hash("history root", &self.history_root)?;
        validate_hash("validator config hash", &self.validator_config_hash)?;
        let config_hash = validate_hash("config hash", &self.config_hash)?;
        if config_hash != expected.config_hash() {
            return Err(Error::Checkpoint(format!(
                "snapshot config hash {config_hash} does not match expected {}",
                expected.config_hash()
            )));
        }
        match (&self.last_closed_head_id, self.last_closed_epoch) {
            (None, 0) => {}
            (Some(head), 1..) => {
                validate_hash("closed HeadID", head)?;
            }
            (None, 1..) => {
                return Err(Error::Checkpoint(
                    "closed HeadID is absent after the first epoch".to_owned(),
                ));
            }
            (Some(_), 0) => {
                return Err(Error::Checkpoint(
                    "closed HeadID is present at epoch zero".to_owned(),
                ));
            }
        }
        if self.files.is_empty() {
            return Err(Error::Checkpoint(
                "checkpoint file digest list is empty".to_owned(),
            ));
        }
        let mut previous: Option<&str> = None;
        let mut seen = BTreeSet::new();
        for file in &self.files {
            validate_relative_path(&file.path)?;
            validate_hex_digest("checkpoint file", &file.sha256)?;
            if previous.is_some_and(|path| path >= file.path.as_str()) {
                return Err(Error::Checkpoint(
                    "checkpoint file entries are not strictly sorted".to_owned(),
                ));
            }
            if !seen.insert(file.path.as_str()) {
                return Err(Error::Checkpoint(format!(
                    "duplicate checkpoint path {}",
                    file.path
                )));
            }
            previous = Some(&file.path);
        }
        Ok(())
    }
}

/// A checkpoint whose manifest, file set, sizes, digests, chain, and schema are valid.
#[derive(Debug)]
pub struct VerifiedCheckpoint {
    root: PathBuf,
    manifest: SnapshotManifestV1,
}

impl VerifiedCheckpoint {
    /// Returns the verified snapshot root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the verified manifest.
    #[must_use]
    pub const fn manifest(&self) -> &SnapshotManifestV1 {
        &self.manifest
    }
}

impl RocksStore {
    /// Creates a `RocksDB` checkpoint and atomically publishes its digest manifest.
    ///
    /// The commit/checkpoint coordination lock is held while reading commit
    /// metadata and constructing the checkpoint, so the manifest cannot race a
    /// block commit.
    ///
    /// # Errors
    ///
    /// Returns an error if no block is committed, the target already exists, a
    /// file is not regular UTF-8-addressable data, or any I/O/RocksDB operation
    /// fails.
    pub fn create_checkpoint(&self, target: impl AsRef<Path>) -> Result<SnapshotManifestV1> {
        let target = target.as_ref();
        ensure_absent(target, "checkpoint target")?;
        let parent = parent_directory(target)?;
        fs::create_dir_all(parent)
            .map_err(|error| Error::io("create checkpoint parent", parent, error))?;
        let staging = staging_path(target, "create")?;
        ensure_absent(&staging, "checkpoint staging directory")?;
        fs::create_dir(&staging)
            .map_err(|error| Error::io("create checkpoint staging directory", &staging, error))?;

        let result = (|| {
            let _guard = self.lock_coordination()?;
            let metadata = self.current_metadata()?.ok_or_else(|| {
                Error::Checkpoint("cannot snapshot before the first block commit".to_owned())
            })?;
            let checkpoint_directory = staging.join(CHECKPOINT_DIRECTORY);
            Checkpoint::new(&self.db)?.create_checkpoint(&checkpoint_directory)?;
            let files = collect_file_digests(&checkpoint_directory)?;
            let manifest = SnapshotManifestV1::from_state(&self.identity, &metadata, files);
            manifest.validate(&self.identity)?;
            let manifest_path = staging.join(MANIFEST_FILE);
            write_synced_file(&manifest_path, &manifest.to_json_bytes()?)?;
            sync_directory_tree(&staging)?;
            fs::rename(&staging, target)
                .map_err(|error| Error::io("publish checkpoint", target, error))?;
            sync_directory(parent)?;
            Ok(manifest)
        })();

        if result.is_err() {
            cleanup_staging(&staging);
        }
        result
    }

    /// Verifies a checkpoint without modifying it or a live database.
    ///
    /// # Errors
    ///
    /// Rejects malformed/oversized manifests, wrong chain/schema/config,
    /// traversal paths, symlinks, missing/extra files, size mismatches, or digest
    /// mismatches.
    pub fn verify_checkpoint(
        snapshot_root: impl AsRef<Path>,
        expected: &StoreIdentityV1,
    ) -> Result<VerifiedCheckpoint> {
        let snapshot_root = snapshot_root.as_ref();
        let manifest_path = snapshot_root.join(MANIFEST_FILE);
        let manifest_metadata = fs::metadata(&manifest_path)
            .map_err(|error| Error::io("read snapshot manifest metadata", &manifest_path, error))?;
        if manifest_metadata.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Checkpoint(format!(
                "snapshot manifest is {} bytes; limit is {MAX_MANIFEST_BYTES}",
                manifest_metadata.len()
            )));
        }
        let bytes = fs::read(&manifest_path)
            .map_err(|error| Error::io("read snapshot manifest", &manifest_path, error))?;
        let manifest: SnapshotManifestV1 =
            serde_json::from_slice(&bytes).map_err(|error| Error::Json(error.to_string()))?;
        manifest.validate(expected)?;
        let checkpoint_directory = snapshot_root.join(CHECKPOINT_DIRECTORY);
        let actual = collect_file_digests(&checkpoint_directory)?;
        if actual != manifest.files {
            return Err(Error::Checkpoint(
                "checkpoint file set, size, or digest differs from the manifest".to_owned(),
            ));
        }
        Ok(VerifiedCheckpoint {
            root: snapshot_root.to_path_buf(),
            manifest,
        })
    }

    /// Verifies and atomically restores a checkpoint into a new database path.
    ///
    /// # Errors
    ///
    /// The destination must not exist. The destination remains absent for every
    /// validation/copy/open failure before the final directory rename.
    pub fn restore_checkpoint(
        snapshot_root: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        expected: &StoreIdentityV1,
    ) -> Result<Self> {
        let verified = Self::verify_checkpoint(snapshot_root, expected)?;
        let destination = destination.as_ref();
        ensure_absent(destination, "restore destination")?;
        let parent = parent_directory(destination)?;
        fs::create_dir_all(parent)
            .map_err(|error| Error::io("create restore parent", parent, error))?;
        let staging = staging_path(destination, "restore")?;
        ensure_absent(&staging, "restore staging directory")?;

        let result = (|| {
            copy_directory_tree(&verified.root.join(CHECKPOINT_DIRECTORY), &staging)?;
            sync_directory_tree(&staging)?;
            {
                let staged_store = Self::open(&staging, expected)?;
                verify_database_metadata(&staged_store, verified.manifest())?;
            }
            fs::rename(&staging, destination)
                .map_err(|error| Error::io("publish restored database", destination, error))?;
            sync_directory(parent)?;
            Self::open(destination, expected)
        })();

        if result.is_err() {
            cleanup_staging(&staging);
        }
        result
    }
}

fn verify_database_metadata(store: &RocksStore, manifest: &SnapshotManifestV1) -> Result<()> {
    let metadata = store
        .current_metadata()?
        .ok_or_else(|| Error::Checkpoint("restored database has no commit metadata".to_owned()))?;
    let expected =
        SnapshotManifestV1::from_state(store.identity(), &metadata, manifest.files.clone());
    if expected != *manifest {
        return Err(Error::Checkpoint(
            "manifest state does not match the restored database metadata".to_owned(),
        ));
    }
    Ok(())
}

fn validate_hash(label: &str, value: &str) -> Result<Hash32> {
    validate_hex_digest(label, value)?;
    Hash32::from_str(value).map_err(|error| Error::Checkpoint(format!("invalid {label}: {error}")))
}

fn validate_hex_digest(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Checkpoint(format!(
            "{label} must be 64 lower-case hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::Checkpoint(format!(
            "checkpoint path is not a safe relative path: {value:?}"
        )));
    }
    Ok(())
}

fn collect_file_digests(root: &Path) -> Result<Vec<SnapshotFileDigestV1>> {
    if !root.is_dir() {
        return Err(Error::Checkpoint(format!(
            "checkpoint database directory does not exist: {}",
            root.display()
        )));
    }
    let mut files = Vec::new();
    collect_file_digests_recursive(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_file_digests_recursive(
    root: &Path,
    directory: &Path,
    files: &mut Vec<SnapshotFileDigestV1>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| Error::io("read checkpoint directory", directory, error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::io("read checkpoint directory entry", directory, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| Error::io("read checkpoint file metadata", &path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Checkpoint(format!(
                "checkpoint contains a symlink: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            collect_file_digests_recursive(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path.strip_prefix(root).map_err(|error| {
                Error::Checkpoint(format!("checkpoint path is outside root: {error}"))
            })?;
            let relative = path_to_manifest_string(relative)?;
            files.push(SnapshotFileDigestV1 {
                path: relative,
                size: metadata.len(),
                sha256: digest_file(&path)?,
            });
        } else {
            return Err(Error::Checkpoint(format!(
                "checkpoint contains a non-file entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn path_to_manifest_string(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(Error::Checkpoint(format!(
                "checkpoint path contains a forbidden component: {}",
                path.display()
            )));
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| {
                    Error::Checkpoint(format!("checkpoint path is not UTF-8: {}", path.display()))
                })?
                .to_owned(),
        );
    }
    Ok(parts.join("/"))
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).map_err(|error| Error::io("open file for hashing", path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::io("hash checkpoint file", path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn copy_directory_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)
        .map_err(|error| Error::io("create restore staging directory", destination, error))?;
    copy_directory_contents(source, destination)
}

fn copy_directory_contents(source: &Path, destination: &Path) -> Result<()> {
    let mut entries = fs::read_dir(source)
        .map_err(|error| Error::io("read checkpoint for restore", source, error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::io("read checkpoint entry for restore", source, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| Error::io("read restore source metadata", &source_path, error))?;
        if metadata.is_dir() {
            fs::create_dir(&destination_path).map_err(|error| {
                Error::io(
                    "create restored checkpoint directory",
                    &destination_path,
                    error,
                )
            })?;
            copy_directory_contents(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path)
                .map_err(|error| Error::io("copy checkpoint file", &destination_path, error))?;
            File::open(&destination_path)
                .and_then(|file| file.sync_all())
                .map_err(|error| {
                    Error::io("sync restored checkpoint file", &destination_path, error)
                })?;
        } else {
            return Err(Error::Checkpoint(format!(
                "restore source contains a non-regular entry: {}",
                source_path.display()
            )));
        }
    }
    Ok(())
}

fn sync_directory_tree(directory: &Path) -> Result<()> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| Error::io("read directory for sync", directory, error))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::io("read directory entry for sync", directory, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| Error::io("read sync target metadata", &path, error))?;
        if metadata.is_dir() {
            sync_directory_tree(&path)?;
        } else if metadata.is_file() {
            File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|error| Error::io("sync checkpoint file", &path, error))?;
        }
    }
    sync_directory(directory)
}

fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| Error::io("sync directory", directory, error))
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path).map_err(|error| Error::io("create manifest", path, error))?;
    file.write_all(bytes)
        .map_err(|error| Error::io("write manifest", path, error))?;
    file.sync_all()
        .map_err(|error| Error::io("sync manifest", path, error))
}

fn ensure_absent(path: &Path, label: &str) -> Result<()> {
    if path.exists() {
        return Err(Error::Checkpoint(format!(
            "{label} already exists: {}",
            path.display()
        )));
    }
    Ok(())
}

fn parent_directory(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            Error::Checkpoint(format!(
                "path has no usable parent directory: {}",
                path.display()
            ))
        })
}

fn staging_path(target: &Path, operation: &str) -> Result<PathBuf> {
    let parent = parent_directory(target)?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::Checkpoint(format!(
                "target name is not valid UTF-8: {}",
                target.display()
            ))
        })?;
    let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(parent.join(format!(
        ".{name}.lantern-{operation}-{}-{counter}.tmp",
        std::process::id()
    )))
}

fn cleanup_staging(staging: &Path) {
    if staging.is_dir() {
        let _ignored = fs::remove_dir_all(staging);
    } else if staging.is_file() {
        let _ignored = fs::remove_file(staging);
    }
}
