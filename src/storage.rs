//! Mounted-filesystem discovery without treating host-local mount paths as identity.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, StorageDiscoveryError>;

#[derive(Debug, Error)]
pub enum StorageDiscoveryError {
    #[error("cannot resolve storage path {path}: {source}")]
    Canonicalize {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("storage path must be a directory: {0}")]
    NotDirectory(PathBuf),
    #[error("findmnt is required for mounted-filesystem discovery but could not be run: {0}")]
    FindmntUnavailable(std::io::Error),
    #[error("findmnt could not identify the mounted filesystem for {path}: {message}")]
    FindmntFailed { path: PathBuf, message: String },
    #[error("findmnt returned invalid JSON: {0}")]
    InvalidOutput(serde_json::Error),
    #[error("findmnt returned no mounted filesystem for {0}")]
    NoFilesystem(PathBuf),
    #[error("findmnt returned multiple mounted filesystems for {0}")]
    AmbiguousFilesystem(PathBuf),
    #[error("mounted root {mount_root} does not contain requested path {path}")]
    InvalidMountRoot { mount_root: PathBuf, path: PathBuf },
}

impl StorageDiscoveryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Canonicalize { .. } => "storage_path_unavailable",
            Self::NotDirectory(_) => "storage_path_not_directory",
            Self::FindmntUnavailable(_) => "findmnt_unavailable",
            Self::FindmntFailed { .. } => "findmnt_failed",
            Self::InvalidOutput(_) => "findmnt_invalid_output",
            Self::NoFilesystem(_) => "filesystem_not_found",
            Self::AmbiguousFilesystem(_) => "filesystem_ambiguous",
            Self::InvalidMountRoot { .. } => "mount_root_invalid",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MountedFilesystem {
    pub path: PathBuf,
    pub mount_root: PathBuf,
    pub relative_path: PathBuf,
    pub source: Option<String>,
    pub filesystem_type: Option<String>,
    pub filesystem_fingerprint: Option<String>,
    pub fingerprint_kind: Option<String>,
    pub identity_state: String,
}

#[derive(Debug, Deserialize)]
struct FindmntOutput {
    filesystems: Vec<FindmntFilesystem>,
}

#[derive(Debug, Deserialize)]
struct FindmntFilesystem {
    target: PathBuf,
    source: Option<String>,
    fstype: Option<String>,
    uuid: Option<String>,
    partuuid: Option<String>,
}

pub fn discover_mounted_filesystem(path: impl AsRef<Path>) -> Result<MountedFilesystem> {
    let requested = path.as_ref();
    let canonical =
        std::fs::canonicalize(requested).map_err(|source| StorageDiscoveryError::Canonicalize {
            path: requested.to_path_buf(),
            source,
        })?;
    if !canonical.is_dir() {
        return Err(StorageDiscoveryError::NotDirectory(canonical));
    }
    let output = Command::new("findmnt")
        .arg("--json")
        .arg("--target")
        .arg(&canonical)
        .arg("--output")
        .arg("TARGET,SOURCE,FSTYPE,UUID,PARTUUID")
        .output()
        .map_err(StorageDiscoveryError::FindmntUnavailable)?;
    parse_findmnt_output(canonical, output)
}

fn parse_findmnt_output(path: PathBuf, output: Output) -> Result<MountedFilesystem> {
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(StorageDiscoveryError::FindmntFailed { path, message });
    }
    parse_findmnt_json(path, &output.stdout)
}

fn parse_findmnt_json(path: PathBuf, bytes: &[u8]) -> Result<MountedFilesystem> {
    let mut parsed: FindmntOutput =
        serde_json::from_slice(bytes).map_err(StorageDiscoveryError::InvalidOutput)?;
    if parsed.filesystems.is_empty() {
        return Err(StorageDiscoveryError::NoFilesystem(path));
    }
    if parsed.filesystems.len() != 1 {
        return Err(StorageDiscoveryError::AmbiguousFilesystem(path));
    }
    let filesystem = parsed.filesystems.remove(0);
    let mount_root = std::fs::canonicalize(&filesystem.target).unwrap_or(filesystem.target);
    let relative_path = path
        .strip_prefix(&mount_root)
        .map_err(|_| StorageDiscoveryError::InvalidMountRoot {
            mount_root: mount_root.clone(),
            path: path.clone(),
        })?
        .to_path_buf();
    let (filesystem_fingerprint, fingerprint_kind) = if let Some(uuid) = nonempty(filesystem.uuid) {
        (
            Some(uuid.to_ascii_lowercase()),
            Some("filesystem_uuid".to_owned()),
        )
    } else if let Some(uuid) = nonempty(filesystem.partuuid) {
        (
            Some(uuid.to_ascii_lowercase()),
            Some("partition_uuid".to_owned()),
        )
    } else {
        (None, None)
    };
    let identity_state = if filesystem_fingerprint.is_some() {
        "confirmed"
    } else {
        "unavailable"
    }
    .to_owned();
    Ok(MountedFilesystem {
        path,
        mount_root,
        relative_path,
        source: filesystem.source,
        filesystem_type: filesystem.fstype,
        filesystem_fingerprint,
        fingerprint_kind,
        identity_state,
    })
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parses_root_and_prefers_filesystem_uuid() {
        let temp = TempDir::new().unwrap();
        let collection = temp.path().join("annex/photos");
        std::fs::create_dir_all(&collection).unwrap();
        let body = serde_json::json!({
            "filesystems": [{
                "target": temp.path(),
                "source": "/dev/sdz1",
                "fstype": "ext4",
                "uuid": "ABCD-1234",
                "partuuid": "PART-5678"
            }]
        });
        let discovered = parse_findmnt_json(
            std::fs::canonicalize(&collection).unwrap(),
            serde_json::to_string(&body).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(discovered.mount_root, temp.path());
        assert_eq!(discovered.relative_path, PathBuf::from("annex/photos"));
        assert_eq!(
            discovered.filesystem_fingerprint.as_deref(),
            Some("abcd-1234")
        );
        assert_eq!(
            discovered.fingerprint_kind.as_deref(),
            Some("filesystem_uuid")
        );
        assert_eq!(discovered.identity_state, "confirmed");
    }

    #[test]
    fn missing_stable_identity_is_explicit() {
        let temp = TempDir::new().unwrap();
        let body = serde_json::json!({
            "filesystems": [{
                "target": temp.path(),
                "source": "overlay",
                "fstype": "overlay",
                "uuid": null,
                "partuuid": null
            }]
        });
        let discovered = parse_findmnt_json(
            std::fs::canonicalize(temp.path()).unwrap(),
            serde_json::to_string(&body).unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(discovered.relative_path, PathBuf::new());
        assert_eq!(discovered.filesystem_fingerprint, None);
        assert_eq!(discovered.identity_state, "unavailable");
    }
}
