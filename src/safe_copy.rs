//! Verified, no-overwrite filesystem placement shared by mutation workflows.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use thiserror::Error;
use ulid::Ulid;

const BUFFER_BYTES: usize = 1024 * 1024;

pub type Result<T> = std::result::Result<T, SafeCopyError>;

#[derive(Debug, Error)]
pub enum SafeCopyError {
    #[error("copy source is not a regular file: {0}")]
    SourceNotRegular(PathBuf),

    #[error("copy destination already exists; refusing to overwrite it: {0}")]
    DestinationExists(PathBuf),

    #[error("source content no longer matches its reviewed BLAKE3 checksum: {0}")]
    SourceChanged(PathBuf),

    #[error("placed destination failed BLAKE3 verification: {0}")]
    DestinationMismatch(PathBuf),

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl SafeCopyError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::SourceNotRegular(_) => "copy_source_not_regular",
            Self::DestinationExists(_) => "copy_destination_exists",
            Self::SourceChanged(_) => "copy_source_changed",
            Self::DestinationMismatch(_) => "copy_destination_mismatch",
            Self::Io { .. } => "copy_io",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCopy {
    pub bytes_copied: u64,
    pub blake3_hex: String,
}

struct TemporaryCopy {
    path: PathBuf,
    keep: bool,
}

impl Drop for TemporaryCopy {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Copies one reviewed regular file without replacing an existing destination.
///
/// The source is read once while writing a same-directory temporary file. That
/// stream must match `expected_blake3_hex`. The temporary file is synced and
/// placed with no-replace semantics, then the final destination is read back
/// and verified before success is returned.
pub fn copy_verified_no_replace(
    source: &Path,
    destination: &Path,
    expected_blake3_hex: &str,
) -> Result<VerifiedCopy> {
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|source_error| io_error("inspect copy source", source, source_error))?;
    if !source_metadata.file_type().is_file() {
        return Err(SafeCopyError::SourceNotRegular(source.to_path_buf()));
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(SafeCopyError::DestinationExists(destination.to_path_buf()));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source_error) => {
            return Err(io_error(
                "inspect copy destination",
                destination,
                source_error,
            ));
        }
    }
    let parent = destination.parent().ok_or_else(|| SafeCopyError::Io {
        operation: "resolve copy destination parent",
        path: destination.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination has no parent directory",
        ),
    })?;
    let temp_path = parent.join(format!(
        ".archive-ledger-copy-{}.tmp",
        Ulid::new().to_string().to_ascii_lowercase()
    ));
    let mut temporary = TemporaryCopy {
        path: temp_path.clone(),
        keep: false,
    };
    let input = File::open(source)
        .map_err(|source_error| io_error("open copy source", source, source_error))?;
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|source_error| io_error("create copy temporary file", &temp_path, source_error))?;
    let (bytes_copied, copied_hash) = copy_and_hash(input, output, &temp_path)?;
    if copied_hash != expected_blake3_hex {
        return Err(SafeCopyError::SourceChanged(source.to_path_buf()));
    }
    place_no_replace(&temp_path, destination)?;
    temporary.keep = true;
    sync_parent_directory(destination)?;

    let (verified_bytes, verified_hash) = hash_file(destination)?;
    if verified_hash != expected_blake3_hex || verified_bytes != bytes_copied {
        return Err(SafeCopyError::DestinationMismatch(
            destination.to_path_buf(),
        ));
    }
    Ok(VerifiedCopy {
        bytes_copied,
        blake3_hex: verified_hash,
    })
}

/// Publishes a fully prepared directory without replacing an existing path.
pub fn place_directory_no_replace(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| io_error("inspect prepared directory", source, error))?;
    if !metadata.file_type().is_dir() {
        return Err(SafeCopyError::SourceNotRegular(source.to_path_buf()));
    }
    place_no_replace(source, destination)?;
    sync_parent_directory(destination)
}

/// Reads an existing regular file and requires the reviewed checksum.
pub fn verify_existing_file(path: &Path, expected_blake3_hex: &str) -> Result<VerifiedCopy> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect existing destination", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(SafeCopyError::SourceNotRegular(path.to_path_buf()));
    }
    let (bytes_copied, blake3_hex) = hash_file(path)?;
    if blake3_hex != expected_blake3_hex {
        return Err(SafeCopyError::DestinationMismatch(path.to_path_buf()));
    }
    Ok(VerifiedCopy {
        bytes_copied,
        blake3_hex,
    })
}

fn copy_and_hash(input: File, output: File, output_path: &Path) -> Result<(u64, String)> {
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, input);
    let mut writer = BufWriter::with_capacity(BUFFER_BYTES, output);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    let mut bytes = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source| io_error("read copy source", output_path, source))?;
        if count == 0 {
            break;
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|source| io_error("write copy temporary file", output_path, source))?;
        hasher.update(&buffer[..count]);
        bytes = bytes.saturating_add(count as u64);
    }
    writer
        .flush()
        .map_err(|source| io_error("flush copy temporary file", output_path, source))?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|source| io_error("sync copy temporary file", output_path, source))?;
    Ok((bytes, hasher.finalize().to_hex().to_string()))
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let input =
        File::open(path).map_err(|source| io_error("open placed destination", path, source))?;
    let mut reader = BufReader::with_capacity(BUFFER_BYTES, input);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    let mut bytes = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|source| io_error("read placed destination", path, source))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes = bytes.saturating_add(count as u64);
    }
    Ok((bytes, hasher.finalize().to_hex().to_string()))
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| SafeCopyError::Io {
        operation: "resolve placed destination parent",
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination has no parent directory",
        ),
    })?;
    let directory = File::open(parent)
        .map_err(|source| io_error("open placed destination parent", parent, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync placed destination parent", parent, source))
}

#[cfg(target_os = "linux")]
fn place_no_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source_path =
        CString::new(source.as_os_str().as_bytes()).map_err(|_| SafeCopyError::Io {
            operation: "place copy temporary file",
            path: source.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "source path contains a NUL byte",
            ),
        })?;
    let destination_path =
        CString::new(destination.as_os_str().as_bytes()).map_err(|_| SafeCopyError::Io {
            operation: "place copy destination",
            path: destination.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "destination path contains a NUL byte",
            ),
        })?;
    // SAFETY: both C strings are NUL-terminated and live for the duration of
    // the call; RENAME_NOREPLACE prevents replacement if a destination races us.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source_path.as_ptr(),
            libc::AT_FDCWD,
            destination_path.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        return Err(SafeCopyError::DestinationExists(destination.to_path_buf()));
    }
    Err(io_error(
        "atomically place copy destination",
        destination,
        error,
    ))
}

#[cfg(not(target_os = "linux"))]
fn place_no_replace(source: &Path, destination: &Path) -> Result<()> {
    fs::hard_link(source, destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            SafeCopyError::DestinationExists(destination.to_path_buf())
        } else {
            io_error("atomically place copy destination", destination, error)
        }
    })?;
    fs::remove_file(source)
        .map_err(|error| io_error("remove placed temporary link", source, error))?;
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> SafeCopyError {
    SafeCopyError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_and_verifies_without_overwriting() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.bin");
        let destination = temp.path().join("destination.bin");
        fs::write(&source, b"reviewed bytes").unwrap();
        let expected = blake3::hash(b"reviewed bytes").to_hex().to_string();

        let copied = copy_verified_no_replace(&source, &destination, &expected).unwrap();
        assert_eq!(copied.bytes_copied, 14);
        assert_eq!(fs::read(&destination).unwrap(), b"reviewed bytes");

        fs::write(&source, b"replacement").unwrap();
        let error = copy_verified_no_replace(&source, &destination, &expected).unwrap_err();
        assert!(matches!(error, SafeCopyError::DestinationExists(_)));
        assert_eq!(fs::read(&destination).unwrap(), b"reviewed bytes");
    }

    #[test]
    fn rejects_source_that_changed_after_review() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.bin");
        let destination = temp.path().join("destination.bin");
        fs::write(&source, b"changed bytes").unwrap();
        let reviewed = blake3::hash(b"original bytes").to_hex().to_string();

        let error = copy_verified_no_replace(&source, &destination, &reviewed).unwrap_err();
        assert!(matches!(error, SafeCopyError::SourceChanged(_)));
        assert!(!destination.exists());
    }
}
