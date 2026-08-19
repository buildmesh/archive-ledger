use std::fs::{self, Metadata, ReadDir};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use thiserror::Error;

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

pub type Result<T> = std::result::Result<T, DiscoveryError>;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("discovery root must be a directory: {0}")]
    RootNotDirectory(PathBuf),

    #[error("filesystem identity is unavailable on this platform")]
    FilesystemIdentityUnavailable,

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl DiscoveryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::RootNotDirectory(_) => "discovery_root_not_directory",
            Self::FilesystemIdentityUnavailable => "filesystem_identity_unavailable",
            Self::Io { .. } => "discovery_io",
        }
    }
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> DiscoveryError {
    DiscoveryError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathEncoding {
    Utf8,
    UnixBytes,
    WindowsUtf16Le,
}

impl PathEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::UnixBytes => "unix_bytes",
            Self::WindowsUtf16Le => "windows_utf16le",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPath {
    pub encoding: PathEncoding,
    pub bytes: Vec<u8>,
    pub display: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredFile {
    pub relative_path: EncodedPath,
    pub size_bytes: u64,
    pub modified_time_utc_ms: Option<u64>,
}

#[derive(Debug)]
pub enum DiscoveryItem {
    File(DiscoveredFile),
    Symlink(EncodedPath),
    Special(EncodedPath),
    FilesystemBoundary(EncodedPath),
    Error {
        relative_path: Option<EncodedPath>,
        error: DiscoveryError,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryStats {
    pub directories_opened: u64,
    pub max_open_directories: usize,
    pub regular_files: u64,
    pub symlinks: u64,
    pub special_files: u64,
    pub filesystem_boundaries: u64,
    pub errors: u64,
}

struct DirectoryFrame {
    entries: ReadDir,
}

pub struct FileDiscovery {
    root: PathBuf,
    root_device: u64,
    stack: Vec<DirectoryFrame>,
    stats: DiscoveryStats,
}

impl FileDiscovery {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let metadata = fs::symlink_metadata(&root)
            .map_err(|source| io_error("inspect discovery root", &root, source))?;
        if !metadata.file_type().is_dir() {
            return Err(DiscoveryError::RootNotDirectory(root));
        }
        let root_device = filesystem_device(&metadata)?;
        let entries = fs::read_dir(&root)
            .map_err(|source| io_error("enumerate discovery root", &root, source))?;
        Ok(Self {
            root,
            root_device,
            stack: vec![DirectoryFrame { entries }],
            stats: DiscoveryStats {
                directories_opened: 1,
                max_open_directories: 1,
                ..DiscoveryStats::default()
            },
        })
    }

    pub fn stats(&self) -> &DiscoveryStats {
        &self.stats
    }

    fn relative_encoded(&self, path: &Path) -> Result<EncodedPath> {
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| DiscoveryError::RootNotDirectory(self.root.clone()))?;
        Ok(encode_relative_path(relative))
    }
}

impl Iterator for FileDiscovery {
    type Item = DiscoveryItem;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let frame = self.stack.last_mut()?;
            let entry = match frame.entries.next() {
                Some(Ok(entry)) => entry,
                Some(Err(source)) => {
                    self.stats.errors += 1;
                    return Some(DiscoveryItem::Error {
                        relative_path: None,
                        error: io_error("read directory entry", &self.root, source),
                    });
                }
                None => {
                    self.stack.pop();
                    continue;
                }
            };
            let path = entry.path();
            let relative_path = match self.relative_encoded(&path) {
                Ok(path) => path,
                Err(error) => {
                    self.stats.errors += 1;
                    return Some(DiscoveryItem::Error {
                        relative_path: None,
                        error,
                    });
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(source) => {
                    self.stats.errors += 1;
                    return Some(DiscoveryItem::Error {
                        relative_path: Some(relative_path),
                        error: io_error("inspect directory entry type", path, source),
                    });
                }
            };

            if file_type.is_symlink() {
                self.stats.symlinks += 1;
                return Some(DiscoveryItem::Symlink(relative_path));
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(source) => {
                    self.stats.errors += 1;
                    return Some(DiscoveryItem::Error {
                        relative_path: Some(relative_path),
                        error: io_error("inspect directory entry", path, source),
                    });
                }
            };
            if file_type.is_dir() {
                match filesystem_device(&metadata) {
                    Ok(device) if device != self.root_device => {
                        self.stats.filesystem_boundaries += 1;
                        return Some(DiscoveryItem::FilesystemBoundary(relative_path));
                    }
                    Err(error) => {
                        self.stats.errors += 1;
                        return Some(DiscoveryItem::Error {
                            relative_path: Some(relative_path),
                            error,
                        });
                    }
                    _ => {}
                }
                match fs::read_dir(&path) {
                    Ok(entries) => {
                        self.stack.push(DirectoryFrame { entries });
                        self.stats.directories_opened += 1;
                        self.stats.max_open_directories =
                            self.stats.max_open_directories.max(self.stack.len());
                        continue;
                    }
                    Err(source) => {
                        self.stats.errors += 1;
                        return Some(DiscoveryItem::Error {
                            relative_path: Some(relative_path),
                            error: io_error("enumerate directory", path, source),
                        });
                    }
                }
            }
            if file_type.is_file() {
                self.stats.regular_files += 1;
                return Some(DiscoveryItem::File(DiscoveredFile {
                    relative_path,
                    size_bytes: metadata.len(),
                    modified_time_utc_ms: modified_time_ms(&metadata),
                }));
            }

            self.stats.special_files += 1;
            return Some(DiscoveryItem::Special(relative_path));
        }
    }
}

pub(crate) fn modified_time_ms(metadata: &Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

#[cfg(unix)]
fn filesystem_device(metadata: &Metadata) -> Result<u64> {
    Ok(metadata.dev())
}

#[cfg(not(unix))]
fn filesystem_device(_metadata: &Metadata) -> Result<u64> {
    Err(DiscoveryError::FilesystemIdentityUnavailable)
}

#[cfg(unix)]
pub(crate) fn encode_relative_path(path: &Path) -> EncodedPath {
    let bytes = path.as_os_str().as_bytes().to_vec();
    if let Some(text) = path.to_str() {
        EncodedPath {
            encoding: PathEncoding::Utf8,
            bytes,
            display: text.to_owned(),
        }
    } else {
        EncodedPath {
            encoding: PathEncoding::UnixBytes,
            display: escape_bytes(&bytes),
            bytes,
        }
    }
}

#[cfg(windows)]
pub(crate) fn encode_relative_path(path: &Path) -> EncodedPath {
    if let Some(text) = path.to_str() {
        return EncodedPath {
            encoding: PathEncoding::Utf8,
            bytes: text.as_bytes().to_vec(),
            display: text.to_owned(),
        };
    }
    let mut bytes = Vec::new();
    for code_unit in path.as_os_str().encode_wide() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    EncodedPath {
        encoding: PathEncoding::WindowsUtf16Le,
        display: path.to_string_lossy().into_owned(),
        bytes,
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn encode_relative_path(path: &Path) -> EncodedPath {
    let display = path.to_string_lossy().into_owned();
    EncodedPath {
        encoding: PathEncoding::Utf8,
        bytes: display.as_bytes().to_vec(),
        display,
    }
}

#[cfg(unix)]
fn escape_bytes(bytes: &[u8]) -> String {
    let mut display = String::new();
    for &byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            display.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(display, "\\x{byte:02x}");
        }
    }
    display
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn discovery_streams_regular_files_without_following_symlinks() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("one/two")).unwrap();
        File::create(temp.path().join("root-file")).unwrap();
        File::create(temp.path().join("one/nested-file")).unwrap();
        File::create(temp.path().join("one/two/deep-file")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(temp.path().join("one"), temp.path().join("link")).unwrap();

        let mut discovery = FileDiscovery::new(temp.path()).unwrap();
        let mut paths = Vec::new();
        let mut symlinks = 0;
        for item in discovery.by_ref() {
            match item {
                DiscoveryItem::File(file) => paths.push(file.relative_path.display),
                DiscoveryItem::Symlink(_) => symlinks += 1,
                DiscoveryItem::Error { error, .. } => panic!("unexpected discovery error: {error}"),
                _ => {}
            }
        }
        paths.sort();
        assert_eq!(
            paths,
            vec!["one/nested-file", "one/two/deep-file", "root-file"]
        );
        #[cfg(unix)]
        assert_eq!(symlinks, 1);
        assert_eq!(discovery.stats().regular_files, 3);
        assert!(discovery.stats().max_open_directories <= 3);
    }

    #[cfg(unix)]
    #[test]
    fn discovery_preserves_non_utf8_path_identity() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let temp = TempDir::new().unwrap();
        let name = OsString::from_vec(vec![b'f', 0x80]);
        File::create(temp.path().join(name)).unwrap();
        let item = FileDiscovery::new(temp.path()).unwrap().next().unwrap();
        let DiscoveryItem::File(file) = item else {
            panic!("expected a regular file");
        };
        assert_eq!(file.relative_path.encoding, PathEncoding::UnixBytes);
        assert_eq!(file.relative_path.bytes, vec![b'f', 0x80]);
        assert_eq!(file.relative_path.display, "f\\x80");
    }
}
