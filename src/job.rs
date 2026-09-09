//! Validation and filesystem containment for local resumable job state.

use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

/// Validates an identifier before it is used as one filesystem path component.
///
/// Historical event and projection values do not need to pass this validator merely to be read.
pub fn validate_job_id(job_id: &str) -> Result<(), String> {
    if job_id.is_empty()
        || !job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(
            "job ID must contain only ASCII letters, digits, underscores, and hyphens".to_owned(),
        );
    }
    Ok(())
}

/// A validated job directory beneath an Archive's private `local/jobs` directory.
pub(crate) struct JobDirectory {
    jobs_root: PathBuf,
    path: PathBuf,
}

impl JobDirectory {
    pub(crate) fn new(archive_root: &Path, job_id: &str) -> io::Result<Self> {
        validate_job_id(job_id).map_err(invalid_input)?;
        let archive_root = fs::canonicalize(archive_root)?;
        require_real_directory(&archive_root)?;
        let local = archive_root.join("local");
        ensure_real_directory(&local)?;
        let jobs_root = local.join("jobs");
        ensure_real_directory(&jobs_root)?;
        let jobs_root = fs::canonicalize(&jobs_root)?;
        if jobs_root.parent() != Some(local.as_path()) {
            return Err(unsafe_path("local/jobs is not a direct Archive child"));
        }
        let path = jobs_root.join(job_id);
        if path.parent() != Some(jobs_root.as_path()) {
            return Err(unsafe_path("job directory is not a direct jobs child"));
        }
        Ok(Self { jobs_root, path })
    }

    pub(crate) fn ensure(&self) -> io::Result<()> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => self.verify(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                builder.mode(0o700);
                builder.create(&self.path)?;
                self.verify()
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    pub(crate) fn read_optional(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        let Some(mut file) = self.open_read_optional(name)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    #[cfg(not(unix))]
    pub(crate) fn read_optional(&self, _name: &str) -> io::Result<Option<Vec<u8>>> {
        Err(unsupported_job_files())
    }

    #[cfg(unix)]
    pub(crate) fn open_read_optional(&self, name: &str) -> io::Result<Option<File>> {
        let directory = self.open_directory()?;
        match open_regular_at(&directory, name, libc::O_RDONLY, 0) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    #[cfg(not(unix))]
    pub(crate) fn open_read_optional(&self, _name: &str) -> io::Result<Option<fs::File>> {
        Err(unsupported_job_files())
    }

    #[cfg(unix)]
    pub(crate) fn write_new(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let directory = self.open_directory()?;
        let mut file = open_regular_at(
            &directory,
            name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        file.write_all(bytes)?;
        file.sync_all()?;
        directory.sync_all()
    }

    #[cfg(not(unix))]
    pub(crate) fn write_new(&self, _name: &str, _bytes: &[u8]) -> io::Result<()> {
        Err(unsupported_job_files())
    }

    #[cfg(unix)]
    pub(crate) fn replace(&self, name: &str, temporary: &str, bytes: &[u8]) -> io::Result<()> {
        validate_leaf_name(name)?;
        validate_leaf_name(temporary)?;
        let directory = self.open_directory()?;
        remove_safe_regular_at(&directory, temporary)?;
        let mut file = open_regular_at(
            &directory,
            temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = remove_safe_regular_at(&directory, temporary);
            return Err(error);
        }
        drop(file);
        let source = leaf_c_string(temporary)?;
        let target = leaf_c_string(name)?;
        // SAFETY: both names are validated NUL-terminated leaf names and the verified directory
        // descriptor remains open. `renameat` replaces a target entry rather than following it.
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                source.as_ptr(),
                directory.as_raw_fd(),
                target.as_ptr(),
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            let _ = remove_safe_regular_at(&directory, temporary);
            return Err(error);
        }
        directory.sync_all()
    }

    #[cfg(not(unix))]
    pub(crate) fn replace(&self, _name: &str, _temporary: &str, _bytes: &[u8]) -> io::Result<()> {
        Err(unsupported_job_files())
    }

    #[cfg(unix)]
    pub(crate) fn open_read_write(&self, name: &str) -> io::Result<File> {
        let directory = self.open_directory()?;
        open_regular_at(&directory, name, libc::O_RDWR | libc::O_CREAT, 0o600)
    }

    #[cfg(not(unix))]
    pub(crate) fn open_read_write(&self, _name: &str) -> io::Result<fs::File> {
        Err(unsupported_job_files())
    }

    #[cfg(unix)]
    pub(crate) fn open_append(&self, name: &str) -> io::Result<File> {
        let directory = self.open_directory()?;
        open_regular_at(
            &directory,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_APPEND,
            0o600,
        )
    }

    #[cfg(not(unix))]
    pub(crate) fn open_append(&self, _name: &str) -> io::Result<fs::File> {
        Err(unsupported_job_files())
    }

    /// Rejects static link attacks on files opened internally by another library, such as SQLite.
    /// The writable Archive state directory remains trusted against concurrent same-UID mutation.
    #[cfg(unix)]
    pub(crate) fn verify_safe_entries(&self, names: &[&str]) -> io::Result<()> {
        let directory = self.open_directory()?;
        for name in names {
            validate_leaf_name(name)?;
            match stat_at(&directory, name) {
                Ok(stat) => require_safe_regular_stat(&stat)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(crate) fn verify_safe_entries(&self, _names: &[&str]) -> io::Result<()> {
        Err(unsupported_job_files())
    }

    /// Removes only known regular files, then removes the now-empty job directory.
    ///
    /// This deliberately avoids recursive deletion. An unexpected entry leaves the directory in
    /// place and causes the final non-recursive removal to fail closed.
    pub(crate) fn cleanup(&self, known_files: &[&str]) -> io::Result<()> {
        match fs::symlink_metadata(&self.path) {
            Ok(_) => self.verify()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
        for name in known_files {
            validate_leaf_name(name)?;
        }
        cleanup_known_files(self, known_files)
    }

    fn verify(&self) -> io::Result<()> {
        require_real_directory(&self.jobs_root)?;
        require_real_directory(&self.path)?;
        let actual = fs::canonicalize(&self.path)?;
        if actual != self.path || actual.parent() != Some(self.jobs_root.as_path()) {
            return Err(unsafe_path(
                "job directory escaped or was linked outside local/jobs",
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn open_directory(&self) -> io::Result<File> {
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)?;
        ensure_same_directory(&handle, &self.path)?;
        Ok(handle)
    }
}

#[cfg(unix)]
fn open_regular_at(
    directory: &File,
    name: &str,
    flags: libc::c_int,
    mode: u32,
) -> io::Result<File> {
    let name = leaf_c_string(name)?;
    // SAFETY: `name` is a validated NUL-terminated leaf, the directory descriptor is open, and a
    // newly returned descriptor is transferred exactly once into `File` below.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` is newly owned after a successful `openat` call.
    let file = unsafe { File::from_raw_fd(descriptor) };
    require_safe_regular_file(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn require_safe_regular_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(unsafe_path("job file is not a singly linked regular file"));
    }
    Ok(())
}

#[cfg(unix)]
fn leaf_c_string(name: &str) -> io::Result<CString> {
    validate_leaf_name(name)?;
    CString::new(name.as_bytes()).map_err(|_| invalid_input("invalid job file"))
}

#[cfg(unix)]
fn stat_at(directory: &File, name: &str) -> io::Result<libc::stat> {
    let name = leaf_c_string(name)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is NUL-terminated, `stat` points to writable storage, and the directory
    // descriptor remains open for this descriptor-relative metadata lookup.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `fstatat` initialized `stat`.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(unix)]
fn require_safe_regular_stat(stat: &libc::stat) -> io::Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
        return Err(unsafe_path("job file is not a singly linked regular file"));
    }
    Ok(())
}

#[cfg(unix)]
fn remove_safe_regular_at(directory: &File, name: &str) -> io::Result<()> {
    let name = leaf_c_string(name)?;
    let stat = match stat_at(
        directory,
        name.to_str().expect("validated job filename is UTF-8"),
    ) {
        Ok(stat) => stat,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    require_safe_regular_stat(&stat)?;
    // SAFETY: `name` is a validated NUL-terminated leaf and the verified directory descriptor
    // remains open. No directory-removal flag is supplied.
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_real_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(path)?;
            require_real_directory(path)
        }
        Err(error) => Err(error),
    }
}

fn require_real_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(unsafe_path("job path component is not a real directory"));
    }
    Ok(())
}

fn validate_leaf_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&b'\\')
    {
        return Err(invalid_input("invalid job cleanup filename"));
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_known_files(directory: &JobDirectory, known_files: &[&str]) -> io::Result<()> {
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&directory.path)?;
    ensure_same_directory(&handle, &directory.path)?;

    for name in known_files {
        let name = CString::new(name.as_bytes()).map_err(|_| invalid_input("invalid job file"))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `name` is NUL-terminated, `stat` points to writable storage, and the directory
        // descriptor remains open for the duration of each descriptor-relative operation.
        let result = unsafe {
            libc::fstatat(
                handle.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::NotFound {
                continue;
            }
            return Err(error);
        }
        // SAFETY: `fstatat` initialized `stat` after returning success.
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
            return Err(unsafe_path("job cleanup encountered an unsafe known entry"));
        }
        // SAFETY: arguments retain the same validity as for `fstatat`; no directory-removal flag
        // is supplied, so a raced directory cannot be recursively or otherwise removed.
        if unsafe { libc::unlinkat(handle.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    ensure_same_directory(&handle, &directory.path)?;
    fs::remove_dir(&directory.path)
}

#[cfg(unix)]
fn ensure_same_directory(handle: &File, path: &Path) -> io::Result<()> {
    let opened = handle.metadata()?;
    let current = fs::symlink_metadata(path)?;
    if current.file_type().is_symlink()
        || !current.is_dir()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(unsafe_path("job directory changed during cleanup"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn cleanup_known_files(directory: &JobDirectory, known_files: &[&str]) -> io::Result<()> {
    for name in known_files {
        let path = directory.path.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                fs::remove_file(path)?;
            }
            Ok(_) => {
                return Err(unsafe_path(
                    "job cleanup encountered a non-regular known entry",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    directory.verify()?;
    fs::remove_dir(&directory.path)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn unsafe_path(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(not(unix))]
fn unsupported_job_files() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "resumable job files require no-follow filesystem operations on this platform",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn job_ids_are_single_portable_path_components() {
        for valid in ["job_01abc", "JOB-9", "a"] {
            validate_job_id(valid).unwrap();
        }
        for invalid in [
            "",
            ".",
            "..",
            "/absolute",
            "../escape",
            "nested/job",
            "nested\\job",
            "has space",
            "unicode_é",
        ] {
            assert!(validate_job_id(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn invalid_job_ids_cannot_select_or_change_a_sentinel_directory() {
        let temp = tempdir().unwrap();
        let archive = temp.path().join("archive");
        let sentinel = temp.path().join("sentinel");
        fs::create_dir(&archive).unwrap();
        fs::create_dir(&sentinel).unwrap();
        fs::write(sentinel.join("keep"), b"preserve me").unwrap();

        for invalid in [
            sentinel.to_string_lossy().into_owned(),
            "../../sentinel".to_owned(),
        ] {
            assert!(JobDirectory::new(&archive, &invalid).is_err());
        }
        assert_eq!(fs::read(sentinel.join("keep")).unwrap(), b"preserve me");
        assert!(!archive.join("local").exists());
    }

    #[test]
    fn cleanup_removes_only_known_regular_files() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("local")).unwrap();
        let job = JobDirectory::new(temp.path(), "job_fixture").unwrap();
        job.ensure().unwrap();
        fs::write(job.path().join("known"), b"scratch").unwrap();
        job.cleanup(&["known"]).unwrap();
        assert!(!job.path().exists());
    }

    #[test]
    fn cleanup_refuses_unexpected_entries() {
        let temp = tempdir().unwrap();
        fs::create_dir(temp.path().join("local")).unwrap();
        let job = JobDirectory::new(temp.path(), "job_fixture").unwrap();
        job.ensure().unwrap();
        fs::write(job.path().join("unexpected"), b"preserve me").unwrap();
        assert!(job.cleanup(&["known"]).is_err());
        assert_eq!(
            fs::read(job.path().join("unexpected")).unwrap(),
            b"preserve me"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_a_symlinked_job_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let sentinel = temp.path().join("sentinel");
        fs::create_dir(&sentinel).unwrap();
        fs::write(sentinel.join("known"), b"preserve me").unwrap();
        fs::create_dir(temp.path().join("local")).unwrap();
        let job = JobDirectory::new(temp.path(), "job_fixture").unwrap();
        symlink(&sentinel, job.path()).unwrap();
        assert!(job.cleanup(&["known"]).is_err());
        assert_eq!(fs::read(sentinel.join("known")).unwrap(), b"preserve me");
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_a_symlinked_known_file() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, b"preserve me").unwrap();
        fs::create_dir(temp.path().join("local")).unwrap();
        let job = JobDirectory::new(temp.path(), "job_fixture").unwrap();
        job.ensure().unwrap();
        symlink(&sentinel, job.path().join("known")).unwrap();
        assert!(job.cleanup(&["known"]).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");
    }

    #[cfg(unix)]
    #[test]
    fn mutable_job_files_refuse_symlinks_and_hard_links() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, b"preserve me").unwrap();
        fs::create_dir(temp.path().join("local")).unwrap();
        let job = JobDirectory::new(temp.path(), "job_fixture").unwrap();
        job.ensure().unwrap();

        symlink(&sentinel, job.path().join("spool")).unwrap();
        assert!(job.open_read_write("spool").is_err());
        assert!(job.read_optional("spool").is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");

        fs::remove_file(job.path().join("spool")).unwrap();
        fs::hard_link(&sentinel, job.path().join("spool")).unwrap();
        assert!(job.open_append("spool").is_err());
        assert!(job.read_optional("spool").is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_job_file_replacement_does_not_follow_its_target() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, b"preserve me").unwrap();
        fs::create_dir(temp.path().join("local")).unwrap();
        let job = JobDirectory::new(temp.path(), "job_fixture").unwrap();
        job.ensure().unwrap();
        symlink(&sentinel, job.path().join("summary")).unwrap();

        job.replace("summary", "summary.tmp", b"checkpoint")
            .unwrap();

        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");
        assert_eq!(fs::read(job.path().join("summary")).unwrap(), b"checkpoint");
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_preflight_rejects_unsafe_main_and_sidecar_entries() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let sentinel = temp.path().join("sentinel");
        fs::write(&sentinel, b"preserve me").unwrap();
        fs::create_dir(temp.path().join("local")).unwrap();
        let job = JobDirectory::new(temp.path(), "job_fixture").unwrap();
        job.ensure().unwrap();
        symlink(&sentinel, job.path().join("seen.sqlite3-wal")).unwrap();

        assert!(job
            .verify_safe_entries(&["seen.sqlite3", "seen.sqlite3-wal"])
            .is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");
    }
}
