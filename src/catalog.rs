//! Per-user discovery of Archive Ledger catalogs.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

const REGISTRY_VERSION: u32 = 1;

pub type Result<T> = std::result::Result<T, CatalogError>;

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("cannot determine {kind}; set {variable}")]
    MissingHome {
        kind: &'static str,
        variable: &'static str,
    },
    #[error("catalog registry operation failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("catalog registry {path} is invalid: {message}")]
    Invalid { path: PathBuf, message: String },
    #[error("archive selector {0:?} is unknown")]
    Unknown(String),
    #[error("archive selector {0:?} is ambiguous; use the stable Archive ID")]
    Ambiguous(String),
    #[error("no Archive is configured; run `archive init <name>`")]
    NoneConfigured,
    #[error(
        "multiple Archives are configured and none is the default; run `archive use <archive>`"
    )]
    NoDefault,
}

impl CatalogError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingHome { .. } => "catalog_home_unavailable",
            Self::Io { .. } => "catalog_registry_io",
            Self::Invalid { .. } => "catalog_registry_invalid",
            Self::Unknown(_) => "archive_unknown",
            Self::Ambiguous(_) => "archive_ambiguous",
            Self::NoneConfigured => "archive_not_configured",
            Self::NoDefault => "archive_default_missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownArchive {
    pub archive_id: String,
    pub display_name: String,
    pub root: PathBuf,
}

impl KnownArchive {
    pub fn database_path(&self) -> PathBuf {
        self.root.join("archive.db")
    }

    pub fn events_path(&self) -> PathBuf {
        self.root.join("canonical")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogRegistry {
    version: u32,
    default_archive_id: Option<String>,
    archives: Vec<KnownArchive>,
}

impl Default for CatalogRegistry {
    fn default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            default_archive_id: None,
            archives: Vec::new(),
        }
    }
}

impl CatalogRegistry {
    pub fn load() -> Result<Self> {
        let path = registry_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(&path).map_err(|source| io_error(&path, source))?;
        let registry: Self =
            serde_json::from_slice(&bytes).map_err(|source| CatalogError::Invalid {
                path: path.clone(),
                message: source.to_string(),
            })?;
        registry.validate(&path)?;
        Ok(registry)
    }

    pub fn archives(&self) -> &[KnownArchive] {
        &self.archives
    }

    pub fn default_archive_id(&self) -> Option<&str> {
        self.default_archive_id.as_deref()
    }

    pub fn resolve(&self, selector: Option<&str>) -> Result<KnownArchive> {
        if let Some(selector) = selector {
            let matches: Vec<_> = self
                .archives
                .iter()
                .filter(|archive| {
                    archive.archive_id == selector || archive.display_name == selector
                })
                .cloned()
                .collect();
            return match matches.as_slice() {
                [] => Err(CatalogError::Unknown(selector.to_owned())),
                [archive] => Ok(archive.clone()),
                _ => Err(CatalogError::Ambiguous(selector.to_owned())),
            };
        }
        if let Some(default_id) = &self.default_archive_id {
            return self
                .archives
                .iter()
                .find(|archive| &archive.archive_id == default_id)
                .cloned()
                .ok_or_else(|| CatalogError::Invalid {
                    path: registry_path().unwrap_or_else(|_| PathBuf::from("catalogs.json")),
                    message: format!("default Archive {default_id:?} is not registered"),
                });
        }
        match self.archives.as_slice() {
            [] => Err(CatalogError::NoneConfigured),
            [archive] => Ok(archive.clone()),
            _ => Err(CatalogError::NoDefault),
        }
    }

    pub fn register(&mut self, archive: KnownArchive, make_default: bool) -> Result<()> {
        if let Some(existing) = self
            .archives
            .iter_mut()
            .find(|existing| existing.archive_id == archive.archive_id)
        {
            if existing.root != archive.root {
                return Err(CatalogError::Invalid {
                    path: registry_path()?,
                    message: format!(
                        "Archive ID {} is already registered at {}",
                        archive.archive_id,
                        existing.root.display()
                    ),
                });
            }
            existing.display_name = archive.display_name.clone();
        } else {
            if let Some(existing) = self
                .archives
                .iter()
                .find(|existing| existing.root == archive.root)
            {
                return Err(CatalogError::Invalid {
                    path: registry_path()?,
                    message: format!(
                        "Archive directory {} is already registered as {}",
                        archive.root.display(),
                        existing.archive_id
                    ),
                });
            }
            self.archives.push(archive.clone());
            self.archives
                .sort_by(|left, right| left.archive_id.cmp(&right.archive_id));
        }
        if self.default_archive_id.is_none() || make_default {
            self.default_archive_id = Some(archive.archive_id);
        }
        self.save()
    }

    pub fn set_default(&mut self, selector: &str) -> Result<KnownArchive> {
        let archive = self.resolve(Some(selector))?;
        self.default_archive_id = Some(archive.archive_id.clone());
        self.save()?;
        Ok(archive)
    }

    pub fn rename(&mut self, archive_id: &str, display_name: &str) -> Result<()> {
        let Some(archive) = self
            .archives
            .iter_mut()
            .find(|archive| archive.archive_id == archive_id)
        else {
            return Ok(());
        };
        archive.display_name = display_name.to_owned();
        self.save()
    }

    fn validate(&self, path: &Path) -> Result<()> {
        if self.version != REGISTRY_VERSION {
            return Err(CatalogError::Invalid {
                path: path.to_path_buf(),
                message: format!(
                    "unsupported version {}; expected {REGISTRY_VERSION}",
                    self.version
                ),
            });
        }
        for (index, archive) in self.archives.iter().enumerate() {
            if archive.archive_id.is_empty() || archive.display_name.trim().is_empty() {
                return Err(CatalogError::Invalid {
                    path: path.to_path_buf(),
                    message: format!("Archive entry {index} has an empty ID or name"),
                });
            }
            if self.archives[..index]
                .iter()
                .any(|prior| prior.archive_id == archive.archive_id)
            {
                return Err(CatalogError::Invalid {
                    path: path.to_path_buf(),
                    message: format!("duplicate Archive ID {}", archive.archive_id),
                });
            }
            if self.archives[..index]
                .iter()
                .any(|prior| prior.root == archive.root)
            {
                return Err(CatalogError::Invalid {
                    path: path.to_path_buf(),
                    message: format!("duplicate Archive directory {}", archive.root.display()),
                });
            }
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        let path = registry_path()?;
        let parent = path.parent().expect("registry path has a parent");
        fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
        let temp = parent.join(format!(
            ".catalogs-{}.tmp",
            Ulid::new().to_string().to_ascii_lowercase()
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|source| io_error(&temp, source))?;
            serde_json::to_writer_pretty(&mut file, self).map_err(|source| {
                CatalogError::Invalid {
                    path: temp.clone(),
                    message: source.to_string(),
                }
            })?;
            file.write_all(b"\n")
                .map_err(|source| io_error(&temp, source))?;
            file.sync_all().map_err(|source| io_error(&temp, source))?;
            fs::rename(&temp, &path).map_err(|source| io_error(&path, source))?;
            sync_directory(parent)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

pub fn central_archive(archive_id: &str, display_name: &str) -> Result<KnownArchive> {
    Ok(KnownArchive {
        archive_id: archive_id.to_owned(),
        display_name: display_name.to_owned(),
        root: data_home()?
            .join("archive-ledger/archives")
            .join(archive_id),
    })
}

pub fn registry_path() -> Result<PathBuf> {
    Ok(config_home()?.join("archive-ledger/catalogs.json"))
}

fn data_home() -> Result<PathBuf> {
    if let Some(path) = nonempty_env("XDG_DATA_HOME") {
        return Ok(path);
    }
    home_subdirectory("data directory", "XDG_DATA_HOME", ".local/share")
}

fn config_home() -> Result<PathBuf> {
    if let Some(path) = nonempty_env("XDG_CONFIG_HOME") {
        return Ok(path);
    }
    home_subdirectory("configuration directory", "XDG_CONFIG_HOME", ".config")
}

fn home_subdirectory(kind: &'static str, variable: &'static str, suffix: &str) -> Result<PathBuf> {
    nonempty_env("HOME")
        .map(|home| home.join(suffix))
        .ok_or(CatalogError::MissingHome { kind, variable })
}

fn nonempty_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn io_error(path: impl Into<PathBuf>, source: std::io::Error) -> CatalogError {
    CatalogError::Io {
        path: path.into(),
        source,
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}
