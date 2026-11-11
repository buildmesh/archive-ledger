//! Shared path mapping and data encoding for static host script templates.
use super::*;
use archive_ledger::{sqlite_queries::CatalogQueryError, SqliteCatalog};

pub(super) fn collection_id(
    catalog: &SqliteCatalog,
    state: &archive_ledger::sqlite_registry::SqliteRegistryState,
    location: &LocationSnapshot,
    selector: Option<&str>,
) -> Result<String, AppError> {
    let collection = if let Some(selector) = selector {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
            .collection_id
    } else if state.collections.len() == 1 {
        state.collections[0].collection_id.clone()
    } else {
        let mut stmt = catalog.connection().prepare(
            "SELECT DISTINCT o.collection_id FROM files f JOIN objects o ON o.object_id=f.object_id JOIN collections c ON c.collection_id=o.collection_id WHERE f.location_id=?1 AND c.status='active' LIMIT 2"
        )?;
        let ids = stmt
            .query_map([&location.location_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() != 1 {
            return Err(AppError::Input(
                "specify --collection for this source Location".into(),
            ));
        }
        ids[0].clone()
    };
    Ok(collection)
}

pub(super) fn mapped_root(
    cli: &Cli,
    catalog: &SqliteCatalog,
    location: &LocationSnapshot,
    host_root: Option<&Path>,
    locations_root: Option<&Path>,
) -> Result<String, AppError> {
    let root = recorded_path(cli, catalog, location)?;
    let host = host_root
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("ARCHIVE_LEDGER_LOCATIONS_DIR").map(PathBuf::from));
    let container = locations_root
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR").map(PathBuf::from));
    if container.is_some() && host.is_none() {
        return Err(AppError::Input(
            "--locations-root requires --host-root or ARCHIVE_LEDGER_LOCATIONS_DIR".into(),
        ));
    }
    let root = if let Some(host) = host {
        let container = container.as_deref().unwrap_or(Path::new("/locations"));
        validate_root(&host)?;
        validate_root(container)?;
        let relative = root.strip_prefix(container).map_err(|_| {
            AppError::Input(format!(
                "recorded Location path {} is outside --locations-root {}",
                root.display(),
                container.display()
            ))
        })?;
        host.join(relative)
    } else {
        root
    };
    root.to_str().map(str::to_owned).ok_or_else(|| {
        AppError::Input(
            "host script roots must be UTF-8; selected filenames may contain arbitrary Unix bytes"
                .into(),
        )
    })
}

pub(super) fn validate_relative_path(path: &[u8]) -> Result<(), CatalogQueryError> {
    if path.contains(&0)
        || path
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(CatalogQueryError::InvalidFilter(
            "host script requires normalized Collection-relative paths without NUL".into(),
        ));
    }
    Ok(())
}

fn validate_root(path: &Path) -> Result<(), AppError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(AppError::Input(
            "host and Location roots must be absolute paths without '..'".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().contains(&0) {
            return Err(AppError::Input("root path contains NUL".into()));
        }
    }
    Ok(())
}

fn recorded_path(
    cli: &Cli,
    catalog: &SqliteCatalog,
    location: &LocationSnapshot,
) -> Result<PathBuf, AppError> {
    let root_id = location
        .archive_root_id
        .as_deref()
        .ok_or_else(|| AppError::Input("host script requires filesystem Locations".into()))?;
    let mount: Option<String> = catalog.connection().query_row(
        "SELECT mount_root_uri FROM device_mounts WHERE archive_root_id=?1 AND host_id=?2 ORDER BY observed_time_utc_ms DESC,mount_id DESC LIMIT 1",
        params![root_id, cli.host], |row| row.get(0),
    ).optional()?;
    let mount = PathBuf::from(mount.ok_or_else(|| {
        AppError::Input(format!(
            "Location {:?} has no recorded mount for this host",
            location.display_name
        ))
    })?);
    validate_root(&mount)?;
    let relative = location
        .relative_path
        .as_ref()
        .ok_or_else(|| AppError::Input("Location lacks a relative path".into()))?;
    let bytes = registry_path_identity_bytes(relative)?;
    if bytes.contains(&0) {
        return Err(AppError::Input("Location path contains NUL".into()));
    }
    let relative = relative_path_from_bytes(&relative.encoding, &bytes)?;
    if relative
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(AppError::Input(
            "Location path must be relative without '.' or '..'".into(),
        ));
    }
    Ok(mount.join(relative))
}

// Data for a quoted heredoc, decoded by Bash's builtin printf %b, never eval.
// Every filename occupies one physical line; escape the delimiter itself too.
pub(super) fn write_manifest_path(output: &mut impl Write, path: &[u8]) -> std::io::Result<()> {
    for (index, byte) in path.iter().copied().enumerate() {
        match byte {
            b'A' if index == 0 && path == b"ARCHIVE_LEDGER_PATHS" => {
                output.write_all(b"\\0101")?;
            }
            b'\\' => output.write_all(b"\\\\")?,
            b'\n' => output.write_all(b"\\n")?,
            b'\r' => output.write_all(b"\\r")?,
            b'\t' => output.write_all(b"\\t")?,
            b' '..=b'~' => output.write_all(&[byte])?,
            _ => write!(output, "\\0{byte:03o}")?,
        }
    }
    writeln!(output)
}
