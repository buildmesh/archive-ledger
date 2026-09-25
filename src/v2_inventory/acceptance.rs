use super::*;
use std::path::Component;

#[derive(Debug, Clone, Serialize)]
pub struct V2ChangePreview {
    pub path: RegistryPath,
    pub expected_object_id: String,
    pub observed_object_id: String,
    pub changed: bool,
}

/// Hash only explicitly selected cataloged ordinary files, without writing jobs or events.
pub fn preview_changes(
    projection: &V2ProjectionDb,
    config: &V2InventoryConfig,
) -> Result<Vec<V2ChangePreview>> {
    validate_config(config)?;
    let connection =
        Connection::open_with_flags(projection.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|source| inventory_sqlite_error(projection.path(), source))?;
    let files = selected_files(&connection, projection.path(), config)?;
    files
        .iter()
        .map(|file| {
            let relative = raw_relative_path(&file.relative_path)?;
            let expected_object_id =
                selected_object(&connection, projection.path(), config, &relative)?;
            validate_selected_path(config, &relative)?;
            let hashed = match hash_file_stable(&config.root_path.join(&relative), file, false) {
                HashOutcome::Stable(hashed) => hashed,
                _ => {
                    return Err(V2InventoryError::Invalid(format!(
                        "cannot stably read selected file {}",
                        relative.display()
                    )))
                }
            };
            validate_selected_path(config, &relative)?;
            let observed_object_id = format!("blake3:{}", hashed.blake3_hex);
            Ok(V2ChangePreview {
                path: RegistryPath::from_path(&relative),
                changed: expected_object_id != observed_object_id,
                expected_object_id,
                observed_object_id,
            })
        })
        .collect()
}

fn selected_object(
    connection: &Connection,
    database: &Path,
    config: &V2InventoryConfig,
    relative: &Path,
) -> Result<String> {
    let logical = encode_relative_path(&prefixed_path(config.logical_prefix.as_deref(), relative));
    let expected: Option<String> = connection
        .query_row(
            "SELECT f.object_id FROM file_refs f WHERE f.collection_id = ?1
         AND f.logical_path_encoding = ?2 AND f.logical_path_bytes = ?3
         AND f.path_state = 'active' AND f.identity_state = 'resolved'
         AND f.object_id IS NOT NULL AND f.external_identity_id IS NULL
         AND NOT EXISTS (SELECT 1 FROM path_observations p WHERE p.file_ref_id = f.file_ref_id
             AND (p.external_identity_id IS NOT NULL OR p.representation != 'ordinary_file'))",
            params![
                config.collection_id,
                logical.encoding.as_str(),
                logical.bytes
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| inventory_sqlite_error(database, source))?;
    expected.ok_or_else(|| {
        V2InventoryError::Invalid(format!(
            "accept-changes requires an existing ordinary file with resolved identity; annex identities are not eligible: {}",
            relative.display()
        ))
    })
}

pub(super) fn validate_selected_path(
    config: &V2InventoryConfig,
    relative: &Path,
) -> Result<fs::Metadata> {
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(name) if name != ".git"))
        || config
            .exclusions
            .iter()
            .any(|excluded| relative.starts_with(excluded))
    {
        return Err(V2InventoryError::Invalid(format!("accept-changes path must be an unexcluded relative file without parent traversal or .git: {}", relative.display())));
    }
    let root = fs::canonicalize(&config.root_path)
        .map_err(|source| io_error("resolve inventory root", &config.root_path, source))?;
    let root_metadata =
        fs::metadata(&root).map_err(|source| io_error("stat inventory root", &root, source))?;
    let mut path = root.clone();
    for part in relative.components() {
        path.push(part);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("stat selected file", &path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(V2InventoryError::Invalid(format!(
                "accept-changes cannot follow symlinks: {}",
                relative.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != root_metadata.dev() {
                return Err(V2InventoryError::Invalid(format!(
                    "accept-changes cannot cross filesystem boundaries: {}",
                    relative.display()
                )));
            }
        }
    }
    let resolved = fs::canonicalize(&path)
        .map_err(|source| io_error("resolve selected file", &path, source))?;
    if !resolved.starts_with(&root) {
        return Err(V2InventoryError::Invalid(
            "selected file escapes inventory root".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|source| io_error("stat selected file", &path, source))?;
    if !metadata.is_file() {
        return Err(V2InventoryError::Invalid(format!(
            "accept-changes requires an exact regular file: {}",
            relative.display()
        )));
    }
    Ok(metadata)
}

pub(super) fn selected_files(
    connection: &Connection,
    database: &Path,
    config: &V2InventoryConfig,
) -> Result<Vec<DiscoveredFile>> {
    let mut selected = std::collections::HashSet::new();
    config
        .accept_changes
        .iter()
        .map(|relative| {
            if !selected.insert(relative.clone()) {
                return Err(V2InventoryError::Invalid(format!(
                    "duplicate accept-changes path: {}",
                    relative.display()
                )));
            }
            let metadata = validate_selected_path(config, relative)?;
            selected_object(connection, database, config, relative)?;
            Ok(DiscoveredFile {
                relative_path: encode_relative_path(relative),
                size_bytes: metadata.len(),
                modified_time_utc_ms: modified_time_ms(&metadata),
            })
        })
        .collect()
}
