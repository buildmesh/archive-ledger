//! Read-only preview of a scan or add: how disk and catalog differ, from
//! metadata alone. It shares discovery and the unchanged-file rule with the real
//! walk, never reads file content, and writes nothing.

use std::collections::{BTreeMap, HashSet};

use super::*;

/// At most this many paths are listed per category, in stable path order.
const PREVIEW_LIST_LIMIT: usize = 20;

#[derive(Debug, Clone, Default, Serialize)]
pub struct V2PreviewCategory {
    pub count: u64,
    pub bytes: u64,
    /// The first paths in encoded-path order; `truncated` when more exist.
    pub paths: Vec<String>,
    pub truncated: bool,
    #[serde(skip)]
    listed: BTreeMap<(String, Vec<u8>), String>,
}

impl V2PreviewCategory {
    fn add(&mut self, path: &EncodedPath, size: u64) {
        self.add_raw(path.encoding.as_str(), &path.bytes, &path.display, size);
    }

    fn add_raw(&mut self, encoding: &str, bytes: &[u8], display: &str, size: u64) {
        self.count = self.count.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
        self.listed
            .insert((encoding.to_owned(), bytes.to_vec()), display.to_owned());
        if self.listed.len() > PREVIEW_LIST_LIMIT {
            self.listed.pop_last();
            self.truncated = true;
        }
    }

    fn finish(&mut self) {
        self.paths = std::mem::take(&mut self.listed).into_values().collect();
    }
}

/// Differences a real run would act on. Integrity results cannot be predicted
/// without reading bytes, so read categories say what would be read, not what
/// it would find.
#[derive(Debug, Clone, Default, Serialize)]
pub struct V2ScanPreview {
    /// On disk, no File at this logical path: would be read and added.
    pub new_files: V2PreviewCategory,
    /// A known File not currently recorded at this Location (copied or moved in,
    /// or reappeared): would be read and recorded here.
    pub new_at_location: V2PreviewCategory,
    /// Recorded here, but size or modification time changed: would be read.
    pub changed: V2PreviewCategory,
    /// Unchanged metadata, but the copy here is corrupt, unknown, or not yet
    /// verified: would be read.
    pub needs_reading: V2PreviewCategory,
    /// Recorded present here but not on disk: a complete scan would mark it
    /// missing. Always empty for `collection add`.
    pub missing: V2PreviewCategory,
    /// Registered annex content whose object file is gone.
    pub annex_content_absent: V2PreviewCategory,
    /// Small annex-tracked files that are neither unchanged, the recorded content
    /// size, nor a pointer's size; telling needs a read, which a preview does not do.
    pub uncertain: V2PreviewCategory,
    /// Registered annex links that cannot be resolved: the real scan records a read
    /// error for each and becomes partial.
    pub unreadable: V2PreviewCategory,
    /// Annex content absent where that is already recorded, or where an add would
    /// not record it: nothing to do.
    pub recorded_absent: u64,
    /// Known files with the same size and mtime as a good copy here: not read.
    pub unchanged: u64,
    /// Annex entries whose content identity is not known yet (not read by a scan).
    pub without_identity: u64,
    pub ignored_symlinks: u64,
    pub ignored_special_files: u64,
    pub excluded_subtrees: u64,
    pub filesystem_boundaries: u64,
    pub traversal_errors: u64,
    pub concurrent_changes: u64,
    /// False when traversal problems would make a complete scan partial, in
    /// which case it would not mark anything missing.
    pub complete_coverage: bool,
}

impl V2ScanPreview {
    /// Whether a real run would record anything other than routine presence refresh.
    pub fn actionable(&self) -> bool {
        [
            &self.new_files,
            &self.new_at_location,
            &self.changed,
            &self.needs_reading,
            &self.missing,
            &self.annex_content_absent,
            &self.uncertain,
            &self.unreadable,
        ]
        .iter()
        .any(|category| category.count > 0)
    }
}

/// Why an on-disk file would be added by a positive inventory run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V2NewFileKind {
    NewToCollection,
    NewToLocation,
}

type NewFileVisitor<'a> = dyn FnMut(V2NewFileKind, &EncodedPath, u64) -> Result<()> + 'a;

/// Visit every newly discovered File or Location presence in discovery order,
/// without reading content or changing the catalog. Summary path samples remain
/// bounded; the visitor is called immediately and may stop the walk with an error.
/// Only novelty and traversal/annex uncertainty counters are populated: recorded
/// ordinary files are not checked for verification status or changed metadata.
/// `location_root` is the actual registered Location root, including when the
/// inventory config selects a subtree. Only positive (`Add`) previews are supported.
pub fn visit_new_files(
    projection: &V2ProjectionDb,
    config: &V2InventoryConfig,
    location_root: &Path,
    visitor: &mut NewFileVisitor<'_>,
) -> Result<V2ScanPreview> {
    if config.scan_mode != ScanMode::Add || !config.accept_changes.is_empty() {
        return Err(V2InventoryError::Invalid(
            "listing new files requires an add preview without accept_changes".to_owned(),
        ));
    }
    let prefix = config
        .location_prefix
        .as_deref()
        .unwrap_or_else(|| Path::new(""));
    if !prefix
        .components()
        .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err(V2InventoryError::Invalid(
            "Location prefix must be a relative path without parent traversal".to_owned(),
        ));
    }
    let location_root = fs::canonicalize(location_root)
        .map_err(|source| io_error("resolve Location root", location_root, source))?;
    let scan_root = fs::canonicalize(&config.root_path)
        .map_err(|source| io_error("resolve inventory root", &config.root_path, source))?;
    let expected_root = location_root.join(prefix);
    let expected_root = fs::canonicalize(&expected_root)
        .map_err(|source| io_error("resolve Location subtree", &expected_root, source))?;
    if expected_root != scan_root || !scan_root.starts_with(&location_root) {
        return Err(V2InventoryError::Invalid(
            "inventory root does not match the Location root and prefix".to_owned(),
        ));
    }
    walk_preview(projection, config, &location_root, true, visitor)
}

pub fn preview_scan(
    projection: &V2ProjectionDb,
    config: &V2InventoryConfig,
) -> Result<V2ScanPreview> {
    walk_preview(
        projection,
        config,
        &config.root_path,
        false,
        &mut |_, _, _| Ok(()),
    )
}

fn walk_preview(
    projection: &V2ProjectionDb,
    config: &V2InventoryConfig,
    annex_root: &Path,
    list_new_only: bool,
    visitor: &mut NewFileVisitor<'_>,
) -> Result<V2ScanPreview> {
    validate_config(config)?;
    validate_scope(projection.path(), config)?;
    let database = projection.path();
    let connection = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|source| inventory_sqlite_error(database, source))?;
    let annex_imported: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM annex_imports WHERE collection_id = ?1 AND worktree_location_id = ?2 AND status = 'complete')",
            params![config.collection_id, config.location_id],
            |row| row.get(0),
        )
        .map_err(|source| inventory_sqlite_error(database, source))?;
    let mut preview = V2ScanPreview::default();
    let mut seen = HashSet::new();
    for discovered in FileDiscovery::with_exclusions(&config.root_path, config.exclusions.clone())?
    {
        match discovered {
            DiscoveryItem::File(file) => {
                let relative = raw_relative_path(&file.relative_path)?;
                let logical = encode_relative_path(&prefixed_path(
                    config.logical_prefix.as_deref(),
                    &relative,
                ));
                let here = encode_relative_path(&prefixed_path(
                    config.location_prefix.as_deref(),
                    &relative,
                ));
                if config.scan_mode == ScanMode::Complete {
                    seen.insert((logical.encoding.as_str().to_owned(), logical.bytes.clone()));
                }
                let annex = if annex_imported {
                    known_annex_entry(
                        &connection,
                        database,
                        &config.collection_id,
                        &config.location_id,
                        &logical,
                    )?
                } else {
                    None
                };
                // The real walk reads up to 32 KiB to recognize an annex pointer file.
                // Without reading: unchanged content is skipped, the recorded content
                // size is content, and a pointer's size is fixed by its key.
                if let Some(known) = annex.as_ref().filter(|_| file.size_bytes <= 32 * 1024) {
                    if !list_new_only
                        && copy_unchanged(
                            &connection,
                            database,
                            &config.collection_id,
                            &config.location_id,
                            &here,
                            file.size_bytes,
                            file.modified_time_utc_ms,
                        )?
                    {
                        preview.unchanged = preview.unchanged.saturating_add(1);
                        continue;
                    }
                    let pointer_len = ("/annex/objects/".len() + known.external_key.len()) as u64;
                    let is_content = known.expected_size == Some(file.size_bytes);
                    let is_pointer = !is_content
                        && (file.size_bytes == pointer_len || file.size_bytes == pointer_len + 1);
                    if is_pointer {
                        if config.scan_mode == ScanMode::Complete
                            && copy_recorded(&connection, database, known)?
                        {
                            preview
                                .annex_content_absent
                                .add(&logical, known.expected_size.unwrap_or(0));
                        } else {
                            preview.recorded_absent = preview.recorded_absent.saturating_add(1);
                        }
                        continue;
                    }
                    if !is_content {
                        preview.uncertain.add(&logical, file.size_bytes);
                        continue;
                    }
                }
                if annex
                    .as_ref()
                    .is_some_and(|known| known.expected_hash_hex.is_none())
                {
                    preview.without_identity = preview.without_identity.saturating_add(1);
                    continue;
                }
                classify(
                    &connection,
                    database,
                    config,
                    &mut preview,
                    &logical,
                    &here,
                    file.size_bytes,
                    file.modified_time_utc_ms,
                    annex.is_some(),
                    list_new_only,
                    visitor,
                )?;
            }
            DiscoveryItem::Symlink(path) => {
                let relative = raw_relative_path(&path)?;
                let logical = encode_relative_path(&prefixed_path(
                    config.logical_prefix.as_deref(),
                    &relative,
                ));
                if !annex_imported {
                    preview.ignored_symlinks = preview.ignored_symlinks.saturating_add(1);
                    continue;
                }
                if config.scan_mode == ScanMode::Complete {
                    seen.insert((logical.encoding.as_str().to_owned(), logical.bytes.clone()));
                }
                let Some(known) = known_annex_entry(
                    &connection,
                    database,
                    &config.collection_id,
                    &config.location_id,
                    &logical,
                )?
                else {
                    preview.ignored_symlinks = preview.ignored_symlinks.saturating_add(1);
                    continue;
                };
                if known
                    .representation
                    .as_deref()
                    .is_some_and(|value| value != "annex_locked_symlink")
                    || known.expected_hash_hex.is_none()
                {
                    preview.without_identity = preview.without_identity.saturating_add(1);
                    continue;
                }
                let here = encode_relative_path(&prefixed_path(
                    config.location_prefix.as_deref(),
                    &relative,
                ));
                let annex_relative = if list_new_only {
                    prefixed_path(config.location_prefix.as_deref(), &relative)
                } else {
                    relative
                };
                match resolve_annex_content(annex_root, &annex_relative, &known)? {
                    AnnexContent::Present { metadata, .. } => classify(
                        &connection,
                        database,
                        config,
                        &mut preview,
                        &logical,
                        &here,
                        metadata.len(),
                        modified_time_ms(&metadata),
                        true,
                        list_new_only,
                        visitor,
                    )?,
                    AnnexContent::Absent => {
                        // Only a complete scan records absence, and only when it is new.
                        if config.scan_mode == ScanMode::Complete
                            && copy_recorded(&connection, database, &known)?
                        {
                            preview
                                .annex_content_absent
                                .add(&logical, known.expected_size.unwrap_or(0));
                        } else {
                            preview.recorded_absent = preview.recorded_absent.saturating_add(1);
                        }
                    }
                    AnnexContent::Error => preview.unreadable.add(&logical, 0),
                }
            }
            DiscoveryItem::Special(_) => {
                preview.ignored_special_files = preview.ignored_special_files.saturating_add(1)
            }
            DiscoveryItem::Excluded(_) => {
                preview.excluded_subtrees = preview.excluded_subtrees.saturating_add(1)
            }
            DiscoveryItem::FilesystemBoundary(_) => {
                preview.filesystem_boundaries = preview.filesystem_boundaries.saturating_add(1)
            }
            DiscoveryItem::ConcurrentChange(_) => {
                preview.concurrent_changes = preview.concurrent_changes.saturating_add(1)
            }
            DiscoveryItem::Error { .. } => {
                preview.traversal_errors = preview.traversal_errors.saturating_add(1)
            }
        }
    }
    // As in the real walk, read errors, not only traversal problems, make a scan partial.
    preview.complete_coverage = preview.traversal_errors == 0
        && preview.concurrent_changes == 0
        && preview.unreadable.count == 0;
    if config.scan_mode == ScanMode::Complete && preview.complete_coverage {
        // The same facts the real scan would turn into missing candidates.
        let mut missing = connection
            .prepare(
                "SELECT p.observed_path_encoding, p.observed_path_bytes, p.observed_path_display,
                        COALESCE(p.observed_size_bytes, 0)
                 FROM path_observations p
                 JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                 WHERE p.location_id = ?1 AND f.collection_id = ?2
                   AND (p.state = 'present' OR EXISTS (
                     SELECT 1 FROM copy_claims pending
                     WHERE pending.location_id = p.location_id
                       AND pending.external_identity_id = p.external_identity_id
                       AND pending.state = 'unknown'
                   ))",
            )
            .map_err(|source| inventory_sqlite_error(database, source))?;
        let rows = missing
            .query_map(params![config.location_id, config.collection_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|source| inventory_sqlite_error(database, source))?;
        for row in rows {
            let (encoding, bytes, display, size) =
                row.map_err(|source| inventory_sqlite_error(database, source))?;
            if !seen.contains(&(encoding.clone(), bytes.clone())) {
                preview.missing.add_raw(
                    &encoding,
                    &bytes,
                    &display,
                    u64::try_from(size).unwrap_or(0),
                );
            }
        }
    }
    for category in [
        &mut preview.new_files,
        &mut preview.new_at_location,
        &mut preview.changed,
        &mut preview.needs_reading,
        &mut preview.missing,
        &mut preview.annex_content_absent,
        &mut preview.uncertain,
        &mut preview.unreadable,
    ] {
        category.finish();
    }
    Ok(preview)
}

/// Whether an annex copy is currently recorded, so observing its absence is a change.
fn copy_recorded(
    connection: &Connection,
    database: &Path,
    known: &KnownAnnexEntry,
) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM copy_claims WHERE copy_claim_id = ?1 AND state NOT IN ('missing', 'superseded'))",
            [known.copy_claim_id.as_deref().unwrap_or_default()],
            |row| row.get(0),
        )
        .map_err(|source| inventory_sqlite_error(database, source))
}

/// Mirrors the real walk's order: unchanged first, then what reading would record.
#[allow(clippy::too_many_arguments)]
fn classify(
    connection: &Connection,
    database: &Path,
    config: &V2InventoryConfig,
    preview: &mut V2ScanPreview,
    logical: &EncodedPath,
    here: &EncodedPath,
    size_bytes: u64,
    modified_time_utc_ms: Option<u64>,
    annex: bool,
    list_new_only: bool,
    visitor: &mut NewFileVisitor<'_>,
) -> Result<()> {
    if !list_new_only
        && copy_unchanged(
            connection,
            database,
            &config.collection_id,
            &config.location_id,
            here,
            size_bytes,
            modified_time_utc_ms,
        )?
    {
        preview.unchanged = preview.unchanged.saturating_add(1);
        return Ok(());
    }
    // The real walk's lookup: an existing File at this path, active or not.
    let existing = file_at_path(connection, database, &config.collection_id, logical)?;
    let Some((object_id, identity_state)) = existing else {
        preview.new_files.add(logical, size_bytes);
        return visitor(V2NewFileKind::NewToCollection, logical, size_bytes);
    };
    if !annex && (identity_state != "resolved" || object_id.is_none()) {
        // The real run stops at this path, so the preview reports the same error.
        return Err(V2InventoryError::Invalid(format!(
            "cataloged path {} has unresolved identity; ordinary inventory cannot replace it",
            logical.display
        )));
    }
    let recorded = recorded_at_location(connection, database, config, here)?;
    if !recorded {
        preview.new_at_location.add(logical, size_bytes);
        return visitor(V2NewFileKind::NewToLocation, logical, size_bytes);
    }
    if list_new_only {
        return Ok(());
    }
    // A copy that is not present with a good last check is read whatever its metadata.
    let good_copy: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM path_observations p
             JOIN file_refs f ON f.file_ref_id = p.file_ref_id
             JOIN copy_claims c ON c.object_id = f.object_id AND c.location_id = p.location_id
               AND c.state = 'present' AND c.last_verification_result = 'ok'
               AND ((c.relative_path_encoding = p.observed_path_encoding
                     AND c.relative_path_bytes = p.observed_path_bytes)
                 OR (p.representation = 'annex_locked_symlink'
                     AND c.external_identity_id = p.external_identity_id))
             WHERE p.location_id = ?1 AND p.observed_path_encoding = ?2
               AND p.observed_path_bytes = ?3 AND p.state = 'present' AND f.collection_id = ?4)",
            params![
                config.location_id,
                here.encoding.as_str(),
                here.bytes,
                config.collection_id
            ],
            |row| row.get(0),
        )
        .map_err(|source| inventory_sqlite_error(database, source))?;
    if good_copy {
        preview.changed.add(logical, size_bytes);
    } else {
        preview.needs_reading.add(logical, size_bytes);
    }
    Ok(())
}

/// Probe active paths first through compact_file_path. The less common fallback
/// preserves the real walk's treatment of retired Files, scoped to this Collection.
fn file_at_path(
    connection: &Connection,
    database: &Path,
    collection_id: &str,
    path: &EncodedPath,
) -> Result<Option<(Option<i64>, String)>> {
    for active in [1, 0] {
        let found = connection
            .query_row(
                "SELECT content_id, identity_state FROM file_objects
             WHERE collection_id=(SELECT id FROM collections WHERE collection_id=?1)
               AND path_encoding=?2 AND path_bytes=?3 AND active=?4 LIMIT 1",
                params![collection_id, path.encoding.as_str(), path.bytes, active],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|source| inventory_sqlite_error(database, source))?;
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

fn recorded_at_location(
    connection: &Connection,
    database: &Path,
    config: &V2InventoryConfig,
    path: &EncodedPath,
) -> Result<bool> {
    for active in [1, 0] {
        let found = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM file_objects f
             JOIN file_locations p ON p.file_id=f.id
             WHERE f.collection_id=(SELECT id FROM collections WHERE collection_id=?1)
               AND f.path_encoding=?2 AND f.path_bytes=?3 AND f.active=?4
               AND p.location_id=(SELECT id FROM locations WHERE location_id=?5)
               AND p.presence=1 AND p.representation!='annex_content')",
                params![
                    config.collection_id,
                    path.encoding.as_str(),
                    path.bytes,
                    active,
                    config.location_id
                ],
                |row| row.get(0),
            )
            .map_err(|source| inventory_sqlite_error(database, source))?;
        if found {
            return Ok(true);
        }
    }
    Ok(false)
}
