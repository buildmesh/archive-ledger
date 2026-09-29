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

pub fn preview_scan(
    projection: &V2ProjectionDb,
    config: &V2InventoryConfig,
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
                seen.insert((logical.encoding.as_str().to_owned(), logical.bytes.clone()));
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
                    if copy_unchanged(
                        &connection,
                        database,
                        &config.collection_id,
                        &config.location_id,
                        &here,
                        file.size_bytes,
                        file.modified_time_utc_ms,
                    )? {
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
                seen.insert((logical.encoding.as_str().to_owned(), logical.bytes.clone()));
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
                if known.representation != "annex_locked_symlink"
                    || known.expected_hash_hex.is_none()
                {
                    preview.without_identity = preview.without_identity.saturating_add(1);
                    continue;
                }
                let here = encode_relative_path(&prefixed_path(
                    config.location_prefix.as_deref(),
                    &relative,
                ));
                match resolve_annex_content(&config.root_path, &relative, &known)? {
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
) -> Result<()> {
    if copy_unchanged(
        connection,
        database,
        &config.collection_id,
        &config.location_id,
        here,
        size_bytes,
        modified_time_utc_ms,
    )? {
        preview.unchanged = preview.unchanged.saturating_add(1);
        return Ok(());
    }
    // The real walk's lookup: an existing File at this path, active or not.
    let existing: Option<(Option<String>, String)> = connection
        .query_row(
            "SELECT object_id, identity_state FROM file_refs WHERE collection_id = ?1 AND logical_path_encoding = ?2 AND logical_path_bytes = ?3 ORDER BY (path_state = 'active') DESC LIMIT 1",
            params![config.collection_id, logical.encoding.as_str(), logical.bytes],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|source| inventory_sqlite_error(database, source))?;
    let Some((object_id, identity_state)) = existing else {
        preview.new_files.add(logical, size_bytes);
        return Ok(());
    };
    if !annex && (identity_state != "resolved" || object_id.is_none()) {
        // The real run stops at this path, so the preview reports the same error.
        return Err(V2InventoryError::Invalid(format!(
            "cataloged path {} has unresolved identity; ordinary inventory cannot replace it",
            logical.display
        )));
    }
    let recorded: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM path_observations p
             JOIN file_refs f ON f.file_ref_id = p.file_ref_id
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
    if !recorded {
        preview.new_at_location.add(logical, size_bytes);
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
