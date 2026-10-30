//! Filesystem workflows for authoritative SQLite catalogs.
use super::*;
use archive_ledger::discovery::EncodedPath;
use archive_ledger::sqlite_catalog::SqliteCatalog;
use archive_ledger::sqlite_writes::{hash_catalog_file, CatalogObservation, ObservationResult};
use std::fs;

pub(super) struct Scope {
    pub collection_id: String,
    pub location: LocationSnapshot,
    pub root: PathBuf,
    pub relative_prefix: PathBuf,
}

pub(super) fn location_path(
    cli: &Cli,
    catalog: &SqliteCatalog,
    location: &LocationSnapshot,
) -> Result<PathBuf, AppError> {
    let root_id = location
        .archive_root_id
        .as_deref()
        .ok_or_else(|| AppError::Input("Location has no local filesystem root".into()))?;
    let mount:Option<(String,String,String)>=catalog.connection().query_row(
        "SELECT mount_root_uri,status,fingerprint_status FROM device_mounts WHERE archive_root_id=?1 AND host_id=?2 ORDER BY observed_time_utc_ms DESC,mount_id DESC LIMIT 1",params![root_id,cli.host],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let (mount, status, fingerprint) = mount.ok_or_else(|| {
        AppError::Input(format!(
            "Location {:?} has no recorded mount on this host",
            location.display_name
        ))
    })?;
    if status != "mounted" || fingerprint == "mismatch" {
        return Err(AppError::Input(
            "Location is not mounted with matching identity".into(),
        ));
    }
    let relative = location
        .relative_path
        .as_ref()
        .ok_or_else(|| AppError::Input("Location has no relative filesystem path".into()))?;
    let recorded_mount = PathBuf::from(mount);
    let root = recorded_mount.join(relative_path_from_bytes(
        &relative.encoding,
        &registry_path_identity_bytes(relative)?,
    )?);
    validate_location_path(catalog, location, &root)?;
    let mounted = archive_ledger::discover_mounted_filesystem(&root)?;
    if fs::canonicalize(&mounted.mount_root)? != fs::canonicalize(&recorded_mount)? {
        return Err(AppError::Input(
            "registered mount is no longer mounted at its recorded path".into(),
        ));
    }
    Ok(fs::canonicalize(root)?)
}
fn validate_location_path(
    catalog: &SqliteCatalog,
    location: &LocationSnapshot,
    path: &Path,
) -> Result<(), AppError> {
    let state = catalog.registry_state(false)?;
    let root = state
        .archive_roots
        .iter()
        .find(|r| Some(&r.archive_root_id) == location.archive_root_id.as_ref())
        .ok_or_else(|| AppError::Input("Location root is missing or retired".into()))?;
    let device = state
        .devices
        .iter()
        .find(|d| d.device_id == root.device_id)
        .ok_or_else(|| AppError::Input("Location Device is missing or retired".into()))?;
    if root.identity_state == "conflict" || device.identity_state == "conflict" {
        return Err(AppError::Input(
            "Location has conflicting Device/root identity".into(),
        ));
    }
    if !fs::symlink_metadata(path)?.is_dir() {
        return Err(AppError::Input(
            "Location path must be a directory, not a symlink".into(),
        ));
    }
    if root.identity_state == "confirmed" {
        let mounted = archive_ledger::discover_mounted_filesystem(path)?;
        if mounted.filesystem_fingerprint != root.filesystem_fingerprint
            || mounted.fingerprint_kind != root.fingerprint_kind
        {
            return Err(AppError::Input(
                "mounted filesystem does not match the registered root fingerprint".into(),
            ));
        }
    }
    Ok(())
}
pub(super) fn resolve_scope(
    cli: &Cli,
    catalog: &SqliteCatalog,
    selector: Option<&str>,
    path: &Path,
    collection: Option<&str>,
) -> Result<Scope, AppError> {
    let path = fs::canonicalize(path)?;
    let state = catalog.registry_state(false)?;
    let (location, root) = if let Some(selector) = selector {
        let location = select_location(&state.locations, selector)?
            .ok_or_else(|| AppError::Input(format!("Location not found: {selector}")))?;
        let root = location_path(cli, catalog, &location)?;
        if !path.starts_with(&root) {
            return Err(AppError::Input(
                "path is outside the selected Location".into(),
            ));
        }
        (location, root)
    } else {
        let mut matching = state
            .locations
            .iter()
            .filter_map(|l| {
                location_path(cli, catalog, l)
                    .ok()
                    .filter(|root| path.starts_with(root))
                    .map(|root| (l.clone(), root))
            })
            .collect::<Vec<_>>();
        matching.sort_by_key(|(_, root)| std::cmp::Reverse(root.components().count()));
        if matching.is_empty() || (matching.len() > 1 && matching[0].1 == matching[1].1) {
            return Err(AppError::Input(
                "path does not identify exactly one Location; specify --location".into(),
            ));
        }
        matching.remove(0)
    };
    let collection_id = if let Some(selector) = collection {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector}")))?
            .collection_id
    } else if state.collections.len() == 1 {
        state.collections[0].collection_id.clone()
    } else {
        let mut query=catalog.connection().prepare("SELECT DISTINCT o.collection_id FROM objects o JOIN files f ON f.object_id=o.object_id WHERE f.location_id=?1 LIMIT 2")?;
        let ids = query
            .query_map([&location.location_id], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() != 1 {
            return Err(AppError::Input(
                "specify --collection for this Location".into(),
            ));
        }
        ids[0].clone()
    };
    Ok(Scope {
        collection_id,
        location,
        relative_prefix: path.strip_prefix(&root).unwrap().to_path_buf(),
        root,
    })
}

fn validate_saved_root(
    cli: &Cli,
    catalog: &SqliteCatalog,
    location_id: &str,
    saved: &Path,
) -> Result<(), AppError> {
    let state = catalog.registry_state(false)?;
    let location = select_location(&state.locations, location_id)?
        .ok_or_else(|| AppError::Input("job Location is missing or retired".into()))?;
    if location_path(cli, catalog, &location)? != fs::canonicalize(saved)? {
        return Err(AppError::Input(
            "Location mount changed since this job started; start a new job".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InventoryConfig {
    collection_id: String,
    location_id: String,
    root: PathBuf,
    path: PathBuf,
    exclusions: Vec<PathBuf>,
    accept_changes: Vec<PathBuf>,
    complete: bool,
    inventory_only: bool,
    #[serde(default)]
    annex_import: bool,
    #[serde(default)]
    import_id: Option<String>,
    batch_entries: usize,
}
#[derive(Default, Serialize)]
struct InventorySummary {
    files_observed: u64,
    confirmed_good: u64,
    integrity_mismatches: u64,
    read_errors: u64,
    missing_paths: u64,
    ignored_symlinks: u64,
    bytes_observed: u64,
    traversal_errors: u64,
}

pub(super) fn execute_write(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
) -> Result<Option<u8>, AppError> {
    let result = match &cli.command {
        Command::Collection {
            command: CollectionCommand::Add(args),
        } => add(cli, catalog, args)?,
        Command::Location {
            command: LocationCommand::Scan(args),
        } => scan(cli, catalog, args)?,
        Command::Scan(args) => legacy_scan(cli, catalog, args)?,
        Command::Import {
            command: ImportCommand::Annex(args),
        } => legacy_annex(cli, catalog, args)?,
        Command::Verify(args) => verify(cli, catalog, args)?,
        Command::Location {
            command: LocationCommand::Copy(args),
        } => copy(cli, catalog, args)?,
        Command::Copy(args) if args.command.is_none() => copy(cli, catalog, &args.mutation)?,
        Command::Job { command } => job(cli, catalog, command)?,
        _ => return Ok(None),
    };
    Ok(Some(result))
}
fn legacy_scope_identity(
    catalog: &SqliteCatalog,
    scope: &Scope,
    device: &str,
    root: &str,
    fingerprint: &str,
) -> Result<(), AppError> {
    if fingerprint == "mismatch" {
        return Err(AppError::Input("filesystem fingerprint mismatch".into()));
    }
    let state = catalog.registry_state(false)?;
    let registered = state
        .archive_roots
        .iter()
        .find(|r| r.archive_root_id == root)
        .ok_or_else(|| AppError::Input("registered root not found".into()))?;
    if registered.device_id != device || scope.location.archive_root_id.as_deref() != Some(root) {
        return Err(AppError::Input(
            "supplied Device/root does not match the Location".into(),
        ));
    }
    Ok(())
}
fn legacy_scan(cli: &Cli, catalog: &mut SqliteCatalog, args: &ScanArgs) -> Result<u8, AppError> {
    if args.scan_id.is_some() {
        return Err(AppError::Input(
            "--scan-id is a legacy event identifier; use --job-id for SQLite scan jobs".into(),
        ));
    }

    if args
        .logical_prefix
        .as_ref()
        .is_some_and(|p| !p.as_os_str().is_empty())
    {
        return Err(AppError::Input("SQLite Locations use Collection-relative mirror paths; logical-prefix remapping is unsupported".into()));
    }
    let scope = resolve_scope(
        cli,
        catalog,
        Some(&args.location),
        &args.path,
        Some(&args.collection),
    )?;
    legacy_scope_identity(
        catalog,
        &scope,
        &args.device,
        &args.root,
        &args.fingerprint_status,
    )?;
    if !scope.relative_prefix.as_os_str().is_empty() {
        return Err(AppError::Input(
            "scan path must equal the Location root".into(),
        ));
    }
    run_inventory(
        cli,
        catalog,
        InventoryConfig {
            collection_id: scope.collection_id,
            location_id: scope.location.location_id,
            root: scope.root.clone(),
            path: scope.root,
            exclusions: args.exclusions.clone(),
            accept_changes: Vec::new(),
            complete: false,
            inventory_only: false,
            annex_import: false,
            import_id: None,
            batch_entries: args.batch_entries,
        },
        args.job_id.as_deref(),
        args.max_items,
        false,
        false,
    )
}
fn legacy_annex(cli: &Cli, catalog: &mut SqliteCatalog, args: &AnnexArgs) -> Result<u8, AppError> {
    let scope = resolve_scope(
        cli,
        catalog,
        Some(&args.worktree_location),
        &args.repository,
        Some(&args.collection),
    )?;
    legacy_scope_identity(catalog, &scope, &args.device, &args.root, "unavailable")?;
    let state = catalog.registry_state(false)?;
    let cas = select_location(&state.locations, &args.cas_location)?
        .ok_or_else(|| AppError::Input("annex CAS Location not found".into()))?;
    if cas.location_id != scope.location.location_id {
        return Err(AppError::Input("SQLite annex inventories track logical paths at the worktree Location; separate CAS Location mappings are unsupported".into()));
    }
    super::sqlite_setup_cli::check_annex_import(
        catalog,
        &scope.collection_id,
        &scope.location.location_id,
        false,
    )?;
    import_annex(
        cli,
        catalog,
        &scope.collection_id,
        &scope.location.location_id,
        &scope.root,
        false,
        args.import_id.as_deref(),
        args.job_id.as_deref(),
        args.max_items,
        args.batch_entries,
    )
}

fn add(cli: &Cli, catalog: &mut SqliteCatalog, args: &CollectionAddArgs) -> Result<u8, AppError> {
    if args.scan_id.is_some() {
        return Err(AppError::Input(
            "--scan-id is a legacy event identifier; use --job-id for SQLite scan jobs".into(),
        ));
    }

    let scope = resolve_scope(
        cli,
        catalog,
        args.location.as_deref(),
        &args.path,
        args.collection.as_deref(),
    )?;
    if !args.accept_changes.is_empty() && !args.dry_run && !args.yes {
        if args.non_interactive || !std::io::stdin().is_terminal() || !prompt_confirmation("Accept these files as the new expected checksums and invalidate previous backup verification?")? {return Err(AppError::Input("accepting content changes requires --yes".into()));}
    }
    run_inventory(
        cli,
        catalog,
        InventoryConfig {
            collection_id: scope.collection_id,
            location_id: scope.location.location_id,
            root: scope.root,
            path: fs::canonicalize(&args.path)?,
            exclusions: args.exclusions.clone(),
            accept_changes: args.accept_changes.clone(),
            complete: false,
            inventory_only: false,
            annex_import: false,
            import_id: None,
            batch_entries: args.batch_entries,
        },
        args.job_id.as_deref(),
        args.max_items,
        args.dry_run,
        args.list_new,
    )
}
fn scan(cli: &Cli, catalog: &mut SqliteCatalog, args: &LocationScanArgs) -> Result<u8, AppError> {
    if args.scan_id.is_some() {
        return Err(AppError::Input(
            "--scan-id is a legacy event identifier; use --job-id for SQLite scan jobs".into(),
        ));
    }

    let path = if let Some(path) = &args.path {
        path.clone()
    } else if let Some(selector) = args.location.as_deref() {
        let state = catalog.registry_state(false)?;
        let location = select_location(&state.locations, selector)?
            .ok_or_else(|| AppError::Input("Location not found".into()))?;
        location_path(cli, catalog, &location)?
    } else {
        std::env::current_dir()?
    };
    let scope = resolve_scope(
        cli,
        catalog,
        args.location.as_deref(),
        &path,
        args.collection.as_deref(),
    )?;
    if !scope.relative_prefix.as_os_str().is_empty() {
        return Err(AppError::Input(
            "location scan must start at the Location root".into(),
        ));
    }
    run_inventory(
        cli,
        catalog,
        InventoryConfig {
            collection_id: scope.collection_id,
            location_id: scope.location.location_id,
            root: scope.root.clone(),
            path: scope.root,
            exclusions: args.exclusions.clone(),
            accept_changes: Vec::new(),
            complete: true,
            inventory_only: false,
            annex_import: false,
            import_id: None,
            batch_entries: args.batch_entries,
        },
        args.job_id.as_deref(),
        args.max_items,
        args.dry_run,
        false,
    )
}

fn path_from_encoded(path: &EncodedPath) -> Result<PathBuf, AppError> {
    relative_path_from_bytes(path.encoding.as_str(), &path.bytes)
}
fn ordinary_relative(path: &Path) -> Result<(), AppError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(AppError::Input(
            "path must be a normalized relative file path".into(),
        ));
    }
    Ok(())
}
fn annex_content_root(path: &Path) -> Option<PathBuf> {
    if !archive_ledger::is_git_annex_repository(path).ok()? {
        return None;
    }
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let common = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    Some(common.join("annex/objects"))
}
// Reject indirection in Location-relative ancestors before reading any content.
// Discovery applies the same device boundary to walks; direct verify/copy paths
// must enforce it too, even when their leaf happens to be a regular file.
fn validate_content_ancestors(root: &Path, path: &Path) -> Result<(), AppError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| AppError::Input("content path escapes its Location".into()))?;
    ordinary_relative(relative)?;
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() {
        return Err(AppError::Input("Location root is not a directory".into()));
    }
    let mut current = root.to_path_buf();
    let count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if index + 1 < count && !metadata.is_dir() {
            return Err(AppError::Input(
                "content path has a symlink or non-directory ancestor".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != root_metadata.dev() {
                return Err(AppError::Input(
                    "content path crosses the Location filesystem boundary".into(),
                ));
            }
        }
    }
    Ok(())
}
fn content_path(
    root: &Path,
    path: &Path,
    annex_root: Option<&Path>,
) -> Result<Option<PathBuf>, AppError> {
    validate_content_ancestors(root, path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_file() {
        return Ok(Some(path.to_path_buf()));
    }
    if !metadata.file_type().is_symlink() {
        return Ok(None);
    }
    let Some(annex_root) = annex_root else {
        return Ok(None);
    };
    let link = fs::read_link(path)?;
    let target = path.parent().unwrap().join(link);
    // Resolve existing targets, and reject arbitrary symlinks outside annex storage.
    match fs::canonicalize(&target) {
        Ok(target) => {
            let annex = fs::canonicalize(annex_root)?;
            if !target.starts_with(annex) {
                return Ok(None);
            }
            validate_content_ancestors(root, &target)?;
            Ok(Some(target))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A dropped annex pointer is missing; an unrelated dangling link is ignored.
            if target.components().any(|c| c.as_os_str() == "annex")
                && target.components().any(|c| c.as_os_str() == "objects")
            {
                Err(error.into())
            } else {
                Ok(None)
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn run_inventory(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
    config: InventoryConfig,
    job: Option<&str>,
    max_items: Option<usize>,
    dry_run: bool,
    list_new: bool,
) -> Result<u8, AppError> {
    validate_saved_root(cli, catalog, &config.location_id, &config.root)?;
    if config.batch_entries == 0 {
        return Err(AppError::Input("--batch-entries must be positive".into()));
    }
    let mut first_dry_path = true;
    if dry_run && cli.json {
        print!("{{\"dry_run\":true,\"paths\":[");
    }
    let job_id = job
        .map(str::to_owned)
        .unwrap_or_else(|| format!("job_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    let params = serde_json::to_value(&config)?;
    if !dry_run {
        let status = catalog.begin_catalog_job(&job_id, "inventory", &params, now_utc_ms()?)?;
        if status != "running" {
            if cli.json {
                println!("{}", json!({"status":status,"job_id":job_id}));
            } else {
                println!("Job {job_id}: {status}");
            }
            return Ok(EXIT_OK);
        }
        catalog.reset_scan_coverage(&job_id)?;
    }
    let annex_root = annex_content_root(&config.path);
    let mut summary = InventorySummary::default();
    let mut batch = Vec::new();
    let mut new_work = 0;
    let mut paused = false;
    let mut unsafe_coverage = false;
    let mut discovery = FileDiscovery::with_exclusions(&config.path, config.exclusions.clone())
        .map_err(|e| AppError::Input(e.to_string()))?;
    let selected = config
        .accept_changes
        .iter()
        .map(|p| {
            ordinary_relative(p)?;
            Ok(p.clone())
        })
        .collect::<Result<BTreeSet<_>, AppError>>()?;
    let mut found_selected = BTreeSet::new();
    if annex_root.is_some() && selected.is_empty() && !dry_run {
        paused = inventory_annex_entries(
            catalog,
            &config,
            &job_id,
            max_items,
            &mut new_work,
            &mut summary,
            None,
        )?;
    }
    for item in &mut discovery {
        if config.inventory_only {
            break;
        }
        if paused {
            break;
        }
        let relative = match item {
            DiscoveryItem::File(file) => path_from_encoded(&file.relative_path)?,
            DiscoveryItem::Symlink(path) => {
                if annex_root.is_none() {
                    summary.ignored_symlinks += 1;
                    continue;
                }
                path_from_encoded(&path)?
            }
            DiscoveryItem::Error { .. } | DiscoveryItem::ConcurrentChange(_) => {
                summary.traversal_errors += 1;
                unsafe_coverage = true;
                continue;
            }
            DiscoveryItem::FilesystemBoundary(_) | DiscoveryItem::Special(_) => {
                unsafe_coverage = true;
                continue;
            }
            DiscoveryItem::Excluded(_) => continue,
        };
        if !selected.is_empty() && !selected.contains(&relative) {
            continue;
        }
        found_selected.insert(relative.clone());
        let physical = config.path.join(&relative);
        if !selected.is_empty() && !fs::symlink_metadata(&physical)?.is_file() {
            return Err(AppError::Input("--accept-changes requires an ordinary regular file; annex references must retain their content key".into()));
        }
        let logical = physical
            .strip_prefix(&config.root)
            .map_err(|_| AppError::Input("inventory escapes Location".into()))?;
        let path = RegistryPath::from_path(logical);
        let bytes = registry_path_identity_bytes(&path)?;
        if annex_root.is_some() && !dry_run && selected.is_empty() {
            let checked:bool=catalog.connection().query_row("SELECT EXISTS(SELECT 1 FROM objects o JOIN catalog_scan_seen s ON s.object_id=o.object_id WHERE s.job_id=?1 AND o.collection_id=?2 AND o.relative_path_encoding=?3 AND o.relative_path_bytes=?4)",params![job_id,config.collection_id,path.encoding,bytes],|r|r.get(0))?;
            if checked {
                continue;
            }
        }

        let processed: bool = if dry_run {
            false
        } else {
            catalog.connection().query_row("SELECT EXISTS(SELECT 1 FROM objects o JOIN catalog_job_items j ON j.object_id=o.object_id WHERE j.job_id=?1 AND o.collection_id=?2 AND o.relative_path_encoding=?3 AND o.relative_path_bytes=?4)",params![job_id,config.collection_id,path.encoding,bytes],|r|r.get(0))?
        };
        if !processed && max_items.is_some_and(|max| new_work >= max) {
            paused = true;
            break;
        }
        if !processed {
            new_work += 1;
        }
        if dry_run {
            let known:bool=catalog.connection().query_row("SELECT EXISTS(SELECT 1 FROM objects o JOIN files f ON f.object_id=o.object_id WHERE o.collection_id=?1 AND o.relative_path_encoding=?2 AND o.relative_path_bytes=?3 AND f.location_id=?4)",params![config.collection_id,path.encoding,bytes,config.location_id],|r|r.get(0))?;
            if !list_new || !known {
                if cli.json {
                    if !first_dry_path {
                        print!(",");
                    }
                    print!("{}", serde_json::to_string(&path)?);
                    first_dry_path = false;
                } else {
                    println!("{}", path.display.escape_debug());
                }
            }
            if !selected.is_empty() {
                let target = content_path(&config.root, &physical, annex_root.as_deref())?
                    .ok_or_else(|| AppError::Input("accepted path is not a regular file".into()))?;
                hash_catalog_file(&target)?;
            }
            continue;
        }
        let result = if config.inventory_only {
            ObservationResult::MetadataUnknown
        } else {
            match content_path(&config.root, &physical, annex_root.as_deref()) {
                Ok(Some(target)) => match hash_catalog_file(&target) {
                    Ok((blake3, size_bytes))
                        if content_path(&config.root, &physical, annex_root.as_deref())
                            .ok()
                            .flatten()
                            .as_ref()
                            == Some(&target) =>
                    {
                        summary.bytes_observed += size_bytes;
                        ObservationResult::Checksum { blake3, size_bytes }
                    }
                    Ok(_) | Err(_) => {
                        summary.read_errors += 1;
                        ObservationResult::ReadError
                    }
                },
                Ok(None) => {
                    summary.ignored_symlinks += 1;
                    continue;
                }
                Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    ObservationResult::Missing
                }
                Err(_) => {
                    summary.read_errors += 1;
                    ObservationResult::ReadError
                }
            }
        };
        summary.files_observed += 1;
        batch.push(CatalogObservation {
            collection_id: config.collection_id.clone(),
            location_id: config.location_id.clone(),
            path,
            time_utc_ms: now_utc_ms()?,
            accept_change: !selected.is_empty()
                && matches!(result, ObservationResult::Checksum { .. }),
            result,
            operation_key: None,
            job_id: Some(job_id.clone()),
        });
        if batch.len() >= config.batch_entries {
            flush_inventory(catalog, &mut batch, &mut summary)?;
        }
    }
    if !selected.is_empty() && found_selected != selected && !paused {
        return Err(AppError::Input(
            "one or more accepted paths were not found".into(),
        ));
    }
    if dry_run {
        if cli.json {
            println!("]}}");
        }
        return Ok(EXIT_OK);
    }
    flush_inventory(catalog, &mut batch, &mut summary)?;
    let status = if paused {
        catalog.checkpoint_catalog_job(&job_id, &serde_json::to_value(&summary)?)?;
        "running"
    } else if config.complete {
        let clean = !unsafe_coverage
            && summary.read_errors == 0
            && config.exclusions.is_empty()
            && config.path == config.root;
        summary.missing_paths = catalog.finish_catalog_scan(
            &job_id,
            &config.collection_id,
            &config.location_id,
            clean,
            now_utc_ms()?,
            &serde_json::to_value(&summary)?,
        )? as u64;
        if clean {
            "complete"
        } else {
            "partial"
        }
    } else {
        catalog.finish_catalog_job(
            &job_id,
            "complete",
            now_utc_ms()?,
            &serde_json::to_value(&summary)?,
        )?;
        "complete"
    };
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"version":1,"job_id":job_id,"status":status,"summary":summary})
            )?
        );
    } else {
        println!(
            "{status}: {} paths checked, {} verified, {} mismatches, {} read errors, {} missing.",
            summary.files_observed,
            summary.confirmed_good,
            summary.integrity_mismatches,
            summary.read_errors,
            summary.missing_paths
        );
        if paused {
            println!("Resume with: archive job resume {job_id}");
        }
    }
    Ok(
        if summary.integrity_mismatches > 0
            || summary.read_errors > 0
            || summary.traversal_errors > 0
        {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}
fn flush_inventory(
    catalog: &mut SqliteCatalog,
    batch: &mut Vec<CatalogObservation>,
    summary: &mut InventorySummary,
) -> Result<(), AppError> {
    for outcome in catalog.observe_batch(batch)? {
        match outcome.result.as_str() {
            "ok" => summary.confirmed_good += 1,
            "mismatch" => summary.integrity_mismatches += 1,
            _ => {}
        }
    }
    batch.clear();
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifyConfig {
    collection_id: String,
    location_id: String,
    root: PathBuf,
    all: bool,
    cutoff: u64,
    object_id: Option<String>,
    #[serde(default = "default_verify_batch_entries")]
    batch_entries: usize,
}
fn default_verify_batch_entries() -> usize {
    500
}
fn verify(cli: &Cli, catalog: &mut SqliteCatalog, args: &VerifyArgs) -> Result<u8, AppError> {
    if args.copy.is_some() {
        return Err(AppError::Input("--copy selects legacy copy claims and is unsupported for SQLite catalogs; select a Location instead".into()));
    }
    if !matches!(args.fingerprint_status.as_str(), "match" | "unavailable") {
        return Err(AppError::Input("verification requires a matching mount; --fingerprint-status must be match or unavailable".into()));
    }
    if args.batch_entries == 0 || i64::try_from(args.batch_entries).is_err() {
        return Err(AppError::Input(
            "--batch-entries must be positive and fit the SQLite integer range".into(),
        ));
    }
    let state = catalog.registry_state(false)?;
    let locations = if let Some(selector) = &args.location {
        vec![select_location(&state.locations, selector)?
            .ok_or_else(|| AppError::Input("Location not found".into()))?]
    } else {
        state.locations.clone()
    };
    if args.job_id.is_some() && locations.len() != 1 {
        return Err(AppError::Input(
            "a fixed verification job ID requires one Location".into(),
        ));
    }
    if args.path.is_some() && locations.len() != 1 {
        return Err(AppError::Input(
            "--path requires one explicit Location".into(),
        ));
    }
    let mut exit = EXIT_OK;
    let mut reports = Vec::new();
    for location in locations {
        let root = if let Some(path) = &args.path {
            validate_location_path(catalog, &location, path)?;
            fs::canonicalize(path)?
        } else {
            match location_path(cli, catalog, &location) {
                Ok(path) => path,
                Err(error) if args.location.is_none() => {
                    eprintln!("Skipping {}: {error}", location.display_name);
                    continue;
                }
                Err(error) => return Err(error),
            }
        };
        let ids=catalog.connection().prepare("SELECT DISTINCT o.collection_id FROM objects o JOIN files f ON f.object_id=o.object_id WHERE f.location_id=?1")?.query_map([&location.location_id],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
        if ids.len() > 1 && args.job_id.is_some() {
            return Err(AppError::Input(
                "a fixed verification job ID requires a Location containing one Collection".into(),
            ));
        }
        for collection_id in ids {
            let days = state
                .collections
                .iter()
                .find(|c| c.collection_id == collection_id)
                .and_then(|c| c.policy_id.as_ref())
                .and_then(|id| state.policies.iter().find(|p| &p.policy_id == id))
                .map_or(365, |p| p.requirements.max_verification_age_days);
            let cutoff = now_utc_ms()?.saturating_sub(
                days.saturating_sub(args.verify_within)
                    .saturating_mul(86_400_000),
            );
            exit = exit.max(run_verify(
                cli,
                catalog,
                VerifyConfig {
                    collection_id,
                    location_id: location.location_id.clone(),
                    root: root.clone(),
                    all: args.all,
                    cutoff,
                    object_id: None,
                    batch_entries: args.batch_entries,
                },
                args.job_id.as_deref(),
                args.max_items,
                Some(&mut reports),
            )?);
        }
    }
    if cli.json {
        println!("{}", json!({"jobs":reports}));
    }
    Ok(exit)
}
fn run_verify(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
    config: VerifyConfig,
    job: Option<&str>,
    max_items: Option<usize>,
    reports: Option<&mut Vec<serde_json::Value>>,
) -> Result<u8, AppError> {
    if config.batch_entries == 0 || i64::try_from(config.batch_entries).is_err() {
        return Err(AppError::Input("invalid verification batch size".into()));
    }
    validate_saved_root(cli, catalog, &config.location_id, &config.root)?;
    let job_id = job
        .map(str::to_owned)
        .unwrap_or_else(|| format!("job_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    let status = catalog.begin_catalog_job(
        &job_id,
        "verify",
        &serde_json::to_value(&config)?,
        now_utc_ms()?,
    )?;
    if status != "running" {
        let report = json!({"job_id":job_id,"location_id":config.location_id,"collection_id":config.collection_id,"status":status});
        if cli.json {
            if let Some(reports) = reports {
                reports.push(report);
            } else {
                println!("{report}");
            }
        } else {
            println!("Job {job_id}: {status}");
        }
        return Ok(EXIT_OK);
    }
    let annex_root = annex_content_root(&config.root);
    let mut summary = InventorySummary::default();
    let mut cursor = String::new();
    let mut processed = 0usize;
    let mut paused = false;
    if annex_root.is_some() {
        let inventory = InventoryConfig {
            collection_id: config.collection_id.clone(),
            location_id: config.location_id.clone(),
            root: config.root.clone(),
            path: config.root.clone(),
            exclusions: Vec::new(),
            accept_changes: Vec::new(),
            complete: false,
            inventory_only: false,
            annex_import: false,
            import_id: None,
            batch_entries: config.batch_entries,
        };
        paused = inventory_annex_entries(
            catalog,
            &inventory,
            &job_id,
            max_items,
            &mut processed,
            &mut summary,
            Some(&config),
        )?;
    }
    loop {
        if paused {
            break;
        }
        let rows=catalog.connection().prepare("SELECT o.object_id,o.relative_path_encoding,o.relative_path_bytes,o.relative_path_display FROM objects o JOIN files f ON f.object_id=o.object_id
            WHERE o.collection_id=?1 AND f.location_id=?2 AND o.object_id>?3 AND (?4 IS NULL OR o.object_id=?4)
            AND (?5 OR f.integrity!='verified' OR f.presence!='present' OR f.last_success_time_utc_ms IS NULL OR f.last_success_time_utc_ms<=?6)
            AND NOT EXISTS(SELECT 1 FROM catalog_job_items j WHERE j.job_id=?7 AND j.object_id=o.object_id)
            ORDER BY o.object_id LIMIT ?8")?.query_map(params![config.collection_id,config.location_id,cursor,config.object_id,config.all,config.cutoff as i64,job_id,config.batch_entries as i64],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,String>(3)?)))?.collect::<Result<Vec<_>,_>>()?;
        if rows.is_empty() {
            break;
        }
        let mut batch = Vec::new();
        for (id, encoding, bytes, display) in rows {
            if max_items.is_some_and(|max| processed >= max) {
                paused = true;
                break;
            }
            cursor = id;
            let relative = relative_path_from_bytes(&encoding, &bytes)?;
            ordinary_relative(&relative)?;
            let result = match content_path(
                &config.root,
                &config.root.join(&relative),
                annex_root.as_deref(),
            ) {
                Ok(Some(path)) => match hash_catalog_file(&path) {
                    Ok((blake3, size_bytes))
                        if content_path(
                            &config.root,
                            &config.root.join(&relative),
                            annex_root.as_deref(),
                        )
                        .ok()
                        .flatten()
                        .as_ref()
                            == Some(&path) =>
                    {
                        summary.bytes_observed += size_bytes;
                        ObservationResult::Checksum { blake3, size_bytes }
                    }
                    Ok(_) | Err(_) => {
                        summary.read_errors += 1;
                        ObservationResult::ReadError
                    }
                },
                Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    ObservationResult::Missing
                }
                _ => {
                    summary.read_errors += 1;
                    ObservationResult::ReadError
                }
            };
            batch.push(CatalogObservation {
                collection_id: config.collection_id.clone(),
                location_id: config.location_id.clone(),
                path: registry_path_from_sql(&encoding, &bytes, &display)?,
                time_utc_ms: now_utc_ms()?,
                result,
                accept_change: false,
                operation_key: None,
                job_id: Some(job_id.clone()),
            });
            summary.files_observed += 1;
            processed += 1;
        }
        flush_inventory(catalog, &mut batch, &mut summary)?;
        if paused {
            break;
        }
    }
    if paused {
        catalog.checkpoint_catalog_job(&job_id, &serde_json::to_value(&summary)?)?;
    } else {
        catalog.finish_catalog_job(
            &job_id,
            "complete",
            now_utc_ms()?,
            &serde_json::to_value(&summary)?,
        )?;
    }
    if cli.json {
        let report = json!({"job_id":job_id,"location_id":config.location_id,"collection_id":config.collection_id,"status":if paused {"running"}else{"complete"},"summary":summary});
        if let Some(reports) = reports {
            reports.push(report);
        } else {
            println!("{report}");
        }
    } else {
        println!(
            "Verified {} files; {} mismatches; {} read errors.",
            summary.files_observed, summary.integrity_mismatches, summary.read_errors
        );
        if paused {
            println!("Resume with: archive job resume {job_id}");
        }
    }
    Ok(
        if summary.integrity_mismatches > 0 || summary.read_errors > 0 {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CopyConfig {
    collection_id: String,
    location_id: String,
    source_location_id: String,
    root: PathBuf,
    source_root: PathBuf,
    filters: Vec<PathBuf>,
}
fn copy(cli: &Cli, catalog: &mut SqliteCatalog, args: &CopyMutationArgs) -> Result<u8, AppError> {
    let cwd = std::env::current_dir()?;
    let state = catalog.registry_state(false)?;
    let source_path = if let Some(source) = &args.from {
        let source = select_location(&state.locations, source)?
            .ok_or_else(|| AppError::Input("source Location not found".into()))?;
        location_path(cli, catalog, &source)?
    } else {
        cwd.clone()
    };
    let source = resolve_scope(
        cli,
        catalog,
        args.from.as_deref(),
        &source_path,
        args.collection.as_deref(),
    )?;
    let destination = select_location(
        &state.locations,
        args.to
            .as_deref()
            .ok_or_else(|| AppError::Input("copy requires --to".into()))?,
    )?
    .ok_or_else(|| AppError::Input("destination Location not found".into()))?;
    if destination.location_id == source.location.location_id {
        return Err(AppError::Input(
            "copy source and destination are the same Location".into(),
        ));
    }
    if !destination.is_writable && !args.dry_run {
        return Err(AppError::Input(
            "destination Location is not registered writable".into(),
        ));
    }
    let root = location_path(cli, catalog, &destination)?;
    let filters = if let Some(filters) = &args.logical_filters {
        filters.clone()
    } else {
        copy_logical_filters(
            &source.root,
            if cwd.starts_with(&source.root) {
                &cwd
            } else {
                &source.root
            },
            &args.paths,
        )?
    };
    if !args.dry_run && !args.yes {
        if args.non_interactive
            || !std::io::stdin().is_terminal()
            || !prompt_confirmation(
                "Copy the selected files without replacing existing destinations?",
            )?
        {
            return Err(AppError::Input("copy requires --yes or --dry-run".into()));
        }
    }
    run_copy(
        cli,
        catalog,
        CopyConfig {
            collection_id: source.collection_id,
            location_id: destination.location_id,
            source_location_id: source.location.location_id,
            root,
            source_root: source.root,
            filters,
        },
        args.job_id.as_deref(),
        args.max_items,
        args.dry_run,
    )
}
fn run_copy(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
    config: CopyConfig,
    job: Option<&str>,
    max_items: Option<usize>,
    dry_run: bool,
) -> Result<u8, AppError> {
    validate_saved_root(cli, catalog, &config.location_id, &config.root)?;
    validate_saved_root(
        cli,
        catalog,
        &config.source_location_id,
        &config.source_root,
    )?;
    if !dry_run {
        let state = catalog.registry_state(false)?;
        if !state
            .locations
            .iter()
            .any(|location| location.location_id == config.location_id && location.is_writable)
        {
            return Err(AppError::Input(
                "copy destination Location is not writable".into(),
            ));
        }
    }
    let mut first_dry_path = true;
    if dry_run && cli.json {
        print!("{{\"dry_run\":true,\"paths\":[");
    }
    let job_id = job
        .map(str::to_owned)
        .unwrap_or_else(|| format!("job_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    if !dry_run
        && catalog.begin_catalog_job(
            &job_id,
            "copy",
            &serde_json::to_value(&config)?,
            now_utc_ms()?,
        )? != "running"
    {
        return Ok(EXIT_OK);
    }
    let annex_root = annex_content_root(&config.source_root);
    let mut cursor = String::new();
    let mut count = 0usize;
    let mut paused = false;
    loop {
        let rows=catalog.connection().prepare("SELECT o.object_id,o.relative_path_encoding,o.relative_path_bytes,o.relative_path_display,o.expected_blake3 FROM objects o JOIN files f ON f.object_id=o.object_id WHERE o.collection_id=?1 AND f.location_id=?2 AND o.object_id>?3
            AND f.presence='present' AND f.integrity='verified' AND f.last_check_result='ok' AND f.observed_blake3=o.expected_blake3
            AND NOT EXISTS(SELECT 1 FROM files d WHERE d.object_id=o.object_id AND d.location_id=?4 AND d.presence='present' AND d.integrity='verified' AND d.last_check_result='ok' AND d.observed_blake3=o.expected_blake3)
            ORDER BY o.object_id LIMIT 500")?.query_map(params![config.collection_id,config.source_location_id,cursor,config.location_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,String>(3)?,r.get::<_,Vec<u8>>(4)?)))?.collect::<Result<Vec<_>,_>>()?;
        if rows.is_empty() {
            break;
        }
        for (id, encoding, bytes, display, expected) in rows {
            cursor = id;
            let relative = relative_path_from_bytes(&encoding, &bytes)?;
            ordinary_relative(&relative)?;
            if !config
                .filters
                .iter()
                .any(|p| p.as_os_str().is_empty() || relative == *p || relative.starts_with(p))
            {
                continue;
            }
            if max_items.is_some_and(|max| count >= max) {
                paused = true;
                break;
            }
            if dry_run {
                if cli.json {
                    if !first_dry_path {
                        print!(",");
                    }
                    print!(
                        "{}",
                        serde_json::to_string(&registry_path_from_sql(
                            &encoding, &bytes, &display
                        )?)?
                    );
                    first_dry_path = false;
                } else {
                    println!("{}", display.escape_debug());
                }

                count += 1;
                continue;
            }
            let source = content_path(
                &config.source_root,
                &config.source_root.join(&relative),
                annex_root.as_deref(),
            )?
            .ok_or_else(|| {
                AppError::Input("copy source is not a regular or annex content file".into())
            })?;
            let logical_destination = config.root.join(&relative);
            create_safe_destination_parents(&config.root, &relative)?;
            let saved_link = match fs::symlink_metadata(&logical_destination) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    Some(fs::read_link(&logical_destination)?)
                }
                Ok(_) => None,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            let destination = if let Some(target) = &saved_link {
                if !archive_ledger::is_git_annex_repository(&config.root)? {
                    return Err(AppError::Input(
                        "copy destination is an unmanaged symlink".into(),
                    ));
                }
                let key = archive_ledger::annex::validate_annex_restore_source(&source, target)?;
                let content = lexical_relative_path(logical_destination.parent().unwrap(), target)
                    .ok_or_else(|| AppError::Input("unsafe annex destination target".into()))?;
                let objects = config.root.join(".git/annex/objects");
                if !content.starts_with(&objects)
                    || content.file_name() != Some(std::ffi::OsStr::new(&key))
                    || content.parent().and_then(Path::file_name)
                        != Some(std::ffi::OsStr::new(&key))
                {
                    return Err(AppError::Input(
                        "annex destination target escapes its content storage".into(),
                    ));
                }
                let relative_content = content.strip_prefix(&config.root).unwrap();
                create_safe_destination_parents(&config.root, relative_content)?;
                content
            } else {
                logical_destination.clone()
            };
            let expected_hex = expected
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let copied = match fs::symlink_metadata(&destination) {
                Ok(_) => archive_ledger::verify_existing_file(&destination, &expected_hex)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    archive_ledger::copy_verified_no_replace(&source, &destination, &expected_hex)?
                }
                Err(e) => return Err(e.into()),
            };
            if content_path(
                &config.source_root,
                &config.source_root.join(&relative),
                annex_root.as_deref(),
            )?
            .as_ref()
                != Some(&source)
            {
                return Err(AppError::Input(
                    "copy source changed its Location path during reading".into(),
                ));
            }
            if let Some(target) = saved_link {
                if fs::read_link(&logical_destination)? != target {
                    return Err(AppError::Input(
                        "annex destination changed during copy".into(),
                    ));
                }
            }
            catalog.observe(&CatalogObservation {
                collection_id: config.collection_id.clone(),
                location_id: config.location_id.clone(),
                path: registry_path_from_sql(&encoding, &bytes, &display)?,
                time_utc_ms: now_utc_ms()?,
                result: ObservationResult::Checksum {
                    blake3: expected
                        .try_into()
                        .map_err(|_| AppError::Input("invalid expected BLAKE3".into()))?,
                    size_bytes: copied.bytes_copied,
                },
                accept_change: false,
                operation_key: None,
                job_id: Some(job_id.clone()),
            })?;
            count += 1;
        }
        if paused {
            break;
        }
    }
    if !dry_run {
        if paused {
            catalog.checkpoint_catalog_job(&job_id, &json!({"copied":count}))?;
        } else {
            catalog.finish_catalog_job(
                &job_id,
                "complete",
                now_utc_ms()?,
                &json!({"copied":count}),
            )?;
        }
    }
    if cli.json && dry_run {
        println!("],\"selected\":{count}}}");
    } else if cli.json {
        println!(
            "{}",
            json!({"job_id":job_id,"status":if paused{"running"}else{"complete"},"copied":count,"dry_run":dry_run})
        );
    } else if !dry_run {
        println!("Copied {count} files.");
        if paused {
            println!("Resume with: archive job resume {job_id}");
        }
    }
    Ok(EXIT_OK)
}

fn job(cli: &Cli, catalog: &mut SqliteCatalog, command: &JobCommand) -> Result<u8, AppError> {
    match command {
        JobCommand::List { limit, all } => {
            let rows=catalog.connection().prepare("SELECT job_id,kind,status,progress_json FROM catalog_jobs WHERE ?1 OR status='running' ORDER BY started_time_utc_ms DESC,job_id LIMIT ?2")?.query_map(params![all,*limit as i64],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?.collect::<Result<Vec<_>,_>>()?;
            if cli.json {
                println!(
                    "{}",
                    json!({"jobs":rows.iter().map(|(id,kind,status,progress)|json!({"job_id":id,"job_type":kind,"status":status,"progress":serde_json::from_str::<serde_json::Value>(progress).unwrap_or_default()})).collect::<Vec<_>>()})
                );
            } else {
                for (id, kind, status, _) in rows {
                    println!("{id}  {kind}  {status}");
                }
            }
        }
        JobCommand::Show { job_id } => {
            let (kind,status,params,progress):(String,String,String,String)=catalog.connection().query_row("SELECT kind,status,params_json,progress_json FROM catalog_jobs WHERE job_id=?1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"job_id":job_id,"job_type":kind,"status":status,"params":serde_json::from_str::<serde_json::Value>(&params)?,"progress":serde_json::from_str::<serde_json::Value>(&progress)?})
                )?
            );
        }
        JobCommand::Cancel { job_id, dry_run } => {
            if !*dry_run {
                catalog.finish_catalog_job(job_id, "cancelled", now_utc_ms()?, &json!({}))?;
            }
            if cli.json {
                println!(
                    "{}",
                    json!({"job_id":job_id,"status":if *dry_run {"would_cancel"} else {"cancelled"},"dry_run":dry_run})
                );
            } else if *dry_run {
                println!("Would cancel catalog job {job_id}; archive files are unchanged.");
            } else {
                println!("Cancelled {job_id}; archive files are unchanged.");
            }
        }
        JobCommand::Resume { job_id, max_items } => {
            let (kind, params): (String, String) = catalog.connection().query_row(
                "SELECT kind,params_json FROM catalog_jobs WHERE job_id=?1",
                [job_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            return match kind.as_str() {
                "inventory" => run_inventory(
                    cli,
                    catalog,
                    serde_json::from_str(&params)?,
                    Some(job_id),
                    *max_items,
                    false,
                    false,
                ),
                "verify" => run_verify(
                    cli,
                    catalog,
                    serde_json::from_str(&params)?,
                    Some(job_id),
                    *max_items,
                    None,
                ),
                "copy" => run_copy(
                    cli,
                    catalog,
                    serde_json::from_str(&params)?,
                    Some(job_id),
                    *max_items,
                    false,
                ),
                "stage_import" => super::sqlite_stage_cli::resume(cli, catalog, job_id),
                _ => Err(AppError::Input(format!(
                    "job type {kind} has no resumable filesystem handler"
                ))),
            };
        }
    }
    Ok(EXIT_OK)
}

/// Called by filesystem setup after registering an annex Location. Inventory-only
/// mode is handled separately from ordinary metadata discovery.
pub(super) fn import_annex(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
    collection_id: &str,
    location_id: &str,
    path: &Path,
    inventory_only: bool,
    import_id: Option<&str>,
    job_id: Option<&str>,
    max_items: Option<usize>,
    batch_entries: usize,
) -> Result<u8, AppError> {
    archive_ledger::validate_annex_repository(path)?;
    run_inventory(
        cli,
        catalog,
        InventoryConfig {
            collection_id: collection_id.into(),
            location_id: location_id.into(),
            root: fs::canonicalize(path)?,
            path: fs::canonicalize(path)?,
            exclusions: Vec::new(),
            accept_changes: Vec::new(),
            complete: false,
            inventory_only,
            annex_import: true,
            import_id: import_id.map(str::to_owned),
            batch_entries,
        },
        job_id,
        max_items,
        false,
        false,
    )
}

fn inventory_annex_entries(
    catalog: &mut SqliteCatalog,
    config: &InventoryConfig,
    job_id: &str,
    max_items: Option<usize>,
    new_work: &mut usize,
    summary: &mut InventorySummary,
    verification: Option<&VerifyConfig>,
) -> Result<bool, AppError> {
    let annex_root = annex_content_root(&config.root);
    let mut error = None;
    let mut batch = Vec::new();
    let complete = archive_ledger::annex::visit_annex_catalog_entries(
        &config.path,
        config.inventory_only,
        |candidate| {
            let action = (|| -> Result<bool, AppError> {
                let relative = path_from_encoded(&candidate.path)?;
                if config
                    .exclusions
                    .iter()
                    .any(|excluded| relative.starts_with(excluded))
                {
                    return Ok(true);
                }
                let absolute = config.path.join(relative);
                let logical = absolute
                    .strip_prefix(&config.root)
                    .map_err(|_| AppError::Input("annex path escapes Location".into()))?;
                let path = RegistryPath::from_path(logical);
                let bytes = registry_path_identity_bytes(&path)?;
                if let Some(verify) = verification {
                    let eligible:bool=catalog.connection().query_row("SELECT EXISTS(SELECT 1 FROM objects o JOIN files f ON f.object_id=o.object_id WHERE o.collection_id=?1 AND o.relative_path_encoding=?2 AND o.relative_path_bytes=?3 AND f.location_id=?4 AND (?5 IS NULL OR o.object_id=?5) AND (?6 OR f.integrity!='verified' OR f.presence!='present' OR f.last_success_time_utc_ms IS NULL OR f.last_success_time_utc_ms<=?7))",params![verify.collection_id,path.encoding,bytes,verify.location_id,verify.object_id,verify.all,verify.cutoff as i64],|r|r.get(0))?;
                    if !eligible {
                        return Ok(true);
                    }
                }
                let processed:bool=catalog.connection().query_row("SELECT EXISTS(SELECT 1 FROM objects o JOIN catalog_job_items j ON j.object_id=o.object_id WHERE j.job_id=?1 AND o.collection_id=?2 AND o.relative_path_encoding=?3 AND o.relative_path_bytes=?4)",params![job_id,config.collection_id,path.encoding,bytes],|r|r.get(0))?;
                // A resumed verification never rechecks completed work. Inventory
                // scans recheck it so absence coverage remains valid for this pass.
                if verification.is_some() && processed {
                    return Ok(true);
                }
                if !processed && max_items.is_some_and(|max| *new_work >= max) {
                    return Ok(false);
                }
                if !processed {
                    *new_work += 1;
                }
                let content_before =
                    match content_path(&config.root, &absolute, annex_root.as_deref()) {
                        Ok(Some(path)) => Some(path),
                        Err(AppError::Io(error))
                            if error.kind() == std::io::ErrorKind::NotFound =>
                        {
                            None
                        }
                        Ok(None) => return Err(AppError::Input(
                            "annex reference does not resolve within its Location content storage"
                                .into(),
                        )),
                        Err(error) => return Err(error),
                    };
                let entry = candidate.inspect()?;
                if matches!(entry.category, "present" | "mismatched")
                    && content_path(&config.root, &absolute, annex_root.as_deref())?
                        != content_before
                {
                    return Err(AppError::Input(
                        "annex content path changed during inspection".into(),
                    ));
                }
                let result = match entry.category {
                    "present" => ObservationResult::Checksum {
                        blake3: entry.blake3.ok_or_else(|| {
                            AppError::Input("verified annex entry lacks BLAKE3".into())
                        })?,
                        size_bytes: entry.size_bytes.unwrap_or(0),
                    },
                    "mismatched" => ObservationResult::RejectedChecksum {
                        blake3: entry.blake3.ok_or_else(|| {
                            AppError::Input("mismatched annex entry lacks BLAKE3".into())
                        })?,
                    },
                    "absent" => ObservationResult::Missing,
                    "read_error" => {
                        summary.read_errors += 1;
                        ObservationResult::ReadError
                    }
                    _ => ObservationResult::MetadataUnknown,
                };
                summary.files_observed += 1;
                summary.bytes_observed += entry.size_bytes.unwrap_or(0);
                batch.push(CatalogObservation {
                    collection_id: config.collection_id.clone(),
                    location_id: config.location_id.clone(),
                    path,
                    time_utc_ms: now_utc_ms()?,
                    result,
                    accept_change: false,
                    operation_key: None,
                    job_id: Some(job_id.into()),
                });
                if batch.len() >= config.batch_entries {
                    flush_inventory(catalog, &mut batch, summary)?;
                }
                Ok(true)
            })();
            match action {
                Ok(more) => more,
                Err(failure) => {
                    error = Some(failure);
                    false
                }
            }
        },
    )?;
    if let Some(error) = error {
        return Err(error);
    }
    flush_inventory(catalog, &mut batch, summary)?;
    Ok(!complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, SqliteCatalog, Cli, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary");
        let backup = temp.path().join("backup");
        fs::create_dir(&primary).unwrap();
        fs::create_dir(&backup).unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "archive", "Files").unwrap();
        catalog.connection().execute_batch("INSERT INTO sites(site_id,display_name,site_kind,status) VALUES ('site','Home','home','active');
          INSERT INTO collections(collection_id,display_name,status) VALUES ('collection','Files','active');
          INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,current_site_id,expected_availability) VALUES ('device','Disk','external','unavailable','active','site','offline');
          INSERT INTO archive_roots(archive_root_id,device_id,display_name,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status) VALUES ('root','device','Root','unavailable',X'2e','utf8','.','active');").unwrap();
        for (id, root) in [("primary", &primary), ("backup", &backup)] {
            let mounted = archive_ledger::discover_mounted_filesystem(root).unwrap();
            let path = RegistryPath::from_path(&mounted.relative_path);
            catalog.connection().execute("INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,is_writable,status) VALUES (?1,?1,'filesystem','root',?2,?3,?4,'device','offline',1,'active')",params![id,registry_path_identity_bytes(&path).unwrap(),path.encoding,path.display]).unwrap();
            catalog.connection().execute("INSERT OR IGNORE INTO device_mounts(mount_id,device_id,archive_root_id,host_id,mount_root_uri,status,fingerprint_status,observed_time_utc_ms) VALUES ('mount','device','root','host',?1,'mounted','unavailable',1)",[mounted.mount_root.to_str().unwrap()]).unwrap();
        }
        let cli = Cli {
            archive: None,
            database: None,
            events: None,
            actor: "actor".into(),
            host: "host".into(),
            json: true,
            command: Command::Status,
        };
        (temp, catalog, cli, primary, backup)
    }
    fn inventory(root: &Path) -> InventoryConfig {
        InventoryConfig {
            collection_id: "collection".into(),
            location_id: "primary".into(),
            root: root.into(),
            path: root.into(),
            exclusions: vec![],
            accept_changes: vec![],
            complete: true,
            inventory_only: false,
            annex_import: false,
            import_id: None,
            batch_entries: 1,
        }
    }
    fn copying(primary: &Path, backup: &Path) -> CopyConfig {
        CopyConfig {
            collection_id: "collection".into(),
            location_id: "backup".into(),
            source_location_id: "primary".into(),
            root: backup.into(),
            source_root: primary.into(),
            filters: vec![PathBuf::new()],
        }
    }
    #[test]
    fn inventory_resume_copy_and_explicit_accept_preserve_backup_bytes() {
        let (_temp, mut catalog, cli, primary, backup) = fixture();
        fs::write(primary.join("one"), b"original").unwrap();
        fs::write(primary.join("two"), b"second").unwrap();
        assert_eq!(
            run_inventory(
                &cli,
                &mut catalog,
                inventory(&primary),
                Some("scan"),
                Some(1),
                false,
                false
            )
            .unwrap(),
            EXIT_OK
        );
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT status FROM catalog_jobs WHERE job_id='scan'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "running"
        );
        run_inventory(
            &cli,
            &mut catalog,
            inventory(&primary),
            Some("scan"),
            None,
            false,
            false,
        )
        .unwrap();
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM files WHERE integrity='verified'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        run_copy(
            &cli,
            &mut catalog,
            copying(&primary, &backup),
            Some("copy"),
            None,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(backup.join("one")).unwrap(), b"original");
        fs::write(primary.join("one"), b"edited").unwrap();
        assert_eq!(
            run_inventory(
                &cli,
                &mut catalog,
                inventory(&primary),
                None,
                None,
                false,
                false
            )
            .unwrap(),
            EXIT_FINDINGS
        );
        let mut accept = inventory(&primary);
        accept.complete = false;
        accept.accept_changes = vec![PathBuf::from("one")];
        run_inventory(&cli, &mut catalog, accept, None, None, false, false).unwrap();
        assert_eq!(catalog.connection().query_row("SELECT f.integrity FROM files f JOIN objects o USING(object_id) WHERE f.location_id='backup' AND o.relative_path_display='one'",[],|r|r.get::<_,String>(0)).unwrap(),"unverified");
        assert!(run_copy(
            &cli,
            &mut catalog,
            copying(&primary, &backup),
            None,
            None,
            false
        )
        .is_err());
        assert_eq!(fs::read(backup.join("one")).unwrap(), b"original");
    }
    #[test]
    fn dry_run_does_not_write_and_unmounted_resume_is_rejected() {
        let (_temp, mut catalog, cli, primary, backup) = fixture();
        fs::write(primary.join("one"), b"original").unwrap();
        run_inventory(
            &cli,
            &mut catalog,
            inventory(&primary),
            None,
            None,
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        run_inventory(
            &cli,
            &mut catalog,
            inventory(&primary),
            None,
            None,
            false,
            false,
        )
        .unwrap();
        run_copy(
            &cli,
            &mut catalog,
            copying(&primary, &backup),
            None,
            None,
            true,
        )
        .unwrap();
        assert!(!backup.join("one").exists());
        catalog
            .connection()
            .execute("UPDATE device_mounts SET status='unmounted'", [])
            .unwrap();
        assert!(run_inventory(
            &cli,
            &mut catalog,
            inventory(&primary),
            None,
            None,
            false,
            false
        )
        .is_err());
    }
    #[cfg(unix)]
    #[test]
    fn annex_inventory_scan_and_dropped_content_restore_use_logical_paths() {
        use sha2::{Digest, Sha256};
        let (_temp, mut catalog, cli, primary, backup) = fixture();
        let key = format!("SHA256E-s8--{:x}.txt", Sha256::digest(b"original"));
        let target = PathBuf::from(format!(".git/annex/objects/ab/cd/{key}/{key}"));
        for root in [&primary, &backup] {
            for args in [vec!["init", "-q"], vec!["config", "annex.uuid", "fixture"]] {
                assert!(std::process::Command::new("git")
                    .arg("-C")
                    .arg(root)
                    .args(args)
                    .status()
                    .unwrap()
                    .success());
            }
            fs::create_dir_all(root.join(target.parent().unwrap())).unwrap();
            std::os::unix::fs::symlink(&target, root.join("reference")).unwrap();
            assert!(std::process::Command::new("git")
                .arg("-C")
                .arg(root)
                .args(["add", "reference"])
                .status()
                .unwrap()
                .success());
        }
        fs::write(primary.join(&target), b"original").unwrap();
        import_annex(
            &cli,
            &mut catalog,
            "collection",
            "primary",
            &primary,
            true,
            None,
            None,
            None,
            1,
        )
        .unwrap();
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE expected_blake3 IS NOT NULL",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        run_inventory(
            &cli,
            &mut catalog,
            inventory(&primary),
            None,
            None,
            false,
            false,
        )
        .unwrap();
        import_annex(
            &cli,
            &mut catalog,
            "collection",
            "backup",
            &backup,
            true,
            None,
            None,
            None,
            1,
        )
        .unwrap();
        run_copy(
            &cli,
            &mut catalog,
            copying(&primary, &backup),
            None,
            None,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(backup.join("reference")).unwrap(), b"original");
        assert!(fs::symlink_metadata(backup.join("reference"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE relative_path_display='reference'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        fs::write(primary.join(&target), b"modified").unwrap();
        assert_eq!(
            run_inventory(
                &cli,
                &mut catalog,
                inventory(&primary),
                None,
                None,
                false,
                false
            )
            .unwrap(),
            EXIT_FINDINGS
        );
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT integrity FROM files WHERE location_id='primary'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "damaged"
        );
    }
    #[test]
    fn unsupported_scope_options_fail_before_creating_jobs() {
        let (_temp, mut catalog, _cli, primary, _backup) = fixture();
        for args in [
            vec!["archive", "verify", "primary", "--copy", "copy_legacy"],
            vec![
                "archive",
                "verify",
                "primary",
                "--fingerprint-status",
                "mismatch",
            ],
            vec!["archive", "verify", "primary", "--batch-entries", "0"],
            vec!["archive", "verify", "--job-id", "ambiguous"],
            vec![
                "archive",
                "collection",
                "add",
                primary.to_str().unwrap(),
                "--collection",
                "collection",
                "--scan-id",
                "legacy",
            ],
            vec![
                "archive",
                "location",
                "scan",
                "primary",
                "--scan-id",
                "legacy",
            ],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(execute_write(&cli, &mut catalog).is_err());
        }
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM catalog_jobs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_cannot_verify_or_supply_a_location_copy() {
        let (temp, mut catalog, cli, primary, backup) = fixture();
        fs::create_dir(primary.join("sub")).unwrap();
        fs::write(primary.join("sub/file"), b"original").unwrap();
        run_inventory(
            &cli,
            &mut catalog,
            inventory(&primary),
            None,
            None,
            false,
            false,
        )
        .unwrap();
        run_copy(
            &cli,
            &mut catalog,
            copying(&primary, &backup),
            None,
            None,
            false,
        )
        .unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("file"), b"original").unwrap();
        fs::remove_file(backup.join("sub/file")).unwrap();
        fs::remove_dir(backup.join("sub")).unwrap();
        std::os::unix::fs::symlink(&external, backup.join("sub")).unwrap();
        fs::remove_file(primary.join("sub/file")).unwrap();
        catalog
            .observe(&CatalogObservation {
                collection_id: "collection".into(),
                location_id: "primary".into(),
                path: RegistryPath::utf8("sub/file"),
                time_utc_ms: now_utc_ms().unwrap(),
                result: ObservationResult::Missing,
                accept_change: false,
                operation_key: None,
                job_id: None,
            })
            .unwrap();
        let mut reverse = copying(&backup, &primary);
        reverse.location_id = "primary".into();
        reverse.source_location_id = "backup".into();
        assert!(run_copy(&cli, &mut catalog, reverse, None, None, false).is_err());
        assert!(!primary.join("sub/file").exists());
        assert_eq!(
            run_verify(
                &cli,
                &mut catalog,
                VerifyConfig {
                    collection_id: "collection".into(),
                    location_id: "backup".into(),
                    root: backup.clone(),
                    all: true,
                    cutoff: 0,
                    object_id: None,
                    batch_entries: 1
                },
                None,
                None,
                None
            )
            .unwrap(),
            EXIT_FINDINGS
        );
        assert_eq!(catalog.connection().query_row("SELECT COUNT(*) FROM files WHERE location_id='backup' AND integrity='verified'",[],|row|row.get::<_,i64>(0)).unwrap(),0);
        assert_eq!(fs::read(external.join("file")).unwrap(), b"original");
    }
}
