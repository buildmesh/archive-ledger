//! Stage commands reuse the existing manifest and no-overwrite filesystem helpers.
use super::*;
use archive_ledger::sqlite_catalog::SqliteCatalog;
use archive_ledger::sqlite_writes::{CatalogObservation, ObservationResult};
use archive_ledger::stage::{
    audit_stage_sqlite, prepare_stage_import_sqlite, select_stage_import_sqlite,
    stage_import_candidates_sqlite,
};

pub(super) fn execute(
    cli: &Cli,
    database: &mut SqliteCatalog,
    args: &StageArgs,
) -> Result<u8, AppError> {
    if let Some(StageCommand::Import(import)) = &args.command {
        return self::import(cli, database, import);
    }
    if archive_ledger::is_git_annex_repository(&args.path)? {
        return Err(AppError::Input(
            "archive stage does not audit a git-annex worktree; import that repository with archive location import-annex so annex pointers are interpreted safely"
                .to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    let collection_id = args
        .collection
        .as_deref()
        .map(|selector| {
            select_collection(&state.collections, selector)?
                .map(|value| value.collection_id)
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))
        })
        .transpose()?;
    let report = audit_stage_sqlite(
        database,
        &StageAuditOptions {
            source: args.path.clone(),
            manifest: args.manifest.clone(),
            collection_id,
            list_limit: args.limit,
        },
    )?;
    if cli.json {
        let mut value = serde_json::to_value(&report)?;
        value.as_object_mut().unwrap().remove("applied_event_seq");
        value["catalog_revision"] = json!(database.metadata()?.revision);
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Staged: {}", report.source.display());
        println!(
            "Files: {} ({}); checksums: {} computed, {} reused",
            report.files_seen,
            format_bytes(report.bytes_seen),
            report.checksums_computed,
            report.checksums_reused
        );
        println!(
            "New to this Archive: {} files / {} unique contents",
            report.new_to_archive_files, report.new_to_archive_objects
        );
        println!(
            "Already cataloged: {}",
            report
                .known_in_selected_collection
                .saturating_add(report.known_only_in_other_collections)
        );
        if !report.listed_files.is_empty() {
            println!("New files:");
            for file in &report.listed_files {
                println!(
                    "  {}  ({})",
                    file.path_display,
                    format_bytes(file.size_bytes)
                );
            }
            if report.listed_files_truncated {
                println!("  …more not shown; use --limit or --json");
            }
        }
        if report.ignored_symlinks > 0 || report.special_files > 0 {
            println!(
                "Ignored: {} symlinks; {} special files",
                report.ignored_symlinks, report.special_files
            );
        }
        if report.audit_status != "complete" {
            println!(
                "Audit partial: {} traversal errors; {} read errors; {} changed during reading",
                report.traversal_errors, report.content_read_errors, report.concurrent_changes
            );
        }
        println!("Checksum manifest: {}", report.manifest.display());
        println!(
            "Protection of cataloged files: {} policy-satisfied; {} at risk; {} unknown",
            report.known_policy_satisfied_files,
            report.known_at_risk_files,
            report.known_policy_unknown_files
        );
        if report.source_removal_ready {
            println!(
                "Source removal readiness: READY — every staged file is cataloged and satisfies its Collection Policy."
            );
        } else {
            println!("Source removal readiness: NOT READY.");
        }
        if report.new_to_archive_files > 0 {
            println!(
                "Next: from a registered destination Location, run archive stage import {} --yes",
                shell_quote(&report.source.to_string_lossy())
            );
        }
    }
    Ok(if !report.source_removal_ready {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    })
}

fn import(cli: &Cli, database: &mut SqliteCatalog, args: &StageImportArgs) -> Result<u8, AppError> {
    if args.non_interactive && !args.dry_run && !args.yes {
        return Err(AppError::Input(
            "stage import in non-interactive mode requires --yes (or use --dry-run)".to_owned(),
        ));
    }
    let reviewed = prepare_stage_import_sqlite(database, &args.source, args.manifest.as_deref())?;
    let source = reviewed.source.clone();
    let manifest = reviewed.manifest.clone();
    let requested_destination = args
        .destination_root
        .clone()
        .unwrap_or(std::env::current_dir()?);
    let destination_cwd = std::fs::canonicalize(&requested_destination).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve destination directory {}: {error}",
            requested_destination.display()
        ))
    })?;
    let scope = super::sqlite_cli::resolve_scope(
        cli,
        database,
        args.location.as_deref(),
        &destination_cwd,
        args.collection.as_deref(),
    )?;
    let location = scope.location;
    let location_root = scope.root;
    let collection_id = scope.collection_id;
    if source.starts_with(&destination_cwd) || destination_cwd.starts_with(&source) {
        return Err(AppError::Input(
            "stage source and destination must not contain one another".to_owned(),
        ));
    }
    let into = args.into.clone().unwrap_or_else(|| {
        source
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| "staged-import".into())
    });
    validate_single_destination_component(&into)?;
    let import_root = destination_cwd.join(&into);
    let resuming = args.job_id.is_some();
    if let Some(job_id) = &args.job_id {
        let exists:bool=database.connection().query_row("SELECT EXISTS(SELECT 1 FROM catalog_jobs WHERE job_id=?1 AND kind='stage_import' AND status='running')",[job_id],|r|r.get(0))?;
        if !exists {
            return Err(AppError::Input(format!(
                "no running stage import job {job_id}"
            )));
        }
    }

    if !resuming && std::fs::symlink_metadata(&import_root).is_ok() {
        return Err(AppError::Input(format!(
            "stage import destination already exists; choose a new --into name: {}",
            import_root.display()
        )));
    }
    let available = available_space(&destination_cwd)?;
    if !resuming && reviewed.eligible_bytes > available {
        return Err(AppError::Input(format!(
            "stage import needs {} but only {} is available at the destination",
            format_bytes(reviewed.eligible_bytes),
            format_bytes(available)
        )));
    }
    let destination_prefix = import_root.strip_prefix(&location_root).map_err(|_| {
        AppError::Input("stage destination is outside the registered Location".into())
    })?;
    let mut cursor = None;
    loop {
        let page = stage_import_candidates_sqlite(database, &reviewed, cursor.as_ref(), 1000)?;
        for candidate in &page.items {
            let encoded =
                RegistryPath::from_path(&destination_prefix.join(&candidate.relative_path));
            let bytes = registry_path_identity_bytes(&encoded)?;
            let expected:Option<Option<Vec<u8>>>=database.connection().query_row("SELECT expected_blake3 FROM objects WHERE collection_id=?1 AND relative_path_encoding=?2 AND relative_path_bytes=?3",params![collection_id,encoded.encoding,bytes],|r|r.get(0)).optional()?;
            let hash = blake3::Hash::from_hex(&candidate.blake3_hex)
                .map_err(|error| AppError::Input(format!("invalid manifest checksum: {error}")))?;
            if expected
                .flatten()
                .is_some_and(|expected| expected != hash.as_bytes())
            {
                return Err(AppError::Input(format!("stage destination {} conflicts with its expected Collection checksum; choose another --into name",encoded.display)));
            }
        }
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    if args.dry_run {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2,
                    "status": "planned",
                    "source": source,
                    "manifest": manifest,
                    "destination": import_root,
                    "collection_id": collection_id,
                    "location_id": location.location_id,
                    "files": reviewed.eligible_files,
                    "bytes": reviewed.eligible_bytes,
                    "ledger_changed": false,
                }))?
            );
        } else {
            println!(
                "Stage import plan: {} new files ({})",
                reviewed.eligible_files,
                format_bytes(reviewed.eligible_bytes)
            );
            println!("From: {}", source.display());
            println!("To: {}", import_root.display());
            println!("Dry run: no files or ledger facts were changed.");
        }
        return Ok(EXIT_OK);
    }
    if reviewed.eligible_files == 0 && !resuming {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2, "status": "nothing_to_import", "files": 0, "bytes": 0
                }))?
            );
        } else {
            println!("Nothing to import; every stable staged file is already cataloged.");
        }
        return Ok(EXIT_OK);
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::Input(
                "stage import requires confirmation; rerun with --yes or inspect it first with --dry-run"
                    .to_owned(),
            ));
        }
        if !prompt_confirmation("Copy and verify these new files?")? {
            return Err(AppError::Input("stage import cancelled".to_owned()));
        }
    }
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    archive_ledger::validate_job_id(&job_id).map_err(AppError::Input)?;
    let plan = select_stage_import_sqlite(database, reviewed, &job_id)?;
    let input_version = plan.input_version().to_owned();
    let job_params = json!({
        "source": source,
        "manifest": manifest,
        "destination_root": destination_cwd,
        "into": into,
        "collection_id": collection_id,
        "location_id": location.location_id,
        "input_version": input_version,
    });
    let status = database.begin_catalog_job(&job_id, "stage_import", &job_params, now_utc_ms()?)?;
    if status != "running" {
        return Err(AppError::Input(format!(
            "stage import job {job_id} is {status}; it cannot resume"
        )));
    }
    let temporary_root = destination_cwd.join(format!(".archive-ledger-import-{job_id}.tmp"));
    let temporary_exists = std::fs::symlink_metadata(&temporary_root).is_ok();
    let published = std::fs::symlink_metadata(&import_root).is_ok();
    if temporary_exists && published {
        return Err(AppError::Input(format!(
            "stage import job {job_id} has both a temporary and published tree; inspect {} and {} before resuming",
            temporary_root.display(), import_root.display()
        )));
    }
    if published && !resuming {
        return Err(AppError::Input(format!(
            "stage import destination already exists; refusing to adopt it: {}",
            import_root.display()
        )));
    }
    if !temporary_exists && !published {
        std::fs::create_dir(&temporary_root)?;
    }
    for root in [&temporary_root, &import_root] {
        match std::fs::symlink_metadata(root) {
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err(AppError::Input(format!(
                    "stage import root is not a regular directory: {}",
                    root.display()
                )))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut temporary_tree = (!published).then(|| TemporaryImportTree {
        path: temporary_root.clone(),
        keep: temporary_exists,
    });
    let working_root = if published {
        &import_root
    } else {
        &temporary_root
    };
    let mut processed_files = 0_u64;
    let mut processed_bytes = 0_u64;
    let mut processed_this_run = 0_usize;
    let mut interrupted = false;
    let mut cursor = None;
    'pages: loop {
        let page = stage_import_candidates_sqlite(database, &plan, cursor.as_ref(), 1_000)?;
        for candidate in &page.items {
            if args
                .max_items
                .is_some_and(|limit| processed_this_run >= limit)
            {
                interrupted = true;
                break 'pages;
            }
            ensure_safe_destination_parents(working_root, &candidate.relative_path)?;
            let source_path = source.join(&candidate.relative_path);
            let destination_path = working_root.join(&candidate.relative_path);
            let verified = match std::fs::symlink_metadata(&destination_path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    if let Some(tree) = &mut temporary_tree {
                        tree.keep = true;
                    }
                    archive_ledger::verify_existing_file(&destination_path, &candidate.blake3_hex)?
                }
                Ok(_) => {
                    return Err(AppError::Input(format!(
                        "stage destination is not a regular file: {}",
                        destination_path.display()
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !published => {
                    if let Some(parent) = destination_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    archive_ledger::copy_verified_no_replace(
                        &source_path,
                        &destination_path,
                        &candidate.blake3_hex,
                    )?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AppError::Input(format!(
                        "published stage import is missing reviewed file {}; refusing recovery",
                        candidate.path_display
                    )))
                }
                Err(error) => return Err(error.into()),
            };
            processed_files = processed_files.saturating_add(1);
            processed_bytes = processed_bytes.saturating_add(verified.bytes_copied);
            processed_this_run = processed_this_run.saturating_add(1);
        }
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    if interrupted {
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
        print_stage_import_running(
            cli.json,
            &job_id,
            "copying",
            processed_files,
            processed_bytes,
        )?;
        database.checkpoint_catalog_job(
            &job_id,
            &json!({
                "phase": "copying",
                "files_verified_this_run": processed_files,
                "bytes_verified_this_run": processed_bytes,
            }),
        )?;
        return Ok(EXIT_OK);
    }
    if let Err(error) = validate_import_tree(working_root, plan.eligible_files) {
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
        return Err(error);
    }
    if !published {
        archive_ledger::place_directory_no_replace(&temporary_root, &import_root)?;
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
    }
    if args.stop_after_publish {
        database.checkpoint_catalog_job(
            &job_id,
            &json!({"phase": "published", "destination": import_root}),
        )?;
        print_stage_import_running(
            cli.json,
            &job_id,
            "published",
            processed_files,
            processed_bytes,
        )?;
        return Ok(EXIT_OK);
    }
    let destination_prefix = import_root.strip_prefix(&location_root).map_err(|_| {
        AppError::Input("stage destination is outside the registered Location".to_owned())
    })?;
    let mut placements = Vec::with_capacity(1_000);
    let mut cursor = None;
    loop {
        let page = stage_import_candidates_sqlite(database, &plan, cursor.as_ref(), 1_000)?;
        for candidate in &page.items {
            let relative = destination_prefix.join(&candidate.relative_path);
            let encoded = RegistryPath::from_path(&relative);
            let hash = blake3::Hash::from_hex(&candidate.blake3_hex)
                .map_err(|error| AppError::Input(format!("invalid manifest checksum: {error}")))?;
            let identity_bytes = registry_path_identity_bytes(&encoded)?;
            let operation_key = stable_id(
                "stage",
                &[
                    job_id.as_bytes(),
                    input_version.as_bytes(),
                    encoded.encoding.as_bytes(),
                    &identity_bytes,
                    candidate.blake3_hex.as_bytes(),
                ],
            );
            let prior: Option<String> = database
                .connection()
                .query_row(
                    "SELECT request_json FROM catalog_write_operations WHERE operation_key=?1",
                    [&operation_key],
                    |row| row.get(0),
                )
                .optional()?;
            let observation_time = if let Some(prior) = prior {
                serde_json::from_str::<CatalogObservation>(&prior)?.time_utc_ms
            } else {
                now_utc_ms()?
            };
            placements.push(CatalogObservation {
                collection_id: collection_id.clone(),
                location_id: location.location_id.clone(),
                path: encoded,
                time_utc_ms: observation_time,
                result: ObservationResult::Checksum {
                    blake3: *hash.as_bytes(),
                    size_bytes: candidate.size_bytes,
                },
                accept_change: false,
                operation_key: Some(operation_key),
                job_id: Some(job_id.clone()),
            });
            if placements.len() == 1000 {
                record_placements(database, &placements)?;
                placements.clear();
            }
        }
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    record_placements(database, &placements)?;
    database.finish_catalog_job(
        &job_id,
        "complete",
        now_utc_ms()?,
        &json!({"files":plan.eligible_files,"bytes":plan.eligible_bytes,"destination":import_root}),
    )?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "status": "complete",
                "job_id": job_id,
                "source": source,
                "destination": import_root,
                "collection_id": collection_id,
                "location_id": location.location_id,
                "files": plan.eligible_files,
                "bytes": plan.eligible_bytes,
            }))?
        );
    } else {
        println!(
            "Stage import complete: {} files ({}) copied, verified, and added to Collection \"{}\".",
            plan.eligible_files,
            format_bytes(plan.eligible_bytes),
            collection_id
        );
        println!("The staged source was not changed.");
    }
    Ok(EXIT_OK)
}

fn record_placements(
    database: &mut SqliteCatalog,
    observations: &[CatalogObservation],
) -> Result<(), AppError> {
    let outcomes = database.observe_batch(observations)?;
    if outcomes.iter().any(|outcome| outcome.result != "ok") {
        return Err(AppError::Input("stage bytes were published, but a Collection expectation changed; inspect the recorded mismatch before resuming".into()));
    }
    Ok(())
}

pub(super) fn resume(cli: &Cli, catalog: &mut SqliteCatalog, job_id: &str) -> Result<u8, AppError> {
    let (kind, parameters): (String, String) = catalog.connection().query_row(
        "SELECT kind,params_json FROM catalog_jobs WHERE job_id=?1",
        [job_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if kind != "stage_import" {
        return Err(AppError::Input("job is not a stage import".into()));
    }
    let value: serde_json::Value = serde_json::from_str(&parameters)?;
    let path = |key: &str| -> Result<PathBuf, AppError> {
        Ok(serde_json::from_value(value[key].clone())?)
    };
    let args = StageImportArgs {
        source: path("source")?,
        manifest: Some(path("manifest")?),
        collection: Some(
            value["collection_id"]
                .as_str()
                .ok_or_else(|| AppError::Input("stage job lacks Collection".into()))?
                .into(),
        ),
        location: Some(
            value["location_id"]
                .as_str()
                .ok_or_else(|| AppError::Input("stage job lacks Location".into()))?
                .into(),
        ),
        into: Some(path("into")?),
        dry_run: false,
        yes: true,
        non_interactive: true,
        job_id: Some(job_id.into()),
        destination_root: Some(path("destination_root")?),
        max_items: None,
        stop_after_publish: false,
    };
    import(cli, catalog, &args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, SqliteCatalog, Cli, StageImportArgs) {
        let temp = TempDir::new().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(source.join("file"), b"original").unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        catalog.connection().execute_batch("INSERT INTO sites(site_id,display_name,site_kind,status) VALUES ('site','Home','home','active');
          INSERT INTO collections(collection_id,display_name,status) VALUES ('collection','Files','active');
          INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,current_site_id,expected_availability) VALUES ('device','Disk','external','unavailable','active','site','offline');
          INSERT INTO archive_roots(archive_root_id,device_id,display_name,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status) VALUES ('root','device','Root','unavailable',X'2e','utf8','.','active');
          INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,is_writable,status) VALUES ('location','Destination','filesystem','root',X'2e','utf8','.','device','offline',1,'active');").unwrap();
        catalog.connection().execute("INSERT INTO device_mounts(mount_id,device_id,archive_root_id,host_id,mount_root_uri,status,fingerprint_status,observed_time_utc_ms) VALUES ('mount','device','root','host',?1,'mounted','unavailable',1)",[destination.to_str().unwrap()]).unwrap();
        // Record the real filesystem mount and Location-relative path, so
        // resume exercises the same mount validation as normal commands.
        let mounted = archive_ledger::discover_mounted_filesystem(&destination).unwrap();
        let relative = RegistryPath::from_path(&mounted.relative_path);
        let bytes = registry_path_identity_bytes(&relative).unwrap();
        catalog
            .connection()
            .execute(
                "UPDATE device_mounts SET mount_root_uri=?1",
                [mounted.mount_root.to_str().unwrap()],
            )
            .unwrap();
        catalog.connection().execute("UPDATE locations SET relative_path_bytes=?1,relative_path_encoding=?2,relative_path_display=?3", params![bytes,relative.encoding,relative.display]).unwrap();
        audit_stage_sqlite(
            &catalog,
            &StageAuditOptions {
                source: source.clone(),
                manifest: None,
                collection_id: Some("collection".into()),
                list_limit: 100,
            },
        )
        .unwrap();
        let cli = Cli {
            archive: None,
            database: None,
            events: None,
            actor: "actor".into(),
            host: "host".into(),
            json: true,
            command: Command::Status,
        };
        let args = StageImportArgs {
            source,
            manifest: None,
            collection: Some("collection".into()),
            location: Some("location".into()),
            into: Some("imported".into()),
            dry_run: false,
            yes: true,
            non_interactive: true,
            job_id: None,
            destination_root: Some(destination),
            max_items: None,
            stop_after_publish: true,
        };
        (temp, catalog, cli, args)
    }

    #[test]
    fn published_stage_resumes_catalog_recording_without_overwriting_or_touching_source() {
        let (_temp, mut catalog, cli, args) = fixture();
        assert_eq!(import(&cli, &mut catalog, &args).unwrap(), EXIT_OK);
        let destination = args
            .destination_root
            .as_ref()
            .unwrap()
            .join("imported/file");
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM files", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        let job: String = catalog
            .connection()
            .query_row("SELECT job_id FROM catalog_jobs", [], |r| r.get(0))
            .unwrap();
        // Simulate a crash after the first catalog batch but before finishing
        // the job. Resume must reuse the original check's immutable timestamp.
        let reviewed = prepare_stage_import_sqlite(&catalog, &args.source, None).unwrap();
        let encoded = RegistryPath::utf8("imported/file");
        let hash = blake3::hash(b"original");
        let operation_key = stable_id(
            "stage",
            &[
                job.as_bytes(),
                reviewed.input_version().as_bytes(),
                encoded.encoding.as_bytes(),
                b"imported/file",
                hash.to_hex().as_bytes(),
            ],
        );
        catalog
            .observe(&CatalogObservation {
                collection_id: "collection".into(),
                location_id: "location".into(),
                path: encoded,
                time_utc_ms: 1,
                result: ObservationResult::Checksum {
                    blake3: *hash.as_bytes(),
                    size_bytes: 8,
                },
                accept_change: false,
                operation_key: Some(operation_key),
                job_id: Some(job.clone()),
            })
            .unwrap();
        assert_eq!(resume(&cli, &mut catalog, &job).unwrap(), EXIT_OK);
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM files WHERE presence='present' AND integrity='verified'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT status FROM catalog_jobs", [], |r| r
                    .get::<_, String>(0))
                .unwrap(),
            "complete"
        );
        assert_eq!(
            std::fs::read(args.source.join("file")).unwrap(),
            b"original"
        );
        assert!(
            import(&cli, &mut catalog, &args).is_err(),
            "existing published root must not be adopted by a new job"
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
    }

    #[test]
    fn stage_rejects_changed_source_without_publishing_or_cataloging() {
        let (_temp, mut catalog, cli, mut args) = fixture();
        args.stop_after_publish = false;
        std::fs::write(args.source.join("file"), b"changed since audit").unwrap();
        assert!(import(&cli, &mut catalog, &args).is_err());
        assert!(!args
            .destination_root
            .as_ref()
            .unwrap()
            .join("imported")
            .exists());
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM files", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            std::fs::read(args.source.join("file")).unwrap(),
            b"changed since audit"
        );
    }
}
