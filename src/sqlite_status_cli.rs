//! Cached current-state summaries and read-only catalog health checks.
use super::*;
use archive_ledger::SqliteCatalog;

#[derive(Default)]
struct Scope {
    collection: Option<String>,
    location: Option<String>,
    device: Option<String>,
    site: Option<String>,
}

pub(super) fn execute_status(cli: &Cli, catalog: &SqliteCatalog) -> Result<Option<u8>, AppError> {
    if let Command::Fsck(args) = &cli.command {
        return fsck(cli, catalog, args).map(Some);
    }
    if let Command::Location {
        command: LocationCommand::Show { id, stale_after },
    } = &cli.command
    {
        return show_location(cli, catalog, id, stale_after).map(Some);
    }
    let mut scope = Scope::default();
    let entity = match &cli.command {
        Command::Status => {
            let metadata = catalog.metadata()?;
            json!({"archive_id":metadata.archive_id,"display_name":metadata.display_name,"revision":metadata.revision})
        }
        Command::Collection {
            command: CollectionCommand::Status { collection },
        } => {
            let state = catalog.registry_state(false)?;
            let selected = match collection {
                Some(selector) => {
                    select_collection(&state.collections, selector)?.ok_or_else(|| {
                        AppError::Input(format!("Collection not found: {selector:?}"))
                    })?
                }
                None if state.collections.len() == 1 => state.collections[0].clone(),
                None => return Err(AppError::Input("specify a Collection name or ID".into())),
            };
            scope.collection = Some(selected.collection_id.clone());
            serde_json::to_value(selected)?
        }
        Command::Location {
            command: LocationCommand::Status { location },
        } => {
            let state = catalog.registry_state(false)?;
            let selected = match location {
                Some(selector) => select_location(&state.locations, selector)?
                    .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?,
                None => cwd_location(cli, catalog, &state.locations)?,
            };
            scope.location = Some(selected.location_id.clone());
            serde_json::to_value(selected)?
        }
        Command::Device {
            command: DeviceCommand::Status { device },
        } => {
            let state = catalog.registry_state(false)?;
            let selector = match device {
                Some(selector) => selector.clone(),
                None => cwd_location(cli, catalog, &state.locations)?
                    .device_id
                    .ok_or_else(|| AppError::Input("cwd Location has no Device".into()))?,
            };
            let selected = select_device(&state.devices, &selector)?
                .ok_or_else(|| AppError::Input(format!("Device not found: {selector:?}")))?;
            scope.device = Some(selected.device_id.clone());
            serde_json::to_value(selected)?
        }
        Command::Site {
            command: SiteCommand::Status { site },
        } => {
            let state = catalog.registry_state(false)?;
            let selector = match site {
                Some(selector) => selector.clone(),
                None => {
                    let location = cwd_location(cli, catalog, &state.locations)?;
                    location
                        .site_id
                        .or_else(|| {
                            state
                                .devices
                                .iter()
                                .find(|d| Some(&d.device_id) == location.device_id.as_ref())
                                .and_then(|d| d.current_site_id.clone())
                        })
                        .ok_or_else(|| AppError::Input("cwd Location has no current Site".into()))?
                }
            };
            let selected = select_site(&state.sites, &selector)?
                .ok_or_else(|| AppError::Input(format!("Site not found: {selector:?}")))?;
            scope.site = Some(selected.site_id.clone());
            serde_json::to_value(selected)?
        }
        _ => return Ok(None),
    };
    let summary = summary(catalog, &scope)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"version":3,"catalog_format":"sqlite","entity":entity,"summary":summary,"evidence":"cached_catalog","policy_evaluated":false})
            )?
        );
    } else {
        println!("{}", entity["display_name"].as_str().unwrap_or("Archive"));
        println!(
            "Expected paths: {} ({} without an expected checksum)",
            summary["objects"], summary["unresolved_objects"]
        );
        println!(
            "File locations: {} present; {} missing; {} unknown",
            summary["present_files"], summary["missing_files"], summary["unknown_files"]
        );
        println!(
            "Checks: {} verified present; {} damaged",
            summary["verified_present_files"], summary["damaged_files"]
        );
        println!("Cached catalog evidence; preservation policy has not been evaluated.");
    }
    Ok(Some(EXIT_OK))
}

fn show_location(
    cli: &Cli,
    catalog: &SqliteCatalog,
    selector: &str,
    stale_after: &str,
) -> Result<u8, AppError> {
    let age = parse_file_evidence_age(stale_after).map_err(|message| {
        AppError::Input(message.replace("--verified-within", "--stale-after"))
    })?;
    let as_of = now_utc_ms()?;
    let transaction = catalog.connection().unchecked_transaction()?;
    let state = catalog.registry_state(true)?;
    let location = select_location(&state.locations, selector)?
        .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?;
    let device = state
        .devices
        .iter()
        .find(|d| Some(&d.device_id) == location.device_id.as_ref());
    let site_id = location
        .site_id
        .as_ref()
        .or_else(|| device.and_then(|d| d.current_site_id.as_ref()));
    let site = state.sites.iter().find(|s| Some(&s.site_id) == site_id);
    // Display the recorded path without probing a mounted/offline filesystem.
    let mount: Option<String> = catalog.connection().query_row(
        "SELECT mount_root_uri FROM device_mounts WHERE archive_root_id=?1 AND host_id=?2 ORDER BY observed_time_utc_ms DESC,mount_id DESC LIMIT 1",
        params![location.archive_root_id, cli.host], |r| r.get(0),
    ).optional()?;
    let recorded_path =
        mount
            .as_ref()
            .zip(location.relative_path.as_ref())
            .map(|(mount, relative)| {
                PathBuf::from(mount)
                    .join(&relative.display)
                    .display()
                    .to_string()
            });
    let summary = location_summary(catalog, &location.location_id, as_of, age)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version":3, "catalog_format":"sqlite", "items":[location],
                "device":device, "site":site, "recorded_path":recorded_path,
                "summary":summary, "stale_after_ms":age, "as_of_utc_ms":as_of,
                "evidence":"cached_catalog", "policy_evaluated":false
            }))?
        );
    } else {
        println!("{}", location.display_name);
        println!("Location: {} ({})", location.location_id, location.status);
        if let Some(path) = recorded_path {
            println!("Recorded path: {path}");
        } else if let Some(path) = &location.relative_path {
            println!("Path relative to archive root: {}", path.display);
        }
        println!(
            "Device / Site: {} / {}",
            device.map_or("unknown", |d| d.display_name.as_str()),
            site.map_or("unknown", |s| s.display_name.as_str())
        );
        println!(
            "Files: {} tracked; {} present; {} missing; {} unknown",
            summary["tracked_files"],
            summary["present_files"],
            summary["missing_files"],
            summary["unknown_files"]
        );
        println!(
            "Present copies: {} verified ({} within {}, {} stale); {} unverified; {} damaged",
            summary["verified_present_files"],
            summary["recent_verified_present_files"],
            stale_after,
            summary["stale_verified_present_files"],
            summary["unverified_present_files"],
            summary["damaged_present_files"]
        );
        println!(
            "Never verified: {} present files. Without an expected checksum: {} tracked files.",
            summary["never_verified_present_files"], summary["unresolved_files"]
        );
        println!(
            "Without another verified copy within {}: {} of {} present files",
            stale_after, summary["present_without_recent_other_copy"], summary["present_files"]
        );
        println!("Collections:");
        for collection in summary["collections"].as_array().unwrap() {
            let counts = &collection["summary"];
            println!("  {}: {} tracked; {} present; {} recently verified; {} stale; {} without another recent verified copy", collection["collection_name"].as_str().unwrap(), counts["tracked_files"], counts["present_files"], counts["recent_verified_present_files"], counts["stale_verified_present_files"], counts["present_without_recent_other_copy"]);
        }
        println!("Stale means a currently verified present copy last checked more than {stale_after} ago. Future-dated verification is counted as unverified. Never-verified counts can overlap damaged/unverified counts.");
        println!("Other copies may share the same Device or Site. Cached catalog evidence; backup policy has not been evaluated.");
    }
    transaction.commit()?;
    Ok(EXIT_OK)
}

fn location_summary(
    catalog: &SqliteCatalog,
    location: &str,
    as_of: u64,
    age: u64,
) -> Result<serde_json::Value, AppError> {
    let cutoff = as_of.saturating_sub(age);
    let healthy = format!(
        "({} AND f.last_success_time_utc_ms<=?3)",
        archive_ledger::sqlite_queries::verified_copy_predicate("f", "o")
    );
    let other_healthy = archive_ledger::sqlite_queries::verified_copy_predicate("other", "o");
    // Start from the Location index and group once. Only the other-copy check probes
    // each Object's primary-key range; neither history nor filesystem state is read.
    let sql = format!(
        "SELECT c.collection_id,c.display_name,
        COUNT(*), SUM(f.presence='present'), SUM(f.presence='missing'), SUM(f.presence='unknown'),
        SUM(COALESCE({healthy},0)),
        SUM(COALESCE(({healthy}) AND f.last_success_time_utc_ms>=?2,0)),
        SUM(COALESCE(({healthy}) AND f.last_success_time_utc_ms<?2,0)),
        SUM(f.presence='present' AND f.integrity!='damaged' AND NOT COALESCE({healthy},0)),
        SUM(f.presence='present' AND f.integrity='damaged'),
        SUM(f.presence='present' AND f.last_success_time_utc_ms IS NULL),
        SUM(o.expected_blake3 IS NULL),
        SUM(f.presence='present' AND NOT EXISTS(
            SELECT 1 FROM files other
            WHERE other.object_id=f.object_id AND other.location_id!=f.location_id
            AND {other_healthy} AND other.last_success_time_utc_ms BETWEEN ?2 AND ?3))
        FROM files f JOIN objects o ON o.object_id=f.object_id
        JOIN collections c ON c.collection_id=o.collection_id
        WHERE f.location_id=?1 GROUP BY c.collection_id ORDER BY c.display_name,c.collection_id"
    );
    let keys = [
        "tracked_files",
        "present_files",
        "missing_files",
        "unknown_files",
        "verified_present_files",
        "recent_verified_present_files",
        "stale_verified_present_files",
        "unverified_present_files",
        "damaged_present_files",
        "never_verified_present_files",
        "unresolved_files",
        "present_without_recent_other_copy",
    ];
    let mut totals = [0i64; 12];
    let mut collections = Vec::new();
    let mut statement = catalog.connection().prepare(&sql)?;
    let mut rows = statement.query(params![location, cutoff as i64, as_of as i64])?;
    while let Some(row) = rows.next()? {
        let mut counts = serde_json::Map::new();
        for (index, key) in keys.iter().enumerate() {
            let count: i64 = row.get(index + 2)?;
            totals[index] += count;
            counts.insert((*key).into(), json!(count));
        }
        collections.push(json!({"collection_id":row.get::<_,String>(0)?, "collection_name":row.get::<_,String>(1)?, "summary":counts}));
    }
    let mut result = serde_json::Map::new();
    for (key, count) in keys.iter().zip(totals) {
        result.insert((*key).into(), json!(count));
    }
    result.insert("collections".into(), json!(collections));
    Ok(result.into())
}

fn cwd_location(
    cli: &Cli,
    catalog: &SqliteCatalog,
    locations: &[LocationSnapshot],
) -> Result<LocationSnapshot, AppError> {
    let cwd = std::fs::canonicalize(std::env::current_dir()?)?;
    let mut matches = Vec::new();
    for location in locations {
        if let Ok(root) = super::sqlite_cli::location_path(cli, catalog, location) {
            if cwd.starts_with(&root) {
                matches.push((root.components().count(), location));
            }
        }
    }
    matches.sort_by_key(|(depth, _)| std::cmp::Reverse(*depth));
    let Some((depth, location)) = matches.first() else {
        return Err(AppError::Input(
            "cwd does not identify a mounted Location; specify its name or ID".into(),
        ));
    };
    if matches.get(1).is_some_and(|(other, _)| other == depth) {
        return Err(AppError::Input(
            "cwd matches multiple Locations; specify its name or ID".into(),
        ));
    }
    Ok((*location).clone())
}

fn summary(catalog: &SqliteCatalog, scope: &Scope) -> Result<serde_json::Value, AppError> {
    let transaction = catalog.connection().unchecked_transaction()?;
    // Object counts stay independent of File counts, including expected paths
    // for which every Location has gone missing or no File row exists yet.
    let object_sql="SELECT COUNT(*),COALESCE(SUM(o.expected_blake3 IS NULL),0) FROM objects o WHERE (?1 IS NULL OR o.collection_id=?1) AND ((?2 IS NULL AND ?3 IS NULL AND ?4 IS NULL) OR EXISTS(SELECT 1 FROM files f JOIN locations l ON l.location_id=f.location_id LEFT JOIN devices d ON d.device_id=l.device_id WHERE f.object_id=o.object_id AND (?2 IS NULL OR l.location_id=?2) AND (?3 IS NULL OR l.device_id=?3) AND (?4 IS NULL OR COALESCE(l.site_id,d.current_site_id)=?4)))";
    let (objects, unresolved): (i64, i64) = transaction.query_row(
        object_sql,
        params![scope.collection, scope.location, scope.device, scope.site],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let file_sql="SELECT COALESCE(SUM(f.presence='present'),0),COALESCE(SUM(f.presence='missing'),0),COALESCE(SUM(f.presence='unknown'),0),COALESCE(SUM(f.presence='present' AND f.integrity='verified' AND f.last_check_result='ok' AND f.last_success_time_utc_ms IS NOT NULL AND f.observed_blake3=o.expected_blake3),0),COALESCE(SUM(f.integrity='damaged'),0) FROM files f JOIN objects o ON o.object_id=f.object_id JOIN locations l ON l.location_id=f.location_id LEFT JOIN devices d ON d.device_id=l.device_id WHERE (?1 IS NULL OR o.collection_id=?1) AND (?2 IS NULL OR l.location_id=?2) AND (?3 IS NULL OR l.device_id=?3) AND (?4 IS NULL OR COALESCE(l.site_id,d.current_site_id)=?4)";
    let (present, missing, unknown, verified, damaged): (i64, i64, i64, i64, i64) = transaction
        .query_row(
            file_sql,
            params![scope.collection, scope.location, scope.device, scope.site],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
    Ok(
        json!({"objects":objects,"unresolved_objects":unresolved,"present_files":present,"missing_files":missing,"unknown_files":unknown,"verified_present_files":verified,"damaged_files":damaged}),
    )
}

fn fsck(cli: &Cli, catalog: &SqliteCatalog, args: &FsckArgs) -> Result<u8, AppError> {
    if args.keep_rebuild || args.rebuild_dir.is_some() {
        return Err(AppError::Input("authoritative catalogs are checked in place without rebuilding; --keep-rebuild and --rebuild-dir apply only to legacy catalogs".into()));
    }
    let findings = health_findings(catalog, args.full)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"version":3,"catalog_format":"sqlite","status":if findings.is_empty(){"ok"}else{"findings"},"full":args.full,"findings":findings,"archive_contents_checked":false})
            )?
        );
    } else if findings.is_empty() {
        println!(
            "Catalog SQLite integrity and foreign keys: OK. Archive contents were not checked."
        );
    } else {
        for finding in &findings {
            println!("{finding}");
        }
    }
    Ok(if findings.is_empty() {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    })
}

fn health_findings(catalog: &SqliteCatalog, full: bool) -> Result<Vec<String>, AppError> {
    let mut statement = catalog.connection().prepare(if full {
        "PRAGMA integrity_check"
    } else {
        "PRAGMA quick_check"
    })?;
    let mut findings = statement
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    findings.retain(|v| v != "ok");
    let mut statement = catalog.connection().prepare("PRAGMA foreign_key_check")?;
    let violations = statement
        .query_map([], |r| {
            Ok(format!(
                "foreign key violation in {} row {:?} referencing {}",
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?,
                r.get::<_, String>(2)?
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    findings.extend(violations);
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summaries_keep_missing_expectations_and_require_matching_checksums() {
        let temp = tempfile::TempDir::new().unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('c','Files','active');
          INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('s','Site','home','active');
          INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('l','Cloud','service','s','online','active');
          INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3) VALUES ('a','c','utf8',X'61','a',zeroblob(32)),('b','c','utf8',X'62','b',NULL),('c','c','utf8',X'63','c',zeroblob(32));
          INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES('a','l','present','verified',1,'ok',zeroblob(32),1),('b','l','missing','unverified',2,'missing',NULL,NULL);").unwrap();
        let all = summary(&catalog, &Scope::default()).unwrap();
        assert_eq!(all["objects"], 3);
        assert_eq!(all["unresolved_objects"], 1);
        assert_eq!(all["verified_present_files"], 1);
        let scoped = summary(
            &catalog,
            &Scope {
                location: Some("l".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(scoped["objects"], 2);
        assert_eq!(scoped["missing_files"], 1);
        catalog
            .connection()
            .execute(
                "UPDATE objects SET expected_blake3=?1 WHERE object_id='a'",
                [vec![1u8; 32]],
            )
            .unwrap();
        assert_eq!(
            summary(&catalog, &Scope::default()).unwrap()["verified_present_files"],
            0
        );
    }

    #[test]
    fn location_protection_counts_separate_presence_health_and_freshness() {
        let temp = tempfile::TempDir::new().unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('c','Files','active'),('d','Media','active');
            INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('s','Home','home','active');
            INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES
                ('l','Primary','service','s','offline','active'),('other','Backup','service','s','offline','active'),('retired','Retired','service','s','offline','retired'),('empty','Empty','service','s','offline','active');").unwrap();
        for (id, collection, presence, integrity, checked, result, observed, success) in [
            (
                "a",
                "c",
                "present",
                "verified",
                Some(100),
                Some("ok"),
                Some(vec![0u8; 32]),
                Some(100),
            ),
            (
                "b",
                "c",
                "present",
                "verified",
                Some(99),
                Some("ok"),
                Some(vec![0u8; 32]),
                Some(99),
            ),
            ("c", "c", "present", "unverified", None, None, None, None),
            (
                "d",
                "c",
                "present",
                "damaged",
                Some(101),
                Some("mismatch"),
                Some(vec![1u8; 32]),
                None,
            ),
            (
                "e",
                "c",
                "missing",
                "verified",
                Some(101),
                Some("missing"),
                Some(vec![0u8; 32]),
                Some(100),
            ),
            ("f", "c", "unknown", "unverified", None, None, None, None),
            ("g", "c", "present", "unverified", None, None, None, None),
            (
                "h",
                "c",
                "present",
                "verified",
                Some(101),
                Some("read_error"),
                Some(vec![0u8; 32]),
                Some(100),
            ),
            (
                "i",
                "c",
                "present",
                "verified",
                Some(101),
                Some("ok"),
                Some(vec![1u8; 32]),
                Some(100),
            ),
            (
                "j",
                "d",
                "present",
                "verified",
                Some(101),
                Some("ok"),
                Some(vec![0u8; 32]),
                Some(101),
            ),
            (
                "k",
                "d",
                "present",
                "verified",
                Some(101),
                Some("ok"),
                Some(vec![0u8; 32]),
                Some(101),
            ),
            (
                "future",
                "c",
                "present",
                "verified",
                Some(201),
                Some("ok"),
                Some(vec![0u8; 32]),
                Some(201),
            ),
        ] {
            let expected = (id != "g").then_some(vec![0u8; 32]);
            catalog.connection().execute("INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3) VALUES(?1,?2,'utf8',?3,?1,?4)", params![id, collection, id.as_bytes(), expected]).unwrap();
            catalog.connection().execute("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES(?1,'l',?2,?3,?4,?5,?6,?7)",params![id,presence,integrity,checked,result,observed,success]).unwrap();
        }
        catalog.connection().execute_batch("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES
            ('a','other','present','verified',100,'ok',zeroblob(32),100),
            ('b','other','present','verified',99,'ok',zeroblob(32),99),
            ('c','other','missing','verified',101,'missing',zeroblob(32),100),
            ('d','other','present','damaged',101,'mismatch',zeroblob(32),100),
            ('h','other','present','verified',101,'ok',randomblob(32),101),
            ('j','other','present','verified',101,'ok',zeroblob(32),101),
            ('k','retired','present','verified',101,'ok',zeroblob(32),101),
            ('future','other','present','verified',201,'ok',zeroblob(32),201);").unwrap();
        let before: i64 = catalog
            .connection()
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        let result = location_summary(&catalog, "l", 200, 100).unwrap();
        for (key, value) in [
            ("tracked_files", 12),
            ("present_files", 10),
            ("missing_files", 1),
            ("unknown_files", 1),
            ("verified_present_files", 4),
            ("recent_verified_present_files", 3),
            ("stale_verified_present_files", 1),
            ("unverified_present_files", 5),
            ("damaged_present_files", 1),
            ("never_verified_present_files", 3),
            ("unresolved_files", 1),
            ("present_without_recent_other_copy", 7),
        ] {
            assert_eq!(result[key], value, "{key}");
        }
        assert_eq!(result["collections"].as_array().unwrap().len(), 2);
        assert_eq!(result["collections"][0]["collection_name"], "Files");
        assert_eq!(result["collections"][1]["summary"]["tracked_files"], 2);
        let empty = location_summary(&catalog, "empty", 200, 100).unwrap();
        assert_eq!(empty["tracked_files"], 0);
        assert_eq!(empty["present_without_recent_other_copy"], 0);
        assert!(empty["collections"].as_array().unwrap().is_empty());
        let after: i64 = catalog
            .connection()
            .query_row("SELECT total_changes()", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn health_checks_report_foreign_key_corruption_without_repair() {
        let temp = tempfile::TempDir::new().unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        assert!(health_findings(&catalog, false).unwrap().is_empty());
        assert!(health_findings(&catalog, true).unwrap().is_empty());
        catalog.connection().execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES('a','missing','utf8',X'61','a'); PRAGMA foreign_keys=ON;").unwrap();
        assert!(health_findings(&catalog, true)
            .unwrap()
            .iter()
            .any(|f| f.contains("foreign key violation in objects")));
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
