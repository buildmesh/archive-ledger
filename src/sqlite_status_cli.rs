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
