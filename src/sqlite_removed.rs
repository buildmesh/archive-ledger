//! Catalog-only removal declarations. No archive filesystem is consulted or changed.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params, params_from_iter, Connection, TransactionBehavior};
use serde::Serialize;

use crate::sqlite_queries::{
    selection_predicate, CatalogFileFilter, CatalogQueryError, CatalogSelection,
};
use crate::{EncodedPath, LosslessPath, SqliteCatalog};

#[derive(Debug, Clone)]
pub enum RemovedSelection {
    Path {
        location_id: String,
        collection_id: Option<String>,
        path: EncodedPath,
    },
    Groups(CatalogFileFilter),
}

#[derive(Debug, Serialize)]
pub struct RemovedResult {
    pub location_id: String,
    pub files_marked_missing: u64,
}

struct Selection {
    target: String,
    predicate: CatalogSelection,
    single: bool,
}

fn selection(request: &RemovedSelection, time: u64) -> Result<Selection, CatalogQueryError> {
    let (target, filter, single) = match request {
        RemovedSelection::Path {
            location_id,
            collection_id,
            path,
        } => (
            location_id.clone(),
            CatalogFileFilter {
                collection_id: collection_id.clone(),
                exact_path: Some(path.clone()),
                ..Default::default()
            },
            true,
        ),
        RemovedSelection::Groups(filter) => {
            let first = filter.location_groups.first().ok_or_else(|| {
                CatalogQueryError::InvalidFilter(
                    "bulk removal requires a positive target Location group".into(),
                )
            })?;
            if first.negated || first.location_ids.len() != 1 {
                return Err(CatalogQueryError::InvalidFilter("the first removal group must be positive and contain exactly one target Location".into()));
            }
            (first.location_ids[0].clone(), filter.clone(), false)
        }
    };
    if target.is_empty() {
        return Err(CatalogQueryError::InvalidFilter(
            "target Location is empty".into(),
        ));
    }
    let mut predicate = selection_predicate(&filter, filter.as_of_utc_ms.unwrap_or(time))?;
    predicate.values.push(target.clone().into());
    let parameter = predicate.values.len();
    predicate.sql.push_str(&format!(" AND EXISTS (SELECT 1 FROM files target WHERE target.object_id=o.object_id AND target.location_id=?{parameter})"));
    Ok(Selection {
        target,
        predicate,
        single,
    })
}

fn validate(connection: &Connection, selection: &Selection) -> Result<(), CatalogQueryError> {
    let active: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM locations WHERE location_id=?1 AND status='active')",
        [&selection.target],
        |row| row.get(0),
    )?;
    if !active {
        return Err(CatalogQueryError::InvalidFilter(
            "target Location is missing or retired".into(),
        ));
    }
    if selection.single {
        let sql = format!(
            "SELECT count(*) FROM (SELECT 1 FROM objects o WHERE {} LIMIT 2)",
            selection.predicate.sql
        );
        let count: i64 = connection.query_row(
            &sql,
            params_from_iter(selection.predicate.values.iter()),
            |row| row.get(0),
        )?;
        if count > 1 {
            return Err(CatalogQueryError::InvalidFilter(
                "path exists in multiple Collections at this Location; specify --collection".into(),
            ));
        }
    }
    Ok(())
}

fn affected_predicate(selection: &Selection) -> String {
    // target is bound last by selection(), including when the shared predicate has no parameters.
    format!("{} AND EXISTS (SELECT 1 FROM files target WHERE target.object_id=o.object_id AND target.location_id=?{} AND target.presence!='missing')",selection.predicate.sql,selection.predicate.values.len())
}

/// Stream the exact affected paths from one read snapshot. Even read-only SQLite
/// connections work: preview does not create temporary tables or change revision.
pub fn preview_removed(
    connection: &Connection,
    request: &RemovedSelection,
    time_utc_ms: u64,
    mut visit: impl FnMut(LosslessPath) -> Result<(), CatalogQueryError>,
) -> Result<RemovedResult, CatalogQueryError> {
    let selection = selection(request, time_utc_ms)?;
    let snapshot = if connection.is_autocommit() {
        Some(connection.unchecked_transaction()?)
    } else {
        None
    };
    validate(connection, &selection)?;
    let sql=format!("SELECT o.relative_path_encoding,o.relative_path_bytes,o.relative_path_display FROM objects o WHERE {} ORDER BY o.collection_id,o.relative_path_encoding,o.relative_path_bytes",affected_predicate(&selection));
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(selection.predicate.values.iter()))?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let encoding: String = row.get(0)?;
        let bytes: Vec<u8> = row.get(1)?;
        let text = if encoding == "utf8" {
            String::from_utf8(bytes.clone()).ok()
        } else {
            None
        };
        let base64 = text.is_none().then(|| URL_SAFE_NO_PAD.encode(bytes));
        visit(LosslessPath {
            encoding,
            text,
            base64,
            display: row.get(2)?,
        })?;
        count += 1;
    }
    drop(rows);
    drop(statement);
    if let Some(snapshot) = snapshot {
        snapshot.commit()?;
    }
    Ok(RemovedResult {
        location_id: selection.target,
        files_marked_missing: count,
    })
}

/// Freeze the selected IDs before changing the evidence used by the predicate.
/// Selection, missing declarations, history, and revision commit together.
pub fn mark_removed(
    catalog: &mut SqliteCatalog,
    request: &RemovedSelection,
    time_utc_ms: u64,
) -> Result<RemovedResult, CatalogQueryError> {
    let time = i64::try_from(time_utc_ms)
        .map_err(|_| CatalogQueryError::InvalidFilter("time exceeds SQLite range".into()))?;
    let selection = selection(request, time_utc_ms)?;
    let tx = catalog
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate(&tx, &selection)?;
    tx.execute_batch(
        "CREATE TEMP TABLE catalog_removed_selection(object_id TEXT PRIMARY KEY) WITHOUT ROWID;",
    )?;
    let sql = format!(
        "INSERT INTO catalog_removed_selection SELECT o.object_id FROM objects o WHERE {}",
        affected_predicate(&selection)
    );
    let count = tx.execute(&sql, params_from_iter(selection.predicate.values.iter()))?;
    if count > 0 {
        let future:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM catalog_removed_selection s JOIN files f ON f.object_id=s.object_id AND f.location_id=?1 WHERE f.last_check_time_utc_ms>?2)",params![selection.target,time],|row|row.get(0))?;
        if future {
            return Err(CatalogQueryError::InvalidFilter(
                "removal predates a selected copy's current check".into(),
            ));
        }
        tx.execute("INSERT INTO history(object_id,location_id,time_utc_ms,kind,check_result,expected_blake3,observed_blake3,details_json)
            SELECT o.object_id,?1,?2,'file_removed','missing',o.expected_blake3,f.observed_blake3,json_object('catalog_only',json('true'),'previous_presence',f.presence,'previous_integrity',f.integrity)
            FROM catalog_removed_selection s JOIN objects o ON o.object_id=s.object_id JOIN files f ON f.object_id=s.object_id AND f.location_id=?1",params![selection.target,time])?;
        tx.execute("UPDATE files SET presence='missing',integrity='unverified',last_check_time_utc_ms=?2,last_check_result='missing'
            WHERE location_id=?1 AND object_id IN (SELECT object_id FROM catalog_removed_selection)",params![selection.target,time])?;
        tx.execute(
            "UPDATE catalog_metadata SET revision=revision+1 WHERE singleton=1",
            [],
        )?;
    }
    tx.execute_batch("DROP TABLE catalog_removed_selection;")?;
    tx.commit()?;
    Ok(RemovedResult {
        location_id: selection.target,
        files_marked_missing: count as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite_writes::{CatalogObservation, ObservationResult};
    use crate::{utf8_path, FileLocationGroup, RegistryPath};

    fn fixture(count: usize) -> (tempfile::TempDir, SqliteCatalog) {
        let directory = tempfile::tempdir().unwrap();
        let catalog =
            SqliteCatalog::create(directory.path().join("catalog.db"), "archive", "Archive")
                .unwrap();
        catalog.connection().execute_batch("INSERT INTO sites VALUES ('site','Site','home',NULL,'active');
            INSERT INTO collections VALUES ('collection','Files',NULL,NULL,NULL,'active');
            INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES
            ('usb','USB','service','site','online','active'),('sd','SD','service','site','offline','active'),('sd02','SD02','service','site','offline','active');").unwrap();
        catalog.connection().execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3)
            SELECT printf('object_%08d',x),'collection','utf8',cast(printf('path/%08d',x) AS BLOB),printf('path/%08d',x),zeroblob(32) FROM n",[count as i64]).unwrap();
        catalog.connection().execute_batch("INSERT INTO files SELECT object_id,'usb','present','verified',100,'ok',expected_blake3,100 FROM objects;
            INSERT INTO files SELECT object_id,CASE WHEN cast(substr(object_id,8) AS INTEGER)%2=0 THEN 'sd' ELSE 'sd02' END,'present','verified',100,'ok',expected_blake3,100 FROM objects;").unwrap();
        (directory, catalog)
    }
    fn group(ids: &[&str], negated: bool, age: Option<u64>) -> FileLocationGroup {
        FileLocationGroup {
            location_ids: ids.iter().map(|v| v.to_string()).collect(),
            negated,
            verified_within_ms: age,
        }
    }
    fn bulk() -> RemovedSelection {
        RemovedSelection::Groups(CatalogFileFilter {
            collection_id: Some("collection".into()),
            location_groups: vec![
                group(&["usb"], false, None),
                group(&["sd", "sd02"], false, Some(30)),
            ],
            as_of_utc_ms: Some(120),
            ..Default::default()
        })
    }
    fn preview(catalog: &SqliteCatalog, request: &RemovedSelection) -> Vec<String> {
        let mut paths = Vec::new();
        preview_removed(catalog.connection(), request, 120, |path| {
            paths.push(path.display);
            Ok(())
        })
        .unwrap();
        paths
    }
    #[test]
    fn bulk_preview_and_commit_agree_and_repeat_is_harmless() {
        let (directory, mut catalog) = fixture(2501);
        let untouched = directory.path().join("archive-content");
        std::fs::write(&untouched, b"preserved").unwrap();
        let readonly = SqliteCatalog::open_read_only(directory.path().join("catalog.db")).unwrap();
        assert_eq!(preview(&readonly, &bulk()).len(), 2501);
        assert_eq!(catalog.metadata().unwrap().revision, 0);
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT count(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            mark_removed(&mut catalog, &bulk(), 120)
                .unwrap()
                .files_marked_missing,
            2501
        );
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT count(*) FROM history WHERE kind='file_removed'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2501
        );
        assert_eq!(
            catalog
                .connection()
                .query_row(
                    "SELECT count(*) FROM files WHERE location_id!='usb' AND presence='present'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2501
        );
        assert_eq!(
            mark_removed(&mut catalog, &bulk(), 121)
                .unwrap()
                .files_marked_missing,
            0
        );
        assert_eq!(catalog.metadata().unwrap().revision, 1);
        assert_eq!(std::fs::read(untouched).unwrap(), b"preserved");
    }
    #[test]
    fn groups_validate_union_negation_and_age() {
        let (_directory, catalog) = fixture(4);
        let mut request = bulk();
        assert_eq!(preview(&catalog, &request).len(), 4);
        let RemovedSelection::Groups(filter) = &mut request else {
            unreachable!()
        };
        filter.location_groups[1].verified_within_ms = Some(10);
        assert!(preview(&catalog, &request).is_empty());
        let RemovedSelection::Groups(filter) = &mut request else {
            unreachable!()
        };
        filter.location_groups[1] = group(&["sd"], true, None);
        assert_eq!(
            preview(&catalog, &request),
            ["path/00000001", "path/00000003"]
        );
        let RemovedSelection::Groups(filter) = &mut request else {
            unreachable!()
        };
        filter.location_groups[0].location_ids.push("sd".into());
        assert!(preview_removed(catalog.connection(), &request, 120, |_| Ok(())).is_err());
        let RemovedSelection::Groups(filter) = &mut request else {
            unreachable!()
        };
        filter.location_groups[0] = group(&["usb"], true, None);
        assert!(preview_removed(catalog.connection(), &request, 120, |_| Ok(())).is_err());
    }
    #[test]
    fn single_copy_handles_unverified_and_rejects_ambiguous_paths() {
        let (_directory, mut catalog) = fixture(1);
        catalog.connection().execute_batch("UPDATE files SET integrity='unverified' WHERE location_id='usb';
            INSERT INTO collections VALUES ('second','Second',NULL,NULL,NULL,'active');
            INSERT INTO objects SELECT 'second-object','second',relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3,expected_size_bytes FROM objects;
            INSERT INTO files(object_id,location_id,presence,integrity) VALUES ('second-object','usb','unknown','unverified');").unwrap();
        let mut request = RemovedSelection::Path {
            location_id: "usb".into(),
            collection_id: None,
            path: utf8_path("path/00000001"),
        };
        assert!(mark_removed(&mut catalog, &request, 120).is_err());
        let RemovedSelection::Path { collection_id, .. } = &mut request else {
            unreachable!()
        };
        *collection_id = Some("collection".into());
        assert_eq!(
            mark_removed(&mut catalog, &request, 120)
                .unwrap()
                .files_marked_missing,
            1
        );
        catalog
            .observe(&CatalogObservation {
                collection_id: "collection".into(),
                location_id: "usb".into(),
                path: RegistryPath::from_path(std::path::Path::new("path/00000001")),
                time_utc_ms: 130,
                result: ObservationResult::MetadataPresent,
                accept_change: false,
                operation_key: None,
                job_id: None,
            })
            .unwrap();
        let state:(String,String,String)=catalog.connection().query_row("SELECT presence,integrity,last_check_result FROM files WHERE object_id='object_00000001' AND location_id='usb'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(
            state,
            ("present".into(), "unverified".into(), "missing".into())
        );
        assert!(preview(&catalog, &bulk()).is_empty());
    }
    #[test]
    fn failure_rolls_back_selection_history_state_and_revision() {
        let (_directory, mut catalog) = fixture(2);
        catalog.connection().execute_batch("CREATE TRIGGER reject_removal BEFORE UPDATE ON files WHEN NEW.presence='missing' BEGIN SELECT RAISE(ABORT,'fixture failure'); END;").unwrap();
        assert!(mark_removed(&mut catalog, &bulk(), 120).is_err());
        assert_eq!(catalog.metadata().unwrap().revision, 0);
        assert_eq!(
            catalog
                .connection()
                .query_row("SELECT count(*) FROM history", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(preview(&catalog, &bulk()).len(), 2);
        catalog
            .connection()
            .execute_batch("DROP TRIGGER reject_removal;")
            .unwrap();
        assert_eq!(
            mark_removed(&mut catalog, &bulk(), 120)
                .unwrap()
                .files_marked_missing,
            2
        );
    }
}
