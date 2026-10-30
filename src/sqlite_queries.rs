//! Indexed current-state queries for the authoritative catalog.
//! Selection predicates are shared with transactional catalog-only operations.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{params_from_iter, types::Value, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::discovery::EncodedPath;
use crate::review::{FileLocationGroup, LosslessPath};

const MAX_PAGE: usize = 1000;

#[derive(Debug, Error)]
pub enum CatalogQueryError {
    #[error("catalog query failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("output failed: {0}")]
    Output(#[from] io::Error),
    #[error("invalid catalog query: {0}")]
    InvalidFilter(String),
    #[error("invalid continuation token")]
    InvalidContinuation,
    #[error("catalog changed; restart the query")]
    StaleContinuation,
    #[error("object not found: {0}")]
    NotFound(String),
}

impl CatalogQueryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Sqlite(_) => "catalog_query_sqlite",
            Self::Output(_) => "output_failed",
            Self::InvalidFilter(_) => "invalid_filter",
            Self::InvalidContinuation => "invalid_continuation",
            Self::StaleContinuation => "stale_continuation",
            Self::NotFound(_) => "not_found",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CatalogFileFilter {
    pub collection_id: Option<String>,
    pub object_id: Option<String>,
    /// `resolved` has an expected checksum; `unresolved`/`unknown` do not.
    pub identity_state: Option<String>,
    pub exact_path: Option<EncodedPath>,
    pub path_prefix: Option<EncodedPath>,
    pub location_groups: Vec<FileLocationGroup>,
    pub as_of_utc_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CatalogObjectRequest {
    pub filter: CatalogFileFilter,
    pub limit: usize,
    pub continuation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogObjectPath {
    pub object_id: String,
    pub collection_id: String,
    pub relative_path: LosslessPath,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogObject {
    pub object_id: String,
    pub collection_id: String,
    pub relative_path: LosslessPath,
    pub expected_blake3: Option<String>,
    pub expected_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogObjectPage {
    pub objects: Vec<CatalogObject>,
    pub next: Option<String>,
    pub as_of_utc_ms: u64,
    pub unresolved_identities_excluded: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogFile {
    pub location_id: String,
    pub location_name: String,
    pub presence: String,
    pub integrity: String,
    pub last_check_time_utc_ms: Option<i64>,
    pub last_check_result: Option<String>,
    pub observed_blake3: Option<String>,
    pub last_success_time_utc_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogObjectReview {
    pub object: CatalogObject,
    pub files: Vec<CatalogFile>,
}

/// SQL expression referring to the Objects table as `o`. Values are positional
/// parameters; consumers append parameters after these, never interpolate input.
pub struct CatalogSelection {
    pub sql: String,
    pub values: Vec<Value>,
}

fn bind(values: &mut Vec<Value>, value: impl Into<Value>) -> String {
    values.push(value.into());
    format!("?{}", values.len())
}

/// Shared identity/health rule for listings and catalog-only selection in a
/// caller's transaction. A healthy copy belongs to this exact expected path;
/// equal content at a different path does not protect it.
pub fn selection_predicate(
    filter: &CatalogFileFilter,
    as_of_utc_ms: u64,
) -> Result<CatalogSelection, CatalogQueryError> {
    let as_of = i64::try_from(as_of_utc_ms)
        .map_err(|_| CatalogQueryError::InvalidFilter("time exceeds SQLite range".into()))?;
    if filter.exact_path.is_some() && filter.path_prefix.is_some() {
        return Err(CatalogQueryError::InvalidFilter(
            "choose exact path or prefix".into(),
        ));
    }
    if filter.location_groups.len() > 32
        || filter
            .location_groups
            .iter()
            .map(|g| g.location_ids.len())
            .sum::<usize>()
            > 2048
    {
        return Err(CatalogQueryError::InvalidFilter(
            "too many Location selectors".into(),
        ));
    }
    let mut values = Vec::new();
    let mut clauses = Vec::new();
    if let Some(collection) = &filter.collection_id {
        clauses.push(format!(
            "o.collection_id={}",
            bind(&mut values, collection.clone())
        ));
    }
    if let Some(object) = &filter.object_id {
        clauses.push(format!("o.object_id={}", bind(&mut values, object.clone())));
    }
    if let Some(state) = filter.identity_state.as_deref() {
        clauses.push(match state {
            "resolved" => "o.expected_blake3 IS NOT NULL".into(),
            "unresolved" | "unknown" => "o.expected_blake3 IS NULL".into(),
            _ => {
                return Err(CatalogQueryError::InvalidFilter(format!(
                    "unsupported identity state: {state}"
                )))
            }
        });
    }
    if let Some(path) = filter.exact_path.as_ref().or(filter.path_prefix.as_ref()) {
        clauses.push(format!(
            "o.relative_path_encoding={}",
            bind(&mut values, path.encoding.as_str().to_owned())
        ));
        if filter.exact_path.is_some() {
            clauses.push(format!(
                "o.relative_path_bytes={}",
                bind(&mut values, path.bytes.clone())
            ));
        } else {
            clauses.push(format!(
                "o.relative_path_bytes>={}",
                bind(&mut values, path.bytes.clone())
            ));
            if let Some(upper) = prefix_upper_bound(&path.bytes) {
                clauses.push(format!(
                    "o.relative_path_bytes<{}",
                    bind(&mut values, upper)
                ));
            }
        }
    }
    if !filter.location_groups.is_empty() {
        clauses.push("o.expected_blake3 IS NOT NULL".into());
    }
    for group in &filter.location_groups {
        if group.location_ids.is_empty() {
            return Err(CatalogQueryError::InvalidFilter(
                "Location group cannot be empty".into(),
            ));
        }
        let locations = group
            .location_ids
            .iter()
            .map(|id| bind(&mut values, id.clone()))
            .collect::<Vec<_>>()
            .join(",");
        let mut predicate = format!(
            "EXISTS (SELECT 1 FROM files f WHERE f.object_id=o.object_id AND f.location_id IN ({locations}) \
             AND f.presence='present' AND f.integrity='verified' AND f.last_check_result='ok' \
             AND f.observed_blake3=o.expected_blake3 AND f.last_success_time_utc_ms IS NOT NULL"
        );
        if let Some(age) = group.verified_within_ms {
            let cutoff = as_of_utc_ms.saturating_sub(age) as i64;
            predicate.push_str(&format!(
                " AND f.last_success_time_utc_ms BETWEEN {} AND {}",
                bind(&mut values, cutoff),
                bind(&mut values, as_of)
            ));
        }
        predicate.push(')');
        if group.negated {
            predicate.insert_str(0, "NOT ");
        }
        clauses.push(predicate);
    }
    Ok(CatalogSelection {
        sql: if clauses.is_empty() {
            "1".into()
        } else {
            clauses.join(" AND ")
        },
        values,
    })
}

fn prefix_upper_bound(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut upper = bytes.to_vec();
    while let Some(last) = upper.pop() {
        if last < 255 {
            upper.push(last + 1);
            return Some(upper);
        }
    }
    None
}

#[derive(Serialize, Deserialize)]
struct Cursor {
    archive_id: String,
    revision: i64,
    filter_hash: String,
    as_of: u64,
    collection: String,
    encoding: String,
    path: Vec<u8>,
}

const PATH_COLUMNS: &str = "o.object_id,o.collection_id,o.relative_path_encoding,o.relative_path_bytes,o.relative_path_display";
const COLUMNS: &str = "o.object_id,o.collection_id,o.relative_path_encoding,o.relative_path_bytes,o.relative_path_display,lower(hex(o.expected_blake3)),o.expected_size_bytes";
const ORDER: &str = "o.collection_id,o.relative_path_encoding,o.relative_path_bytes";

fn filter_hash(filter: &CatalogFileFilter) -> String {
    fn path(p: &Option<EncodedPath>) -> Option<(&str, &[u8])> {
        p.as_ref()
            .map(|p| (p.encoding.as_str(), p.bytes.as_slice()))
    }
    // Display text is not path identity and has no effect on a selection.
    let bytes = serde_json::to_vec(&(
        &filter.collection_id,
        &filter.object_id,
        &filter.identity_state,
        path(&filter.exact_path),
        path(&filter.path_prefix),
        &filter.location_groups,
    ))
    .expect("serializable query fields");
    blake3::hash(&bytes).to_hex().to_string()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as u64
}

fn read_path(row: &rusqlite::Row<'_>) -> rusqlite::Result<(CatalogObjectPath, Vec<u8>)> {
    let encoding: String = row.get(2)?;
    let bytes: Vec<u8> = row.get(3)?;
    let display = row.get(4)?;
    let text = if encoding == "utf8" {
        String::from_utf8(bytes.clone()).ok()
    } else {
        None
    };
    let base64 = if text.is_none() {
        Some(URL_SAFE_NO_PAD.encode(&bytes))
    } else {
        None
    };
    Ok((
        CatalogObjectPath {
            object_id: row.get(0)?,
            collection_id: row.get(1)?,
            relative_path: LosslessPath {
                encoding,
                display,
                text,
                base64,
            },
        },
        bytes,
    ))
}

fn read_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<(CatalogObject, Vec<u8>)> {
    let (path, bytes) = read_path(row)?;
    let hash: String = row.get(5)?;
    let size: Option<i64> = row.get(6)?;
    Ok((
        CatalogObject {
            object_id: path.object_id,
            collection_id: path.collection_id,
            relative_path: path.relative_path,
            expected_blake3: if hash.is_empty() { None } else { Some(hash) },
            expected_size_bytes: size.map(|size| size as u64),
        },
        bytes,
    ))
}

fn append_cursor(
    selection: &mut CatalogSelection,
    filter: &CatalogFileFilter,
    collection: String,
    encoding: String,
    path: Vec<u8>,
) {
    // With a fixed Collection, seek on the remaining index columns directly.
    // A redundant Collection in this tuple makes SQLite revisit earlier pages.
    if filter.collection_id.is_some() {
        let encoding = bind(&mut selection.values, encoding);
        let path = bind(&mut selection.values, path);
        selection.sql.push_str(&format!(
            " AND (o.relative_path_encoding,o.relative_path_bytes)>({encoding},{path})"
        ));
    } else {
        let collection = bind(&mut selection.values, collection);
        let encoding = bind(&mut selection.values, encoding);
        let path = bind(&mut selection.values, path);
        selection
            .sql
            .push_str(&format!(" AND ({ORDER})>({collection},{encoding},{path})"));
    }
}

/// Bounded structured output with indexed keyset pagination. Revision and frozen
/// verification time are checked in the same read snapshot as returned rows.
pub fn find_objects(
    connection: &Connection,
    request: CatalogObjectRequest,
) -> Result<CatalogObjectPage, CatalogQueryError> {
    if !(1..=MAX_PAGE).contains(&request.limit) {
        return Err(CatalogQueryError::InvalidFilter(
            "page limit must be 1..1000".into(),
        ));
    }
    let snapshot = if connection.is_autocommit() {
        Some(connection.unchecked_transaction()?)
    } else {
        None
    };
    let (archive_id, revision): (String, i64) = connection.query_row(
        "SELECT archive_id,revision FROM catalog_metadata WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let filter_hash = filter_hash(&request.filter);
    let cursor: Option<Cursor> = request
        .continuation
        .as_ref()
        .map(|token| {
            if token.len() > 1_048_576 {
                return Err(CatalogQueryError::InvalidContinuation);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| CatalogQueryError::InvalidContinuation)?;
            serde_json::from_slice(&bytes).map_err(|_| CatalogQueryError::InvalidContinuation)
        })
        .transpose()?;
    let as_of = if let Some(cursor) = &cursor {
        if cursor.archive_id != archive_id || cursor.revision != revision {
            return Err(CatalogQueryError::StaleContinuation);
        }
        if cursor.filter_hash != filter_hash
            || request
                .filter
                .as_of_utc_ms
                .is_some_and(|time| time != cursor.as_of)
        {
            return Err(CatalogQueryError::InvalidContinuation);
        }
        cursor.as_of
    } else {
        request.filter.as_of_utc_ms.unwrap_or_else(now_ms)
    };
    let mut selection = selection_predicate(&request.filter, as_of)?;
    if let Some(cursor) = cursor {
        append_cursor(
            &mut selection,
            &request.filter,
            cursor.collection,
            cursor.encoding,
            cursor.path,
        );
    }
    let limit = bind(&mut selection.values, (request.limit + 1) as i64);
    let sql = format!(
        "SELECT {COLUMNS} FROM objects o WHERE {} ORDER BY {ORDER} LIMIT {limit}",
        selection.sql
    );
    let mut statement = connection.prepare(&sql)?;
    let mut records = statement
        .query_map(params_from_iter(selection.values.iter()), read_object)?
        .collect::<Result<Vec<_>, _>>()?;
    let more = records.len() > request.limit;
    records.truncate(request.limit);
    let next = if more {
        let (object, path) = records.last().expect("nonempty limited page");
        Some(
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Cursor {
                    archive_id,
                    revision,
                    filter_hash,
                    as_of,
                    collection: object.collection_id.clone(),
                    encoding: object.relative_path.encoding.clone(),
                    path: path.clone(),
                })
                .expect("serializable cursor"),
            ),
        )
    } else {
        None
    };
    drop(statement);
    if let Some(snapshot) = snapshot {
        snapshot.commit()?;
    }
    Ok(CatalogObjectPage {
        objects: records.into_iter().map(|(object, _)| object).collect(),
        next,
        as_of_utc_ms: as_of,
        unresolved_identities_excluded: !request.filter.location_groups.is_empty(),
    })
}

/// Stream the complete selection in one statement. Human output must not silently
/// stop after a structured-output page. The callback can write each path directly.
pub fn visit_objects(
    connection: &Connection,
    filter: &CatalogFileFilter,
    mut visit: impl FnMut(CatalogObjectPath) -> Result<(), CatalogQueryError>,
) -> Result<u64, CatalogQueryError> {
    let selection = selection_predicate(filter, filter.as_of_utc_ms.unwrap_or_else(now_ms))?;
    let sql = format!(
        "SELECT {PATH_COLUMNS} FROM objects o WHERE {} ORDER BY {ORDER}",
        selection.sql
    );
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(params_from_iter(selection.values.iter()))?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        visit(read_path(row)?.0)?;
        count += 1;
    }
    Ok(count)
}

pub fn show_object(
    connection: &Connection,
    object_id: &str,
) -> Result<CatalogObjectReview, CatalogQueryError> {
    let snapshot = if connection.is_autocommit() {
        Some(connection.unchecked_transaction()?)
    } else {
        None
    };
    let object = connection
        .query_row(
            &format!("SELECT {COLUMNS} FROM objects o WHERE o.object_id=?1"),
            [object_id],
            read_object,
        )
        .optional()?
        .ok_or_else(|| CatalogQueryError::NotFound(object_id.into()))?
        .0;
    let mut statement=connection.prepare("SELECT f.location_id,l.display_name,f.presence,f.integrity,f.last_check_time_utc_ms,f.last_check_result,lower(hex(f.observed_blake3)),f.last_success_time_utc_ms FROM files f JOIN locations l ON l.location_id=f.location_id WHERE f.object_id=?1 ORDER BY f.location_id")?;
    let files = statement
        .query_map([object_id], |row| {
            let hash: String = row.get(6)?;
            Ok(CatalogFile {
                location_id: row.get(0)?,
                location_name: row.get(1)?,
                presence: row.get(2)?,
                integrity: row.get(3)?,
                last_check_time_utc_ms: row.get(4)?,
                last_check_result: row.get(5)?,
                observed_blake3: if hash.is_empty() { None } else { Some(hash) },
                last_success_time_utc_ms: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if let Some(snapshot) = snapshot {
        snapshot.commit()?;
    }
    Ok(CatalogObjectReview { object, files })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::PathEncoding;
    use crate::sqlite_catalog::SqliteCatalog;
    use rusqlite::{params, StatementStatus};

    fn fixture(count: usize) -> (tempfile::TempDir, SqliteCatalog) {
        let directory = tempfile::tempdir().unwrap();
        let catalog =
            SqliteCatalog::create(directory.path().join("catalog.db"), "archive", "Test").unwrap();
        catalog.connection().execute_batch("INSERT INTO sites VALUES ('site','Site','home',NULL,'active');
            INSERT INTO collections VALUES ('collection','Files',NULL,NULL,NULL,'active');
            INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES
            ('disk','Primary','service','site','online','active'),('backup','Backup','service','site','offline','active'),('other','Other','service','site','offline','active');").unwrap();
        add_objects(catalog.connection(), 1, count);
        (directory, catalog)
    }

    fn add_objects(connection: &Connection, start: usize, count: usize) {
        connection.execute("WITH RECURSIVE n(x) AS (VALUES(?1) UNION ALL SELECT x+1 FROM n WHERE x<?2)
            INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3)
            SELECT printf('object_%08d',x),'collection','utf8',cast(printf('path/%08d',x) AS BLOB),printf('path/%08d',x),zeroblob(32) FROM n",params![start as i64,(start+count-1) as i64]).unwrap();
        connection.execute("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms)
            SELECT object_id,'disk','present','verified',100,'ok',expected_blake3,100 FROM objects WHERE object_id>=?1 AND object_id<=?2",params![format!("object_{start:08}"),format!("object_{:08}",start+count-1)]).unwrap();
    }

    fn group(ids: &[&str], negated: bool, age: Option<u64>) -> FileLocationGroup {
        FileLocationGroup {
            location_ids: ids.iter().map(|id| id.to_string()).collect(),
            negated,
            verified_within_ms: age,
        }
    }
    fn selection() -> CatalogFileFilter {
        CatalogFileFilter {
            collection_id: Some("collection".into()),
            location_groups: vec![
                group(&["disk"], false, None),
                group(&["backup", "other"], true, None),
            ],
            as_of_utc_ms: Some(120),
            ..Default::default()
        }
    }
    fn ids(connection: &Connection, filter: &CatalogFileFilter) -> Vec<String> {
        let mut ids = Vec::new();
        visit_objects(connection, filter, |object| {
            ids.push(object.object_id);
            Ok(())
        })
        .unwrap();
        ids
    }

    #[test]
    fn groups_require_same_expected_path_and_current_healthy_evidence() {
        let (_directory, catalog) = fixture(7);
        let connection = catalog.connection();
        connection.execute_batch("INSERT INTO files SELECT object_id,'backup',presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms FROM files WHERE object_id!='object_00000001';
            UPDATE files SET integrity='damaged',last_check_result='mismatch',observed_blake3=randomblob(32) WHERE object_id='object_00000003' AND location_id='backup';
            UPDATE files SET presence='missing',last_check_result='missing' WHERE object_id='object_00000004' AND location_id='backup';
            UPDATE files SET last_check_result='read_error' WHERE object_id='object_00000005' AND location_id='backup';
            UPDATE files SET observed_blake3=randomblob(32) WHERE object_id='object_00000006' AND location_id='backup';
            UPDATE objects SET expected_blake3=NULL WHERE object_id='object_00000007';").unwrap();
        // All Objects initially share the same hash: a backup at path 2 must not protect path 1.
        assert_eq!(
            ids(connection, &selection()),
            [1, 3, 4, 5, 6].map(|n| format!("object_{n:08}"))
        );
        let mut recent = selection();
        recent.location_groups[1].verified_within_ms = Some(10);
        assert_eq!(ids(connection, &recent).len(), 6);
        recent.location_groups[1].verified_within_ms = Some(30);
        assert_eq!(ids(connection, &recent).len(), 5);
        let review = show_object(connection, "object_00000003").unwrap();
        assert_eq!(
            review.object.expected_blake3.as_deref(),
            Some("0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(review.files[0].integrity, "damaged");
        assert_eq!(review.files.len(), 2);
        assert!(matches!(
            show_object(connection, "missing"),
            Err(CatalogQueryError::NotFound(_))
        ));
    }

    #[test]
    fn identity_filters_distinguish_unknown_expected_checksum() {
        let (_directory, catalog) = fixture(2);
        catalog
            .connection()
            .execute(
                "UPDATE objects SET expected_blake3=NULL WHERE object_id='object_00000002'",
                [],
            )
            .unwrap();
        let mut filter = CatalogFileFilter {
            identity_state: Some("resolved".into()),
            ..Default::default()
        };
        assert_eq!(ids(catalog.connection(), &filter), ["object_00000001"]);
        for state in ["unknown", "unresolved"] {
            filter.identity_state = Some(state.into());
            assert_eq!(ids(catalog.connection(), &filter), ["object_00000002"]);
        }
        filter.location_groups = selection().location_groups;
        assert!(ids(catalog.connection(), &filter).is_empty());
        filter.identity_state = Some("conflict".into());
        assert!(matches!(
            selection_predicate(&filter, 120),
            Err(CatalogQueryError::InvalidFilter(_))
        ));
    }

    #[test]
    fn pagination_freezes_time_binds_revision_and_streams_all_paths() {
        let (_directory, catalog) = fixture(2501);
        let connection = catalog.connection();
        let mut next = None;
        let mut all = Vec::new();
        loop {
            let page = find_objects(
                connection,
                CatalogObjectRequest {
                    filter: selection(),
                    limit: 1000,
                    continuation: next,
                },
            )
            .unwrap();
            assert_eq!(page.as_of_utc_ms, 120);
            all.extend(page.objects.into_iter().map(|object| object.object_id));
            next = page.next;
            if next.is_none() {
                break;
            }
        }
        assert_eq!(all.len(), 2501);
        assert_eq!(all, ids(connection, &selection()));
        let first = find_objects(
            connection,
            CatalogObjectRequest {
                filter: selection(),
                limit: 1,
                continuation: None,
            },
        )
        .unwrap();
        let mut changed = selection();
        changed.collection_id = Some("other".into());
        assert!(matches!(
            find_objects(
                connection,
                CatalogObjectRequest {
                    filter: changed,
                    limit: 1,
                    continuation: first.next.clone()
                }
            ),
            Err(CatalogQueryError::InvalidContinuation)
        ));
        connection
            .execute("UPDATE catalog_metadata SET revision=revision+1", [])
            .unwrap();
        assert!(matches!(
            find_objects(
                connection,
                CatalogObjectRequest {
                    filter: selection(),
                    limit: 1,
                    continuation: first.next
                }
            ),
            Err(CatalogQueryError::StaleContinuation)
        ));
    }

    #[test]
    fn lossless_exact_and_prefix_filters_preserve_byte_identity() {
        let (_directory, catalog) = fixture(1);
        let connection = catalog.connection();
        connection.execute("UPDATE objects SET relative_path_encoding='unix_bytes',relative_path_bytes=?1,relative_path_display='nonutf8'",[b"folder/\xff".as_slice()]).unwrap();
        let mut filter = CatalogFileFilter {
            collection_id: Some("collection".into()),
            exact_path: Some(EncodedPath {
                encoding: PathEncoding::UnixBytes,
                bytes: b"folder/\xff".to_vec(),
                display: "ignored".into(),
            }),
            ..Default::default()
        };
        let page = find_objects(
            connection,
            CatalogObjectRequest {
                filter: filter.clone(),
                limit: 1,
                continuation: None,
            },
        )
        .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(page.objects[0].relative_path.base64.as_ref().unwrap())
                .unwrap(),
            b"folder/\xff"
        );
        filter.exact_path = None;
        filter.path_prefix = Some(EncodedPath {
            encoding: PathEncoding::UnixBytes,
            bytes: b"folder/".to_vec(),
            display: "ignored".into(),
        });
        assert_eq!(ids(connection, &filter).len(), 1);
        filter.path_prefix.as_mut().unwrap().bytes = b"folder0".to_vec();
        assert!(ids(connection, &filter).is_empty());
    }

    fn query_steps(
        connection: &Connection,
        filter: &CatalogFileFilter,
        cursor: Option<(&str, &str, &[u8])>,
        limit: Option<i64>,
    ) -> (i64, usize) {
        let mut selection = selection_predicate(filter, 120).unwrap();
        if let Some((collection, encoding, path)) = cursor {
            append_cursor(
                &mut selection,
                filter,
                collection.to_owned(),
                encoding.to_owned(),
                path.to_vec(),
            );
        }
        let mut sql = format!(
            "SELECT {COLUMNS} FROM objects o WHERE {} ORDER BY {ORDER}",
            selection.sql
        );
        if let Some(limit) = limit {
            sql.push_str(&format!(" LIMIT {}", bind(&mut selection.values, limit)));
        }
        let mut statement = connection.prepare(&sql).unwrap();
        let count = statement
            .query_map(params_from_iter(selection.values.iter()), |_| Ok(()))
            .unwrap()
            .count();
        (
            i64::from(statement.get_status(StatementStatus::VmStep)),
            count,
        )
    }

    #[test]
    fn exact_show_and_complete_grouped_queries_do_not_scan_unrelated_state_or_history() {
        let (_directory, catalog) = fixture(5000);
        let connection = catalog.connection();
        let mut exact = selection();
        exact.exact_path = Some(EncodedPath {
            encoding: PathEncoding::Utf8,
            bytes: b"path/00000001".to_vec(),
            display: "path".into(),
        });
        let small_exact = query_steps(connection, &exact, None, None);
        let small_all = query_steps(connection, &selection(), None, None);
        let page_steps = |count: usize, filter: &CatalogFileFilter| {
            let mut steps = 0;
            for offset in (0..count).step_by(1000) {
                let key = format!("path/{offset:08}");
                steps += query_steps(
                    connection,
                    filter,
                    Some(("collection", "utf8", key.as_bytes())),
                    Some(1000),
                )
                .0;
            }
            steps
        };
        let small_paged = page_steps(5000, &selection());
        let mut unscoped = selection();
        unscoped.collection_id = None;
        let small_global = page_steps(5000, &unscoped);
        add_objects(connection, 5001, 5000);
        connection.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20000) INSERT INTO history(time_utc_ms,kind) SELECT x,'checked' FROM n;").unwrap();
        let large_exact = query_steps(connection, &exact, None, None);
        let large_all = query_steps(connection, &selection(), None, None);
        let large_paged = page_steps(10000, &selection());
        let large_global = page_steps(10000, &unscoped);
        eprintln!("catalog steps exact {small_exact:?}->{large_exact:?}; all {small_all:?}->{large_all:?}; paged {small_paged}->{large_paged}; unscoped {small_global}->{large_global}");
        assert!(large_exact.0 <= small_exact.0 + 10);
        assert!(large_all.0 <= small_all.0 * 2 + 100);
        assert!(large_paged <= small_paged * 2 + 1000);
        assert!(large_global <= small_global * 2 + 1000);
        exact.exact_path.as_mut().unwrap().bytes = b"missing".to_vec();
        assert!(query_steps(connection, &exact, None, None).0 < 100);
        // Show uses equality indexes on both tables rather than a global aggregate.
        for sql in ["EXPLAIN QUERY PLAN SELECT * FROM objects WHERE object_id='object_00000001'", "EXPLAIN QUERY PLAN SELECT f.*,l.display_name FROM files f JOIN locations l ON l.location_id=f.location_id WHERE f.object_id='object_00000001'"] {
            let plans=connection.prepare(sql).unwrap().query_map([],|row|row.get::<_,String>(3)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
            assert!(plans.iter().all(|plan|!plan.contains("SCAN")),"{plans:?}");
        }
    }

    #[test]
    #[ignore = "manual disposable release benchmark"]
    fn benchmark_large_catalog() {
        for count in [100_000, 500_000] {
            let (_directory, catalog) = fixture(count);
            let start = std::time::Instant::now();
            let returned = visit_objects(catalog.connection(), &selection(), |_| Ok(())).unwrap();
            eprintln!(
                "catalog release grouped full list count={returned}, elapsed={:?}",
                start.elapsed()
            );
            assert_eq!(returned, count as u64);
        }
    }
}
