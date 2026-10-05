//! Native writes for the compact, canonically rebuildable catalog.
use super::*;

pub(super) const SCHEMA: &str = include_str!("compact_projection.sql");
pub(super) const DEFERRED_INDEXES: &[&str] = &[
    "compact_file_content",
    "compact_file_external",
    "compact_copy_content",
    "compact_copy_external",
];

const ACTIVE_FILE_LOOKUP: &str = "SELECT f.canonical_id,o.object_id,r.record_id,f.identity_state
 FROM file_objects f JOIN collections c ON c.id=f.collection_id
 LEFT JOIN content_objects o ON o.id=f.content_id JOIN records r ON r.id=f.last_record
 WHERE c.collection_id=?1 AND f.path_encoding=?2 AND f.path_bytes=?3 AND f.active=1";

fn run<P: rusqlite::Params>(
    tx: &Transaction<'_>,
    path: &Path,
    sql: &str,
    args: P,
) -> Result<usize> {
    tx.prepare_cached(sql)
        .and_then(|mut s| s.execute(args))
        .map_err(|e| sqlite_error(path, e))
}
fn key<P: rusqlite::Params>(tx: &Transaction<'_>, path: &Path, sql: &str, args: P) -> Result<i64> {
    tx.prepare_cached(sql)
        .and_then(|mut s| s.query_row(args, |r| r.get(0)))
        .map_err(|e| sqlite_error(path, e))
}
fn named(tx: &Transaction<'_>, path: &Path, table: &str, column: &str, value: &str) -> Result<i64> {
    key(
        tx,
        path,
        &format!("SELECT id FROM {table} WHERE {column}=?1"),
        [value],
    )
}
fn record_key(tx: &Transaction<'_>, path: &Path, record: &VerifiedV2Record) -> Result<i64> {
    named(
        tx,
        path,
        "records",
        "record_id",
        &record.record.envelope.record_id,
    )
}
fn bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2)
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(V2ProjectionError::Invalid(
            "invalid lowercase checksum".into(),
        ));
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}
fn optional_number(item: &serde_json::Map<String, Value>, field: &str) -> Result<Option<i64>> {
    item.get(field)
        .and_then(Value::as_u64)
        .map(|n| sql_i64(n, field))
        .transpose()
}
fn checksum(tx: &Transaction<'_>, path: &Path, algorithm: &str, hex: &str) -> Result<i64> {
    let digest = bytes(hex)?;
    if (algorithm == "sha256" && digest.len() != 32)
        || (algorithm == "sha512" && digest.len() != 64)
    {
        return Err(V2ProjectionError::Invalid(
            "checksum has incorrect length".into(),
        ));
    }
    run(
        tx,
        path,
        "INSERT OR IGNORE INTO checksums(algorithm,digest) VALUES(?1,?2)",
        params![algorithm, digest],
    )?;
    key(
        tx,
        path,
        "SELECT id FROM checksums WHERE algorithm=?1 AND digest=?2",
        params![algorithm, digest],
    )
}
fn content(
    tx: &Transaction<'_>,
    path: &Path,
    item: &serde_json::Map<String, Value>,
    record: i64,
    time: i64,
    size: i64,
    source: &str,
) -> Result<i64> {
    let name = string(item, "object_id")?;
    let hash = string(item, "blake3_hex")?;
    if name != format!("blake3:{hash}") {
        return Err(V2ProjectionError::Invalid(
            "content identity disagrees with BLAKE3".into(),
        ));
    }
    let digest = bytes(hash)?;
    if digest.len() != 32 {
        return Err(V2ProjectionError::Invalid("invalid BLAKE3 length".into()));
    }
    run(tx,path,"INSERT OR IGNORE INTO content_objects(digest,size_bytes,extension_hint,first_record,first_time) VALUES(?1,?2,?3,?4,?5)",params![digest,size,item.get("extension_hint").and_then(Value::as_str),record,time])?;
    let (id, stored): (i64, i64) = tx
        .prepare_cached("SELECT id,size_bytes FROM content_objects WHERE digest=?1")
        .and_then(|mut s| s.query_row([&digest], |r| Ok((r.get(0)?, r.get(1)?))))
        .map_err(|e| sqlite_error(path, e))?;
    if stored != size {
        return Err(V2ProjectionError::Invalid(format!(
            "conflicting content identity for {name}"
        )));
    }
    for algorithm in ["sha256", "sha512"] {
        if let Some(hash) = item
            .get(&format!("{algorithm}_hex"))
            .and_then(Value::as_str)
        {
            let hash = checksum(tx, path, algorithm, hash)?;
            run(tx,path,"INSERT OR IGNORE INTO content_checksums(content_id,checksum_id,source,record_id) VALUES(?1,?2,?3,?4)",params![id,hash,source,record])?;
        }
    }
    Ok(id)
}
fn path_value(
    item: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(crate::registry::RegistryPath, Vec<u8>)> {
    let value: crate::registry::RegistryPath =
        serde_json::from_value(required(item, field)?.clone())?;
    let bytes =
        registry_path_bytes(&value).map_err(|e| V2ProjectionError::Invalid(e.to_string()))?;
    Ok((value, bytes))
}
#[allow(clippy::too_many_arguments)]
fn file(
    tx: &Transaction<'_>,
    path: &Path,
    item: &serde_json::Map<String, Value>,
    record: i64,
    content: Option<i64>,
    external: Option<i64>,
    state: &str,
) -> Result<i64> {
    let collection = named(
        tx,
        path,
        "collections",
        "collection_id",
        string(item, "collection_id")?,
    )?;
    let (logical, logical_bytes) = path_value(item, "logical_path")?;
    let name = string(item, "file_ref_id")?;
    run(tx,path,"INSERT INTO file_objects(canonical_id,collection_id,path_encoding,path_bytes,path_display,content_id,external_id,identity_state,modified_time,observed_size,first_record,last_record) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?11) ON CONFLICT(canonical_id) DO UPDATE SET content_id=excluded.content_id,external_id=COALESCE(excluded.external_id,file_objects.external_id),identity_state=excluded.identity_state,active=1,modified_time=excluded.modified_time,observed_size=excluded.observed_size,last_record=excluded.last_record,removed_record=NULL",
        params![name,collection,logical.encoding,logical_bytes,(!(logical.encoding=="utf8" && logical.display.as_bytes()==logical_bytes)).then_some(&logical.display),content,external,state,optional_number(item,"modified_time_utc_ms")?,optional_number(item,"observed_size_bytes")?.or(optional_number(item,"size_bytes")?),record])?;
    named(tx, path, "file_objects", "canonical_id", name)
}
#[allow(clippy::too_many_arguments)]
fn binding(
    tx: &Transaction<'_>,
    path: &Path,
    item: &serde_json::Map<String, Value>,
    file: i64,
    location: &str,
    record: i64,
    time: i64,
    content: Option<i64>,
    external: Option<i64>,
    presence: bool,
    preserve_modified_time: bool,
) -> Result<i64> {
    let location = named(tx, path, "locations", "location_id", location)?;
    run(tx,path,"INSERT INTO file_locations(file_id,location_id,representation,content_id,external_id,presence,first_record,last_record,seen_time,observed_size,modified_time) VALUES(?1,?2,?3,?4,?5,?6,?7,?7,?8,?9,?10) ON CONFLICT(file_id,location_id) DO UPDATE SET representation=excluded.representation,content_id=excluded.content_id,external_id=COALESCE(excluded.external_id,file_locations.external_id),presence=excluded.presence,last_record=excluded.last_record,seen_time=excluded.seen_time,observed_size=excluded.observed_size,modified_time=CASE WHEN ?11 THEN file_locations.modified_time ELSE excluded.modified_time END",
        params![file,location,item.get("representation").and_then(Value::as_str).unwrap_or("ordinary_file"),content,external,presence,record,time,optional_number(item,"observed_size_bytes")?.or(optional_number(item,"size_bytes")?),optional_number(item,"modified_time_utc_ms")?,preserve_modified_time])?;
    key(
        tx,
        path,
        "SELECT id FROM file_locations WHERE file_id=?1 AND location_id=?2",
        params![file, location],
    )
}
#[allow(clippy::too_many_arguments)]
fn annex_content_location(
    tx: &Transaction<'_>,
    path: &Path,
    file: i64,
    location: i64,
    content: Option<i64>,
    external: Option<i64>,
    record: i64,
    time: i64,
    presence: Option<i64>,
) -> Result<i64> {
    run(tx,path,"INSERT INTO file_locations(file_id,location_id,representation,content_id,external_id,presence,first_record,last_record,seen_time) VALUES(?1,?2,'annex_content',?3,?4,COALESCE(?5,0),?6,?6,CASE WHEN ?5 IS NULL THEN 0 ELSE ?7 END) ON CONFLICT(file_id,location_id) DO UPDATE SET content_id=excluded.content_id,external_id=excluded.external_id,last_record=excluded.last_record,presence=COALESCE(?5,file_locations.presence),seen_time=CASE WHEN ?5 IS NULL THEN file_locations.seen_time ELSE excluded.seen_time END",params![file,location,content,external,presence,record,time])?;
    key(
        tx,
        path,
        "SELECT id FROM file_locations WHERE file_id=?1 AND location_id=?2",
        params![file, location],
    )
}

fn append_check(
    tx: &Transaction<'_>,
    path: &Path,
    binding: i64,
    time: i64,
    presence: i64,
    integrity: i64,
    error: Option<(&str, Option<&str>)>,
) -> Result<i64> {
    run(
        tx,
        path,
        "INSERT INTO checks(file_location_id,checked_at,presence,integrity) VALUES(?1,?2,?3,?4)",
        params![binding, time, presence, integrity],
    )?;
    let id = tx.last_insert_rowid();
    if let Some((code, detail)) = error {
        run(
            tx,
            path,
            "INSERT INTO check_errors(check_id,code,detail) VALUES(?1,?2,?3)",
            params![id, code, detail],
        )?;
    }
    run(
        tx,
        path,
        "UPDATE file_locations SET latest_presence=?2 WHERE id=?1 AND ?3>=0",
        params![binding, id, presence],
    )?;
    Ok(id)
}
fn integrity(result: Option<&str>) -> Result<i64> {
    match result {
        None => Ok(0),
        Some("ok") => Ok(1),
        Some("hash_mismatch") => Ok(2),
        Some("read_error") => Ok(0),
        Some("identity_mismatch") => Ok(0),
        Some(other) => Err(V2ProjectionError::Invalid(format!(
            "unsupported integrity result {other}"
        ))),
    }
}
#[allow(clippy::too_many_arguments)]
fn copy(
    tx: &Transaction<'_>,
    path: &Path,
    item: &serde_json::Map<String, Value>,
    binding: i64,
    location: &str,
    name: &str,
    record: i64,
    content: Option<i64>,
    external: Option<i64>,
    state: &str,
    basis: &str,
    check: Option<i64>,
    integrity: i64,
) -> Result<i64> {
    let (copy, copy_bytes) = path_value(item, "copy_path")?;
    let location = named(tx, path, "locations", "location_id", location)?;
    let same:bool=tx.prepare_cached("SELECT f.path_encoding=?2 AND f.path_bytes=?3 FROM file_locations p JOIN file_objects f ON f.id=p.file_id WHERE p.id=?1").and_then(|mut s|s.query_row(params![binding,copy.encoding,copy_bytes],|r|r.get(0))).map_err(|e|sqlite_error(path,e))?;
    // Compact indexed identity for the physical path; bytes remain only in the
    // File or sparse CAS locator. A hash collision is rejected, never merged.
    let mut path_hasher = blake3::Hasher::new();
    path_hasher.update(&(copy.encoding.len() as u64).to_le_bytes());
    path_hasher.update(copy.encoding.as_bytes());
    path_hasher.update(&copy_bytes);
    let path_key = path_hasher.finalize();
    // The active-path invariant spans normal paths and sparse annex locators.
    let previous: Vec<i64> = {
        let mut s=tx.prepare_cached("SELECT b.id FROM copy_bindings b JOIN file_locations p ON p.id=b.owner JOIN file_objects f ON f.id=p.file_id WHERE b.location_id=?1 AND b.state!='superseded' AND b.canonical_id!=?2 AND b.path_key=?3 AND COALESCE(b.locator_encoding,f.path_encoding)=?4 AND COALESCE(b.locator_bytes,f.path_bytes)=?5").map_err(|e|sqlite_error(path,e))?;
        let rows = s
            .query_map(
                params![
                    location,
                    name,
                    path_key.as_bytes().as_slice(),
                    copy.encoding,
                    copy_bytes
                ],
                |r| r.get(0),
            )
            .map_err(|e| sqlite_error(path, e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| sqlite_error(path, e))?
    };
    if !previous.is_empty() && basis == "source_metadata" {
        return Err(V2ProjectionError::Invalid(
            "inventory Copy conflicts with an active physical path".into(),
        ));
    }
    for previous in previous {
        run(
            tx,
            path,
            "UPDATE copy_bindings SET state='superseded',state_record=?2 WHERE id=?1",
            params![previous, record],
        )?;
    }
    run(tx,path,"INSERT INTO copy_bindings(canonical_id,owner,location_id,path_key,locator_encoding,locator_bytes,locator_display,content_id,external_id,basis,state,first_record,state_record,latest_presence,latest_integrity) VALUES(?1,?2,?3,?14,?4,?5,?6,?7,?8,?9,?10,?11,?11,?12,?13) ON CONFLICT(canonical_id) DO UPDATE SET content_id=excluded.content_id,external_id=COALESCE(excluded.external_id,copy_bindings.external_id),basis=excluded.basis,state=excluded.state,state_record=excluded.state_record,latest_presence=COALESCE(excluded.latest_presence,copy_bindings.latest_presence),latest_integrity=COALESCE(excluded.latest_integrity,copy_bindings.latest_integrity) WHERE excluded.basis!='source_metadata'",
        params![name,binding,location,(!same).then_some(&copy.encoding),(!same).then_some(&copy_bytes),(!same && !(copy.encoding=="utf8" && copy.display.as_bytes()==copy_bytes)).then_some(&copy.display),content,external,basis,state,record,check.filter(|_|matches!(state,"present"|"missing"|"corrupt")),check.filter(|_|integrity!=0 || item.get("verification_result").and_then(Value::as_str).is_some()),path_key.as_bytes().as_slice()])?;
    let id = named(tx, path, "copy_bindings", "canonical_id", name)?;
    run(
        tx,
        path,
        "UPDATE file_locations SET copy_id=?2 WHERE id=?1",
        params![binding, id],
    )?;
    Ok(id)
}

pub(super) fn project_annex_entry(
    tx: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    _item_index: u64,
    path: &Path,
) -> Result<()> {
    let rid = record_key(tx, path, record)?;
    let time = sql_i64(record.record.envelope.time_utc_ms, "annex observation time")?;
    let content = if item.get("object_id").and_then(Value::as_str).is_some() {
        Some(content(
            tx,
            path,
            item,
            rid,
            time,
            sql_i64(number(item, "observed_size_bytes")?, "annex size")?,
            "annex_import",
        )?)
    } else {
        None
    };
    let expected = match (
        item.get("expected_hash_algo").and_then(Value::as_str),
        item.get("expected_hash_hex").and_then(Value::as_str),
    ) {
        (Some(a), Some(h)) => Some(checksum(tx, path, a, h)?),
        _ => None,
    };
    let external_name = string(item, "external_identity_id")?;
    let resolution = string(item, "resolution_state")?;
    run(tx,path,"INSERT INTO source_identities(canonical_id,namespace,source_key,expected_checksum,expected_size,content_id,resolution,first_record,resolved_record) VALUES(?1,'git-annex',?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(canonical_id) DO UPDATE SET expected_checksum=excluded.expected_checksum,expected_size=excluded.expected_size,content_id=CASE WHEN source_identities.resolution!='conflict' THEN COALESCE(excluded.content_id,source_identities.content_id) ELSE source_identities.content_id END,resolution=CASE WHEN source_identities.resolution!='conflict' AND excluded.content_id IS NOT NULL THEN 'resolved' ELSE source_identities.resolution END,resolved_record=CASE WHEN source_identities.resolution!='conflict' THEN COALESCE(excluded.resolved_record,source_identities.resolved_record) ELSE source_identities.resolved_record END",
        params![external_name,string(item,"external_key")?,expected,optional_number(item,"expected_size_bytes")?,content,resolution,rid,content.map(|_|rid)])?;
    let external = named(tx, path, "source_identities", "canonical_id", external_name)?;
    let resolved: Option<i64> = tx
        .prepare_cached("SELECT content_id FROM source_identities WHERE id=?1")
        .and_then(|mut s| s.query_row([external], |r| r.get(0)))
        .map_err(|e| sqlite_error(path, e))?;
    let file_content = content.or(resolved);
    let fid = file(
        tx,
        path,
        item,
        rid,
        file_content,
        Some(external),
        if file_content.is_some() {
            "resolved"
        } else if resolution == "unsupported" {
            "unknown"
        } else {
            resolution
        },
    )?;
    let binding = binding(
        tx,
        path,
        item,
        fid,
        string(item, "worktree_location_id")?,
        rid,
        time,
        content,
        Some(external),
        string(item, "path_state")? == "present",
        false,
    )?;
    let source = string(item, "source_repo_id")?;
    run(
        tx,
        path,
        "INSERT OR IGNORE INTO annex_sources(uuid) VALUES(?1)",
        [source],
    )?;
    let source = named(tx, path, "annex_sources", "uuid", source)?;
    let location = named(
        tx,
        path,
        "locations",
        "location_id",
        string(item, "cas_location_id")?,
    )?;
    run(tx,path,"INSERT INTO source_availability(identity_id,source_id,remote_id,state,location_id,observed_time,record_id) VALUES(?1,?2,?2,?3,?4,?5,?6) ON CONFLICT(identity_id,source_id,remote_id) DO UPDATE SET state=excluded.state,location_id=excluded.location_id,observed_time=excluded.observed_time,record_id=excluded.record_id WHERE excluded.state!='unknown'",params![external,source,string(item,"local_availability")?,location,time,rid])?;
    let result = item.get("verification_result").and_then(Value::as_str);
    let integrity = integrity(result)?;
    let state = item
        .get("copy_state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let inventory = item.get("claim_basis").and_then(Value::as_str) == Some("source_metadata");
    if let (Some(name), Some(copy_location), Some(_)) = (
        item.get("copy_claim_id").and_then(Value::as_str),
        item.get("copy_location_id").and_then(Value::as_str),
        item.get("copy_path").filter(|v| !v.is_null()),
    ) {
        let target = if copy_location != string(item, "worktree_location_id")? {
            // The CAS target and its worktree link have independent presence.
            if !inventory {
                append_check(
                    tx,
                    path,
                    binding,
                    time,
                    if string(item, "path_state")? == "present" {
                        1
                    } else {
                        0
                    },
                    0,
                    None,
                )?;
            }
            let location = named(tx, path, "locations", "location_id", copy_location)?;
            let known_presence = if inventory {
                None
            } else {
                match state {
                    "present" | "corrupt" => Some(1_i64),
                    "missing" => Some(0),
                    _ => None,
                }
            };
            annex_content_location(
                tx,
                path,
                fid,
                location,
                content,
                Some(external),
                rid,
                time,
                known_presence,
            )?
        } else {
            binding
        };
        let check = if inventory {
            None
        } else {
            Some(append_check(
                tx,
                path,
                target,
                time,
                match state {
                    "present" | "corrupt" => 1,
                    "missing" => 0,
                    _ => -1,
                },
                integrity,
                result
                    .filter(|r| *r != "ok")
                    .map(|r| (r, item.get("error_detail").and_then(Value::as_str))),
            )?)
        };
        let copy = copy(
            tx,
            path,
            item,
            target,
            copy_location,
            name,
            rid,
            content,
            Some(external),
            state,
            item.get("claim_basis")
                .and_then(Value::as_str)
                .unwrap_or("observed_bytes"),
            check,
            integrity,
        )?;
        run(
            tx,
            path,
            "UPDATE file_locations SET copy_id=?2 WHERE id=?1",
            params![binding, copy],
        )?;
    } else if !inventory {
        append_check(
            tx,
            path,
            binding,
            time,
            if string(item, "path_state")? == "present" {
                1
            } else {
                0
            },
            0,
            None,
        )?;
    }
    Ok(())
}

pub(super) fn project_content_observed(
    tx: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    _item_index: u64,
    verified: &V2VerificationContext,
    path: &Path,
) -> Result<()> {
    let rid = record_key(tx, path, record)?;
    let time = sql_i64(number(item, "observed_time_utc_ms")?, "observation time")?;
    let cid = content(
        tx,
        path,
        item,
        rid,
        time,
        sql_i64(number(item, "size_bytes")?, "object size")?,
        string(item, "representation")?,
    )?;
    let external = item
        .get("external_identity_id")
        .and_then(Value::as_str)
        .map(|name| named(tx, path, "source_identities", "canonical_id", name))
        .transpose()?;
    if let Some(external) = external {
        if ["sha256_hex", "sha512_hex"]
            .iter()
            .any(|f| item.get(*f).and_then(Value::as_str).is_some())
        {
            run(tx,path,"UPDATE source_identities SET content_id=?2,resolution='resolved',resolved_record=?3 WHERE id=?1 AND resolution!='conflict'",params![external,cid,rid])?;
        }
    }
    let collection = string(item, "collection_id")?;
    let (logical, logical_bytes) = path_value(item, "logical_path")?;
    let existing: Option<(String, Option<String>, String, String)> = tx
        .prepare_cached(ACTIVE_FILE_LOOKUP)
        .and_then(|mut s| {
            s.query_row(params![collection, logical.encoding, logical_bytes], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .optional()
        })
        .map_err(|e| sqlite_error(path, e))?;
    if existing
        .as_ref()
        .is_some_and(|e| e.0 != string(item, "file_ref_id").unwrap_or(""))
    {
        return Err(V2ProjectionError::Invalid(
            "content item changes the stable File ID for a logical path".into(),
        ));
    }
    let conflict = if existing.as_ref().is_some_and(|e| e.3 == "conflict") {
        true
    } else if let Some((_, Some(old), old_record, _)) = &existing {
        if old == string(item, "object_id")? {
            false
        } else {
            let (origin, seq): (String, i64) = tx
                .query_row(
                    "SELECT origin_id,origin_seq FROM records WHERE record_id=?1",
                    [old_record],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| sqlite_error(path, e))?;
            let seq = sql_u64(seq, "existing File origin sequence")?;
            let frontier = verified
                .frontiers
                .get(&record.causal_frontier_hash)
                .ok_or_else(|| {
                    V2ProjectionError::Invalid(
                        "content observation causal frontier is unavailable".into(),
                    )
                })?;
            let descends = frontier
                .origins
                .iter()
                .any(|o| o.origin_id == origin && o.seq >= seq);
            if !descends {
                insert_file_identity_conflict(
                    tx,
                    collection,
                    &logical.encoding,
                    &logical_bytes,
                    &origin,
                    seq,
                    old_record,
                    &record.record.envelope.origin_id,
                    record.record.envelope.origin_seq,
                    &record.record.envelope.record_id,
                    path,
                )?;
            }
            !descends
        }
    } else {
        false
    };
    let fid = file(
        tx,
        path,
        item,
        rid,
        (!conflict).then_some(cid),
        external,
        if conflict { "conflict" } else { "resolved" },
    )?;
    let location = string(item, "location_id")?;
    let binding = binding(
        tx,
        path,
        item,
        fid,
        location,
        rid,
        time,
        Some(cid),
        external,
        true,
        false,
    )?;
    let check = append_check(tx, path, binding, time, 1, 1, None)?;
    copy(
        tx,
        path,
        item,
        binding,
        location,
        string(item, "copy_claim_id")?,
        rid,
        Some(cid),
        external,
        "present",
        "observed_bytes",
        Some(check),
        1,
    )?;
    Ok(())
}

pub(super) fn project_copy_verification_failed(
    tx: &Transaction<'_>,
    item: &serde_json::Map<String, Value>,
    record: &VerifiedV2Record,
    _item_index: u64,
    path: &Path,
) -> Result<()> {
    let result = string(item, "result")?;
    if !matches!(result, "hash_mismatch" | "read_error" | "identity_mismatch") {
        return Err(V2ProjectionError::Invalid(format!(
            "unsupported verification failure {result:?}"
        )));
    }
    let rid = record_key(tx, path, record)?;
    let time = optional_number(item, "verified_time_utc_ms")?.unwrap_or(sql_i64(
        record.record.envelope.time_utc_ms,
        "verification time",
    )?);
    let name = string(item, "copy_claim_id")?;
    let location = string(item, "location_id")?;
    let mut existing: Option<i64> = tx
        .query_row(
            "SELECT id FROM copy_bindings WHERE canonical_id=?1",
            [name],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| sqlite_error(path, e))?;
    if let Some(file_name) = item.get("file_ref_id").and_then(Value::as_str) {
        let (logical, logical_bytes) = path_value(item, "logical_path")?;
        let valid:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM file_refs WHERE file_ref_id=?1 AND collection_id=?2 AND logical_path_encoding=?3 AND logical_path_bytes=?4) AND EXISTS(SELECT 1 FROM objects WHERE object_id=?5 AND canonical_hash_hex=?6)",params![file_name,string(item,"collection_id")?,logical.encoding,logical_bytes,string(item,"object_id")?,string(item,"expected_hash_hex")?],|r|r.get(0)).map_err(|e|sqlite_error(path,e))?;
        if !valid || result != "hash_mismatch" || string(item, "expected_hash_algo")? != "blake3" {
            return Err(V2ProjectionError::Invalid(
                "ordinary verification failure has invalid expected File/Object".into(),
            ));
        }
        if existing.is_some() {
            let (copy, copy_bytes) = path_value(item, "copy_path")?;
            let valid:bool=tx.query_row("SELECT location_id=?2 AND relative_path_encoding=?3 AND relative_path_bytes=?4 AND object_id=?5 FROM copy_claims WHERE copy_claim_id=?1",params![name,location,copy.encoding,copy_bytes,string(item,"object_id")?],|r|r.get(0)).map_err(|e|sqlite_error(path,e))?;
            if !valid {
                return Err(V2ProjectionError::Invalid(
                    "verification failure changes Copy identity".into(),
                ));
            }
        }
        let fid = named(tx, path, "file_objects", "canonical_id", file_name)?;
        let cid = named(
            tx,
            path,
            "content_objects",
            "object_id",
            string(item, "object_id")?,
        )?;
        run(
            tx,
            path,
            "UPDATE file_objects SET active=1,removed_record=NULL WHERE id=?1",
            [fid],
        )?;
        let binding = binding(
            tx,
            path,
            item,
            fid,
            location,
            rid,
            time,
            Some(cid),
            None,
            true,
            // Failure evidence does not establish a new metadata baseline for repair.
            true,
        )?;
        let check = append_check(
            tx,
            path,
            binding,
            time,
            1,
            2,
            Some((result, item.get("error_detail").and_then(Value::as_str))),
        )?;
        existing = Some(copy(
            tx,
            path,
            item,
            binding,
            location,
            name,
            rid,
            Some(cid),
            None,
            "corrupt",
            "observed_bytes",
            Some(check),
            2,
        )?);
    } else {
        let id = existing.ok_or_else(|| {
            V2ProjectionError::Invalid(format!(
                "verification failure references unknown Copy {name}"
            ))
        })?;
        let owner=key(tx,path,"SELECT owner FROM copy_bindings WHERE id=?1 AND location_id=(SELECT id FROM locations WHERE location_id=?2)",params![id,location])?;
        let check = append_check(
            tx,
            path,
            owner,
            time,
            if result == "hash_mismatch" { 1 } else { -1 },
            if result == "hash_mismatch" { 2 } else { 0 },
            Some((result, item.get("error_detail").and_then(Value::as_str))),
        )?;
        run(tx,path,"UPDATE copy_bindings SET state=?2,state_record=?3,latest_presence=CASE WHEN ?2='corrupt' THEN ?4 ELSE latest_presence END,latest_integrity=?4 WHERE id=?1",params![id,if result=="hash_mismatch"{"corrupt"}else{"unknown"},rid,check])?;
    }
    let _ = existing;
    Ok(())
}

// This transient map lives only for one scan finalization. It shares a check
// between its path/Copy updates without treating equal timestamps as event IDs.
fn begin_scan_presence(tx: &Transaction<'_>, path: &Path) -> Result<()> {
    tx.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS compact_scan_presence(
        binding_id INTEGER NOT NULL,presence INTEGER NOT NULL,check_id INTEGER NOT NULL,
        PRIMARY KEY(binding_id,presence)) WITHOUT ROWID;
        DELETE FROM temp.compact_scan_presence;",
    )
    .map_err(|e| sqlite_error(path, e))
}

fn presence_check(
    tx: &Transaction<'_>,
    path: &Path,
    binding: i64,
    time: i64,
    presence: i64,
    batch: &str,
) -> Result<i64> {
    let cached: Option<i64> = tx
        .query_row(
            "SELECT check_id FROM temp.compact_scan_presence WHERE binding_id=?1 AND presence=?2",
            params![binding, presence],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| sqlite_error(path, e))?;
    if let Some(id) = cached {
        return Ok(id);
    }
    // Reuse a direct content observation from this batch, never a previous scan
    // whose clock happened to have the same or a larger timestamp.
    let direct:Option<i64>=tx.query_row("SELECT c.id FROM file_locations p JOIN checks c ON c.id=p.latest_presence JOIN records r ON r.id=p.last_record WHERE p.id=?1 AND c.presence=?2 AND c.integrity IN(1,2) AND p.content_id IS NOT NULL AND r.batch_id=?3",params![binding,presence,batch],|r|r.get(0)).optional().map_err(|e|sqlite_error(path,e))?;
    let id = if let Some(id) = direct {
        id
    } else {
        let previous:Option<(i64,i64)>=tx.query_row("SELECT c.id,c.checked_at FROM file_locations p JOIN checks c ON c.id=p.latest_presence WHERE p.id=?1 AND c.presence=?2",params![binding,presence],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|sqlite_error(path,e))?;
        let new = append_check(tx, path, binding, time, presence, 0, None)?;
        // Preserve current freshness across a backward clock, while the newly
        // appended historical check keeps the actual scan timestamp.
        if let Some((old, _)) = previous.filter(|(_, old_time)| *old_time > time) {
            run(
                tx,
                path,
                "UPDATE file_locations SET latest_presence=?2 WHERE id=?1",
                params![binding, old],
            )?;
            old
        } else {
            new
        }
    };
    run(
        tx,
        path,
        "INSERT INTO temp.compact_scan_presence(binding_id,presence,check_id) VALUES(?1,?2,?3)",
        params![binding, presence, id],
    )?;
    Ok(id)
}

// Consume targets in bounded stable-id pages; checks are append-only.
fn scan_targets<F>(
    tx: &Transaction<'_>,
    path: &Path,
    sql: &str,
    scan: &str,
    report: &mut dyn FnMut(V2ApplyProgress),
    phase: &'static str,
    mut apply: F,
) -> Result<()>
where
    F: FnMut(i64) -> Result<()>,
{
    let mut after = 0_i64;
    let mut processed = 0_u64;
    report(V2ApplyProgress::ScanFinalization { phase, processed });
    loop {
        let targets = {
            let mut s = tx.prepare_cached(sql).map_err(|e| sqlite_error(path, e))?;
            let rows = s
                .query_map(params![scan, after], |r| r.get::<_, i64>(0))
                .map_err(|e| sqlite_error(path, e))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| sqlite_error(path, e))?
        };
        if targets.is_empty() {
            break;
        }
        for target in targets {
            apply(target)?;
            after = target;
            processed += 1;
        }
        report(V2ApplyProgress::ScanFinalization { phase, processed });
    }
    Ok(())
}

// Build indexed lookup sets once, rather than scanning every logical path for
// each Copy. These are transaction-local work tables, not new persistent indexes.
fn prepare_scan_copy_targets(
    tx: &Transaction<'_>,
    path: &Path,
    scan: &str,
    location: &str,
    collection: &str,
) -> Result<()> {
    tx.execute_batch(
        "CREATE TEMP TABLE compact_scan_paths(
        encoding TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(encoding,bytes)) WITHOUT ROWID;
        CREATE TEMP TABLE compact_scan_present_paths(
        encoding TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(encoding,bytes)) WITHOUT ROWID;
        CREATE TEMP TABLE compact_scan_annex_ids(id INTEGER PRIMARY KEY);
        CREATE TEMP TABLE compact_scan_copy_targets(
        id INTEGER PRIMARY KEY, covered INTEGER NOT NULL, present INTEGER NOT NULL);",
    )
    .map_err(|e| sqlite_error(path, e))?;
    // Match the historical view predicates exactly: coverage includes removed
    // and absent paths too, but never synthetic annex-content observations.
    run(
        tx,
        path,
        "INSERT OR IGNORE INTO temp.compact_scan_paths
        SELECT f.path_encoding,f.path_bytes FROM file_locations p
        JOIN file_objects f ON f.id=p.file_id
        WHERE p.location_id=(SELECT id FROM locations WHERE location_id=?1)
        AND f.collection_id=(SELECT id FROM collections WHERE collection_id=?2)
        AND p.representation!='annex_content'",
        params![location, collection],
    )?;
    run(
        tx,
        path,
        "INSERT OR IGNORE INTO temp.compact_scan_present_paths
        SELECT f.path_encoding,f.path_bytes FROM file_locations p
        JOIN file_objects f ON f.id=p.file_id
        WHERE p.location_id=(SELECT id FROM locations WHERE location_id=?1)
        AND p.complete_scan=?2 AND p.presence=1 AND p.representation!='annex_content'",
        params![location, scan],
    )?;
    run(
        tx,
        path,
        "INSERT OR IGNORE INTO temp.compact_scan_annex_ids
        SELECT p.external_id FROM file_locations p
        WHERE p.location_id=(SELECT id FROM locations WHERE location_id=?1)
        AND p.complete_scan=?2 AND p.presence=1
        AND p.representation='annex_locked_symlink' AND p.external_id IS NOT NULL",
        params![location, scan],
    )?;
    run(
        tx,
        path,
        "INSERT INTO temp.compact_scan_copy_targets
        SELECT b.id,
          EXISTS(SELECT 1 FROM temp.compact_scan_paths p
            WHERE p.encoding=COALESCE(b.locator_encoding,f.path_encoding)
            AND p.bytes=COALESCE(b.locator_bytes,f.path_bytes)),
          EXISTS(SELECT 1 FROM temp.compact_scan_present_paths p
            WHERE p.encoding=COALESCE(b.locator_encoding,f.path_encoding)
            AND p.bytes=COALESCE(b.locator_bytes,f.path_bytes))
          OR EXISTS(SELECT 1 FROM temp.compact_scan_annex_ids p WHERE p.id=b.external_id)
        FROM copy_bindings b JOIN file_locations owner ON owner.id=b.owner
        JOIN file_objects f ON f.id=owner.file_id
        WHERE b.location_id=(SELECT id FROM locations WHERE location_id=?1)
        AND b.state IN('present','corrupt','unknown')",
        [location],
    )?;
    tx.execute_batch(
        "DROP TABLE temp.compact_scan_paths;
        DROP TABLE temp.compact_scan_present_paths; DROP TABLE temp.compact_scan_annex_ids;",
    )
    .map_err(|e| sqlite_error(path, e))?;
    Ok(())
}

pub(super) fn finalize_scans_for_batch(
    tx: &Transaction<'_>,
    record: &VerifiedV2Record,
    path: &Path,
    report: &mut dyn FnMut(V2ApplyProgress),
) -> Result<()> {
    let pending = {
        let mut s=tx.prepare("SELECT scan_id,desired_status,finished_time_utc_ms,summary_json,finished_record_id FROM scan_pending_completions WHERE batch_id=?1 ORDER BY scan_id").map_err(|e|sqlite_error(path,e))?;
        let rows = s
            .query_map([&record.record.envelope.batch_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| sqlite_error(path, e))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| sqlite_error(path, e))?
    };
    let rid = record_key(tx, path, record)?;
    for (scan, status, finished, summary_json, finished_record) in pending {
        let summary_value: Value = serde_json::from_str(&summary_json)?;
        let summary = object(&summary_value, "scan summary")?;
        let (mode,location,collection,start):(String,String,String,i64)=tx.query_row("SELECT scan_mode,location_id,collection_id,started_time_utc_ms FROM scan_runs WHERE scan_id=?1 AND status='running'",[&scan],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|e|sqlite_error(path,e))?;
        if status == "complete" && mode == "complete" {
            begin_scan_presence(tx, path)?;
            let count=key(tx,path,"SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id=?1 AND activated=0 AND candidate_kind='path'",[&scan])?;
            if sql_u64(count, "scan candidate count")? != number(summary, "missing_paths")? {
                return Err(V2ProjectionError::Invalid(format!(
                    "scan {scan} missing-candidate count does not match its completion"
                )));
            }
            scan_targets(tx,path,"SELECT p.id FROM file_locations p JOIN file_objects f ON f.id=p.file_id JOIN locations l ON l.id=p.location_id WHERE p.id>?2 AND EXISTS(SELECT 1 FROM scan_missing_candidates c WHERE c.scan_id=?1 AND c.activated=0 AND c.candidate_kind='path' AND c.file_ref_id=f.canonical_id AND c.location_id=l.location_id AND c.path_encoding=f.path_encoding AND c.path_bytes=f.path_bytes) ORDER BY p.id LIMIT 512",&scan,report,"Applying scan presence (uncommitted)",|id|{
                let check=presence_check(tx,path,id,finished,0,&record.record.envelope.batch_id)?;
                run(tx,path,"UPDATE file_locations SET presence=0,complete_scan=?2,last_record=?3,latest_presence=?4 WHERE id=?1",params![id,scan,rid,check])?;
                Ok(())
            })?;
            scan_targets(tx,path,"SELECT b.id FROM copy_bindings b WHERE b.id>?2 AND b.canonical_id IN(SELECT copy_claim_id FROM scan_missing_candidates WHERE scan_id=?1 AND activated=0 AND copy_claim_id IS NOT NULL) ORDER BY b.id LIMIT 512",&scan,report,"Applying scan presence (uncommitted)",|id|{
                let owner=key(tx,path,"SELECT owner FROM copy_bindings WHERE id=?1",[id])?;
                let check=presence_check(tx,path,owner,finished,0,&record.record.envelope.batch_id)?;
                run(tx,path,"UPDATE copy_bindings SET state='missing',state_record=?2,complete_scan=?3,latest_presence=?4 WHERE id=?1",params![id,rid,scan,check])?;
                Ok(())
            })?;
            run(
                tx,
                path,
                "UPDATE scan_missing_candidates SET activated=1 WHERE scan_id=?1",
                [&scan],
            )?;
            run(tx,path,"UPDATE file_locations SET complete_scan=?1 WHERE location_id=(SELECT id FROM locations WHERE location_id=?2) AND presence=1 AND file_id IN(SELECT f.id FROM file_objects f JOIN collections c ON c.id=f.collection_id WHERE c.collection_id=?3 AND f.active=1)",params![scan,location,collection])?;
            report(V2ApplyProgress::ScanFinalization {
                phase: "Matching scan copies (uncommitted)",
                processed: 0,
            });
            prepare_scan_copy_targets(tx, path, &scan, &location, &collection)?;
            run(
                tx,
                path,
                "UPDATE copy_bindings SET complete_scan=?1 WHERE id IN
                (SELECT id FROM temp.compact_scan_copy_targets WHERE covered=1)",
                [&scan],
            )?;
            if summary.contains_key("unchanged_files") {
                scan_targets(tx,path,"SELECT id FROM file_locations WHERE complete_scan=?1 AND presence=1 AND id>?2 ORDER BY id LIMIT 512",&scan,report,"Applying scan presence (uncommitted)",|id|{
                    let check=presence_check(tx,path,id,start,1,&record.record.envelope.batch_id)?;
                    run(tx,path,"UPDATE file_locations SET seen_time=MAX(seen_time,?2),latest_presence=?3 WHERE id=?1",params![id,start,check])?;
                    Ok(())
                })?;
                scan_targets(tx,path,"SELECT id FROM temp.compact_scan_copy_targets WHERE id>?2 AND present=1 AND ?1 IS NOT NULL ORDER BY id LIMIT 512",&scan,report,"Refreshing copy presence (uncommitted)",|id|{
                    let owner=key(tx,path,"SELECT owner FROM copy_bindings WHERE id=?1",[id])?;
                    let check=presence_check(tx,path,owner,start,1,&record.record.envelope.batch_id)?;
                    run(tx,path,"UPDATE copy_bindings SET latest_presence=?2 WHERE id=?1",params![id,check])?;
                    Ok(())
                })?;
            }
            tx.execute_batch(
                "DROP TABLE temp.compact_scan_presence; DROP TABLE temp.compact_scan_copy_targets;",
            )
            .map_err(|e| sqlite_error(path, e))?;
        } else if key(
            tx,
            path,
            "SELECT COUNT(*) FROM scan_missing_candidates WHERE scan_id=?1",
            [&scan],
        )? != 0
        {
            return Err(V2ProjectionError::Invalid(format!(
                "non-complete scan {scan} contains missing candidates"
            )));
        }
        let errors = number(summary, "read_errors")?
            .saturating_add(number(summary, "concurrent_changes")?)
            .saturating_add(number(summary, "traversal_errors")?);
        run(tx,path,"UPDATE scan_runs SET status=?2,finished_time_utc_ms=?3,observations_count=?4,missing_candidate_count=?5,files_seen=?4,bytes_seen=?6,new_paths=?7,changed_paths=?8,missing_paths=?5,unchanged_paths=?9,error_count=?10,error_summary_json=?11,finished_record_id=?12 WHERE scan_id=?1 AND status='running'",
            params![scan,status,finished,sql_i64(number(summary,"files_observed")?,"files seen")?,sql_i64(number(summary,"missing_paths")?,"missing paths")?,sql_i64(number(summary,"bytes_observed")?,"bytes seen")?,sql_i64(number(summary,"new_paths")?,"new paths")?,sql_i64(number(summary,"changed_paths")?,"changed paths")?,sql_i64(number(summary,"confirmed_good")?,"unchanged paths")?,sql_i64(errors,"errors")?,summary_json,finished_record])?;
        run(
            tx,
            path,
            "DELETE FROM scan_pending_completions WHERE scan_id=?1",
            [scan],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_database() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE records(id INTEGER PRIMARY KEY,batch_id TEXT NOT NULL);
             INSERT INTO records VALUES(1,'batch_content');
             CREATE TABLE file_locations(id INTEGER PRIMARY KEY,latest_presence INTEGER,last_record INTEGER,content_id INTEGER);
             INSERT INTO file_locations VALUES(1,NULL,1,1);
             CREATE TABLE checks(id INTEGER PRIMARY KEY,file_location_id INTEGER NOT NULL,
                 checked_at INTEGER NOT NULL,presence INTEGER NOT NULL,integrity INTEGER NOT NULL);
             CREATE TABLE check_errors(check_id INTEGER PRIMARY KEY,code TEXT NOT NULL,detail TEXT);"
        ).unwrap();
        connection
    }

    #[test]
    fn active_file_lookup_uses_the_unique_active_path_index() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(CONTROL_SCHEMA).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        let plan = connection
            .prepare(&format!("EXPLAIN QUERY PLAN {ACTIVE_FILE_LOOKUP}"))
            .unwrap()
            .query_map(params!["collection", "utf8", b"path".as_slice()], |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|line| line.contains("SEARCH f USING INDEX compact_file_path")),
            "{plan:?}"
        );
        assert!(!plan.iter().any(|line| line.contains("SCAN f")), "{plan:?}");
    }

    #[test]
    fn scan_presence_reuses_only_its_batch_content_or_own_finalization_check() {
        let mut connection = check_database();
        let tx = connection.transaction().unwrap();
        let path = Path::new(":memory:");
        let verified = append_check(&tx, path, 1, 30, 1, 1, None).unwrap();
        begin_scan_presence(&tx, path).unwrap();
        assert_eq!(
            presence_check(&tx, path, 1, 20, 1, "batch_content").unwrap(),
            verified
        );
        assert_eq!(
            presence_check(&tx, path, 1, 20, 1, "batch_content").unwrap(),
            verified
        );
        begin_scan_presence(&tx, path).unwrap();
        let seen = presence_check(&tx, path, 1, 40, 1, "scan_two").unwrap();
        assert_ne!(seen, verified);
        assert_eq!(
            presence_check(&tx, path, 1, 40, 1, "scan_two").unwrap(),
            seen
        );
        assert_eq!(
            key(&tx, path, "SELECT COUNT(*) FROM checks", []).unwrap(),
            2
        );
        assert_eq!(
            key(
                &tx,
                path,
                "SELECT integrity FROM checks WHERE id=?1",
                [verified]
            )
            .unwrap(),
            1
        );
        assert_eq!(
            key(
                &tx,
                path,
                "SELECT integrity FROM checks WHERE id=?1",
                [seen]
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn distinct_scans_append_equal_and_backward_clock_checks_without_regressing_freshness() {
        let mut connection = check_database();
        let tx = connection.transaction().unwrap();
        let path = Path::new(":memory:");
        append_check(&tx, path, 1, 30, 1, 1, None).unwrap();
        begin_scan_presence(&tx, path).unwrap();
        let same_time = presence_check(&tx, path, 1, 30, 1, "scan_two").unwrap();
        assert_eq!(
            presence_check(&tx, path, 1, 30, 1, "scan_two").unwrap(),
            same_time
        );
        begin_scan_presence(&tx, path).unwrap();
        let current = presence_check(&tx, path, 1, 10, 1, "scan_three").unwrap();
        assert_eq!(current, same_time);
        assert_eq!(
            presence_check(&tx, path, 1, 10, 1, "scan_three").unwrap(),
            current
        );
        let checks = tx
            .prepare("SELECT checked_at,integrity FROM checks ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(checks, vec![(30, 1), (30, 0), (10, 0)]);
        assert_eq!(
            key(
                &tx,
                path,
                "SELECT latest_presence FROM file_locations WHERE id=1",
                []
            )
            .unwrap(),
            same_time
        );
    }

    #[test]
    fn shared_copy_failure_view_is_independent_of_first_file_owner() {
        let rows = |owner: i64| {
            let mut connection = Connection::open_in_memory().unwrap();
            connection
                .execute_batch(
                    "PRAGMA foreign_keys=ON;
                CREATE TABLE records(id INTEGER PRIMARY KEY,record_id TEXT,batch_id TEXT);
                CREATE TABLE collections(id INTEGER PRIMARY KEY,collection_id TEXT);
                CREATE TABLE locations(id INTEGER PRIMARY KEY,location_id TEXT);
                INSERT INTO records VALUES(1,'record','batch');
                INSERT INTO collections VALUES(1,'collection');
                INSERT INTO locations VALUES(1,'cas');",
                )
                .unwrap();
            connection.execute_batch(SCHEMA).unwrap();
            connection.execute_batch("INSERT INTO file_objects(id,canonical_id,collection_id,path_encoding,path_bytes,identity_state,first_record,last_record)
                VALUES(1,'first_alias',1,'utf8',X'61','unknown',1,1),(2,'second_alias',1,'utf8',X'62','unknown',1,1);
                INSERT INTO file_locations(id,file_id,location_id,representation,presence,first_record,last_record,seen_time)
                VALUES(1,1,1,'annex_content',1,1,1,10),(2,2,1,'annex_content',1,1,1,10);").unwrap();
            connection.execute("INSERT INTO copy_bindings(id,canonical_id,owner,location_id,path_key,basis,state,first_record,state_record)
                VALUES(1,'shared_copy',?1,1,zeroblob(32),'observed_metadata','unknown',1,1)",[owner]).unwrap();
            connection
                .execute("UPDATE file_locations SET copy_id=1", [])
                .unwrap();
            let tx = connection.transaction().unwrap();
            append_check(
                &tx,
                Path::new(":memory:"),
                owner,
                20,
                -1,
                0,
                Some(("read_error", Some("failed"))),
            )
            .unwrap();
            let rows=tx.prepare("SELECT file_ref_id,copy_claim_id,location_id,checked_at,presence,integrity,error_code FROM file_checks").unwrap()
                .query_map([],|r|Ok((r.get::<_,Option<String>>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?,r.get::<_,Option<String>>(6)?))).unwrap()
                .collect::<rusqlite::Result<Vec<_>>>().unwrap();
            rows
        };
        assert_eq!(rows(1), rows(2));
        assert_eq!(
            rows(1),
            vec![(
                None,
                Some("shared_copy".into()),
                "cas".into(),
                20,
                -1,
                0,
                Some("read_error".into())
            )]
        );
    }

    #[test]
    fn cas_presence_and_time_change_only_with_an_actual_observation() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE file_locations(
            id INTEGER PRIMARY KEY,file_id INTEGER,location_id INTEGER,representation TEXT,
            content_id INTEGER,external_id INTEGER,presence INTEGER,first_record INTEGER,
            last_record INTEGER,seen_time INTEGER,UNIQUE(file_id,location_id));",
            )
            .unwrap();
        let tx = connection.transaction().unwrap();
        let path = Path::new(":memory:");
        for (time, observed, expected) in [
            (5, None, (0, 0)),
            (10, Some(1), (1, 10)),
            (20, None, (1, 10)),
            (30, Some(0), (0, 30)),
            (40, Some(1), (1, 40)),
        ] {
            annex_content_location(&tx, path, 1, 1, None, None, 1, time, observed).unwrap();
            let state: (i64, i64) = tx
                .query_row("SELECT presence,seen_time FROM file_locations", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap();
            assert_eq!(state, expected);
        }
    }

    #[test]
    fn unreadable_attempt_keeps_prior_presence_without_claiming_integrity() {
        let mut connection = check_database();
        let tx = connection.transaction().unwrap();
        let path = Path::new(":memory:");
        let seen = append_check(&tx, path, 1, 10, 1, 1, None).unwrap();
        let failure = append_check(
            &tx,
            path,
            1,
            20,
            -1,
            0,
            Some(("read_error", Some("unreadable"))),
        )
        .unwrap();
        assert_eq!(
            key(
                &tx,
                path,
                "SELECT latest_presence FROM file_locations WHERE id=1",
                []
            )
            .unwrap(),
            seen
        );
        assert_eq!(
            key(
                &tx,
                path,
                "SELECT integrity FROM checks WHERE id=?1",
                [failure]
            )
            .unwrap(),
            0
        );
        let error: String = tx
            .query_row(
                "SELECT code FROM check_errors WHERE check_id=?1",
                [failure],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(error, "read_error");
    }
}

#[cfg(test)]
#[path = "compact_projection/scan_tests.rs"]
mod scan_tests;
