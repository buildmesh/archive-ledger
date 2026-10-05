//! Behavioral equivalence of complete-scan target selection against the original
//! query contracts. The fixture deliberately includes bindings outside the scan.
use super::*;
use std::collections::BTreeSet;

// Original finalization predicates, selecting the IDs that UPDATE would change.
const OLD_COVERED: &str = "SELECT copy_bindings.id FROM copy_bindings
 WHERE location_id=(SELECT id FROM locations WHERE location_id=?2)
 AND state IN('present','corrupt','unknown')
 AND EXISTS(SELECT 1 FROM path_observations p
 JOIN file_refs f ON f.file_ref_id=p.file_ref_id
 JOIN copy_claims cc ON cc.copy_claim_id=copy_bindings.canonical_id
 WHERE p.location_id=?2 AND f.collection_id=?3
 AND p.observed_path_encoding=cc.relative_path_encoding
 AND p.observed_path_bytes=cc.relative_path_bytes)";
const OLD_PRESENT: &str = "SELECT b.id FROM copy_bindings b
 JOIN locations l ON l.id=b.location_id
 WHERE b.state IN('present','corrupt','unknown')
 AND l.location_id=(SELECT location_id FROM scan_runs WHERE scan_id=?1)
 AND EXISTS(SELECT 1 FROM path_observations p
 JOIN copy_claims cc ON cc.copy_claim_id=b.canonical_id
 WHERE p.location_id=l.location_id AND p.last_complete_scan_id=?1 AND p.state='present'
 AND ((p.observed_path_encoding=cc.relative_path_encoding AND p.observed_path_bytes=cc.relative_path_bytes)
 OR(p.representation='annex_locked_symlink' AND p.external_identity_id=cc.external_identity_id)))";

fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE records(id INTEGER PRIMARY KEY,record_id TEXT UNIQUE,origin_id TEXT,
             origin_seq INTEGER,batch_id TEXT);
         CREATE TABLE collections(id INTEGER PRIMARY KEY,collection_id TEXT UNIQUE);
         CREATE TABLE locations(id INTEGER PRIMARY KEY,location_id TEXT UNIQUE);
         CREATE TABLE scan_runs(scan_id TEXT PRIMARY KEY,location_id TEXT,collection_id TEXT);
         INSERT INTO records VALUES(1,'record','origin',1,'batch');
         INSERT INTO collections VALUES(1,'scanned'),(2,'other');
         INSERT INTO locations VALUES(1,'here'),(2,'elsewhere');
         INSERT INTO scan_runs VALUES('scan','here','scanned');",
    )
    .unwrap();
    db.execute_batch(SCHEMA).unwrap();
    db.execute_batch(
        "INSERT INTO source_identities(id,canonical_id,namespace,source_key,resolution,first_record)
         VALUES(1,'external_shared','git-annex','shared','unresolved',1),
               (2,'external_other','git-annex','other','unresolved',1);",
    )
    .unwrap();
    db
}

fn file(
    db: &Connection,
    name: &str,
    collection: i64,
    encoding: &str,
    bytes: &[u8],
    active: bool,
) -> i64 {
    db.execute(
        "INSERT INTO file_objects(canonical_id,collection_id,path_encoding,path_bytes,
             identity_state,active,first_record,last_record)
         VALUES(?1,?2,?3,?4,'unknown',?5,1,1)",
        params![name, collection, encoding, bytes, active],
    )
    .unwrap();
    db.last_insert_rowid()
}

#[allow(clippy::too_many_arguments)]
fn observation(
    db: &Connection,
    file: i64,
    location: i64,
    representation: &str,
    present: bool,
    scan: Option<&str>,
    external: Option<i64>,
) -> i64 {
    db.execute(
        "INSERT INTO file_locations(file_id,location_id,representation,external_id,presence,
             first_record,last_record,seen_time,complete_scan)
         VALUES(?1,?2,?3,?4,?5,1,1,10,?6)",
        params![file, location, representation, external, present, scan],
    )
    .unwrap();
    db.last_insert_rowid()
}

fn copy(
    db: &Connection,
    name: &str,
    owner: i64,
    location: i64,
    state: &str,
    external: Option<i64>,
    locator: Option<(&str, &[u8])>,
) -> i64 {
    let (encoding, bytes): (String, Vec<u8>) = match locator {
        Some((encoding, bytes)) => (encoding.into(), bytes.into()),
        None => db
            .query_row(
                "SELECT f.path_encoding,f.path_bytes FROM file_locations p
                 JOIN file_objects f ON f.id=p.file_id WHERE p.id=?1",
                [owner],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap(),
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(encoding.len() as u64).to_le_bytes());
    hasher.update(encoding.as_bytes());
    hasher.update(&bytes);
    db.execute(
        "INSERT INTO copy_bindings(canonical_id,owner,location_id,path_key,
             locator_encoding,locator_bytes,external_id,basis,state,first_record,state_record)
         VALUES(?1,?2,?3,?4,?5,?6,?7,'observed_metadata',?8,1,1)",
        params![
            name,
            owner,
            location,
            hasher.finalize().as_bytes().as_slice(),
            locator.map(|(encoding, _)| encoding),
            locator.map(|(_, bytes)| bytes),
            external,
            state
        ],
    )
    .unwrap();
    let id = db.last_insert_rowid();
    db.execute(
        "UPDATE file_locations SET copy_id=?2 WHERE id=?1",
        params![owner, id],
    )
    .unwrap();
    id
}

fn ids<P: rusqlite::Params>(db: &Connection, sql: &str, args: P) -> BTreeSet<i64> {
    db.prepare(sql)
        .unwrap()
        .query_map(args, |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn names(db: &Connection, ids: &BTreeSet<i64>) -> BTreeSet<String> {
    ids.iter()
        .map(|id| {
            db.query_row(
                "SELECT canonical_id FROM copy_bindings WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap()
        })
        .collect()
}

#[test]
fn scan_copy_targets_match_original_view_predicates_across_binding_variants() {
    let mut db = database();
    // Ordinary default paths; Copy eligibility and observation presence differ.
    for (name, state, present, active, complete) in [
        ("ordinary", "present", true, true, Some("scan")),
        ("corrupt", "corrupt", true, true, Some("scan")),
        ("unknown", "unknown", true, true, Some("scan")),
        ("missing_copy", "missing", true, true, Some("scan")),
        ("superseded_copy", "superseded", true, true, Some("scan")),
        ("missing_path", "present", false, true, Some("scan")),
        ("old_coverage", "present", true, true, Some("previous_scan")),
        ("removed_file", "present", true, false, Some("scan")),
    ] {
        let f = file(&db, name, 1, "utf8", name.as_bytes(), active);
        let p = observation(&db, f, 1, "ordinary_file", present, complete, None);
        copy(&db, name, p, 1, state, None, None);
    }
    // A sparse physical locator can match another File, without a copy_id link.
    let f = file(&db, "explicit_owner", 2, "utf8", b"owner-only", true);
    let owner = observation(&db, f, 1, "ordinary_file", true, None, None);
    copy(
        &db,
        "explicit_locator",
        owner,
        1,
        "present",
        None,
        Some(("utf8", b"physical-target")),
    );
    let f = file(&db, "explicit_match", 1, "utf8", b"physical-target", true);
    observation(&db, f, 1, "ordinary_file", true, Some("scan"), None);

    // Shared annex Copy: its owner is outside the scanned Collection and absent.
    // A different covered alias proves presence by external identity, not path.
    let f = file(&db, "annex_owner", 2, "utf8", b"uncovered-owner", true);
    let owner = observation(&db, f, 1, "annex_locked_symlink", false, None, Some(1));
    let shared = copy(
        &db,
        "annex_alias",
        owner,
        1,
        "unknown",
        Some(1),
        Some(("utf8", b".git/annex/objects/shared")),
    );
    let f = file(&db, "annex_alias", 1, "utf8", b"covered-alias", true);
    let alias = observation(
        &db,
        f,
        1,
        "annex_locked_symlink",
        true,
        Some("scan"),
        Some(1),
    );
    db.execute(
        "UPDATE file_locations SET copy_id=?2 WHERE id=?1",
        params![alias, shared],
    )
    .unwrap();

    // Synthetic CAS bindings are not logical path observations.
    let f = file(&db, "synthetic", 1, "utf8", b"synthetic", true);
    let owner = observation(&db, f, 1, "annex_content", true, Some("scan"), Some(2));
    copy(&db, "synthetic", owner, 1, "present", Some(2), None);

    // SQL equality of NULL external identities must never become a match.
    let f = file(&db, "null_identity", 1, "utf8", b"null-link", true);
    let owner = observation(&db, f, 1, "annex_locked_symlink", true, Some("scan"), None);
    copy(
        &db,
        "null_identity",
        owner,
        1,
        "unknown",
        None,
        Some(("utf8", b".git/annex/objects/null")),
    );

    // Neither ordinary paths nor annex identities can borrow another Location.
    let f = file(&db, "other_location", 1, "utf8", b"elsewhere-path", true);
    let owner = observation(
        &db,
        f,
        2,
        "annex_locked_symlink",
        true,
        Some("scan"),
        Some(1),
    );
    copy(&db, "other_location", owner, 2, "present", Some(1), None);
    let f = file(
        &db,
        "wrong_location_witness",
        1,
        "utf8",
        b"outside-only",
        true,
    );
    let owner = observation(&db, f, 2, "ordinary_file", true, Some("scan"), None);
    copy(
        &db,
        "wrong_location_witness",
        owner,
        1,
        "present",
        None,
        None,
    );

    // The original marker filters Collection, but the refresh predicate trusts
    // complete_scan. Do not silently add active/Collection filters to refresh.
    let f = file(
        &db,
        "other_collection",
        2,
        "utf8",
        b"other-collection",
        true,
    );
    let owner = observation(&db, f, 1, "ordinary_file", true, None, None);
    copy(&db, "other_collection", owner, 1, "present", None, None);
    let f = file(
        &db,
        "marked_other_collection",
        2,
        "utf8",
        b"marked-other",
        true,
    );
    let owner = observation(&db, f, 1, "ordinary_file", true, Some("scan"), None);
    copy(
        &db,
        "marked_other_collection",
        owner,
        1,
        "present",
        None,
        None,
    );

    let f = file(&db, "binary_path", 1, "unix_bytes", b"binary-\xff", true);
    let owner = observation(&db, f, 1, "ordinary_file", true, Some("scan"), None);
    copy(&db, "binary_path", owner, 1, "present", None, None);
    let f = file(&db, "encoding_mismatch", 1, "utf8", b"same-bytes", true);
    let owner = observation(&db, f, 1, "ordinary_file", true, Some("scan"), None);
    copy(
        &db,
        "encoding_mismatch",
        owner,
        1,
        "present",
        None,
        Some(("unix_bytes", b"same-bytes")),
    );

    let old_covered = ids(&db, OLD_COVERED, params!["scan", "here", "scanned"]);
    let old_present = ids(&db, OLD_PRESENT, ["scan"]);
    let expected = |values: &[&str]| {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        names(&db, &old_covered),
        expected(&[
            "ordinary",
            "corrupt",
            "unknown",
            "missing_path",
            "old_coverage",
            "removed_file",
            "explicit_locator",
            "binary_path",
        ])
    );
    assert_eq!(
        names(&db, &old_present),
        expected(&[
            "ordinary",
            "corrupt",
            "unknown",
            "removed_file",
            "explicit_locator",
            "annex_alias",
            "marked_other_collection",
            "binary_path",
        ])
    );

    let tx = db.transaction().unwrap();
    prepare_scan_copy_targets(&tx, Path::new(":memory:"), "scan", "here", "scanned").unwrap();
    let covered = ids(
        &tx,
        "SELECT id FROM temp.compact_scan_copy_targets WHERE covered=1",
        [],
    );
    let present = ids(
        &tx,
        "SELECT id FROM temp.compact_scan_copy_targets WHERE present=1",
        [],
    );
    assert_eq!(covered, old_covered);
    assert_eq!(present, old_present);
}
