// Frozen pre-optimization queries provide an independent equivalence oracle.
const OLD_SUMMARY: &str = r#"WITH eligible AS (
                 SELECT DISTINCT c.object_id, c.location_id
                 FROM copy_claims c
                 WHERE c.state = 'present'
                   AND c.last_verification_result = 'ok'
                   AND c.last_seen_time_utc_ms >= ?2
                   AND c.last_verified_time_utc_ms >= ?3
             ), qualifying AS (
                 SELECT e.object_id, l.device_id,
                        COALESCE(d.current_site_id, l.site_id) AS site_id,
                        l.expected_availability, l.encryption_state
                 FROM eligible e
                 JOIN locations l ON l.location_id = e.location_id AND l.status = 'active'
                 LEFT JOIN devices d ON d.device_id = l.device_id AND d.status = 'active'
                 WHERE (
                       l.device_id IS NULL OR
                       (d.device_id IS NOT NULL
                        AND d.identity_state = 'confirmed'
                        AND d.last_fingerprint_status = 'match'
                        AND d.last_checkin_time_utc_ms >= ?4)
                   )
             ), coverage AS (
                 SELECT object_id,
                        COUNT(*) AS qualifying_copies,
                        COUNT(DISTINCT device_id) AS devices,
                        COUNT(DISTINCT site_id) AS sites,
                        MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 THEN 1 ELSE 0 END) AS has_offsite,
                        MAX(CASE WHEN expected_availability = 'offline' THEN 1 ELSE 0 END) AS has_offline,
                        MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 AND encryption_state = 'encrypted' THEN 1 ELSE 0 END) AS has_encrypted_offsite
                 FROM qualifying
                 GROUP BY object_id
             )
             SELECT COUNT(*), COALESCE(SUM(COALESCE(o.size_bytes, 0)), 0),
                    COALESCE(SUM(CASE
                        WHEN f.object_id IS NOT NULL AND (
                            COALESCE(c.qualifying_copies, 0) < ?6 OR
                            COALESCE(c.devices, 0) < ?7 OR
                            COALESCE(c.sites, 0) < ?8 OR
                            (?9 = 1 AND COALESCE(c.has_offsite, 0) = 0) OR
                            (?10 = 1 AND COALESCE(c.has_offline, 0) = 0) OR
                            (?11 = 1 AND COALESCE(c.has_encrypted_offsite, 0) = 0)
                        ) THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN f.object_id IS NULL THEN 1 ELSE 0 END), 0)
             FROM file_refs f
             LEFT JOIN objects o ON o.object_id = f.object_id
             LEFT JOIN coverage c ON c.object_id = f.object_id
             WHERE f.collection_id = ?1 AND f.path_state = 'active'"#;
const OLD_DETAILS: &str = r#"WITH eligible AS (
             SELECT DISTINCT c.object_id, c.location_id
             FROM copy_claims c
             WHERE ?6 = 1
               AND c.state = 'present'
               AND c.last_verification_result = 'ok'
               AND c.last_seen_time_utc_ms >= ?2
               AND c.last_verified_time_utc_ms >= ?3
         ), qualifying AS (
             SELECT e.object_id, l.device_id,
                    COALESCE(d.current_site_id, l.site_id) AS site_id,
                    l.expected_availability, l.encryption_state
             FROM eligible e
             JOIN locations l ON l.location_id = e.location_id AND l.status = 'active'
             LEFT JOIN devices d ON d.device_id = l.device_id AND d.status = 'active'
             WHERE (
                   l.device_id IS NULL OR
                   (d.device_id IS NOT NULL
                    AND d.identity_state = 'confirmed'
                    AND d.last_fingerprint_status = 'match'
                    AND d.last_checkin_time_utc_ms >= ?4)
               )
         ), coverage AS (
             SELECT object_id,
                    COUNT(*) AS qualifying_copies,
                    COUNT(DISTINCT device_id) AS devices,
                    COUNT(DISTINCT site_id) AS sites,
                    MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 THEN 1 ELSE 0 END) AS has_offsite,
                    MAX(CASE WHEN expected_availability = 'offline' THEN 1 ELSE 0 END) AS has_offline,
                    MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 AND encryption_state = 'encrypted' THEN 1 ELSE 0 END) AS has_encrypted_offsite
             FROM qualifying
             GROUP BY object_id
         )
         SELECT f.file_ref_id, f.logical_path_display, f.object_id, o.size_bytes,
                COALESCE(c.qualifying_copies, 0), COALESCE(c.devices, 0),
                COALESCE(c.sites, 0), COALESCE(c.has_offsite, 0),
                COALESCE(c.has_offline, 0), COALESCE(c.has_encrypted_offsite, 0)
         FROM file_refs f
         LEFT JOIN objects o ON o.object_id = f.object_id
         LEFT JOIN coverage c ON c.object_id = f.object_id
         WHERE f.collection_id = ?1 AND f.path_state = 'active' ORDER BY f.file_ref_id"#;

use super::{V2_RISK_COVERAGE, V2_RISK_DETAILS, V2_RISK_TOTALS};
use rusqlite::{params, params_from_iter, types::Value, Connection, StatementStatus};

fn database() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE records(id INTEGER PRIMARY KEY,record_id TEXT UNIQUE,origin_id TEXT,origin_seq INTEGER);
         CREATE TABLE collections(id INTEGER PRIMARY KEY,collection_id TEXT UNIQUE);
         CREATE TABLE devices(device_id TEXT PRIMARY KEY,status TEXT,identity_state TEXT,
             last_fingerprint_status TEXT,last_checkin_time_utc_ms INTEGER,current_site_id TEXT);
         CREATE TABLE locations(id INTEGER PRIMARY KEY,location_id TEXT UNIQUE,device_id TEXT,
             site_id TEXT,status TEXT,expected_availability TEXT,encryption_state TEXT);
         INSERT INTO records VALUES(1,'record','origin',1);
         INSERT INTO collections VALUES(1,'selected'),(2,'other'),(3,'empty');
         INSERT INTO devices VALUES('device','active','confirmed','match',100,'home');
         INSERT INTO locations VALUES(1,'local','device',NULL,'active','online','unencrypted'),
             (2,'service',NULL,'away','active','offline','encrypted');",
    ).unwrap();
    db.execute_batch(include_str!("compact_projection.sql"))
        .unwrap();
    db
}

fn content(db: &Connection, id: i64) {
    let mut digest = [0_u8; 32];
    digest[..8].copy_from_slice(&id.to_le_bytes());
    db.execute(
        "INSERT INTO content_objects(id,digest,size_bytes,first_record,first_time)
        VALUES(?1,?2,100,1,0)",
        params![id, digest.as_slice()],
    )
    .unwrap();
}

fn file(db: &Connection, name: &str, collection: i64, content: Option<i64>) -> i64 {
    db.execute(
        "INSERT INTO file_objects(canonical_id,collection_id,path_encoding,path_bytes,
        content_id,identity_state,first_record,last_record)
        VALUES(?1,?2,'utf8',?3,?4,'resolved',1,1)",
        params![name, collection, name.as_bytes(), content],
    )
    .unwrap();
    db.last_insert_rowid()
}

fn copy(db: &Connection, file: i64, content: i64, location: i64, id: i64) {
    db.execute(
        "INSERT OR IGNORE INTO file_locations(file_id,location_id,representation,
        content_id,presence,first_record,last_record,seen_time)
        VALUES(?1,?2,'regular',?3,1,1,1,100)",
        params![file, location, content],
    )
    .unwrap();
    let owner: i64 = db
        .query_row(
            "SELECT id FROM file_locations WHERE file_id=?1 AND location_id=?2",
            params![file, location],
            |row| row.get(0),
        )
        .unwrap();
    db.execute(
        "INSERT INTO checks(id,file_location_id,checked_at,presence,integrity)
        VALUES(?1,?2,100,1,1)",
        params![id, owner],
    )
    .unwrap();
    let mut path_key = [0_u8; 32];
    path_key[..8].copy_from_slice(&id.to_le_bytes());
    db.execute(
        "INSERT INTO copy_bindings(id,canonical_id,owner,location_id,path_key,content_id,
        basis,state,first_record,state_record,latest_presence,latest_integrity)
        VALUES(?1,?2,?3,?4,?5,?6,'observed_bytes','present',1,1,?1,?1)",
        params![
            id,
            format!("copy{id}"),
            owner,
            location,
            path_key.as_slice(),
            content
        ],
    )
    .unwrap();
}

fn parameters(active: bool) -> Vec<Value> {
    vec![
        "selected".to_owned().into(),
        100.into(),
        100.into(),
        100.into(),
        "home".to_owned().into(),
        i64::from(active).into(),
    ]
}

fn query(db: &Connection, sql: &str, parameters: &[Value]) -> (Vec<Vec<Value>>, i32) {
    let mut statement = db.prepare(sql).unwrap();
    let columns = statement.column_count();
    let rows = statement
        .query_map(params_from_iter(parameters), |row| {
            (0..columns)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    (rows, statement.get_status(StatementStatus::VmStep))
}

fn assert_equivalent(db: &Connection, active: bool) -> Vec<Vec<Value>> {
    assert_equivalent_with_parameters(db, parameters(active))
}

fn assert_equivalent_with_parameters(db: &Connection, parameters: Vec<Value>) -> Vec<Vec<Value>> {
    let mut old = query(db, OLD_DETAILS, &parameters).0;
    let mut new = query(
        db,
        &format!("{V2_RISK_COVERAGE}{V2_RISK_DETAILS} ORDER BY f.canonical_id"),
        &parameters,
    )
    .0;
    // Output only consumes identity availability, not the internal identity value.
    for row in old.iter_mut().chain(new.iter_mut()) {
        row[2] = Value::Integer(i64::from(row[2] != Value::Null));
    }
    assert_eq!(old, new);
    if parameters[5] == Value::Integer(1) {
        for requirements in [
            [2, 2, 2, 1, 1, 1],
            [0, 0, 0, 0, 0, 0],
            [3, 0, 0, 0, 0, 0],
            [0, 3, 0, 0, 0, 0],
            [0, 0, 3, 0, 0, 0],
            [0, 0, 0, 1, 0, 0],
            [0, 0, 0, 0, 1, 0],
            [0, 0, 0, 0, 0, 1],
        ] {
            let requirements = requirements.map(Value::Integer);
            let mut old_parameters = parameters[..5].to_vec();
            old_parameters.extend_from_slice(&requirements);
            let mut new_parameters = parameters.clone();
            new_parameters.extend_from_slice(&requirements);
            assert_eq!(
                query(db, OLD_SUMMARY, &old_parameters).0,
                query(
                    db,
                    &format!("{V2_RISK_COVERAGE}{V2_RISK_TOTALS}"),
                    &new_parameters
                )
                .0
            );
        }
    }
    new
}

#[test]
fn risk_queries_preserve_coverage_and_freshness_semantics() {
    let db = database();
    content(&db, 1);
    content(&db, 2);
    file(&db, "selected-a", 1, Some(1));
    file(&db, "selected-b", 1, Some(1));
    file(&db, "selected-unresolved", 1, None);
    let owner = file(&db, "other-owner", 2, Some(1));
    let removed = file(&db, "removed", 1, Some(2));
    db.execute("UPDATE file_objects SET active=0 WHERE id=?1", [removed])
        .unwrap();
    copy(&db, owner, 1, 1, 1);
    copy(&db, owner, 1, 1, 2); // One Location counts once, even with two Copies.
    copy(&db, owner, 1, 2, 3);
    let baseline = assert_equivalent(&db, true);
    assert_eq!(&baseline[0][4..], &[2, 1, 2, 1, 1, 1].map(Value::Integer));
    assert_eq!(baseline.len(), 3);
    let inactive = assert_equivalent(&db, false);
    assert_eq!(&inactive[0][4..], &[0, 0, 0, 0, 0, 0].map(Value::Integer));

    // Isolate the device-less Copy, and exercise each way evidence stops qualifying.
    db.execute(
        "UPDATE copy_bindings SET state='missing' WHERE location_id=1",
        [],
    )
    .unwrap();
    for mutation in [
        "UPDATE copy_bindings SET state='missing' WHERE id=3",
        "UPDATE copy_bindings SET state='corrupt' WHERE id=3",
        "UPDATE copy_bindings SET state='unknown' WHERE id=3",
        "UPDATE copy_bindings SET state='superseded' WHERE id=3",
        "UPDATE copy_bindings SET latest_presence=NULL WHERE id=3",
        "UPDATE copy_bindings SET latest_integrity=NULL WHERE id=3",
        "UPDATE checks SET checked_at=99 WHERE id=3",
        "UPDATE checks SET integrity=0 WHERE id=3",
        "UPDATE checks SET integrity=2 WHERE id=3",
        "INSERT INTO check_errors VALUES(3,'read_error',NULL)",
        "INSERT INTO check_errors VALUES(3,'identity_mismatch',NULL)",
        "UPDATE locations SET status='retired' WHERE id=2",
    ] {
        db.execute_batch("SAVEPOINT variant").unwrap();
        db.execute_batch(mutation).unwrap();
        let result = assert_equivalent(&db, true);
        assert_eq!(result[0][4], Value::Integer(0), "{mutation}");
        db.execute_batch("ROLLBACK TO variant; RELEASE variant")
            .unwrap();
    }
    // Separate timestamps and unequal cutoffs detect accidentally swapped evidence joins.
    db.execute_batch(
        "SAVEPOINT freshness;
        INSERT INTO checks SELECT 4,file_location_id,200,1,0 FROM checks WHERE id=3;
        INSERT INTO checks SELECT 5,file_location_id,300,-1,1 FROM checks WHERE id=3;
        UPDATE copy_bindings SET latest_presence=4,latest_integrity=5 WHERE id=3;",
    )
    .unwrap();
    let mut args = parameters(true);
    args[1] = 200.into();
    args[2] = 300.into();
    assert_eq!(
        assert_equivalent_with_parameters(&db, args.clone())[0][4],
        Value::Integer(1)
    );
    db.execute("UPDATE checks SET checked_at=199 WHERE id=4", [])
        .unwrap();
    assert_eq!(
        assert_equivalent_with_parameters(&db, args.clone())[0][4],
        Value::Integer(0)
    );
    db.execute_batch(
        "UPDATE checks SET checked_at=200 WHERE id=4;
        UPDATE checks SET checked_at=299 WHERE id=5;",
    )
    .unwrap();
    assert_eq!(
        assert_equivalent_with_parameters(&db, args)[0][4],
        Value::Integer(0)
    );
    db.execute_batch("ROLLBACK TO freshness; RELEASE freshness")
        .unwrap();
    let mut empty_args = parameters(true);
    empty_args[0] = "empty".to_owned().into();
    assert!(assert_equivalent_with_parameters(&db, empty_args).is_empty());

    db.execute("INSERT INTO check_errors VALUES(3,'other_error',NULL)", [])
        .unwrap();
    assert_eq!(assert_equivalent(&db, true)[0][4], Value::Integer(1));
    db.execute("DELETE FROM check_errors", []).unwrap();

    db.execute(
        "UPDATE copy_bindings SET state=CASE WHEN id=1 THEN 'present' ELSE 'missing' END",
        [],
    )
    .unwrap();
    for mutation in [
        "UPDATE devices SET status='retired'",
        "UPDATE devices SET identity_state='conflict'",
        "UPDATE devices SET identity_state='unavailable'",
        "UPDATE devices SET last_fingerprint_status='mismatch'",
        "UPDATE devices SET last_fingerprint_status=NULL",
        "UPDATE devices SET last_checkin_time_utc_ms=99",
        "UPDATE devices SET last_checkin_time_utc_ms=NULL",
    ] {
        db.execute_batch("SAVEPOINT variant").unwrap();
        db.execute_batch(mutation).unwrap();
        assert_eq!(
            assert_equivalent(&db, true)[0][4],
            Value::Integer(0),
            "{mutation}"
        );
        db.execute_batch("ROLLBACK TO variant; RELEASE variant")
            .unwrap();
    }
    let violations: Vec<_> = db
        .prepare("PRAGMA foreign_key_check")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(violations.is_empty());
}

#[test]
fn risk_query_work_does_not_scale_with_unrelated_collection_copies() {
    let db = database();
    content(&db, 1);
    let selected = file(&db, "selected", 1, Some(1));
    copy(&db, selected, 1, 1, 1);
    let sql = format!("{V2_RISK_COVERAGE}{V2_RISK_DETAILS} ORDER BY f.canonical_id");
    let args = parameters(true);
    let before = query(&db, &sql, &args);
    let old_before = query(&db, OLD_DETAILS, &args).1;
    db.execute_batch("BEGIN").unwrap();
    for id in 2..=5001 {
        content(&db, id);
        let other = file(&db, &format!("other-{id}"), 2, Some(id));
        copy(&db, other, id, 1, id);
    }
    db.execute_batch("COMMIT").unwrap();
    let after = query(&db, &sql, &args);
    let old_after = query(&db, OLD_DETAILS, &args).1;
    eprintln!("risk query VM steps: old {old_before} -> {old_after}; scoped {} -> {} (5,000 unrelated Copies)", before.1, after.1);
    assert_eq!(before.0, after.0);
    assert!(
        after.1 < before.1 * 2,
        "VM steps: {} -> {}",
        before.1,
        after.1
    );
    assert!(
        old_after > old_before * 20,
        "old query must expose the regression"
    );
    assert!(after.1 * 20 < old_after, "new={} old={old_after}", after.1);
    assert_equivalent(&db, true);
}
