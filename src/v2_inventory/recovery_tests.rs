use super::*;
use tempfile::TempDir;

fn open_seen(path: &Path) -> Connection {
    let seen = Connection::open(path).unwrap();
    seen.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         CREATE TABLE IF NOT EXISTS seen(path_encoding TEXT, path_bytes BLOB,
             PRIMARY KEY(path_encoding, path_bytes));
         CREATE TABLE IF NOT EXISTS inventory_checkpoint(singleton INTEGER PRIMARY KEY,
             spool_bytes INTEGER NOT NULL, summary_json TEXT NOT NULL);",
    )
    .unwrap();
    seen
}

fn remember(seen: &Connection, path: &str) {
    seen.execute("INSERT INTO seen VALUES ('utf8', ?1)", [path.as_bytes()])
        .unwrap();
}

#[test]
fn checkpoint_keeps_nonspooled_decisions_atomic_with_outcomes_and_summary() {
    // Exercise interruption before spool sync, after sync but before the index
    // commit, and after the commit. Recovery must never keep an index ahead of
    // its spool, nor repeat a checkpointed decision that emitted no outcome.
    for boundary in ["buffered", "synced", "committed"] {
        let temp = TempDir::new().unwrap();
        let job = JobDirectory::new(temp.path(), "job_recovery").unwrap();
        job.ensure().unwrap();
        let seen_path = job.path().join("inventory-seen.sqlite3");
        let seen = open_seen(&seen_path);
        let (_, new_job, mut spool) =
            recover_inventory_checkpoint(&job, &seen, &seen_path).unwrap();
        assert!(new_job);
        seen.execute_batch("BEGIN IMMEDIATE").unwrap();
        write_spool_item(&mut spool, &json!({"kind": "first"})).unwrap();
        remember(&seen, "first");
        remember(&seen, "unreadable");
        let summary = V2InventorySummary {
            files_observed: 1,
            read_errors: 1,
            concurrent_changes: 2,
            observed_without_verification: 3,
            integrity_mismatches: 4,
            ..Default::default()
        };
        checkpoint_inventory(&mut spool, &seen, &seen_path, &summary).unwrap();
        let first_prefix = fs::read(&spool.path).unwrap();

        seen.execute_batch("BEGIN IMMEDIATE").unwrap();
        remember(&seen, "second");
        remember(&seen, "unsupported");
        write_spool_item(&mut spool, &json!({"kind": "second"})).unwrap();
        let mut next_summary = summary.clone();
        next_summary.files_observed += 2;
        next_summary.observed_without_verification += 1;
        match boundary {
            "synced" => spool.sync().unwrap(),
            "committed" => {
                checkpoint_inventory(&mut spool, &seen, &seen_path, &next_summary).unwrap()
            }
            _ => {}
        }
        // Dropping the connection rolls back precisely the outstanding local
        // transaction. A real SIGKILL run separately exercises process death.
        drop(seen);
        drop(spool);
        let expected_prefix = if boundary == "committed" {
            fs::read(job.path().join("inventory-items.jsonl")).unwrap()
        } else {
            first_prefix
        };
        let mut tail = job.open_append("inventory-items.jsonl").unwrap();
        tail.write_all(b"{\"torn\":").unwrap();
        tail.sync_all().unwrap();
        drop(tail);

        let seen = open_seen(&seen_path);
        let (recovered, new_job, spool) =
            recover_inventory_checkpoint(&job, &seen, &seen_path).unwrap();
        assert!(!new_job);
        assert_eq!(
            fs::read(&spool.path).unwrap(),
            expected_prefix,
            "{boundary}"
        );
        assert_eq!(
            recovered,
            if boundary == "committed" {
                next_summary
            } else {
                summary
            },
            "{boundary}"
        );
        let paths = seen
            .prepare("SELECT CAST(path_bytes AS TEXT) FROM seen ORDER BY path_bytes")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            paths,
            if boundary == "committed" {
                vec!["first", "second", "unreadable", "unsupported"]
            } else {
                vec!["first", "unreadable"]
            },
            "{boundary}"
        );
    }
}

#[test]
fn interruption_before_first_checkpoint_restarts_unpublished_progress() {
    let temp = TempDir::new().unwrap();
    let job = JobDirectory::new(temp.path(), "job_initial").unwrap();
    job.ensure().unwrap();
    let seen_path = job.path().join("inventory-seen.sqlite3");
    let seen = open_seen(&seen_path);
    remember(&seen, "legacy-decision");
    job.write_new("inventory-items.jsonl", b"{\"kind\":\"torn")
        .unwrap();
    let (summary, new_job, spool) = recover_inventory_checkpoint(&job, &seen, &seen_path).unwrap();
    assert!(new_job);
    assert_eq!(summary, V2InventorySummary::default());
    assert!(fs::read(&spool.path).unwrap().is_empty());
    assert_eq!(
        seen.query_row("SELECT COUNT(*) FROM seen", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
