use std::fs::{self, File};
use std::path::Path;
use std::time::Instant;

use archive_ledger::{
    EventStore, EventStoreConfig, LocationScanner, ProjectionConfig, ProjectionDb, ScanConfig,
    ScanMode, ScanStatus,
};
use rusqlite::Connection;
use tempfile::TempDir;

#[test]
#[ignore = "explicit 500k complete-scan and missing-activation scale gate"]
fn complete_scan_and_atomic_missing_activation_scale_gate() {
    let file_count: usize = std::env::var("ARCHIVE_LEDGER_SCAN_SCALE_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500_000);
    let temp = TempDir::new().unwrap();
    let canonical_temp = std::env::var_os("ARCHIVE_LEDGER_SCAN_CANONICAL_PARENT")
        .map(TempDir::new_in)
        .transpose()
        .unwrap();
    let fixture = temp.path().join("fixture");
    fs::create_dir(&fixture).unwrap();
    let files_per_directory = 1_000;

    let fixture_started = Instant::now();
    for directory_number in 0..file_count.div_ceil(files_per_directory) {
        let directory = fixture.join(format!("d{directory_number:06}"));
        fs::create_dir(&directory).unwrap();
        let start = directory_number * files_per_directory;
        let end = (start + files_per_directory).min(file_count);
        for file_number in start..end {
            File::create(directory.join(format!("f{file_number:09}"))).unwrap();
        }
    }
    let fixture_elapsed = fixture_started.elapsed();

    let store = EventStore::open_or_create(
        canonical_temp.as_ref().map_or_else(
            || temp.path().join("canonical"),
            |temp| temp.path().to_owned(),
        ),
        EventStoreConfig {
            rollover_events: 100_000,
            ..EventStoreConfig::default()
        },
    )
    .unwrap();
    let database = ProjectionDb::open_or_create(
        temp.path().join("archive.db"),
        "arc_scan_scale",
        ProjectionConfig::default(),
    )
    .unwrap();
    seed_topology(database.path());

    let first_scanner = scanner(
        &store,
        &database,
        &fixture,
        "scan_scale_present",
        "job_scale_present",
    );
    let resume_started = Instant::now();
    if file_count > 1 {
        let interrupted = first_scanner
            .run_at_most(Some((file_count / 2).max(1)))
            .unwrap();
        assert_eq!(interrupted.status, ScanStatus::Interrupted);
    }
    let resume_elapsed = resume_started.elapsed();
    let scan_started = Instant::now();
    let first = first_scanner.run().unwrap();
    let scan_elapsed = scan_started.elapsed();
    eprintln!(
        "present_scan_complete files={file_count} elapsed_ms={}",
        scan_elapsed.as_millis()
    );
    assert_eq!(first.status, ScanStatus::Complete);
    assert_eq!(first.summary.files_seen, file_count as u64);
    let stale_report_started = Instant::now();
    let stale_report = database
        .stale_presence_report(u64::MAX, Some("collection_scale"), Some(1))
        .unwrap();
    let stale_report_elapsed = stale_report_started.elapsed();
    // The fixture intentionally uses empty files, so every path resolves to
    // one deduplicated Object even though the query scans every copy claim.
    assert_eq!(stale_report.stale_object_count, 1);
    assert_eq!(stale_report.devices.len(), 1);
    assert_eq!(stale_report.devices[0].stale_object_count, 1);

    let removal_started = Instant::now();
    for directory_number in 0..file_count.div_ceil(files_per_directory) {
        let directory = fixture.join(format!("d{directory_number:06}"));
        for entry in fs::read_dir(&directory).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
    }
    let removal_elapsed = removal_started.elapsed();
    eprintln!(
        "removal_complete files={file_count} elapsed_ms={}",
        removal_elapsed.as_millis()
    );

    let missing_started = Instant::now();
    let second = scanner(
        &store,
        &database,
        &fixture,
        "scan_scale_missing",
        "job_scale_missing",
    )
    .run()
    .unwrap();
    let missing_elapsed = missing_started.elapsed();
    eprintln!(
        "missing_scan_complete files={file_count} elapsed_ms={}",
        missing_elapsed.as_millis()
    );
    assert_eq!(second.status, ScanStatus::Complete);
    assert_eq!(second.summary.missing_paths, file_count as u64);
    let connection = Connection::open(database.path()).unwrap();
    let (missing_copies, activated, canonical_events): (i64, i64, i64) = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'),
                (SELECT COUNT(*) FROM scan_missing_candidates
                 WHERE scan_id = 'scan_scale_missing' AND activated = 1),
                (SELECT COUNT(*) FROM events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(missing_copies, file_count as i64);
    assert_eq!(activated, (file_count * 2) as i64);

    eprintln!(
        "scan_scale_metrics files={file_count} fixture_ms={} interrupted_prefix_ms={} present_scan_ms={} stale_report_ms={} removal_ms={} missing_scan_ms={} peak_rss_kib={} canonical_events={} canonical_bytes={} sqlite_bytes={}",
        fixture_elapsed.as_millis(),
        resume_elapsed.as_millis(),
        scan_elapsed.as_millis(),
        stale_report_elapsed.as_millis(),
        removal_elapsed.as_millis(),
        missing_elapsed.as_millis(),
        peak_rss_kib().unwrap_or(0),
        canonical_events,
        directory_size(store.root()),
        fs::metadata(database.path()).unwrap().len(),
    );
}

fn scanner<'a>(
    store: &'a EventStore,
    database: &'a ProjectionDb,
    root: &Path,
    scan_id: &str,
    job_id: &str,
) -> LocationScanner<'a> {
    LocationScanner::new(
        store,
        database,
        ScanConfig {
            root_path: root.to_path_buf(),
            scan_id: scan_id.to_owned(),
            job_id: job_id.to_owned(),
            collection_id: "collection_scale".to_owned(),
            location_id: "location_scale".to_owned(),
            device_id: "device_scale".to_owned(),
            archive_root_id: "root_scale".to_owned(),
            location_prefix: None,
            logical_prefix: None,
            exclusions: Vec::new(),
            fingerprint_status: "match".to_owned(),
            batch_entries: 1_000,
            scan_mode: ScanMode::Complete,
        },
    )
    .unwrap()
}

fn seed_topology(database: &Path) {
    Connection::open(database)
        .unwrap()
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             INSERT INTO collections(collection_id, display_name, status, last_event_id)
             VALUES ('collection_scale', 'Scale', 'active', 'seed');
             INSERT INTO devices(
                device_id, display_name, device_kind, identity_state, status,
                expected_availability, last_event_id
             ) VALUES ('device_scale', 'Scale device', 'disk', 'confirmed', 'active', 'online', 'seed');
             INSERT INTO archive_roots(
                archive_root_id, device_id, display_name, root_path_on_device_bytes,
                root_path_encoding, root_path_display, status, created_event_id
             ) VALUES ('root_scale', 'device_scale', 'Scale root', x'2f', 'utf8', '/', 'active', 'seed');
             INSERT INTO locations(
                location_id, display_name, kind, archive_root_id, relative_path_bytes,
                relative_path_encoding, relative_path_display, device_id,
                encryption_state, trust_level, expected_availability, is_writable,
                status, created_event_id, last_event_id
             ) VALUES (
                'location_scale', 'Scale files', 'filesystem', 'root_scale', x'2e',
                'utf8', '.', 'device_scale', 'unknown', 'trusted', 'online', 0,
                'active', 'seed', 'seed'
             );",
        )
        .unwrap();
}

fn directory_size(root: &Path) -> u64 {
    let mut total = 0_u64;
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                directories.push(entry.path());
            } else {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    total
}

fn peak_rss_kib() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}
