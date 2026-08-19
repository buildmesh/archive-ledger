use std::fs::{self, File};
use std::path::Path;
use std::time::Instant;

use archive_ledger::{
    DiscoveryItem, EventReferences, EventRequest, EventStore, EventStoreConfig, FileDiscovery,
    ProjectionConfig, ProjectionDb,
};
use serde_json::json;
use tempfile::TempDir;

#[test]
#[ignore = "explicit 500k-file scale gate"]
fn discovery_projection_checkpoint_and_rebuild_scale_gate() {
    let file_count: usize = std::env::var("ARCHIVE_LEDGER_SCALE_FILES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(500_000);
    let temp = TempDir::new().unwrap();
    let fixture = temp.path().join("fixture");
    fs::create_dir(&fixture).unwrap();

    let fixture_started = Instant::now();
    let files_per_directory = 1_000;
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

    let canonical = temp.path().join("canonical");
    let store = EventStore::open_or_create(
        &canonical,
        EventStoreConfig {
            rollover_events: 100_000,
            max_event_bytes: 1024 * 1024,
            actor_id: "scale-user".to_owned(),
            host_id: "scale-host".to_owned(),
        },
    )
    .unwrap();

    let discovery_started = Instant::now();
    let mut discovery = FileDiscovery::new(&fixture).unwrap();
    let mut discovered = 0_usize;
    let batches = std::iter::from_fn(|| {
        let mut batch = Vec::with_capacity(1_000);
        while batch.len() < 1_000 {
            let Some(item) = discovery.next() else {
                break;
            };
            match item {
                DiscoveryItem::File(file) => {
                    let item_key = format!(
                        "{}:{}",
                        file.relative_path.encoding.as_str(),
                        file.relative_path.display
                    );
                    batch.push(
                        EventRequest::new(
                            "file_ref_observed",
                            json!({
                                "operation_key": format!("scale:{discovered}"),
                                "job_type": "scale_discovery",
                                "item_type": "path",
                                "item_key": item_key,
                                "outcome_kind": "observed"
                            }),
                        )
                        .with_references(EventReferences {
                            job_id: Some("job_scale_500k".to_owned()),
                            ..EventReferences::default()
                        }),
                    );
                    discovered += 1;
                }
                DiscoveryItem::Error { error, .. } => {
                    panic!("scale discovery failed: {error}")
                }
                DiscoveryItem::Symlink(_)
                | DiscoveryItem::Special(_)
                | DiscoveryItem::Excluded(_)
                | DiscoveryItem::FilesystemBoundary(_) => {}
                DiscoveryItem::ConcurrentChange(path) => {
                    panic!("fixture changed during discovery at {path:?}")
                }
            }
        }
        (!batch.is_empty()).then_some(batch)
    });
    let append_stats = store.append_batches(batches).unwrap();
    let discovery_elapsed = discovery_started.elapsed();
    assert_eq!(discovered, file_count);
    assert_eq!(
        append_stats.events_appended,
        u64::try_from(file_count).unwrap()
    );
    assert!(discovery.stats().max_open_directories <= 2);

    let checkpoint_started = Instant::now();
    let checkpoint = store.create_checkpoint().unwrap();
    let checkpoint_elapsed = checkpoint_started.elapsed();
    assert_eq!(
        checkpoint.event_last_seq,
        u64::try_from(file_count).unwrap() + 1
    );
    assert!(checkpoint.segments.len() >= 3);

    let database_path = temp.path().join("archive.db");
    let database =
        ProjectionDb::open_or_create(&database_path, "arc_scale", ProjectionConfig::default())
            .unwrap();
    let apply_started = Instant::now();
    let interrupted = database.apply_at_most(&store, 10).unwrap();
    assert!(!interrupted.caught_up);
    let resumed = database.apply(&store).unwrap();
    let apply_elapsed = apply_started.elapsed();
    assert!(resumed.caught_up);
    assert_eq!(
        database.status().unwrap().cursor.applied_seq,
        checkpoint.event_last_seq
    );

    let rebuild_path = temp.path().join("rebuilt.db");
    let rebuild_started = Instant::now();
    let rebuild_stats = ProjectionDb::rebuild(
        &store,
        &rebuild_path,
        "arc_scale",
        ProjectionConfig::default(),
    )
    .unwrap();
    let rebuild_elapsed = rebuild_started.elapsed();
    assert!(rebuild_stats.caught_up);
    let rebuilt =
        ProjectionDb::open_or_create(&rebuild_path, "arc_scale", ProjectionConfig::default())
            .unwrap();
    assert_eq!(database.status().unwrap(), rebuilt.status().unwrap());

    let peak_rss = peak_rss_kib().unwrap_or(0);
    assert!(
        peak_rss < 64 * 1024,
        "test-process peak RSS was {peak_rss} KiB"
    );

    eprintln!(
        "scale_metrics files={file_count} fixture_ms={} discovery_import_ms={} checkpoint_ms={} apply_ms={} rebuild_ms={} peak_rss_kib={} canonical_bytes={} sqlite_bytes={} rebuilt_bytes={}",
        fixture_elapsed.as_millis(),
        discovery_elapsed.as_millis(),
        checkpoint_elapsed.as_millis(),
        apply_elapsed.as_millis(),
        rebuild_elapsed.as_millis(),
        peak_rss,
        directory_size(&canonical),
        fs::metadata(&database_path).unwrap().len(),
        fs::metadata(&rebuild_path).unwrap().len(),
    );
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
