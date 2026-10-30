//! Command-boundary coverage: expression parsing, complete output, and catalog-only effects.
use archive_ledger::SqliteCatalog;
use rusqlite::params;
use serde_json::Value;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn command(temp: &TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_archive"));
    command
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("HOME", temp.path().join("home"));
    command
}
fn success(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn json(command: &mut Command) -> Value {
    serde_json::from_slice(&success(command).stdout).unwrap()
}
fn fixture() -> (TempDir, SqliteCatalog) {
    let temp = TempDir::new().unwrap();
    success(command(&temp).args([
        "init",
        "Removal test",
        "--archive-id",
        "arc_removed",
        "--non-interactive",
    ]));
    let catalog = SqliteCatalog::open(
        temp.path()
            .join("data/archive-ledger/archives/arc_removed/archive.db"),
    )
    .unwrap();
    catalog.connection().execute_batch("INSERT INTO sites VALUES ('site','Site','home',NULL,'active');
        INSERT INTO collections VALUES ('collection','Files',NULL,NULL,NULL,'active');
        INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES
        ('usb','Files on usb','service','site','offline','active'),('sd','Files on sd','service','site','offline','active'),('sd02','Files on sd02','service','site','offline','active');
        WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<250)
        INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3)
        SELECT printf('object_%08d',x),'collection','utf8',cast(printf('file/%08d',x) AS BLOB),printf('file/%08d',x),zeroblob(32) FROM n;").unwrap();
    catalog.connection().execute("INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3) VALUES ('control','collection','utf8',?1,?2,zeroblob(32))",params![b"line\nbreak".as_slice(),"line\nbreak"]).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    catalog.connection().execute("INSERT INTO files SELECT object_id,'usb','present','verified',?1,'ok',expected_blake3,?1 FROM objects",[now]).unwrap();
    catalog.connection().execute("INSERT INTO files SELECT object_id,CASE WHEN cast(substr(object_id,8) AS INTEGER)%2=0 THEN 'sd' ELSE 'sd02' END,'present','verified',CASE WHEN cast(substr(object_id,8) AS INTEGER)%2=0 THEN ?1 ELSE ?2 END,'ok',expected_blake3,CASE WHEN cast(substr(object_id,8) AS INTEGER)%2=0 THEN ?1 ELSE ?2 END FROM objects",params![now,now-60*24*60*60*1000i64]).unwrap();
    std::fs::write(
        temp.path().join("untouched-file"),
        b"archive contents remain",
    )
    .unwrap();
    (temp, catalog)
}
const BULK: &[&str] = &[
    "file",
    "removed",
    "--collection",
    "Files",
    "--in",
    "Files on usb",
    "--and",
    "--in",
    "Files on sd",
    "--in",
    "Files on sd02",
];

#[test]
fn bulk_removal_parses_groups_streams_every_preview_and_never_deletes_files() {
    let (temp, catalog) = fixture();
    let before_revision = catalog.metadata().unwrap().revision;
    let before_history: i64 = catalog
        .connection()
        .query_row("SELECT count(*) FROM history", [], |row| row.get(0))
        .unwrap();
    let preview = success(command(&temp).args(BULK).arg("--dry-run"));
    let output = String::from_utf8(preview.stdout).unwrap();
    let lines = output.lines().collect::<Vec<_>>();
    assert!(lines[0].starts_with("Dry run:"));
    assert_eq!(
        lines.len(),
        252,
        "one explanatory line and all251paths, without hidden pagination"
    );
    assert_eq!(lines.last(), Some(&"line\\nbreak"));
    let recent = json(command(&temp).arg("--json").args(BULK).args([
        "--verified-within",
        "30d",
        "--dry-run",
    ]));
    assert_eq!(recent["affected_count"], 126);
    assert_eq!(recent["paths"].as_array().unwrap().len(), 126);
    let negative = json(command(&temp).args([
        "--json",
        "file",
        "removed",
        "--collection",
        "Files",
        "--in",
        "Files on usb",
        "--and",
        "--not",
        "--in",
        "Files on sd",
        "--dry-run",
    ]));
    assert_eq!(negative["affected_count"], 125);
    let invalid = command(&temp)
        .args([
            "--json",
            "file",
            "removed",
            "--in",
            "Files on usb",
            "--in",
            "Files on sd",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    let error: Value = serde_json::from_slice(&invalid.stderr).unwrap();
    assert_eq!(error["error"]["code"], "invalid_filter");
    assert_eq!(catalog.metadata().unwrap().revision, before_revision);
    assert_eq!(
        catalog
            .connection()
            .query_row("SELECT count(*) FROM history", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        before_history
    );
    let applied = json(command(&temp).arg("--json").args(BULK));
    assert_eq!(applied["files_marked_missing"], 251);
    let repeated = json(command(&temp).arg("--json").args(BULK));
    assert_eq!(repeated["files_marked_missing"], 0);
    assert_eq!(catalog.metadata().unwrap().revision, before_revision + 1);
    assert_eq!(
        catalog
            .connection()
            .query_row(
                "SELECT count(*) FROM history WHERE kind='file_removed'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        251
    );
    assert_eq!(
        catalog
            .connection()
            .query_row(
                "SELECT count(*) FROM files WHERE location_id!='usb' AND presence='present'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        251
    );
    assert_eq!(
        std::fs::read(temp.path().join("untouched-file")).unwrap(),
        b"archive contents remain"
    );
    let empty = success(command(&temp).args(BULK).arg("--dry-run"));
    assert!(String::from_utf8(empty.stdout)
        .unwrap()
        .contains("No matching catalog copies."));
}

#[test]
fn single_removal_requires_complete_mode_and_resolves_location_names() {
    let (temp, catalog) = fixture();
    let bad = command(&temp)
        .args(["file", "removed", "--location", "Files on usb", "--dry-run"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let bad = command(&temp)
        .args([
            "file",
            "removed",
            "--location",
            "Files on usb",
            "--path",
            "file/00000001",
            "--in",
            "Files on sd",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let result = json(command(&temp).args([
        "--json",
        "file",
        "removed",
        "--location",
        "Files on usb",
        "--path",
        "file/00000001",
    ]));
    assert_eq!(result["files_marked_missing"], 1);
    assert_eq!(result["location_id"], "usb");
    assert_eq!(
        catalog
            .connection()
            .query_row(
                "SELECT count(*) FROM files WHERE presence='missing'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        std::fs::read(temp.path().join("untouched-file")).unwrap(),
        b"archive contents remain"
    );
}
