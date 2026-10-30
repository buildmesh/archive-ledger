//! Backup/restore command parsing and explicit restored-directory selection.
use archive_ledger::SqliteCatalog;
use serde_json::Value;
use std::{fs, process::Command};
use tempfile::TempDir;

fn command(temp: &TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_archive"));
    command
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("HOME", temp.path().join("home"))
        .arg("--json");
    command
}
fn json(command: &mut Command) -> Value {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn backup_restore_roundtrip_preserves_originals_and_refuses_overwrite() {
    let temp = TempDir::new().unwrap();
    let original_root = temp.path().join("original");
    let restored_root = temp.path().join("restored");
    fs::create_dir(&original_root).unwrap();
    fs::create_dir(&restored_root).unwrap();
    let original_db = original_root.join("archive.db");
    let restored_db = restored_root.join("archive.db");
    let backup = temp.path().join("snapshot.db");
    let catalog = SqliteCatalog::create(&original_db, "arc_backup", "Backup roundtrip").unwrap();
    catalog.connection().execute_batch("INSERT INTO collections VALUES ('collection','Files',NULL,NULL,NULL,'active');
        INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3)
        VALUES ('expected-object','collection','utf8',x'70686f746f2e6a7067','photo.jpg',zeroblob(32));
        UPDATE catalog_metadata SET revision=7;").unwrap();
    drop(catalog);
    let original_bytes = fs::read(&original_db).unwrap();
    let report = json(
        command(&temp)
            .arg("--archive")
            .arg(&original_root)
            .args(["backup", "--to"])
            .arg(&backup),
    );
    assert_eq!(report["catalog_format"], "sqlite");
    assert_eq!(report["restored"], false);
    assert_eq!(report["backup"]["archive_id"], "arc_backup");
    assert_eq!(report["backup"]["revision"], 7);
    let backup_bytes = fs::read(&backup).unwrap();
    let restored = json(
        command(&temp)
            .args(["restore", "catalog"])
            .arg(&backup)
            .arg("--to")
            .arg(&restored_db),
    );
    assert_eq!(restored["restored"], true);
    assert_eq!(restored["backup"]["revision"], 7);
    let found = json(command(&temp).arg("--archive").arg(&restored_root).args([
        "file",
        "find",
        "--collection",
        "Files",
    ]));
    assert_eq!(found["objects"].as_array().unwrap().len(), 1);
    assert_eq!(found["objects"][0]["relative_path"]["text"], "photo.jpg");
    let shown = json(command(&temp).arg("--archive").arg(&restored_root).args([
        "object",
        "show",
        "expected-object",
    ]));
    assert_eq!(
        shown["object_review"]["object"]["object_id"],
        "expected-object"
    );
    assert!(shown["object_review"]["files"]
        .as_array()
        .unwrap()
        .is_empty());
    let restored_bytes = fs::read(&restored_db).unwrap();
    let refused_backup = command(&temp)
        .arg("--archive")
        .arg(&original_root)
        .args(["backup", "--to"])
        .arg(&backup)
        .output()
        .unwrap();
    assert!(!refused_backup.status.success());
    let error: Value = serde_json::from_slice(&refused_backup.stderr).unwrap();
    assert_eq!(error["error"]["code"], "catalog_backup_invalid");
    let refused_restore = command(&temp)
        .args(["restore", "catalog"])
        .arg(&backup)
        .arg("--to")
        .arg(&restored_db)
        .output()
        .unwrap();
    assert!(!refused_restore.status.success());
    let error: Value = serde_json::from_slice(&refused_restore.stderr).unwrap();
    assert_eq!(error["error"]["code"], "catalog_backup_invalid");
    assert_eq!(fs::read(&original_db).unwrap(), original_bytes);
    assert_eq!(fs::read(&backup).unwrap(), backup_bytes);
    assert_eq!(fs::read(&restored_db).unwrap(), restored_bytes);
}
