use archive_ledger::SqliteCatalog;
use serde_json::Value;
use std::process::Command;

#[test]
fn location_show_works_read_only_without_mounts_and_preserves_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
    catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('c','Files','active');
        INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('s','Home','home','active');
        INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('l','Disk','service','s','offline','active');
        INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES('a','c','utf8',X'61','a');
        INSERT INTO files(object_id,location_id,presence,integrity) VALUES('a','l','present','unverified');").unwrap();
    let version: i64 = catalog
        .connection()
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let run = |json: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_archive"));
        cmd.arg("--archive").arg(temp.path()).args([
            "location",
            "show",
            "Disk",
            "--stale-after",
            "7d",
        ]);
        if json {
            cmd.arg("--json");
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    let json: Value = serde_json::from_slice(&run(true)).unwrap();
    assert_eq!(json["items"][0]["location_id"], "l");
    assert_eq!(json["summary"]["tracked_files"], 1);
    assert_eq!(json["summary"]["present_without_recent_other_copy"], 1);
    assert_eq!(json["stale_after_ms"], 7 * 86400000u64);
    let text = String::from_utf8(run(false)).unwrap();
    assert!(text.starts_with("Name: Disk\nCollection: Files\nDevice: unknown\nSite: Home\n"));
    assert!(text.contains("\n\nFiles\n"));
    assert!(text
        .lines()
        .any(|line| line.trim() == "Total tracked                1"));
    assert!(text.contains("\n\nVerification of present files\n"));
    assert!(text.contains("\n\nBackup coverage\n"));
    assert!(!text.contains("Files by Collection"));
    assert!(text.contains("within 7d"));
    // Archive status uses the same grouped presentation without changing evidence.
    let status = Command::new(env!("CARGO_BIN_EXE_archive"))
        .arg("--archive")
        .arg(temp.path())
        .args(["status"])
        .output()
        .unwrap();
    assert!(status.status.success());
    let text = String::from_utf8(status.stdout).unwrap();
    assert!(text.starts_with("Name: Test\nArchive ID: arc\n\nFiles\n"));
    assert!(text.contains("\n\nCopies across Locations\n"));
    assert!(text.contains("Verified present (any age)"));
    assert_eq!(
        catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
}

#[test]
fn location_show_labels_empty_and_multiple_collections() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
    catalog.connection().execute_batch("INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('s','Home','home','active');
        INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('l','Disk','service','s','offline','active');").unwrap();
    let show = || {
        let out = Command::new(env!("CARGO_BIN_EXE_archive"))
            .arg("--archive")
            .arg(temp.path())
            .args(["location", "show", "Disk"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    assert!(show().starts_with("Name: Disk\nCollection: None tracked yet\n"));
    catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('a','Music','active'),('b','Photos','active');
        INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES('a','a','utf8',X'61','a'),('b','b','utf8',X'62','b');
        INSERT INTO files(object_id,location_id,presence,integrity) VALUES('a','l','present','unverified'),('b','l','missing','unverified');").unwrap();
    let text = show();
    assert!(text.starts_with("Name: Disk\nCollections:\n  Music\n  Photos\n"));
    assert!(text.contains("\n\nFiles by Collection\n  Music\n"));
    assert!(text.contains("\n  Photos\n    Total tracked"));
}
