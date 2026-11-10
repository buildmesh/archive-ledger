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
    assert!(text.contains("1 tracked; 1 present"));
    assert!(text.contains("within 7d"));
    assert_eq!(
        catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
}
