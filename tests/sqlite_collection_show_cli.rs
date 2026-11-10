use archive_ledger::SqliteCatalog;
use serde_json::Value;
use std::process::Command;

#[test]
fn collection_show_preserves_metadata_and_reports_protection_without_writes() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
    catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,description,status) VALUES('c','Files','Test collection','active'),('e','Empty',NULL,'active');
        INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('s','Home','home','active');
        INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('l','Disk','service','s','offline','active');
        INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES('a','c','utf8',X'61','a'),('b','c','utf8',X'62','b');
        INSERT INTO files(object_id,location_id,presence,integrity) VALUES('a','l','present','unverified');").unwrap();
    let version: i64 = catalog
        .connection()
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_archive"))
            .arg("--archive")
            .arg(temp.path())
            .args(args)
            .output()
            .unwrap()
    };
    let out = run(&[
        "--json",
        "collection",
        "show",
        "Files",
        "--stale-after",
        "7d",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["items"][0]["description"], "Test collection");
    assert_eq!(value["summary"]["total_files"], 2);
    assert_eq!(
        value["summary"]["present_copies"],
        serde_json::json!({"0":1,"1":1})
    );
    assert_eq!(
        value["summary"]["recent_verified_copies"],
        serde_json::json!({"0":2})
    );
    assert_eq!(value["stale_after_ms"], 7 * 86400000u64);
    let out = run(&["collection", "show", "Files"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("50.0%"));
    assert!(text.contains("Verification window: 30d"));
    assert!(text.contains("Known Sites"));
    assert!(text.contains("1 files have no present copy"));
    let empty = run(&["--json", "collection", "show", "Empty"]);
    assert!(empty.status.success());
    let empty: Value = serde_json::from_slice(&empty.stdout).unwrap();
    assert_eq!(
        empty["summary"]["present_copies"],
        serde_json::json!({"0":0})
    );
    assert!(
        !run(&["collection", "show", "Files", "--stale-after", "0d"])
            .status
            .success()
    );
    assert!(!run(&["collection", "show", "Absent"]).status.success());
    assert_eq!(
        catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
}
