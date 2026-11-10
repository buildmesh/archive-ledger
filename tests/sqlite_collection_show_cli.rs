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
    assert!(text.contains("Files by known Site count"));
    assert!(!text.contains("Collection ID:"));
    assert!(text.starts_with("Name: Files\nStatus: active\nDescription: Test collection\n"));
    assert!(text.contains("\n\nFiles\n  Total tracked: 2\n"));
    assert!(text.contains("\n\nProtection gaps\n  No present copy: 1\n"));
    assert!(text.contains("\n\nSite information\n"));
    let empty_text = run(&["collection", "show", "Empty"]);
    assert!(empty_text.status.success());
    let empty_text = String::from_utf8(empty_text.stdout).unwrap();
    assert!(empty_text.contains("Total tracked: 0"));
    assert!(empty_text.contains("0 (0.0%)"));
    assert!(!empty_text.contains("NaN"));
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

#[test]
fn collection_status_reuses_copy_distributions_and_preserves_json_status() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
    catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('c','Files','active');
        INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('s','Home','home','active');
        INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES('l','Disk','service','s','offline','active'),('m','Backup','service','s','offline','active');
        INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES('a','c','utf8',X'61','a'),('b','c','utf8',X'62','b'),('c','c','utf8',X'63','c');
        INSERT INTO files(object_id,location_id,presence,integrity) VALUES('b','l','present','unverified'),('c','l','present','unverified'),('c','m','present','unverified');").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_archive"))
            .arg("--archive")
            .arg(temp.path())
            .args(args)
            .output()
            .unwrap()
    };
    let version: i64 = catalog
        .connection()
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let show = run(&["collection", "show", "Files"]);
    assert!(show.status.success());
    for args in [
        vec!["collection", "status", "Files"],
        vec!["collection", "status", "c"],
        vec!["collection", "status"],
    ] {
        let status = run(&args);
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        assert_eq!(status.stdout, show.stdout);
    }
    let text = String::from_utf8(show.stdout).unwrap();
    let distribution = text
        .split("Files by copy count\n")
        .nth(1)
        .unwrap()
        .split("\nSite information")
        .next()
        .unwrap();
    for (copies, unit, verified) in [
        (0, "copies", "3 (100.0%)"),
        (1, "copy", "0 (0.0%)"),
        (2, "copies", "0 (0.0%)"),
    ] {
        assert!(distribution.contains(&format!(
            "  {copies} {unit}\n    Present: 1 (33.3%)\n    Recently verified: {verified}"
        )));
    }
    assert!(distribution.contains("Files by known Site count\n  0 Sites\n"));
    assert!(distribution.contains("  1 Site\n    Present: 2 (66.7%)"));
    assert!(distribution.lines().all(|line| line.len() <= 40));
    let json = run(&["--json", "collection", "status", "Files"]);
    assert!(json.status.success());
    let json: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json["entity"]["collection_id"], "c");
    assert_eq!(json["summary"]["objects"], 3);
    assert_eq!(json["summary"]["present_files"], 3);
    assert!(!run(&["collection", "status", "Absent"]).status.success());
    assert_eq!(
        catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
    catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('e','Extra','active');").unwrap();
    let ambiguous = run(&["collection", "status"]);
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("specify a Collection"));
    catalog
        .connection()
        .execute_batch("UPDATE collections SET status='retired' WHERE collection_id='e';")
        .unwrap();
    assert!(run(&["collection", "status"]).status.success());
}

#[test]
fn collection_init_does_not_give_the_collection_a_location_path_description() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
    let content = temp.path().join("content");
    std::fs::create_dir(&content).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_archive"))
        .arg("--archive")
        .arg(temp.path())
        .args(["--json", "collection", "init"])
        .arg(&content)
        .args([
            "--name",
            "Files",
            "--location-name",
            "Files on disk",
            "--device",
            "disk",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json["collection"]["description"].is_null());
    assert_eq!(json["location"]["display_name"], "Files on disk");
    assert!(json["location"]["relative_path"].is_object());
    assert_eq!(
        catalog.registry_state(false).unwrap().collections[0].description,
        None
    );
}
