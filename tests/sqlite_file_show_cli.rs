#![cfg(unix)]
use archive_ledger::SqliteCatalog;
use rusqlite::params;
use serde_json::Value;
use std::process::{Command, Output};
use tempfile::TempDir;

struct Fixture {
    temp: TempDir,
    catalog: SqliteCatalog,
    mount: String,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let catalog = SqliteCatalog::create(temp.path().join("archive.db"), "arc", "Test").unwrap();
        let mount = temp
            .path()
            .join("offline-drive")
            .to_str()
            .unwrap()
            .to_owned();
        catalog.connection().execute_batch(
            "INSERT INTO collections(collection_id,display_name,status) VALUES
                ('c','Files','active'),('other','Photos','active');
            INSERT INTO sites(site_id,display_name,site_kind,status) VALUES
                ('home','Home','home','active'),('away','Offsite','offsite','active');
            INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,current_site_id,expected_availability)
                VALUES('disk','disk10','external','unavailable','active','home','offline');
            INSERT INTO archive_roots(archive_root_id,device_id,display_name,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status)
                VALUES('root','disk','Disk root','unavailable',X'2f','utf8','/','active');
            INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,status)
                VALUES('primary','Files on disk10','filesystem','root',X'616e6e65782f66696c6573','utf8','annex/files','disk','offline','active');
            INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status)
                VALUES('remote','Remote copy','service','away','offline','active');",
        ).unwrap();
        catalog.connection().execute(
            "INSERT INTO device_mounts VALUES('mount','disk','root','local-host',?1,'unmounted','unavailable',2)",
            [&mount],
        ).unwrap();
        Self {
            temp,
            catalog,
            mount,
        }
    }

    fn object(&self, id: &str, collection: &str, path: &str) {
        self.catalog.connection().execute(
            "INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3,expected_size_bytes)
                VALUES(?1,?2,'utf8',?3,?4,zeroblob(32),4)",
            params![id, collection, path.as_bytes(), path],
        ).unwrap();
    }

    fn copy(&self, id: &str, location: &str, presence: &str) {
        self.catalog.connection().execute(
            "INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms)
                VALUES(?1,?2,?3,'verified',1700000000000,'ok',zeroblob(32),1700000000000)",
            params![id, location, presence],
        ).unwrap();
    }

    fn show(&self, selector: &str, options: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_archive"))
            .env_remove("ARCHIVE_LEDGER_ARCHIVE")
            .arg("--archive")
            .arg(self.temp.path())
            .args(["file", "show", selector])
            .args(options)
            .output()
            .unwrap()
    }

    fn json(&self, selector: &str, options: &[&str]) -> Value {
        let mut args = options.to_vec();
        args.push("--json");
        let output = self.show(selector, &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn absolute(&self, path: &str) -> String {
        format!("{}/annex/files/{path}", self.mount)
    }
}

#[test]
fn relative_and_absolute_paths_and_ids_share_read_only_copy_details() {
    let f = Fixture::new();
    let path = "quotes ' \" $(literal)/line\nbreak.txt";
    f.object("object_a", "c", path);
    f.copy("object_a", "primary", "present");
    f.copy("object_a", "remote", "missing");
    let version: i64 = f
        .catalog
        .connection()
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let expected = f.json(path, &[]);
    assert_eq!(expected["object_review"]["object"]["object_id"], "object_a");
    assert_eq!(f.json("object_a", &[]), expected);
    assert_eq!(f.json(&f.absolute(path), &[]), expected);
    for spelling in [
        path.replace("/line", "/./line"),
        path.replace("/line", "//line"),
    ] {
        assert_eq!(f.json(&f.absolute(&spelling), &[]), expected);
    }
    let files = expected["object_review"]["files"].as_array().unwrap();
    let primary = files
        .iter()
        .find(|row| row["location_id"] == "primary")
        .unwrap();
    assert_eq!(primary["device_id"], "disk");
    assert_eq!(primary["device_name"], "disk10");
    assert_eq!(primary["site_id"], "home");
    assert_eq!(primary["site_name"], "Home");
    let remote = files
        .iter()
        .find(|row| row["location_id"] == "remote")
        .unwrap();
    assert!(remote["device_id"].is_null());
    assert_eq!(remote["site_name"], "Offsite");
    assert_eq!(remote["presence"], "missing");
    let output = f.show(path, &[]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.starts_with("Path: quotes ' \" $(literal)/line\\nbreak.txt\nCollection: Files\n"),
        "{text}"
    );
    for label in [
        "Expected BLAKE3:",
        "Expected size: 4 bytes",
        "Locations",
        "Device: disk10",
        "Site: Home",
        "Presence: present",
        "Integrity: verified",
        "2023-11-14 22:13:20 UTC",
    ] {
        assert!(text.contains(label), "missing {label:?} in {text}");
    }
    assert!(text.to_lowercase().contains("cached"));
    assert!(!text.contains("Object ID:"));
    assert!(!text.contains("object_a"));
    assert!(
        !std::path::Path::new(&f.mount).exists(),
        "the registered drive remains offline"
    );
    assert_eq!(
        f.catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
}

#[test]
fn duplicate_relative_paths_require_collection_and_collection_also_scopes_ids() {
    let f = Fixture::new();
    f.object("first", "c", "shared.txt");
    f.object("second", "other", "shared.txt");
    let ambiguous = f.show("shared.txt", &[]);
    assert!(!ambiguous.status.success());
    let error = String::from_utf8_lossy(&ambiguous.stderr);
    for fragment in ["--collection", "Files", "Photos"] {
        assert!(error.contains(fragment), "{error}");
    }
    assert_eq!(
        f.json("shared.txt", &["--collection", "Files"])["object_review"]["object"]["object_id"],
        "first"
    );
    assert_eq!(
        f.json("shared.txt", &["--collection", "other"])["object_review"]["object"]["object_id"],
        "second"
    );
    assert!(!f
        .show("first", &["--collection", "Photos"])
        .status
        .success());
    assert!(!f
        .show("shared.txt", &["--collection", "Absent"])
        .status
        .success());
    assert!(!f.show("not-tracked.txt", &[]).status.success());
    assert!(f.json("first", &[])["object_review"]["files"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn exact_collection_path_wins_over_absolute_path_and_id_interpretations() {
    let f = Fixture::new();
    f.object("physical", "c", "file.txt");
    f.copy("physical", "primary", "present");
    let absolute = f.absolute("file.txt");
    f.object("literal_absolute", "other", &absolute);
    assert_eq!(
        f.json(&absolute, &[])["object_review"]["object"]["object_id"],
        "literal_absolute"
    );
    assert_eq!(
        f.json(&absolute, &["--collection", "Files"])["object_review"]["object"]["object_id"],
        "physical"
    );
    f.object("literal_id", "other", "physical");
    assert_eq!(
        f.json("physical", &[])["object_review"]["object"]["object_id"],
        "literal_id"
    );
}

#[test]
fn absolute_resolution_uses_current_host_mount_and_recorded_location_membership() {
    let f = Fixture::new();
    f.object("missing", "c", "gone.txt");
    f.copy("missing", "primary", "missing");
    f.object("unlocated", "c", "elsewhere.txt");
    f.catalog
        .connection()
        .execute_batch(
            "INSERT INTO device_mounts VALUES
          ('old','disk','root','local-host','/old-drive','mounted','unavailable',1),
          ('other-host','disk','root','another-host','/other-drive','mounted','unavailable',99);",
        )
        .unwrap();
    assert_eq!(
        f.json(&f.absolute("gone.txt"), &[])["object_review"]["object"]["object_id"],
        "missing"
    );
    for path in [
        "/old-drive/annex/files/gone.txt".to_owned(),
        "/other-drive/annex/files/gone.txt".to_owned(),
        format!("{}/annex/files-extra/gone.txt", f.mount),
        f.absolute("elsewhere.txt"),
    ] {
        assert!(
            !f.show(&path, &[]).status.success(),
            "unexpected match: {path}"
        );
    }
    assert_eq!(
        f.json(
            "/other-drive/annex/files/gone.txt",
            &["--host", "another-host"]
        )["object_review"]["object"]["object_id"],
        "missing"
    );
}

#[test]
fn nested_roots_report_ambiguous_objects_instead_of_choosing_arbitrarily() {
    let f = Fixture::new();
    f.catalog.connection().execute_batch(
        "INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,status)
          VALUES('nested','Nested Photos','filesystem','root',X'616e6e65782f66696c65732f737562','utf8','annex/files/sub','disk','offline','active');",
    ).unwrap();
    f.object("outer", "c", "sub/photo.jpg");
    f.copy("outer", "primary", "present");
    f.object("inner", "other", "photo.jpg");
    f.copy("inner", "nested", "present");
    let path = f.absolute("sub/photo.jpg");
    let ambiguous = f.show(&path, &[]);
    assert!(!ambiguous.status.success());
    let error = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(
        error.contains("Files") && error.contains("Photos") && error.contains("--collection"),
        "{error}"
    );
    assert_eq!(
        f.json(&path, &["--collection", "Files"])["object_review"]["object"]["object_id"],
        "outer"
    );
    assert_eq!(
        f.json(&path, &["--collection", "Photos"])["object_review"]["object"]["object_id"],
        "inner"
    );
}
