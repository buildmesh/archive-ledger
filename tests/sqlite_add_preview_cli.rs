#![cfg(unix)]

use archive_ledger::{RegistryPath, SqliteCatalog};
use rusqlite::params;
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path, process::Command};
use tempfile::TempDir;

fn success(command: &mut Command) -> std::process::Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn fixture() -> (TempDir, SqliteCatalog) {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("catalog")).unwrap();
    fs::create_dir(temp.path().join("primary")).unwrap();
    let catalog =
        SqliteCatalog::create(temp.path().join("catalog/archive.db"), "archive", "Files").unwrap();
    catalog.connection().execute_batch("INSERT INTO sites(site_id,display_name,site_kind,status) VALUES ('site','Home','home','active');
        INSERT INTO collections(collection_id,display_name,status) VALUES ('collection','Files','active');
        INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,current_site_id,expected_availability) VALUES ('device','Disk','external','unavailable','active','site','offline');
        INSERT INTO archive_roots(archive_root_id,device_id,display_name,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status) VALUES ('root','device','Root','unavailable',X'2e','utf8','.','active');
        INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status) VALUES ('other','Other','service','site','offline','active');").unwrap();
    let mounted = archive_ledger::discover_mounted_filesystem(temp.path().join("primary")).unwrap();
    let relative = RegistryPath::from_path(&mounted.relative_path);
    catalog.connection().execute("INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,is_writable,status) VALUES ('primary','Primary','filesystem','root',?1,?2,?3,'device','offline',1,'active')", params![relative.text.as_ref().unwrap().as_bytes(),relative.encoding,relative.display]).unwrap();
    catalog.connection().execute("INSERT INTO device_mounts(mount_id,device_id,archive_root_id,host_id,mount_root_uri,status,fingerprint_status,observed_time_utc_ms) VALUES ('mount','device','root','fixture',?1,'mounted','unavailable',1)", [mounted.mount_root.to_str().unwrap()]).unwrap();
    (temp, catalog)
}

fn add(temp: &TempDir) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_archive"));
    cmd.args(["--host", "fixture", "--archive"])
        .arg(temp.path().join("catalog"))
        .args(["collection", "add"])
        .arg(temp.path().join("primary"))
        .args([
            "--collection",
            "Files",
            "--location",
            "Primary",
            "--dry-run",
        ]);
    cmd
}

fn track(catalog: &SqliteCatalog, path: &str, location: &str, presence: &str) {
    catalog.connection().execute("INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES (?1,'collection','utf8',?2,?1)", params![path,path.as_bytes()]).unwrap();
    catalog.connection().execute("INSERT INTO files(object_id,location_id,presence,integrity) VALUES (?1,?2,?3,'unverified')", params![path,location,presence]).unwrap();
}

fn pointer(root: &Path, name: &str, key: &str, present: bool) {
    let target = format!(".git/annex/objects/ab/cd/{key}/{key}");
    std::os::unix::fs::symlink(&target, root.join(name)).unwrap();
    if present {
        fs::create_dir_all(root.join(&target).parent().unwrap()).unwrap();
        // Deliberately not the advertised content: preview must not checksum it.
        fs::write(root.join(&target), b"not checked by preview").unwrap();
    }
}

#[test]
fn add_preview_lists_only_available_new_location_files_without_writes() {
    let (temp, catalog) = fixture();
    let root = temp.path().join("primary");
    success(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"]),
    );
    success(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["config", "annex.uuid", "fixture"]),
    );
    for name in ["known", "known-missing", "elsewhere", "new"] {
        fs::write(root.join(name), b"ordinary").unwrap();
    }
    track(&catalog, "known", "primary", "present");
    track(&catalog, "known-missing", "primary", "missing");
    track(&catalog, "elsewhere", "other", "present");
    let key = format!("SHA256E-s1--{}.txt", "0".repeat(64));
    pointer(&root, "available-annex", &key, true);
    let absent_key = format!("SHA256E-s1--{}.txt", "1".repeat(64));
    pointer(&root, "dropped-annex", &absent_key, false);
    std::os::unix::fs::symlink("new", root.join("ordinary-link")).unwrap();
    std::os::unix::fs::symlink("absent", root.join("dangling-ordinary")).unwrap();
    std::os::unix::fs::symlink("cycle", root.join("cycle")).unwrap();
    let version: i64 = catalog
        .connection()
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let expected = BTreeSet::from(["available-annex", "elsewhere", "new"]);
    let text = success(&mut add(&temp));
    let text = String::from_utf8(text.stdout).unwrap();
    assert_eq!(text.lines().collect::<BTreeSet<_>>(), expected);
    let output = success(add(&temp).arg("--json"));
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        output["paths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["text"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        success(add(&temp).arg("--list-new")).stdout,
        text.as_bytes()
    );
    let limited = success(add(&temp).args(["--json", "--max-items", "1"]));
    let limited: Value = serde_json::from_slice(&limited.stdout).unwrap();
    assert_eq!(limited["paths"].as_array().unwrap().len(), 1);
    assert_eq!(
        catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
    assert_eq!(
        catalog
            .connection()
            .query_row("SELECT count(*) FROM catalog_jobs", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn add_accept_changes_preview_still_includes_tracked_selected_files() {
    let (temp, catalog) = fixture();
    fs::write(temp.path().join("primary/known"), b"changed").unwrap();
    track(&catalog, "known", "primary", "present");
    let output = success(add(&temp).args(["--json", "--accept-changes", "known"]));
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output["paths"][0]["text"], "known");
    assert_eq!(output["paths"].as_array().unwrap().len(), 1);
}

#[test]
fn indexed_regular_annex_pointers_are_absent_but_unlocked_files_are_previewed() {
    use sha2::{Digest, Sha256};
    let (temp, catalog) = fixture();
    let root = temp.path().join("primary");
    success(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["init", "-q"]),
    );
    success(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["config", "annex.uuid", "fixture"]),
    );
    let contents = b"available";
    let key = format!(
        "SHA256E-s{}--{:x}.txt",
        contents.len(),
        Sha256::digest(contents)
    );
    let pointer = format!("/annex/objects/{key}\n");
    for path in ["dropped-pointer", "unlocked"] {
        fs::write(root.join(path), &pointer).unwrap();
    }
    success(
        Command::new("git")
            .arg("-C")
            .arg(&root)
            .args(["add", "dropped-pointer", "unlocked"]),
    );
    fs::write(root.join("unlocked"), contents).unwrap();
    // Only indexed pointers represent annex metadata; an ordinary untracked
    // file with pointer-looking contents remains a regular file for import.
    fs::write(root.join("ordinary"), &pointer).unwrap();
    let version: i64 = catalog
        .connection()
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let preview = success(add(&temp).arg("--json"));
    let preview: Value = serde_json::from_slice(&preview.stdout).unwrap();
    let paths = preview["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["text"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(paths, BTreeSet::from(["ordinary", "unlocked"]));
    assert_eq!(
        catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
    success(
        Command::new(env!("CARGO_BIN_EXE_archive"))
            .args(["--host", "fixture", "--archive"])
            .arg(temp.path().join("catalog"))
            .args(["collection", "add"])
            .arg(&root)
            .args(["--collection", "Files", "--location", "Primary"]),
    );
    let states = catalog.connection().prepare("SELECT o.relative_path_display,f.presence FROM objects o JOIN files f USING(object_id) WHERE f.location_id='primary' ORDER BY o.relative_path_display").unwrap().query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
    assert_eq!(
        states,
        vec![
            ("dropped-pointer".into(), "missing".into()),
            ("ordinary".into(), "present".into()),
            ("unlocked".into(), "present".into())
        ]
    );
}
