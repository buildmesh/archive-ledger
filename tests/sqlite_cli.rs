#![cfg(unix)]
use serde_json::Value;
use std::{
    fs,
    process::{Command, Output},
};
use tempfile::TempDir;

fn archive(temp: &TempDir) -> Command {
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
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn json(command: &mut Command) -> Value {
    serde_json::from_slice(&success(command).stdout).unwrap()
}

#[test]
fn default_init_creates_authoritative_sqlite_without_git() {
    let temp = TempDir::new().unwrap();
    let empty_path = temp.path().join("empty-bin");
    fs::create_dir(&empty_path).unwrap();
    let initialized = json(archive(&temp).env("PATH", &empty_path).args([
        "--json",
        "init",
        "Personal",
        "--archive-id",
        "arc_personal",
        "--non-interactive",
    ]));
    assert_eq!(initialized["catalog_format"], "sqlite");
    let root = temp
        .path()
        .join("data/archive-ledger/archives/arc_personal");
    let catalog = archive_ledger::SqliteCatalog::open_read_only(root.join("archive.db")).unwrap();
    assert_eq!(catalog.metadata().unwrap().archive_id, "arc_personal");
    assert!(!root.join("canonical").exists());
    assert!(!root.join("local/clients").exists());
    let status = json(archive(&temp).args(["--json", "status"]));
    assert_eq!(status["catalog_format"], "sqlite");
}

#[test]
fn default_catalog_routes_inventory_groups_history_verify_and_copy() {
    let temp = TempDir::new().unwrap();
    success(archive(&temp).args([
        "init",
        "Personal",
        "--archive-id",
        "arc_personal",
        "--non-interactive",
    ]));
    let primary = temp.path().join("primary");
    let backup = temp.path().join("backup");
    fs::create_dir(&primary).unwrap();
    fs::create_dir(&backup).unwrap();
    fs::write(primary.join("one"), b"one").unwrap();
    fs::write(primary.join("two"), b"two").unwrap();
    fs::write(backup.join("one"), b"one").unwrap();
    fs::write(backup.join("renamed"), b"two").unwrap();
    success(archive(&temp).args([
        "collection",
        "init",
        primary.to_str().unwrap(),
        "--name",
        "Files",
        "--location-name",
        "Primary",
        "--device",
        "Disk",
        "--site",
        "Home",
        "--allow-unidentified-root",
        "--non-interactive",
    ]));
    success(archive(&temp).args([
        "collection",
        "add",
        primary.to_str().unwrap(),
        "--collection",
        "Files",
    ]));
    success(archive(&temp).args([
        "location",
        "init",
        backup.to_str().unwrap(),
        "--collection",
        "Files",
        "--location-name",
        "Backup",
        "--device",
        "Disk",
        "--site",
        "Home",
        "--allow-unidentified-root",
        "--non-interactive",
    ]));
    success(archive(&temp).args(["location", "scan", "Backup", "--collection", "Files"]));
    let absent = success(archive(&temp).args([
        "file",
        "find",
        "--collection",
        "Files",
        "--in",
        "Primary",
        "--and",
        "--not",
        "--in",
        "Backup",
        "--verified-within",
        "30d",
        "--print0",
    ]));
    assert_eq!(
        absent.stdout, b"two\0",
        "equal bytes at a different path do not back up this Object"
    );
    let all =
        success(archive(&temp).args(["file", "find", "--collection", "Files", "--limit", "1"]));
    assert_eq!(all.stdout, b"one\nrenamed\ntwo\n");
    let page = json(archive(&temp).args([
        "--json",
        "file",
        "find",
        "--collection",
        "Files",
        "--limit",
        "1",
    ]));
    assert_eq!(page["objects"].as_array().unwrap().len(), 1);
    assert!(page["next"].is_string());
    let id = page["objects"][0]["object_id"].as_str().unwrap();
    let shown = json(archive(&temp).args(["--json", "file", "show", id]));
    assert_eq!(shown["object_review"]["files"].as_array().unwrap().len(), 2);
    let history = json(archive(&temp).args(["--json", "file", "history", id]));
    assert!(history["items"].as_array().unwrap().len() >= 2);
    let verified = json(archive(&temp).args(["--json", "verify", "Backup", "--all"]));
    assert_eq!(verified["jobs"].as_array().unwrap().len(), 1);
    let dry = json(archive(&temp).current_dir(&primary).args([
        "--json",
        "copy",
        "--from",
        "Primary",
        "--to",
        "Backup",
        "--collection",
        "Files",
        "--dry-run",
    ]));
    assert_eq!(dry["selected"], 1);
    assert!(!backup.join("two").exists());
    success(archive(&temp).current_dir(&primary).args([
        "copy",
        "--from",
        "Primary",
        "--to",
        "Backup",
        "--collection",
        "Files",
        "--yes",
    ]));
    assert_eq!(fs::read(backup.join("two")).unwrap(), b"two");
    assert!(success(archive(&temp).args([
        "file",
        "find",
        "--collection",
        "Files",
        "--in",
        "Primary",
        "--and",
        "--not",
        "--in",
        "Backup"
    ]))
    .stdout
    .is_empty());
}
