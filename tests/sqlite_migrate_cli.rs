//! Migration CLI boundary: explicit destination, preserved source, no activation.
mod support;

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
fn explicit_migration_keeps_original_registered_and_does_not_activate_destination() {
    let temp = TempDir::new().unwrap();
    support::legacy_archive(temp.path(), "Legacy", "arc_legacy", false);
    let source = temp.path().join("data/archive-ledger/archives/arc_legacy");
    let destination = temp.path().join("converted");
    let registry = temp.path().join("config/archive-ledger/catalogs.json");
    let original_registry = fs::read(&registry).unwrap();
    let original_database = fs::read(source.join("archive.db")).unwrap();
    let original_genesis = fs::read(source.join("canonical/genesis.json")).unwrap();
    let report = json(
        command(&temp)
            .arg("--archive")
            .arg(&source)
            .args(["migrate", "--to"])
            .arg(&destination),
    );
    assert_eq!(report["activated"], false);
    assert_eq!(report["migration"]["archive_id"], "arc_legacy");
    assert_eq!(report["migration"]["objects"], 0);
    assert_eq!(report["migration"]["files"], 0);
    assert!(std::path::Path::new(report["migration"]["backup"].as_str().unwrap()).is_file());
    let status = json(
        command(&temp)
            .arg("--archive")
            .arg(&destination)
            .arg("status"),
    );
    assert_eq!(status["catalog_format"], "sqlite");
    assert_eq!(status["entity"]["archive_id"], "arc_legacy");
    assert_eq!(fs::read(&registry).unwrap(), original_registry);
    let registered: Value = serde_json::from_slice(&original_registry).unwrap();
    assert_eq!(registered["default_archive_id"], "arc_legacy");
    assert_eq!(registered["archives"][0]["root"], source.to_str().unwrap());
    let migrated_database = fs::read(destination.join("archive.db")).unwrap();
    let refused = command(&temp)
        .arg("--archive")
        .arg(&source)
        .args(["migrate", "--to"])
        .arg(&destination)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let error: Value = serde_json::from_slice(&refused.stderr).unwrap();
    assert_eq!(error["error"]["code"], "catalog_migration_failed");
    assert_eq!(
        fs::read(destination.join("archive.db")).unwrap(),
        migrated_database
    );
    assert_eq!(
        fs::read(source.join("archive.db")).unwrap(),
        original_database
    );
    assert_eq!(
        fs::read(source.join("canonical/genesis.json")).unwrap(),
        original_genesis
    );
    assert_eq!(fs::read(registry).unwrap(), original_registry);
}
