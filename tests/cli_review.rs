use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn archive(temp: &TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_archive"));
    command
        .arg("--database")
        .arg(temp.path().join("archive.db"))
        .arg("--events")
        .arg(temp.path().join("canonical"));
    command
}

#[test]
fn empty_archive_cli_has_human_and_stable_json_workflows() {
    let temp = TempDir::new().unwrap();
    let initialized = archive(&temp)
        .args(["--json", "init", "--archive-id", "arc_cli_fixture"])
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let output: Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(output["archive_id"], "arc_cli_fixture");
    assert_eq!(output["applied_event_seq"], 1);

    let added = archive(&temp)
        .args([
            "site",
            "add",
            "--id",
            "site_home",
            "--name",
            "Home",
            "--kind",
            "home",
        ])
        .output()
        .unwrap();
    assert!(added.status.success());
    assert!(String::from_utf8(added.stdout)
        .unwrap()
        .contains("SQLite is current through 2"));

    let listed = archive(&temp)
        .args(["--json", "site", "list"])
        .output()
        .unwrap();
    assert!(listed.status.success());
    let output: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(output["version"], 1);
    assert_eq!(output["items"][0]["display_name"], "Home");

    let json_add = archive(&temp)
        .args([
            "--json",
            "site",
            "add",
            "--id",
            "site_remote",
            "--name",
            "Remote",
            "--kind",
            "office",
        ])
        .output()
        .unwrap();
    assert!(json_add.status.success());
    let output: Value = serde_json::from_slice(&json_add.stdout).unwrap();
    assert_eq!(output["version"], 1);

    let duplicate = archive(&temp)
        .args([
            "--json",
            "site",
            "add",
            "--id",
            "site_home",
            "--name",
            "Home",
            "--kind",
            "home",
        ])
        .output()
        .unwrap();
    assert_eq!(duplicate.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&duplicate.stderr).unwrap();
    assert_eq!(error["error"]["code"], "already_exists");

    let malformed = archive(&temp)
        .args(["--json", "site", "update", "--snapshot", "{"])
        .output()
        .unwrap();
    assert_eq!(malformed.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&malformed.stderr).unwrap();
    assert_eq!(error["error"]["code"], "invalid_input");

    let checkpoint = archive(&temp)
        .args(["--json", "checkpoint"])
        .output()
        .unwrap();
    assert!(checkpoint.status.success());
    let checkpoint_output: Value = serde_json::from_slice(&checkpoint.stdout).unwrap();
    assert_eq!(checkpoint_output["version"], 1);
    assert!(checkpoint_output["local_git_commit"].as_str().is_some());

    let verified = Command::new(env!("CARGO_BIN_EXE_archive"))
        .arg("--database")
        .arg(temp.path().join("database-does-not-exist.db"))
        .arg("--events")
        .arg(temp.path().join("canonical"))
        .args(["--json", "events", "verify"])
        .output()
        .unwrap();
    assert!(verified.status.success());
    let output: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert!(output["last_seq"].as_u64().unwrap() > 0);

    let rebuilt = temp.path().join("clean-restore.db");
    let restored = Command::new(env!("CARGO_BIN_EXE_archive"))
        .args(["--json", "restore", "check"])
        .arg(temp.path().join("canonical"))
        .arg("--rebuild-database")
        .arg(&rebuilt)
        .output()
        .unwrap();
    assert!(restored.status.success());
    let output: Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(output["archive_id"], "arc_cli_fixture");
    assert_eq!(output["verified_event_seq"], output["rebuilt_event_seq"]);

    let empty_files = archive(&temp)
        .args(["--json", "file", "find", "--limit", "10"])
        .output()
        .unwrap();
    assert!(empty_files.status.success());
    let output: Value = serde_json::from_slice(&empty_files.stdout).unwrap();
    assert_eq!(output["version"], 1);
    assert!(output["items"].as_array().unwrap().is_empty());

    std::fs::rename(
        temp.path().join("canonical"),
        temp.path().join("canonical-unavailable"),
    )
    .unwrap();
    let cached_report = archive(&temp)
        .args(["--json", "report", "risk", "--limit", "10"])
        .output()
        .unwrap();
    assert!(cached_report.status.success());
    let output: Value = serde_json::from_slice(&cached_report.stdout).unwrap();
    assert_eq!(output["version"], 1);
    assert!(output["findings"]["items"].as_array().unwrap().is_empty());

    let invalid_result = archive(&temp)
        .args(["--json", "report", "integrity", "--result", "healthy"])
        .output()
        .unwrap();
    assert_eq!(invalid_result.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&invalid_result.stderr).unwrap();
    assert_eq!(error["error"]["code"], "policy_invalid_state");

    let refused_rebuild = archive(&temp)
        .args(["--json", "db", "rebuild"])
        .output()
        .unwrap();
    assert_eq!(refused_rebuild.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&refused_rebuild.stderr).unwrap();
    assert_eq!(error["error"]["code"], "invalid_input");
    assert!(temp.path().join("archive.db").is_file());
}
