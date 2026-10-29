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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn json(command: &mut Command) -> Value {
    serde_json::from_slice(&success(command).stdout).unwrap()
}

#[test]
fn file_find_groups_match_backup_content_and_stream_lossless_paths() {
    use std::os::unix::ffi::OsStringExt;
    let temp = TempDir::new().unwrap();
    success(archive(&temp).args([
        "init",
        "Personal",
        "--archive-id",
        "arc_personal",
        "--non-interactive",
    ]));
    let source = temp.path().join("source");
    let backup = temp.path().join("backup");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&backup).unwrap();
    fs::write(source.join("backed.txt"), b"backed").unwrap();
    fs::write(source.join("new\nfile.txt"), b"new").unwrap();
    fs::write(
        source.join(std::ffi::OsString::from_vec(b"raw\xff.txt".to_vec())),
        b"raw",
    )
    .unwrap();
    fs::write(backup.join("renamed.txt"), b"backed").unwrap();
    success(archive(&temp).args([
        "collection",
        "init",
        source.to_str().unwrap(),
        "--name",
        "Files",
        "--device",
        "Test Device",
        "--site",
        "Home",
        "--allow-unidentified-root",
        "--non-interactive",
    ]));
    success(archive(&temp).args([
        "collection",
        "add",
        source.to_str().unwrap(),
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
        "Test Device",
        "--site",
        "Home",
        "--allow-unidentified-root",
        "--non-interactive",
    ]));
    success(archive(&temp).args([
        "location",
        "scan",
        "--path",
        backup.to_str().unwrap(),
        "--collection",
        "Files",
    ]));
    let locations = json(archive(&temp).args(["--json", "location", "list"]));
    let source_id = locations["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["display_name"] != "Backup")
        .unwrap()["location_id"]
        .as_str()
        .unwrap();
    let absent = json(archive(&temp).args([
        "--json",
        "file",
        "find",
        "--collection",
        "Files",
        "--in",
        source_id,
        "--and",
        "--not",
        "--in=Backup",
    ]));
    assert_eq!(absent["items"].as_array().unwrap().len(), 2);
    let streamed = success(archive(&temp).args([
        "file",
        "find",
        "--collection",
        "Files",
        "--in",
        source_id,
        "--and",
        "--not",
        "--in=Backup",
        "--print0",
        "--limit",
        "1",
    ]));
    let mut paths = streamed
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(
        paths,
        vec![b"new\nfile.txt".as_slice(), b"raw\xff.txt".as_slice()]
    );
    let backed = json(archive(&temp).args([
        "--json",
        "file",
        "find",
        "--collection",
        "Files",
        "--in",
        source_id,
        "--and",
        "--in=Backup",
        "--verified-within=30d",
    ]));
    assert_eq!(backed["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        backed["items"][0]["matching_sources"][0]["relative_path"]["text"],
        "backed.txt"
    );
    let alternatives = json(archive(&temp).args([
        "--json",
        "file",
        "find",
        "--collection",
        "Files",
        "--in",
        source_id,
        "--in=Backup",
    ]));
    assert_eq!(alternatives["items"].as_array().unwrap().len(), 4);
    assert_eq!(backed["selection_evidence"]["basis"], "catalog");
    assert_eq!(backed["selection_evidence"]["fresh_verification"], false);
    let repeated = json(archive(&temp).args([
        "--json",
        "file",
        "find",
        "--in",
        source_id,
        "--collection",
        "Files",
        "--verified-within=30d",
        "--and",
        "--not",
        "--in=Backup",
        "--verified-within=30d",
        "--and",
        "--not",
        "--in=Backup",
    ]));
    assert_eq!(repeated["items"].as_array().unwrap().len(), 2);
    let ambiguous = archive(&temp)
        .args(["file", "find", "--in", source_id, "--in=Backup", "--print0"])
        .output()
        .unwrap();
    assert_eq!(ambiguous.status.code(), Some(2));
    assert!(ambiguous.stdout.is_empty());
}

#[test]
fn file_find_rejects_malformed_groups_before_opening_archive() {
    let temp = TempDir::new().unwrap();
    for expression in [
        vec!["--and", "--in=A"],
        vec!["--in=A", "--and"],
        vec!["--in=A", "--not", "--in=B"],
        vec!["--not", "--not", "--in=A"],
        vec!["--verified-within=30d"],
        vec!["--in=A", "--verified-within=0d"],
        vec!["--in=A", "--verified-within=18446744073709551615w"],
        vec!["--in=A", "--verified-within=1d", "--verified-within=2d"],
    ] {
        let output = archive(&temp)
            .args(["--json", "file", "find"])
            .args(&expression)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{expression:?}");
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(
            error["error"]["code"], "invalid_input",
            "{expression:?}: {error}"
        );
    }
}
