#![cfg(unix)]

use archive_ledger::SqliteCatalog;
use rusqlite::params;
use std::{
    ffi::OsString,
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{symlink, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

struct Fixture {
    temp: TempDir,
    catalog: SqliteCatalog,
    source: PathBuf,
}

impl Fixture {
    fn new(source_name: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let catalog_dir = temp.path().join("catalog");
        fs::create_dir(&catalog_dir).unwrap();
        let catalog = SqliteCatalog::create(catalog_dir.join("archive.db"), "arc", "Test").unwrap();
        catalog.connection().execute_batch("\
            INSERT INTO collections(collection_id,display_name,status) VALUES('collection','Files','active');
            INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('site','Home','home','active');
            INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,current_site_id,expected_availability) VALUES
                ('usb-device','USB disk','disk','unavailable','active','site','offline'),
                ('backup-device','Backup disk','disk','unavailable','active','site','offline');
            INSERT INTO archive_roots(archive_root_id,device_id,display_name,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status) VALUES
                ('usb-root','usb-device','USB root','unavailable',X'2f','utf8','/','active'),
                ('backup-root','backup-device','Backup root','unavailable',X'2f','utf8','/','active');
            INSERT INTO locations(location_id,display_name,kind,site_id,expected_availability,status)
                VALUES('unknown','Unknown device','service','site','offline','active');
        ").unwrap();
        for (id, name, root, device, relative) in [
            ("usb", "USB", "usb-root", "usb-device", source_name),
            ("same", "Same disk", "usb-root", "usb-device", "same"),
            ("backup", "Backup", "backup-root", "backup-device", "backup"),
            ("other", "Other", "backup-root", "backup-device", "other"),
        ] {
            // Host scripts are external even when registered Locations are read-only.
            catalog.connection().execute("INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,is_writable,status) VALUES(?1,?2,'filesystem',?3,?4,'utf8',?5,?6,'offline',0,'active')", params![id,name,root,relative.as_bytes(),relative,device]).unwrap();
        }
        catalog.connection().execute("INSERT INTO device_mounts(mount_id,device_id,archive_root_id,host_id,mount_root_uri,status,fingerprint_status,observed_time_utc_ms) VALUES('mount','usb-device','usb-root','fixture',?1,'mounted','unavailable',1)", [temp.path().to_str().unwrap()]).unwrap();
        let source = temp.path().join(source_name);
        fs::create_dir(&source).unwrap();
        Self {
            temp,
            catalog,
            source,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_archive"));
        command
            .env_remove("ARCHIVE_LEDGER_LOCATIONS_DIR")
            .env_remove("ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR")
            .env_remove("ARCHIVE_LEDGER_OUTPUT")
            .args(["--host", "fixture", "--archive"])
            .arg(self.temp.path().join("catalog"))
            .args(["file", "remove", "--host-script", "--from", "USB"]);
        command
    }

    fn object(&self, id: &str, path: &[u8], locations: &[&str]) {
        let encoding = if std::str::from_utf8(path).is_ok() {
            "utf8"
        } else {
            "unix_bytes"
        };
        let checksum = blake3::hash(b"payload");
        self.catalog.connection().execute("INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display,expected_blake3,expected_size_bytes) VALUES(?1,'collection',?2,?3,?4,?5,7)", params![id,encoding,path,String::from_utf8_lossy(path),checksum.as_bytes().as_slice()]).unwrap();
        for location in locations {
            self.catalog.connection().execute("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES(?1,?2,'present','verified',?3,'ok',?4,?3)", params![id,location,now_ms(),checksum.as_bytes().as_slice()]).unwrap();
        }
    }

    fn file(&self, id: &str, path: &[u8], locations: &[&str]) {
        let source = self.source.join(OsString::from_vec(path.to_vec()));
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(source, b"payload").unwrap();
        self.object(id, path, locations);
    }

    fn script(&self, command: &mut Command) -> PathBuf {
        let output = command.output().unwrap();
        assert_success(&output);
        assert!(output.stdout.starts_with(b"#!/usr/bin/env bash\n"));
        let path = self.temp.path().join("remove.sh");
        fs::write(&path, output.stdout).unwrap();
        path
    }

    fn run_script(&self, script: &Path, args: &[&str]) -> Output {
        Command::new("bash")
            .arg(script)
            .args(args)
            .current_dir(self.temp.path())
            .output()
            .unwrap()
    }

    fn data_version(&self) -> i64 {
        self.catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn manifest(generated: &str) -> &str {
    let template = include_str!("../src/host_remove_template.sh");
    let (header, rest) = template.split_once("# ARCHIVE_LEDGER_ROOTS\n").unwrap();
    let (middle, footer) = rest.split_once("# ARCHIVE_LEDGER_MANIFEST\n").unwrap();
    let (before_expiry, after_expiry) = footer.split_once("# ARCHIVE_LEDGER_EXPIRY\n").unwrap();
    assert!(generated.starts_with(header));
    let (data, rest) = generated
        .split_once(middle)
        .unwrap()
        .1
        .split_once(before_expiry)
        .unwrap();
    let expiry = rest.strip_suffix(after_expiry).unwrap();
    expiry
        .trim()
        .strip_prefix("evidence_expires_at=")
        .unwrap()
        .parse::<i64>()
        .unwrap();
    data
}

#[test]
fn selection_requires_recent_matching_backup_evidence_and_never_updates_catalog() {
    let f = Fixture::new("usb");
    for name in [
        "recent",
        "stale",
        "future",
        "missing",
        "damaged",
        "unverified",
        "wrong-hash",
        "no-hash",
        "unresolved",
        "target-missing",
        "target-damaged",
        "target-wrong-hash",
    ] {
        f.file(name, name.as_bytes(), &["usb", "backup"]);
    }
    f.file("other-only", b"other-only", &["usb", "other"]);
    f.file("no-backup", b"no-backup", &["usb"]);
    f.file("no-target", b"no-target", &["backup"]);
    f.catalog.connection().execute_batch("\
        UPDATE files SET last_success_time_utc_ms=1 WHERE object_id='stale' AND location_id='backup';
        UPDATE files SET presence='missing' WHERE object_id='missing' AND location_id='backup';
        UPDATE files SET integrity='damaged',last_check_result='mismatch' WHERE object_id='damaged' AND location_id='backup';
        UPDATE files SET integrity='unverified',last_success_time_utc_ms=NULL WHERE object_id='unverified' AND location_id='backup';
        UPDATE files SET observed_blake3=zeroblob(32) WHERE object_id='wrong-hash' AND location_id='backup';
        UPDATE files SET observed_blake3=NULL WHERE object_id='no-hash' AND location_id='backup';
        UPDATE objects SET expected_blake3=NULL WHERE object_id='unresolved';
        UPDATE files SET presence='missing' WHERE object_id='target-missing' AND location_id='usb';
        UPDATE files SET integrity='damaged',last_check_result='mismatch' WHERE object_id='target-damaged' AND location_id='usb';
        UPDATE files SET observed_blake3=zeroblob(32) WHERE object_id='target-wrong-hash' AND location_id='usb';
    ").unwrap();
    f.catalog.connection().execute("UPDATE files SET last_success_time_utc_ms=?1 WHERE object_id='future' AND location_id='backup'", [now_ms() + 86_400_000]).unwrap();
    let version = f.data_version();
    let metadata = f.catalog.metadata().unwrap();
    let script =
        f.script(
            f.command()
                .args(["--collection", "Files", "--in", "Backup", "--in", "Other"]),
        );
    let generated = fs::read_to_string(&script).unwrap();
    let selected: Vec<_> = manifest(&generated)
        .lines()
        .map(|line| line.split_once('\t').unwrap().1)
        .collect();
    assert_eq!(selected.len(), 2, "{selected:?}");
    assert!(selected.contains(&"recent"));
    assert!(selected.contains(&"other-only"));
    assert_success(&f.run_script(&script, &[]));
    assert_success(&f.run_script(&script, &["--dry-run"]));
    assert_eq!(fs::read_dir(&f.source).unwrap().count(), 15);
    assert_success(&f.run_script(&script, &["--delete"]));
    assert!(!f.source.join("recent").exists());
    assert!(!f.source.join("other-only").exists());
    assert_eq!(fs::read_dir(&f.source).unwrap().count(), 13);
    assert_eq!(f.catalog.metadata().unwrap(), metadata);
    assert_eq!(f.data_version(), version);
    let presence: String = f
        .catalog
        .connection()
        .query_row(
            "SELECT presence FROM files WHERE object_id='recent' AND location_id='usb'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        presence, "present",
        "physical deletion requires a later Location scan"
    );
}

#[test]
fn verification_window_can_be_explicitly_extended() {
    let f = Fixture::new("usb");
    f.file("older", b"older", &["usb", "backup"]);
    f.catalog
        .connection()
        .execute(
            "UPDATE files SET last_success_time_utc_ms=?1 WHERE location_id='backup'",
            [now_ms() - 60 * 86_400_000],
        )
        .unwrap();
    let script = f.script(f.command().args(["--in", "Backup"]));
    assert_success(&f.run_script(&script, &["--delete"]));
    assert!(f.source.join("older").exists());
    let script = f.script(
        f.command()
            .args(["--in", "Backup", "--verified-within", "90d"]),
    );
    assert_success(&f.run_script(&script, &["--delete"]));
    assert!(!f.source.join("older").exists());
}

#[test]
fn every_named_backup_must_have_a_known_different_device() {
    let f = Fixture::new("usb");
    f.file("file", b"file", &["usb", "backup", "same", "unknown"]);
    for invalid in ["USB", "Same disk", "Unknown device"] {
        for backups in [
            vec!["--in", invalid],
            vec!["--in", "Backup", "--in", invalid],
        ] {
            let output = f.command().args(backups).output().unwrap();
            assert!(!output.status.success(), "accepted backup {invalid}");
            let partial = f.temp.path().join("partial.sh");
            fs::write(&partial, output.stdout).unwrap();
            let _ = f.run_script(&partial, &["--delete"]);
            assert_eq!(fs::read(f.source.join("file")).unwrap(), b"payload");
        }
    }
}

#[test]
fn readable_manifest_and_shell_escaping_preserve_every_filename_byte() {
    let f = Fixture::new("usb ' $(touch ROOT_INJECTED) `touch ROOT_TICKED`\nend");
    let paths = [
        b"space and 'quotes\".txt".to_vec(),
        b"line\nbreak".to_vec(),
        b"$(touch FILE_INJECTED)".to_vec(),
        b"`touch FILE_TICKED`".to_vec(),
        b"-leading-option".to_vec(),
        b"raw-\xff-name".to_vec(),
        b"nested/file".to_vec(),
        b"$(touch PARENT_INJECTED)/file".to_vec(),
        b"ARCHIVE_LEDGER_PATHS".to_vec(),
        b"ARCHIVE_LEDGER_PATHS\ntouch HEREDOC_INJECTED\n#".to_vec(),
        b"literal-\\n-\\c-\\0377-\\".to_vec(),
        b"tabs\tand\rcarriage\x1bescape".to_vec(),
        "caf\u{e9}.txt".as_bytes().to_vec(),
        (1..=255).filter(|byte| *byte != b'/').collect(),
    ];
    for (i, path) in paths.iter().enumerate() {
        f.file(&format!("file-{i}"), path, &["usb", "backup"]);
    }
    let script = f.script(f.command().args(["--in", "Backup"]));
    let generated = fs::read_to_string(&script).unwrap();
    let data = manifest(&generated);
    let paths_in_script: Vec<_> = data
        .lines()
        .map(|line| {
            let (checksum, path) = line.split_once('\t').unwrap();
            assert_eq!(checksum, blake3::hash(b"payload").to_hex().as_str());
            path
        })
        .collect();
    assert!(paths_in_script.contains(&"nested/file"));
    assert!(paths_in_script.contains(&"space and 'quotes\".txt"));
    assert!(paths_in_script.contains(&r"line\nbreak"));
    assert!(paths_in_script.contains(&r"literal-\\n-\\c-\\0377-\\"));
    assert_success(
        &Command::new("bash")
            .arg("-n")
            .arg(&script)
            .output()
            .unwrap(),
    );
    assert_success(&f.run_script(&script, &[]));
    assert_success(&f.run_script(&script, &["--dry-run"]));
    for path in &paths {
        assert!(f.source.join(OsString::from_vec(path.clone())).exists());
    }
    assert_success(&f.run_script(&script, &["--delete"]));
    for path in paths {
        assert!(!f.source.join(OsString::from_vec(path)).exists());
    }
    for marker in [
        "ROOT_INJECTED",
        "ROOT_TICKED",
        "FILE_INJECTED",
        "FILE_TICKED",
        "PARENT_INJECTED",
        "HEREDOC_INJECTED",
    ] {
        assert!(
            !f.temp.path().join(marker).exists(),
            "shell executed filename/root: {marker}"
        );
    }
}

#[test]
fn runtime_checksum_preserves_changed_and_unselected_files() {
    let f = Fixture::new("usb");
    f.file("changed", b"changed", &["usb", "backup"]);
    f.file("selected", b"selected", &["usb", "backup"]);
    f.file("missing", b"missing", &["usb", "backup"]);
    fs::write(f.source.join("untracked"), b"original untracked").unwrap();
    let script = f.script(f.command().args(["--in", "Backup"]));
    fs::write(f.source.join("changed"), b"changed after generation").unwrap();
    fs::remove_file(f.source.join("missing")).unwrap();
    assert!(!f.run_script(&script, &["--delete"]).status.success());
    assert_eq!(
        fs::read(f.source.join("changed")).unwrap(),
        b"changed after generation"
    );
    assert_eq!(
        fs::read(f.source.join("untracked")).unwrap(),
        b"original untracked"
    );
    assert_eq!(fs::read(f.source.join("selected")).unwrap(), b"payload");
    assert!(!f.source.join("missing").exists());
}

#[test]
fn expired_backup_evidence_refuses_every_deletion() {
    let f = Fixture::new("usb");
    f.file("file", b"file", &["usb", "backup"]);
    let script = f.script(f.command().args(["--in", "Backup"]));
    let generated = fs::read_to_string(&script).unwrap();
    let assignment = generated
        .lines()
        .find(|line| line.starts_with("evidence_expires_at="))
        .unwrap();
    fs::write(
        &script,
        generated.replacen(assignment, "evidence_expires_at=1", 1),
    )
    .unwrap();
    assert_success(&f.run_script(&script, &["--dry-run"]));
    let output = f.run_script(&script, &["--delete"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expired"));
    assert_eq!(fs::read(f.source.join("file")).unwrap(), b"payload");
}

#[test]
fn final_symlink_removal_preserves_its_target_and_missing_paths_skip_safely() {
    let f = Fixture::new("usb");
    let target = f.temp.path().join("annex-content");
    fs::write(&target, b"payload").unwrap();
    symlink(&target, f.source.join("annex-link")).unwrap();
    f.object("link", b"annex-link", &["usb", "backup"]);
    f.object("missing", b"missing", &["usb", "backup"]);
    let script = f.script(f.command().args(["--in", "Backup"]));
    assert_success(&f.run_script(&script, &["--delete"]));
    assert!(fs::symlink_metadata(f.source.join("annex-link")).is_err());
    assert_eq!(fs::read(target).unwrap(), b"payload");
}

#[test]
fn symlink_ancestors_and_directories_are_refused() {
    for root_symlink in [false, true] {
        let f = Fixture::new("usb");
        f.file("file", b"sub/file", &["usb", "backup"]);
        let script = f.script(f.command().args(["--in", "Backup"]));
        let outside = f.temp.path().join("outside");
        let replaced = if root_symlink {
            f.source.clone()
        } else {
            f.source.join("sub")
        };
        fs::rename(&replaced, &outside).unwrap();
        symlink(&outside, &replaced).unwrap();
        assert!(!f.run_script(&script, &["--delete"]).status.success());
        let protected = if root_symlink {
            outside.join("sub/file")
        } else {
            outside.join("file")
        };
        assert_eq!(fs::read(protected).unwrap(), b"payload");
    }
    let f = Fixture::new("usb");
    f.object("directory", b"directory", &["usb", "backup"]);
    fs::create_dir(f.source.join("directory")).unwrap();
    fs::write(f.source.join("directory/child"), b"preserved").unwrap();
    let script = f.script(f.command().args(["--in", "Backup"]));
    assert!(!f.run_script(&script, &["--delete"]).status.success());
    assert_eq!(
        fs::read(f.source.join("directory/child")).unwrap(),
        b"preserved"
    );
}

#[test]
fn mapped_roots_support_offline_generation_and_component_boundaries() {
    let f = Fixture::new("usb");
    f.file("file", b"file", &["usb", "backup"]);
    f.catalog
        .connection()
        .execute("UPDATE device_mounts SET mount_root_uri='/locations'", [])
        .unwrap();
    let unavailable = f.temp.path().join("unavailable");
    fs::rename(&f.source, &unavailable).unwrap();
    let script = f.script(
        f.command()
            .env("ARCHIVE_LEDGER_LOCATIONS_DIR", "/wrong-host-root")
            .env(
                "ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR",
                "/wrong-container-root",
            )
            .args(["--in", "Backup", "--host-root"])
            .arg(f.temp.path())
            .args(["--locations-root", "/locations"]),
    );
    fs::rename(unavailable, &f.source).unwrap();
    assert_success(&f.run_script(&script, &["--delete"]));
    assert!(!f.source.join("file").exists());
    let output = f
        .command()
        .args(["--in", "Backup"])
        .env("ARCHIVE_LEDGER_LOCATIONS_DIR", f.temp.path())
        .env("ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR", "/locations")
        .output()
        .unwrap();
    assert_success(&output);
    f.catalog
        .connection()
        .execute("UPDATE device_mounts SET mount_root_uri='/locations2'", [])
        .unwrap();
    let output = f
        .command()
        .args(["--in", "Backup", "--host-root"])
        .arg(f.temp.path())
        .args(["--locations-root", "/locations"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "lexical prefixes are not path components"
    );
}

#[test]
fn empty_and_incomplete_manifests_never_delete_unlisted_files() {
    let f = Fixture::new("usb");
    fs::write(f.source.join("untracked"), b"preserved").unwrap();
    let empty = f.script(f.command().args(["--in", "Backup"]));
    assert_success(&f.run_script(&empty, &["--delete"]));
    assert_eq!(fs::read(f.source.join("untracked")).unwrap(), b"preserved");
    f.file("file", b"file", &["usb", "backup"]);
    let script = f.script(f.command().args(["--in", "Backup"]));
    let generated = fs::read_to_string(&script).unwrap();
    let data = manifest(&generated);
    let end_of_data = generated.find(data).unwrap() + data.len();
    let truncated = f.temp.path().join("truncated.sh");
    fs::write(&truncated, &generated[..end_of_data]).unwrap();
    assert!(!f.run_script(&truncated, &["--delete"]).status.success());
    assert_eq!(fs::read(f.source.join("file")).unwrap(), b"payload");
}

#[test]
fn invalid_paths_and_conflicting_cli_options_fail_without_deletion() {
    for invalid in [
        b"../escape".as_slice(),
        b"/absolute",
        b"nested/../escape",
        b"nul\0name",
    ] {
        let f = Fixture::new("usb");
        f.file("valid", b"aaa-valid", &["usb", "backup"]);
        f.object("bad", invalid, &["usb", "backup"]);
        let output = f.command().args(["--in", "Backup"]).output().unwrap();
        assert!(
            !output.status.success(),
            "accepted invalid path: {invalid:?}"
        );
        let partial = f.temp.path().join("partial.sh");
        fs::write(&partial, output.stdout).unwrap();
        let _ = f.run_script(&partial, &["--delete"]);
        assert_eq!(fs::read(f.source.join("aaa-valid")).unwrap(), b"payload");
    }
    let f = Fixture::new("usb");
    for extra in [
        vec!["--json"],
        vec!["--yes"],
        vec!["--dry-run"],
        vec!["--delete"],
        vec!["some/path"],
        vec!["--and", "--in", "Other"],
        vec!["--not", "--in", "Other"],
        vec!["--verified-within", "nonsense"],
    ] {
        assert!(!f
            .command()
            .args(["--in", "Backup"])
            .args(extra)
            .output()
            .unwrap()
            .status
            .success());
    }
    assert!(
        !f.command().output().unwrap().status.success(),
        "at least one backup must be named"
    );
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_archive"))
            .args(["file", "remove", "--from", "USB", "--in", "Backup"])
            .output()
            .unwrap()
            .status
            .success(),
        "host-script mode must be explicit"
    );
    f.file("file", b"file", &["usb", "backup"]);
    let script = f.script(f.command().args(["--in", "Backup"]));
    for args in [
        vec!["--yes"],
        vec!["--delete", "--dry-run"],
        vec!["--delete", "--delete"],
    ] {
        assert!(!f.run_script(&script, &args).status.success());
        assert_eq!(fs::read(f.source.join("file")).unwrap(), b"payload");
    }
}

#[test]
fn expiry_uses_newest_backup_per_file_and_first_deadline_across_files() {
    let f = Fixture::new("usb");
    let now = now_ms();
    f.object("first", b"first", &["usb", "backup", "other"]);
    f.object("second", b"second", &["usb", "backup", "other"]);
    for (object, location, days) in [
        ("first", "backup", 20),
        ("first", "other", 5),
        ("second", "backup", 10),
        ("second", "other", 2),
    ] {
        f.catalog.connection().execute(
            "UPDATE files SET last_success_time_utc_ms=?1 WHERE object_id=?2 AND location_id=?3",
            params![now - days * 86_400_000, object, location],
        ).unwrap();
    }
    let script = f.script(f.command().args(["--in", "Backup", "--in", "Other"]));
    let generated = fs::read_to_string(script).unwrap();
    assert!(generated
        .lines()
        .any(|line| line == format!("evidence_expires_at={}", (now + 25 * 86_400_000) / 1000)));
}

#[test]
fn removal_manifest_streams_beyond_page_limits() {
    let f = Fixture::new("usb");
    f.catalog.connection().execute_batch("BEGIN").unwrap();
    for i in 0..1001 {
        f.object(
            &format!("object-{i}"),
            format!("file-{i}").as_bytes(),
            &["usb", "backup"],
        );
    }
    f.catalog.connection().execute_batch("COMMIT").unwrap();
    let script = f.script(f.command().args(["--in", "Backup"]));
    assert_eq!(
        manifest(&fs::read_to_string(script).unwrap())
            .lines()
            .count(),
        1001
    );
}

#[test]
fn unavailable_or_malformed_host_time_never_bypasses_expiry() {
    let f = Fixture::new("usb");
    f.file("file", b"file", &["usb", "backup"]);
    let script = f.script(f.command().args(["--in", "Backup"]));
    let generated = fs::read_to_string(&script).unwrap();
    let expiry = generated
        .lines()
        .find(|line| line.starts_with("evidence_expires_at="))
        .unwrap();
    fs::write(
        &script,
        generated.replacen(expiry, "evidence_expires_at=1", 1),
    )
    .unwrap();
    let bin = f.temp.path().join("clock-bin");
    fs::create_dir(&bin).unwrap();
    let date = bin.join("date");
    let mut paths = vec![bin];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let path = std::env::join_paths(paths).unwrap();
    for clock in [
        "exit 1",
        "printf 'nonnumeric\\n'",
        "exit 0",
        "printf '999999999999999999999999\\n'",
        "printf '08\\n'",
    ] {
        fs::write(&date, format!("#!/bin/sh\n{clock}\n")).unwrap();
        fs::set_permissions(&date, fs::Permissions::from_mode(0o755)).unwrap();
        let output = Command::new("bash")
            .arg(&script)
            .arg("--delete")
            .env("PATH", &path)
            .output()
            .unwrap();
        assert!(!output.status.success(), "accepted clock: {clock}");
        assert_eq!(fs::read(f.source.join("file")).unwrap(), b"payload");
    }
}
