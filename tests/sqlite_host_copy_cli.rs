#![cfg(unix)]

use archive_ledger::SqliteCatalog;
use rusqlite::params;
use std::{
    ffi::OsString,
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

struct Fixture {
    temp: TempDir,
    catalog: SqliteCatalog,
    source: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new(source_name: &str, destination_name: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let catalog_dir = temp.path().join("catalog");
        fs::create_dir(&catalog_dir).unwrap();
        let catalog = SqliteCatalog::create(catalog_dir.join("archive.db"), "arc", "Test").unwrap();
        catalog.connection().execute_batch("INSERT INTO collections(collection_id,display_name,status) VALUES('collection','Files','active');
            INSERT INTO sites(site_id,display_name,site_kind,status) VALUES('site','Home','home','active');
            INSERT INTO devices(device_id,display_name,device_kind,identity_state,status,current_site_id,expected_availability) VALUES('device','Disk','disk','unavailable','active','site','offline');
            INSERT INTO archive_roots(archive_root_id,device_id,display_name,identity_state,root_path_on_device_bytes,root_path_encoding,root_path_display,status) VALUES('root','device','Root','unavailable',X'2f','utf8','/','active');").unwrap();
        for (id, name, relative) in [
            ("source", "Source", source_name),
            ("destination", "Destination", destination_name),
            ("backup", "Backup", "backup"),
            ("other", "Other", "other"),
            ("extra", "Extra", "extra"),
        ] {
            // Even the destination is registered read-only; the host script is external.
            catalog.connection().execute("INSERT INTO locations(location_id,display_name,kind,archive_root_id,relative_path_bytes,relative_path_encoding,relative_path_display,device_id,expected_availability,is_writable,status) VALUES(?1,?2,'filesystem','root',?3,'utf8',?4,'device','offline',0,'active')", params![id,name,relative.as_bytes(),relative]).unwrap();
        }
        catalog.connection().execute("INSERT INTO device_mounts(mount_id,device_id,archive_root_id,host_id,mount_root_uri,status,fingerprint_status,observed_time_utc_ms) VALUES('mount','device','root','fixture',?1,'mounted','unavailable',1)", [temp.path().to_str().unwrap()]).unwrap();
        let source = temp.path().join(source_name);
        let destination = temp.path().join(destination_name);
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        Self {
            temp,
            catalog,
            source,
            destination,
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
            .args([
                "copy",
                "--from",
                "Source",
                "--to",
                "Destination",
                "--host-script",
            ]);
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        for location in locations {
            self.catalog.connection().execute("INSERT INTO files(object_id,location_id,presence,integrity,last_check_time_utc_ms,last_check_result,observed_blake3,last_success_time_utc_ms) VALUES(?1,?2,'present','verified',?3,'ok',?4,?3)", params![id,location,now,checksum.as_bytes().as_slice()]).unwrap();
        }
    }

    fn file(&self, id: &str, path: &[u8], locations: &[&str]) {
        let source = self.source.join(OsString::from_vec(path.to_vec()));
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(source, b"payload").unwrap();
        self.object(id, path, locations);
    }

    fn script(&self, command: &mut Command) -> PathBuf {
        let output = success(command);
        assert!(output.stdout.starts_with(b"#!/usr/bin/env bash\n"));
        let path = self.temp.path().join("copy.sh");
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
}

fn success(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert_success(&output);
    output
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn selection_is_read_only_and_cannot_be_widened_beyond_source() {
    let f = Fixture::new("source", "destination");
    f.file("keep", b"nested/keep", &["source"]);
    f.file("backed", b"backed", &["source", "backup"]);
    f.file("other", b"other", &["source", "other"]);
    f.file("outside", b"outside", &["extra"]);
    f.file("damaged", b"damaged", &["source"]);
    f.catalog.connection().execute("UPDATE files SET integrity='damaged',last_check_result='mismatch' WHERE object_id='damaged'", []).unwrap();
    let version: i64 = f
        .catalog
        .connection()
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let metadata = f.catalog.metadata().unwrap();
    let database = f.temp.path().join("catalog/archive.db");
    fs::set_permissions(&database, fs::Permissions::from_mode(0o444)).unwrap();
    let script = f.script(
        f.command()
            .args(["--not", "--in", "Backup", "--in", "Other"]),
    );
    assert_success(&f.run_script(&script, &["--dry-run"]));
    assert_eq!(fs::read_dir(&f.destination).unwrap().count(), 0);
    assert_success(&f.run_script(&script, &[]));
    assert_eq!(
        fs::read(f.destination.join("nested/keep")).unwrap(),
        b"payload"
    );
    for excluded in ["backed", "other", "outside", "damaged"] {
        assert!(
            !f.destination.join(excluded).exists(),
            "unexpected copy: {excluded}"
        );
    }
    let script = f.script(f.command().args([
        "--in", "Source", "--in", "Extra", "--and", "--not", "--in", "Backup", "--in", "Other",
    ]));
    assert_success(&f.run_script(&script, &[]));
    assert!(!f.destination.join("outside").exists());
    // A stale backup no longer satisfies a group requiring recent verification.
    // Source verification remains current, so the source file can now be copied.
    fs::set_permissions(&database, fs::Permissions::from_mode(0o644)).unwrap();
    f.catalog.connection().execute("UPDATE files SET last_success_time_utc_ms=1 WHERE object_id='backed' AND location_id='backup'", []).unwrap();
    let script = f.script(f.command().args([
        "--not",
        "--in",
        "Backup",
        "--in",
        "Other",
        "--verified-within",
        "30d",
    ]));
    assert_success(&f.run_script(&script, &[]));
    assert_eq!(fs::read(f.destination.join("backed")).unwrap(), b"payload");
    assert_eq!(f.catalog.metadata().unwrap(), metadata);
    assert_eq!(
        f.catalog
            .connection()
            .query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        version
    );
    let destination_claims: i64 = f
        .catalog
        .connection()
        .query_row(
            "SELECT count(*) FROM files WHERE location_id='destination'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(destination_claims, 0);
    fs::set_permissions(database, fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn filenames_and_roots_are_data_and_existing_destinations_are_preserved() {
    let f = Fixture::new(
        "source ' $(touch ROOT_INJECTED) `touch ROOT_TICKED`\nend",
        "destination ' $(touch DEST_INJECTED)",
    );
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
        // Exercise every possible non-NUL, non-separator filename byte through Bash.
        (1..=255).filter(|byte| *byte != b'/').collect(),
    ];
    for (i, path) in paths.iter().enumerate() {
        f.file(&format!("file-{i}"), path, &["source"]);
    }
    f.file("existing", b"existing", &["source"]);
    fs::write(f.destination.join("existing"), b"original destination").unwrap();
    f.file("existing-link", b"existing-link", &["source"]);
    let outside_existing = f.temp.path().join("outside-existing");
    fs::write(&outside_existing, b"original link target").unwrap();
    std::os::unix::fs::symlink(&outside_existing, f.destination.join("existing-link")).unwrap();
    fs::write(f.source.join("annex-content"), b"payload").unwrap();
    std::os::unix::fs::symlink("annex-content", f.source.join("annex-link")).unwrap();
    f.object("symlink", b"annex-link", &["source"]);
    let script = f.script(&mut f.command());
    let generated = fs::read_to_string(&script).unwrap();
    let manifest = generated
        .split_once("<<'ARCHIVE_LEDGER_PATHS'\n")
        .unwrap()
        .1
        .split_once("\nARCHIVE_LEDGER_PATHS\n")
        .unwrap()
        .0;
    assert!(manifest.lines().any(|line| line == "nested/file"));
    assert!(manifest
        .lines()
        .any(|line| line == "space and 'quotes\".txt"));
    assert!(manifest.lines().any(|line| line == r"line\nbreak"));
    assert!(manifest
        .lines()
        .any(|line| line == r"\0101RCHIVE_LEDGER_PATHS"));
    assert!(manifest
        .lines()
        .any(|line| line == r"literal-\\n-\\c-\\0377-\\"));
    // Only the two root assignments and the manifest data may vary from the
    // reviewed static template; no filename contributes executable shell logic.
    let template = include_str!("../src/host_copy_template.sh");
    let (header, rest) = template.split_once("# ARCHIVE_LEDGER_ROOTS\n").unwrap();
    let (middle, footer) = rest.split_once("# ARCHIVE_LEDGER_MANIFEST\n").unwrap();
    assert!(generated.starts_with(header));
    let after_roots = generated.split_once(middle).unwrap().1;
    assert_eq!(after_roots, format!("{manifest}\n{footer}"));
    assert_success(
        &Command::new("bash")
            .arg("-n")
            .arg(&script)
            .output()
            .unwrap(),
    );
    assert!(!f.run_script(&script, &["--delete"]).status.success());
    assert_eq!(fs::read_dir(&f.destination).unwrap().count(), 2);
    assert_success(&f.run_script(&script, &[]));
    for path in paths {
        assert_eq!(
            fs::read(f.destination.join(OsString::from_vec(path))).unwrap(),
            b"payload"
        );
    }
    assert_eq!(
        fs::read(f.destination.join("existing")).unwrap(),
        b"original destination"
    );
    assert_eq!(
        fs::read(&outside_existing).unwrap(),
        b"original link target"
    );
    assert!(fs::symlink_metadata(f.destination.join("existing-link"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read(f.destination.join("annex-link")).unwrap(),
        b"payload"
    );
    assert!(!fs::symlink_metadata(f.destination.join("annex-link"))
        .unwrap()
        .file_type()
        .is_symlink());
    for marker in [
        "ROOT_INJECTED",
        "ROOT_TICKED",
        "DEST_INJECTED",
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
fn mapped_roots_need_no_container_mount_and_match_path_components() {
    let f = Fixture::new("source", "destination");
    f.file("file", b"file", &["source"]);
    f.catalog
        .connection()
        .execute("UPDATE device_mounts SET mount_root_uri='/locations'", [])
        .unwrap();
    let mut command = f.command();
    command
        .env("ARCHIVE_LEDGER_LOCATIONS_DIR", "/wrong-host-root")
        .env(
            "ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR",
            "/wrong-container-root",
        )
        .arg("--host-root")
        .arg(f.temp.path())
        .args(["--locations-root", "/locations"]);
    let script = f.script(&mut command);
    assert_success(&f.run_script(&script, &[]));
    assert_eq!(fs::read(f.destination.join("file")).unwrap(), b"payload");
    let mut from_environment = f.command();
    from_environment
        .env("ARCHIVE_LEDGER_LOCATIONS_DIR", f.temp.path())
        .env("ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR", "/locations");
    assert_success(&from_environment.output().unwrap());
    f.catalog
        .connection()
        .execute("UPDATE device_mounts SET mount_root_uri='/locations2'", [])
        .unwrap();
    let output = f
        .command()
        .arg("--host-root")
        .arg(f.temp.path())
        .args(["--locations-root", "/locations"])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a lexical prefix must not count as a mapped path component"
    );
}

#[test]
fn scripts_cover_all_matches_and_handle_no_matches() {
    let f = Fixture::new("source", "destination");
    f.catalog.connection().execute_batch("BEGIN").unwrap();
    for n in 0..1001 {
        f.file(
            &format!("object-{n}"),
            format!("file-{n}").as_bytes(),
            &["source"],
        );
    }
    f.catalog.connection().execute_batch("COMMIT").unwrap();
    let script = f.script(&mut f.command());
    assert_success(&f.run_script(&script, &[]));
    assert_eq!(fs::read_dir(&f.destination).unwrap().count(), 1001);
    fs::write(f.source.join("untracked"), b"must not copy").unwrap();
    let script = f.script(f.command().args(["--not", "--in", "Source"]));
    assert_success(&f.run_script(&script, &[]));
    assert_eq!(fs::read_dir(&f.destination).unwrap().count(), 1001);
    assert!(!f.destination.join("untracked").exists());
}

#[test]
fn destination_ancestor_symlinks_cannot_escape_the_selected_root() {
    let f = Fixture::new("source", "destination");
    f.file("file", b"sub/file", &["source"]);
    let outside = f.temp.path().join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, f.destination.join("sub")).unwrap();
    let script = f.script(&mut f.command());
    let output = f.run_script(&script, &[]);
    assert!(!output.status.success());
    assert!(!outside.join("file").exists());
    assert!(fs::symlink_metadata(f.destination.join("sub"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn invalid_manifest_paths_and_conflicting_cli_options_are_rejected() {
    for invalid in [
        b"../escape".as_slice(),
        b"/absolute",
        b"nested/../escape",
        b"nul\0name",
    ] {
        let f = Fixture::new("source", "destination");
        f.file("valid", b"aaa-valid", &["source"]);
        f.object("bad", invalid, &["source"]);
        let output = f.command().output().unwrap();
        assert!(
            !output.status.success(),
            "accepted invalid path: {invalid:?}"
        );
        // An incomplete script emitted before validation failed must not copy anything.
        let script = f.temp.path().join("partial.sh");
        fs::write(&script, output.stdout).unwrap();
        let _ = f.run_script(&script, &[]);
        assert_eq!(fs::read_dir(&f.destination).unwrap().count(), 0);
        assert!(!f.temp.path().join("escape").exists());
    }
    let f = Fixture::new("source", "destination");
    for extra in [
        vec!["--json"],
        vec!["--yes"],
        vec!["--dry-run"],
        vec!["some/path"],
        vec!["--and", "--in", "Backup"],
    ] {
        assert!(!f.command().args(extra).output().unwrap().status.success());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_archive"))
        .args([
            "copy",
            "--from",
            "Source",
            "--to",
            "Destination",
            "--not",
            "--in",
            "Backup",
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "filters must not be silently ignored without --host-script"
    );
}
