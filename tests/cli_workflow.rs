#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::{Command, Output};

    use serde_json::Value;
    use sha2::{Digest as _, Sha256};
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

    fn central_archive(temp: &TempDir) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_archive"));
        command
            .env("XDG_DATA_HOME", temp.path().join("data"))
            .env("XDG_CONFIG_HOME", temp.path().join("config"))
            .env("HOME", temp.path().join("home"));
        command
    }

    fn install_fake_findmnt(temp: &TempDir) -> std::path::PathBuf {
        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let findmnt = bin.join("findmnt");
        fs::write(
            &findmnt,
            b"#!/bin/sh\nuuid=${FAKE_UUID:-null}\nprintf '{\"filesystems\":[{\"target\":\"%s\",\"source\":\"/dev/test1\",\"fstype\":\"ext4\",\"uuid\":%s,\"partuuid\":null}]}\\n' \"$FAKE_MOUNT_TARGET\" \"$uuid\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&findmnt).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&findmnt, permissions).unwrap();
        bin
    }

    fn use_fake_findmnt(command: &mut Command, bin: &Path, mount: &Path, uuid: Option<&str>) {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut paths = vec![bin.to_path_buf()];
        paths.extend(std::env::split_paths(&path));
        command
            .env("PATH", std::env::join_paths(paths).unwrap())
            .env("FAKE_MOUNT_TARGET", mount);
        if let Some(uuid) = uuid {
            command.env("FAKE_UUID", format!("\"{uuid}\""));
        } else {
            command.env_remove("FAKE_UUID");
        }
    }

    fn success(command: &mut Command) -> Output {
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "command failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn json(output: &Output) -> Value {
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn git(path: &Path, args: &[&str]) {
        git_stdout(path, args);
    }

    fn git_stdout(path: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn annex_fixture(temp: &TempDir) -> std::path::PathBuf {
        annex_fixture_at(temp.path())
    }

    fn annex_fixture_at(parent: &Path) -> std::path::PathBuf {
        let repo = parent.join("annex-source");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "Archive Ledger Test"]);
        git(&repo, &["config", "user.email", "test@example.invalid"]);
        git(&repo, &["config", "annex.uuid", "annex-source-fixture"]);

        let content = b"annex content\n";
        let key = format!(
            "SHA256E-s{}--{:x}.photo.jpg",
            content.len(),
            Sha256::digest(content)
        );
        let relative = std::path::PathBuf::from(format!(".git/annex/objects/aa/bb/{key}/{key}"));
        let object = repo.join(&relative);
        fs::create_dir_all(object.parent().unwrap()).unwrap();
        fs::write(&object, content).unwrap();
        symlink(&relative, repo.join("photo.jpg")).unwrap();
        let absent_content = b"not stored in this repository\n";
        let absent_key = format!(
            "SHA256E-s{}--{:x}.document.pdf",
            absent_content.len(),
            Sha256::digest(absent_content)
        );
        let absent_relative = std::path::PathBuf::from(format!(
            ".git/annex/objects/cc/dd/{absent_key}/{absent_key}"
        ));
        symlink(&absent_relative, repo.join("document.pdf")).unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-m", "annex fixture"]);

        git(&repo, &["checkout", "--orphan", "git-annex"]);
        git(&repo, &["rm", "-rf", "."]);
        fs::write(repo.join("uuid.log"), b"fixture\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-m", "annex metadata"]);
        git(&repo, &["checkout", "main"]);
        repo
    }

    #[test]
    fn named_archives_are_central_and_default_selection_is_explicit() {
        let temp = TempDir::new().unwrap();
        let unrelated_cwd = temp.path().join("working-files");
        fs::create_dir(&unrelated_cwd).unwrap();

        let missing_name = central_archive(&temp)
            .args(["init", "--non-interactive"])
            .output()
            .unwrap();
        assert_eq!(missing_name.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&missing_name.stderr).contains("--name is required"));

        let first = success(central_archive(&temp).current_dir(&unrelated_cwd).args([
            "--json",
            "init",
            "--name",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let first = json(&first);
        assert_eq!(first["archive_name"], "Personal");
        assert_eq!(first["starter"], Value::Null);
        assert_eq!(
            first["database"].as_str().unwrap(),
            temp.path()
                .join("data/archive-ledger/archives/arc_personal/archive.db")
                .to_str()
                .unwrap()
        );
        assert!(!unrelated_cwd.join(".archive-ledger").exists());

        let second = success(central_archive(&temp).args([
            "--json",
            "init",
            "--name",
            "Research",
            "--archive-id",
            "arc_research",
            "--non-interactive",
        ]));
        assert_eq!(json(&second)["archive_name"], "Research");

        success(central_archive(&temp).args(["rename", "Personal Archive"]));
        let personal_status = central_archive(&temp)
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(personal_status.status.code(), Some(10));
        assert_eq!(json(&personal_status)["archive_name"], "Personal Archive");

        success(central_archive(&temp).args([
            "init",
            "--name",
            "Work",
            "--archive-id",
            "arc_work",
            "--make-default",
            "--non-interactive",
        ]));
        let work_status = central_archive(&temp)
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(work_status.status.code(), Some(10));
        assert_eq!(json(&work_status)["archive_id"], "arc_work");

        success(central_archive(&temp).args(["use", "Research"]));
        success(central_archive(&temp).args(["rename", "Research Archive"]));
        let research_status = central_archive(&temp)
            .args(["--json", "status"])
            .output()
            .unwrap();
        assert_eq!(research_status.status.code(), Some(10));
        assert_eq!(json(&research_status)["archive_id"], "arc_research");
        assert_eq!(json(&research_status)["archive_name"], "Research Archive");

        let explicit = central_archive(&temp)
            .env("ARCHIVE_LEDGER_ARCHIVE", "Research Archive")
            .args(["--json", "--archive", "Personal Archive", "status"])
            .output()
            .unwrap();
        assert_eq!(explicit.status.code(), Some(10));
        assert_eq!(json(&explicit)["archive_id"], "arc_personal");

        let archive_root = temp
            .path()
            .join("data/archive-ledger/archives/arc_personal");
        let by_path = central_archive(&temp)
            .arg("--archive")
            .arg(&archive_root)
            .args(["--json", "events", "verify"])
            .output()
            .unwrap();
        assert!(by_path.status.success());
        assert_eq!(json(&by_path)["last_seq"], 2);
    }

    #[test]
    fn collection_init_discovers_relative_paths_and_reuses_a_remounted_root() {
        let temp = TempDir::new().unwrap();
        let bin = install_fake_findmnt(&temp);
        let mount_a = temp.path().join("mount-a");
        let mount_b = temp.path().join("mount-b");
        let photos = mount_a.join("annex/photos");
        let documents = mount_b.join("annex/documents");
        fs::create_dir_all(&photos).unwrap();
        fs::create_dir_all(&documents).unwrap();

        success(central_archive(&temp).args([
            "init",
            "--name",
            "Setup",
            "--archive-id",
            "arc_setup",
            "--non-interactive",
        ]));

        let mut missing_device = central_archive(&temp);
        use_fake_findmnt(&mut missing_device, &bin, &mount_a, Some("TEST-UUID"));
        let missing_device = missing_device
            .arg("collection")
            .arg("init")
            .arg(&photos)
            .args(["--name", "Probe", "--non-interactive"])
            .output()
            .unwrap();
        assert_eq!(missing_device.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&missing_device.stderr).contains("--device"));

        let mut first = central_archive(&temp);
        use_fake_findmnt(&mut first, &bin, &mount_a, Some("TEST-UUID"));
        let first = success(
            first
                .arg("--json")
                .arg("collection")
                .arg("init")
                .arg(&photos)
                .args([
                    "--name",
                    "Photos",
                    "--device",
                    "SD01",
                    "--site",
                    "Home",
                    "--non-interactive",
                ]),
        );
        let first = json(&first);
        assert_eq!(first["mounted"]["relative_path"], "annex/photos");
        assert_eq!(first["archive_root"]["filesystem_fingerprint"], "test-uuid");
        assert_eq!(first["archive_root"]["fingerprint_kind"], "filesystem_uuid");
        assert_eq!(first["location"]["display_name"], "Photos on SD01");

        let mut second = central_archive(&temp);
        use_fake_findmnt(&mut second, &bin, &mount_b, Some("test-uuid"));
        let second = success(
            second
                .arg("--json")
                .arg("collection")
                .arg("init")
                .arg(&documents)
                .args(["--name", "Documents", "--non-interactive"]),
        );
        let second = json(&second);
        assert_eq!(second["mounted"]["relative_path"], "annex/documents");
        assert_eq!(
            second["archive_root"]["archive_root_id"],
            first["archive_root"]["archive_root_id"]
        );
        assert_eq!(second["device"]["device_id"], first["device"]["device_id"]);
        assert_eq!(second["site"]["site_id"], first["site"]["site_id"]);

        let unknown = mount_a.join("unknown");
        fs::create_dir(&unknown).unwrap();
        let mut unsafe_init = central_archive(&temp);
        use_fake_findmnt(&mut unsafe_init, &bin, &mount_a, None);
        let unsafe_init = unsafe_init
            .arg("collection")
            .arg("init")
            .arg(&unknown)
            .args([
                "--name",
                "Unknown",
                "--device",
                "SD01",
                "--site",
                "Home",
                "--non-interactive",
            ])
            .output()
            .unwrap();
        assert_eq!(unsafe_init.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&unsafe_init.stderr).contains("--allow-unidentified-root"));

        let database_path = temp
            .path()
            .join("data/archive-ledger/archives/arc_setup/archive.db");
        let connection = rusqlite::Connection::open(database_path).unwrap();
        let count = |table: &str| {
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap()
        };
        assert_eq!(count("archive_roots"), 1);
        assert_eq!(count("devices"), 1);
        assert_eq!(count("sites"), 1);
        assert_eq!(count("locations"), 2);
        assert_eq!(count("collections"), 2);
    }

    #[test]
    fn ergonomic_annex_import_uses_one_partial_location_per_repository() {
        let temp = TempDir::new().unwrap();
        let bin = install_fake_findmnt(&temp);
        let mount_a = temp.path().join("mount-a");
        let mount_b = temp.path().join("mount-b");
        fs::create_dir_all(&mount_a).unwrap();
        fs::create_dir_all(&mount_b).unwrap();
        let source = annex_fixture_at(&mount_a);
        let remote = mount_b.join("annex-remote");
        let cloned = Command::new("git")
            .arg("clone")
            .arg(&source)
            .arg(&remote)
            .output()
            .unwrap();
        assert!(
            cloned.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&cloned.stderr)
        );
        git(&remote, &["branch", "git-annex", "origin/git-annex"]);
        git(&remote, &["config", "annex.uuid", "annex-remote-fixture"]);
        let source_head = git_stdout(&source, &["rev-parse", "HEAD"]);
        let source_status = git_stdout(&source, &["status", "--porcelain=v1"]);
        let remote_head = git_stdout(&remote, &["rev-parse", "HEAD"]);
        let remote_status = git_stdout(&remote, &["status", "--porcelain=v1"]);

        success(central_archive(&temp).args([
            "init",
            "--name",
            "Media",
            "--archive-id",
            "arc_media",
            "--non-interactive",
        ]));
        let mut first = central_archive(&temp);
        use_fake_findmnt(&mut first, &bin, &mount_a, Some("MEDIA-MAIN"));
        let first = success(
            first
                .arg("--json")
                .arg("collection")
                .arg("init")
                .arg(&source)
                .args([
                    "--name",
                    "Photos",
                    "--device",
                    "Main Computer",
                    "--site",
                    "Home",
                    "--import-annex",
                    "--non-interactive",
                ]),
        );
        let first = json(&first);
        assert_eq!(first["annex_import"]["summary"]["entries_seen"], 2);
        assert_eq!(first["annex_import"]["summary"]["present"], 1);
        assert_eq!(first["annex_import"]["summary"]["absent"], 1);
        let collection_id = first["collection"]["collection_id"].as_str().unwrap();
        let first_location = first["location"]["location_id"].as_str().unwrap();

        let mut second = central_archive(&temp);
        use_fake_findmnt(&mut second, &bin, &mount_b, Some("MEDIA-REMOTE"));
        let second = success(
            second
                .arg("--json")
                .arg("location")
                .arg("import-annex")
                .arg(&remote)
                .args([
                    "--collection",
                    "Photos",
                    "--device",
                    "SD01",
                    "--site",
                    "Home",
                    "--non-interactive",
                ]),
        );
        let second = json(&second);
        assert_eq!(second["collection"]["collection_id"], collection_id);
        assert_eq!(second["annex_import"]["summary"]["present"], 0);
        assert_eq!(second["annex_import"]["summary"]["absent"], 2);
        assert_ne!(second["location"]["location_id"], first_location);

        let database_path = temp
            .path()
            .join("data/archive-ledger/archives/arc_media/archive.db");
        let connection = rusqlite::Connection::open(database_path).unwrap();
        let counts: (i64, i64, i64, i64, i64, i64) = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM collections),
                   (SELECT COUNT(*) FROM locations),
                   (SELECT COUNT(*) FROM devices),
                   (SELECT COUNT(*) FROM file_refs),
                   (SELECT COUNT(*) FROM objects),
                   (SELECT COUNT(*) FROM copy_claims)",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(counts, (1, 2, 2, 2, 1, 1));
        let availability: (i64, i64) = connection
            .query_row(
                "SELECT
                   SUM(CASE WHEN state = 'present' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN state = 'missing' THEN 1 ELSE 0 END)
                 FROM external_availability",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(availability, (1, 3));
        let split_import_locations: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM annex_imports
                 WHERE legacy_worktree_location_id IS NOT NULL
                    OR legacy_cas_location_id IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(split_import_locations, 0);
        assert_eq!(git_stdout(&source, &["rev-parse", "HEAD"]), source_head);
        assert_eq!(
            git_stdout(&source, &["status", "--porcelain=v1"]),
            source_status
        );
        assert_eq!(git_stdout(&remote, &["rev-parse", "HEAD"]), remote_head);
        assert_eq!(
            git_stdout(&remote, &["status", "--porcelain=v1"]),
            remote_status
        );
    }

    #[test]
    fn cli_manages_inventory_integrity_resume_metadata_and_restore() {
        let temp = TempDir::new().unwrap();
        let files = temp.path().join("files");
        fs::create_dir(&files).unwrap();
        fs::write(files.join("a.txt"), b"alpha\n").unwrap();
        fs::write(files.join("b.txt"), b"beta\n").unwrap();

        let initialized = success(
            archive(&temp)
                .args(["--json", "init", "--archive-id", "arc_workflow"])
                .arg("--non-interactive")
                .arg("--root-path")
                .arg(&files)
                .args([
                    "--fingerprint",
                    "fixture-device",
                    "--fingerprint-kind",
                    "fixture",
                ]),
        );
        assert_eq!(
            json(&initialized)["starter"]["location_id"],
            "location_primary"
        );

        let interrupted = success(archive(&temp).args([
            "--json",
            "scan",
            "location_primary",
            "--collection",
            "collection_primary",
            "--path",
            files.to_str().unwrap(),
            "--device",
            "device_primary",
            "--root",
            "root_primary",
            "--job-id",
            "job_scan_fixture",
            "--scan-id",
            "scan_fixture",
            "--max-items",
            "1",
        ]));
        assert_eq!(json(&interrupted)["status"], "running");
        let resumed = success(archive(&temp).args(["--json", "job", "resume", "job_scan_fixture"]));
        let resumed = json(&resumed);
        assert_eq!(resumed["status"], "complete");
        assert_eq!(resumed["summary"]["files_seen"], 2);
        assert_eq!(resumed["summary"]["new_paths"], 2);
        assert_eq!(resumed["summary"]["unchanged_paths"], 0);

        let verified = success(
            archive(&temp)
                .args(["--json", "verify", "location_primary", "--path"])
                .arg(&files),
        );
        assert_eq!(json(&verified)["summary"]["ok"], 2);

        fs::write(files.join("a.txt"), b"corrupt\n").unwrap();
        let corrupt = archive(&temp)
            .args(["--json", "verify", "location_primary", "--path"])
            .arg(&files)
            .output()
            .unwrap();
        assert_eq!(corrupt.status.code(), Some(10));
        assert_eq!(json(&corrupt)["summary"]["hash_mismatch"], 1);

        let annex = annex_fixture(&temp);
        success(archive(&temp).args([
            "location",
            "add",
            "--id",
            "location_annex_cas",
            "--name",
            "Annex CAS",
            "--kind",
            "filesystem",
            "--root",
            "root_primary",
            "--device",
            "device_primary",
            "--path",
            ".git/annex/objects",
        ]));
        let imported = success(
            archive(&temp)
                .args(["--json", "import", "annex"])
                .arg(&annex)
                .args([
                    "--collection",
                    "collection_primary",
                    "--worktree-location",
                    "location_primary",
                    "--cas-location",
                    "location_annex_cas",
                    "--device",
                    "device_primary",
                    "--root",
                    "root_primary",
                ]),
        );
        assert_eq!(json(&imported)["summary"]["present"], 1);
        let remotes = success(archive(&temp).args(["--json", "annex-remote", "list", "--all"]));
        assert!(!json(&remotes)["items"].as_array().unwrap().is_empty());
        success(archive(&temp).args([
            "annex-remote",
            "map",
            "annex-source-fixture",
            "remote-fixture",
            "location_annex_cas",
            "--name",
            "Fixture remote",
        ]));

        success(archive(&temp).args([
            "site",
            "add",
            "--id",
            "site_remote",
            "--name",
            "Remote",
            "--kind",
            "cloud",
        ]));
        success(archive(&temp).args([
            "location",
            "add",
            "--id",
            "location_metadata",
            "--name",
            "Metadata backup",
            "--kind",
            "service",
            "--site",
            "site_remote",
        ]));
        let bare = temp.path().join("metadata.git");
        success(Command::new("git").args(["init", "--bare"]).arg(&bare));
        success(
            archive(&temp)
                .args([
                    "metadata-destination",
                    "add",
                    "--id",
                    "metadata_remote",
                    "--name",
                    "Remote metadata",
                    "--location",
                    "location_metadata",
                    "--remote",
                    "backup",
                    "--locator",
                ])
                .arg(&bare),
        );
        git(
            &temp.path().join("canonical"),
            &["remote", "add", "backup", bare.to_str().unwrap()],
        );
        let checkpoint = archive(&temp)
            .args(["--json", "checkpoint", "--replicate"])
            .output()
            .unwrap();
        assert_eq!(checkpoint.status.code(), Some(10));
        assert_eq!(json(&checkpoint)["replication_observations"], 1);
        let metadata = archive(&temp)
            .args(["--json", "report", "metadata"])
            .output()
            .unwrap();
        assert_eq!(metadata.status.code(), Some(10));
        assert_eq!(
            json(&metadata)["destinations"][0]["latest_independence_status"],
            "unknown"
        );
        success(archive(&temp).args(["--json", "events", "verify"]));

        let clone = temp.path().join("restored-events");
        success(
            Command::new("git")
                .args(["clone", "--branch", "archive-ledger"])
                .arg(&bare)
                .arg(&clone),
        );
        let restored = success(
            Command::new(env!("CARGO_BIN_EXE_archive"))
                .args(["--json", "restore", "check"])
                .arg(&clone)
                .arg("--rebuild-database")
                .arg(temp.path().join("restored.db")),
        );
        let restored = json(&restored);
        assert_eq!(
            restored["verified_event_seq"],
            restored["rebuilt_event_seq"]
        );
    }

    #[test]
    fn verification_establishes_identity_after_a_scan_read_error() {
        let temp = TempDir::new().unwrap();
        let files = temp.path().join("files");
        fs::create_dir(&files).unwrap();
        let unreadable = files.join("retry.txt");
        fs::write(&unreadable, b"read me later\n").unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();

        success(
            archive(&temp)
                .args([
                    "init",
                    "--archive-id",
                    "arc_retry",
                    "--non-interactive",
                    "--root-path",
                ])
                .arg(&files),
        );
        let scan = archive(&temp)
            .args([
                "--json",
                "scan",
                "location_primary",
                "--collection",
                "collection_primary",
                "--path",
            ])
            .arg(&files)
            .args(["--device", "device_primary", "--root", "root_primary"])
            .output()
            .unwrap();
        fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(scan.status.code(), Some(10));
        assert_eq!(json(&scan)["summary"]["content_read_errors"], 1);

        let before = success(archive(&temp).args([
            "--json",
            "file",
            "find",
            "--collection",
            "collection_primary",
            "--exact",
            "retry.txt",
        ]));
        assert_eq!(json(&before)["items"][0]["identity_state"], "unknown");

        let verified = success(
            archive(&temp)
                .args(["--json", "verify", "location_primary", "--path"])
                .arg(&files),
        );
        assert_eq!(json(&verified)["summary"]["ok"], 1);
        let after = success(archive(&temp).args([
            "--json",
            "file",
            "find",
            "--collection",
            "collection_primary",
            "--exact",
            "retry.txt",
        ]));
        assert_eq!(json(&after)["items"][0]["identity_state"], "resolved");
        assert!(json(&after)["items"][0]["object_id"].as_str().is_some());
    }
}
