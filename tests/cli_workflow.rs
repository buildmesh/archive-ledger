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
    }

    fn annex_fixture(temp: &TempDir) -> std::path::PathBuf {
        let repo = temp.path().join("annex-source");
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
