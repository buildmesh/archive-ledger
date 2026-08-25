#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use serde_json::Value;
    use sha2::{Digest as _, Sha256};
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
            "command failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn json(output: &Output) -> Value {
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn root(temp: &TempDir) -> PathBuf {
        temp.path()
            .join("data/archive-ledger/archives/arc_personal")
    }

    fn git(root: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    }

    fn git_success(root: &Path, args: &[&str]) {
        let output = git(root, args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn copy_tree(source: &Path, target: &Path) {
        fs::create_dir_all(target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&source_path, &target_path);
            } else {
                fs::copy(source_path, target_path).unwrap();
            }
        }
    }

    #[test]
    fn init_status_verify_and_rebuild_use_one_verified_v2_state() {
        let temp = TempDir::new().unwrap();
        let initialized = success(archive(&temp).args([
            "--json",
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let initialized = json(&initialized);
        assert_eq!(initialized["version"], 2);
        assert_eq!(initialized["archive_name"], "Personal");

        let before = json(&success(archive(&temp).args(["--json", "status"])));
        assert_eq!(before["schema_version"], 6);
        assert_eq!(before["event_tree_version"], 2);
        assert_eq!(before["records"], 3);
        assert_eq!(before["collections"], serde_json::json!([]));
        assert_eq!(before["collection_count"], 0);
        assert_eq!(
            before["accepted_frontier_hash"],
            before["applied_frontier_hash"]
        );

        let canonical = root(&temp).join("canonical");
        let unavailable = root(&temp).join("canonical-unavailable");
        fs::rename(&canonical, &unavailable).unwrap();
        let cached = json(&success(archive(&temp).args(["--json", "status"])));
        assert_eq!(before, cached, "normal status is served by SQLite");
        fs::rename(&unavailable, &canonical).unwrap();

        let verification = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        assert_eq!(verification["version"], 2);
        assert_eq!(verification["records"], 3);
        assert_eq!(verification["segments"], 1);
        assert_eq!(verification["frontiers"], 2);

        success(archive(&temp).args(["db", "rebuild"]));
        let after = json(&success(archive(&temp).args(["--json", "status"])));
        assert_eq!(before, after);

        let archive_root = root(&temp);
        let canonical = archive_root.join("canonical");
        assert!(canonical.join("genesis.json").is_file());
        assert!(git(&canonical, &["status", "--short"]).stdout.is_empty());
        let branch = git(&canonical, &["branch", "--show-current"]);
        assert_eq!(
            String::from_utf8_lossy(&branch.stdout).trim(),
            "archive-ledger"
        );
        let key = fs::read_dir(archive_root.join("local/clients"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn fsck_is_read_only_and_full_mode_compares_a_disposable_rebuild() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let archive_root = root(&temp);
        let canonical = archive_root.join("canonical");
        let database = archive_root.join("archive.db");
        let before_database = fs::read(&database).unwrap();
        let before_head = git(&canonical, &["rev-parse", "HEAD"]).stdout;

        let routine = json(&success(archive(&temp).args(["--json", "fsck"])));
        assert_eq!(routine["healthy"], true);
        assert_eq!(routine["projection_current"], true);
        assert!(routine["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["code"] == "full_check_not_requested"));

        let rebuild_dir = temp.path().join("fsck-work");
        let full = json(&success(
            archive(&temp)
                .args(["--json", "fsck", "--full", "--rebuild-dir"])
                .arg(&rebuild_dir),
        ));
        assert_eq!(full["healthy"], true);
        assert!(full["table_digests"].as_array().unwrap().len() > 20);
        assert!(full["checks"].as_array().unwrap().iter().any(|check| {
            check["code"] == "projection_logical_equivalence" && check["status"] == "pass"
        }));
        assert_eq!(fs::read(&database).unwrap(), before_database);
        assert_eq!(git(&canonical, &["rev-parse", "HEAD"]).stdout, before_head);
        assert!(git(&canonical, &["status", "--short"]).stdout.is_empty());
        assert_eq!(fs::read_dir(&rebuild_dir).unwrap().count(), 0);

        let keep_dir = temp.path().join("fsck-kept-work");
        let kept = json(&success(
            archive(&temp)
                .args([
                    "--json",
                    "fsck",
                    "--full",
                    "--keep-rebuild",
                    "--rebuild-dir",
                ])
                .arg(&keep_dir),
        ));
        let kept_path = PathBuf::from(kept["rebuild_path"].as_str().unwrap());
        assert!(kept_path.is_file());
        assert!(kept_path.starts_with(&keep_dir));
        assert_eq!(fs::read(&database).unwrap(), before_database);
        assert_eq!(git(&canonical, &["rev-parse", "HEAD"]).stdout, before_head);
        assert!(git(&canonical, &["status", "--short"]).stdout.is_empty());

        let local_work = rusqlite::Connection::open(&database).unwrap();
        local_work
            .execute_batch(
                "INSERT INTO jobs(
                   job_id, job_type, status, created_time_utc_ms, params_json, input_version
                 ) VALUES ('job_local_fsck', 'local_test', 'running', 1, '{}', '1');
                 INSERT INTO job_items(
                   job_item_id, job_id, item_type, item_key, status,
                   attempts, updated_time_utc_ms
                 ) VALUES (
                   'item_local_fsck', 'job_local_fsck', 'path', 'one', 'pending', 0, 1
                 );",
            )
            .unwrap();
        drop(local_work);
        let local_only = json(&success(
            archive(&temp)
                .args(["--json", "fsck", "--full", "--rebuild-dir"])
                .arg(&rebuild_dir),
        ));
        assert_eq!(local_only["healthy"], true);
        assert!(local_only["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| {
                check["code"] == "projection_logical_equivalence" && check["status"] == "pass"
            }));
        fs::write(&database, &before_database).unwrap();

        let wrong_identity = rusqlite::Connection::open(&database).unwrap();
        wrong_identity
            .execute(
                "UPDATE archive_meta SET value = 'arc_wrong' WHERE key = 'archive_id'",
                [],
            )
            .unwrap();
        drop(wrong_identity);
        let identity = archive(&temp).args(["--json", "fsck"]).output().unwrap();
        assert_eq!(identity.status.code(), Some(10));
        let identity = json(&identity);
        assert!(identity["checks"].as_array().unwrap().iter().any(|check| {
            check["code"] == "projection_identity" && check["status"] == "finding"
        }));
        fs::write(&database, &before_database).unwrap();

        let wrong_cursor = rusqlite::Connection::open(&database).unwrap();
        wrong_cursor
            .execute(
                "UPDATE projection_origins SET applied_seq = applied_seq - 1 WHERE applied_seq > 0",
                [],
            )
            .unwrap();
        drop(wrong_cursor);
        let cursor = archive(&temp).args(["--json", "fsck"]).output().unwrap();
        assert_eq!(cursor.status.code(), Some(10));
        let cursor = json(&cursor);
        assert!(cursor["checks"].as_array().unwrap().iter().any(|check| {
            check["code"] == "projection_cursors" && check["status"] == "finding"
        }));
        fs::write(&database, &before_database).unwrap();

        let wrong_foreign_key = rusqlite::Connection::open(&database).unwrap();
        wrong_foreign_key
            .execute_batch("PRAGMA foreign_keys = OFF")
            .unwrap();
        wrong_foreign_key
            .execute(
                "UPDATE batch_runs SET origin_id = 'origin_missing' WHERE rowid = (SELECT MIN(rowid) FROM batch_runs)",
                [],
            )
            .unwrap();
        drop(wrong_foreign_key);
        let foreign_key = archive(&temp).args(["--json", "fsck"]).output().unwrap();
        assert_eq!(foreign_key.status.code(), Some(10));
        let foreign_key = json(&foreign_key);
        assert!(foreign_key["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| {
                check["code"] == "sqlite_foreign_keys" && check["status"] == "finding"
            }));
        fs::write(&database, &before_database).unwrap();

        let changed = rusqlite::Connection::open(&database).unwrap();
        changed
            .execute(
                "UPDATE archive_meta SET value = 'Diverged' WHERE key = 'archive_display_name'",
                [],
            )
            .unwrap();
        drop(changed);
        let divergent = archive(&temp)
            .args(["--json", "fsck", "--full", "--rebuild-dir"])
            .arg(&rebuild_dir)
            .output()
            .unwrap();
        assert_eq!(divergent.status.code(), Some(10));
        let divergent = json(&divergent);
        assert!(divergent["checks"].as_array().unwrap().iter().any(|check| {
            check["code"] == "projection_logical_equivalence" && check["status"] == "finding"
        }));
        assert_eq!(
            rusqlite::Connection::open(&database)
                .unwrap()
                .query_row(
                    "SELECT value FROM archive_meta WHERE key = 'archive_display_name'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "Diverged"
        );
        fs::write(&database, &before_database).unwrap();

        let events = canonical.join("events/v2/origins");
        let origin = fs::read_dir(events)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let segment = fs::read_dir(origin)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original_segment = fs::read(&segment).unwrap();
        let mut bytes = original_segment.clone();
        bytes[16] ^= 1;
        fs::write(&segment, bytes).unwrap();
        let corrupted = archive(&temp).args(["--json", "fsck"]).output().unwrap();
        assert_eq!(corrupted.status.code(), Some(10));
        let corrupted = json(&corrupted);
        assert!(corrupted["checks"].as_array().unwrap().iter().any(|check| {
            check["code"] == "canonical_events_invalid" && check["status"] == "finding"
        }));

        fs::write(&segment, original_segment).unwrap();
        let blob = git(&canonical, &["rev-parse", "HEAD:genesis.json"]);
        assert!(blob.status.success());
        let blob = String::from_utf8(blob.stdout).unwrap();
        let blob = blob.trim();
        let object = canonical
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]);
        let mut object_bytes = fs::read(&object).unwrap();
        object_bytes[8] ^= 1;
        let mut permissions = fs::metadata(&object).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&object, permissions).unwrap();
        fs::write(&object, object_bytes).unwrap();
        let damaged_git = archive(&temp).args(["--json", "fsck"]).output().unwrap();
        assert_eq!(damaged_git.status.code(), Some(2));
        let damaged_git = json(&damaged_git);
        assert!(damaged_git["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["code"] == "git_objects_valid" && check["status"] == "finding"));
    }

    #[test]
    fn fsck_full_compares_an_intentionally_behind_projection_at_its_frontier() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let archive_root = root(&temp);
        let canonical = archive_root.join("canonical");
        let database = archive_root.join("archive.db");
        let store = archive_ledger::V2OriginStore::open(&canonical).unwrap();
        store
            .append_batch(
                "test_unapplied_history",
                1,
                serde_json::json!({}),
                serde_json::json!({}),
                vec![serde_json::json!({"kind": "test_unapplied_fact"})],
            )
            .unwrap();
        let before_database = fs::read(&database).unwrap();
        let before_head = git(&canonical, &["rev-parse", "HEAD"]).stdout;
        let rebuild_dir = temp.path().join("fsck-behind-work");

        let output = archive(&temp)
            .args(["--json", "fsck", "--full", "--rebuild-dir"])
            .arg(&rebuild_dir)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(10));
        let report = json(&output);
        assert_eq!(report["projection_current"], false);
        assert!(report["checks"].as_array().unwrap().iter().any(|check| {
            check["code"] == "projection_current" && check["status"] == "finding"
        }));
        assert!(report["checks"].as_array().unwrap().iter().any(|check| {
            check["code"] == "projection_logical_equivalence" && check["status"] == "pass"
        }));
        assert_eq!(fs::read(&database).unwrap(), before_database);
        assert_eq!(git(&canonical, &["rev-parse", "HEAD"]).stdout, before_head);
        assert!(git(&canonical, &["status", "--short"]).stdout.is_empty());
        assert_eq!(fs::read_dir(&rebuild_dir).unwrap().count(), 0);
    }

    #[test]
    fn sync_enrollment_approval_status_and_revocation_are_safe_cli_workflows() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let primary = root(&temp);
        let remote = temp.path().join("coordination.git");
        fs::create_dir(&remote).unwrap();
        git_success(&remote, &["init", "--bare", "--quiet"]);
        success(archive(&temp).args([
            "sync",
            "remote",
            "add",
            "central",
            remote.to_str().unwrap(),
        ]));
        success(archive(&temp).args(["sync", "central"]));
        let replica = temp.path().join("replica");
        copy_tree(&primary, &replica);
        let request_path = temp.path().join("laptop.enrollment.json");

        let enrollment = json(&success(
            archive(&temp)
                .arg("--archive")
                .arg(&replica)
                .args(["--json", "sync", "enroll", "--name", "Laptop", "--output"])
                .arg(&request_path),
        ));
        let client_id = enrollment["client_id"].as_str().unwrap().to_owned();
        let request_bytes = fs::read(&request_path).unwrap();
        assert!(!String::from_utf8_lossy(&request_bytes).contains("secret_key"));

        let approved = json(&success(
            archive(&temp)
                .args(["--json", "sync", "approve"])
                .arg(&request_path),
        ));
        assert_eq!(approved["client_id"], client_id);
        success(archive(&temp).args(["sync", "central"]));
        let status = json(&success(archive(&temp).args(["--json", "sync", "status"])));
        assert_eq!(status["clients"].as_array().unwrap().len(), 2);
        assert_eq!(
            status["active_client_id"],
            status["clients"][0]["client_id"]
        );

        let refused = archive(&temp)
            .args(["sync", "revoke", &client_id])
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("requires --yes"));
        success(archive(&temp).args(["sync", "revoke", &client_id, "--yes"]));
        let status = json(&success(archive(&temp).args(["--json", "sync", "status"])));
        let laptop = status["clients"]
            .as_array()
            .unwrap()
            .iter()
            .find(|client| client["client_id"] == client_id)
            .unwrap();
        assert_eq!(laptop["status"], "revoked");
    }

    #[test]
    fn managed_sync_remote_transfers_enrollment_and_incrementally_applies_projection() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let primary = root(&temp);
        let remote = temp.path().join("central.git");
        fs::create_dir(&remote).unwrap();
        git_success(&remote, &["init", "--bare", "--quiet"]);
        success(archive(&temp).args([
            "sync",
            "remote",
            "add",
            "central",
            remote.to_str().unwrap(),
        ]));
        let seeded = json(&success(archive(&temp).args(["--json", "sync"])));
        assert_eq!(seeded["sync"]["pushed"], true);

        let replica = temp.path().join("replica");
        fs::create_dir(&replica).unwrap();
        let clone = Command::new("git")
            .args(["clone", "--quiet", "--branch", "archive-ledger"])
            .arg(&remote)
            .arg(replica.join("canonical"))
            .output()
            .unwrap();
        assert!(
            clone.status.success(),
            "clone failed: {}",
            String::from_utf8_lossy(&clone.stderr)
        );
        fs::copy(primary.join("archive.db"), replica.join("archive.db")).unwrap();
        let request = temp.path().join("managed-laptop.enrollment.json");
        let enrollment = json(&success(
            archive(&temp)
                .arg("--archive")
                .arg(&replica)
                .args(["--json", "sync", "enroll", "--name", "Laptop", "--output"])
                .arg(&request),
        ));
        success(archive(&temp).args(["sync", "approve", request.to_str().unwrap()]));
        success(archive(&temp).args(["sync", "central"]));
        let pulled = json(&success(
            archive(&temp)
                .arg("--archive")
                .arg(&replica)
                .args(["--json", "sync"]),
        ));
        assert_eq!(pulled["projection"]["caught_up"], true);
        let status = json(&success(
            archive(&temp)
                .arg("--archive")
                .arg(&replica)
                .args(["--json", "sync", "status"]),
        ));
        assert_eq!(status["active_client_id"], enrollment["client_id"]);
        assert_eq!(status["clients"].as_array().unwrap().len(), 2);
        assert_eq!(status["remotes"][0]["name"], "origin");

        let content = temp.path().join("sync-content");
        fs::create_dir(&content).unwrap();
        success(archive(&temp).args([
            "collection",
            "init",
            content.to_str().unwrap(),
            "--name",
            "Files",
            "--device",
            "Desktop",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));
        fs::write(content.join("one.txt"), b"one\n").unwrap();
        success(archive(&temp).args([
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        success(archive(&temp).args(["sync", "central"]));
        success(archive(&temp).arg("--archive").arg(&replica).args(["sync"]));
        let replica_database = rusqlite::Connection::open(replica.join("archive.db")).unwrap();
        assert_eq!(
            replica_database
                .query_row("SELECT COUNT(*) FROM file_refs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            replica_database
                .query_row(
                    "SELECT COUNT(*) FROM verification_results WHERE result = 'ok'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn sync_clone_uses_an_out_of_band_snapshot_and_applies_the_newer_tail() {
        let source_env = TempDir::new().unwrap();
        success(archive(&source_env).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let remote = source_env.path().join("central.git");
        fs::create_dir(&remote).unwrap();
        git_success(&remote, &["init", "--bare", "--quiet"]);
        success(archive(&source_env).args([
            "sync",
            "remote",
            "add",
            "central",
            remote.to_str().unwrap(),
        ]));
        success(archive(&source_env).args(["sync", "central"]));
        let snapshot = source_env.path().join("portable-snapshot");
        let created = json(&success(
            archive(&source_env)
                .args(["--json", "snapshot", "create"])
                .arg(&snapshot),
        ));
        assert_eq!(created["archive_id"], "arc_personal");
        success(archive(&source_env).args([
            "site",
            "add",
            "--id",
            "site_after_snapshot",
            "--name",
            "After snapshot",
            "--kind",
            "home",
        ]));
        success(archive(&source_env).args(["sync", "central"]));

        let clone_env = TempDir::new().unwrap();
        let cloned = json(&success(
            archive(&clone_env)
                .args(["--json", "sync", "clone"])
                .arg(&remote)
                .arg("--snapshot")
                .arg(&snapshot),
        ));
        assert_eq!(cloned["snapshot_used"], true);
        assert!(cloned["snapshot"]["records_applied"].as_u64().unwrap() > 0);
        let sites = json(&success(
            archive(&clone_env).args(["--json", "site", "list"]),
        ));
        assert_eq!(sites["items"][0]["display_name"], "After snapshot");
        assert!(root(&clone_env).join("archive.db").is_file());
        assert!(root(&clone_env).join("canonical/genesis.json").is_file());
    }

    #[test]
    fn verification_rejects_corruption_and_pre_v2_trees_clearly() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let events = root(&temp).join("canonical/events/v2/origins");
        let origin = fs::read_dir(&events)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let segment = fs::read_dir(origin)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut bytes = fs::read(&segment).unwrap();
        bytes[16] ^= 1;
        fs::write(segment, bytes).unwrap();
        let corrupted = archive(&temp).args(["events", "verify"]).output().unwrap();
        assert_eq!(corrupted.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&corrupted.stderr).contains("version 2 event tree is invalid")
        );

        let old = TempDir::new().unwrap();
        fs::create_dir(old.path().join("canonical")).unwrap();
        let unsupported = Command::new(env!("CARGO_BIN_EXE_archive"))
            .arg("--database")
            .arg(old.path().join("archive.db"))
            .arg("--events")
            .arg(old.path().join("canonical"))
            .args(["events", "verify"])
            .output()
            .unwrap();
        assert_eq!(unsupported.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&unsupported.stderr).contains("pre-v2 development Archive"));
    }

    #[test]
    fn failed_initialization_publishes_neither_archive_nor_registry_entry() {
        let temp = TempDir::new().unwrap();
        let empty_path = temp.path().join("empty-path");
        fs::create_dir(&empty_path).unwrap();
        let failed = archive(&temp)
            .env("PATH", &empty_path)
            .args([
                "init",
                "Personal",
                "--archive-id",
                "arc_personal",
                "--non-interactive",
            ])
            .output()
            .unwrap();
        assert_eq!(failed.status.code(), Some(2));
        assert!(!root(&temp).exists());
        assert!(!temp
            .path()
            .join("config/archive-ledger/catalogs.json")
            .exists());
        let archive_parent = temp.path().join("data/archive-ledger/archives");
        assert!(
            !archive_parent.exists() || fs::read_dir(archive_parent).unwrap().next().is_none(),
            "prepared Archive directories must be cleaned after failure"
        );
    }

    #[test]
    fn registry_commands_append_v2_batches_and_rebuild_the_same_topology() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        success(archive(&temp).args([
            "site",
            "add",
            "--id",
            "site_home",
            "--name",
            "Home",
            "--kind",
            "home",
        ]));
        success(archive(&temp).args([
            "device",
            "add",
            "--id",
            "device_main",
            "--name",
            "Main Computer",
            "--kind",
            "computer",
            "--site",
            "site_home",
        ]));
        success(archive(&temp).args([
            "root",
            "add",
            "--id",
            "root_main",
            "--name",
            "Main filesystem",
            "--kind",
            "filesystem",
            "--device",
            "device_main",
            "--path",
            "/",
        ]));
        success(archive(&temp).args([
            "location",
            "register",
            "--id",
            "location_photos",
            "--name",
            "Photos on Main Computer",
            "--kind",
            "filesystem",
            "--device",
            "device_main",
            "--root",
            "root_main",
            "--path",
            "srv/photos",
            "--writable",
        ]));

        let locations = json(&success(
            archive(&temp).args(["--json", "location", "list"]),
        ));
        assert_eq!(locations["version"], 2);
        assert_eq!(locations["items"][0]["location_id"], "location_photos");
        assert_eq!(locations["items"][0]["relative_path"]["text"], "srv/photos");
        let events = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        assert_eq!(events["records"], 15);
        assert_eq!(events["segments"], 5);
        assert!(git(&root(&temp).join("canonical"), &["status", "--short"])
            .stdout
            .is_empty());

        success(archive(&temp).args(["db", "rebuild"]));
        let rebuilt = json(&success(archive(&temp).args([
            "--json",
            "location",
            "show",
            "location_photos",
        ])));
        assert_eq!(
            rebuilt["items"][0]["display_name"],
            "Photos on Main Computer"
        );
    }

    #[test]
    fn collection_init_creates_starter_topology_and_policy_in_v2() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let content = temp.path().join("content/photos");
        fs::create_dir_all(&content).unwrap();
        let initialized = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "init",
            content.to_str().unwrap(),
            "--name",
            "Photos",
            "--device",
            "Main Computer",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ])));
        assert_eq!(initialized["version"], 2);
        assert_eq!(initialized["collection"]["display_name"], "Photos");
        assert_eq!(
            initialized["location"]["display_name"],
            "Photos on Main Computer"
        );
        assert_eq!(initialized["collection"]["policy_id"], "policy_starter");

        let collections = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "list",
        ])));
        assert_eq!(collections["items"].as_array().unwrap().len(), 1);
        let policies = json(&success(archive(&temp).args(["--json", "policy", "list"])));
        assert_eq!(policies["items"].as_array().unwrap().len(), 1);
        success(archive(&temp).args(["rename", "Family Archive"]));
        let status = json(&success(archive(&temp).args(["--json", "status"])));
        assert_eq!(status["archive_name"], "Family Archive");
        assert_eq!(status["collections"][0]["collection_name"], "Photos");
        let events = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        assert_eq!(events["records"], 27);
        assert_eq!(events["segments"], 9);
    }

    #[test]
    fn collection_add_hashes_regular_files_ignores_symlinks_and_rebuilds() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let content = temp.path().join("content/files");
        fs::create_dir_all(content.join("nested")).unwrap();
        fs::create_dir(content.join(".git")).unwrap();
        fs::write(content.join("one.txt"), b"one\n").unwrap();
        // Two paths with identical bytes are one Object at one Location, so they
        // must never be counted as two independent preservation copies.
        fs::write(content.join("nested/two.bin"), b"one\n").unwrap();
        fs::write(content.join(".git/ignored"), b"not content").unwrap();
        symlink("one.txt", content.join("alias.txt")).unwrap();
        success(archive(&temp).args([
            "collection",
            "init",
            content.to_str().unwrap(),
            "--name",
            "Files",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));

        let paused = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
            "--job-id",
            "job_inventory_resume",
            "--scan-id",
            "scan_inventory_resume",
            "--max-items",
            "1",
        ])));
        assert_eq!(paused["status"], "running");
        assert_eq!(paused["summary"]["files_observed"], 1);
        let job = json(&success(archive(&temp).args([
            "--json",
            "job",
            "show",
            "job_inventory_resume",
        ])));
        assert_eq!(job["status"], "running");
        let added = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_inventory_resume",
        ])));
        assert_eq!(added["status"], "complete");
        assert_eq!(added["summary"]["files_observed"], 2);
        assert_eq!(added["summary"]["new_paths"], 2);
        assert_eq!(added["summary"]["ignored_symlinks"], 1);
        assert_eq!(added["append"]["items_written"], 7);

        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let counts: (i64, i64, i64) = database
            .query_row(
                "SELECT (SELECT COUNT(*) FROM file_refs), (SELECT COUNT(*) FROM copy_claims WHERE state = 'present'), (SELECT COUNT(*) FROM verification_results WHERE result = 'ok')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (2, 2, 2));
        drop(database);

        let second = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        assert_eq!(second["summary"]["new_paths"], 0);
        assert_eq!(second["summary"]["confirmed_good"], 2);

        let first_page = json(&success(archive(&temp).args([
            "--json",
            "file",
            "find",
            "--collection",
            "Files",
            "--limit",
            "1",
        ])));
        assert_eq!(first_page["version"], 2);
        assert_eq!(first_page["items"].as_array().unwrap().len(), 1);
        let first_file_id = first_page["items"][0]["file_ref_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let continuation = first_page["next"].as_str().unwrap();
        let second_page = json(&success(archive(&temp).args([
            "--json",
            "file",
            "find",
            "--collection",
            "Files",
            "--limit",
            "1",
            "--continue",
            continuation,
        ])));
        assert_eq!(second_page["items"].as_array().unwrap().len(), 1);
        assert_ne!(second_page["items"][0]["file_ref_id"], first_file_id);
        assert!(second_page["next"].is_null());
        let prefix = json(&success(archive(&temp).args([
            "--json",
            "file",
            "find",
            "--collection",
            "Files",
            "--prefix",
            "nested",
        ])));
        assert_eq!(prefix["items"].as_array().unwrap().len(), 1);
        assert_eq!(prefix["items"][0]["logical_path"]["text"], "nested/two.bin");
        let shown = json(&success(archive(&temp).args([
            "--json",
            "file",
            "show",
            &first_file_id,
        ])));
        assert_eq!(shown["version"], 2);
        assert_eq!(shown["file_review"]["file"]["file_ref_id"], first_file_id);
        assert_eq!(
            shown["file_review"]["copies"].as_array().unwrap().len(),
            2,
            "duplicate-content paths expose the same two physical claims",
        );
        assert_eq!(shown["file_review"]["copies_truncated"], false);
        let object_id = shown["file_review"]["file"]["object_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let object =
            json(&success(archive(&temp).args([
                "--json", "object", "show", &object_id, "--limit", "1",
            ])));
        assert_eq!(object["version"], 2);
        assert_eq!(object["object_id"], object_id);
        assert_eq!(object["files"]["items"].as_array().unwrap().len(), 1);
        assert!(object["files"]["next"].is_string());

        let history = json(&success(archive(&temp).args([
            "--json",
            "file",
            "history",
            &first_file_id,
            "--limit",
            "1",
        ])));
        assert_eq!(history["version"], 2);
        assert_eq!(history["items"].as_array().unwrap().len(), 1);
        assert_eq!(history["items"][0]["item"]["file_ref_id"], first_file_id);
        let history_continuation = history["next"].as_str().unwrap();
        let next_history = json(&success(archive(&temp).args([
            "--json",
            "file",
            "history",
            &first_file_id,
            "--limit",
            "1",
            "--continue",
            history_continuation,
        ])));
        assert_eq!(next_history["items"].as_array().unwrap().len(), 1);
        let object_history = json(&success(
            archive(&temp).args(["--json", "object", "history", &object_id]),
        ));
        assert!(object_history["items"].as_array().unwrap().len() >= 2);
        let human = success(archive(&temp).args(["file", "show", &first_file_id]));
        assert!(String::from_utf8_lossy(&human.stdout).contains("Copies:"));
        let human_history =
            success(archive(&temp).args(["file", "history", &first_file_id, "--limit", "1"]));
        assert!(String::from_utf8_lossy(&human_history.stdout).contains("content_observed"));
        let missing = archive(&temp)
            .args(["--json", "file", "show", "file_missing"])
            .output()
            .unwrap();
        assert_eq!(missing.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("not_found"));

        let archive_status = archive(&temp).args(["--json", "status"]).output().unwrap();
        assert_eq!(archive_status.status.code(), Some(10));
        let archive_status = json(&archive_status);
        assert_eq!(archive_status["collections"][0]["file_count"], 2);
        assert_eq!(archive_status["collections"][0]["files_at_risk"], 2);
        let collection_status = archive(&temp)
            .args(["--json", "collection", "status", "Files"])
            .output()
            .unwrap();
        assert_eq!(collection_status.status.code(), Some(10));
        let collection_status = json(&collection_status);
        assert_eq!(collection_status["file_count"], 2);
        assert_eq!(collection_status["known_size_bytes"], 8);
        assert_eq!(
            collection_status["locations"][0]["metrics"]["file_count"],
            2
        );
        assert_eq!(
            collection_status["locations"][0]["metrics"]["stale_presence_count"],
            0
        );
        let location_status = json(&success(archive(&temp).args([
            "--json",
            "location",
            "status",
            "Files on Test Device",
        ])));
        assert_eq!(location_status["metrics"]["file_count"], 2);
        assert_eq!(location_status["metrics"]["space_used_bytes"], 8);
        let device_status = json(&success(archive(&temp).args([
            "--json",
            "device",
            "status",
            "Test Device",
        ])));
        assert_eq!(device_status["file_count"], 2);
        assert_eq!(device_status["space_used_bytes"], 8);
        assert_eq!(device_status["device"]["identity_state"], "unavailable");
        let human_device_status = success(archive(&temp).args(["device", "status", "Test Device"]));
        let human_device_status = String::from_utf8_lossy(&human_device_status.stdout);
        assert!(human_device_status.contains("Device identity: unavailable"));
        assert!(human_device_status.contains("archive device identity"));
        let site_status = json(&success(
            archive(&temp).args(["--json", "site", "status", "Home"]),
        ));
        assert_eq!(site_status["devices"][0]["metrics"]["file_count"], 2);
        let risk = archive(&temp)
            .args(["--json", "report", "risk", "--collection", "Files"])
            .output()
            .unwrap();
        assert_eq!(risk.status.code(), Some(10));
        let risk = json(&risk);
        assert_eq!(risk["files_at_risk"], 2);
        assert_eq!(
            risk["collections"][0]["findings"].as_array().unwrap().len(),
            2
        );
        assert_eq!(
            risk["collections"][0]["findings"][0]["qualifying_copies"],
            0
        );
        assert_eq!(risk["collections"][0]["findings"][0]["sites"], 0);

        let root_before = json(&success(archive(&temp).args(["--json", "root", "list"])));
        let confirmed = json(&success(archive(&temp).args([
            "--json",
            "device",
            "identity",
            "Test Device",
            "--kind",
            "serial",
            "--fingerprint",
            "TEST-DEVICE-001",
        ])));
        assert_eq!(confirmed["device"]["identity_state"], "confirmed");
        assert_eq!(confirmed["fingerprint_status"], "match");
        assert_eq!(confirmed["archive_root_identity_unchanged"], true);
        let root_after = json(&success(archive(&temp).args(["--json", "root", "list"])));
        assert_eq!(root_before["items"], root_after["items"]);
        let confirmed_risk = archive(&temp)
            .args(["--json", "report", "risk", "--collection", "Files"])
            .output()
            .unwrap();
        assert_eq!(confirmed_risk.status.code(), Some(10));
        let confirmed_risk = json(&confirmed_risk);
        assert_eq!(
            confirmed_risk["collections"][0]["findings"][0]["qualifying_copies"],
            1
        );

        success(archive(&temp).args([
            "device",
            "add",
            "--id",
            "device_clone",
            "--name",
            "Possible clone",
            "--kind",
            "disk",
        ]));
        let before_collision = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        let collision = archive(&temp)
            .args([
                "device",
                "identity",
                "Possible clone",
                "--kind",
                "serial",
                "--fingerprint",
                "TEST-DEVICE-001",
            ])
            .output()
            .unwrap();
        assert_eq!(collision.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&collision.stderr).contains("already belongs"));
        let after_collision = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        assert_eq!(before_collision["records"], after_collision["records"]);

        let conflict = json(&success(archive(&temp).args([
            "--json",
            "device",
            "identity",
            "Test Device",
            "--conflict",
        ])));
        assert_eq!(conflict["device"]["identity_state"], "conflict");
        assert_eq!(conflict["fingerprint_status"], "mismatch");
        let conflict_risk = json(
            &archive(&temp)
                .args(["--json", "report", "risk", "--collection", "Files"])
                .output()
                .unwrap(),
        );
        assert_eq!(
            conflict_risk["collections"][0]["findings"][0]["qualifying_copies"],
            0
        );
        let unavailable = json(&success(archive(&temp).args([
            "--json",
            "device",
            "identity",
            "Test Device",
            "--unavailable",
        ])));
        assert_eq!(unavailable["device"]["identity_state"], "unavailable");
        assert!(unavailable["device"]["hardware_fingerprint"].is_null());
        assert_eq!(unavailable["fingerprint_status"], "unavailable");
        success(archive(&temp).args([
            "device",
            "identity",
            "Test Device",
            "--kind",
            "serial",
            "--fingerprint",
            "TEST-DEVICE-001",
        ]));

        let root_identity = archive(&temp)
            .args([
                "device",
                "identity",
                "Possible clone",
                "--kind",
                "filesystem_uuid",
                "--fingerprint",
                "root-uuid",
            ])
            .output()
            .unwrap();
        assert_eq!(root_identity.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&root_identity.stderr)
            .contains("identifies a filesystem/Archive Root"));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        database
            .execute("UPDATE copy_claims SET last_seen_time_utc_ms = 0", [])
            .unwrap();
        drop(database);
        let stale = archive(&temp)
            .args([
                "--json",
                "report",
                "stale-presence",
                "--collection",
                "Files",
                "--locations",
            ])
            .output()
            .unwrap();
        assert_eq!(stale.status.code(), Some(10));
        let stale = json(&stale);
        assert_eq!(stale["threshold_days"], 365);
        assert_eq!(stale["stale_presence_count"], 2);

        fs::remove_file(content.join("nested/two.bin")).unwrap();
        let scanned = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "--path",
            content.to_str().unwrap(),
            "--collection",
            "Files",
            "--job-id",
            "job_scan_resume",
            "--scan-id",
            "scan_resume",
            "--max-items",
            "0",
        ])));
        assert_eq!(scanned["status"], "running");
        assert_eq!(scanned["summary"]["files_observed"], 0);
        let before_resume = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            before_resume
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(before_resume);
        let scanned = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_scan_resume",
        ])));
        assert_eq!(scanned["status"], "complete");
        assert_eq!(scanned["summary"]["missing_paths"], 1);

        let stale_page = archive(&temp)
            .args([
                "--json",
                "file",
                "find",
                "--collection",
                "Files",
                "--limit",
                "1",
                "--continue",
                continuation,
            ])
            .output()
            .unwrap();
        assert_eq!(stale_page.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&stale_page.stderr).contains("stale_continuation"));

        success(archive(&temp).args(["db", "rebuild"]));
        let rebuilt = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            rebuilt
                .query_row("SELECT COUNT(*) FROM file_refs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn location_import_annex_records_all_keys_and_only_present_bytes_as_copies() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let seed = temp.path().join("seed");
        fs::create_dir(&seed).unwrap();
        success(archive(&temp).args([
            "collection",
            "init",
            seed.to_str().unwrap(),
            "--name",
            "Files",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));

        let repo = temp.path().join("annex");
        fs::create_dir(&repo).unwrap();
        git_success(&repo, &["init", "-b", "main"]);
        git_success(&repo, &["config", "user.name", "Archive Ledger Test"]);
        git_success(&repo, &["config", "user.email", "test@example.invalid"]);
        git_success(&repo, &["config", "annex.uuid", "fixture-annex-uuid"]);
        let present_content = b"present annex content\n";
        let present_hash = Sha256::digest(present_content);
        let present_key = format!("SHA256E-s{}--{:x}.txt", present_content.len(), present_hash);
        let absent_content = b"absent annex content\n";
        let absent_hash = Sha256::digest(absent_content);
        let absent_key = format!("SHA256E-s{}--{:x}.txt", absent_content.len(), absent_hash);
        let present_target = PathBuf::from(format!(
            ".git/annex/objects/aa/bb/{present_key}/{present_key}"
        ));
        let absent_target = PathBuf::from(format!(
            ".git/annex/objects/cc/dd/{absent_key}/{absent_key}"
        ));
        fs::create_dir_all(repo.join(&present_target).parent().unwrap()).unwrap();
        fs::write(repo.join(&present_target), present_content).unwrap();
        symlink(&present_target, repo.join("present.txt")).unwrap();
        symlink(&absent_target, repo.join("absent.txt")).unwrap();
        fs::create_dir(repo.join("organized")).unwrap();
        symlink("../present.txt", repo.join("organized/alias.txt")).unwrap();
        git_success(&repo, &["add", "."]);
        git_success(&repo, &["commit", "-m", "fixture"]);

        let paused = json(&success(archive(&temp).args([
            "--json",
            "location",
            "import-annex",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
            "--job-id",
            "job_annex_resume",
            "--import-id",
            "import_annex_resume",
            "--max-items",
            "1",
        ])));
        assert_eq!(paused["annex_import"]["status"], "running");
        assert_eq!(paused["annex_import"]["summary"]["entries_seen"], 1);
        fs::OpenOptions::new()
            .append(true)
            .open(root(&temp).join("local/jobs/job_annex_resume/annex-items.jsonl"))
            .unwrap()
            .write_all(b"crash-tail-that-must-be-truncated\n")
            .unwrap();
        let imported = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_annex_resume",
        ])));
        assert_eq!(imported["version"], 2);
        assert_eq!(imported["summary"]["present"], 1);
        assert_eq!(imported["summary"]["absent"], 1);
        assert_eq!(imported["summary"]["ignored_symlinks"], 1);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM file_refs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(database);

        let first_scan = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "--path",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        assert_eq!(first_scan["summary"]["files_observed"], 2);
        assert_eq!(first_scan["summary"]["confirmed_good"], 1);
        assert_eq!(first_scan["summary"]["ignored_symlinks"], 1);
        assert_eq!(first_scan["summary"]["missing_paths"], 0);

        fs::create_dir_all(repo.join(&absent_target).parent().unwrap()).unwrap();
        fs::write(repo.join(&absent_target), absent_content).unwrap();
        let after_get = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "--path",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        assert_eq!(after_get["summary"]["confirmed_good"], 2);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        drop(database);
        fs::write(repo.join(&absent_target), b"corrupt bytes").unwrap();
        let corrupt = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "--path",
                repo.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(corrupt.status.code(), Some(10));
        let corrupt = json(&corrupt);
        assert_eq!(corrupt["summary"]["integrity_mismatches"], 1);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'corrupt'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(database);
        success(archive(&temp).args(["db", "rebuild"]));
        let rebuilt = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT COUNT(*) FROM annex_imports WHERE status = 'complete'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'corrupt'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn copy_places_verified_objects_without_overwrite_and_rebuilds() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("one.txt"), b"one\n").unwrap();
        fs::write(source.join("nested/two.txt"), b"two\n").unwrap();
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
            destination.to_str().unwrap(),
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

        let paused = json(&success(archive(&temp).current_dir(&source).args([
            "--json",
            "copy",
            "--to",
            "Backup",
            "--collection",
            "Files",
            "--yes",
            "--non-interactive",
            "--job-id",
            "job_copy_resume",
            "--max-items",
            "1",
        ])));
        assert_eq!(paused["status"], "running");
        assert_eq!(paused["files_verified_this_run"], 1);
        let jobs = json(&success(archive(&temp).args(["--json", "job", "list"])));
        assert_eq!(jobs["items"][0]["job_id"], "job_copy_resume");
        assert_eq!(jobs["items"][0]["status"], "running");

        let copied = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_copy_resume",
        ])));
        assert_eq!(copied["status"], "complete");
        assert_eq!(copied["summary"]["copied_objects"], 1);
        assert_eq!(fs::read(destination.join("one.txt")).unwrap(), b"one\n");
        assert_eq!(
            fs::read(destination.join("nested/two.txt")).unwrap(),
            b"two\n"
        );
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            4
        );
        assert_eq!(
            database
                .query_row(
                    "SELECT status FROM jobs WHERE job_id = 'job_copy_resume'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "complete"
        );
        drop(database);
        success(archive(&temp).args(["db", "rebuild"]));
        let rebuilt = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'present'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            4
        );
    }

    #[test]
    fn stage_audit_reuses_checksums_and_imports_only_archive_unknown_files() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let known = temp.path().join("known");
        let destination = temp.path().join("destination");
        let staged = temp.path().join("staged");
        fs::create_dir(&known).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::create_dir(&staged).unwrap();
        fs::write(known.join("known.txt"), b"already protected\n").unwrap();
        fs::write(staged.join("duplicate.txt"), b"already protected\n").unwrap();
        fs::write(staged.join("new.txt"), b"new content\n").unwrap();
        fs::write(staged.join("new-two.txt"), b"second new content\n").unwrap();
        success(archive(&temp).args([
            "collection",
            "init",
            known.to_str().unwrap(),
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
            known.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        success(archive(&temp).args([
            "location",
            "init",
            destination.to_str().unwrap(),
            "--collection",
            "Files",
            "--location-name",
            "Import Destination",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));

        let first = archive(&temp)
            .args([
                "--json",
                "stage",
                staged.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(first.status.code(), Some(10));
        let first = json(&first);
        assert_eq!(first["files_seen"], 3);
        assert_eq!(first["checksums_computed"], 3);
        assert_eq!(first["new_to_archive_files"], 2);
        assert_eq!(first["known_in_selected_collection"], 1);

        let second = archive(&temp)
            .args([
                "--json",
                "stage",
                staged.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(second.status.code(), Some(10));
        let second = json(&second);
        assert_eq!(second["checksums_computed"], 0);
        assert_eq!(second["checksums_reused"], 3);

        let paused = json(&success(archive(&temp).current_dir(&destination).args([
            "--json",
            "stage",
            "import",
            staged.to_str().unwrap(),
            "--collection",
            "Files",
            "--location",
            "Import Destination",
            "--into",
            "recovered",
            "--yes",
            "--non-interactive",
            "--job-id",
            "job_stage_resume",
            "--max-items",
            "1",
        ])));
        assert_eq!(paused["status"], "running");
        assert_eq!(paused["files_verified_this_run"], 1);
        let imported = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_stage_resume",
        ])));
        assert_eq!(imported["status"], "complete");
        assert_eq!(imported["files"], 2);
        assert_eq!(
            fs::read(destination.join("recovered/new.txt")).unwrap(),
            b"new content\n"
        );
        assert_eq!(
            fs::read(destination.join("recovered/new-two.txt")).unwrap(),
            b"second new content\n"
        );
        assert!(!destination.join("recovered/duplicate.txt").exists());
        assert_eq!(fs::read(staged.join("new.txt")).unwrap(), b"new content\n");

        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM file_refs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            3
        );
        drop(database);
        success(archive(&temp).args(["db", "rebuild"]));
        let after = archive(&temp)
            .args([
                "--json",
                "stage",
                staged.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(after.status.code(), Some(10));
        let after = json(&after);
        assert_eq!(after["new_to_archive_files"], 0);
        assert_eq!(after["checksums_reused"], 3);
        assert_eq!(after["known_at_risk_files"], 3);
        assert_eq!(after["known_policy_unknown_files"], 0);
    }
}
