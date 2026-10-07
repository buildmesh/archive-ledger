#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use serde_json::Value;
    use sha2::{Digest as _, Sha256, Sha512};
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

    fn compact_checks(temp: &TempDir) -> Vec<(i64, i64, i64, i64, i64)> {
        rusqlite::Connection::open(root(temp).join("archive.db"))
            .unwrap()
            .prepare("SELECT id, file_location_id, checked_at, presence, integrity FROM checks ORDER BY id")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    // Presence and integrity can initially share one check. Split the fixture's
    // selected pointer so aging one clock does not accidentally age the other.
    fn age_copy_checks(
        database: &rusqlite::Connection,
        path: Option<&str>,
        seen: Option<i64>,
        verified: Option<i64>,
    ) {
        let copies = database
            .prepare("SELECT b.id FROM copy_bindings b JOIN copy_claims c ON c.copy_claim_id = b.canonical_id WHERE ?1 IS NULL OR c.relative_path_display = ?1")
            .unwrap()
            .query_map([path], |row| row.get::<_, i64>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(!copies.is_empty());
        for copy in copies {
            for (pointer, time) in [("latest_presence", seen), ("latest_integrity", verified)] {
                if let Some(time) = time {
                    assert_eq!(database.execute(
                        &format!("INSERT INTO checks(file_location_id, checked_at, presence, integrity) SELECT c.file_location_id, ?2, c.presence, c.integrity FROM checks c JOIN copy_bindings b ON c.id = b.{pointer} WHERE b.id = ?1"),
                        rusqlite::params![copy, time],
                    ).unwrap(), 1);
                    database
                        .execute(
                            &format!("UPDATE copy_bindings SET {pointer} = ?2 WHERE id = ?1"),
                            rusqlite::params![copy, database.last_insert_rowid()],
                        )
                        .unwrap();
                }
            }
        }
    }

    // Detailed hash evidence remains canonical; compact checks retain only the
    // outcome. Inspect authenticated items to keep the algorithm/hash regression.
    fn canonical_hash_results(
        temp: &TempDir,
        algorithm: &str,
        result: &str,
        object: Option<&str>,
    ) -> usize {
        let store = archive_ledger::V2OriginStore::open(root(temp).join("canonical")).unwrap();
        let mut defaults = std::collections::BTreeMap::<String, Value>::new();
        let mut count = 0;
        store
            .visit_verified(|record| {
                let envelope = &record.record.envelope;
                let payload = &envelope.payload;
                if let Some(value) = payload.get("defaults") {
                    defaults.insert(envelope.batch_id.clone(), value.clone());
                }
                if let Some(items) = payload.get("items").and_then(Value::as_array) {
                    for raw in items {
                        let mut item = defaults
                            .get(&envelope.batch_id)
                            .and_then(|value| value.get(raw["kind"].as_str().unwrap()))
                            .and_then(Value::as_object)
                            .cloned()
                            .unwrap_or_default();
                        item.extend(raw.as_object().unwrap().clone());
                        let item = Value::Object(item);
                        let observed_result = item
                            .get("verification_result")
                            .or_else(|| item.get("result"));
                        if item["expected_hash_algo"] != algorithm
                            || observed_result.and_then(Value::as_str) != Some(result)
                            || object.is_some_and(|object| item["object_id"] != object)
                        {
                            continue;
                        }
                        let expected = item["expected_hash_hex"].as_str().unwrap();
                        let observed = item
                            .get("observed_hash_hex")
                            .or_else(|| item.get(format!("{algorithm}_hex")))
                            .and_then(Value::as_str)
                            .unwrap();
                        assert_eq!(observed.len(), if algorithm == "sha512" { 128 } else { 64 });
                        assert_eq!(expected == observed, result == "ok");
                        count += 1;
                    }
                }
                Ok(())
            })
            .unwrap();
        count
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_guide_does_not_use_the_callers_selected_archive() {
        let caller = TempDir::new().unwrap();
        success(archive(&caller).args([
            "init",
            "Caller archive",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let caller_root = root(&caller);
        let database_before = fs::read(caller_root.join("archive.db")).unwrap();
        let head_before = git(&caller_root.join("canonical"), &["rev-parse", "HEAD"]).stdout;
        let guide = TempDir::new().unwrap();
        let output = Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/test-lifecycle-guide.py"))
            .args(["--binary", env!("CARGO_BIN_EXE_archive")])
            .env("HOME", guide.path())
            .env("XDG_DATA_HOME", guide.path().join("caller-data"))
            .env("XDG_CONFIG_HOME", guide.path().join("caller-config"))
            .env("ARCHIVE_LEDGER_ARCHIVE", &caller_root)
            .env("ARCHIVE_LEDGER_OUTPUT", "json")
            .output()
            .unwrap();
        assert_eq!(
            git(&caller_root.join("canonical"), &["rev-parse", "HEAD"]).stdout,
            head_before,
            "guide mutated the caller-selected catalog"
        );
        assert_eq!(
            fs::read(caller_root.join("archive.db")).unwrap(),
            database_before,
            "guide mutated the caller-selected projection"
        );
        assert!(
            output.status.success(),
            "guide failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn job_lookup_keeps_old_terminal_rows_authoritative() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        database
            .execute_batch(
                "BEGIN;
            INSERT INTO jobs(job_id,job_type,status,created_time_utc_ms,params_json,input_version)
            VALUES ('job_old','annex_import','cancelled',0,'{}','import_old');
            WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10001)
            INSERT INTO jobs(job_id,job_type,status,created_time_utc_ms,params_json,input_version)
            SELECT 'job_new_'||x,'annex_import','complete',x,'{}','import_new_'||x FROM n;
            COMMIT;",
            )
            .unwrap();
        drop(database);
        let shown = json(&success(
            archive(&temp).args(["--json", "job", "show", "job_old"]),
        ));
        assert_eq!(shown["status"], "cancelled");
        let output = archive(&temp)
            .args(["job", "resume", "job_old"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("already cancelled"));
    }

    #[test]
    fn cli_information_exits_succeed_without_opening_an_archive() {
        let temp = TempDir::new().unwrap();
        for mode in ["human", "flag_json", "env_json"] {
            for args in [
                vec!["--help"],
                vec!["-h"],
                vec!["help"],
                vec!["location", "--help"],
                vec!["help", "location"],
                vec!["--version"],
                vec!["-V"],
            ] {
                let mut command = archive(&temp);
                command.env(
                    "ARCHIVE_LEDGER_OUTPUT",
                    if mode == "env_json" { "json" } else { "human" },
                );
                if mode == "flag_json" {
                    command.arg("--json");
                }
                let output = success(command.args(&args));
                assert!(output.stderr.is_empty(), "{mode} {args:?}");
                let text = String::from_utf8(output.stdout).unwrap();
                if args == ["--version"] || args == ["-V"] {
                    assert_eq!(text, format!("archive {}\n", env!("CARGO_PKG_VERSION")));
                } else {
                    assert!(text.contains("Usage:"), "{mode} {args:?}: {text}");
                }
            }
        }
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn cli_invalid_input_remains_an_error_in_human_and_json_modes() {
        let temp = TempDir::new().unwrap();
        for mode in ["human", "flag_json", "env_json"] {
            for args in [vec!["--unknown-option"], vec!["location"], vec![]] {
                let mut command = archive(&temp);
                command.env(
                    "ARCHIVE_LEDGER_OUTPUT",
                    if mode == "env_json" { "json" } else { "human" },
                );
                if mode == "flag_json" {
                    command.arg("--json");
                }
                let output = command.args(&args).output().unwrap();
                assert_eq!(output.status.code(), Some(2), "{mode} {args:?}");
                assert!(output.stdout.is_empty(), "{mode} {args:?}");
                assert!(!output.stderr.is_empty(), "{mode} {args:?}");
                if mode != "human" {
                    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
                    assert_eq!(error["error"]["code"], "invalid_input");
                }
            }
        }
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    fn root(temp: &TempDir) -> PathBuf {
        temp.path()
            .join("data/archive-ledger/archives/arc_personal")
    }

    #[test]
    fn sqlite_diagnostics_reach_human_and_json_errors() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        // A real SQLite failure against disposable bytes exercises the complete
        // projection-to-CLI error path without exhausting disks or changing mounts.
        let database = root(&temp).join("archive.db");
        fs::write(&database, vec![0xa5; 4096]).unwrap();
        for json_mode in [false, true] {
            let mut command = archive(&temp);
            command.env("ARCHIVE_LEDGER_OUTPUT", "human");
            if json_mode {
                command.arg("--json");
            }
            let output = command.arg("status").output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8(output.stderr).unwrap();
            let message = if json_mode {
                let error: Value = serde_json::from_str(&stderr).unwrap();
                assert_eq!(error["error"]["code"], "v2_projection_sqlite");
                error["error"]["message"].as_str().unwrap().to_owned()
            } else {
                assert!(stderr.starts_with("error [v2_projection_sqlite]:"));
                stderr
            };
            assert!(message.contains("file is not a database"));
            assert!(message.contains("SQLite primary code 26, extended code 26"));
            assert!(!message.contains("SQLITE_TMPDIR"));
        }
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

    fn assert_job_resume_refuses_symlink(temp: &TempDir, job_id: &str, name: &str) {
        use std::os::unix::fs::symlink;

        let path = root(temp).join("local/jobs").join(job_id).join(name);
        let original = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read job fixture {path:?}: {error}"),
        };
        if original.is_some() {
            fs::remove_file(&path).unwrap();
        }
        let sentinel = temp
            .path()
            .join(format!("sentinel-{}", name.replace('.', "-")));
        fs::write(&sentinel, b"preserve me").unwrap();
        symlink(&sentinel, &path).unwrap();

        let output = archive(temp)
            .args(["job", "resume", job_id])
            .output()
            .unwrap();
        assert!(!output.status.success(), "resumed through symlink {name}");
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");

        fs::remove_file(&path).unwrap();
        if let Some(bytes) = original {
            fs::write(path, bytes).unwrap();
        }
    }

    fn assert_job_resume_refuses_busy_job(temp: &TempDir, job_id: &str) {
        let status = || {
            let output = archive(temp).args(["--json", "status"]).output().unwrap();
            // Fixtures may intentionally have preservation findings.
            assert!(matches!(output.status.code(), Some(0 | 10)));
            json(&output)
        };
        let job_dir = root(temp).join("local/jobs").join(job_id);
        let job_files = || {
            fs::read_dir(&job_dir)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), fs::read(entry.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let files_before = job_files();
        let status_before = status();
        let job_before = json(&success(
            archive(temp).args(["--json", "job", "show", job_id]),
        ));
        let lock_dir = root(temp).join("local/job-locks");
        fs::create_dir_all(&lock_dir).unwrap();
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_dir.join(format!("{job_id}.lock")))
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();

        let mut child = archive(temp)
            .args(["--json", "job", "resume", job_id])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("resume waited for the busy job lock: {job_id}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        // Annex progress currently logs to stderr before the final JSON error.
        let stderr = String::from_utf8(output.stderr).unwrap();
        let error: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
        assert_eq!(error["error"]["code"], "job_busy");
        assert!(error["error"]["message"].as_str().unwrap().contains(job_id));
        assert_eq!(job_files(), files_before, "busy resume changed job files");
        assert_eq!(
            json(&success(
                archive(temp).args(["--json", "job", "show", job_id]),
            )),
            job_before,
            "busy resume changed the job checkpoint"
        );
        let status_after = status();
        for frontier in ["accepted_frontier_hash", "applied_frontier_hash"] {
            assert_eq!(status_after[frontier], status_before[frontier]);
        }
        drop(lock);
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
        assert_eq!(before["schema_version"], 8);
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
        let mut cached = json(&success(archive(&temp).args(["--json", "status"])));
        // Protection is read from canonical Git and reports why it is unknown without it.
        assert!(before["catalog_protection"]["error"].is_null());
        assert!(cached["catalog_protection"]["error"].is_string());
        let mut before_sqlite = before.clone();
        before_sqlite["catalog_protection"] = Value::Null;
        cached["catalog_protection"] = Value::Null;
        assert_eq!(before_sqlite, cached, "normal status is served by SQLite");
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
    fn archive_list_and_ls_show_all_registered_archives_without_opening_them() {
        let temp = TempDir::new().unwrap();
        let empty = json(&success(archive(&temp).args(["--json", "list"])));
        assert_eq!(empty["version"], 1);
        assert!(empty["default_archive_id"].is_null());
        assert_eq!(empty["archives"], serde_json::json!([]));
        let empty_human = success(archive(&temp).args(["list"]));
        assert!(String::from_utf8_lossy(&empty_human.stdout).contains("No Archives configured"));

        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        success(archive(&temp).args([
            "init",
            "Work",
            "--archive-id",
            "arc_work",
            "--make-default",
            "--non-interactive",
        ]));

        let listed = json(&success(archive(&temp).args(["--json", "list"])));
        assert_eq!(listed["default_archive_id"], "arc_work");
        assert_eq!(listed["archives"].as_array().unwrap().len(), 2);
        assert_eq!(listed["archives"][0]["display_name"], "Personal");
        assert_eq!(listed["archives"][0]["default"], false);
        assert!(listed["archives"][0]["root"].is_string());
        assert_eq!(listed["archives"][1]["display_name"], "Work");
        assert_eq!(listed["archives"][1]["archive_id"], "arc_work");
        assert_eq!(listed["archives"][1]["default"], true);

        let human = success(archive(&temp).args(["list"]));
        let alias = success(archive(&temp).args(["ls"]));
        assert_eq!(human.stdout, alias.stdout);
        let human = String::from_utf8_lossy(&human.stdout);
        assert!(human.contains("  Personal (arc_personal)"));
        assert!(human.contains("* Work (arc_work) — default"));

        // Listing is registry-only: a missing catalog database remains visible
        // instead of making discovery fail while the user chooses or repairs it.
        fs::remove_file(root(&temp).join("archive.db")).unwrap();
        let still_listed = json(&success(archive(&temp).args(["--json", "list"])));
        assert_eq!(still_listed["archives"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn older_schema_projection_can_be_rebuilt_through_archive_path() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let archive_root = root(&temp);
        let database = archive_root.join("archive.db");
        // This tests dispatch around an unsupported projection header. Rebuild
        // derives its contents from canonical history, not the old table layout.
        rusqlite::Connection::open(&database).unwrap().execute_batch(
            "PRAGMA user_version = 6; UPDATE archive_meta SET value = '6' WHERE key = 'schema_version';",
        ).unwrap();
        let previous = fs::read(&database).unwrap();
        let genesis_path = archive_root.join("canonical/genesis.json");
        let genesis = fs::read(&genesis_path).unwrap();
        let refused = archive(&temp)
            .arg("--archive")
            .arg(&archive_root)
            .args(["collection", "list"])
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("db rebuild"));
        assert!(!String::from_utf8_lossy(&refused.stderr).contains("pre-v2"));
        let rebuilt = json(&success(
            archive(&temp)
                .arg("--archive")
                .arg(&archive_root)
                .args(["--json", "db", "rebuild"]),
        ));
        let retained = rebuilt["previous_database"].as_str().unwrap();
        assert_eq!(fs::read(retained).unwrap(), previous);
        assert_eq!(fs::read(genesis_path).unwrap(), genesis);
        let current = json(&success(
            archive(&temp)
                .arg("--archive")
                .arg(&archive_root)
                .args(["--json", "status"]),
        ));
        assert_eq!(current["schema_version"], 8);
        assert_eq!(current["records"], 3);
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
                    "SELECT COUNT(*) FROM checks WHERE integrity = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(replica_database);

        let base_commit =
            String::from_utf8(git(&primary.join("canonical"), &["rev-parse", "HEAD"]).stdout)
                .unwrap()
                .trim()
                .to_owned();
        let desktop_batch = content.join("desktop-batch");
        fs::create_dir(&desktop_batch).unwrap();
        let desktop_file = desktop_batch.join("desktop-only.txt");
        fs::write(&desktop_file, b"desktop\n").unwrap();
        success(archive(&temp).args([
            "collection",
            "add",
            desktop_batch.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        let laptop_batch = content.join("laptop-batch");
        fs::create_dir(&laptop_batch).unwrap();
        let laptop_file = laptop_batch.join("laptop-only.txt");
        fs::write(&laptop_file, b"laptop\n").unwrap();
        success(archive(&temp).arg("--archive").arg(&replica).args([
            "collection",
            "add",
            laptop_batch.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        success(archive(&temp).args(["sync", "central"]));
        success(archive(&temp).arg("--archive").arg(&replica).args(["sync"]));
        success(archive(&temp).args(["sync", "central"]));
        let changes = json(&success(archive(&temp).args([
            "--json",
            "app",
            "changes",
            "--collection",
            "Files",
            "--since",
            &base_commit,
        ])));
        let paths = changes["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["logical_path"]["display"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                "desktop-batch/desktop-only.txt",
                "laptop-batch/laptop-only.txt"
            ]
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
    fn sync_clone_rejects_an_option_shaped_locator_before_git_runs() {
        let temp = TempDir::new().unwrap();
        let fake_bin = temp.path().join("bin");
        let marker = temp.path().join("git-was-run");
        fs::create_dir(&fake_bin).unwrap();
        let fake_git = fake_bin.join("git");
        fs::write(&fake_git, "#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n").unwrap();
        fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755)).unwrap();

        let output = archive(&temp)
            .env("PATH", &fake_bin)
            .env("MARKER", &marker)
            .args([
                "sync",
                "clone",
                "--",
                "--upload-pack=/tmp/untrusted-program",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("option-shaped"));
        assert!(!marker.exists(), "Git ran before locator validation");
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

    fn immutable_files_fixture() -> (TempDir, PathBuf) {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let content = temp.path().join("files");
        fs::create_dir(&content).unwrap();
        for (name, bytes) in [
            ("a.txt", "original a"),
            ("b.txt", "original b"),
            ("c.txt", "original c"),
        ] {
            fs::write(content.join(name), bytes).unwrap();
        }
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
        success(archive(&temp).args([
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        (temp, content)
    }

    #[test]
    fn scan_engine_commands_announce_resumable_job_only_in_human_mode() {
        let (temp, content) = immutable_files_fixture();
        let scan = |extra: &[&str]| {
            let mut command = archive(&temp);
            command.args(extra).args([
                "location",
                "scan",
                "--path",
                content.to_str().unwrap(),
                "--collection",
                "Files",
                "--max-items",
                "1",
                "--job-id",
            ]);
            command
        };
        let human = success(scan(&[]).arg("job_scan_hint"));
        assert_eq!(
            String::from_utf8(human.stderr).unwrap(),
            "Location scan job job_scan_hint. If interrupted, resume with: archive job resume job_scan_hint\n",
            "redirected stderr gets the hint but no live progress block"
        );
        assert!(String::from_utf8_lossy(&human.stdout)
            .contains("Resume with: archive job resume job_scan_hint"));

        // A fresh scan of the same Location is refused while that job is unfinished.
        success(archive(&temp).args(["job", "cancel", "job_scan_hint"]));
        let machine = success(scan(&["--json"]).arg("job_scan_json"));
        assert!(machine.stderr.is_empty());
        assert_eq!(json(&machine)["status"], "running");
        let resumed = success(archive(&temp).args(["--json", "job", "resume", "job_scan_json"]));
        assert!(resumed.stderr.is_empty());
        assert_eq!(json(&resumed)["status"], "complete");

        for name in ["d.txt", "e.txt"] {
            fs::write(content.join(name), name).unwrap();
        }
        let add = |extra: &[&str], job_id: &str| {
            let mut command = archive(&temp);
            command.args(extra).args([
                "collection",
                "add",
                content.to_str().unwrap(),
                "--collection",
                "Files",
                "--max-items",
                "1",
                "--job-id",
                job_id,
            ]);
            command
        };
        let human = success(&mut add(&[], "job_add_hint"));
        assert_eq!(
            String::from_utf8(human.stderr).unwrap(),
            "Collection add job job_add_hint. If interrupted, resume with: archive job resume job_add_hint\n"
        );
        let machine = success(&mut add(&["--json"], "job_add_json"));
        assert!(machine.stderr.is_empty());
        assert_eq!(json(&machine)["status"], "running");
    }

    #[test]
    fn unfinished_jobs_are_listed_by_default_and_local_only_jobs_are_discoverable() {
        let (temp, content) = immutable_files_fixture();
        let scan = |job_id: &str, max_items: Option<&str>| {
            let mut command = archive(&temp);
            command.args([
                "location",
                "scan",
                "--path",
                content.to_str().unwrap(),
                "--collection",
                "Files",
                "--job-id",
                job_id,
            ]);
            if let Some(max_items) = max_items {
                command.args(["--max-items", max_items]);
            }
            success(&mut command);
        };
        scan("job_finished", None);
        scan("job_paused", Some("1"));
        let ids = |list: &Value, key: &str| -> Vec<String> {
            list[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|job| job["job_id"].as_str().unwrap().to_owned())
                .collect()
        };

        let unfinished = json(&success(archive(&temp).args(["--json", "job", "list"])));
        assert_eq!(ids(&unfinished, "items"), ["job_paused"]);
        assert_eq!(ids(&unfinished, "local_only"), Vec::<String>::new());
        let all = json(&success(
            archive(&temp).args(["--json", "job", "list", "--all"]),
        ));
        assert!(ids(&all, "items").contains(&"job_finished".to_owned()));
        let human =
            String::from_utf8(success(archive(&temp).args(["job", "list"])).stdout).unwrap();
        assert!(human
            .contains("job_paused  running  location_scan  started just now  1 files processed"));
        assert!(!human.contains("job_finished"));
        let status =
            String::from_utf8(archive(&temp).arg("status").output().unwrap().stdout).unwrap();
        assert!(status.contains("1 unfinished job (job_paused); see archive job show job_paused"));
        let shown =
            String::from_utf8(success(archive(&temp).args(["job", "show", "job_paused"])).stdout)
                .unwrap();
        assert!(shown.contains("Last recorded progress: scanning files, 1 files processed"));

        // A rebuild drops the unpublished row; an interrupted run can leave a bare directory.
        success(archive(&temp).args(["db", "rebuild"]));
        fs::create_dir(root(&temp).join("local/jobs/job_orphan")).unwrap();
        let rebuilt = json(&success(archive(&temp).args(["--json", "job", "list"])));
        assert_eq!(ids(&rebuilt, "items"), Vec::<String>::new());
        let local: Vec<_> = rebuilt["local_only"]
            .as_array()
            .unwrap()
            .iter()
            .map(|job| {
                (
                    job["job_id"].as_str().unwrap(),
                    job["job_type"].as_str(),
                    job["state"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            local,
            [
                ("job_orphan", None, "unrecognized"),
                ("job_paused", Some("location_scan"), "resumable"),
            ]
        );
        let shown = json(&success(archive(&temp).args([
            "--json",
            "job",
            "show",
            "job_paused",
        ])));
        assert_eq!(shown["state"], "resumable");
        let status = json(&archive(&temp).args(["--json", "status"]).output().unwrap());
        assert_eq!(status["unfinished_jobs"], 1);
        // Listing is read-only for job state: the orphan stays for inspection.
        assert!(root(&temp).join("local/jobs/job_orphan").is_dir());

        let resumed = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_paused",
        ])));
        assert_eq!(resumed["status"], "complete");
        let after = json(&success(archive(&temp).args(["--json", "job", "list"])));
        assert_eq!(ids(&after, "local_only"), ["job_orphan"]);
        assert_eq!(ids(&after, "items"), Vec::<String>::new());

        // An unexpected entry is reported without hiding database jobs or breaking status.
        scan("job_paused_again", Some("1"));
        fs::write(root(&temp).join("local/jobs/.DS_Store"), b"").unwrap();
        let listed = json(&success(archive(&temp).args(["--json", "job", "list"])));
        assert_eq!(ids(&listed, "items"), ["job_paused_again"]);
        assert!(listed["local_jobs_error"].is_string());
        let human =
            String::from_utf8(success(archive(&temp).args(["job", "list"])).stdout).unwrap();
        assert!(human.contains("WARNING: cannot inspect local job directories"));
        assert!(human.contains("job_paused_again  running"));
        let status = archive(&temp).arg("status").output().unwrap();
        assert!(String::from_utf8_lossy(&status.stdout)
            .contains("WARNING: cannot inspect local job directories"));
        let status = json(&archive(&temp).args(["--json", "status"]).output().unwrap());
        assert_eq!(status["unfinished_jobs"], 1);
        assert!(status["local_jobs_error"].is_string());
    }

    #[test]
    fn job_cancel_removes_only_the_unfinished_jobs_local_files() {
        let (temp, content) = immutable_files_fixture();
        fs::write(content.join("d.txt"), b"d").unwrap();
        let path = content.to_str().unwrap();
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            path,
            "--collection",
            "Files",
            "--job-id",
            "job_scan",
            "--max-items",
            "1",
        ]));
        success(archive(&temp).args([
            "collection",
            "add",
            path,
            "--collection",
            "Files",
            "--job-id",
            "job_add",
            "--max-items",
            "1",
        ]));
        let jobs = root(&temp).join("local/jobs");
        let other_before = fs::read_dir(jobs.join("job_add")).unwrap().count();

        let planned = json(&success(archive(&temp).args([
            "--json",
            "job",
            "cancel",
            "job_scan",
            "--dry-run",
        ])));
        assert_eq!(planned["status"], "planned");
        assert!(planned["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["name"] == "inventory-items.jsonl"));
        assert!(jobs.join("job_scan/inventory-config.json").is_file());

        // A live run holds the job lock; cancel must refuse and delete nothing.
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root(&temp).join("local/job-locks/job_scan.lock"))
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        let busy = archive(&temp)
            .args(["job", "cancel", "job_scan"])
            .output()
            .unwrap();
        assert!(!busy.status.success());
        assert!(String::from_utf8_lossy(&busy.stderr).contains("job_busy"));
        assert!(jobs.join("job_scan/inventory-config.json").is_file());
        drop(lock);

        let cancelled = json(&success(
            archive(&temp).args(["--json", "job", "cancel", "job_scan"]),
        ));
        assert_eq!(cancelled["status"], "cancelled");
        assert_eq!(cancelled["job_type"], "location_scan");
        assert!(!jobs.join("job_scan").exists());
        assert_eq!(
            fs::read_dir(jobs.join("job_add")).unwrap().count(),
            other_before
        );
        let shown = json(&success(
            archive(&temp).args(["--json", "job", "show", "job_scan"]),
        ));
        assert_eq!(shown["status"], "cancelled");
        for args in [
            vec!["job", "resume", "job_scan"],
            vec!["job", "cancel", "job_scan"],
            vec![
                "location",
                "scan",
                "--path",
                path,
                "--collection",
                "Files",
                "--job-id",
                "job_scan",
            ],
        ] {
            let refused = archive(&temp).args(&args).output().unwrap();
            assert!(!refused.status.success(), "{args:?}");
            assert!(
                String::from_utf8_lossy(&refused.stderr).contains("cancelled"),
                "{args:?}"
            );
        }
        success(archive(&temp).args(["fsck"]));
        // A cleanup interrupted after the row was marked cancelled can be finished.
        fs::create_dir(jobs.join("job_scan")).unwrap();
        fs::write(jobs.join("job_scan/inventory-items.jsonl"), b"{}").unwrap();
        success(archive(&temp).args(["job", "cancel", "job_scan"]));
        assert!(!jobs.join("job_scan").exists());

        let resumed = json(&success(
            archive(&temp).args(["--json", "job", "resume", "job_add"]),
        ));
        assert_eq!(resumed["status"], "complete");
        let finished = archive(&temp)
            .args(["job", "cancel", "job_add"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&finished.stderr).contains("already complete"));
        assert!(
            !String::from_utf8_lossy(&finished.stderr).contains("invalid inventory configuration")
        );

        // db rebuild drops the unpublished row; the local job is still cancellable.
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            path,
            "--collection",
            "Files",
            "--job-id",
            "job_local",
            "--max-items",
            "1",
        ]));
        success(archive(&temp).args(["db", "rebuild"]));
        let planned = json(&success(archive(&temp).args([
            "--json",
            "job",
            "cancel",
            "job_local",
            "--dry-run",
        ])));
        assert_eq!(planned["job_type"], "location_scan");
        assert!(jobs.join("job_local").is_dir());
        success(archive(&temp).args(["job", "cancel", "job_local"]));
        assert!(!jobs.join("job_local").exists());
        let gone = archive(&temp)
            .args(["job", "resume", "job_local"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&gone.stderr).contains("not found"));
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn location_scan_refuses_to_strand_an_unfinished_scan_of_the_same_location() {
        let (temp, content) = immutable_files_fixture();
        let other = temp.path().join("other");
        fs::create_dir(&other).unwrap();
        fs::write(other.join("o.txt"), b"o").unwrap();
        success(archive(&temp).args([
            "collection",
            "init",
            other.to_str().unwrap(),
            "--name",
            "Other",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));
        let path = content.to_str().unwrap();
        let scan = |extra: &[&str]| {
            let mut command = archive(&temp);
            command
                .args(["location", "scan", "--path", path, "--collection", "Files"])
                .args(extra);
            command.output().unwrap()
        };
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            path,
            "--collection",
            "Files",
            "--job-id",
            "job_first",
            "--max-items",
            "1",
        ]));
        let job_count = || -> i64 {
            rusqlite::Connection::open(root(&temp).join("archive.db"))
                .unwrap()
                .query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
                .unwrap()
        };
        let job_root = root(&temp).join("local/jobs/job_first");
        let job_files = || {
            fs::read_dir(&job_root)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), fs::read(entry.path()).unwrap())
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let files_before = job_files();
        for rebuild in [false, true] {
            if rebuild {
                success(archive(&temp).args(["db", "rebuild"]));
                let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
                let rows: i64 = database
                    .query_row(
                        "SELECT COUNT(*) FROM jobs WHERE job_id = 'job_first'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(rows, 0, "unfinished job survives only in local files");
            }
            let before = job_count();
            let refused = scan(&[]);
            assert!(
                !refused.status.success(),
                "fresh scan allowed after rebuild={rebuild}"
            );
            let message = String::from_utf8(refused.stderr).unwrap();
            assert!(
                message.starts_with("error [unfinished_scan_job]:"),
                "{message}"
            );
            assert!(message.contains("archive job resume job_first"));
            assert!(message.contains("archive job cancel job_first"));
            for extra in [vec!["--json"], vec!["--json", "--dry-run"]] {
                let refused = scan(&extra);
                assert!(refused.stdout.is_empty());
                let error: Value = serde_json::from_slice(&refused.stderr).unwrap();
                assert_eq!(error["error"]["code"], "unfinished_scan_job");
                assert_eq!(error["error"]["details"]["jobs"][0]["job_id"], "job_first");
                assert_eq!(error["error"]["details"]["jobs"][0]["live"], false);
            }
            assert_eq!(job_count(), before, "a refused scan creates no job");
            assert_eq!(
                job_files(),
                files_before,
                "refusal preserves checkpoint state"
            );
        }

        // Without a projected row, scope cannot be inspected while the job is locked.
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root(&temp).join("local/job-locks/job_first.lock"))
            .unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        let busy = scan(&["--json"]);
        let error: Value = serde_json::from_slice(&busy.stderr).unwrap();
        assert_eq!(error["error"]["code"], "job_busy");
        assert_eq!(job_files(), files_before);
        drop(lock);

        // Other Locations are unaffected, and the unfinished job itself can resume.
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            other.to_str().unwrap(),
            "--collection",
            "Other",
        ]));
        success(archive(&temp).args(["job", "resume", "job_first"]));
        // Completed database rows take precedence over leftover local configuration.
        fs::create_dir_all(&job_root).unwrap();
        fs::write(
            job_root.join("inventory-config.json"),
            b"invalid leftover config",
        )
        .unwrap();
        success(&mut {
            let mut command = archive(&temp);
            command.args(["location", "scan", "--path", path, "--collection", "Files"]);
            command
        });

        // After cancel, a fresh scan proceeds.
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            path,
            "--collection",
            "Files",
            "--job-id",
            "job_second",
            "--max-items",
            "1",
        ]));
        success(archive(&temp).args(["db", "rebuild"]));
        assert!(!scan(&[]).status.success());
        success(archive(&temp).args(["job", "cancel", "job_second"]));
        assert!(scan(&[]).status.success());
    }

    #[test]
    fn catalog_protection_warns_until_history_is_synced_to_a_remote() {
        let (temp, content) = immutable_files_fixture();
        let status = |temp: &TempDir| {
            String::from_utf8(archive(temp).arg("status").output().unwrap().stdout).unwrap()
        };
        let protection = |temp: &TempDir| {
            json(&archive(temp).args(["--json", "status"]).output().unwrap())["catalog_protection"]
                .clone()
        };
        let unprotected = protection(&temp);
        assert_eq!(unprotected["sync_remotes"], 0);
        assert!(unprotected["unsynced_commits"].as_u64().unwrap() > 0);
        assert!(status(&temp).contains(
            "not yet on a sync remote; a local Git commit is not a backup. Next: archive sync remote add"
        ));

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
        assert_eq!(protection(&temp)["next"], "archive sync");
        success(archive(&temp).args(["sync"]));
        let synced = protection(&temp);
        assert_eq!(synced["unsynced_commits"], 0);
        assert!(synced["next"].is_null());
        assert!(!status(&temp).contains("sync remote"));

        // New catalog work is unprotected again until the next sync.
        fs::write(content.join("d.txt"), b"d").unwrap();
        let added = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        assert_eq!(added["catalog_protection"]["unsynced_commits"], 1);
        let scanned = String::from_utf8(
            success(archive(&temp).args([
                "location",
                "scan",
                "--path",
                content.to_str().unwrap(),
                "--collection",
                "Files",
            ]))
            .stdout,
        )
        .unwrap();
        assert!(scanned.contains("WARNING: 2 catalog commits are not yet on a sync remote"));
        success(archive(&temp).args(["sync"]));
        assert_eq!(protection(&temp)["unsynced_commits"], 0);

        // A clone holds exactly the remote's history.
        let clone_env = TempDir::new().unwrap();
        success(archive(&clone_env).args(["sync", "clone", remote.to_str().unwrap()]));
        assert_eq!(protection(&clone_env)["unsynced_commits"], 0);

        // Re-pointing a remote name at new storage must not inherit earlier knowledge.
        let empty = temp.path().join("empty.git");
        fs::create_dir(&empty).unwrap();
        git_success(&empty, &["init", "--bare", "--quiet"]);
        success(archive(&temp).args(["sync", "remote", "remove", "central", "--yes"]));
        success(archive(&temp).args(["sync", "remote", "add", "central", empty.to_str().unwrap()]));
        assert!(protection(&temp)["unsynced_commits"].as_u64().unwrap() > 0);
        assert!(status(&temp).contains("not yet on a sync remote"));

        // If protection cannot be checked, say so instead of looking protected.
        git_success(
            &root(&temp).join("canonical"),
            &[
                "remote",
                "add",
                "unsupported",
                "https://user@example.invalid/x.git",
            ],
        );
        assert!(protection(&temp)["error"].is_string());
        assert!(status(&temp)
            .contains("WARNING: cannot check whether catalog history is on a sync remote"));
    }

    #[test]
    fn unchanged_files_are_not_reread_and_complete_scans_refresh_presence_only() {
        let (temp, content) = immutable_files_fixture();
        let path = content.to_str().unwrap();
        let database_path = root(&temp).join("archive.db");
        let times = |name: &str| -> (i64, i64) {
            rusqlite::Connection::open(&database_path)
                .unwrap()
                .query_row(
                    "SELECT last_seen_time_utc_ms, last_verified_time_utc_ms FROM copy_claims WHERE relative_path_display = ?1",
                    [name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap()
        };
        let age = |seen: i64, verified: i64| {
            let database = rusqlite::Connection::open(&database_path).unwrap();
            age_copy_checks(&database, None, Some(seen), Some(verified));
        };
        // An unreadable but unchanged file proves the scan does not read it.
        let locked = content.join("b.txt");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

        age(1_000, 2_000);
        let original_checks = compact_checks(&temp);
        let added = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "add",
            path,
            "--collection",
            "Files",
        ])));
        assert_eq!(added["summary"]["unchanged_files"], 3);
        assert_eq!(added["summary"]["read_errors"], 0);
        assert_eq!(
            compact_checks(&temp),
            original_checks,
            "add does not invent a check for an unchanged file"
        );
        assert_eq!(
            times("a.txt"),
            (1_000, 2_000),
            "add refreshes neither presence nor integrity"
        );

        let output = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "--path",
                path,
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert!(matches!(output.status.code(), Some(0 | 10)));
        let scanned = json(&output);
        assert_eq!(scanned["status"], "complete");
        assert_eq!(scanned["summary"]["unchanged_files"], 3);
        assert_eq!(scanned["summary"]["read_errors"], 0);
        assert_eq!(scanned["summary"]["confirmed_good"], 0);
        assert_eq!(scanned["verification_due"]["due"], 3);
        let (seen, verified) = times("a.txt");
        assert!(seen > 1_000, "a complete scan refreshes presence");
        assert_eq!(verified, 2_000, "only reading bytes refreshes verification");
        let presence_checks = compact_checks(&temp);
        assert_eq!(&presence_checks[..original_checks.len()], &original_checks);
        assert_eq!(presence_checks.len(), original_checks.len() + 3);
        assert!(
            presence_checks[original_checks.len()..]
                .iter()
                .all(|check| check.3 == 1 && check.4 == 0),
            "complete coverage appends presence-only checks"
        );
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();

        // Human output names the next step; replay reproduces the refreshed presence.
        let human = String::from_utf8(
            archive(&temp)
                .args(["location", "scan", "--path", path, "--collection", "Files"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(human.contains("unchanged files were not re-read; presence refreshed"));
        assert!(human.contains("due for verification"));
        assert!(human.contains("Next: archive verify"));
        let before = times("c.txt").0;
        success(archive(&temp).args(["db", "rebuild"]));
        assert!(times("c.txt").0 >= before);
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn verification_never_revives_missing_paths_or_rereads_short_policies_every_run() {
        let (temp, content) = immutable_files_fixture();
        let path = content.to_str().unwrap();
        // Two paths with identical bytes share one Object.
        fs::write(content.join("twin-1.txt"), b"same bytes").unwrap();
        fs::write(content.join("twin-2.txt"), b"same bytes").unwrap();
        success(archive(&temp).args(["collection", "add", path, "--collection", "Files"]));
        fs::remove_file(content.join("twin-1.txt")).unwrap();
        success(archive(&temp).args(["location", "scan", "--path", path, "--collection", "Files"]));
        let state = |name: &str| -> String {
            rusqlite::Connection::open(root(&temp).join("archive.db"))
                .unwrap()
                .query_row(
                    "SELECT p.state FROM path_observations p JOIN file_refs f USING (file_ref_id) WHERE f.logical_path_display = ?1",
                    [name],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(state("twin-1.txt"), "missing");
        let location = "Files on Test Device";
        let all =
            json(&success(archive(&temp).args([
                "--json", "verify", location, "--path", path, "--all",
            ])));
        assert_eq!(all["summary"]["read_errors"], 0);
        assert_eq!(
            state("twin-1.txt"),
            "missing",
            "verify must not revive a removed path"
        );
        assert_eq!(state("twin-2.txt"), "present");

        // A 30-day Policy is due at most every 15 days, not on every run.
        success(archive(&temp).args([
            "policy",
            "update",
            "Two copies at two sites",
            "--verification-days",
            "30",
        ]));
        let first = json(&success(
            archive(&temp).args(["--json", "verify", location, "--path", path]),
        ));
        assert_eq!(
            first["status"], "idle",
            "copies verified just now are not due"
        );
    }

    #[test]
    fn list_new_streams_all_categories_without_reading_or_recording() {
        use std::os::unix::ffi::OsStringExt;
        let (temp, source) = immutable_files_fixture();
        fs::create_dir(source.join("sub")).unwrap();
        for i in 0..25 {
            fs::write(source.join(format!("sub/known-{i:02}")), b"known").unwrap();
        }
        success(archive(&temp).args([
            "collection",
            "add",
            source.join("sub").to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        let second = temp.path().join("second");
        fs::create_dir(&second).unwrap();
        success(archive(&temp).args([
            "location",
            "init",
            second.to_str().unwrap(),
            "--collection",
            "Files",
            "--location-name",
            "Second",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));
        let sub = second.join("sub");
        fs::create_dir(&sub).unwrap();
        for i in 0..25 {
            fs::write(sub.join(format!("known-{i:02}")), b"known").unwrap();
            fs::write(sub.join(format!("new-{i:02}")), b"new").unwrap();
        }
        // Names are lossless in JSON, and human output safely quotes control characters.
        let raw = std::ffi::OsString::from_vec(b"raw-\xff\nname".to_vec());
        fs::write(sub.join(&raw), b"raw").unwrap();
        fs::set_permissions(sub.join("new-00"), fs::Permissions::from_mode(0o000)).unwrap();
        fs::create_dir(sub.join("skip")).unwrap();
        fs::write(sub.join("skip/excluded"), b"skip").unwrap();
        fs::write(second.join("outside-subtree"), b"outside").unwrap();
        std::os::unix::fs::symlink("new-00", sub.join("ordinary-link")).unwrap();
        let db = root(&temp).join("archive.db");
        let before = fs::read(&db).unwrap();
        let head = git(&root(&temp).join("canonical"), &["rev-parse", "HEAD"]);
        let list = |machine: bool| {
            let mut command = archive(&temp);
            if machine {
                command.arg("--json");
            }
            command.args([
                "collection",
                "add",
                sub.to_str().unwrap(),
                "--collection",
                "Files",
                "--location",
                "Second",
                "--dry-run",
                "--list-new",
                "--exclude",
                "skip",
            ]);
            command.output().unwrap()
        };
        let output = list(true);
        assert_eq!(
            output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value = json(&output);
        assert_eq!(value["complete"], true);
        assert_eq!(value["summary"]["new_to_collection"], 26);
        assert_eq!(value["summary"]["new_to_location"], 25);
        assert_eq!(value["summary"]["excluded_subtrees"], 1);
        assert_eq!(value["summary"]["ignored_symlinks"], 1);
        assert!(value.get("verification_due").is_none());
        let items = value["items"].as_array().unwrap();
        assert_eq!(items.len(), 51);
        assert_eq!(
            items
                .iter()
                .filter(|v| v["kind"] == "new_to_collection")
                .count(),
            26
        );
        assert_eq!(
            items
                .iter()
                .filter(|v| v["kind"] == "new_to_location")
                .count(),
            25
        );
        for item in items {
            assert!(item["path"]["display"]
                .as_str()
                .unwrap()
                .starts_with("sub/"));
        }
        let encoded = items
            .iter()
            .find(|v| v["path"]["encoding"] == "unix_bytes")
            .unwrap();
        let decoded: archive_ledger::RegistryPath =
            serde_json::from_value(encoded["path"].clone()).unwrap();
        assert_eq!(
            decoded.to_path_buf().unwrap(),
            PathBuf::from("sub").join(&raw)
        );
        let human = list(false);
        assert_eq!(human.status.code(), Some(10));
        let text = String::from_utf8(human.stdout).unwrap();
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("new-to-"))
                .count(),
            51
        );
        assert!(text.contains("Listing complete"));
        assert_eq!(before, fs::read(&db).unwrap());
        assert_eq!(
            head,
            git(&root(&temp).join("canonical"), &["rev-parse", "HEAD"])
        );

        // Directory read failures produce an explicit partial result, never a clean empty list.
        fs::create_dir(sub.join("unreadable")).unwrap();
        fs::set_permissions(sub.join("unreadable"), fs::Permissions::from_mode(0o000)).unwrap();
        let partial = list(true);
        assert_eq!(partial.status.code(), Some(10));
        let partial = json(&partial);
        assert_eq!(partial["complete"], false);
        assert!(partial["summary"]["traversal_errors"].as_u64().unwrap() > 0);
        fs::set_permissions(sub.join("unreadable"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(before, fs::read(&db).unwrap());

        // Existing-but-unverified files are not mislabeled as new.
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute("UPDATE checks SET integrity=0", []).unwrap();
        drop(conn);
        let known = archive(&temp)
            .args([
                "--json",
                "collection",
                "add",
                source.to_str().unwrap(),
                "--collection",
                "Files",
                "--dry-run",
                "--list-new",
            ])
            .output()
            .unwrap();
        assert_eq!(
            known.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&known.stderr)
        );
        assert_eq!(json(&known)["items"].as_array().unwrap().len(), 0);
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute("UPDATE file_objects SET content_id=NULL,identity_state='unresolved' WHERE path_bytes=?1", [b"a.txt".as_slice()]).unwrap();
        drop(conn);
        let failed = archive(&temp)
            .args([
                "--json",
                "collection",
                "add",
                source.to_str().unwrap(),
                "--collection",
                "Files",
                "--dry-run",
                "--list-new",
            ])
            .output()
            .unwrap();
        assert_eq!(failed.status.code(), Some(2));
        let failed = json(&failed);
        assert_eq!(failed["complete"], false);
        assert!(failed["error"]["code"].is_string());
        for extra in [
            vec!["--list-new"],
            vec!["--dry-run", "--list-new", "--accept-changes", "a.txt"],
        ] {
            let invalid = archive(&temp)
                .args(["collection", "add", source.to_str().unwrap()])
                .args(extra)
                .output()
                .unwrap();
            assert_eq!(invalid.status.code(), Some(2));
        }
    }

    #[test]
    fn scan_and_add_dry_runs_classify_differences_without_reading_or_writing() {
        let (temp, content) = immutable_files_fixture();
        let path = content.to_str().unwrap();
        let database_path = root(&temp).join("archive.db");
        let snapshot = || {
            let records = json(&success(
                archive(&temp).args(["--json", "events", "verify"]),
            ))["records"]
                .clone();
            (fs::read(&database_path).unwrap(), records)
        };
        age_copy_checks(
            &rusqlite::Connection::open(&database_path).unwrap(),
            Some("c.txt"),
            Some(1000),
            None,
        );
        for index in 0..25 {
            fs::write(content.join(format!("new-{index:02}.txt")), b"n").unwrap();
        }
        fs::write(content.join("a.txt"), b"edited contents").unwrap();
        fs::remove_file(content.join("b.txt")).unwrap();
        // Unreadable files prove that no content is read.
        for name in ["a.txt", "new-00.txt"] {
            fs::set_permissions(content.join(name), fs::Permissions::from_mode(0o000)).unwrap();
        }
        let before = snapshot();
        let scan = |extra: &[&str]| {
            let mut command = archive(&temp);
            command
                .arg("--json")
                .args([
                    "location",
                    "scan",
                    "--path",
                    path,
                    "--collection",
                    "Files",
                    "--dry-run",
                ])
                .args(extra);
            command.output().unwrap()
        };
        let planned = scan(&[]);
        assert_eq!(planned.status.code(), Some(10));
        let planned = json(&planned);
        let preview = &planned["preview"];
        assert_eq!(planned["status"], "planned");
        assert_eq!(preview["new_files"]["count"], 25);
        assert_eq!(preview["new_files"]["paths"].as_array().unwrap().len(), 20);
        assert_eq!(preview["new_files"]["truncated"], true);
        assert_eq!(preview["new_files"]["paths"][0], "new-00.txt");
        assert_eq!(preview["changed"]["paths"], serde_json::json!(["a.txt"]));
        assert_eq!(preview["missing"]["paths"], serde_json::json!(["b.txt"]));
        assert_eq!(preview["unchanged"], 1);
        assert_eq!(planned["presence_stale"], 1);
        assert_eq!(planned["actionable"], true);
        let added = archive(&temp)
            .args([
                "--json",
                "collection",
                "add",
                path,
                "--collection",
                "Files",
                "--dry-run",
            ])
            .output()
            .unwrap();
        assert_eq!(added.status.code(), Some(10));
        let added = json(&added);
        assert_eq!(added["mode"], "add");
        assert_eq!(
            added["preview"]["missing"]["count"], 0,
            "add never marks missing"
        );
        assert_eq!(snapshot(), before, "a dry run records nothing");

        // After the matching real run only persistent corruption remains actionable.
        for name in ["a.txt", "new-00.txt"] {
            fs::set_permissions(content.join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        fs::write(content.join("a.txt"), b"original a").unwrap();
        success(archive(&temp).args(["location", "scan", "--path", path, "--collection", "Files"]));
        let clean = scan(&[]);
        assert_eq!(
            clean.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&clean.stdout)
        );
        assert_eq!(json(&clean)["actionable"], false);

        // The suggested command covers the same files as the preview.
        fs::create_dir(content.join("cache")).unwrap();
        fs::write(content.join("cache/tmp.bin"), b"t").unwrap();
        fs::write(content.join("late.txt"), b"late").unwrap();
        let excluded = json(&scan(&["--exclude", "cache"]));
        assert_eq!(
            excluded["preview"]["new_files"]["paths"],
            serde_json::json!(["late.txt"])
        );
        assert!(
            excluded["next"]
                .as_str()
                .unwrap()
                .ends_with("--exclude 'cache'"),
            "{excluded}"
        );
        let added = json(
            &archive(&temp)
                .args([
                    "--json",
                    "collection",
                    "add",
                    path,
                    "--collection",
                    "Files",
                    "--dry-run",
                    "--exclude",
                    "cache",
                ])
                .output()
                .unwrap(),
        );
        assert!(
            added["next"].as_str().unwrap().contains("--location "),
            "{added}"
        );
    }

    #[test]
    fn integrity_report_locates_verified_copies_of_corrupt_content() {
        let (temp, content) = immutable_files_fixture();
        let backup = temp.path().join("backup");
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("a.txt"), b"original a").unwrap();
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
        let clean = json(&success(archive(&temp).args([
            "--json",
            "report",
            "integrity",
        ])));
        assert_eq!(clean["corrupt_copies"], 0);

        // Bit rot on the backup keeps size and mtime; only a full verify finds it.
        let rotted = backup.join("a.txt");
        let modified = fs::metadata(&rotted).unwrap().modified().unwrap();
        fs::write(&rotted, b"original X").unwrap();
        fs::File::options()
            .write(true)
            .open(&rotted)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        let verified = archive(&temp)
            .args([
                "verify",
                "Backup",
                "--path",
                backup.to_str().unwrap(),
                "--all",
            ])
            .output()
            .unwrap();
        assert_eq!(verified.status.code(), Some(10));
        // The only copy of c.txt is damaged too.
        fs::write(content.join("c.txt"), b"damaged c").unwrap();
        let _ = archive(&temp)
            .args([
                "location",
                "scan",
                "--path",
                content.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();

        let report = archive(&temp)
            .args(["--json", "report", "integrity"])
            .output()
            .unwrap();
        assert_eq!(report.status.code(), Some(10));
        let report = json(&report);
        assert_eq!(report["corrupt_copies"], 2);
        let item = |logical: &str| {
            report["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["logical_path"] == logical)
                .unwrap()
                .clone()
        };
        let a = item("a.txt");
        assert_eq!(a["corrupt_copy"]["location_name"], "Backup");
        let good = a["good_copies"].as_array().unwrap();
        assert_eq!(good.len(), 1);
        assert_eq!(good[0]["location_name"], "Files on Test Device");
        assert_eq!(good[0]["path"], "a.txt");
        assert!(good[0]["connected"].is_boolean());
        assert_eq!(item("c.txt")["good_copies"], serde_json::json!([]));

        let human = String::from_utf8(
            archive(&temp)
                .args(["report", "integrity"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(
            human.contains("good copy: Files on Test Device (a.txt"),
            "{human}"
        );
        assert!(
            human.contains("no verified copy remains in the Archive"),
            "{human}"
        );
        assert!(human.contains("then run archive verify"), "{human}");
    }

    #[test]
    fn repair_replaces_corrupt_copies_from_verified_sources_and_keeps_the_bytes() {
        let (temp, content) = immutable_files_fixture();
        let main = content.to_str().unwrap();
        let backup = temp.path().join("backup");
        fs::create_dir(&backup).unwrap();
        fs::write(backup.join("a.txt"), b"original a").unwrap();
        fs::write(backup.join("b.txt"), b"original b").unwrap();
        // A read-only directory, as git-annex object directories are.
        for root in [&content, &backup] {
            fs::create_dir(root.join("locked")).unwrap();
            fs::write(root.join("locked/d.txt"), b"original d").unwrap();
        }
        success(archive(&temp).args(["collection", "add", main, "--collection", "Files"]));
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
        let backup_path = backup.to_str().unwrap();
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            backup_path,
            "--collection",
            "Files",
        ]));
        // Bit rot keeps size and modification time.
        let rot = |path: &Path, bytes: &[u8]| {
            let modified = fs::metadata(path).unwrap().modified().unwrap();
            fs::write(path, bytes).unwrap();
            fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(modified)
                .unwrap();
            modified
        };
        let a_modified = rot(&backup.join("a.txt"), b"original X");
        rot(&backup.join("locked/d.txt"), b"original Q");
        fs::set_permissions(backup.join("locked"), fs::Permissions::from_mode(0o555)).unwrap();
        rot(&content.join("c.txt"), b"original Z");
        // An edit changes size and modification time.
        fs::write(backup.join("b.txt"), b"edited b, longer").unwrap();
        for (location, path) in [("Backup", backup_path), ("Files on Test Device", main)] {
            let _ = archive(&temp)
                .args(["verify", location, "--path", path, "--all"])
                .output()
                .unwrap();
        }
        let _ = archive(&temp)
            .args([
                "location",
                "scan",
                "--path",
                backup_path,
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        let repair = |extra: &[&str]| {
            let mut command = archive(&temp);
            command.arg("--json").arg("repair").args(extra);
            command.output().unwrap()
        };
        let status = |report: &Value, logical: &str| {
            report["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["logical_path"] == logical)
                .unwrap()["status"]
                .clone()
        };

        let before = fs::read(backup.join("a.txt")).unwrap();
        let planned = repair(&["Backup", "--path", backup_path, "--dry-run"]);
        assert_eq!(planned.status.code(), Some(10));
        let planned = json(&planned);
        assert_eq!(status(&planned, "a.txt"), "planned");
        assert_eq!(
            planned["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["logical_path"] == "a.txt")
                .unwrap()["source"]["path"],
            "a.txt"
        );
        assert_eq!(status(&planned, "b.txt"), "skipped_changed");
        assert_eq!(
            fs::read(backup.join("a.txt")).unwrap(),
            before,
            "a dry run changes nothing"
        );
        let main_plan = json(&repair(&[
            "Files on Test Device",
            "--path",
            main,
            "--dry-run",
        ]));
        assert_eq!(status(&main_plan, "c.txt"), "no_source");
        let refused = repair(&["Backup", "--path", backup_path, "--non-interactive"]);
        assert!(!refused.status.success());

        let repaired = repair(&[
            "Backup",
            "--path",
            backup_path,
            "--yes",
            "--job-id",
            "job_repair",
        ]);
        assert_eq!(repaired.status.code(), Some(10), "b.txt remains unresolved");
        let repaired = json(&repaired);
        assert_eq!(status(&repaired, "a.txt"), "repaired");
        assert_eq!(status(&repaired, "locked/d.txt"), "repaired");
        assert_eq!(
            fs::read(backup.join("locked/d.txt")).unwrap(),
            b"original d"
        );
        assert_eq!(
            fs::metadata(backup.join("locked"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555,
            "a read-only directory is restored"
        );
        assert_eq!(fs::read(backup.join("a.txt")).unwrap(), b"original a");
        assert_eq!(
            fs::metadata(backup.join("a.txt"))
                .unwrap()
                .modified()
                .unwrap(),
            a_modified
        );
        let kept = backup.join(".archive-ledger/quarantine/job_repair/a.txt");
        assert_eq!(
            fs::read(&kept).unwrap(),
            b"original X",
            "the corrupt bytes are preserved"
        );
        assert_eq!(
            fs::read(backup.join("b.txt")).unwrap(),
            b"edited b, longer",
            "an edit is left alone"
        );
        let rescanned = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "--path",
                backup_path,
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(rescanned.status.code(), Some(10), "b.txt is still corrupt");
        let rescanned = json(&rescanned);
        assert_eq!(
            rescanned["summary"]["new_paths"], 0,
            "scans ignore the quarantine"
        );
        let integrity = json(
            &archive(&temp)
                .args(["--json", "report", "integrity"])
                .output()
                .unwrap(),
        );
        assert!(integrity["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["logical_path"] != "a.txt"));

        let changed = json(&success(archive(&temp).args([
            "--json",
            "repair",
            "Backup",
            "--path",
            backup_path,
            "--yes",
            "--include-changed",
        ])));
        assert_eq!(status(&changed, "b.txt"), "repaired");
        assert_eq!(fs::read(backup.join("b.txt")).unwrap(), b"original b");

        // Resume after a crash between quarantining the corrupt file and placing the replacement.
        rot(&backup.join("a.txt"), b"original Y");
        let _ = archive(&temp)
            .args(["verify", "Backup", "--path", backup_path, "--all"])
            .output()
            .unwrap();
        let area = backup.join(".archive-ledger/quarantine/job_resume");
        fs::create_dir_all(area.join(".staged")).unwrap();
        fs::rename(backup.join("a.txt"), area.join("a.txt")).unwrap();
        fs::write(area.join(".staged/a.txt"), b"original a").unwrap();
        let resumed = json(&success(archive(&temp).args([
            "--json",
            "repair",
            "Backup",
            "--path",
            backup_path,
            "--yes",
            "--job-id",
            "job_resume",
        ])));
        assert_eq!(status(&resumed, "a.txt"), "repaired");
        assert_eq!(fs::read(backup.join("a.txt")).unwrap(), b"original a");
        assert_eq!(fs::read(area.join("a.txt")).unwrap(), b"original Y");
        // A two-step no-replace move (link, then unlink) interrupted after the link
        // leaves the corrupt file at both paths; resume removes only the extra link.
        rot(&backup.join("a.txt"), b"original W");
        let _ = archive(&temp)
            .args(["verify", "Backup", "--path", backup_path, "--all"])
            .output()
            .unwrap();
        let area = backup.join(".archive-ledger/quarantine/job_linked");
        fs::create_dir_all(area.join(".staged")).unwrap();
        fs::hard_link(backup.join("a.txt"), area.join("a.txt")).unwrap();
        fs::write(area.join(".staged/a.txt"), b"original a").unwrap();
        let linked = json(&success(archive(&temp).args([
            "--json",
            "repair",
            "Backup",
            "--path",
            backup_path,
            "--yes",
            "--job-id",
            "job_linked",
        ])));
        assert_eq!(status(&linked, "a.txt"), "repaired");
        assert_eq!(fs::read(backup.join("a.txt")).unwrap(), b"original a");
        assert_eq!(fs::read(area.join("a.txt")).unwrap(), b"original W");

        // Good bytes already in place but not yet recorded: record without moving anything.
        let modified = rot(&backup.join("a.txt"), b"original V");
        let _ = archive(&temp)
            .args(["verify", "Backup", "--path", backup_path, "--all"])
            .output()
            .unwrap();
        fs::write(backup.join("a.txt"), b"original a").unwrap();
        fs::File::options()
            .write(true)
            .open(backup.join("a.txt"))
            .unwrap()
            .set_modified(modified)
            .unwrap();
        let recorded = json(&success(archive(&temp).args([
            "--json",
            "repair",
            "Backup",
            "--path",
            backup_path,
            "--yes",
            "--job-id",
            "job_recorded",
        ])));
        assert_eq!(status(&recorded, "a.txt"), "repaired");
        assert!(
            !backup
                .join(".archive-ledger/quarantine/job_recorded/a.txt")
                .exists(),
            "good bytes are not quarantined"
        );
        let integrity = json(
            &archive(&temp)
                .args(["--json", "report", "integrity"])
                .output()
                .unwrap(),
        );
        assert!(integrity["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["logical_path"] != "a.txt"));
        success(archive(&temp).args(["fsck"]));
        fs::set_permissions(backup.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn immutable_file_object(temp: &TempDir, name: &str) -> String {
        rusqlite::Connection::open(root(temp).join("archive.db"))
            .unwrap()
            .query_row(
                "SELECT object_id FROM file_refs WHERE logical_path_display = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn immutable_projection_state(temp: &TempDir) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
        let database = rusqlite::Connection::open(root(temp).join("archive.db")).unwrap();
        [
            "file_refs",
            "path_observations",
            "copy_claims",
            "file_checks",
            "objects",
        ]
        .into_iter()
        .map(|table| {
            // Logical views exclude locally allocated integer identities.
            let query = format!("SELECT * FROM {table}");
            let columns = database.prepare(&query).unwrap().column_count();
            let ordering = (1..=columns)
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let mut statement = database
                .prepare(&format!("{query} ORDER BY {ordering}"))
                .unwrap();
            let columns = statement.column_count();
            statement
                .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .collect()
    }

    fn regular_file_tree(path: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        let mut files = std::collections::BTreeMap::new();
        if path.exists() {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    for (name, bytes) in regular_file_tree(&entry.path()) {
                        files.insert(PathBuf::from(entry.file_name()).join(name), bytes);
                    }
                } else if entry.file_type().unwrap().is_file() {
                    files.insert(
                        PathBuf::from(entry.file_name()),
                        fs::read(entry.path()).unwrap(),
                    );
                }
            }
        }
        files
    }

    #[test]
    fn immutable_scan_reports_corruption_preserves_identity_and_recovers_restored_bytes() {
        let (temp, content) = immutable_files_fixture();
        let expected = immutable_file_object(&temp, "a.txt");
        let original_checks = compact_checks(&temp);
        fs::write(content.join("a.txt"), b"different and longer contents").unwrap();
        // A metadata-only change must still confirm the same content identity.
        fs::File::options()
            .write(true)
            .open(content.join("b.txt"))
            .unwrap()
            .set_times(
                fs::FileTimes::new()
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(123456)),
            )
            .unwrap();
        let output = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "--path",
                content.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary = json(&output)["summary"].clone();
        assert_eq!(summary["integrity_mismatches"], 1);
        assert_eq!(summary["changed_paths"], 0);
        // b.txt changed only its mtime, so it is re-read; c.txt is unchanged and skipped.
        assert_eq!(summary["confirmed_good"], 1);
        assert_eq!(summary["unchanged_files"], 1);
        let checked = compact_checks(&temp);
        assert_eq!(
            &checked[..original_checks.len()],
            &original_checks,
            "new observations never overwrite prior checks"
        );
        let appended = &checked[original_checks.len()..];
        assert_eq!(appended.iter().filter(|check| check.4 == 1).count(), 1);
        assert_eq!(appended.iter().filter(|check| check.4 == 2).count(), 1);
        assert_eq!(immutable_file_object(&temp, "a.txt"), expected);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let corrupt: (String, String, String, Option<String>) = database.query_row(
            "SELECT object_id, state, last_verification_result, last_error_code FROM copy_claims WHERE relative_path_display = 'a.txt' AND state != 'superseded'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(
            (&corrupt.0, corrupt.1.as_str(), corrupt.2.as_str()),
            (&expected, "corrupt", "hash_mismatch")
        );
        assert!(corrupt.3.is_some());
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM checks WHERE integrity = 2",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            canonical_hash_results(&temp, "blake3", "hash_mismatch", Some(&expected)),
            1
        );
        drop(database);
        let before = immutable_projection_state(&temp);
        success(archive(&temp).args(["db", "apply"]));
        assert_eq!(
            compact_checks(&temp),
            checked,
            "reapplying committed events must not duplicate checks"
        );
        success(archive(&temp).args(["db", "rebuild"]));
        assert_eq!(immutable_projection_state(&temp), before);

        // The additive command follows the same immutable default.
        let output = archive(&temp)
            .args([
                "collection",
                "add",
                content.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(10));
        let findings = String::from_utf8_lossy(&output.stdout);
        assert!(findings.contains("content differs from catalog"));
        assert!(findings.contains("a.txt"));
        assert!(findings.contains("--accept-changes FILE --dry-run"));
        assert_eq!(immutable_file_object(&temp, "a.txt"), expected);

        fs::write(content.join("a.txt"), b"original a").unwrap();
        let restored = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "--path",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        assert_eq!(restored["summary"]["integrity_mismatches"], 0);
        // The corrupt copy is always re-read; the two untouched files are skipped.
        assert_eq!(restored["summary"]["confirmed_good"], 1);
        assert_eq!(restored["summary"]["unchanged_files"], 2);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let restored: (String, String, String, Option<String>, Option<String>) = database.query_row(
            "SELECT object_id, state, last_verification_result, last_error_code, last_error_detail FROM copy_claims WHERE relative_path_display = 'a.txt' AND state != 'superseded'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).unwrap();
        assert_eq!(
            restored,
            (expected.clone(), "present".into(), "ok".into(), None, None)
        );
        drop(database);
        // Disappearance does not grant permission to redefine the same path
        // when it later reappears with different bytes.
        fs::remove_file(content.join("a.txt")).unwrap();
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        fs::write(
            content.join("a.txt"),
            b"unexpected replacement after disappearance",
        )
        .unwrap();
        let reappeared = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "--path",
                content.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(reappeared.status.code(), Some(10));
        assert_eq!(json(&reappeared)["summary"]["integrity_mismatches"], 1);
        assert_eq!(immutable_file_object(&temp, "a.txt"), expected);
        let before = immutable_projection_state(&temp);
        success(archive(&temp).args(["db", "rebuild"]));
        assert_eq!(immutable_projection_state(&temp), before);
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn immutable_acceptance_is_explicit_read_only_when_planned_and_scoped_when_resumed() {
        let (temp, content) = immutable_files_fixture();
        let original_objects: Vec<_> = ["a.txt", "b.txt", "c.txt"]
            .map(|name| immutable_file_object(&temp, name))
            .into();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(
                content.join(name),
                format!("intentional new contents of {name}"),
            )
            .unwrap();
        }
        let canonical = regular_file_tree(&root(&temp).join("canonical"));
        let jobs = regular_file_tree(&root(&temp).join("local/jobs"));
        let database = fs::read(root(&temp).join("archive.db")).unwrap();
        for controls in [
            &["--dry-run", "--non-interactive"][..],
            &["--non-interactive"][..],
        ] {
            let output = archive(&temp)
                .args([
                    "--json",
                    "collection",
                    "add",
                    content.to_str().unwrap(),
                    "--collection",
                    "Files",
                    "--accept-changes",
                    "a.txt",
                    "--accept-changes",
                    "b.txt",
                ])
                .args(controls)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(if controls.contains(&"--dry-run") {
                    0
                } else {
                    2
                }),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            if controls.contains(&"--dry-run") {
                let preview = json(&output);
                assert_eq!(preview["status"], "planned");
                let items = preview["items"].as_array().unwrap();
                assert_eq!(items.len(), 2);
                for item in items {
                    assert_eq!(item["changed"], true);
                    assert_ne!(item["expected_object_id"], item["observed_object_id"]);
                    assert!(original_objects[..2]
                        .iter()
                        .any(|expected| item["expected_object_id"] == *expected));
                }
            }
            assert_eq!(regular_file_tree(&root(&temp).join("canonical")), canonical);
            assert_eq!(regular_file_tree(&root(&temp).join("local/jobs")), jobs);
            assert_eq!(fs::read(root(&temp).join("archive.db")).unwrap(), database);
        }
        let paused = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
            "--accept-changes",
            "a.txt",
            "--accept-changes",
            "b.txt",
            "--yes",
            "--non-interactive",
            "--max-items",
            "1",
            "--job-id",
            "job_accept_selected",
        ])));
        assert_eq!(paused["status"], "running");
        let resumed = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_accept_selected",
        ])));
        assert_eq!(resumed["status"], "complete");
        assert_eq!(resumed["summary"]["files_observed"], 2);
        assert_eq!(resumed["summary"]["changed_paths"], 2);
        assert_eq!(resumed["summary"]["integrity_mismatches"], 0);
        for (index, name) in ["a.txt", "b.txt"].into_iter().enumerate() {
            assert_ne!(immutable_file_object(&temp, name), original_objects[index]);
        }
        assert_eq!(immutable_file_object(&temp, "c.txt"), original_objects[2]);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(database.query_row(
            "SELECT COUNT(*) FROM checks c JOIN file_locations p ON p.id = c.file_location_id JOIN file_objects f ON f.id = p.file_id WHERE f.path_encoding = 'utf8' AND f.path_bytes = CAST('c.txt' AS BLOB) AND c.integrity != 0", [], |row| row.get::<_, i64>(0),
        ).unwrap(), 1, "unselected changed file was hashed during acceptance");
        drop(database);
        for name in ["a.txt", "b.txt", "c.txt"] {
            assert_eq!(
                fs::read_to_string(content.join(name)).unwrap(),
                format!("intentional new contents of {name}")
            );
        }
        let before = immutable_projection_state(&temp);
        success(archive(&temp).args(["db", "rebuild"]));
        assert_eq!(immutable_projection_state(&temp), before);
    }

    #[test]
    fn immutable_mismatch_at_a_new_location_rebuilds_and_resume_keeps_finding_exit_status() {
        let (temp, _) = immutable_files_fixture();
        let expected = immutable_file_object(&temp, "a.txt");
        let backup = temp.path().join("backup");
        fs::create_dir(&backup).unwrap();
        fs::write(
            backup.join("a.txt"),
            b"wrong first copy at another location",
        )
        .unwrap();
        fs::write(backup.join("b.txt"), b"original b").unwrap();
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
        let paused = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "--path",
                backup.to_str().unwrap(),
                "--collection",
                "Files",
                "--max-items",
                "1",
                "--job-id",
                "job_mismatch_resume",
            ])
            .output()
            .unwrap();
        assert!(matches!(paused.status.code(), Some(0 | 10)));
        assert_eq!(json(&paused)["status"], "running");
        let resumed = archive(&temp)
            .args(["--json", "job", "resume", "job_mismatch_resume"])
            .output()
            .unwrap();
        assert_eq!(
            resumed.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(json(&resumed)["summary"]["integrity_mismatches"], 1);
        assert_eq!(immutable_file_object(&temp, "a.txt"), expected);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let copies = database.prepare(
            "SELECT l.display_name, c.object_id, c.state FROM copy_claims c JOIN locations l USING (location_id) WHERE c.relative_path_display = 'a.txt' ORDER BY l.display_name"
        ).unwrap().query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
            .unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(
            copies,
            vec![
                ("Backup".into(), expected.clone(), "corrupt".into()),
                ("Files on Test Device".into(), expected, "present".into())
            ]
        );
        drop(database);
        let before = immutable_projection_state(&temp);
        success(archive(&temp).args(["db", "rebuild"]));
        assert_eq!(immutable_projection_state(&temp), before);
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn immutable_acceptance_rejects_nonfiles_untracked_paths_and_path_escapes_without_changes() {
        use std::os::unix::fs::symlink;

        let (temp, content) = immutable_files_fixture();
        fs::create_dir(content.join("subdir")).unwrap();
        fs::create_dir(content.join(".git")).unwrap();
        fs::write(content.join(".git/config"), b"not collection content").unwrap();
        fs::write(
            content.join("untracked.txt"),
            b"new file requires normal add",
        )
        .unwrap();
        symlink("a.txt", content.join("alias.txt")).unwrap();
        symlink(&content, content.join("subdir/link")).unwrap();
        let canonical = regular_file_tree(&root(&temp).join("canonical"));
        let database = fs::read(root(&temp).join("archive.db")).unwrap();
        let jobs = regular_file_tree(&root(&temp).join("local/jobs"));
        for selected in [
            "../files/a.txt",
            "subdir",
            "alias.txt",
            "subdir/link/a.txt",
            "untracked.txt",
            ".git/config",
            "absent.txt",
        ] {
            let output = archive(&temp)
                .args([
                    "collection",
                    "add",
                    content.to_str().unwrap(),
                    "--collection",
                    "Files",
                    "--accept-changes",
                    "a.txt",
                    "--accept-changes",
                    selected,
                    "--yes",
                    "--non-interactive",
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "unexpectedly accepted {selected}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(regular_file_tree(&root(&temp).join("canonical")), canonical);
            assert_eq!(fs::read(root(&temp).join("archive.db")).unwrap(), database);
            assert_eq!(regular_file_tree(&root(&temp).join("local/jobs")), jobs);
        }
    }

    #[test]
    fn immutable_acceptance_cannot_redefine_an_imported_annex_identity() {
        let (temp, _) = immutable_files_fixture();
        let repo = inventory_only_annex_fixture(&temp);
        success(archive(&temp).args([
            "location",
            "import-annex",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
            "--location-name",
            "Annex",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
            "--inventory-only",
        ]));
        // Make the tracked annex path an ordinary unlocked file so the refusal
        // exercises its canonical identity, rather than generic symlink checks.
        fs::remove_file(repo.join("src/sha256")).unwrap();
        fs::write(
            repo.join("src/sha256"),
            b"an intentional edit cannot redefine an annex key",
        )
        .unwrap();
        let canonical = regular_file_tree(&root(&temp).join("canonical"));
        let database = fs::read(root(&temp).join("archive.db")).unwrap();
        let jobs = regular_file_tree(&root(&temp).join("local/jobs"));
        let refused = archive(&temp)
            .args([
                "collection",
                "add",
                repo.to_str().unwrap(),
                "--collection",
                "Files",
                "--accept-changes",
                "src/sha256",
                "--yes",
                "--non-interactive",
            ])
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("annex"));
        assert_eq!(regular_file_tree(&root(&temp).join("canonical")), canonical);
        assert_eq!(fs::read(root(&temp).join("archive.db")).unwrap(), database);
        assert_eq!(regular_file_tree(&root(&temp).join("local/jobs")), jobs);

        // Resolving an annex-origin File does not prevent ordinary backups
        // from establishing copies against its unchanged canonical identity.
        fs::write(repo.join("src/sha256"), b"available sha256").unwrap();
        let scanned = archive(&temp)
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
        // The fixture deliberately includes a separate corrupt annex object.
        assert_eq!(scanned.status.code(), Some(10));
        assert_eq!(json(&scanned)["summary"]["integrity_mismatches"], 1);
        let identity = || {
            rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap().query_row(
                "SELECT object_id, external_identity_id FROM file_refs WHERE logical_path_display = 'src/sha256'",
                [], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ).unwrap()
        };
        let expected_identity = identity();
        let backup = temp.path().join("ordinary-annex-backup");
        fs::create_dir_all(backup.join("src")).unwrap();
        fs::write(backup.join("src/sha256"), b"available sha256").unwrap();
        success(archive(&temp).args([
            "location",
            "init",
            backup.to_str().unwrap(),
            "--collection",
            "Files",
            "--location-name",
            "Ordinary Backup",
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
            backup.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        success(archive(&temp).args([
            "location",
            "scan",
            "--path",
            backup.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        assert_eq!(identity(), expected_identity);
        fs::write(backup.join("src/sha256"), b"damaged ordinary backup").unwrap();
        let corrupt = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "--path",
                backup.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert_eq!(corrupt.status.code(), Some(10));
        assert_eq!(json(&corrupt)["summary"]["integrity_mismatches"], 1);
        assert_eq!(identity(), expected_identity);
        let connection = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let copy: (String, String, String) = connection.query_row(
            "SELECT c.object_id, c.state, c.last_verification_result FROM copy_claims c JOIN locations l USING (location_id) WHERE l.display_name = 'Ordinary Backup' AND c.relative_path_display = 'src/sha256' AND c.state != 'superseded'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(
            copy,
            (
                expected_identity.0,
                "corrupt".into(),
                "hash_mismatch".into()
            )
        );
        drop(connection);
        let before = immutable_projection_state(&temp);
        success(archive(&temp).args(["db", "rebuild"]));
        assert_eq!(immutable_projection_state(&temp), before);
    }

    fn inventory_checkpoint_fixture() -> (TempDir, PathBuf) {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let content = temp.path().join("content/files");
        fs::create_dir_all(content.join("excluded/nested")).unwrap();
        fs::write(content.join("excluded/nested/hidden.txt"), b"excluded").unwrap();
        symlink("first.txt", content.join("alias.txt")).unwrap();
        // A socket is a special file that discovery must count without reading.
        let socket = UnixListener::bind(content.join("special.sock")).unwrap();
        drop(socket);
        fs::write(content.join("first.txt"), b"first\n").unwrap();
        fs::create_dir(content.join("nested")).unwrap();
        fs::write(content.join("nested/second.txt"), b"second\n").unwrap();
        fs::write(content.join("third.txt"), b"third\n").unwrap();
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
        (temp, content)
    }

    fn inventory_checkpoint_scan(temp: &TempDir, content: &Path, pause: bool) -> Value {
        let mut command = archive(temp);
        command.args([
            "--json",
            "location",
            "scan",
            "--path",
            content.to_str().unwrap(),
            "--collection",
            "Files",
            "--exclude",
            "excluded",
            "--job-id",
            "job_inventory_checkpoint",
            "--scan-id",
            "scan_inventory_checkpoint",
            "--batch-entries",
            "2",
        ]);
        if pause {
            command.args(["--max-items", "1"]);
        }
        json(&success(&mut command))
    }

    fn inventory_checkpoint(job_root: &Path) -> (i64, String) {
        let connection =
            rusqlite::Connection::open(job_root.join("inventory-seen.sqlite3")).unwrap();
        connection
            .query_row(
                "SELECT spool_bytes, summary_json FROM inventory_checkpoint WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    #[test]
    fn inventory_resume_finishes_interrupted_git_publication_without_duplicate_events() {
        for already_applied in [false, true] {
            let (temp, content) = inventory_checkpoint_fixture();
            assert_eq!(
                inventory_checkpoint_scan(&temp, &content, true)["status"],
                "running"
            );
            let canonical = root(&temp).join("canonical");
            let before_commit = git(&canonical, &["rev-parse", "HEAD"]).stdout;
            let before_frontier = fs::read(canonical.join("frontiers/v2/HEAD")).unwrap();
            // Exercise the real boundary: append advances its durable frontier,
            // then Git refuses publication because its index is locked.
            let index_lock = canonical.join(".git/index.lock");
            fs::write(&index_lock, b"test-owned publication interruption").unwrap();
            let failed = archive(&temp)
                .args(["--json", "job", "resume", "job_inventory_checkpoint"])
                .output()
                .unwrap();
            assert!(!failed.status.success());
            assert_ne!(
                fs::read(canonical.join("frontiers/v2/HEAD")).unwrap(),
                before_frontier
            );
            assert_eq!(
                git(&canonical, &["rev-parse", "HEAD"]).stdout,
                before_commit
            );
            fs::remove_file(index_lock).unwrap();
            let canonical_bytes = || {
                let mut files = regular_file_tree(&canonical);
                files.retain(|path, _| !path.starts_with(".git"));
                files
            };
            let pending_tree = canonical_bytes();
            let pending_events = json(&success(
                archive(&temp).args(["--json", "events", "verify"]),
            ));
            let spool =
                root(&temp).join("local/jobs/job_inventory_checkpoint/inventory-items.jsonl");
            assert!(spool.exists());
            if already_applied {
                success(archive(&temp).args(["db", "apply"]));
                let job = json(&success(archive(&temp).args([
                    "--json",
                    "job",
                    "show",
                    "job_inventory_checkpoint",
                ])));
                assert_eq!(job["status"], "complete");
            }
            let resumed = json(&success(archive(&temp).args([
                "--json",
                "job",
                "resume",
                "job_inventory_checkpoint",
            ])));
            assert_eq!(resumed["status"], "complete");
            assert_eq!(resumed["summary"]["files_observed"], 3);
            assert!(!spool.exists());
            assert_eq!(canonical_bytes(), pending_tree);
            assert!(git(&canonical, &["status", "--porcelain"])
                .stdout
                .is_empty());
            assert_eq!(
                git(&canonical, &["show", "HEAD:frontiers/v2/HEAD"]).stdout,
                fs::read(canonical.join("frontiers/v2/HEAD")).unwrap()
            );
            assert_eq!(
                git(&canonical, &["rev-parse", "HEAD^"]).stdout,
                before_commit
            );
            let after_events = json(&success(
                archive(&temp).args(["--json", "events", "verify"]),
            ));
            assert_eq!(after_events, pending_events);
            let projected = immutable_projection_state(&temp);
            success(archive(&temp).args(["db", "rebuild"]));
            assert_eq!(immutable_projection_state(&temp), projected);
            success(
                archive(&temp)
                    .args(["fsck", "--full", "--rebuild-dir"])
                    .arg(temp.path().join("publication-rebuild")),
            );
        }
    }

    #[test]
    fn inventory_checkpoint_discards_uncommitted_tail_and_preserves_scan_summary() {
        let (baseline_temp, baseline_content) = inventory_checkpoint_fixture();
        let uninterrupted = inventory_checkpoint_scan(&baseline_temp, &baseline_content, false);
        assert_eq!(uninterrupted["status"], "complete");
        assert_eq!(uninterrupted["summary"]["files_observed"], 3);
        assert_eq!(uninterrupted["summary"]["ignored_symlinks"], 1);
        assert_eq!(uninterrupted["summary"]["ignored_special_files"], 1);
        assert!(
            uninterrupted["summary"]["excluded_subtrees"]
                .as_u64()
                .unwrap()
                >= 1
        );

        let (temp, content) = inventory_checkpoint_fixture();
        let paused = inventory_checkpoint_scan(&temp, &content, true);
        assert_eq!(paused["status"], "running");
        assert_eq!(paused["summary"]["files_observed"], 1);
        let job_root = root(&temp).join("local/jobs/job_inventory_checkpoint");
        let spool_path = job_root.join("inventory-items.jsonl");
        let committed_spool = fs::read(&spool_path).unwrap();
        let checkpoint = inventory_checkpoint(&job_root);
        assert_eq!(checkpoint.0 as u64, committed_spool.len() as u64);
        assert!(checkpoint.0 > 0);
        assert!(serde_json::from_str::<Value>(&checkpoint.1)
            .unwrap()
            .is_object());
        let config: Value =
            serde_json::from_slice(&fs::read(job_root.join("inventory-config.json")).unwrap())
                .unwrap();
        assert_eq!(config["batch_entries"], 2);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let params: String = database
            .query_row(
                "SELECT params_json FROM jobs WHERE job_id = 'job_inventory_checkpoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&params).unwrap()["batch_entries"],
            2
        );
        drop(database);
        success(archive(&temp).args(["db", "rebuild"]));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM jobs WHERE job_id = 'job_inventory_checkpoint'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        drop(database);
        assert_eq!(fs::read(&spool_path).unwrap(), committed_spool);
        assert_eq!(inventory_checkpoint(&job_root), checkpoint);
        assert_job_resume_refuses_symlink(
            &temp,
            "job_inventory_checkpoint",
            "inventory-config.json",
        );

        let mut spool = fs::OpenOptions::new()
            .append(true)
            .open(&spool_path)
            .unwrap();
        // Both a whole uncommitted record and a torn final record must disappear.
        // Keeping the first line would make canonical publication invalid.
        spool
            .write_all(b"{\"kind\":\"must_not_be_published\"}\n{\"kind\":")
            .unwrap();
        spool.sync_all().unwrap();
        drop(spool);
        let resumed = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_inventory_checkpoint",
        ])));
        assert_eq!(resumed["status"], "complete");
        assert_eq!(resumed["summary"], uninterrupted["summary"]);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let file_count: i64 = database
            .query_row("SELECT COUNT(*) FROM file_refs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(file_count, 3);
        drop(database);
        success(archive(&temp).args(["db", "rebuild"]));
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn inventory_checkpoint_upgrades_legacy_paused_job_by_reenumerating_unpublished_work() {
        let (baseline_temp, baseline_content) = inventory_checkpoint_fixture();
        let uninterrupted = inventory_checkpoint_scan(&baseline_temp, &baseline_content, false);
        let (temp, content) = inventory_checkpoint_fixture();
        let paused = inventory_checkpoint_scan(&temp, &content, true);
        assert_eq!(paused["status"], "running");
        let job_root = root(&temp).join("local/jobs/job_inventory_checkpoint");
        let seen = rusqlite::Connection::open(job_root.join("inventory-seen.sqlite3")).unwrap();
        let seen_count: i64 = seen
            .query_row("SELECT COUNT(*) FROM seen", [], |row| row.get(0))
            .unwrap();
        assert!(seen_count > 0);
        seen.execute_batch("DROP TABLE inventory_checkpoint")
            .unwrap();
        drop(seen);
        let config_path = job_root.join("inventory-config.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        config.as_object_mut().unwrap().remove("batch_entries");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let params: String = database
            .query_row(
                "SELECT params_json FROM jobs WHERE job_id = 'job_inventory_checkpoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut params: Value = serde_json::from_str(&params).unwrap();
        params.as_object_mut().unwrap().remove("batch_entries");
        database
            .execute(
                "UPDATE jobs SET params_json = ?1 WHERE job_id = 'job_inventory_checkpoint'",
                [serde_json::to_string(&params).unwrap()],
            )
            .unwrap();
        drop(database);
        fs::write(
            job_root.join("inventory-summary.json"),
            serde_json::to_vec(&paused["summary"]).unwrap(),
        )
        .unwrap();
        let mut spool = fs::OpenOptions::new()
            .append(true)
            .open(job_root.join("inventory-items.jsonl"))
            .unwrap();
        spool.write_all(b"{\"kind\":").unwrap();
        spool.sync_all().unwrap();
        drop(spool);

        let resumed = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_inventory_checkpoint",
        ])));
        assert_eq!(resumed["status"], "complete");
        assert_eq!(resumed["summary"], uninterrupted["summary"]);
        // Rebuild reads the replacement job_started item, including the default
        // interval used when the legacy job had no persisted batch setting.
        success(archive(&temp).args(["db", "rebuild"]));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let file_count: i64 = database
            .query_row("SELECT COUNT(*) FROM file_refs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(file_count, 3);
        let params: String = database
            .query_row(
                "SELECT params_json FROM jobs WHERE job_id = 'job_inventory_checkpoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&params).unwrap()["batch_entries"],
            1_000
        );
    }

    #[test]
    fn inventory_checkpoint_refuses_corrupt_missing_or_truncated_committed_spool() {
        for damage in ["invalid_json", "missing_newline", "missing", "truncated"] {
            let (temp, content) = inventory_checkpoint_fixture();
            let paused = inventory_checkpoint_scan(&temp, &content, true);
            assert_eq!(paused["status"], "running");
            let job_root = root(&temp).join("local/jobs/job_inventory_checkpoint");
            let spool_path = job_root.join("inventory-items.jsonl");
            let original = fs::read(&spool_path).unwrap();
            let checkpoint_before = inventory_checkpoint(&job_root);
            assert_eq!(checkpoint_before.0 as usize, original.len());
            assert!(!original.is_empty());
            let mut damaged = original.clone();
            match damage {
                "invalid_json" => damaged[0] = b'!',
                "missing_newline" => *damaged.last_mut().unwrap() = b' ',
                "missing" => fs::remove_file(&spool_path).unwrap(),
                "truncated" => damaged.truncate(original.len() / 2),
                _ => unreachable!(),
            }
            if damage != "missing" {
                fs::write(&spool_path, &damaged).unwrap();
            }
            let head_path = root(&temp).join("canonical/frontiers/v2/HEAD");
            let head_before = fs::read(&head_path).unwrap();
            let projection_frontiers = || {
                let connection =
                    rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
                connection
                    .query_row(
                        "SELECT (SELECT value FROM archive_meta WHERE key = 'accepted_frontier_hash'),
                                (SELECT value FROM archive_meta WHERE key = 'applied_frontier_hash')",
                        [],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .unwrap()
            };
            let projection_before = projection_frontiers();
            let events_before = json(&success(
                archive(&temp).args(["--json", "events", "verify"]),
            ));
            let output = archive(&temp)
                .args(["--json", "job", "resume", "job_inventory_checkpoint"])
                .output()
                .unwrap();
            assert!(
                !output.status.success(),
                "accepted {damage} committed spool"
            );
            assert_eq!(fs::read(&head_path).unwrap(), head_before, "{damage}");
            assert_eq!(projection_frontiers(), projection_before, "{damage}");
            assert_eq!(
                inventory_checkpoint(&job_root),
                checkpoint_before,
                "{damage}"
            );
            if damage == "missing" {
                assert!(!spool_path.exists(), "recreated missing committed spool");
            } else {
                assert_eq!(fs::read(&spool_path).unwrap(), damaged, "{damage}");
            }
            let events_after = json(&success(
                archive(&temp).args(["--json", "events", "verify"]),
            ));
            assert_eq!(events_after, events_before, "{damage}");

            // Restoring the exact checkpoint bytes makes the same job resumable.
            fs::write(&spool_path, &original).unwrap();
            let resumed = json(&success(archive(&temp).args([
                "--json",
                "job",
                "resume",
                "job_inventory_checkpoint",
            ])));
            assert_eq!(resumed["status"], "complete");
            assert_eq!(resumed["summary"]["files_observed"], 3);
        }
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
        for name in [
            "inventory-config.json",
            "inventory-items.jsonl",
            "inventory-seen.sqlite3",
            "inventory-seen.sqlite3-wal",
        ] {
            assert_job_resume_refuses_symlink(&temp, "job_inventory_resume", name);
        }
        assert_job_resume_refuses_busy_job(&temp, "job_inventory_resume");
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
                "SELECT (SELECT COUNT(*) FROM file_refs), (SELECT COUNT(*) FROM copy_claims WHERE state = 'present'), (SELECT COUNT(*) FROM checks WHERE integrity = 1)",
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
        // Unchanged files are not re-read by a second add.
        assert_eq!(second["summary"]["confirmed_good"], 0);
        assert_eq!(second["summary"]["unchanged_files"], 2);

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

        // A full verification adds a second history record for each File.
        success(archive(&temp).args([
            "verify",
            "Files on Test Device",
            "--path",
            content.to_str().unwrap(),
            "--all",
        ]));
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

        // A findings limit bounds presentation, not Collection totals. The first
        // finding stays in the same canonical File-ID order as the full report.
        for limit in ["0", "1"] {
            let limited = archive(&temp)
                .args([
                    "--json",
                    "report",
                    "risk",
                    "--collection",
                    "Files",
                    "--limit",
                    limit,
                ])
                .output()
                .unwrap();
            assert_eq!(limited.status.code(), Some(10));
            let limited = json(&limited);
            assert_eq!(
                limited["collections"][0]["summary"],
                risk["collections"][0]["summary"]
            );
            let findings = limited["collections"][0]["findings"].as_array().unwrap();
            assert_eq!(findings.len(), limit.parse::<usize>().unwrap());
            if limit == "1" {
                assert_eq!(findings[0], risk["collections"][0]["findings"][0]);
            }
        }
        for field in [
            "file_count",
            "known_size_bytes",
            "files_at_risk",
            "files_uncertain",
        ] {
            assert_eq!(
                collection_status[field],
                risk["collections"][0]["summary"][field]
            );
            assert_eq!(
                archive_status["collections"][0][field],
                collection_status[field]
            );
        }

        // Without an active policy both query paths retain the same full totals
        // and classify even resolved content as uncertain.
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        database
            .execute("UPDATE policies SET enabled=0", [])
            .unwrap();
        let no_policy_status = archive(&temp)
            .args(["--json", "collection", "status", "Files"])
            .output()
            .unwrap();
        assert_eq!(no_policy_status.status.code(), Some(10));
        let no_policy_status = json(&no_policy_status);
        let no_policy_report = archive(&temp)
            .args(["--json", "report", "risk", "--collection", "Files"])
            .output()
            .unwrap();
        assert_eq!(no_policy_report.status.code(), Some(10));
        let no_policy_report = json(&no_policy_report);
        assert_eq!(no_policy_status["files_at_risk"], 0);
        assert_eq!(no_policy_status["files_uncertain"], 2);
        for field in [
            "file_count",
            "known_size_bytes",
            "files_at_risk",
            "files_uncertain",
        ] {
            assert_eq!(
                no_policy_status[field],
                no_policy_report["collections"][0]["summary"][field]
            );
        }
        assert!(no_policy_report["collections"][0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["result"] == "uncertain"));
        database
            .execute("UPDATE policies SET enabled=1", [])
            .unwrap();
        drop(database);

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
        age_copy_checks(&database, None, Some(0), None);
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
        assert_job_resume_refuses_busy_job(&temp, "job_scan_resume");
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
        drop(rebuilt);
        success(archive(&temp).args(["fsck"]));
    }

    fn inventory_only_annex_fixture(temp: &TempDir) -> PathBuf {
        use std::os::unix::fs::symlink;

        let repo = temp.path().join("annex-inventory");
        fs::create_dir(&repo).unwrap();
        git_success(&repo, &["init", "-b", "main"]);
        git_success(&repo, &["config", "user.name", "Archive Ledger Test"]);
        git_success(&repo, &["config", "user.email", "test@example.invalid"]);
        git_success(&repo, &["config", "annex.uuid", "inventory-fixture"]);
        fs::create_dir(repo.join("src")).unwrap();
        fs::create_dir(repo.join("data")).unwrap();
        for (name, bytes, sha512, available, corrupt) in [
            ("sha256", b"available sha256".as_slice(), false, true, false),
            ("sha512", b"available sha512".as_slice(), true, true, false),
            (
                "missing",
                b"missing content".as_slice(),
                false,
                false,
                false,
            ),
            ("corrupt", b"expected content".as_slice(), true, true, true),
        ] {
            let (backend, digest) = if sha512 {
                ("SHA512E", format!("{:x}", Sha512::digest(bytes)))
            } else {
                ("SHA256E", format!("{:x}", Sha256::digest(bytes)))
            };
            let key = format!("{backend}-s{}--{digest}.txt", bytes.len());
            let object = PathBuf::from(format!(".git/annex/objects/aa/bb/{key}/{key}"));
            symlink(Path::new("..").join(&object), repo.join("src").join(name)).unwrap();
            symlink(format!("../src/{name}"), repo.join("data").join(name)).unwrap();
            if available {
                fs::create_dir_all(repo.join(&object).parent().unwrap()).unwrap();
                fs::write(
                    repo.join(&object),
                    if corrupt {
                        vec![b'x'; bytes.len()]
                    } else {
                        bytes.to_vec()
                    },
                )
                .unwrap();
            }
        }
        git_success(&repo, &["add", "."]);
        git_success(&repo, &["commit", "-m", "inventory-only fixture"]);
        repo
    }

    #[test]
    fn list_new_annex_subtree_preserves_absence_and_reports_unreadable_links() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let repo = inventory_only_annex_fixture(&temp);
        success(archive(&temp).args([
            "collection",
            "init",
            repo.to_str().unwrap(),
            "--name",
            "Files",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
            "--import-annex",
            "--inventory-only",
        ]));
        let sub = repo.join("src");
        fs::write(sub.join("brand-new"), b"new ordinary file").unwrap();
        std::os::unix::fs::symlink("brand-new", sub.join("ordinary-link")).unwrap();
        let db_path = root(&temp).join("archive.db");
        let before = fs::read(&db_path).unwrap();
        let list = || {
            archive(&temp)
                .args([
                    "--json",
                    "collection",
                    "add",
                    sub.to_str().unwrap(),
                    "--collection",
                    "Files",
                    "--dry-run",
                    "--list-new",
                ])
                .output()
                .unwrap()
        };
        let output = list();
        assert_eq!(
            output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listing = json(&output);
        assert_eq!(listing["complete"], true, "{listing}");
        assert_eq!(listing["summary"]["unreadable"], 0);
        assert_eq!(listing["summary"]["annex_content_absent"], 1);
        assert_eq!(listing["summary"]["ignored_symlinks"], 1);
        let items = listing["items"].as_array().unwrap();
        assert!(items
            .iter()
            .any(|v| v["path"]["text"] == "src/brand-new" && v["kind"] == "new_to_collection"));
        assert!(!items.iter().any(|v| v["path"]["text"] == "src/missing"));
        assert!(!items
            .iter()
            .any(|v| v["path"]["text"] == "src/ordinary-link"));
        assert_eq!(before, fs::read(&db_path).unwrap());
        // Absolute annex links are refused by the shared resolver; report partial coverage.
        let target = fs::read_link(sub.join("sha256")).unwrap();
        let absolute = fs::canonicalize(sub.join(&target)).unwrap();
        fs::remove_file(sub.join("sha256")).unwrap();
        std::os::unix::fs::symlink(absolute, sub.join("sha256")).unwrap();
        let partial = list();
        assert_eq!(partial.status.code(), Some(10));
        let partial = json(&partial);
        assert_eq!(partial["complete"], false);
        assert_eq!(partial["summary"]["unreadable"], 1);
        assert_eq!(before, fs::read(&db_path).unwrap());
    }

    #[test]
    fn annex_inventory_only_collection_init_then_scan_establishes_integrity() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let repo = inventory_only_annex_fixture(&temp);
        symlink(
            fs::read_link(repo.join("src/sha256")).unwrap(),
            repo.join("src/sha256-alias"),
        )
        .unwrap();
        git_success(&repo, &["add", "src/sha256-alias"]);
        git_success(
            &repo,
            &[
                "commit",
                "-m",
                "second tracked reference to same annex object",
            ],
        );
        let original_index = fs::read(repo.join(".git/index")).unwrap();
        let original_content: Vec<_> = ["sha256", "sha512", "corrupt"]
            .iter()
            .map(|name| {
                (
                    repo.join("src").join(name),
                    fs::read(repo.join("src").join(name)).unwrap(),
                )
            })
            .collect();
        let output = success(archive(&temp).args([
            "--json",
            "collection",
            "init",
            repo.to_str().unwrap(),
            "--name",
            "Files",
            "--location-name",
            "Annex Location",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
            "--import-annex",
            "--inventory-only",
        ]));
        let imported = json(&output);
        assert_eq!(imported["annex_import"]["summary"]["unchecked"], 5);
        assert_eq!(imported["annex_import"]["summary"]["ignored_symlinks"], 4);
        assert_eq!(imported["annex_import"]["summary"]["present"], 0);
        assert_eq!(imported["annex_import"]["summary"]["absent"], 0);
        assert_eq!(imported["annex_import"]["summary"]["mismatched"], 0);
        let progress = String::from_utf8_lossy(&output.stderr);
        assert!(progress.contains("Annex import: Preparing"), "{progress}");
        let final_progress = progress
            .lines()
            .find(|line| line.contains("Annex import: Complete"))
            .expect("annex import reports completion on stderr");
        assert!(final_progress.contains("5 unchecked"), "{final_progress}");
        assert!(
            final_progress.contains("records replayed this pass"),
            "{final_progress}"
        );
        assert!(!final_progress.contains("inspected"), "{final_progress}");
        assert!(
            final_progress.contains("4 skipped links"),
            "{final_progress}"
        );
        assert!(
            !progress.contains('\u{1b}'),
            "captured progress has ANSI escapes: {progress}"
        );

        // Both the immediate projection and canonical replay must preserve
        // uncertainty rather than treating indexed references as verified bytes.
        let metadata_state = immutable_projection_state(&temp);
        for rebuild in [false, true] {
            if rebuild {
                success(archive(&temp).args(["db", "rebuild"]));
            }
            let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
            let inventory: (i64, i64, i64, i64, i64) = database.query_row(
                "SELECT (SELECT COUNT(*) FROM file_refs),
                        (SELECT COUNT(*) FROM objects),
                        (SELECT COUNT(*) FROM checks WHERE integrity != 0),
                        (SELECT COUNT(*) FROM copy_claims WHERE state = 'unknown' AND claim_basis = 'source_metadata'),
                        (SELECT COUNT(*) FROM external_identities WHERE resolution_state = 'unresolved' AND object_id IS NULL)",
                [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            ).unwrap();
            assert_eq!(inventory, (5, 0, 0, 4, 4));
            assert_eq!(
                database
                    .query_row(
                        "SELECT COUNT(*) FROM copy_bindings WHERE latest_integrity IS NOT NULL",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .unwrap(),
                0,
                "metadata inventory must not record an integrity check"
            );
            drop(database);
            assert_eq!(immutable_projection_state(&temp), metadata_state);
        }

        // Removing one logical reference must not withdraw the shared CAS
        // copy that the other registered reference still verifies.
        fs::remove_file(repo.join("src/sha256-alias")).unwrap();
        let scanned = archive(&temp)
            .args([
                "--json",
                "location",
                "scan",
                "Annex Location",
                "--path",
                repo.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            scanned.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&scanned.stderr)
        );
        let summary = &json(&scanned)["summary"];
        assert_eq!(summary["confirmed_good"], 2);
        assert_eq!(summary["integrity_mismatches"], 1);
        success(archive(&temp).args(["db", "rebuild"]));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let scanned_state: (i64, i64, i64, i64) = database.query_row(
            "SELECT (SELECT COUNT(*) FROM objects WHERE canonical_hash_algo = 'blake3'),
                    (SELECT COUNT(*) FROM copy_claims WHERE state = 'present' AND last_verification_result = 'ok' AND object_id IS NOT NULL AND claim_basis = 'observed_bytes'),
                    (SELECT COUNT(*) FROM copy_claims WHERE state = 'corrupt' AND last_verification_result = 'hash_mismatch'),
                    (SELECT COUNT(*) FROM copy_claims WHERE state = 'missing')",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(scanned_state, (2, 2, 1, 1));
        let shared_copy: (String, String) = database
            .query_row(
                "SELECT p.state, c.state FROM file_refs f
             JOIN path_observations p ON p.file_ref_id = f.file_ref_id
             JOIN copy_claims c ON c.external_identity_id = f.external_identity_id
             WHERE f.logical_path_display = 'src/sha256-alias'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(shared_copy, ("missing".to_owned(), "present".to_owned()));
        assert_eq!(fs::read(repo.join(".git/index")).unwrap(), original_index);
        for (path, bytes) in original_content {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
        assert!(!repo.join("src/missing").exists());
        assert_eq!(
            fs::read_link(repo.join("data/sha256")).unwrap(),
            Path::new("../src/sha256")
        );
    }

    #[test]
    fn interrupted_annex_import_of_a_changed_repository_is_cancelled_and_restarted() {
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
        let repo = inventory_only_annex_fixture(&temp);
        let import = |job_id: &str, extra: &[&str]| {
            let mut command = archive(&temp);
            command
                .args([
                    "--json",
                    "location",
                    "import-annex",
                    repo.to_str().unwrap(),
                    "--collection",
                    "Files",
                ])
                .args([
                    "--device",
                    "Test Device",
                    "--site",
                    "Home",
                    "--allow-unidentified-root",
                ])
                .args(["--non-interactive", "--inventory-only", "--job-id", job_id])
                .args(extra);
            command.output().unwrap()
        };
        let paused = import("job_changed", &["--max-items", "2"]);
        assert!(
            paused.status.success(),
            "{}",
            String::from_utf8_lossy(&paused.stderr)
        );
        assert_eq!(json(&paused)["annex_import"]["status"], "running");

        // The repository changes while the import is interrupted.
        git_success(
            &repo,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "change",
            ],
        );
        let refused = archive(&temp)
            .args(["job", "resume", "job_changed"])
            .output()
            .unwrap();
        assert!(!refused.status.success());
        let message = String::from_utf8_lossy(&refused.stderr);
        assert!(message.contains("[annex_source_changed]"), "{message}");
        assert!(
            message.contains("archive job cancel job_changed"),
            "{message}"
        );
        assert!(message.contains("--inventory-only"), "{message}");
        assert!(
            message.contains("archive location import-annex"),
            "{message}"
        );
        // A new import is refused while that one is unfinished.
        assert!(!import("job_second", &[]).status.success());

        let planned = json(&success(archive(&temp).args([
            "--json",
            "job",
            "cancel",
            "job_changed",
            "--dry-run",
        ])));
        assert_eq!(planned["job_type"], "annex_import");
        assert!(planned["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["name"] == "annex-config.json"));
        let cancelled = json(&success(archive(&temp).args([
            "--json",
            "job",
            "cancel",
            "job_changed",
        ])));
        assert_eq!(cancelled["status"], "cancelled");
        assert!(!root(&temp).join("local/jobs/job_changed").exists());
        let again = archive(&temp)
            .args(["job", "resume", "job_changed"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&again.stderr).contains("cancelled"));
        // Reusing the cancelled ID is refused before any job files are recreated.
        assert!(!import("job_changed", &[]).status.success());
        assert!(!root(&temp).join("local/jobs/job_changed").exists());

        // Importing again from the changed repository completes.
        let restarted = import("job_restarted", &[]);
        assert!(
            restarted.status.success(),
            "{}",
            String::from_utf8_lossy(&restarted.stderr)
        );
        assert_eq!(json(&restarted)["annex_import"]["status"], "complete");
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn annex_inventory_only_location_import_resumes_without_hashing() {
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
        let repo = inventory_only_annex_fixture(&temp);
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
            "--inventory-only",
            "--job-id",
            "job_unchecked_resume",
            "--max-items",
            "5",
        ])));
        assert_eq!(paused["annex_import"]["status"], "running");
        assert_eq!(paused["annex_import"]["summary"]["unchecked"], 1);
        success(archive(&temp).args(["db", "rebuild"]));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM jobs WHERE job_id = 'job_unchecked_resume'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        drop(database);
        assert_job_resume_refuses_symlink(&temp, "job_unchecked_resume", "annex-config.json");
        let canonical = root(&temp).join("canonical");
        let before_commit = git(&canonical, &["rev-parse", "HEAD"]).stdout;
        let index_lock = canonical.join(".git/index.lock");
        fs::write(&index_lock, b"test-owned publication interruption").unwrap();
        let failed = archive(&temp)
            .args(["--json", "job", "resume", "job_unchecked_resume"])
            .output()
            .unwrap();
        assert!(!failed.status.success());
        let progress = String::from_utf8_lossy(&failed.stderr);
        assert!(progress.contains("Stopped before completion"), "{progress}");
        assert!(progress.contains("spool bytes read"), "{progress}");
        fs::remove_file(index_lock).unwrap();
        let pending = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        assert_ne!(
            git(&canonical, &["show", "HEAD:frontiers/v2/HEAD"]).stdout,
            fs::read(canonical.join("frontiers/v2/HEAD")).unwrap()
        );
        let resumed = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_unchecked_resume",
        ])));
        assert_eq!(resumed["summary"]["unchecked"], 4);
        assert_eq!(resumed["summary"]["present"], 0);
        assert_eq!(resumed["summary"]["mismatched"], 0);
        assert_eq!(
            json(&success(
                archive(&temp).args(["--json", "events", "verify"])
            )),
            pending
        );
        assert_eq!(
            git(&canonical, &["rev-parse", "HEAD^"]).stdout,
            before_commit
        );
        assert!(git(&canonical, &["status", "--porcelain"])
            .stdout
            .is_empty());
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM objects", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn annex_setup_guards_unfinished_and_completed_imports_before_writes() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let repo = inventory_only_annex_fixture(&temp);
        let alias = temp.path().join("annex-alias");
        std::os::unix::fs::symlink(&repo, &alias).unwrap();
        let setup = [
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
            "--inventory-only",
        ];
        success(
            archive(&temp)
                .args([
                    "collection",
                    "init",
                    repo.to_str().unwrap(),
                    "--name",
                    "Files",
                    "--import-annex",
                    "--job-id",
                    "job_guard",
                    "--max-items",
                    "5",
                ])
                .args(setup),
        );
        let canonical = root(&temp).join("canonical");
        let state = || {
            let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
            let counts: (i64, i64, i64) = database
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM jobs), (SELECT COUNT(*) FROM annex_imports),
                        (SELECT COUNT(*) FROM operation_outcomes)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            (git(&canonical, &["rev-parse", "HEAD"]).stdout, counts)
        };
        let assert_refused = |args: &[&str], expected: &str| {
            let before = state();
            let output = archive(&temp)
                .arg("--json")
                .args(args)
                .args(setup)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            let error: Value = serde_json::from_slice(&output.stderr).unwrap();
            assert!(
                error["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains(expected),
                "{error}"
            );
            assert_eq!(
                state(),
                before,
                "refusal must not append topology or import evidence, or start a job"
            );
            assert!(git(&canonical, &["status", "--porcelain"])
                .stdout
                .is_empty());
        };
        assert_refused(
            &[
                "location",
                "import-annex",
                alias.to_str().unwrap(),
                "--collection",
                "Files",
            ],
            "archive job resume 'job_guard'",
        );
        assert_refused(
            &[
                "location",
                "import-annex",
                repo.to_str().unwrap(),
                "--collection",
                "Files",
                "--reimport",
            ],
            "archive job resume 'job_guard'",
        );
        assert_refused(
            &[
                "collection",
                "init",
                repo.to_str().unwrap(),
                "--name",
                "Files",
                "--import-annex",
            ],
            "archive job resume 'job_guard'",
        );
        success(archive(&temp).args(["db", "rebuild"]));
        assert_refused(
            &[
                "location",
                "import-annex",
                alias.to_str().unwrap(),
                "--collection",
                "Files",
                "--reimport",
            ],
            "archive job resume 'job_guard'",
        );
        success(archive(&temp).args(["job", "resume", "job_guard"]));
        assert_refused(
            &[
                "location",
                "import-annex",
                alias.to_str().unwrap(),
                "--collection",
                "Files",
            ],
            "--reimport",
        );
        success(archive(&temp).args(["db", "rebuild"]));
        assert_refused(
            &[
                "location",
                "import-annex",
                repo.to_str().unwrap(),
                "--collection",
                "Files",
            ],
            "--reimport",
        );
        success(
            archive(&temp)
                .args([
                    "location",
                    "import-annex",
                    repo.to_str().unwrap(),
                    "--collection",
                    "Files",
                    "--reimport",
                ])
                .args(setup),
        );
        assert_eq!(state().1 .1, 2, "explicit reimport remains available");
    }

    #[test]
    fn annex_inventory_only_requires_an_annex_import_command() {
        let temp = TempDir::new().unwrap();
        for args in [
            vec!["collection", "init", "--inventory-only"],
            vec!["location", "init", "--inventory-only"],
        ] {
            let output = archive(&temp).args(args).output().unwrap();
            assert_eq!(output.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&output.stderr).contains("--inventory-only"));
        }
    }

    #[test]
    fn annex_inventory_only_unlocked_scan_defers_missing_and_resolves_retrieved_content() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let repo = temp.path().join("unlocked-annex");
        fs::create_dir(&repo).unwrap();
        git_success(&repo, &["init", "-b", "main"]);
        git_success(&repo, &["config", "user.name", "Archive Ledger Test"]);
        git_success(&repo, &["config", "user.email", "test@example.invalid"]);
        git_success(
            &repo,
            &["config", "annex.uuid", "unlocked-inventory-fixture"],
        );
        let entries = [
            ("00-pointer", b"later retrieved".as_slice(), true),
            ("10-content", b"unlocked sha256".as_slice(), false),
            ("20-content", b"unlocked sha512".as_slice(), true),
            ("30-missing", b"worktree absent".as_slice(), false),
        ];
        for (name, bytes, sha512) in &entries {
            let (backend, digest) = if *sha512 {
                ("SHA512E", format!("{:x}", Sha512::digest(bytes)))
            } else {
                ("SHA256E", format!("{:x}", Sha256::digest(bytes)))
            };
            let key = format!("{backend}-s{}--{digest}.txt", bytes.len());
            fs::write(repo.join(name), format!("/annex/objects/{key}\n")).unwrap();
        }
        git_success(&repo, &["add", "."]);
        git_success(&repo, &["commit", "-m", "indexed unlocked pointers"]);
        fs::remove_file(repo.join("30-missing")).unwrap();
        let imported = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "init",
            repo.to_str().unwrap(),
            "--name",
            "Files",
            "--location-name",
            "Unlocked Annex",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
            "--import-annex",
            "--inventory-only",
        ])));
        assert_eq!(imported["annex_import"]["summary"]["unchecked"], 4);

        // All existing worktree files are pointers, so whichever is visited
        // first stages a missing-copy candidate that must remain inert.
        let paused = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "Unlocked Annex",
            "--path",
            repo.to_str().unwrap(),
            "--job-id",
            "job_unlocked_scan",
            "--max-items",
            "1",
        ])));
        assert_eq!(paused["status"], "running");
        assert_eq!(paused["summary"]["observed_without_verification"], 1);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'unknown'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            4
        );
        drop(database);

        let scanned = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_unlocked_scan",
        ])));
        assert_eq!(scanned["status"], "complete");
        assert_eq!(scanned["summary"]["confirmed_good"], 0);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            4
        );
        drop(database);

        for (name, bytes, _) in &entries[1..3] {
            fs::write(repo.join(name), bytes).unwrap();
        }
        let scanned = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "Unlocked Annex",
            "--path",
            repo.to_str().unwrap(),
        ])));
        assert_eq!(scanned["summary"]["new_paths"], 2);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let states: (i64, i64) = database.query_row(
            "SELECT (SELECT COUNT(*) FROM copy_claims WHERE state = 'missing'),
                    (SELECT COUNT(*) FROM copy_claims WHERE state = 'present' AND object_id IS NOT NULL AND claim_basis = 'observed_bytes' AND last_verification_result = 'ok')",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(states, (2, 2));
        drop(database);

        // Replacing the pointer with retrieved bytes must establish its
        // identity on the ordinary scan path, without another import.
        fs::write(repo.join(entries[0].0), entries[0].1).unwrap();
        let scanned = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "Unlocked Annex",
            "--path",
            repo.to_str().unwrap(),
        ])));
        // The two files verified by the previous scan are skipped; only the new one is read.
        assert_eq!(scanned["summary"]["confirmed_good"], 0);
        assert_eq!(scanned["summary"]["unchanged_files"], 2);
        assert_eq!(scanned["summary"]["new_paths"], 1);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let claims =
            || {
                let mut statement = database.prepare(
                "SELECT copy_claim_id, object_id, state, claim_basis, last_verified_record_id
                 FROM copy_claims ORDER BY copy_claim_id",
            ).unwrap();
                let rows = statement
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                        ))
                    })
                    .unwrap();
                rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
            };
        let verified_claims = claims();
        success(archive(&temp).args([
            "location",
            "import-annex",
            "--reimport",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
            "--location-name",
            "Unlocked Annex",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
            "--inventory-only",
        ]));
        assert_eq!(
            claims(),
            verified_claims,
            "metadata-only reimport must preserve observed evidence"
        );
        drop(database);
        success(archive(&temp).args(["db", "rebuild"]));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let retrieved: (String, String, String, String) = database
            .query_row(
                "SELECT f.identity_state, c.state, c.claim_basis, o.canonical_hash_hex
             FROM file_refs f JOIN copy_claims c ON c.external_identity_id = f.external_identity_id
             JOIN objects o ON o.object_id = c.object_id
             WHERE f.logical_path_display = '00-pointer'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            retrieved,
            (
                "resolved".to_owned(),
                "present".to_owned(),
                "observed_bytes".to_owned(),
                blake3::hash(entries[0].1).to_hex().to_string(),
            )
        );
        assert!(!repo.join("30-missing").exists());

        // The metadata-only reimport re-recorded path metadata, so the preview and the
        // real scan agree that the three content files must be read again.
        let planned = json(
            &archive(&temp)
                .args([
                    "--json",
                    "location",
                    "scan",
                    "Unlocked Annex",
                    "--path",
                    repo.to_str().unwrap(),
                    "--dry-run",
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(planned["preview"]["changed"]["count"], 3, "{planned}");
        let scanned = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "Unlocked Annex",
            "--path",
            repo.to_str().unwrap(),
        ])));
        assert_eq!(scanned["summary"]["confirmed_good"], 3);
        // Small unlocked annex content and already recorded absence need no read or record.
        for extra in [&[][..], &["--collection", "Files"][..]] {
            let mut command = archive(&temp);
            command.arg("--json");
            if extra.is_empty() {
                command.args([
                    "location",
                    "scan",
                    "Unlocked Annex",
                    "--path",
                    repo.to_str().unwrap(),
                    "--dry-run",
                ]);
            } else {
                command
                    .args(["collection", "add", repo.to_str().unwrap(), "--dry-run"])
                    .args(extra);
            }
            let output = command.output().unwrap();
            let preview = json(&output);
            assert_eq!(output.status.code(), Some(0), "{preview}");
            assert_eq!(preview["preview"]["uncertain"]["count"], 0);
        }
    }

    #[test]
    fn annex_sha512_native_import_scan_and_verify_without_git_filters() {
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
        let repo = temp.path().join("annex-sha512");
        fs::create_dir(&repo).unwrap();
        git_success(&repo, &["init", "-b", "main"]);
        git_success(&repo, &["config", "user.name", "Archive Ledger Test"]);
        git_success(&repo, &["config", "user.email", "test@example.invalid"]);
        git_success(&repo, &["config", "annex.uuid", "sha512-fixture"]);
        let contents: [&[u8]; 4] = [
            b"locked bytes\n",
            b"unlocked bytes\n",
            b"absent bytes\n",
            b"expected bytes\n",
        ];
        let names = ["locked.txt", "unlocked.txt", "absent.txt", "corrupt.txt"];
        let mut targets = Vec::new();
        let mut digests = Vec::new();
        for (index, content) in contents.iter().enumerate() {
            let digest = format!("{:x}", Sha512::digest(content));
            let backend = if index % 2 == 0 { "SHA512" } else { "SHA512E" };
            let extension = if index % 2 == 0 { "" } else { ".txt" };
            let key = format!("{backend}-s{}--{digest}{extension}", content.len());
            let target = PathBuf::from(format!(".git/annex/objects/aa/bb/{key}/{key}"));
            if index == 1 {
                fs::write(repo.join(names[index]), format!("/annex/objects/{key}\n")).unwrap();
            } else {
                symlink(&target, repo.join(names[index])).unwrap();
                if index != 2 {
                    fs::create_dir_all(repo.join(&target).parent().unwrap()).unwrap();
                    let bytes = if index == 3 {
                        vec![b'x'; content.len()]
                    } else {
                        content.to_vec()
                    };
                    fs::write(repo.join(&target), bytes).unwrap();
                }
            }
            targets.push(target);
            digests.push(digest);
        }
        git_success(&repo, &["add", "."]);
        git_success(&repo, &["commit", "-m", "SHA512 fixture"]);
        fs::write(repo.join("unlocked.txt"), contents[1]).unwrap();
        // A cold index requires Git status to consult this filter. Native import
        // must read the index and worktree directly without invoking it.
        fs::write(
            repo.join(".git/info/attributes"),
            "unlocked.txt filter=annex\n",
        )
        .unwrap();
        git_success(
            &repo,
            &[
                "config",
                "filter.annex.process",
                "printf invoked > .git/filter-invoked; exit 1",
            ],
        );
        git_success(&repo, &["config", "filter.annex.required", "true"]);
        fs::remove_file(repo.join(".git/index")).unwrap();
        git_success(&repo, &["read-tree", "HEAD"]);
        let initial_index = fs::read(repo.join(".git/index")).unwrap();
        let import_output = archive(&temp)
            .args([
                "--json",
                "location",
                "import-annex",
                repo.to_str().unwrap(),
                "--collection",
                "Files",
                "--location-name",
                "SHA512 Location",
                "--device",
                "Test Device",
                "--site",
                "Home",
                "--allow-unidentified-root",
                "--non-interactive",
            ])
            .output()
            .unwrap();
        assert_eq!(
            import_output.status.code(),
            Some(10),
            "{}",
            String::from_utf8_lossy(&import_output.stderr)
        );
        let imported = json(&import_output);
        assert_eq!(imported["annex_import"]["summary"]["present"], 2);
        assert_eq!(imported["annex_import"]["summary"]["absent"], 1);
        assert_eq!(imported["annex_import"]["summary"]["mismatched"], 1);
        assert!(!repo.join(".git/filter-invoked").exists());
        assert_eq!(fs::read(repo.join(".git/index")).unwrap(), initial_index);
        assert_eq!(fs::read(repo.join("unlocked.txt")).unwrap(), contents[1]);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let absent: (String, String, Option<String>) = database.query_row(
            "SELECT e.expected_hash_algo, e.expected_hash_hex, e.object_id FROM external_identities e JOIN file_refs f ON f.external_identity_id = e.external_identity_id WHERE f.logical_path_display = 'absent.txt'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(absent, ("sha512".to_owned(), digests[2].clone(), None));
        assert_eq!(canonical_hash_results(&temp, "sha512", "ok", None), 2);
        assert_eq!(
            canonical_hash_results(&temp, "sha512", "hash_mismatch", None),
            1
        );
        let integrity_counts: (i64, i64) = database
            .query_row(
                "SELECT SUM(integrity = 1), SUM(integrity = 2) FROM checks",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(integrity_counts, (2, 1));
        drop(database);

        // Recovered absent bytes resolve from the recorded SHA512 key. Both
        // locked and unlocked content are rechecked against that key on scans.
        fs::create_dir_all(repo.join(&targets[2]).parent().unwrap()).unwrap();
        fs::write(repo.join(&targets[2]), contents[2]).unwrap();
        fs::write(repo.join(&targets[3]), contents[3]).unwrap();
        let scanned = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "--path",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        // Import already read and verified the locked content; the scan reads the rest.
        assert_eq!(scanned["summary"]["confirmed_good"], 2);
        assert_eq!(scanned["summary"]["unchanged_files"], 2);
        // Re-import fills checksum metadata missing from an older projection
        // while preserving the same Location and Collection File identities.
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        database.execute("UPDATE source_identities SET expected_checksum = NULL, content_id = NULL, resolution = 'unresolved' WHERE namespace = 'git-annex'", []).unwrap();
        drop(database);
        let reimported = json(&success(archive(&temp).args([
            "--json",
            "location",
            "import-annex",
            "--reimport",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
            "--location-name",
            "SHA512 Location",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ])));
        assert_eq!(
            reimported["location"]["location_id"],
            imported["location"]["location_id"]
        );
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            database
                .query_row("SELECT COUNT(*) FROM file_refs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            4
        );
        assert_eq!(database.query_row("SELECT COUNT(*) FROM external_identities WHERE expected_hash_algo = 'sha512' AND length(expected_hash_hex) = 128 AND resolution_state = 'resolved' AND object_id IS NOT NULL", [], |row| row.get::<_, i64>(0)).unwrap(), 4);
        drop(database);
        success(archive(&temp).args([
            "verify",
            "SHA512 Location",
            "--path",
            repo.to_str().unwrap(),
        ]));
        fs::write(repo.join(&targets[0]), vec![b'x'; contents[0].len()]).unwrap();
        fs::write(repo.join("unlocked.txt"), vec![b'x'; contents[1].len()]).unwrap();
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
        assert_eq!(json(&corrupt)["summary"]["integrity_mismatches"], 2);
        let verification = archive(&temp)
            .args([
                "--json",
                "verify",
                "SHA512 Location",
                "--path",
                repo.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(verification.status.code(), Some(10));
        assert!(!repo.join(".git/filter-invoked").exists());
        success(archive(&temp).args(["db", "rebuild"]));
        let rebuilt = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT COUNT(*) FROM objects WHERE canonical_hash_algo = 'blake3'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            4
        );
        for digest in &digests {
            assert_eq!(rebuilt.query_row(
                "SELECT COUNT(*) FROM object_hashes WHERE hash_algo = 'sha512' AND hash_hex = ?1", [digest], |row| row.get::<_, i64>(0)
            ).unwrap(), 1);
        }
        // Scans check the original annex SHA512; verify checks the established BLAKE3 identity.
        assert_eq!(
            canonical_hash_results(&temp, "sha512", "hash_mismatch", None),
            3
        );
        assert_eq!(
            canonical_hash_results(&temp, "blake3", "hash_mismatch", None),
            2
        );
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT COUNT(*) FROM checks WHERE integrity = 2",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            5
        );
        // Prove this fixture would trigger the filter under the old snapshot
        // command, rather than merely configuring an unused filter.
        fs::remove_file(repo.join(".git/index")).unwrap();
        git_success(&repo, &["read-tree", "HEAD"]);
        let status = git(
            &repo,
            &["status", "--porcelain=v1", "-z", "--untracked-files=no"],
        );
        assert!(!status.status.success());
        assert!(repo.join(".git/filter-invoked").exists());
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

        let refused = archive(&temp)
            .args([
                "collection",
                "add",
                repo.to_str().unwrap(),
                "--collection",
                "Files",
            ])
            .output()
            .unwrap();
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr)
            .contains("cannot inventory an unimported git-annex repository"));

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
        for name in [
            "annex-config.json",
            "annex-summary.json",
            "annex-items.jsonl",
        ] {
            assert_job_resume_refuses_symlink(&temp, "job_annex_resume", name);
        }
        fs::OpenOptions::new()
            .append(true)
            .open(root(&temp).join("local/jobs/job_annex_resume/annex-items.jsonl"))
            .unwrap()
            .write_all(b"crash-tail-that-must-be-truncated\n")
            .unwrap();
        assert_job_resume_refuses_busy_job(&temp, "job_annex_resume");
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
        // A dangling annex link supplies Collection identity, not a stored copy
        // or a Location presence/check observation.
        let absent_rows: (i64, i64, i64) = database
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM file_locations p JOIN file_objects f ON f.id=p.file_id
                     WHERE f.path_bytes=CAST('absent.txt' AS BLOB)),
                    (SELECT COUNT(*) FROM checks),
                    (SELECT COUNT(*) FROM source_availability WHERE state='missing')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(absent_rows, (0, 1, 0));
        drop(database);

        success(archive(&temp).args(["db", "rebuild"]));
        let rebuilt = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        assert_eq!(
            rebuilt
                .query_row(
                    "SELECT COUNT(*) FROM file_locations p JOIN file_objects f ON f.id=p.file_id
                 WHERE f.path_bytes=CAST('absent.txt' AS BLOB)",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(rebuilt);

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
        // Import already read the present content, so the scan does not re-read it.
        assert_eq!(first_scan["summary"]["confirmed_good"], 0);
        assert_eq!(first_scan["summary"]["unchanged_files"], 1);
        assert_eq!(first_scan["summary"]["ignored_symlinks"], 1);
        assert_eq!(first_scan["summary"]["missing_paths"], 0);

        fs::write(
            repo.join("created-after-import.txt"),
            b"ordinary new file\n",
        )
        .unwrap();
        fs::write(
            repo.join(".git/archive-ledger-must-ignore"),
            b"git metadata\n",
        )
        .unwrap();
        symlink("present.txt", repo.join("ordinary-alias.txt")).unwrap();
        let added = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "add",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        assert_eq!(added["summary"]["new_paths"], 1);
        assert_eq!(added["summary"]["ignored_symlinks"], 2);
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let added_file: (String, String, String) = database
            .query_row(
                "SELECT f.identity_state, p.representation, c.relative_path_display
                 FROM file_refs f
                 JOIN path_observations p ON p.file_ref_id = f.file_ref_id
                 JOIN copy_claims c ON c.object_id = f.object_id AND c.location_id = p.location_id
                 WHERE f.logical_path_display = 'created-after-import.txt'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            added_file,
            (
                "resolved".to_owned(),
                "ordinary_file".to_owned(),
                "created-after-import.txt".to_owned(),
            )
        );
        assert_eq!(
            database
                .query_row(
                    "SELECT COUNT(*) FROM file_refs WHERE logical_path_display IN ('ordinary-alias.txt', '.git/archive-ledger-must-ignore')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        drop(database);

        let preview = |repo: &Path| {
            let output = archive(&temp)
                .args([
                    "--json",
                    "location",
                    "scan",
                    "--path",
                    repo.to_str().unwrap(),
                    "--collection",
                    "Files",
                    "--dry-run",
                ])
                .output()
                .unwrap();
            (output.status.code(), json(&output))
        };
        let (code, before_get) = preview(&repo);
        assert_eq!(
            code,
            Some(0),
            "an imported, scanned annex Location has nothing to record"
        );
        assert_eq!(before_get["actionable"], false);
        // An unresolvable registered link makes the real scan partial, so the preview
        // lists it as unreadable and predicts no missing files.
        fs::remove_file(repo.join("present.txt")).unwrap();
        symlink(repo.join(&present_target), repo.join("present.txt")).unwrap();
        let (code, broken) = preview(&repo);
        assert_eq!(code, Some(10));
        assert_eq!(
            broken["preview"]["unreadable"]["paths"],
            serde_json::json!(["present.txt"])
        );
        assert_eq!(broken["preview"]["complete_coverage"], false);
        assert_eq!(broken["preview"]["missing"]["count"], 0);
        fs::remove_file(repo.join("present.txt")).unwrap();
        symlink(&present_target, repo.join("present.txt")).unwrap();
        assert_eq!(preview(&repo).0, Some(0));
        fs::create_dir_all(repo.join(&absent_target).parent().unwrap()).unwrap();
        fs::write(repo.join(&absent_target), absent_content).unwrap();
        // Newly retrieved annex content is found from the object file's metadata.
        let (code, retrieved) = preview(&repo);
        assert_eq!(code, Some(10));
        let read = ["new_files", "new_at_location", "changed", "needs_reading"]
            .iter()
            .map(|category| retrieved["preview"][category]["count"].as_u64().unwrap())
            .sum::<u64>();
        assert_eq!(read, 1, "{retrieved}");
        let after_get = json(&success(archive(&temp).args([
            "--json",
            "location",
            "scan",
            "--path",
            repo.to_str().unwrap(),
            "--collection",
            "Files",
        ])));
        // Only the newly retrieved content is read; already verified copies are skipped.
        assert_eq!(after_get["summary"]["confirmed_good"], 1);
        assert_eq!(after_get["summary"]["unchanged_files"], 2);
        assert_eq!(
            preview(&repo).1["actionable"],
            false,
            "clean after the matching real run"
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
            3
        );
        drop(database);

        // A partial annex repository that lacks this content must not regress
        // the Collection File's identity. Archive Ledger can then populate its
        // registered dangling annex symlink without invoking git-annex.
        let destination_repo = temp.path().join("annex-destination");
        fs::create_dir(&destination_repo).unwrap();
        git_success(&destination_repo, &["init", "-b", "main"]);
        git_success(
            &destination_repo,
            &["config", "user.name", "Archive Ledger Test"],
        );
        git_success(
            &destination_repo,
            &["config", "user.email", "test@example.invalid"],
        );
        git_success(
            &destination_repo,
            &["config", "annex.uuid", "fixture-annex-destination-uuid"],
        );
        symlink(&absent_target, destination_repo.join("absent.txt")).unwrap();
        git_success(&destination_repo, &["add", "."]);
        git_success(&destination_repo, &["commit", "-m", "fixture destination"]);
        success(archive(&temp).args([
            "location",
            "import-annex",
            destination_repo.to_str().unwrap(),
            "--collection",
            "Files",
            "--location-name",
            "Annex Destination",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));
        let database = rusqlite::Connection::open(root(&temp).join("archive.db")).unwrap();
        let identity: (String, Option<String>) = database
            .query_row(
                "SELECT identity_state, object_id FROM file_refs WHERE logical_path_display = 'absent.txt'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(identity.0, "resolved");
        assert!(identity.1.is_some());
        drop(database);
        let planned = json(&success(archive(&temp).current_dir(&repo).args([
            "--json",
            "copy",
            "--to",
            "Annex Destination",
            "--collection",
            "Files",
            "absent.txt",
            "--dry-run",
        ])));
        assert_eq!(planned["status"], "planned");
        assert_eq!(planned["summary"]["selected_logical_files"], 1);
        assert!(!destination_repo.join(&absent_target).exists());
        assert!(!destination_repo.join(".git/annex/objects").exists());

        // Missing object-store parents are allowed, but existing symlink
        // ancestors must still fail closed for both planning and copying.
        let outside = temp.path().join("outside-annex");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        symlink(&outside, destination_repo.join(".git/annex")).unwrap();
        for controls in [&["--dry-run"][..], &["--yes", "--non-interactive"][..]] {
            let refused = archive(&temp)
                .current_dir(&repo)
                .args([
                    "copy",
                    "--to",
                    "Annex Destination",
                    "--collection",
                    "Files",
                    "absent.txt",
                ])
                .args(controls)
                .output()
                .unwrap();
            assert!(!refused.status.success());
            assert!(String::from_utf8_lossy(&refused.stderr)
                .contains("copy destination parent is not a directory"));
            assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
            assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        }
        fs::remove_file(destination_repo.join(".git/annex")).unwrap();

        success(archive(&temp).current_dir(&repo).args([
            "copy",
            "--to",
            "Annex Destination",
            "--collection",
            "Files",
            "absent.txt",
            "--yes",
            "--non-interactive",
        ]));
        assert!(destination_repo.join(".git/annex/objects").is_dir());
        assert!(fs::symlink_metadata(destination_repo.join("absent.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read(destination_repo.join("absent.txt")).unwrap(),
            absent_content
        );

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
            2
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
        drop(rebuilt);
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn copy_places_verified_objects_without_overwrite_and_rebuilds() {
        use std::os::unix::fs::symlink;

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

        let outside = temp.path().join("outside.txt");
        fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, destination.join("one.txt")).unwrap();
        let refused = archive(&temp)
            .current_dir(&source)
            .args([
                "copy",
                "--to",
                "Backup",
                "--collection",
                "Files",
                "one.txt",
                "--dry-run",
            ])
            .output()
            .unwrap();
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("unmanaged symlink"));
        assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
        fs::remove_file(destination.join("one.txt")).unwrap();

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

    #[test]
    fn verification_reads_due_copies_oldest_first_and_all_copies_on_request() {
        // A visible filesystem UUID lets the runner prove the Archive Root identity.
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let content = temp.path().join("content/verify");
        fs::create_dir_all(&content).unwrap();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(content.join(name), name.as_bytes()).unwrap();
        }
        let path = content.to_str().unwrap();
        success(archive(&temp).args([
            "collection",
            "init",
            path,
            "--name",
            "Files",
            "--device",
            "Test Device",
            "--site",
            "Home",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));
        success(archive(&temp).args(["collection", "add", path, "--collection", "Files"]));
        success(archive(&temp).args([
            "device",
            "identity",
            "Test Device",
            "--kind",
            "serial",
            "--fingerprint",
            "VERIFY-DEVICE-001",
        ]));
        let database_path = root(&temp).join("archive.db");
        let verified_at = |name: &str| -> i64 {
            rusqlite::Connection::open(&database_path)
                .unwrap()
                .query_row(
                    "SELECT last_verified_time_utc_ms FROM copy_claims WHERE relative_path_display = ?1",
                    [name],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let age = |name: &str, time: i64| {
            let database = rusqlite::Connection::open(&database_path).unwrap();
            age_copy_checks(&database, Some(name), None, Some(time));
        };

        // Freshly added copies are not due.
        let idle = json(&success(archive(&temp).args(["--json", "verify"])));
        assert_eq!(idle["status"], "idle");

        // Presence stays fresh; only verification is old. Oldest verified goes first.
        age("b.txt", 1_000);
        age("a.txt", 2_000);
        success(archive(&temp).args(["background", "enable", "--max-items", "1"]));
        let status = json(&success(archive(&temp).args([
            "--json",
            "background",
            "status",
        ])));
        assert_eq!(status["pending_stale_presence"], 2);
        let first = json(&success(archive(&temp).args([
            "--json",
            "background",
            "run",
        ])));
        assert_eq!(first["summary"]["selected"], 1);
        assert!(
            verified_at("b.txt") > 2_000,
            "oldest verified copy is read first"
        );
        assert_eq!(verified_at("a.txt"), 2_000);
        let job_id = first["job_id"].as_str().unwrap().to_owned();
        let resumed = json(&success(
            archive(&temp).args(["--json", "job", "resume", &job_id]),
        ));
        assert_eq!(resumed["status"], "complete");
        assert!(verified_at("a.txt") > 2_000);

        // Foreground verify of one Location reads only what is due.
        age("a.txt", 3_000);
        let one = json(&success(archive(&temp).args([
            "--json",
            "verify",
            "Files on Test Device",
        ])));
        assert_eq!(one["summary"]["selected"], 1);
        assert_eq!(one["summary"]["verified_ok"], 1);

        // Content replaced with the same size and mtime is not due, but --all reads it.
        let original = fs::metadata(content.join("c.txt"))
            .unwrap()
            .modified()
            .unwrap();
        fs::write(content.join("c.txt"), b"X.txt").unwrap();
        fs::File::options()
            .write(true)
            .open(content.join("c.txt"))
            .unwrap()
            .set_modified(original)
            .unwrap();
        let nothing_due = json(&success(archive(&temp).args(["--json", "verify"])));
        assert_eq!(nothing_due["status"], "idle");
        let partial = archive(&temp)
            .args([
                "--json",
                "verify",
                "Files on Test Device",
                "--all",
                "--max-items",
                "1",
            ])
            .output()
            .unwrap();
        assert!(matches!(partial.status.code(), Some(0 | 10)));
        let partial = json(&partial);
        assert_eq!(partial["status"], "running");
        let job_id = partial["job_id"].as_str().unwrap().to_owned();
        let all = archive(&temp)
            .args(["--json", "job", "resume", &job_id])
            .output()
            .unwrap();
        assert_eq!(all.status.code(), Some(10));
        let all = json(&all);
        assert_eq!(all["status"], "complete");
        assert_eq!(
            all["summary"]["selected"], 3,
            "each copy is read exactly once"
        );
        assert_eq!(all["summary"]["hash_mismatches"], 1);
        success(archive(&temp).args(["fsck"]));
    }

    #[test]
    fn background_stale_refresh_is_opt_in_bounded_identity_gated_and_read_only() {
        // This fixture must live on a filesystem whose UUID is visible so the
        // fail-closed background reader can prove the Archive Root identity.
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let content = temp.path().join("content/background");
        fs::create_dir_all(&content).unwrap();
        fs::write(content.join("one.txt"), b"one\n").unwrap();
        fs::write(content.join("two.txt"), b"two\n").unwrap();
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
        success(archive(&temp).args([
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ]));
        success(archive(&temp).args([
            "device",
            "identity",
            "Test Device",
            "--kind",
            "serial",
            "--fingerprint",
            "BACKGROUND-DEVICE-001",
        ]));

        let database_path = root(&temp).join("archive.db");
        let database = rusqlite::Connection::open(&database_path).unwrap();
        age_copy_checks(&database, None, Some(0), None);
        drop(database);
        let original_one = fs::read(content.join("one.txt")).unwrap();
        let original_two = fs::read(content.join("two.txt")).unwrap();

        let disabled = archive(&temp)
            .args(["--json", "background", "run"])
            .output()
            .unwrap();
        assert_eq!(disabled.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&disabled.stderr).contains("disabled"));
        let default_status = json(&success(archive(&temp).args([
            "--json",
            "background",
            "status",
        ])));
        assert_eq!(default_status["enabled"], false);
        assert_eq!(default_status["pending_stale_presence"], 2);

        success(archive(&temp).args(["background", "enable", "--max-items", "1"]));
        let paused = json(&success(archive(&temp).args([
            "--json",
            "background",
            "pause",
        ])));
        assert_eq!(paused["paused"], true);
        let paused_run = archive(&temp)
            .args(["--json", "background", "run"])
            .output()
            .unwrap();
        assert_eq!(paused_run.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&paused_run.stderr).contains("paused"));
        success(archive(&temp).args(["background", "enable", "--max-items", "1"]));

        let first = json(&success(archive(&temp).args([
            "--json",
            "background",
            "run",
        ])));
        assert_eq!(first["status"], "running");
        assert_eq!(first["summary"]["selected"], 1);
        assert_eq!(first["summary"]["verified_ok"], 1);
        let job_id = first["job_id"].as_str().unwrap().to_owned();
        let visible = json(&success(
            archive(&temp).args(["--json", "job", "show", &job_id]),
        ));
        assert_eq!(visible["status"], "running");
        let completed = json(&success(
            archive(&temp).args(["--json", "job", "resume", &job_id]),
        ));
        assert_eq!(completed["status"], "complete");
        assert_eq!(completed["summary"]["selected"], 2);
        assert_eq!(completed["summary"]["verified_ok"], 2);
        assert_eq!(completed["summary"]["remaining_stale"], 0);
        assert_eq!(fs::read(content.join("one.txt")).unwrap(), original_one);
        assert_eq!(fs::read(content.join("two.txt")).unwrap(), original_two);

        let database = rusqlite::Connection::open(&database_path).unwrap();
        age_copy_checks(&database, Some("one.txt"), Some(0), None);
        drop(database);
        success(archive(&temp).args(["device", "identity", "Test Device", "--conflict"]));
        let before_idle = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        let gated = json(&success(archive(&temp).args([
            "--json",
            "background",
            "run",
        ])));
        assert_eq!(gated["status"], "idle");
        assert_eq!(gated["job_id"], Value::Null);
        assert_eq!(gated["summary"]["selected"], 0);
        assert_eq!(gated["summary"]["skipped_devices"], 1);
        assert_eq!(gated["summary"]["remaining_stale"], 1);
        let after_idle = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        assert_eq!(before_idle["records"], after_idle["records"]);
        success(archive(&temp).args([
            "device",
            "identity",
            "Test Device",
            "--kind",
            "serial",
            "--fingerprint",
            "BACKGROUND-DEVICE-001",
        ]));
        let refreshed = json(&success(archive(&temp).args([
            "--json",
            "background",
            "run",
        ])));
        assert_eq!(refreshed["status"], "complete");
        assert_eq!(refreshed["summary"]["verified_ok"], 1);

        fs::write(content.join("two.txt"), b"tampered\n").unwrap();
        let database = rusqlite::Connection::open(&database_path).unwrap();
        age_copy_checks(&database, Some("two.txt"), Some(0), None);
        drop(database);
        let mismatch = archive(&temp)
            .args(["--json", "background", "run"])
            .output()
            .unwrap();
        assert_eq!(mismatch.status.code(), Some(10));
        let mismatch = json(&mismatch);
        assert_eq!(mismatch["status"], "complete");
        assert_eq!(mismatch["summary"]["hash_mismatches"], 1);
        assert_eq!(fs::read(content.join("two.txt")).unwrap(), b"tampered\n");
        let database = rusqlite::Connection::open(&database_path).unwrap();
        let state: String = database
            .query_row(
                "SELECT state FROM copy_claims WHERE relative_path_display = 'two.txt'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "corrupt");
        drop(database);

        success(archive(&temp).args(["db", "rebuild"]));
        let rebuilt = rusqlite::Connection::open(&database_path).unwrap();
        let rebuilt_state: String = rebuilt
            .query_row(
                "SELECT state FROM copy_claims WHERE relative_path_display = 'two.txt'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rebuilt_state, "corrupt");
        drop(rebuilt);
        let config = json(&success(archive(&temp).args([
            "--json",
            "background",
            "status",
        ])));
        assert_eq!(config["enabled"], true);
        assert_eq!(config["max_items"], 1);
        assert!(git(&root(&temp).join("canonical"), &["status", "--short"])
            .stdout
            .is_empty());
    }

    #[test]
    fn app_change_feed_and_access_planning_are_cursor_bound_and_set_oriented() {
        let temp = TempDir::new().unwrap();
        success(archive(&temp).args([
            "init",
            "Personal",
            "--archive-id",
            "arc_personal",
            "--non-interactive",
        ]));
        let content = temp.path().join("content");
        fs::create_dir(&content).unwrap();
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
        let canonical = root(&temp).join("canonical");
        let base_commit = String::from_utf8(git(&canonical, &["rev-parse", "HEAD"]).stdout)
            .unwrap()
            .trim()
            .to_owned();

        // Both logical Files deliberately share one Object so candidate lookup
        // cannot expand into a File-by-Copy Cartesian product.
        fs::write(content.join("one.jpg"), b"same bytes\n").unwrap();
        fs::write(content.join("two.jpg"), b"same bytes\n").unwrap();
        success(archive(&temp).args([
            "collection",
            "add",
            content.to_str().unwrap(),
            "--collection",
            "Files",
        ]));

        let first = json(&success(archive(&temp).args([
            "--json",
            "app",
            "changes",
            "--collection",
            "Files",
            "--since",
            &base_commit,
            "--limit",
            "1",
        ])));
        assert_eq!(first["version"], 1);
        assert_eq!(first["items"].as_array().unwrap().len(), 1);
        assert_eq!(
            first["semantics"],
            "currently_active_files_first_introduced_after_cursor"
        );
        let continuation = first["next"].as_str().unwrap();
        let second = json(&success(archive(&temp).args([
            "--json",
            "app",
            "changes",
            "--collection",
            "Files",
            "--since",
            &base_commit,
            "--limit",
            "1",
            "--continue",
            continuation,
        ])));
        assert_eq!(second["items"].as_array().unwrap().len(), 1);
        assert!(second["next"].is_null());
        assert_ne!(
            first["items"][0]["file_ref_id"],
            second["items"][0]["file_ref_id"]
        );

        let current_commit = first["current"]["git_commit"].as_str().unwrap();
        let none = json(&success(archive(&temp).args([
            "--json",
            "app",
            "changes",
            "--collection",
            "Files",
            "--since",
            current_commit,
        ])));
        assert!(none["items"].as_array().unwrap().is_empty());
        let missing_cursor = archive(&temp)
            .args([
                "app",
                "changes",
                "--collection",
                "Files",
                "--since",
                "not-a-commit",
            ])
            .output()
            .unwrap();
        assert_eq!(missing_cursor.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&missing_cursor.stderr).contains("[cursor_not_found]"));

        let files = json(&success(archive(&temp).args([
            "--json",
            "file",
            "find",
            "--collection",
            "Files",
        ])));
        let first_id = files["items"][0]["file_ref_id"].as_str().unwrap();
        let second_id = files["items"][1]["file_ref_id"].as_str().unwrap();
        let request = temp.path().join("request.jsonl");
        fs::write(
            &request,
            format!("{first_id:?}\n{{\"file_ref_id\":{second_id:?}}}\n\"file_missing\"\n"),
        )
        .unwrap();
        let access = json(&success(archive(&temp).args([
            "--json",
            "app",
            "access",
            "--collection",
            "Files",
            "--input",
            request.to_str().unwrap(),
        ])));
        assert_eq!(access["requested_file_count"], 3);
        assert_eq!(access["summary"]["accessible"], 2);
        assert_eq!(access["summary"]["not_found"], 1);
        assert_eq!(access["items"][0]["state"], "accessible");
        assert_eq!(
            access["items"][0]["local_candidate"]["evidence"],
            "present_claim_on_revalidated_mount_not_freshly_verified"
        );
        assert!(Path::new(
            access["items"][0]["local_candidate"]["path"]["text"]
                .as_str()
                .unwrap()
        )
        .starts_with(&content));
        assert_eq!(access["items"][2]["state"], "not_found");

        let page = json(&success(archive(&temp).args([
            "--json",
            "app",
            "access",
            "--collection",
            "Files",
            "--input",
            request.to_str().unwrap(),
            "--limit",
            "1",
        ])));
        let access_continuation = page["next"].as_str().unwrap().to_owned();
        fs::write(&request, format!("{first_id:?}\n{second_id:?}\n")).unwrap();
        let changed_request = archive(&temp)
            .args([
                "--json",
                "app",
                "access",
                "--collection",
                "Files",
                "--input",
                request.to_str().unwrap(),
                "--limit",
                "1",
                "--continue",
                &access_continuation,
            ])
            .output()
            .unwrap();
        assert_eq!(changed_request.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&changed_request.stderr)
                .contains("\"code\":\"stale_continuation\""),
            "unexpected error: {}",
            String::from_utf8_lossy(&changed_request.stderr)
        );

        let database_path = root(&temp).join("archive.db");
        let database = rusqlite::Connection::open(&database_path).unwrap();
        database
            .execute("UPDATE device_mounts SET status = 'unmounted'", [])
            .unwrap();
        drop(database);
        let offline = json(&success(archive(&temp).args([
            "--json",
            "app",
            "access",
            "--collection",
            "Files",
            "--input",
            request.to_str().unwrap(),
        ])));
        assert!(offline["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["state"] == "attachment_required"));
        assert_eq!(offline["summary"]["attachment_required"], 2);
        assert_eq!(
            offline["attachment_plan"]["steps"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            offline["attachment_plan"]["steps"][0]["device_name"],
            "Test Device"
        );
        assert_eq!(
            offline["attachment_plan"]["steps"][0]["newly_covered_files"],
            2
        );
        assert_eq!(offline["attachment_plan"]["optimality"], "not_guaranteed");

        let database = rusqlite::Connection::open(&database_path).unwrap();
        database
            .execute("UPDATE copy_bindings SET state = 'missing'", [])
            .unwrap();
        drop(database);
        let unavailable = json(&success(archive(&temp).args([
            "--json",
            "app",
            "access",
            "--collection",
            "Files",
            "--input",
            request.to_str().unwrap(),
        ])));
        assert!(unavailable["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["state"] == "no_known_copy"));
        assert_eq!(unavailable["summary"]["no_known_copy"], 2);
        assert_eq!(
            unavailable["attachment_plan"]["no_attachable_copy_count"],
            2
        );
    }
}
