#[cfg(unix)]
mod unix {
    use std::fs::{self, File};
    use std::io::{BufWriter, Write as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{Duration, Instant};

    use serde_json::Value;
    use tempfile::TempDir;

    struct ScaleTemp {
        directory: Option<TempDir>,
        keep: bool,
    }

    impl ScaleTemp {
        fn new() -> Self {
            Self {
                directory: Some(TempDir::new().unwrap()),
                keep: std::env::var_os("ARCHIVE_LEDGER_SCALE_KEEP").is_some(),
            }
        }

        fn path(&self) -> &Path {
            self.directory.as_ref().unwrap().path()
        }
    }

    impl Drop for ScaleTemp {
        fn drop(&mut self) {
            if self.keep {
                let kept = self.directory.take().unwrap().keep();
                eprintln!("v2_scale_artifacts={}", kept.display());
            }
        }
    }

    #[test]
    #[ignore = "100k-file v2 acceptance gate; run explicitly with one test thread"]
    fn one_resumable_inventory_uses_one_commit_and_bounded_v2_records() {
        let file_count = std::env::var("ARCHIVE_LEDGER_V2_SCALE_FILES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(100_000);
        assert!(file_count > 1);
        let temp = ScaleTemp::new();
        let fixture = temp.path().join("fixture");
        let fixture_started = Instant::now();
        create_fixture(&fixture, file_count);
        let fixture_elapsed = fixture_started.elapsed();

        success(archive(&temp).args([
            "init",
            "Scale",
            "--archive-id",
            "arc_scale",
            "--non-interactive",
        ]));
        success(archive(&temp).args([
            "collection",
            "init",
            fixture.to_str().unwrap(),
            "--name",
            "Files",
            "--device",
            "Scale Device",
            "--site",
            "Scale Site",
            "--allow-unidentified-root",
            "--non-interactive",
        ]));

        let canonical = archive_root(&temp).join("canonical");
        let base_commit = git_head(&canonical);
        let commits_before = git_count(&canonical);
        let interrupted_started = Instant::now();
        let interrupted = json(&success(archive(&temp).args([
            "--json",
            "collection",
            "add",
            fixture.to_str().unwrap(),
            "--collection",
            "Files",
            "--job-id",
            "job_scale_inventory",
            "--scan-id",
            "scan_scale_inventory",
            "--max-items",
            &(file_count / 2).to_string(),
        ])));
        let interrupted_elapsed = interrupted_started.elapsed();
        assert_eq!(interrupted["status"], "running");
        assert_eq!(
            interrupted["summary"]["files_observed"],
            u64::try_from(file_count / 2).unwrap()
        );
        assert_eq!(git_count(&canonical), commits_before);

        let resume_started = Instant::now();
        let completed = json(&success(archive(&temp).args([
            "--json",
            "job",
            "resume",
            "job_scale_inventory",
        ])));
        let resume_elapsed = resume_started.elapsed();
        assert_eq!(completed["status"], "complete");
        assert_eq!(
            completed["summary"]["files_observed"],
            u64::try_from(file_count).unwrap()
        );
        assert_eq!(
            completed["append"]["items_written"],
            u64::try_from(file_count).unwrap() + 5
        );
        let records_written = completed["append"]["records_written"].as_u64().unwrap();
        assert!(
            records_written < 1_000,
            "100k logical observations expanded to {records_written} physical records"
        );
        assert_eq!(
            completed["apply"]["records_applied"].as_u64().unwrap(),
            records_written
        );
        assert_eq!(git_count(&canonical), commits_before + 1);

        let database_path = archive_root(&temp).join("archive.db");
        let database = rusqlite::Connection::open(&database_path).unwrap();
        let counts: (i64, i64, i64) = database
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM file_refs),
                   (SELECT COUNT(*) FROM copy_claims WHERE state = 'present'),
                   (SELECT COUNT(*) FROM verification_results WHERE result = 'ok')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            counts,
            (
                i64::try_from(file_count).unwrap(),
                i64::try_from(file_count).unwrap(),
                i64::try_from(file_count).unwrap(),
            )
        );
        let request_path = temp.path().join("app-request.jsonl");
        let mut request = BufWriter::new(File::create(&request_path).unwrap());
        let mut statement = database
            .prepare("SELECT file_ref_id FROM file_refs ORDER BY file_ref_id")
            .unwrap();
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap();
        for id in ids {
            writeln!(request, "{:?}", id.unwrap()).unwrap();
        }
        request.flush().unwrap();
        drop(request);
        drop(statement);
        drop(database);

        let changes_started = Instant::now();
        let changes = json(&success(archive(&temp).args([
            "--json",
            "app",
            "changes",
            "--collection",
            "Files",
            "--since",
            &base_commit,
            "--limit",
            "1000",
        ])));
        let changes_elapsed = changes_started.elapsed();
        assert_eq!(
            changes["items"].as_array().unwrap().len(),
            file_count.min(1_000)
        );
        assert!(
            changes_elapsed < Duration::from_secs(5),
            "application change-feed page took {changes_elapsed:?}"
        );

        let access_started = Instant::now();
        let access = json(&success(archive(&temp).args([
            "--json",
            "app",
            "access",
            "--collection",
            "Files",
            "--input",
            request_path.to_str().unwrap(),
            "--limit",
            "100",
        ])));
        let access_elapsed = access_started.elapsed();
        assert_eq!(
            access["requested_file_count"],
            u64::try_from(file_count).unwrap()
        );
        assert_eq!(
            access["summary"]["accessible"],
            u64::try_from(file_count).unwrap()
        );
        assert_eq!(access["items"].as_array().unwrap().len(), 100);
        assert!(access["attachment_plan"]["steps"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(
            access_elapsed < Duration::from_secs(15),
            "application access plan took {access_elapsed:?}"
        );

        let status_started = Instant::now();
        let status_output = archive(&temp).args(["--json", "status"]).output().unwrap();
        assert_eq!(
            status_output.status.code(),
            Some(10),
            "status failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&status_output.stdout),
            String::from_utf8_lossy(&status_output.stderr)
        );
        let status_elapsed = status_started.elapsed();
        let status = json(&status_output);
        assert_eq!(
            status["collections"][0]["file_count"],
            u64::try_from(file_count).unwrap()
        );
        assert!(
            status_elapsed < Duration::from_secs(5),
            "SQLite status took {status_elapsed:?}"
        );

        let verification = json(&success(
            archive(&temp).args(["--json", "events", "verify"]),
        ));
        assert_eq!(verification["origins"], 1);
        assert_eq!(
            verification["records"].as_u64().unwrap(),
            completed["append"]["last_seq"].as_u64().unwrap()
        );

        let rebuild_path = temp.path().join("rebuilt.db");
        let rebuild_started = Instant::now();
        success(archive(&temp).args(["db", "rebuild", "--target", rebuild_path.to_str().unwrap()]));
        let rebuild_elapsed = rebuild_started.elapsed();
        let rebuilt = rusqlite::Connection::open(&rebuild_path).unwrap();
        assert_eq!(
            rebuilt
                .query_row("SELECT COUNT(*) FROM file_refs", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            i64::try_from(file_count).unwrap()
        );

        eprintln!(
            "v2_scale_metrics files={file_count} fixture_ms={} interrupted_half_ms={} resume_publish_apply_ms={} app_changes_ms={} app_access_ms={} status_ms={} rebuild_ms={} records_written={} segments={} git_commit_delta=1 canonical_bytes={} sqlite_bytes={} rebuilt_bytes={}",
            fixture_elapsed.as_millis(),
            interrupted_elapsed.as_millis(),
            resume_elapsed.as_millis(),
            changes_elapsed.as_millis(),
            access_elapsed.as_millis(),
            status_elapsed.as_millis(),
            rebuild_elapsed.as_millis(),
            records_written,
            verification["segments"].as_u64().unwrap(),
            directory_size(&canonical),
            fs::metadata(&database_path).unwrap().len(),
            fs::metadata(&rebuild_path).unwrap().len(),
        );
    }

    fn archive(temp: &ScaleTemp) -> Command {
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

    fn archive_root(temp: &ScaleTemp) -> PathBuf {
        temp.path().join("data/archive-ledger/archives/arc_scale")
    }

    fn create_fixture(root: &Path, file_count: usize) {
        const FILES_PER_DIRECTORY: usize = 1_000;
        fs::create_dir(root).unwrap();
        for directory_number in 0..file_count.div_ceil(FILES_PER_DIRECTORY) {
            let directory = root.join(format!("d{directory_number:06}"));
            fs::create_dir(&directory).unwrap();
            let start = directory_number * FILES_PER_DIRECTORY;
            let end = (start + FILES_PER_DIRECTORY).min(file_count);
            for file_number in start..end {
                File::create(directory.join(format!("f{file_number:09}"))).unwrap();
            }
        }
    }

    fn git_count(root: &Path) -> u64 {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-list", "--count", "HEAD"])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn git_head(root: &Path) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn directory_size(root: &Path) -> u64 {
        let mut total = 0_u64;
        let mut directories = vec![root.to_path_buf()];
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                if metadata.is_dir() {
                    directories.push(entry.path());
                } else {
                    total = total.saturating_add(metadata.len());
                }
            }
        }
        total
    }
}
