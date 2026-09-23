use super::*;
use crate::v2_projection::V2ProjectionDb;
use tempfile::TempDir;

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let destination = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

fn canonical_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == ".git" {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, output);
            } else {
                output.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}

fn append_name(store: &V2OriginStore, name: &str) -> Result<V2AppendResult> {
    store.append_batch(
        "archive_update",
        1,
        json!({"archive_id": "arc_recovery"}),
        json!({}),
        vec![json!({
            "kind": "archive_updated",
            "archive_id": "arc_recovery",
            "archive_display_name": name
        })],
    )
}

fn append_local_job(store: &V2OriginStore, name: &str) -> Result<V2AppendResult> {
    store.append_batch(
        "job_start",
        1,
        json!({}),
        json!({}),
        vec![json!({
            "kind": "job_started",
            "job_id": format!("job_{name}"),
            "job_type": "scan",
            "input_version": "1",
            "params": {}
        })],
    )
}

struct InterruptedAppend {
    _temp: TempDir,
    archive: PathBuf,
    store: V2OriginStore,
    accepted: BTreeMap<PathBuf, Vec<u8>>,
    accepted_hash: String,
    origin_id: String,
    first_seq: u64,
    segment: PathBuf,
    manifest: PathBuf,
    frontier: PathBuf,
    artifacts: BTreeMap<PathBuf, Vec<u8>>,
    newly_enrolled: bool,
}

impl InterruptedAppend {
    fn new() -> Self {
        Self::new_for_origin(false)
    }

    fn new_for_origin(newly_enrolled: bool) -> Self {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_recovery", "Original", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        if newly_enrolled {
            let authority = temp.path().join("enrollment-authority");
            copy_tree(&archive, &authority);
            let request = store.prepare_enrollment("New recovery client").unwrap();
            V2OriginStore::open(authority.join("canonical"))
                .unwrap()
                .approve_enrollment(&request)
                .unwrap();
            fs::remove_dir_all(archive.join("canonical")).unwrap();
            copy_tree(&authority.join("canonical"), &archive.join("canonical"));
        } else {
            // Two accepted segments make corruption outside the most recent segment
            // observable: recovery must verify the entire accepted history.
            append_name(&store, "Accepted").unwrap();
        }
        let accepted = canonical_files(store.root());
        let accepted_hash = store.verify().unwrap().accepted_frontier_hash;
        let generator = temp.path().join("generator");
        copy_tree(&archive, &generator);
        let generating_store = V2OriginStore::open(generator.join("canonical")).unwrap();
        let interrupted = if newly_enrolled {
            append_local_job(&generating_store, "Interrupted")
        } else {
            append_name(&generating_store, "Interrupted")
        }
        .unwrap();
        let segment = segment_relative_path(&interrupted.origin_id, interrupted.first_seq);
        let manifest = manifest_relative_path(&interrupted.origin_id, interrupted.first_seq);
        let frontier = frontier_path(Path::new(""), &interrupted.accepted_frontier_hash).unwrap();
        let artifacts = [&segment, &manifest, &frontier]
            .into_iter()
            .map(|path| {
                (
                    path.clone(),
                    fs::read(generating_store.root().join(path)).unwrap(),
                )
            })
            .collect();
        Self {
            _temp: temp,
            archive,
            store,
            accepted,
            accepted_hash,
            origin_id: interrupted.origin_id,
            first_seq: interrupted.first_seq,
            segment,
            manifest,
            frontier,
            artifacts,
            newly_enrolled,
        }
    }

    fn write(&self, path: &Path, bytes: &[u8]) {
        let target = self.store.root().join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, bytes).unwrap();
    }

    fn install(&self, paths: &[&Path]) -> BTreeMap<PathBuf, Vec<u8>> {
        paths
            .iter()
            .map(|path| {
                let bytes = self.artifacts.get(*path).unwrap().clone();
                self.write(path, &bytes);
                (path.to_path_buf(), bytes)
            })
            .collect()
    }

    fn assert_recovered(&self, expected: &BTreeMap<PathBuf, Vec<u8>>) {
        let appended = if self.newly_enrolled {
            append_local_job(&self.store, "Recovered")
        } else {
            append_name(&self.store, "Recovered")
        }
        .unwrap();
        assert_eq!(appended.first_seq, self.first_seq);
        let recovery_root = self.archive.join("local/append-recovery");
        let retained: Vec<_> = fs::read_dir(&recovery_root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(retained.len(), 1);
        let retained = &retained[0];
        assert_eq!(
            appended.recovered_append.as_deref(),
            Some(retained.as_path())
        );
        let metadata: Value =
            serde_json::from_slice(&fs::read(retained.join("recovery.json")).unwrap()).unwrap();
        assert_eq!(metadata["accepted_frontier_hash"], self.accepted_hash);
        assert_eq!(metadata["origin_id"], self.origin_id);
        assert_eq!(metadata["first_seq"], self.first_seq);
        let mappings = metadata["files"].as_array().unwrap();
        assert_eq!(mappings.len(), expected.len());
        for (source, bytes) in expected {
            let mapping = mappings
                .iter()
                .find(|mapping| mapping["source"].as_str() == source.to_str())
                .expect("each displaced artifact must be recorded");
            let retained_name = if source == &self.segment {
                "segment.jsonl"
            } else if source == &self.manifest {
                "manifest.json"
            } else {
                "frontier.json"
            };
            assert_eq!(mapping["retained"], retained_name);
            assert_eq!(fs::read(retained.join(retained_name)).unwrap(), *bytes);
        }
        for (path, bytes) in &self.accepted {
            if path != Path::new("frontiers/v2/HEAD") {
                assert_eq!(fs::read(self.store.root().join(path)).unwrap(), *bytes);
            }
        }
        assert!(!self.store.root().join(&self.frontier).exists());
        let tracked =
            git_stdout(self.store.root(), "inspect recovered tree", &["ls-files"]).unwrap();
        assert!(!tracked
            .lines()
            .any(|path| path == self.frontier.to_str().unwrap()));
        assert!(!tracked.contains("append-recovery"));
        let verified = self.store.verify().unwrap();
        assert_eq!(
            verified.accepted_frontier_hash,
            appended.accepted_frontier_hash
        );
        assert_eq!(verified.segment_count, 3);
        let database_path = self.archive.join("recovered.db");
        V2ProjectionDb::rebuild(&self.store, &database_path).unwrap();
        let database = V2ProjectionDb::open_existing(&database_path).unwrap();
        if self.newly_enrolled {
            let connection = rusqlite::Connection::open(&database_path).unwrap();
            let jobs: Vec<String> = connection
                .prepare("SELECT job_id FROM jobs ORDER BY job_id")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            assert_eq!(jobs, ["job_Recovered"]);
        } else {
            assert_eq!(database.status().unwrap().archive_name, "Recovered");
        }
        run_git(
            self.store.root(),
            "fsck recovered repository",
            &["fsck", "--full"],
        )
        .unwrap();
    }

    fn assert_refused(&self, require_recovery_code: bool) {
        let before = canonical_files(self.store.root());
        let index_before = fs::read(self.store.root().join(".git/index")).unwrap();
        let head_before =
            git_stdout(self.store.root(), "read head", &["rev-parse", "HEAD"]).unwrap();
        let error = append_name(&self.store, "Must not publish").unwrap_err();
        if require_recovery_code {
            assert_eq!(error.code(), "v2_append_recovery_refused", "{error}");
        }
        assert_eq!(canonical_files(self.store.root()), before);
        assert_eq!(
            fs::read(self.store.root().join(".git/index")).unwrap(),
            index_before
        );
        assert_eq!(
            git_stdout(self.store.root(), "read head", &["rev-parse", "HEAD"]).unwrap(),
            head_before
        );
        assert!(!self.archive.join("local/append-recovery").exists());
    }
}

#[test]
fn recovers_first_interrupted_append_from_newly_enrolled_origin() {
    let fixture = InterruptedAppend::new_for_origin(true);
    assert_eq!(fixture.first_seq, 1);
    let accepted = fixture.store.verify().unwrap();
    assert!(accepted.clients.contains_key(&fixture.origin_id));
    assert!(accepted
        .accepted_frontier
        .origins
        .iter()
        .all(|origin| origin.origin_id != fixture.origin_id));
    let manifest: SignedSegmentManifest =
        serde_json::from_slice(&fixture.artifacts[&fixture.manifest]).unwrap();
    assert!(manifest.body.previous_segment_manifest_hash.is_none());
    let expected = fixture.install(&[&fixture.segment, &fixture.manifest, &fixture.frontier]);
    fixture.assert_recovered(&expected);
    assert_eq!(
        fixture
            .store
            .verify()
            .unwrap()
            .accepted_frontier
            .origins
            .len(),
        2
    );
}

#[test]
fn recovers_each_pre_head_publication_boundary_without_adopting_abandoned_batch() {
    for stage in 0..5 {
        let fixture = InterruptedAppend::new();
        let mut expected = fixture.install(&[&fixture.segment]);
        if stage >= 1 {
            let mut manifest = fixture.artifacts[&fixture.manifest].clone();
            if stage == 1 {
                manifest.truncate(manifest.len() / 2);
            }
            fixture.write(&fixture.manifest, &manifest);
            expected.insert(fixture.manifest.clone(), manifest);
        }
        if stage >= 3 {
            let mut frontier = fixture.artifacts[&fixture.frontier].clone();
            if stage == 3 {
                frontier.truncate(frontier.len() / 2);
            }
            fixture.write(&fixture.frontier, &frontier);
            expected.insert(fixture.frontier.clone(), frontier);
        }
        fixture.assert_recovered(&expected);
    }
}

#[test]
fn recovers_segment_without_a_parseable_record_and_manifest_without_segment() {
    let fixture = InterruptedAppend::new();
    let bytes = b"interrupted segment write\n".to_vec();
    fixture.write(&fixture.segment, &bytes);
    fixture.assert_recovered(&BTreeMap::from([(fixture.segment.clone(), bytes)]));

    let fixture = InterruptedAppend::new();
    let expected = fixture.install(&[&fixture.manifest]);
    fixture.assert_recovered(&expected);
}

#[test]
fn recovers_when_a_prior_recovery_already_removed_frontier_or_manifest() {
    for removed_manifest in [false, true] {
        let fixture = InterruptedAppend::new();
        let mut expected =
            fixture.install(&[&fixture.segment, &fixture.manifest, &fixture.frontier]);
        fs::remove_file(fixture.store.root().join(&fixture.frontier)).unwrap();
        expected.remove(&fixture.frontier);
        if removed_manifest {
            fs::remove_file(fixture.store.root().join(&fixture.manifest)).unwrap();
            expected.remove(&fixture.manifest);
        }
        fixture.assert_recovered(&expected);
    }
}

#[test]
fn refuses_candidates_in_index_current_commit_history_or_reflogs() {
    for stage in 0..4 {
        let fixture = InterruptedAppend::new();
        fixture.install(&[&fixture.segment, &fixture.manifest, &fixture.frontier]);
        let accepted_commit = git_stdout(
            fixture.store.root(),
            "read accepted commit",
            &["rev-parse", "HEAD"],
        )
        .unwrap();
        run_git(
            fixture.store.root(),
            "stage interrupted files",
            &["add", "--", "events", "manifests", "frontiers"],
        )
        .unwrap();
        if stage >= 1 {
            commit_canonical_tree(fixture.store.root(), "test interrupted commit").unwrap();
        }
        if stage == 2 {
            run_git(
                fixture.store.root(),
                "remove interrupted artifacts",
                &[
                    "rm",
                    "--",
                    fixture.segment.to_str().unwrap(),
                    fixture.manifest.to_str().unwrap(),
                    fixture.frontier.to_str().unwrap(),
                ],
            )
            .unwrap();
            commit_canonical_tree(fixture.store.root(), "test remove interrupted commit").unwrap();
            fixture.install(&[&fixture.segment, &fixture.manifest, &fixture.frontier]);
        }
        if stage == 3 {
            run_git(
                fixture.store.root(),
                "isolate reflog history",
                &["reset", "--hard", &accepted_commit],
            )
            .unwrap();
            fixture.install(&[&fixture.segment, &fixture.manifest, &fixture.frontier]);
        }
        fixture.assert_refused(true);
    }
}

#[test]
fn refuses_recovery_when_older_accepted_history_is_corrupt() {
    let fixture = InterruptedAppend::new();
    fixture.install(&[&fixture.segment, &fixture.manifest, &fixture.frontier]);
    let old_segment = fixture
        .store
        .root()
        .join(segment_relative_path(&fixture.origin_id, 1));
    let mut bytes = fs::read(&old_segment).unwrap();
    bytes[10] ^= 1;
    fs::write(old_segment, bytes).unwrap();
    fixture.assert_refused(false);
}

#[test]
fn refuses_mismatched_detached_frontier_and_incomplete_manifest_with_frontier() {
    for partial_manifest in [false, true] {
        let fixture = InterruptedAppend::new();
        fixture.install(&[&fixture.segment, &fixture.manifest, &fixture.frontier]);
        let path = if partial_manifest {
            &fixture.manifest
        } else {
            &fixture.frontier
        };
        let mut bytes = fixture.artifacts[path].clone();
        if partial_manifest {
            bytes.truncate(bytes.len() / 2);
        } else {
            bytes[10] ^= 1;
        }
        fixture.write(path, &bytes);
        fixture.assert_refused(true);
    }
}

#[cfg(unix)]
#[test]
fn refuses_symlinked_or_hardlinked_candidates_without_modifying_their_targets() {
    use std::os::unix::fs::symlink;
    for hard_link in [false, true] {
        let fixture = InterruptedAppend::new();
        let external = fixture.archive.join("external-segment");
        let original = &fixture.artifacts[&fixture.segment];
        fs::write(&external, original).unwrap();
        let candidate = fixture.store.root().join(&fixture.segment);
        if hard_link {
            fs::hard_link(&external, &candidate).unwrap();
        } else {
            symlink(&external, &candidate).unwrap();
        }
        fixture.assert_refused(true);
        assert_eq!(fs::read(external).unwrap(), *original);
        if !hard_link {
            assert!(fs::symlink_metadata(candidate)
                .unwrap()
                .file_type()
                .is_symlink());
        }
    }
}

#[cfg(unix)]
#[test]
fn refuses_a_candidate_beneath_a_symlinked_origin_directory() {
    use std::os::unix::fs::symlink;
    let fixture = InterruptedAppend::new();
    fixture.install(&[&fixture.segment, &fixture.manifest]);
    let origin_directory = fixture
        .store
        .root()
        .join(&fixture.segment)
        .parent()
        .unwrap()
        .to_path_buf();
    let external = fixture.archive.join("external-origin");
    fs::rename(&origin_directory, &external).unwrap();
    symlink(&external, &origin_directory).unwrap();
    fixture.assert_refused(true);
    assert!(fs::symlink_metadata(origin_directory)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read(external.join(fixture.segment.file_name().unwrap())).unwrap(),
        fixture.artifacts[&fixture.segment]
    );
}
