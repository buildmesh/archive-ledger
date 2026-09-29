use super::*;
use tempfile::TempDir;

fn append(store: &V2OriginStore, name: &str) -> Result<V2AppendResult> {
    store.append_batch(
        "archive_update",
        1,
        json!({}),
        json!({}),
        vec![json!({
            "kind": "archive_updated", "archive_id": "arc_publication", "archive_display_name": name
        })],
    )
}

struct Pending {
    _temp: TempDir,
    store: V2OriginStore,
    parent: String,
    frontier: String,
    segment: PathBuf,
}

impl Pending {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let archive = temp.path().join("archive");
        initialize_v2_archive(&archive, "arc_publication", "Original", 1_782_000_000_000).unwrap();
        let store = V2OriginStore::open(archive.join("canonical")).unwrap();
        let parent = git_stdout(store.root(), "read parent", &["rev-parse", "HEAD"]).unwrap();
        let before = store.verify_compact().unwrap();
        let origin = store.active_origin_id().unwrap();
        let next = before
            .accepted_frontier
            .origins
            .iter()
            .find(|tail| tail.origin_id == origin)
            .unwrap()
            .seq
            + 1;
        // A real failure after durable HEAD replacement, before git add/commit.
        let lock = store.root().join(".git/index.lock");
        fs::write(&lock, b"test-owned lock").unwrap();
        assert!(append(&store, "Published once").is_err());
        fs::remove_file(lock).unwrap();
        let frontier = store.verify_compact().unwrap().accepted_frontier_hash;
        assert_ne!(frontier, before.accepted_frontier_hash);
        let segment = segment_relative_path(&origin, next);
        Self {
            _temp: temp,
            store,
            parent,
            frontier,
            segment,
        }
    }

    fn assert_refused_preserving_inputs(&self) {
        let files = snapshot(self.store.root());
        let index = fs::read(self.store.root().join(".git/index")).unwrap();
        let error = self.store.recover_pending_publication().unwrap_err();
        assert_eq!(error.code(), "v2_publication_recovery_refused", "{error}");
        assert_eq!(snapshot(self.store.root()), files);
        assert_eq!(
            fs::read(self.store.root().join(".git/index")).unwrap(),
            index
        );
        assert_eq!(
            git_stdout(self.store.root(), "read parent", &["rev-parse", "HEAD"]).unwrap(),
            self.parent
        );
    }
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == ".git" {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), files);
            } else {
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

#[test]
fn publication_recovers_unstaged_and_staged_signed_append_once() {
    for staged in [false, true] {
        let pending = Pending::new();
        let files = snapshot(pending.store.root());
        let records = pending.store.verify_compact().unwrap().record_count;
        if staged {
            run_git(
                pending.store.root(),
                "stage interrupted append",
                &["add", "--", "events", "manifests", "frontiers"],
            )
            .unwrap();
        }
        let commit = pending
            .store
            .recover_pending_publication()
            .unwrap()
            .unwrap();
        assert_ne!(commit, pending.parent);
        assert_eq!(
            git_stdout(
                pending.store.root(),
                "read commit parent",
                &["rev-parse", "HEAD^"]
            )
            .unwrap(),
            pending.parent
        );
        assert_eq!(snapshot(pending.store.root()), files);
        assert_eq!(
            pending.store.verify_compact().unwrap().record_count,
            records
        );
        assert_eq!(
            git_blob(
                pending.store.root(),
                "HEAD",
                "frontiers/v2/HEAD",
                "read frontier"
            )
            .unwrap(),
            format!("{}\n", pending.frontier).as_bytes()
        );
        assert!(git_stdout(
            pending.store.root(),
            "inspect clean tree",
            &["status", "--porcelain"]
        )
        .unwrap()
        .is_empty());
        assert_eq!(pending.store.recover_pending_publication().unwrap(), None);
        assert_eq!(
            git_stdout(pending.store.root(), "read commit", &["rev-parse", "HEAD"]).unwrap(),
            commit
        );
    }
}

#[test]
fn publication_is_committed_separately_before_next_append() {
    let pending = Pending::new();
    append(&pending.store, "Next mutation").unwrap();
    assert_eq!(
        git_stdout(
            pending.store.root(),
            "read original parent",
            &["rev-parse", "HEAD^^"]
        )
        .unwrap(),
        pending.parent
    );
    assert_eq!(
        git_blob(
            pending.store.root(),
            "HEAD^",
            "frontiers/v2/HEAD",
            "read recovered frontier"
        )
        .unwrap(),
        format!("{}\n", pending.frontier).as_bytes()
    );
}

#[test]
fn publication_refuses_unrelated_and_ambiguous_index_changes_without_writes() {
    for case in 0..5 {
        let pending = Pending::new();
        match case {
            0 | 1 => {
                fs::write(pending.store.root().join("operator-notes"), b"preserve me").unwrap();
                if case == 1 {
                    run_git(
                        pending.store.root(),
                        "stage unrelated file",
                        &["add", "operator-notes"],
                    )
                    .unwrap();
                }
            }
            2 => {
                let hash = git_stdout(
                    pending.store.root(),
                    "hash wrong index bytes",
                    &["hash-object", "-w", "--no-filters", "genesis.json"],
                )
                .unwrap();
                run_git(
                    pending.store.root(),
                    "stage ambiguous HEAD",
                    &[
                        "update-index",
                        "--cacheinfo",
                        "100644",
                        &hash,
                        "frontiers/v2/HEAD",
                    ],
                )
                .unwrap();
            }
            3 => {
                run_git(
                    pending.store.root(),
                    "hide tracked file",
                    &["update-index", "--skip-worktree", "genesis.json"],
                )
                .unwrap();
            }
            _ => {
                run_git(
                    pending.store.root(),
                    "stage all",
                    &["add", "--", "events", "manifests", "frontiers"],
                )
                .unwrap();
                fs::write(
                    pending.store.root().join(&pending.segment),
                    b"changed after staging",
                )
                .unwrap();
            }
        }
        pending.assert_refused_preserving_inputs();
    }
}

#[test]
fn publication_refuses_corrupt_signed_history_and_reflog_rollback() {
    for case in 0..3 {
        let mut pending = Pending::new();
        if case < 2 {
            let path = if case == 0 {
                pending.segment.clone()
            } else {
                segment_relative_path(&pending.store.active_origin_id().unwrap(), 1)
            };
            let path = pending.store.root().join(path);
            let mut bytes = fs::read(&path).unwrap();
            bytes[10] ^= 1;
            fs::write(path, bytes).unwrap();
        } else {
            pending.store.recover_pending_publication().unwrap();
            run_git(
                pending.store.root(),
                "simulate rollback",
                &["reset", "--mixed", &pending.parent],
            )
            .unwrap();
            pending.parent = git_stdout(
                pending.store.root(),
                "read rollback parent",
                &["rev-parse", "HEAD"],
            )
            .unwrap();
        }
        pending.assert_refused_preserving_inputs();
    }
}

#[cfg(unix)]
#[test]
fn publication_refuses_linked_candidates_and_preserves_targets() {
    for hard_link in [false, true] {
        let pending = Pending::new();
        let source = pending.store.root().join(&pending.segment);
        let external = pending._temp.path().join("external-segment");
        fs::rename(&source, &external).unwrap();
        if hard_link {
            fs::hard_link(&external, &source).unwrap();
        } else {
            std::os::unix::fs::symlink(&external, &source).unwrap();
        }
        let bytes = fs::read(&external).unwrap();
        pending.assert_refused_preserving_inputs();
        assert_eq!(fs::read(external).unwrap(), bytes);
    }
}

#[test]
fn publication_refuses_real_pending_merge_without_consuming_merge_metadata() {
    let pending = Pending::new();
    let root = pending.store.root();
    let tree = git_stdout(root, "read committed tree", &["rev-parse", "HEAD^{tree}"]).unwrap();
    let other = git_stdout(
        root,
        "create unrelated empty commit",
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@localhost",
            "commit-tree",
            &tree,
            "-p",
            &pending.parent,
            "-m",
            "Unrelated empty commit",
        ],
    )
    .unwrap();
    run_git(
        root,
        "start unrelated merge",
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@localhost",
            "merge",
            "--no-ff",
            "--no-commit",
            &other,
        ],
    )
    .unwrap();
    assert!(git_stdout(
        root,
        "confirm merge has no staged tree changes",
        &["diff", "--cached", "--name-only"]
    )
    .unwrap()
    .is_empty());
    let git_dir = git_stdout(root, "locate gitdir", &["rev-parse", "--git-dir"]).unwrap();
    let git_dir = root.join(git_dir);
    let metadata = snapshot(&git_dir);
    assert_eq!(
        fs::read(git_dir.join("MERGE_HEAD")).unwrap(),
        format!("{other}\n").as_bytes()
    );
    pending.assert_refused_preserving_inputs();
    assert_eq!(snapshot(&git_dir), metadata);
}

#[test]
fn publication_refuses_other_in_progress_git_operation_states() {
    for name in [
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "REBASE_HEAD",
        "rebase-merge",
        "rebase-apply",
        "sequencer",
    ] {
        let pending = Pending::new();
        let location = git_stdout(
            pending.store.root(),
            "locate operation state",
            &["rev-parse", "--git-path", name],
        )
        .unwrap();
        let path = pending.store.root().join(location);
        if name.ends_with("HEAD") {
            fs::write(&path, format!("{}\n", pending.parent)).unwrap();
        } else {
            fs::create_dir(&path).unwrap();
            fs::write(path.join("operator-state"), b"preserve operation").unwrap();
        }
        pending.assert_refused_preserving_inputs();
        if name.ends_with("HEAD") {
            assert_eq!(
                fs::read(&path).unwrap(),
                format!("{}\n", pending.parent).as_bytes()
            );
        } else {
            assert_eq!(
                fs::read(path.join("operator-state")).unwrap(),
                b"preserve operation"
            );
        }
    }
}
