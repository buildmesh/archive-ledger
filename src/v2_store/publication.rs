//! Finish the one local append whose durable frontier advanced before its Git commit.

use super::*;

const HEAD_PATH: &str = "frontiers/v2/HEAD";

impl V2OriginStore {
    /// Publish an already accepted, verified local append without generating events.
    /// Returns the new Git commit, or `None` when publication is already complete.
    pub fn recover_pending_publication(&self) -> Result<Option<String>> {
        let (lock, lock_path) = self.acquire_append_lock()?;
        let result = self.recover_pending_publication_locked();
        let unlock = FileExt::unlock(&lock)
            .map_err(|source| io_error("unlock canonical append", &lock_path, source));
        match (result, unlock) {
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            (Ok(result), Ok(())) => Ok(result),
        }
    }

    pub(super) fn recover_pending_publication_locked(&self) -> Result<Option<String>> {
        let committed = git_blob(&self.root, "HEAD", HEAD_PATH, "read committed frontier")?;
        let working = read_file(&self.root.join(HEAD_PATH))?;
        if committed == working {
            return Ok(None);
        }
        self.finish_pending_publication(&committed)
            .map(Some)
            .map_err(|error| match error {
                V2StoreError::PublicationRecoveryRefused(_) => error,
                other => refused(other.to_string()),
            })
    }

    fn finish_pending_publication(&self, committed_head: &[u8]) -> Result<String> {
        refuse_in_progress_git_operation(&self.root)?;
        let parent = git_stdout(
            &self.root,
            "read publication parent",
            &["rev-parse", "HEAD"],
        )?;
        let old_hash = std::str::from_utf8(committed_head)
            .map_err(|_| refused("committed frontier HEAD is not UTF-8"))?
            .trim();
        regular_file(&self.root, HEAD_PATH)?;
        let new_hash = read_file(&self.root.join(HEAD_PATH))?;
        let new_hash = std::str::from_utf8(&new_hash)
            .map_err(|_| refused("working frontier HEAD is not UTF-8"))?
            .trim();
        let new_frontier = path_text(&frontier_path(Path::new(""), new_hash)?)?;
        regular_file(&self.root, &new_frontier)?;
        let successor: CausalFrontier = parse_json(
            &self.root.join(&new_frontier),
            &read_file(&self.root.join(&new_frontier))?,
        )?;
        if successor.previous_frontiers != [old_hash] {
            return Err(refused(
                "working frontier is not one direct successor of Git HEAD",
            ));
        }
        let old_frontier = path_text(&frontier_path(Path::new(""), old_hash)?)?;
        let base: CausalFrontier = serde_json::from_slice(&git_blob(
            &self.root,
            &parent,
            &old_frontier,
            "read committed base frontier",
        )?)
        .map_err(|_| refused("committed base frontier is malformed"))?;
        let origin = self.active_origin_id()?;
        let old_tail = base.origins.iter().find(|tail| tail.origin_id == origin);
        let first_seq = old_tail
            .map_or(Some(1), |tail| tail.seq.checked_add(1))
            .ok_or_else(|| refused("local origin sequence overflow"))?;
        let new_tail = successor
            .origins
            .iter()
            .find(|tail| tail.origin_id == origin)
            .ok_or_else(|| refused("successor has no active local origin"))?;
        let mut expected_frontier = base.clone();
        expected_frontier
            .origins
            .retain(|tail| tail.origin_id != origin);
        expected_frontier.origins.push(new_tail.clone());
        expected_frontier
            .origins
            .sort_by(|a, b| a.origin_id.cmp(&b.origin_id));
        expected_frontier.previous_frontiers = vec![old_hash.to_owned()];
        if successor != expected_frontier || new_tail.seq < first_seq {
            return Err(refused(
                "successor must advance only the active local origin",
            ));
        }
        let segment = path_text(&segment_relative_path(&origin, first_seq))?;
        let manifest = path_text(&manifest_relative_path(&origin, first_seq))?;
        let expected = BTreeSet::from([
            HEAD_PATH.to_owned(),
            segment.clone(),
            manifest.clone(),
            new_frontier,
        ]);
        let tree = parse_entries(
            &git_stdout_preserve(
                &self.root,
                "inspect committed publication tree",
                &["ls-tree", "-r", "-z", &parent],
            )?,
            false,
        )?;
        let index = parse_entries(
            &git_stdout_preserve(
                &self.root,
                "inspect publication index",
                &["ls-files", "--stage", "-z"],
            )?,
            true,
        )?;
        // Refuse conflict, assume-unchanged, and skip-worktree entries before any write.
        for entry in
            git_stdout_preserve(&self.root, "inspect index flags", &["ls-files", "-v", "-z"])?
                .split('\0')
                .filter(|entry| !entry.is_empty())
        {
            if !entry.starts_with("H ") {
                return Err(refused("index has unresolved or hidden entries"));
            }
        }
        let mut working_entries = BTreeMap::new();
        for path in tree.keys().chain(expected.iter()) {
            if working_entries.contains_key(path) {
                continue;
            }
            regular_file(&self.root, path)?;
            let hash = git_stdout(
                &self.root,
                "hash publication file",
                &["hash-object", "--no-filters", "--", path],
            )?;
            let entry = ("100644".to_owned(), hash);
            if !expected.contains(path) && tree.get(path) != Some(&entry) {
                return Err(refused(format!("unrelated working change at {path}")));
            }
            working_entries.insert(path.clone(), entry);
        }
        for path in expected.iter().filter(|path| path.as_str() != HEAD_PATH) {
            if tree.contains_key(path)
                || !git_stdout(
                    &self.root,
                    "inspect publication history",
                    &[
                        "log",
                        "--all",
                        "--reflog",
                        "--full-history",
                        "-1",
                        "--format=%H",
                        "--",
                        path,
                    ],
                )?
                .is_empty()
            {
                return Err(refused(format!(
                    "publication path has existing Git history: {path}"
                )));
            }
        }
        for (path, entry) in &index {
            if if expected.contains(path) {
                Some(entry) != tree.get(path) && Some(entry) != working_entries.get(path)
            } else {
                Some(entry) != tree.get(path)
            } {
                return Err(refused(format!(
                    "unrelated or ambiguous index entry at {path}"
                )));
            }
        }
        if tree.keys().any(|path| !index.contains_key(path)) {
            return Err(refused("index removes committed paths"));
        }
        for path in git_stdout_preserve(
            &self.root,
            "inspect untracked publication files",
            &["ls-files", "--others", "-z"],
        )?
        .split('\0')
        .filter(|path| !path.is_empty())
        {
            if !expected.contains(path) {
                return Err(refused(format!("unrelated untracked file at {path}")));
            }
        }
        // Full streaming verification is deliberate on this exceptional path, after
        // proving that no accepted files changed and that candidates are regular files.
        let verified = self.verify_compact()?;
        if verified.accepted_frontier_hash != new_hash {
            return Err(refused("working frontier changed during verification"));
        }
        let signed: SignedSegmentManifest = parse_json(
            &self.root.join(&manifest),
            &read_file(&self.root.join(&manifest))?,
        )?;
        if signed.body.first_seq != first_seq
            || signed.body.last_seq != new_tail.seq
            || signed.body.causal_base_frontier_hash != old_hash
            || signed.body.previous_segment_manifest_hash.as_deref()
                != old_tail.map(|tail| tail.segment_manifest_hash.as_str())
            || signed.manifest_hash()? != new_tail.segment_manifest_hash
        {
            return Err(refused("local advance is not exactly one signed segment"));
        }
        if git_stdout(
            &self.root,
            "recheck publication parent",
            &["rev-parse", "HEAD"],
        )? != parent
        {
            return Err(refused("Git HEAD changed during publication recovery"));
        }
        refuse_in_progress_git_operation(&self.root)?;
        // Only validated paths are staged, with raw blobs so Git filters cannot
        // transform signed canonical bytes. Failed commits may leave this exact index.
        for path in &expected {
            let hash = git_stdout(
                &self.root,
                "write publication blob",
                &["hash-object", "-w", "--no-filters", "--", path],
            )?;
            if hash != working_entries[path].1 {
                return Err(refused("publication files changed during recovery"));
            }
        }
        for path in &expected {
            run_git(
                &self.root,
                "stage verified publication",
                &[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    "100644",
                    &working_entries[path].1,
                    path,
                ],
            )?;
        }
        commit_staged_canonical_tree(&self.root, "recover pending publication")
    }
}

// A clean-looking index can still belong to an unfinished merge or sequenced
// operation. Ordinary `git commit` would consume that state (including extra
// merge parents), so recovery must leave it entirely for the operator to resolve.
fn refuse_in_progress_git_operation(root: &Path) -> Result<()> {
    for name in [
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "REBASE_HEAD",
        "rebase-merge",
        "rebase-apply",
        "sequencer",
    ] {
        let location = git_stdout(
            root,
            "locate Git operation state",
            &["rev-parse", "--git-path", name],
        )?;
        let path = root.join(location);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Err(refused(format!("unfinished Git operation ({name})"))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("inspect Git operation state", path, error)),
        }
    }
    Ok(())
}

fn refused(message: impl Into<String>) -> V2StoreError {
    V2StoreError::PublicationRecoveryRefused(message.into())
}

fn parse_entries(output: &str, index: bool) -> Result<BTreeMap<String, (String, String)>> {
    let mut entries = BTreeMap::new();
    for entry in output.split('\0').filter(|entry| !entry.is_empty()) {
        let (metadata, path) = entry
            .split_once('\t')
            .ok_or_else(|| refused("unrecognized Git entry"))?;
        let parts: Vec<_> = metadata.split_whitespace().collect();
        let hash = if index {
            if parts.len() != 3 || parts[2] != "0" {
                return Err(refused("unmerged index entry"));
            }
            parts[1]
        } else {
            if parts.len() != 3 || parts[1] != "blob" {
                return Err(refused("unexpected Git tree entry"));
            }
            parts[2]
        };
        if parts[0] != "100644"
            || entries
                .insert(path.to_owned(), (parts[0].to_owned(), hash.to_owned()))
                .is_some()
        {
            return Err(refused("unsafe or duplicate Git entry"));
        }
    }
    Ok(entries)
}

fn regular_file(root: &Path, relative: &str) -> Result<()> {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(refused("unsafe publication path"));
        }
        path.push(component);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect publication path", &path, error))?;
        if metadata.file_type().is_symlink()
            || if path == root.join(relative) {
                !metadata.is_file()
            } else {
                !metadata.is_dir()
            }
        {
            return Err(refused(format!(
                "unsafe publication path {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        if metadata.is_file() {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 || metadata.mode() & 0o111 != 0 {
                return Err(refused(format!(
                    "linked or executable publication file {}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}
