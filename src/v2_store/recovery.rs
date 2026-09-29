//! Recovery of the local writer's unpublished next-sequence append.
//!
//! Accepted history is never adopted, rewritten, or removed here. The append
//! lock must be held by the caller until the replacement append is published.

use super::*;

impl V2OriginStore {
    pub(super) fn recover_unpublished_append(
        &self,
        origin: &str,
        first_seq: u64,
        expected_head: &str,
    ) -> Result<Option<PathBuf>> {
        let segment = segment_relative_path(origin, first_seq);
        let manifest = manifest_relative_path(origin, first_seq);
        if !entry_exists(&self.root.join(&segment))? && !entry_exists(&self.root.join(&manifest))? {
            return Ok(None);
        }

        // The usual append fast path is insufficient authority for moving files.
        let verified = self.verify_compact()?;
        if verified.accepted_frontier_hash != expected_head {
            return Err(refused("accepted frontier changed before recovery"));
        }
        let tail = verified
            .accepted_frontier
            .origins
            .iter()
            .find(|t| t.origin_id == origin);
        if tail.map_or(Some(1), |t| t.seq.checked_add(1)) != Some(first_seq) {
            return Err(refused("accepted origin changed before recovery"));
        }
        let segment_exists = plain_file_exists(&self.root, &segment)?;
        let manifest_exists = plain_file_exists(&self.root, &manifest)?;
        let mut successor = None;
        if manifest_exists {
            let bytes = read_file(&self.root.join(&manifest))?;
            match serde_json::from_slice::<SignedSegmentManifest>(&bytes) {
                Ok(signed) => {
                    let client = verified
                        .clients
                        .get(origin)
                        .ok_or_else(|| refused("origin is not enrolled"))?;
                    let key = VerifyingKey::from_bytes(&client.public_key)
                        .map_err(|_| refused("origin public key is invalid"))?;
                    signed.verify(&key).map_err(|e| refused(e.to_string()))?;
                    let body = &signed.body;
                    if signed.canonical_bytes()? != bytes
                        || body.archive_id != verified.genesis.body.archive_id
                        || body.genesis_hash != verified.genesis_hash
                        || body.origin_id != origin
                        || body.first_seq != first_seq
                        || body.segment_path != path_text(&segment)?
                        || body.causal_base_frontier_hash != verified.accepted_frontier_hash
                        || body.previous_segment_manifest_hash.as_deref()
                            != tail.map(|t| t.segment_manifest_hash.as_str())
                    {
                        return Err(refused(
                            "manifest is not the local next append from accepted HEAD",
                        ));
                    }
                    if segment_exists {
                        verify_segment_file(
                            &self.root.join(&segment),
                            body.segment_bytes,
                            &body.segment_blake3,
                        )
                        .map_err(|e| refused(e.to_string()))?;
                    }
                    let mut frontier = verified.accepted_frontier.clone();
                    let next = OriginFrontier {
                        origin_id: origin.to_owned(),
                        seq: body.last_seq,
                        event_hash: body.last_record_hash.clone(),
                        segment_manifest_hash: signed.manifest_hash()?,
                    };
                    if let Some(current) =
                        frontier.origins.iter_mut().find(|t| t.origin_id == origin)
                    {
                        *current = next;
                    } else {
                        frontier.origins.push(next);
                        frontier
                            .origins
                            .sort_by(|a, b| a.origin_id.cmp(&b.origin_id));
                    }
                    frontier.previous_frontiers = vec![verified.accepted_frontier_hash.clone()];
                    successor = Some(frontier);
                }
                // write_new_synced may have created an incomplete manifest. A
                // frontier cannot have been written after that failed write.
                Err(error) if error.is_eof() => {}
                Err(error) => {
                    return Err(refused(format!(
                        "unpublished manifest is malformed: {error}"
                    )))
                }
            }
        }

        let expected_frontier = successor
            .as_ref()
            .map(|f| -> Result<_> {
                Ok((
                    frontier_path(&self.root, &f.frontier_hash()?)?,
                    f.canonical_bytes()?,
                ))
            })
            .transpose()?;
        let mut files = Vec::new();
        // Examine detached frontiers on this exceptional path. An unexpected
        // local advance could be a fork or imported history, not our crash tail.
        for path in read_sorted_files(&self.root.join("frontiers/v2"), ".json")? {
            let relative = path
                .strip_prefix(&self.root)
                .expect("child of canonical tree");
            let accepted = path
                .file_stem()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("frontier-"))
                .is_some_and(|hex| verified.frontiers.contains_key(&format!("blake3:{hex}")));
            if accepted {
                continue;
            }
            plain_file_exists(&self.root, relative)?;
            let bytes = read_file(&path)?;
            if let Some((expected_path, expected_bytes)) = &expected_frontier {
                if path == *expected_path && expected_bytes.starts_with(&bytes) {
                    files.push((relative.to_path_buf(), "frontier.json"));
                    continue;
                }
            }
            let frontier: CausalFrontier = serde_json::from_slice(&bytes).map_err(|_| {
                refused(format!(
                    "cannot identify detached frontier {}",
                    relative.display()
                ))
            })?;
            if frontier
                .origins
                .iter()
                .any(|t| t.origin_id == origin && t.seq >= first_seq)
            {
                return Err(refused(format!(
                    "unexpected detached frontier {}",
                    relative.display()
                )));
            }
        }
        if manifest_exists {
            files.push((manifest, "manifest.json"));
        }
        if segment_exists {
            files.push((segment, "segment.jsonl"));
        }
        // Refuse any evidence already staged or present in named/reflog history.
        // Such a collision may be a rolled-back HEAD, not an unpublished append.
        for (relative, _) in &files {
            let path = path_text(relative)?;
            if !git_stdout(
                &self.root,
                "check recovery index",
                &["ls-files", "--", &path],
            )?
            .is_empty()
                || !git_stdout(
                    &self.root,
                    "check recovery history",
                    &[
                        "log",
                        "--all",
                        "--reflog",
                        "--full-history",
                        "-1",
                        "--format=%H",
                        "--",
                        &path,
                    ],
                )?
                .is_empty()
            {
                return Err(refused(format!(
                    "{} is staged or has Git history",
                    relative.display()
                )));
            }
        }

        let archive = self
            .root
            .parent()
            .ok_or_else(|| refused("canonical tree has no Archive parent"))?;
        let local = archive.join("local");
        ensure_durable_directory(&local)?;
        let recovery_root = local.join("append-recovery");
        ensure_durable_directory(&recovery_root)?;
        let retained = recovery_root.join(lower_ulid());
        fs::create_dir(&retained)
            .map_err(|e| io_error("create append recovery directory", &retained, e))?;
        sync_directory(&recovery_root)?;
        write_new_synced(&retained.join("recovery.json"), &serde_json::to_vec_pretty(&json!({
            "version": 1,
            "accepted_frontier_hash": verified.accepted_frontier_hash,
            "origin_id": origin,
            "first_seq": first_seq,
            "files": files.iter().map(|(source, retained)| json!({"source": source, "retained": retained})).collect::<Vec<_>>(),
        })).map_err(|e| refused(e.to_string()))?, Some(0o600))?;
        // Frontier first, manifest second, segment last: a crash during recovery
        // leaves a recognizable collision until all associated metadata is safe.
        for (relative, name) in files {
            let source = self.root.join(&relative);
            plain_file_exists(&self.root, &relative)?;
            File::open(&source)
                .and_then(|file| file.sync_all())
                .map_err(|e| io_error("sync unpublished append evidence", &source, e))?;
            fs::rename(&source, retained.join(name))
                .map_err(|e| io_error("preserve unpublished append evidence", &source, e))?;
            sync_directory(&retained)?;
            sync_directory(source.parent().expect("canonical file has parent"))?;
        }
        Ok(Some(retained))
    }

    /// Read-only inspection at the already verified frontier; does not require
    /// the local client's signing key (fsck also runs on restored copies).
    pub(crate) fn unpublished_append_paths(
        &self,
        verified: &V2VerificationReport,
    ) -> Result<Vec<PathBuf>> {
        let frontier = read_frontier(
            &self.root,
            &verified.accepted_frontier_hash,
            &verified.archive_id,
            &verified.genesis_hash,
        )?;
        let mut paths = Vec::new();
        for (directory, suffix) in [
            ("events/v2/origins", ".jsonl"),
            ("manifests/v2/origins", ".manifest.json"),
        ] {
            let parent = self.root.join(directory);
            for entry in fs::read_dir(&parent)
                .map_err(|e| io_error("inspect unpublished origins", &parent, e))?
            {
                let entry =
                    entry.map_err(|e| io_error("inspect unpublished origin", &parent, e))?;
                let metadata = fs::symlink_metadata(entry.path()).map_err(|e| {
                    io_error("inspect unpublished origin directory", entry.path(), e)
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(refused("unsafe unpublished origin directory"));
                }
                let origin = entry.file_name();
                let origin = origin
                    .to_str()
                    .ok_or_else(|| refused("origin directory is not UTF-8"))?;
                validate_origin_id(origin)?;
                let tail = frontier
                    .origins
                    .iter()
                    .find(|t| t.origin_id == origin)
                    .map_or(0, |t| t.seq);
                for path in read_sorted_files(&entry.path(), suffix)? {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();
                    let Some(number) = name
                        .strip_prefix("seg-")
                        .and_then(|n| n.strip_suffix(suffix))
                    else {
                        continue;
                    };
                    if number.parse::<u64>().is_ok_and(|seq| seq > tail) {
                        paths.push(
                            path.strip_prefix(&self.root)
                                .expect("canonical child")
                                .to_path_buf(),
                        );
                    }
                }
            }
        }
        paths.sort();
        Ok(paths)
    }
}

fn refused(message: impl Into<String>) -> V2StoreError {
    V2StoreError::AppendRecoveryRefused(message.into())
}

fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error("inspect unpublished append", path, e)),
    }
}

fn plain_file_exists(root: &Path, relative: &Path) -> Result<bool> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        path.push(component);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io_error("inspect recovery path", &path, e)),
        };
        if metadata.file_type().is_symlink()
            || if path == root.join(relative) {
                !metadata.is_file()
            } else {
                !metadata.is_dir()
            }
        {
            return Err(refused(format!("unsafe recovery path {}", path.display())));
        }
        #[cfg(unix)]
        if metadata.is_file() {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(refused(format!("linked recovery file {}", path.display())));
            }
        }
    }
    Ok(true)
}

fn ensure_durable_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(refused(format!(
            "unsafe recovery directory {}",
            path.display()
        ))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|e| io_error("create recovery parent", path, e))?;
            sync_directory(path.parent().expect("recovery directory has parent"))
        }
        Err(e) => Err(io_error("inspect recovery directory", path, e)),
    }
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| io_error("sync append recovery directory", path, e))
}
