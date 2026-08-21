ALTER TABLE archive_roots ADD COLUMN filesystem_fingerprint TEXT;
ALTER TABLE archive_roots ADD COLUMN fingerprint_kind TEXT;
ALTER TABLE archive_roots ADD COLUMN identity_state TEXT NOT NULL DEFAULT 'unavailable'
    CHECK (identity_state IN ('confirmed', 'unavailable', 'conflict'));

CREATE UNIQUE INDEX archive_roots_confirmed_fingerprint
    ON archive_roots(fingerprint_kind, filesystem_fingerprint)
    WHERE status = 'active'
      AND identity_state = 'confirmed'
      AND filesystem_fingerprint IS NOT NULL;

ALTER TABLE device_mounts ADD COLUMN archive_root_id TEXT REFERENCES archive_roots(archive_root_id);
CREATE INDEX device_mounts_root_time
    ON device_mounts(archive_root_id, observed_time_utc_ms);

ALTER TABLE scan_runs ADD COLUMN scan_mode TEXT NOT NULL DEFAULT 'complete'
    CHECK (scan_mode IN ('add', 'complete'));

ALTER TABLE annex_imports RENAME TO annex_imports_v4;

CREATE TABLE annex_imports (
    import_id TEXT PRIMARY KEY,
    job_id TEXT,
    repo_path_bytes BLOB NOT NULL,
    repo_path_encoding TEXT NOT NULL,
    repo_path_display TEXT NOT NULL,
    collection_id TEXT NOT NULL REFERENCES collections(collection_id),
    location_id TEXT NOT NULL REFERENCES locations(location_id),
    legacy_worktree_location_id TEXT REFERENCES locations(location_id),
    legacy_cas_location_id TEXT REFERENCES locations(location_id),
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    archive_root_id TEXT NOT NULL REFERENCES archive_roots(archive_root_id),
    annex_uuid TEXT,
    git_head_commit TEXT,
    status TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    started_event_id TEXT NOT NULL,
    completed_event_id TEXT
);

INSERT INTO annex_imports(
    import_id, job_id, repo_path_bytes, repo_path_encoding, repo_path_display,
    collection_id, location_id, legacy_worktree_location_id,
    legacy_cas_location_id, device_id, archive_root_id, annex_uuid,
    git_head_commit, status, summary_json, started_event_id, completed_event_id
)
SELECT import_id, job_id, repo_path_bytes, repo_path_encoding, repo_path_display,
       collection_id, worktree_location_id, worktree_location_id,
       cas_location_id, device_id, archive_root_id, annex_uuid,
       git_head_commit, status, summary_json, started_event_id, completed_event_id
FROM annex_imports_v4;

DROP TABLE annex_imports_v4;
