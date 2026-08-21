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

ALTER TABLE annex_imports ADD COLUMN location_id TEXT REFERENCES locations(location_id);
