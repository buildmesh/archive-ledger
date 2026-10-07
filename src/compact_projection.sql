-- Integer identities are local projection keys. Canonical names remain at the boundary.
CREATE TABLE content_objects (
 id INTEGER PRIMARY KEY, digest BLOB NOT NULL UNIQUE CHECK(length(digest)=32),
 object_id TEXT GENERATED ALWAYS AS ('blake3:' || lower(hex(digest))) VIRTUAL,
 size_bytes INTEGER NOT NULL CHECK(size_bytes>=0), extension_hint TEXT,
 first_record INTEGER NOT NULL REFERENCES records(id), first_time INTEGER NOT NULL
) STRICT;
CREATE UNIQUE INDEX content_object_name ON content_objects(object_id);
CREATE TABLE checksums (
 id INTEGER PRIMARY KEY, algorithm TEXT NOT NULL CHECK(algorithm IN ('sha256','sha512')),
 digest BLOB NOT NULL, UNIQUE(algorithm,digest)
) STRICT;
CREATE TABLE content_checksums (
 content_id INTEGER NOT NULL REFERENCES content_objects(id), checksum_id INTEGER NOT NULL REFERENCES checksums(id),
 source TEXT NOT NULL, record_id INTEGER NOT NULL REFERENCES records(id), PRIMARY KEY(content_id,checksum_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE source_identities (
 id INTEGER PRIMARY KEY, canonical_id TEXT NOT NULL UNIQUE, namespace TEXT NOT NULL, source_key TEXT NOT NULL,
 expected_checksum INTEGER REFERENCES checksums(id), expected_size INTEGER,
 content_id INTEGER REFERENCES content_objects(id), resolution TEXT NOT NULL CHECK(resolution IN ('unresolved','resolved','conflict','unsupported')),
 first_record INTEGER NOT NULL REFERENCES records(id), resolved_record INTEGER REFERENCES records(id),
 UNIQUE(namespace,source_key)
) STRICT;
CREATE TABLE annex_sources (id INTEGER PRIMARY KEY, uuid TEXT NOT NULL UNIQUE) STRICT;
CREATE TABLE source_availability (
 identity_id INTEGER NOT NULL REFERENCES source_identities(id), source_id INTEGER NOT NULL REFERENCES annex_sources(id),
 remote_id INTEGER NOT NULL REFERENCES annex_sources(id), state TEXT NOT NULL CHECK(state IN ('present','missing','unknown')),
 location_id INTEGER REFERENCES locations(id), observed_time INTEGER NOT NULL, record_id INTEGER NOT NULL REFERENCES records(id),
 PRIMARY KEY(identity_id,source_id,remote_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE file_objects (
 id INTEGER PRIMARY KEY, canonical_id TEXT NOT NULL UNIQUE, collection_id INTEGER NOT NULL REFERENCES collections(id),
 path_encoding TEXT NOT NULL, path_bytes BLOB NOT NULL, path_display TEXT,
 content_id INTEGER REFERENCES content_objects(id), external_id INTEGER REFERENCES source_identities(id),
 identity_state TEXT NOT NULL CHECK(identity_state IN ('resolved','unresolved','conflict','unknown')),
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 modified_time INTEGER, observed_size INTEGER, first_record INTEGER NOT NULL REFERENCES records(id),
 last_record INTEGER NOT NULL REFERENCES records(id), removed_record INTEGER REFERENCES records(id)
) STRICT;
CREATE UNIQUE INDEX compact_file_path ON file_objects(collection_id,path_encoding,path_bytes) WHERE active=1;
CREATE INDEX compact_file_content ON file_objects(content_id) WHERE content_id IS NOT NULL;
CREATE INDEX compact_file_external ON file_objects(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX compact_file_collection ON file_objects(collection_id,active,content_id);
CREATE TABLE file_locations (
 id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL REFERENCES file_objects(id), location_id INTEGER NOT NULL REFERENCES locations(id),
 representation TEXT NOT NULL, content_id INTEGER REFERENCES content_objects(id), external_id INTEGER REFERENCES source_identities(id),
 presence INTEGER NOT NULL CHECK(presence IN (0,1)), copy_id INTEGER REFERENCES copy_bindings(id), latest_presence INTEGER REFERENCES checks(id),
 first_record INTEGER NOT NULL REFERENCES records(id), last_record INTEGER NOT NULL REFERENCES records(id),
 seen_time INTEGER NOT NULL, observed_size INTEGER, modified_time INTEGER, complete_scan TEXT,
 UNIQUE(file_id,location_id)
) STRICT;
CREATE INDEX compact_location_files ON file_locations(location_id,file_id);
-- Refresh every logical alias of a missing physical Copy without a full scan.
CREATE INDEX compact_file_copy ON file_locations(copy_id) WHERE copy_id IS NOT NULL;
-- One shared Copy identity can serve multiple logical annex paths.
CREATE TABLE copy_bindings (
 id INTEGER PRIMARY KEY, canonical_id TEXT NOT NULL UNIQUE,
 owner INTEGER NOT NULL REFERENCES file_locations(id), location_id INTEGER NOT NULL REFERENCES locations(id),
 path_key BLOB NOT NULL CHECK(length(path_key)=32),
 locator_encoding TEXT, locator_bytes BLOB, locator_display TEXT,
 content_id INTEGER REFERENCES content_objects(id), external_id INTEGER REFERENCES source_identities(id),
 basis TEXT NOT NULL CHECK(basis IN ('observed_bytes','observed_metadata','source_metadata')),
 state TEXT NOT NULL CHECK(state IN ('present','missing','corrupt','unknown','superseded')),
 first_record INTEGER NOT NULL REFERENCES records(id), state_record INTEGER NOT NULL REFERENCES records(id),
 latest_presence INTEGER REFERENCES checks(id), latest_integrity INTEGER REFERENCES checks(id), complete_scan TEXT
) STRICT;
CREATE UNIQUE INDEX compact_copy_active_path ON copy_bindings(location_id,path_key) WHERE state!='superseded';
CREATE INDEX compact_copy_content ON copy_bindings(content_id,state);
CREATE INDEX compact_copy_external ON copy_bindings(external_id,state);
CREATE INDEX compact_copy_location ON copy_bindings(location_id,state);
CREATE TABLE checks (
 id INTEGER PRIMARY KEY, file_location_id INTEGER NOT NULL REFERENCES file_locations(id),
 checked_at INTEGER NOT NULL, presence INTEGER NOT NULL CHECK(presence IN (-1,0,1)),
 integrity INTEGER NOT NULL CHECK(integrity IN (0,1,2))
) STRICT;
CREATE TABLE check_errors (
 check_id INTEGER PRIMARY KEY REFERENCES checks(id), code TEXT NOT NULL, detail TEXT
) STRICT;
CREATE VIEW objects AS SELECT object_id,'blake3' AS canonical_hash_algo,lower(hex(digest)) AS canonical_hash_hex,
 size_bytes,NULL AS media_type,extension_hint,(SELECT record_id FROM records WHERE id=c.first_record) AS first_seen_record_id,first_time AS first_seen_time_utc_ms
 FROM content_objects c ;
CREATE VIEW object_hashes AS SELECT c.object_id,h.algorithm AS hash_algo,lower(hex(h.digest)) AS hash_hex,x.source,(SELECT record_id FROM records WHERE id=x.record_id) AS verified_record_id
 FROM content_checksums x JOIN content_objects c ON c.id=x.content_id JOIN checksums h ON h.id=x.checksum_id ;
CREATE VIEW external_identities AS SELECT x.canonical_id AS external_identity_id,x.namespace,x.source_key AS external_key,
 h.algorithm AS expected_hash_algo,CASE WHEN h.digest IS NOT NULL THEN lower(hex(h.digest)) END AS expected_hash_hex,x.expected_size AS expected_size_bytes,
 c.object_id,x.resolution AS resolution_state,NULL AS source_detail_json,(SELECT record_id FROM records WHERE id=x.first_record) AS first_seen_record_id,(SELECT record_id FROM records WHERE id=x.resolved_record) AS resolved_record_id
 FROM source_identities x LEFT JOIN checksums h ON h.id=x.expected_checksum LEFT JOIN content_objects c ON c.id=x.content_id
  ;
CREATE VIEW external_availability AS SELECT x.canonical_id AS external_identity_id,s.uuid AS source_repo_id,remote.uuid AS source_remote_id,
 a.state,l.location_id,a.observed_time AS observed_time_utc_ms,(SELECT record_id FROM records WHERE id=a.record_id) AS observed_record_id
 FROM source_availability a JOIN source_identities x ON x.id=a.identity_id JOIN annex_sources s ON s.id=a.source_id
 JOIN annex_sources remote ON remote.id=a.remote_id LEFT JOIN locations l ON l.id=a.location_id ;
CREATE VIEW file_refs AS SELECT f.canonical_id AS file_ref_id,l.collection_id,f.path_bytes AS logical_path_bytes,
 f.path_encoding AS logical_path_encoding,COALESCE(f.path_display,CAST(f.path_bytes AS TEXT)) AS logical_path_display,c.object_id,x.canonical_id AS external_identity_id,
 f.identity_state,CASE f.active WHEN 1 THEN 'active' ELSE 'removed' END AS path_state,NULL AS created_time_utc_ms,
 f.modified_time AS modified_time_utc_ms,f.observed_size AS observed_size_bytes,(SELECT record_id FROM records WHERE id=f.first_record) AS first_seen_record_id,
 (SELECT record_id FROM records WHERE id=f.last_record) AS last_seen_record_id,(SELECT record_id FROM records WHERE id=f.removed_record) AS removed_record_id
 FROM file_objects f JOIN collections l ON l.id=f.collection_id LEFT JOIN content_objects c ON c.id=f.content_id
 LEFT JOIN source_identities x ON x.id=f.external_id
 ;
CREATE VIEW path_observations AS SELECT f.canonical_id AS file_ref_id,l.location_id,f.path_bytes AS observed_path_bytes,
 f.path_encoding AS observed_path_encoding,COALESCE(f.path_display,CAST(f.path_bytes AS TEXT)) AS observed_path_display,p.representation,c.object_id,x.canonical_id AS external_identity_id,
 CASE p.presence WHEN 1 THEN 'present' ELSE 'missing' END AS state,(SELECT record_id FROM records WHERE id=p.first_record) AS first_seen_record_id,(SELECT record_id FROM records WHERE id=p.last_record) AS last_seen_record_id,
 p.seen_time AS last_seen_time_utc_ms,p.complete_scan AS last_complete_scan_id,p.observed_size AS observed_size_bytes,p.modified_time AS modified_time_utc_ms
 FROM file_locations p JOIN file_objects f ON f.id=p.file_id JOIN locations l ON l.id=p.location_id
 LEFT JOIN content_objects c ON c.id=p.content_id LEFT JOIN source_identities x ON x.id=p.external_id
   WHERE p.representation!='annex_content';
CREATE VIEW copy_claims AS SELECT b.canonical_id AS copy_claim_id,l.location_id,
 COALESCE(b.locator_bytes,f.path_bytes) AS relative_path_bytes,COALESCE(b.locator_encoding,f.path_encoding) AS relative_path_encoding,
 CASE WHEN b.locator_bytes IS NOT NULL THEN COALESCE(b.locator_display,CAST(b.locator_bytes AS TEXT)) ELSE COALESCE(f.path_display,CAST(f.path_bytes AS TEXT)) END AS relative_path_display,c.object_id,x.canonical_id AS external_identity_id,
 b.basis AS claim_basis,b.state,(SELECT origin_id FROM records WHERE id=b.state_record) AS state_origin_id,(SELECT origin_seq FROM records WHERE id=b.state_record) AS state_origin_seq,(SELECT record_id FROM records WHERE id=b.state_record) AS state_record_id,
 (SELECT record_id FROM records WHERE id=b.first_record) AS first_seen_record_id,(SELECT record_id FROM records WHERE id=b.state_record) AS last_seen_record_id,p.checked_at AS last_seen_time_utc_ms,
 b.complete_scan AS last_complete_scan_id,NULL AS last_verified_record_id,v.checked_at AS last_verified_time_utc_ms,
 CASE WHEN e.code IN ('read_error','identity_mismatch') THEN e.code ELSE CASE v.integrity WHEN 1 THEN 'ok' WHEN 2 THEN 'hash_mismatch' END END AS last_verification_result,
 e.code AS last_error_code,e.detail AS last_error_detail
 FROM copy_bindings b JOIN file_locations owner ON owner.id=b.owner JOIN file_objects f ON f.id=owner.file_id
 JOIN locations l ON l.id=b.location_id LEFT JOIN content_objects c ON c.id=b.content_id LEFT JOIN source_identities x ON x.id=b.external_id

 LEFT JOIN checks p ON p.id=b.latest_presence
 LEFT JOIN checks v ON v.id=b.latest_integrity LEFT JOIN check_errors e ON e.check_id=v.id;

CREATE VIEW file_checks AS SELECT CASE WHEN b.id IS NULL THEN f.canonical_id END AS file_ref_id,
 b.canonical_id AS copy_claim_id,l.location_id,c.checked_at,c.presence,c.integrity,e.code AS error_code,e.detail AS error_detail
 FROM checks c JOIN file_locations p ON p.id=c.file_location_id JOIN file_objects f ON f.id=p.file_id
 JOIN locations l ON l.id=p.location_id LEFT JOIN copy_bindings b ON b.id=p.copy_id AND b.location_id=p.location_id
 LEFT JOIN check_errors e ON e.check_id=c.id;
