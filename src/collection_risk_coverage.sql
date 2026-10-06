WITH selected_content AS MATERIALIZED (
    SELECT DISTINCT content_id
    FROM file_objects
    WHERE collection_id = (SELECT id FROM collections WHERE collection_id = ?1)
      AND active = 1 AND content_id IS NOT NULL AND ?6 = 1
), eligible AS (
    -- Keep selected content outermost: look up its Copies through compact_copy_content,
    -- including Copies owned by Files in other Collections. A Location counts once.
    SELECT DISTINCT b.content_id, b.location_id
    FROM selected_content s
    CROSS JOIN copy_bindings b ON b.content_id = s.content_id AND b.state = 'present'
    JOIN checks p ON p.id = b.latest_presence AND p.checked_at >= ?2
    JOIN checks v ON v.id = b.latest_integrity AND v.checked_at >= ?3 AND v.integrity = 1
    LEFT JOIN check_errors e ON e.check_id = v.id
    WHERE e.code IS NULL OR e.code NOT IN ('read_error', 'identity_mismatch')
), qualifying AS (
    SELECT e.content_id, l.device_id,
           COALESCE(d.current_site_id, l.site_id) AS site_id,
           l.expected_availability, l.encryption_state
    FROM eligible e
    JOIN locations l ON l.id = e.location_id AND l.status = 'active'
    LEFT JOIN devices d ON d.device_id = l.device_id AND d.status = 'active'
    WHERE l.device_id IS NULL OR (
        d.device_id IS NOT NULL AND d.identity_state = 'confirmed'
        AND d.last_fingerprint_status = 'match' AND d.last_checkin_time_utc_ms >= ?4
    )
), coverage AS (
    SELECT content_id, COUNT(*) AS qualifying_copies,
           COUNT(DISTINCT device_id) AS devices, COUNT(DISTINCT site_id) AS sites,
           MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 THEN 1 ELSE 0 END) AS has_offsite,
           MAX(CASE WHEN expected_availability = 'offline' THEN 1 ELSE 0 END) AS has_offline,
           MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 AND encryption_state = 'encrypted' THEN 1 ELSE 0 END) AS has_encrypted_offsite
    FROM qualifying
    GROUP BY content_id
)
