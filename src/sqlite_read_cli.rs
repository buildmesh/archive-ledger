//! Read-only CLI workflows for authoritative SQLite catalogs.
use super::*;
use archive_ledger::sqlite_catalog::SqliteCatalog;
use archive_ledger::sqlite_queries::{
    find_objects, show_object, visit_objects, CatalogFileFilter, CatalogObjectRequest,
    CatalogQueryError,
};
use archive_ledger::LosslessPath;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub(super) fn execute_read(cli: &Cli, catalog: &SqliteCatalog) -> Result<Option<u8>, AppError> {
    match &cli.command {
        Command::File { command } => match command {
            FileCommand::Removed(_) | FileCommand::Remove(_) => return Ok(None),
            FileCommand::Find(args) => find(cli, catalog, args)?,
            FileCommand::Show {
                file_ref_id,
                collection,
            } => {
                let snapshot = catalog.connection().unchecked_transaction()?;
                let id = resolve_file(catalog, &cli.host, file_ref_id, collection.as_deref())?;
                show(cli, catalog, &id)?;
                snapshot.commit()?;
            }
            FileCommand::History {
                file_ref_id,
                limit,
                continuation,
            } => history(cli, catalog, file_ref_id, *limit, continuation.as_deref())?,
        },
        Command::Object { command } => match command {
            ObjectCommand::Show {
                object_id,
                limit,
                continuation,
            } => {
                validate_limit(*limit)?;
                if continuation.is_some() {
                    return Err(AppError::Input("object show returns one expected path and all its Locations; --continue is not applicable".into()));
                }
                show(cli, catalog, object_id)?;
            }
            ObjectCommand::History {
                object_id,
                limit,
                continuation,
            } => history(cli, catalog, object_id, *limit, continuation.as_deref())?,
        },
        _ => return Ok(None),
    }
    Ok(Some(EXIT_OK))
}

fn validate_limit(limit: usize) -> Result<(), AppError> {
    if !(1..=1000).contains(&limit) {
        return Err(AppError::Input("--limit must be between 1 and 1000".into()));
    }
    Ok(())
}

fn find(cli: &Cli, catalog: &SqliteCatalog, args: &FileFindArgs) -> Result<(), AppError> {
    let state = catalog.registry_state(false)?;
    let collection_id = args
        .collection
        .as_deref()
        .map(|selector| {
            select_collection(&state.collections, selector)?
                .map(|collection| collection.collection_id)
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))
        })
        .transpose()?;
    let filter = CatalogFileFilter {
        collection_id,
        copies_below: args.copies_below,
        verified_copies: args.verified_copies || args.copies_verified_within.is_some(),
        copies_verified_within_ms: args.copies_verified_within,
        exact_path: args.exact.clone().map(utf8_path),
        path_prefix: args.prefix.clone().map(utf8_path),
        identity_state: args.identity_state.clone(),
        location_groups: resolve_file_location_groups(args, &state.locations)?,
        ..Default::default()
    };
    let limit = args.limit.unwrap_or(if cli.json { 100 } else { 1000 });
    validate_limit(limit)?;
    if args.print0 {
        if cli.json || args.continuation.is_some() {
            return Err(AppError::Input(
                "--print0 cannot be combined with --json or --continue".into(),
            ));
        }
        if !(filter.copies_below.is_some() && filter.collection_id.is_some())
            && !filter
                .location_groups
                .iter()
                .find(|group| !group.negated)
                .is_some_and(|group| group.location_ids.len() == 1)
        {
            return Err(AppError::Input("--print0 requires one source Location, or --collection with --copies-below; use --json for multiple sources".into()));
        }
    }
    let request = CatalogObjectRequest {
        filter: filter.clone(),
        limit,
        continuation: args.continuation.clone(),
    };
    if cli.json {
        let page = find_objects(catalog.connection(), request)?;
        let mut output = serde_json::to_value(page)?;
        output["version"] = json!(1);
        output["catalog_format"] = json!("sqlite");
        if !filter.location_groups.is_empty() {
            output["selection_evidence"] = json!({"basis":"catalog","identity":"collection_relative_path_and_expected_checksum","unresolved_identities":"excluded","fresh_verification":false});
        }
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }
    if !filter.location_groups.is_empty() {
        eprintln!("Unresolved identities are excluded.");
    }
    let stdout = std::io::stdout();
    let mut output = std::io::BufWriter::new(stdout.lock());
    if args.continuation.is_none() {
        visit_objects(catalog.connection(), &filter, |object| {
            write_path(&mut output, &object.relative_path, args.print0)
        })?;
    } else {
        let mut request = request;
        loop {
            let page = find_objects(catalog.connection(), request.clone())?;
            for object in page.objects {
                write_path(&mut output, &object.relative_path, false)?;
            }
            match page.next {
                Some(next) => request.continuation = Some(next),
                None => break,
            }
        }
    }
    output.flush()?;
    Ok(())
}

pub(super) fn escaped_display(value: &str) -> std::borrow::Cow<'_, str> {
    if !value.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    std::borrow::Cow::Owned(escaped)
}

pub(super) fn write_path(
    output: &mut impl Write,
    path: &LosslessPath,
    print0: bool,
) -> Result<(), CatalogQueryError> {
    if !print0 {
        writeln!(output, "{}", escaped_display(&path.display))?;
        return Ok(());
    }
    let bytes = match path.encoding.as_str() {
        "utf8" => path
            .text
            .as_ref()
            .ok_or_else(|| CatalogQueryError::InvalidFilter("UTF-8 path lacks text".into()))?
            .as_bytes()
            .to_vec(),
        "unix_bytes" => URL_SAFE_NO_PAD
            .decode(path.base64.as_deref().ok_or_else(|| {
                CatalogQueryError::InvalidFilter("path lacks lossless bytes".into())
            })?)
            .map_err(|error| {
                CatalogQueryError::InvalidFilter(format!("invalid path bytes: {error}"))
            })?,
        _ => {
            return Err(CatalogQueryError::InvalidFilter(
                "--print0 cannot represent this path encoding; use --json".into(),
            ))
        }
    };
    if bytes.contains(&0) {
        return Err(CatalogQueryError::InvalidFilter("path contains NUL".into()));
    }
    output.write_all(&bytes)?;
    output.write_all(&[0])?;
    Ok(())
}

// Probe the existing unique (Collection, encoding, path) index once per
// Collection. Never scan Objects to resolve a path without --collection.
fn resolve_file(
    catalog: &SqliteCatalog,
    host: &str,
    selector: &str,
    collection_selector: Option<&str>,
) -> Result<String, AppError> {
    let connection = catalog.connection();
    let state = catalog.registry_state(false)?;
    let collections = if let Some(selector) = collection_selector {
        vec![select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?]
    } else {
        state.collections
    };
    let mut matches = std::collections::BTreeMap::<String, String>::new();
    let mut exact = connection.prepare(
        "SELECT object_id FROM objects WHERE collection_id=?1 AND relative_path_encoding='utf8' AND relative_path_bytes=?2"
    )?;
    for collection in &collections {
        let id: Option<String> = exact
            .query_row(
                params![collection.collection_id, selector.as_bytes()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = id {
            matches.insert(id, format!("{}: {selector}", collection.display_name));
        }
    }
    if !matches.is_empty() {
        return unique_file(matches);
    }
    // IDs remain available, including IDs belonging to retired Collections.
    let id_collection: Option<String> = connection
        .query_row(
            "SELECT collection_id FROM objects WHERE object_id=?1",
            [selector],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(id_collection) = id_collection {
        if collection_selector.is_none()
            || collections.iter().any(|c| c.collection_id == id_collection)
        {
            return Ok(selector.to_owned());
        }
    }
    let path = Path::new(selector);
    if path.is_absolute() {
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(AppError::Input("absolute file paths must not contain '..'; use the recorded path without resolving symlinks".into()));
        }
        let mut roots = connection.prepare(
            "SELECT l.location_id,l.relative_path_encoding,l.relative_path_bytes,m.mount_root_uri
             FROM locations l JOIN device_mounts m ON m.mount_id=(
               SELECT mount_id FROM device_mounts WHERE archive_root_id=l.archive_root_id AND host_id=?1
               ORDER BY observed_time_utc_ms DESC,mount_id DESC LIMIT 1)
             WHERE l.status='active' AND l.kind='filesystem'"
        )?;
        let rows = roots.query_map([host], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut at_location = connection.prepare(
            "SELECT o.object_id FROM objects o WHERE o.collection_id=?1 AND o.relative_path_encoding='utf8' AND o.relative_path_bytes=?2
             AND EXISTS(SELECT 1 FROM files f WHERE f.object_id=o.object_id AND f.location_id=?3)"
        )?;
        for row in rows {
            let (location_id, encoding, bytes, mount) = row?;
            let relative = relative_path_from_bytes(&encoding, &bytes)?;
            if !Path::new(&mount).is_absolute()
                || relative.is_absolute()
                || Path::new(&mount)
                    .components()
                    .chain(relative.components())
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                continue;
            }
            let root = Path::new(&mount).join(relative);
            // strip_prefix compares components, not string prefixes; no stat or canonicalize.
            let Ok(relative) = path.strip_prefix(&root) else {
                continue;
            };
            let relative: PathBuf = relative.components().collect();
            let Some(relative) = relative.to_str() else {
                continue;
            };
            for collection in &collections {
                let id: Option<String> = at_location
                    .query_row(
                        params![collection.collection_id, relative.as_bytes(), location_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(id) = id {
                    matches.insert(id, format!("{}: {relative}", collection.display_name));
                }
            }
        }
    }
    if matches.is_empty() {
        return Err(CatalogQueryError::NotFound(format!("{selector:?}. Use a Collection-relative path with --collection, an existing catalog ID, or an absolute path under a recorded Location for this host.")).into());
    }
    unique_file(matches)
}

fn unique_file(matches: std::collections::BTreeMap<String, String>) -> Result<String, AppError> {
    if matches.len() == 1 {
        return Ok(matches.into_keys().next().expect("one match"));
    }
    let choices = matches
        .iter()
        .map(|(id, path)| format!("  {path:?} ({id})"))
        .collect::<Vec<_>>()
        .join("\n");
    Err(AppError::Input(format!("File path is ambiguous. Use --collection with the exact Collection-relative path, or a catalog ID:\n{choices}")))
}

fn show(cli: &Cli, catalog: &SqliteCatalog, object_id: &str) -> Result<(), AppError> {
    let review = show_object(catalog.connection(), object_id)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"version":1,"catalog_format":"sqlite","object_review":review})
            )?
        );
        return Ok(());
    }
    let collection_name: String = catalog.connection().query_row(
        "SELECT display_name FROM collections WHERE collection_id=?1",
        [&review.object.collection_id],
        |row| row.get(0),
    )?;
    println!(
        "Path: {}",
        escaped_display(&review.object.relative_path.display)
    );
    println!("Collection: {}", escaped_display(&collection_name));
    println!(
        "Expected BLAKE3: {}",
        review
            .object
            .expected_blake3
            .as_deref()
            .unwrap_or("unknown")
    );
    match review.object.expected_size_bytes {
        Some(size) => println!("Expected size: {size} bytes"),
        None => println!("Expected size: unknown"),
    }
    println!("\nLocations: {}", review.files.len());
    if review.files.is_empty() {
        println!("  No recorded copies.");
    }
    for file in review.files {
        println!("\n  {}", escaped_display(&file.location_name));
        println!(
            "    Device: {}",
            escaped_display(file.device_name.as_deref().unwrap_or("unknown"))
        );
        println!(
            "    Site: {}",
            escaped_display(file.site_name.as_deref().unwrap_or("unknown"))
        );
        println!("    Presence: {}", file.presence);
        println!("    Integrity: {}", file.integrity);
        println!(
            "    Last check: {} ({})",
            display_time(catalog, file.last_check_time_utc_ms)?,
            file.last_check_result.as_deref().unwrap_or("never")
        );
        println!(
            "    Last successful verification: {}",
            display_time(catalog, file.last_success_time_utc_ms)?
        );
        if let Some(observed) = file.observed_blake3 {
            if Some(&observed) != review.object.expected_blake3.as_ref() {
                println!("    Observed BLAKE3: {observed}");
            }
        }
    }
    println!("\nEvidence: Cached catalog; drives have not been checked.");
    Ok(())
}
fn display_time(catalog: &SqliteCatalog, time: Option<i64>) -> Result<String, AppError> {
    let Some(time) = time else {
        return Ok("never".into());
    };
    let formatted: Option<String> = catalog.connection().query_row(
        "SELECT strftime('%Y-%m-%d %H:%M:%S UTC', ?1 / 1000.0, 'unixepoch')",
        [time],
        |row| row.get(0),
    )?;
    Ok(formatted.unwrap_or_else(|| format!("{time} ms since Unix epoch")))
}

#[derive(Debug, Serialize)]
struct HistoryEntry {
    history_id: i64,
    location_id: Option<String>,
    time_utc_ms: i64,
    kind: String,
    check_result: Option<String>,
    expected_blake3: Option<String>,
    observed_blake3: Option<String>,
    details: Option<serde_json::Value>,
}
#[derive(Serialize)]
struct HistoryPage {
    version: u8,
    catalog_format: &'static str,
    object_id: String,
    items: Vec<HistoryEntry>,
    next: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct HistoryCursor {
    archive_id: String,
    revision: i64,
    object_id: String,
    time: i64,
    id: i64,
}

fn history_page(
    catalog: &SqliteCatalog,
    object_id: &str,
    limit: usize,
    continuation: Option<&str>,
) -> Result<HistoryPage, AppError> {
    validate_limit(limit)?;
    let connection = catalog.connection();
    let snapshot = connection.unchecked_transaction()?;
    let (archive_id, revision): (String, i64) = connection.query_row(
        "SELECT archive_id,revision FROM catalog_metadata WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM objects WHERE object_id=?1)",
        [object_id],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(CatalogQueryError::NotFound(object_id.into()).into());
    }
    let cursor = continuation
        .map(|token| {
            if token.len() > 16384 {
                return Err(CatalogQueryError::InvalidContinuation);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| CatalogQueryError::InvalidContinuation)?;
            serde_json::from_slice::<HistoryCursor>(&bytes)
                .map_err(|_| CatalogQueryError::InvalidContinuation)
        })
        .transpose()?;
    if let Some(cursor) = &cursor {
        if cursor.archive_id != archive_id || cursor.revision != revision {
            return Err(CatalogQueryError::StaleContinuation.into());
        }
        if cursor.object_id != object_id {
            return Err(CatalogQueryError::InvalidContinuation.into());
        }
    }
    let mut sql="SELECT history_id,location_id,time_utc_ms,kind,check_result,lower(hex(expected_blake3)),lower(hex(observed_blake3)),details_json FROM history WHERE object_id=?1".to_owned();
    let mut values = vec![rusqlite::types::Value::Text(object_id.into())];
    if let Some(cursor) = cursor {
        sql.push_str(" AND (time_utc_ms,history_id)>(?2,?3)");
        values.push(cursor.time.into());
        values.push(cursor.id.into());
    }
    values.push(((limit + 1) as i64).into());
    sql.push_str(&format!(
        " ORDER BY time_utc_ms,history_id LIMIT ?{}",
        values.len()
    ));
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        let hash = |column| -> rusqlite::Result<Option<String>> {
            let value: String = row.get(column)?;
            Ok((!value.is_empty()).then_some(value))
        };
        let details: Option<String> = row.get(7)?;
        items.push(HistoryEntry {
            history_id: row.get(0)?,
            location_id: row.get(1)?,
            time_utc_ms: row.get(2)?,
            kind: row.get(3)?,
            check_result: row.get(4)?,
            expected_blake3: hash(5)?,
            observed_blake3: hash(6)?,
            details: details
                .map(|value| serde_json::from_str(&value))
                .transpose()?,
        });
    }
    let more = items.len() > limit;
    items.truncate(limit);
    let next = if more {
        let last = items.last().expect("nonempty limited history page");
        Some(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&HistoryCursor {
            archive_id,
            revision,
            object_id: object_id.into(),
            time: last.time_utc_ms,
            id: last.history_id,
        })?))
    } else {
        None
    };
    drop(rows);
    drop(statement);
    snapshot.commit()?;
    Ok(HistoryPage {
        version: 1,
        catalog_format: "sqlite",
        object_id: object_id.into(),
        items,
        next,
    })
}

fn history(
    cli: &Cli,
    catalog: &SqliteCatalog,
    object_id: &str,
    limit: usize,
    continuation: Option<&str>,
) -> Result<(), AppError> {
    let page = history_page(catalog, object_id, limit, continuation)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&page)?);
        return Ok(());
    }
    if page.items.is_empty() {
        println!("No matching history entries.");
    }
    for entry in page.items {
        println!(
            "{}  {}  {}  {}",
            entry.time_utc_ms,
            escaped_display(&entry.kind),
            entry.location_id.as_deref().unwrap_or("—"),
            entry.check_result.as_deref().unwrap_or("—")
        );
    }
    if let Some(next) = page.next {
        println!("More history: rerun with --continue {next}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_output_is_lossless_and_keeps_control_characters_on_one_line() {
        let path = LosslessPath {
            encoding: "unix_bytes".into(),
            display: "line\nbreak".into(),
            text: None,
            base64: Some(URL_SAFE_NO_PAD.encode(b"line\n\xff")),
        };
        let mut output = Vec::new();
        write_path(&mut output, &path, true).unwrap();
        assert_eq!(output, b"line\n\xff\0");
        output.clear();
        write_path(&mut output, &path, false).unwrap();
        assert_eq!(output, b"line\\nbreak\n");
    }
    #[test]
    fn history_pages_bind_object_and_revision() {
        let directory = tempfile::tempdir().unwrap();
        let catalog =
            SqliteCatalog::create(directory.path().join("catalog.db"), "archive", "Archive")
                .unwrap();
        catalog.connection().execute_batch("INSERT INTO collections VALUES ('collection','Files',NULL,NULL,NULL,'active');
            INSERT INTO objects(object_id,collection_id,relative_path_encoding,relative_path_bytes,relative_path_display) VALUES ('object','collection','utf8',x'61','a'),('other','collection','utf8',x'62','b');
            INSERT INTO history(object_id,time_utc_ms,kind) VALUES ('object',10,'first'),('object',10,'second'),('object',11,'third');").unwrap();
        let page = history_page(&catalog, "object", 1, None).unwrap();
        assert_eq!(page.items[0].kind, "first");
        let next = page.next.as_deref();
        assert!(matches!(
            history_page(&catalog, "other", 1, next),
            Err(AppError::CatalogQuery(
                CatalogQueryError::InvalidContinuation
            ))
        ));
        let second = history_page(&catalog, "object", 2, next).unwrap();
        assert_eq!(
            second
                .items
                .iter()
                .map(|item| item.kind.as_str())
                .collect::<Vec<_>>(),
            ["second", "third"]
        );
        assert!(second.next.is_none());
        catalog
            .connection()
            .execute("UPDATE catalog_metadata SET revision=1", [])
            .unwrap();
        assert!(matches!(
            history_page(&catalog, "object", 1, next),
            Err(AppError::CatalogQuery(CatalogQueryError::StaleContinuation))
        ));
    }
}
