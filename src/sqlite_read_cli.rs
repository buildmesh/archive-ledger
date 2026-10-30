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
            FileCommand::Removed(_) => return Ok(None),
            FileCommand::Find(args) => find(cli, catalog, args)?,
            FileCommand::Show { file_ref_id } => show(cli, catalog, file_ref_id)?,
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
        if !filter
            .location_groups
            .iter()
            .find(|group| !group.negated)
            .is_some_and(|group| group.location_ids.len() == 1)
        {
            return Err(AppError::Input("--print0 requires exactly one Location in the first positive --in group; use --json for multiple sources".into()));
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

fn escaped_display(value: &str) -> std::borrow::Cow<'_, str> {
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

fn write_path(
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
        "{}  [{}]",
        escaped_display(&review.object.relative_path.display),
        escaped_display(&collection_name)
    );
    println!("  Object: {}", review.object.object_id);
    println!(
        "  Expected BLAKE3: {}",
        review
            .object
            .expected_blake3
            .as_deref()
            .unwrap_or("unknown")
    );
    if let Some(size) = review.object.expected_size_bytes {
        println!("  Expected size: {size} bytes");
    }
    if review.files.is_empty() {
        println!("  Locations: no recorded copies");
    } else {
        println!("  Locations:");
        for file in review.files {
            println!(
                "    {} — {}, {}",
                escaped_display(&file.location_name),
                file.presence,
                file.integrity
            );
            println!(
                "      Last check: {} ({})",
                display_time(file.last_check_time_utc_ms),
                file.last_check_result.as_deref().unwrap_or("never")
            );
            println!(
                "      Last successful verification: {}",
                display_time(file.last_success_time_utc_ms)
            );
            if let Some(observed) = file.observed_blake3 {
                println!("      Observed BLAKE3: {observed}");
            }
        }
    }
    Ok(())
}
fn display_time(time: Option<i64>) -> String {
    time.map(|value| value.to_string())
        .unwrap_or_else(|| "never".into())
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
