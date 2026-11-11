//! Generate backed-up file removal scripts without touching catalog or content.
use super::*;
use archive_ledger::sqlite_queries::{
    selection_predicate, verified_copy_predicate, CatalogFileFilter,
};
use archive_ledger::SqliteCatalog;
use rusqlite::{params_from_iter, types::Value};

const TEMPLATE: &str = include_str!("host_remove_template.sh");

pub(super) fn execute(
    cli: &Cli,
    catalog: &SqliteCatalog,
    args: &HostRemoveArgs,
) -> Result<u8, AppError> {
    if cli.json {
        return Err(AppError::Input(
            "--host-script outputs Bash, not JSON".into(),
        ));
    }
    let tx = catalog.connection().unchecked_transaction()?;
    let state = catalog.registry_state(false)?;
    let resolve = |name: &str| {
        select_location(&state.locations, name)?
            .ok_or_else(|| AppError::Input(format!("Location not found: {name:?}")))
    };
    let target = resolve(&args.from)?;
    let device = target
        .device_id
        .as_ref()
        .ok_or_else(|| AppError::Input("removal target must have a known Device".into()))?;
    let mut backup_ids = Vec::new();
    for name in &args.locations {
        let backup = resolve(name)?;
        if backup.location_id == target.location_id
            || backup.device_id.as_ref().is_none_or(|id| id == device)
        {
            return Err(AppError::Input(format!("backup Location {name:?} must belong to a different known Device than the removal target")));
        }
        backup_ids.push(backup.location_id);
    }
    backup_ids.sort();
    backup_ids.dedup();
    let collection =
        sqlite_host_script::collection_id(catalog, &state, &target, args.collection.as_deref())?;
    let root = sqlite_host_script::mapped_root(
        cli,
        catalog,
        &target,
        args.host_root.as_deref(),
        args.locations_root.as_deref(),
    )?;
    let now = now_utc_ms()?;
    let filter = CatalogFileFilter {
        collection_id: Some(collection),
        location_groups: vec![
            FileLocationGroup {
                location_ids: vec![target.location_id],
                negated: false,
                verified_within_ms: None,
            },
            FileLocationGroup {
                location_ids: backup_ids.clone(),
                negated: false,
                verified_within_ms: Some(args.verified_within),
            },
        ],
        as_of_utc_ms: Some(now),
        ..Default::default()
    };
    let mut selection = selection_predicate(&filter, now)?;
    // The newest qualifying backup keeps each selected file protected longest.
    // The complete script expires when the first selected file's evidence does.
    let mut bind = |value: Value| {
        selection.values.push(value);
        format!("?{}", selection.values.len())
    };
    let ids = backup_ids
        .into_iter()
        .map(|id| bind(id.into()))
        .collect::<Vec<_>>()
        .join(",");
    let cutoff = bind((now.saturating_sub(args.verified_within) as i64).into());
    let as_of = bind((now as i64).into());
    let sql = format!("SELECT o.relative_path_encoding,o.relative_path_bytes,lower(hex(o.expected_blake3)),
        (SELECT MAX(b.last_success_time_utc_ms) FROM files b WHERE b.object_id=o.object_id
         AND b.location_id IN ({ids}) AND {} AND b.last_success_time_utc_ms BETWEEN {cutoff} AND {as_of})
        FROM objects o WHERE {} ORDER BY o.collection_id,o.relative_path_encoding,o.relative_path_bytes",
        verified_copy_predicate("b", "o"), selection.sql);
    let (header, rest) = TEMPLATE
        .split_once("# ARCHIVE_LEDGER_ROOTS\n")
        .expect("fixed roots marker");
    let (middle, rest) = rest
        .split_once("# ARCHIVE_LEDGER_MANIFEST\n")
        .expect("fixed manifest marker");
    let (after_manifest, footer) = rest
        .split_once("# ARCHIVE_LEDGER_EXPIRY\n")
        .expect("fixed expiry marker");
    let stdout = std::io::stdout();
    let mut output = std::io::BufWriter::new(stdout.lock());
    output.write_all(header.as_bytes())?;
    writeln!(output, "target_root={}", shell_quote(&root))?;
    output.write_all(middle.as_bytes())?;
    let mut expires = now.saturating_add(args.verified_within);
    let mut count = 0u64;
    {
        let mut statement = catalog.connection().prepare(&sql)?;
        let mut rows = statement.query(params_from_iter(selection.values.iter()))?;
        while let Some(row) = rows.next()? {
            let encoding: String = row.get(0)?;
            let path: Vec<u8> = row.get(1)?;
            if !matches!(encoding.as_str(), "utf8" | "unix_bytes")
                || (encoding == "utf8" && std::str::from_utf8(&path).is_err())
            {
                return Err(AppError::Input(
                    "host removal script requires Unix-compatible path bytes".into(),
                ));
            }
            sqlite_host_script::validate_relative_path(&path)?;
            let hash: String = row.get(2)?;
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(AppError::Input(
                    "selected file lacks a valid expected BLAKE3".into(),
                ));
            }
            // The query bounds this timestamp between nonnegative cutoff and now.
            let last_verified = row.get::<_, i64>(3)? as u64;
            expires = expires.min(last_verified.saturating_add(args.verified_within));
            write!(output, "{hash}\t")?;
            sqlite_host_script::write_manifest_path(&mut output, &path)?;
            count += 1;
        }
    }
    tx.commit()?;
    // Never complete the function or emit its invocation on a partial selection.
    output.write_all(after_manifest.as_bytes())?;
    writeln!(output, "evidence_expires_at={}", expires / 1000)?;
    output.write_all(footer.as_bytes())?;
    output.flush()?;
    eprintln!(
        "Selected {count} files with matching backup evidence on another Device within {} seconds.",
        args.verified_within / 1000
    );
    eprintln!("Save stdout as remove.sh; review it, run bash remove.sh --dry-run, then bash remove.sh --delete. Afterward reconcile the target with archive location scan.");
    Ok(EXIT_OK)
}
