//! Generate a host-executed copy script from a read-only catalog snapshot.
use super::*;
use archive_ledger::sqlite_queries::{visit_objects, CatalogFileFilter};
use archive_ledger::SqliteCatalog;

const TEMPLATE: &str = include_str!("host_copy_template.sh");

pub(super) fn arguments(cli: &Cli) -> Option<&CopyMutationArgs> {
    let args = match &cli.command {
        Command::Copy(args) if args.command.is_none() => &args.mutation,
        Command::Location {
            command: LocationCommand::Copy(args),
        } => args,
        _ => return None,
    };
    args.host.host_script.then_some(args)
}

pub(super) fn execute(
    cli: &Cli,
    catalog: &SqliteCatalog,
    args: &CopyMutationArgs,
) -> Result<u8, AppError> {
    if cli.json {
        return Err(AppError::Input(
            "--host-script outputs Bash, not JSON".into(),
        ));
    }
    let transaction = catalog.connection().unchecked_transaction()?;
    let state = catalog.registry_state(false)?;
    let select = |selector: Option<&str>, role: &str| {
        let selector =
            selector.ok_or_else(|| AppError::Input(format!("--host-script requires --{role}")))?;
        select_location(&state.locations, selector)?
            .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))
    };
    let source = select(args.from.as_deref(), "from")?;
    let destination = select(args.to.as_deref(), "to")?;
    if source.location_id == destination.location_id {
        return Err(AppError::Input(
            "copy source and destination are the same Location".into(),
        ));
    }
    let collection =
        sqlite_host_script::collection_id(catalog, &state, &source, args.collection.as_deref())?;
    let mut groups = vec![FileLocationGroup {
        location_ids: vec![source.location_id.clone()],
        negated: false,
        verified_within_ms: None,
    }];
    for group in &args.host.location_groups {
        let mut group = group.clone();
        group.location_ids = group
            .location_ids
            .iter()
            .map(|name| {
                select_location(&state.locations, name)?
                    .map(|location| location.location_id)
                    .ok_or_else(|| AppError::Input(format!("Location not found: {name:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        group.location_ids.sort();
        group.location_ids.dedup();
        groups.push(group);
    }
    let source_root = sqlite_host_script::mapped_root(
        cli,
        catalog,
        &source,
        args.host.host_root.as_deref(),
        args.host.locations_root.as_deref(),
    )?;
    let destination_root = sqlite_host_script::mapped_root(
        cli,
        catalog,
        &destination,
        args.host.host_root.as_deref(),
        args.host.locations_root.as_deref(),
    )?;
    if source_root == destination_root {
        return Err(AppError::Input(
            "mapped source and destination are the same directory".into(),
        ));
    }
    let filter = CatalogFileFilter {
        collection_id: Some(collection),
        location_groups: groups,
        exclude_present_location_id: Some(destination.location_id.clone()),
        as_of_utc_ms: Some(now_utc_ms()?),
        ..Default::default()
    };
    let (header, rest) = TEMPLATE
        .split_once("# ARCHIVE_LEDGER_ROOTS\n")
        .expect("fixed template roots marker");
    let (before_manifest, footer) = rest
        .split_once("# ARCHIVE_LEDGER_MANIFEST\n")
        .expect("fixed template manifest marker");
    let stdout = std::io::stdout();
    let mut output = std::io::BufWriter::new(stdout.lock());
    output.write_all(header.as_bytes())?;
    writeln!(output, "source_root={}", shell_quote(&source_root))?;
    writeln!(
        output,
        "destination_root={}",
        shell_quote(&destination_root)
    )?;
    output.write_all(before_manifest.as_bytes())?;
    let count = visit_objects(catalog.connection(), &filter, |object| {
        let mut path = Vec::new();
        super::sqlite_read_cli::write_path(&mut path, &object.relative_path, true)?;
        // write_path supplies the terminal NUL and rejects embedded NULs.
        let relative = &path[..path.len() - 1];
        sqlite_host_script::validate_relative_path(relative)?;
        sqlite_host_script::write_manifest_path(&mut output, relative)?;
        Ok(())
    })?;
    transaction.commit()?;
    // Never emit the executable copy footer until the complete selection succeeds.
    output.write_all(footer.as_bytes())?;
    output.flush()?;
    eprintln!("Selected {count} files from cached checksum evidence; unresolved and unverified source files are excluded.");
    eprintln!("Save stdout as copy.sh; run bash copy.sh --dry-run, then bash copy.sh on the host.");
    Ok(EXIT_OK)
}
