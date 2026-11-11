//! Generate a host-executed copy script from a read-only catalog snapshot.
use super::*;
use archive_ledger::sqlite_queries::{visit_objects, CatalogFileFilter, CatalogQueryError};
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
    let collection = if let Some(selector) = &args.collection {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
            .collection_id
    } else if state.collections.len() == 1 {
        state.collections[0].collection_id.clone()
    } else {
        let mut stmt = catalog.connection().prepare(
            "SELECT DISTINCT o.collection_id FROM files f JOIN objects o ON o.object_id=f.object_id JOIN collections c ON c.collection_id=o.collection_id WHERE f.location_id=?1 AND c.status='active' LIMIT 2"
        )?;
        let ids = stmt
            .query_map([&source.location_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() != 1 {
            return Err(AppError::Input(
                "specify --collection for this source Location".into(),
            ));
        }
        ids[0].clone()
    };
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
    let source_root = recorded_path(cli, catalog, &source)?;
    let destination_root = recorded_path(cli, catalog, &destination)?;
    let host_root = args
        .host
        .host_root
        .clone()
        .or_else(|| std::env::var_os("ARCHIVE_LEDGER_LOCATIONS_DIR").map(PathBuf::from));
    let locations_root =
        args.host.locations_root.clone().or_else(|| {
            std::env::var_os("ARCHIVE_LEDGER_CONTAINER_LOCATIONS_DIR").map(PathBuf::from)
        });
    if locations_root.is_some() && host_root.is_none() {
        return Err(AppError::Input(
            "--locations-root requires --host-root or ARCHIVE_LEDGER_LOCATIONS_DIR".into(),
        ));
    }
    let map = |root: PathBuf| -> Result<PathBuf, AppError> {
        if let Some(host) = &host_root {
            let container = locations_root.as_deref().unwrap_or(Path::new("/locations"));
            validate_root(host)?;
            validate_root(container)?;
            let relative = root.strip_prefix(container).map_err(|_| {
                AppError::Input(format!(
                    "recorded Location path {} is outside --locations-root {}",
                    root.display(),
                    container.display()
                ))
            })?;
            Ok(host.join(relative))
        } else {
            Ok(root)
        }
    };
    let source_root = map(source_root)?;
    let destination_root = map(destination_root)?;
    if source_root == destination_root {
        return Err(AppError::Input(
            "mapped source and destination are the same directory".into(),
        ));
    }
    let utf8_root = |root: &Path| {
        root.to_str().map(str::to_owned).ok_or_else(|| {
        AppError::Input("host script roots must be UTF-8; selected filenames may contain arbitrary Unix bytes".into())
    })
    };
    let source_root = utf8_root(&source_root)?;
    let destination_root = utf8_root(&destination_root)?;
    let filter = CatalogFileFilter {
        collection_id: Some(collection),
        location_groups: groups,
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
        if relative
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err(CatalogQueryError::InvalidFilter(
                "host script requires normalized Collection-relative paths".into(),
            ));
        }
        write_manifest_path(&mut output, relative)?;
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

fn validate_root(path: &Path) -> Result<(), AppError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(AppError::Input(
            "host and Location roots must be absolute paths without '..'".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        if path.as_os_str().as_bytes().contains(&0) {
            return Err(AppError::Input("root path contains NUL".into()));
        }
    }
    Ok(())
}

fn recorded_path(
    cli: &Cli,
    catalog: &SqliteCatalog,
    location: &LocationSnapshot,
) -> Result<PathBuf, AppError> {
    let root_id = location
        .archive_root_id
        .as_deref()
        .ok_or_else(|| AppError::Input("host script requires filesystem Locations".into()))?;
    let mount: Option<String> = catalog.connection().query_row(
        "SELECT mount_root_uri FROM device_mounts WHERE archive_root_id=?1 AND host_id=?2 ORDER BY observed_time_utc_ms DESC,mount_id DESC LIMIT 1",
        params![root_id, cli.host], |row| row.get(0),
    ).optional()?;
    let mount = PathBuf::from(mount.ok_or_else(|| {
        AppError::Input(format!(
            "Location {:?} has no recorded mount for this host",
            location.display_name
        ))
    })?);
    validate_root(&mount)?;
    let relative = location
        .relative_path
        .as_ref()
        .ok_or_else(|| AppError::Input("Location lacks a relative path".into()))?;
    let bytes = registry_path_identity_bytes(relative)?;
    if bytes.contains(&0) {
        return Err(AppError::Input("Location path contains NUL".into()));
    }
    let relative = relative_path_from_bytes(&relative.encoding, &bytes)?;
    if relative
        .components()
        .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(AppError::Input(
            "Location path must be relative without '.' or '..'".into(),
        ));
    }
    Ok(mount.join(relative))
}

// Data for a quoted heredoc, decoded by Bash's builtin printf %b, never eval.
// Every filename occupies one physical line; escape the delimiter itself too.
fn write_manifest_path(output: &mut impl Write, path: &[u8]) -> std::io::Result<()> {
    for (index, byte) in path.iter().copied().enumerate() {
        match byte {
            b'A' if index == 0 && path == b"ARCHIVE_LEDGER_PATHS" => {
                output.write_all(b"\\0101")?;
            }
            b'\\' => output.write_all(b"\\\\")?,
            b'\n' => output.write_all(b"\\n")?,
            b'\r' => output.write_all(b"\\r")?,
            b'\t' => output.write_all(b"\\t")?,
            b' '..=b'~' => output.write_all(&[byte])?,
            _ => write!(output, "\\0{byte:03o}")?,
        }
    }
    writeln!(output)
}
