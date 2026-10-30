//! Explicit catalog-only removal declarations; archive contents are untouched.
use super::*;
use archive_ledger::sqlite_catalog::SqliteCatalog;
use archive_ledger::sqlite_queries::{CatalogFileFilter, CatalogQueryError};
use archive_ledger::sqlite_removed::{mark_removed, preview_removed, RemovedSelection};

pub(super) fn execute_removed(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
    args: &FileRemovedArgs,
) -> Result<u8, AppError> {
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
    let resolve = |selector: &str| -> Result<String, AppError> {
        select_location(&state.locations, selector)?
            .map(|location| location.location_id)
            .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))
    };
    let selection=match (&args.location,&args.path) {
        (Some(location),Some(path)) if args.location_groups.is_empty()=>RemovedSelection::Path{
            location_id:resolve(location)?,collection_id,path:utf8_path(path.clone()),
        },
        (None,None)=>{
            let groups=args.location_groups.iter().map(|group| {
                let mut resolved=group.clone();
                resolved.location_ids=group.location_ids.iter().map(|id|resolve(id)).collect::<Result<Vec<_>,_>>()?;
                resolved.location_ids.sort();resolved.location_ids.dedup();
                Ok(resolved)
            }).collect::<Result<Vec<_>,AppError>>()?;
            RemovedSelection::Groups(CatalogFileFilter{collection_id,location_groups:groups,..Default::default()})
        }
        _=>return Err(AppError::Input("use --location and --path together for one copy, or Location groups for bulk removal; do not combine the modes".into())),
    };
    let time = now_utc_ms()?;
    if args.dry_run {
        let stdout = std::io::stdout();
        let mut output = std::io::BufWriter::new(stdout.lock());
        let mut first = true;
        let result = preview_removed(catalog.connection(), &selection, time, |path| {
            if first {
                write_header(&mut output, cli.json)?;
            }
            if cli.json {
                if !first {
                    write!(output, ",")?;
                }
                serde_json::to_writer(&mut output, &path)
                    .map_err(|error| CatalogQueryError::Output(std::io::Error::other(error)))?;
            } else {
                write_display(&mut output, &path.display)?;
            }
            first = false;
            Ok(())
        })?;
        if first {
            write_header(&mut output, cli.json)?;
        }
        if cli.json {
            writeln!(
                output,
                "],\"affected_count\":{},\"location_id\":{}}}",
                result.files_marked_missing,
                serde_json::to_string(&result.location_id)?
            )?;
        } else if result.files_marked_missing == 0 {
            writeln!(output, "No matching catalog copies.")?;
        }
        output.flush()?;
    } else {
        let result = mark_removed(catalog, &selection, time)?;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"version":1,"catalog_format":"sqlite","catalog_only":true,"location_id":result.location_id,"files_marked_missing":result.files_marked_missing})
                )?
            );
        } else if result.files_marked_missing == 0 {
            println!("No matching catalog copies; no files were read or deleted.");
        } else {
            println!(
                "Marked {} copies missing in the catalog only; no files were read or deleted.",
                result.files_marked_missing
            );
        }
    }
    Ok(EXIT_OK)
}

fn write_header(output: &mut impl Write, json: bool) -> std::io::Result<()> {
    if json {
        write!(output,"{{\"version\":1,\"catalog_format\":\"sqlite\",\"dry_run\":true,\"message\":\"Catalog-only removal: no files will be read or deleted.\",\"paths\":[")
    } else {
        writeln!(output,"Dry run: mark these copies missing in the catalog only; no files will be read or deleted.")
    }
}

fn write_display(output: &mut impl Write, display: &str) -> std::io::Result<()> {
    if display.chars().any(char::is_control) {
        for character in display.chars() {
            if character.is_control() {
                write!(output, "{}", character.escape_default())?;
            } else {
                write!(output, "{character}")?;
            }
        }
        writeln!(output)
    } else {
        writeln!(output, "{display}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dry_run_paths_cannot_inject_extra_terminal_lines() {
        let mut output = Vec::new();
        write_display(&mut output, "a\nb\u{1b}c").unwrap();
        assert_eq!(String::from_utf8(output).unwrap(), "a\\nb\\u{1b}c\n");
    }
}
