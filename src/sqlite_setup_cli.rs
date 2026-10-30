//! Setup and registry commands for the authoritative catalog.
use super::*;
use archive_ledger::{sqlite_registry::SqliteRegistry, SqliteCatalog};

// Reuse existing CLI selectors over registry snapshots. No legacy database or
// history is consulted; the sequence field is never exposed as canonical evidence.
pub(super) fn state(
    catalog: &SqliteCatalog,
    all: bool,
) -> Result<archive_ledger::RegistryState, AppError> {
    let s = catalog.registry_state(all)?;
    Ok(archive_ledger::RegistryState {
        version: 3,
        applied_event_seq: s.revision,
        sites: s.sites,
        policies: s.policies,
        collections: s.collections,
        devices: s.devices,
        archive_roots: s.archive_roots,
        locations: s.locations,
        risk_domains: s.risk_domains,
        risk_assignments: s.risk_assignments,
    })
}
fn record(cli: &Cli, catalog: &mut SqliteCatalog, change: RegistryChange) -> Result<(), AppError> {
    let result = SqliteRegistry::new(catalog).record(change, &cli.host, now_utc_ms()?)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string(&json!({"version":3,"revision":result.revision}))?
        );
    } else {
        println!("Recorded.");
    }
    Ok(())
}
fn print_values(
    kind: RegistryKind,
    values: Vec<serde_json::Value>,
    as_json: bool,
    list: bool,
) -> Result<(), AppError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"version":3,"items":values}))?
        );
    } else {
        print_v2_registry_values(kind, values, false, list)?;
    }
    Ok(())
}
fn entity(
    cli: &Cli,
    database: &mut SqliteCatalog,
    kind: RegistryKind,
    command: &RegistryEntityCommand,
) -> Result<u8, AppError> {
    match command {
        RegistryEntityCommand::Discover { path } => {
            if !matches!(kind, RegistryKind::Device) {
                return Err(AppError::Input(
                    "discover is available only under device".to_owned(),
                ));
            }
            let discovered = archive_ledger::discover_mounted_filesystem(path)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"version": 3, "mounted_filesystem": discovered})
                    )?
                );
            } else {
                println!("Path: {}", discovered.path.display());
                println!("Mounted root: {}", discovered.mount_root.display());
                println!("Relative path: {}", discovered.relative_path.display());
                match (
                    discovered.fingerprint_kind.as_deref(),
                    discovered.filesystem_fingerprint.as_deref(),
                ) {
                    (Some(kind), Some(value)) => println!("Stable identity: {kind} {value}"),
                    _ => println!("Stable identity: unavailable"),
                }
            }
        }
        RegistryEntityCommand::List { all } => {
            let state = state(database, *all)?;
            print_values(kind, registry_values(kind, &state)?, cli.json, true)?;
        }
        RegistryEntityCommand::Show { id } => {
            let state = state(database, true)?;
            let values = registry_values(kind, &state)?;
            let value = select_registry_value(kind, &values, id)?;
            print_values(kind, vec![value], cli.json, false)?;
        }
        RegistryEntityCommand::Add(args) => {
            let change = if let Some(snapshot) = &args.snapshot {
                parse_registry_change(kind, RegistryAction::Register, snapshot)?
            } else {
                build_registry_add(kind, args)?
            };
            record(cli, database, change)?;
        }
        RegistryEntityCommand::Update { snapshot } => record(
            cli,
            database,
            parse_registry_change(kind, RegistryAction::Update, snapshot)?,
        )?,
        RegistryEntityCommand::Retire { snapshot, yes } => {
            if !yes {
                return Err(AppError::Input(
                    "retirement requires --yes after reviewing the full snapshot".to_owned(),
                ));
            }
            record(
                cli,
                database,
                parse_registry_change(kind, RegistryAction::Retire, snapshot)?,
            )?;
        }
        RegistryEntityCommand::Move { snapshot } => record(
            cli,
            database,
            parse_registry_change(kind, RegistryAction::Move, snapshot)?,
        )?,
        RegistryEntityCommand::Assign {
            risk_domain_id,
            entity_type,
            entity_id,
        } => record(
            cli,
            database,
            RegistryChange::AssignRisk(RiskAssignment {
                entity_type: entity_type.clone(),
                entity_id: entity_id.clone(),
                risk_domain_id: risk_domain_id.clone(),
            }),
        )?,
        RegistryEntityCommand::Unassign {
            risk_domain_id,
            entity_type,
            entity_id,
        } => record(
            cli,
            database,
            RegistryChange::UnassignRisk(RiskAssignment {
                entity_type: entity_type.clone(),
                entity_id: entity_id.clone(),
                risk_domain_id: risk_domain_id.clone(),
            }),
        )?,
        RegistryEntityCommand::CheckIn {
            device_id,
            fingerprint_status,
        } => record(
            cli,
            database,
            RegistryChange::DeviceCheckIn(DeviceCheckIn {
                device_id: device_id.clone(),
                fingerprint_status: fingerprint_status.clone(),
            }),
        )?,
        RegistryEntityCommand::Mount {
            device_id,
            mount_id,
            mount_root_uri,
            status,
            fingerprint_status,
        } => record(
            cli,
            database,
            RegistryChange::DeviceMount(DeviceMount {
                mount_id: mount_id.clone(),
                device_id: device_id.clone(),
                archive_root_id: None,
                mount_root_uri: mount_root_uri.clone(),
                status: status.clone(),
                fingerprint_status: fingerprint_status.clone(),
            }),
        )?,
    }
    Ok(EXIT_OK)
}

pub(super) fn execute_setup(
    cli: &Cli,
    database: &mut SqliteCatalog,
) -> Result<Option<u8>, AppError> {
    let result = match &cli.command {
        Command::Rename { new_name } => {
            let metadata = database.metadata()?;
            let result =
                SqliteRegistry::new(database).rename_archive(new_name.trim(), now_utc_ms()?)?;
            CatalogRegistry::load()?.rename(&metadata.archive_id, new_name.trim())?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string(
                        &json!({"version":3,"archive_id":metadata.archive_id,"archive_name":new_name.trim(),"revision":result.revision})
                    )?
                );
            } else {
                println!("Renamed Archive to {:?}.", new_name.trim());
            }
            EXIT_OK
        }
        Command::Site { command } => match command {
            SiteCommand::List { all } => entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::List { all: *all },
            )?,
            SiteCommand::Show { id } => entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            SiteCommand::Add(args) => entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Add(args.clone()),
            )?,
            SiteCommand::Update { snapshot } => entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            SiteCommand::Retire { snapshot, yes } => entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            SiteCommand::Rename { site, new_name } => {
                let change = rename_change(database, RegistryKind::Site, site, new_name)?;
                record(cli, database, change)?;
                EXIT_OK
            }
            SiteCommand::Status { .. } => return Ok(None),
        },
        Command::Device { command } => match command {
            DeviceCommand::Discover { path } => entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Discover { path: path.clone() },
            )?,
            DeviceCommand::List { all } => entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::List { all: *all },
            )?,
            DeviceCommand::Show { id } => entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            DeviceCommand::Add(args) => entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Add(args.clone()),
            )?,
            DeviceCommand::Update { snapshot } => entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            DeviceCommand::Retire { snapshot, yes } => entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            DeviceCommand::Rename { device, new_name } => {
                let change = rename_change(database, RegistryKind::Device, device, new_name)?;
                record(cli, database, change)?;
                EXIT_OK
            }
            DeviceCommand::Identity(args) => device_identity(cli, database, args)?,
            DeviceCommand::Move {
                device_positional,
                device_option,
                to,
            } => {
                let selector = device_positional
                    .as_deref()
                    .or(device_option.as_deref())
                    .expect("clap requires one Device selector");
                let state = state(database, false)?;
                let mut device = select_device(&state.devices, selector)?
                    .ok_or_else(|| AppError::Input(format!("Device not found: {selector:?}")))?;
                let site = select_site(&state.sites, to)?
                    .ok_or_else(|| AppError::Input(format!("Site not found: {to:?}")))?;
                if device.current_site_id.as_deref() == Some(&site.site_id) {
                    return Err(AppError::Input(format!(
                        "Device {} is already at Site {}",
                        device.display_name, site.display_name
                    )));
                }
                device.current_site_id = Some(site.site_id);
                record(
                    cli,
                    database,
                    RegistryChange::Device(RegistryAction::Move, device),
                )?;
                EXIT_OK
            }
            DeviceCommand::CheckIn {
                device_id,
                fingerprint_status,
            } => {
                record(
                    cli,
                    database,
                    RegistryChange::DeviceCheckIn(DeviceCheckIn {
                        device_id: device_id.clone(),
                        fingerprint_status: fingerprint_status.clone(),
                    }),
                )?;
                EXIT_OK
            }
            DeviceCommand::Mount {
                device_id,
                mount_id,
                mount_root_uri,
                status,
                fingerprint_status,
            } => {
                record(
                    cli,
                    database,
                    RegistryChange::DeviceMount(DeviceMount {
                        mount_id: mount_id.clone(),
                        device_id: device_id.clone(),
                        archive_root_id: None,
                        mount_root_uri: mount_root_uri.clone(),
                        status: status.clone(),
                        fingerprint_status: fingerprint_status.clone(),
                    }),
                )?;
                EXIT_OK
            }
            DeviceCommand::Status { .. } => return Ok(None),
        },
        Command::Root { command } => entity(cli, database, RegistryKind::Root, command)?,
        Command::RiskDomain { command } => {
            entity(cli, database, RegistryKind::RiskDomain, command)?
        }
        Command::Collection { command } => match command {
            CollectionCommand::List { all } => entity(
                cli,
                database,
                RegistryKind::Collection,
                &RegistryEntityCommand::List { all: *all },
            )?,
            CollectionCommand::Show { id } => entity(
                cli,
                database,
                RegistryKind::Collection,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            CollectionCommand::Update { snapshot } => entity(
                cli,
                database,
                RegistryKind::Collection,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            CollectionCommand::Retire { snapshot, yes } => entity(
                cli,
                database,
                RegistryKind::Collection,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            CollectionCommand::Rename {
                collection,
                new_name,
            } => {
                let change =
                    rename_change(database, RegistryKind::Collection, collection, new_name)?;
                record(cli, database, change)?;
                EXIT_OK
            }
            CollectionCommand::Status { .. } => return Ok(None),
            CollectionCommand::Init(args) => collection_init(cli, database, args)?,
            CollectionCommand::Add(_) => return Ok(None),
        },
        Command::Location { command } => match command {
            LocationCommand::Discover { path } => entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Discover { path: path.clone() },
            )?,
            LocationCommand::List { all } => entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::List { all: *all },
            )?,
            LocationCommand::Show { id } => entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            LocationCommand::Register(args) => entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Add(args.clone()),
            )?,
            LocationCommand::Update { snapshot } => entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            LocationCommand::Retire { snapshot, yes } => entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            LocationCommand::Rename { location, new_name } => {
                let change = rename_change(database, RegistryKind::Location, location, new_name)?;
                record(cli, database, change)?;
                EXIT_OK
            }
            LocationCommand::Status { .. } => return Ok(None),
            LocationCommand::Init(args) => {
                validate_setup_source(&args.path, false, SetupCommand::Location)?;
                let state = state(database, false)?;
                let collection = select_collection(&state.collections, &args.collection)?
                    .ok_or_else(|| {
                        AppError::Input(format!("Collection not found: {:?}", args.collection))
                    })?;
                let setup = CollectionInitArgs {
                    path: args.path.clone(),
                    name: Some(collection.display_name.clone()),
                    device: args.device.clone(),
                    site: args.site.clone(),
                    location_name: args.location_name.clone(),
                    root_name: args.root_name.clone(),
                    allow_unidentified_root: args.allow_unidentified_root,
                    non_interactive: args.non_interactive,
                    import_annex: false,
                    inventory_only: false,
                    batch_entries: 1_000,
                    job_id: None,
                    import_id: None,
                    max_items: None,
                };
                filesystem_setup(cli, database, &setup, Some(collection))?
            }
            LocationCommand::Scan(_) => return Ok(None),
            LocationCommand::ImportAnnex(args) => {
                let state = state(database, false)?;
                let collection = select_collection(&state.collections, &args.collection)?
                    .ok_or_else(|| {
                        AppError::Input(format!("Collection not found: {:?}", args.collection))
                    })?;
                let setup = CollectionInitArgs {
                    path: args.repository.clone(),
                    name: Some(collection.display_name.clone()),
                    device: args.device.clone(),
                    site: args.site.clone(),
                    location_name: args.location_name.clone(),
                    root_name: args.root_name.clone(),
                    allow_unidentified_root: args.allow_unidentified_root,
                    non_interactive: args.non_interactive,
                    import_annex: true,
                    inventory_only: args.inventory_only,
                    batch_entries: args.batch_entries,
                    job_id: args.job_id.clone(),
                    import_id: args.import_id.clone(),
                    max_items: args.max_items,
                };
                annex_setup(cli, database, &setup, Some(collection), args.reimport)?
            }
            LocationCommand::Copy(_) => return Ok(None),
        },
        Command::Policy { command } => match command {
            PolicyCommand::List { all } => entity(
                cli,
                database,
                RegistryKind::Policy,
                &RegistryEntityCommand::List { all: *all },
            )?,
            PolicyCommand::Show { id } => entity(
                cli,
                database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            PolicyCommand::Add { snapshot } => entity(
                cli,
                database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Add(Box::new(RegistryAddArgs {
                    snapshot: Some(snapshot.clone()),
                    id: None,
                    name: None,
                    kind: None,
                    description: None,
                    site: None,
                    policy: None,
                    device: None,
                    root: None,
                    path: None,
                    fingerprint: None,
                    fingerprint_kind: None,
                    availability: "online".to_owned(),
                    encryption: "unknown".to_owned(),
                    trust: "unknown".to_owned(),
                    writable: false,
                })),
            )?,
            PolicyCommand::Retire { snapshot, yes } => entity(
                cli,
                database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            PolicyCommand::Update(args) => policy_update(cli, database, args)?,
            PolicyCommand::Evaluate => return Ok(None),
        },
        _ => return Ok(None),
    };
    Ok(Some(result))
}

fn rename_change(
    database: &SqliteCatalog,
    kind: RegistryKind,
    selector: &str,
    new_name: &str,
) -> Result<RegistryChange, AppError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(AppError::Input("new name must be non-empty".to_owned()));
    }
    let state = state(database, false)?;
    match kind {
        RegistryKind::Site => {
            let mut value = select_site(&state.sites, selector)?
                .ok_or_else(|| AppError::Input(format!("Site not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .sites
                    .iter()
                    .map(|item| (&item.site_id, &item.display_name)),
                &value.site_id,
                new_name,
                "Site",
            )?;
            if value.display_name == new_name {
                return Err(AppError::Input("Site already has that name".to_owned()));
            }
            value.display_name = new_name.to_owned();
            Ok(RegistryChange::Site(RegistryAction::Update, value))
        }
        RegistryKind::Collection => {
            let mut value = select_collection(&state.collections, selector)?
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .collections
                    .iter()
                    .map(|item| (&item.collection_id, &item.display_name)),
                &value.collection_id,
                new_name,
                "Collection",
            )?;
            if value.display_name == new_name {
                return Err(AppError::Input(
                    "Collection already has that name".to_owned(),
                ));
            }
            value.display_name = new_name.to_owned();
            Ok(RegistryChange::Collection(RegistryAction::Update, value))
        }
        RegistryKind::Device => {
            let mut value = select_device(&state.devices, selector)?
                .ok_or_else(|| AppError::Input(format!("Device not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .devices
                    .iter()
                    .map(|item| (&item.device_id, &item.display_name)),
                &value.device_id,
                new_name,
                "Device",
            )?;
            if value.display_name == new_name {
                return Err(AppError::Input("Device already has that name".to_owned()));
            }
            value.display_name = new_name.to_owned();
            Ok(RegistryChange::Device(RegistryAction::Update, value))
        }
        RegistryKind::Location => {
            let mut value = select_location(&state.locations, selector)?
                .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .locations
                    .iter()
                    .map(|item| (&item.location_id, &item.display_name)),
                &value.location_id,
                new_name,
                "Location",
            )?;
            if value.display_name == new_name {
                return Err(AppError::Input("Location already has that name".to_owned()));
            }
            value.display_name = new_name.to_owned();
            Ok(RegistryChange::Location(RegistryAction::Update, value))
        }
        _ => Err(AppError::Input(
            "rename is not available for this registry type".to_owned(),
        )),
    }
}

fn policy_update(
    cli: &Cli,
    database: &mut SqliteCatalog,
    args: &PolicyUpdateArgs,
) -> Result<u8, AppError> {
    let state = state(database, false)?;
    let mut policy = state
        .policies
        .iter()
        .find(|item| item.policy_id == args.policy || item.display_name == args.policy)
        .cloned()
        .ok_or_else(|| AppError::Input(format!("Policy not found: {:?}", args.policy)))?;
    if let Some(name) = &args.name {
        policy.display_name = name.clone();
    }
    if let Some(value) = args.copies {
        policy.requirements.min_qualifying_copies = value;
    }
    if let Some(value) = args.devices {
        policy.requirements.min_devices = value;
    }
    if let Some(value) = args.sites {
        policy.requirements.min_sites = value;
    }
    if let Some(value) = args.require_offsite {
        policy.requirements.require_offsite_copy = value;
    }
    if let Some(value) = args.require_offline {
        policy.requirements.require_offline_copy = value;
    }
    if let Some(value) = args.require_encrypted_offsite {
        policy.requirements.require_encrypted_offsite = value;
    }
    if let Some(value) = args.verification_days {
        policy.requirements.max_verification_age_days = value;
    }
    if let Some(value) = args.observation_days {
        policy.requirements.max_observation_age_days = value;
    }
    if let Some(value) = args.device_checkin_days {
        policy.requirements.max_device_checkin_age_days = value;
    }
    policy.policy_version = policy
        .policy_version
        .checked_add(1)
        .ok_or_else(|| AppError::Input("policy version overflow".to_owned()))?;
    record(
        cli,
        database,
        RegistryChange::Policy(RegistryAction::Update, policy),
    )?;
    Ok(EXIT_OK)
}

fn collection_init(
    cli: &Cli,
    database: &mut SqliteCatalog,
    args: &CollectionInitArgs,
) -> Result<u8, AppError> {
    validate_setup_source(&args.path, args.import_annex, SetupCommand::Collection)?;
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();
    let name = match args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.to_owned(),
        None if interactive => prompt_default("Collection name", "")?,
        None => {
            return Err(AppError::Input(
                "collection init requires --name when input is non-interactive".to_owned(),
            ))
        }
    };
    let mut setup = args.clone();
    setup.name = Some(name);
    if setup.import_annex {
        annex_setup(cli, database, &setup, None, false)
    } else {
        filesystem_setup(cli, database, &setup, None)
    }
}

fn device_identity(
    cli: &Cli,
    database: &mut SqliteCatalog,
    args: &DeviceIdentityArgs,
) -> Result<u8, AppError> {
    let state = state(database, false)?;
    let mut device = select_device(&state.devices, &args.device)?
        .ok_or_else(|| AppError::Input(format!("Device not found: {:?}", args.device)))?;
    let previous = device.clone();
    let fingerprint_status;
    if let (Some(value), Some(kind)) = (&args.fingerprint, &args.fingerprint_kind) {
        let value = value.trim();
        let kind = kind.trim().to_ascii_lowercase();
        if value.is_empty() || kind.is_empty() {
            return Err(AppError::Input(
                "Device fingerprint kind and value must be non-empty".to_owned(),
            ));
        }
        if is_archive_root_fingerprint_kind(&kind) {
            return Err(AppError::Input(format!(
                "{kind:?} identifies a filesystem/Archive Root, not a Device; use stable hardware evidence such as serial, wwn, nvme_eui64, or hardware_uuid"
            )));
        }
        if let Some(existing) = state.devices.iter().find(|candidate| {
            candidate.device_id != device.device_id
                && candidate.status == "active"
                && candidate.identity_state == "confirmed"
                && candidate.fingerprint_kind.as_deref() == Some(kind.as_str())
                && candidate.hardware_fingerprint.as_deref() == Some(value)
        }) {
            return Err(AppError::Input(format!(
                "that hardware identity already belongs to Device {:?} ({}); reuse that Device for this storage, or confirm a stronger distinct hardware identity",
                existing.display_name, existing.device_id
            )));
        }
        device.hardware_fingerprint = Some(value.to_owned());
        device.fingerprint_kind = Some(kind);
        device.identity_state = "confirmed".to_owned();
        fingerprint_status = "match";
    } else if args.unavailable {
        device.hardware_fingerprint = None;
        device.fingerprint_kind = None;
        device.identity_state = "unavailable".to_owned();
        fingerprint_status = "unavailable";
    } else if args.conflict {
        if device.hardware_fingerprint.is_none() || device.fingerprint_kind.is_none() {
            return Err(AppError::Input(
                "cannot mark a Device identity conflict before any hardware identity has been recorded; use --unavailable or confirm stable hardware evidence"
                    .to_owned(),
            ));
        }
        device.identity_state = "conflict".to_owned();
        fingerprint_status = "mismatch";
    } else {
        return Err(AppError::Input(
            "choose a Device identity action".to_owned(),
        ));
    }

    let committed = SqliteRegistry::new(database).record_batch(
        &[
            RegistryChange::Device(RegistryAction::Update, device.clone()),
            RegistryChange::DeviceCheckIn(DeviceCheckIn {
                device_id: device.device_id.clone(),
                fingerprint_status: fingerprint_status.to_owned(),
            }),
        ],
        &cli.host,
        now_utc_ms()?,
    )?;

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 3,
                "device": device,
                "previous_identity": {
                    "state": previous.identity_state,
                    "fingerprint_kind": previous.fingerprint_kind,
                    "hardware_fingerprint": previous.hardware_fingerprint,
                },
                "fingerprint_status": fingerprint_status,
                "revision": committed.revision,
                "archive_root_identity_unchanged": true,
            }))?
        );
    } else {
        println!("Device: {}", device.display_name);
        println!("Identity: {}", device.identity_state);
        if let (Some(kind), Some(value)) = (
            device.fingerprint_kind.as_deref(),
            device.hardware_fingerprint.as_deref(),
        ) {
            println!("Hardware evidence: {kind} {value}");
        } else {
            println!("Hardware evidence: unavailable");
        }
        match device.identity_state.as_str() {
            "confirmed" => println!(
                "Recorded a current match. Policy may now count this Device when its Copy evidence also qualifies."
            ),
            "conflict" => println!(
                "This Device will not count as independent protection until its identity conflict is resolved."
            ),
            _ => println!(
                "This Device will not count as independent protection while hardware identity is unavailable."
            ),
        }
        println!("Archive Root filesystem/partition identity was not changed.");
    }
    Ok(EXIT_OK)
}

fn filesystem_setup(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
    args: &CollectionInitArgs,
    existing_collection: Option<CollectionSnapshot>,
) -> Result<u8, AppError> {
    let (setup, changes) =
        plan_filesystem_setup(&state(catalog, false)?, args, existing_collection)?;
    let result = SqliteRegistry::new(catalog).record_batch(&changes, &cli.host, now_utc_ms()?)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version":3,"revision":result.revision,"collection":setup.collection,
                "location":setup.location,"device":setup.device,"site":setup.site,
                "archive_root":setup.root,"mounted":setup.mounted,
            }))?
        );
    } else {
        println!(
            "Configured Location {:?} for Collection {:?}.",
            setup.location.display_name, setup.collection.display_name
        );
        println!(
            "Next: archive collection add . --collection {}",
            shell_quote(&setup.collection.display_name)
        );
    }
    Ok(EXIT_OK)
}

pub(super) fn check_annex_import(
    catalog: &SqliteCatalog,
    collection_id: &str,
    location_id: &str,
    reimport: bool,
) -> Result<(), AppError> {
    let mut statement = catalog.connection().prepare(
        "SELECT job_id,status FROM catalog_jobs WHERE kind='inventory' AND json_extract(params_json,'$.annex_import')=1 AND json_extract(params_json,'$.collection_id')=?1 AND json_extract(params_json,'$.location_id')=?2 AND status IN ('running','complete') ORDER BY status DESC,started_time_utc_ms DESC"
    )?;
    let mut rows = statement.query(rusqlite::params![collection_id, location_id])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let status: String = row.get(1)?;
        if status == "running" {
            return Err(AppError::Input(format!(
                "this Location has an unfinished annex import; resume with archive job resume {id}"
            )));
        }
        if !reimport {
            return Err(AppError::Input("this Location already has a completed annex import; use location scan for ordinary updates, or location import-annex --reimport for an intentional repeat".into()));
        }
    }
    Ok(())
}

fn annex_setup(
    cli: &Cli,
    catalog: &mut SqliteCatalog,
    args: &CollectionInitArgs,
    existing_collection: Option<CollectionSnapshot>,
    reimport: bool,
) -> Result<u8, AppError> {
    validate_setup_source(&args.path, true, SetupCommand::Collection)?;
    if args.batch_entries == 0 {
        return Err(AppError::Input(
            "--batch-entries must be greater than zero".into(),
        ));
    }
    let (setup, changes) =
        plan_filesystem_setup(&state(catalog, false)?, args, existing_collection)?;
    check_annex_import(
        catalog,
        &setup.collection.collection_id,
        &setup.location.location_id,
        reimport,
    )?;
    SqliteRegistry::new(catalog).record_batch(&changes, &cli.host, now_utc_ms()?)?;
    super::sqlite_cli::import_annex(
        cli,
        catalog,
        &setup.collection.collection_id,
        &setup.location.location_id,
        &setup.mounted.path,
        args.inventory_only,
        args.import_id.as_deref(),
        args.job_id.as_deref(),
        args.max_items,
        args.batch_entries,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn filesystem_setup_commits_registry_together_without_scanning_contents() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("files");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("original"), b"original").unwrap();
        let mut catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        let cli = Cli {
            archive: None,
            database: None,
            events: None,
            actor: "actor".into(),
            host: "host".into(),
            json: true,
            command: Command::Collection {
                command: CollectionCommand::Init(CollectionInitArgs {
                    path: root.clone(),
                    name: Some("Files".into()),
                    device: Some("Disk".into()),
                    site: Some("Home".into()),
                    location_name: Some("Files on Disk".into()),
                    root_name: None,
                    allow_unidentified_root: true,
                    non_interactive: true,
                    import_annex: false,
                    inventory_only: false,
                    batch_entries: 1000,
                    job_id: None,
                    import_id: None,
                    max_items: None,
                }),
            },
        };
        assert_eq!(execute_setup(&cli, &mut catalog).unwrap(), Some(EXIT_OK));
        let snapshot = state(&catalog, false).unwrap();
        assert_eq!(snapshot.collections.len(), 1);
        assert_eq!(snapshot.locations.len(), 1);
        assert_eq!(snapshot.devices.len(), 1);
        assert_eq!(snapshot.sites.len(), 1);
        assert_eq!(catalog.metadata().unwrap().revision, 1);
        let object_count: i64 = catalog
            .connection()
            .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))
            .unwrap();
        assert_eq!(object_count, 0);
        assert_eq!(fs::read(root.join("original")).unwrap(), b"original");
        assert!(execute_setup(&cli, &mut catalog).is_err());
        assert_eq!(catalog.metadata().unwrap().revision, 1);
    }

    #[test]
    fn annex_repeat_guard_distinguishes_scan_and_import_jobs() {
        let temp = tempfile::TempDir::new().unwrap();
        let catalog =
            SqliteCatalog::create(temp.path().join("catalog.db"), "arc", "Archive").unwrap();
        catalog.connection().execute("INSERT INTO catalog_jobs(job_id,kind,params_json,status,started_time_utc_ms) VALUES ('scan','inventory',?1,'complete',1)", [r#"{"collection_id":"c","location_id":"l","annex_import":false}"#]).unwrap();
        assert!(check_annex_import(&catalog, "c", "l", false).is_ok());
        catalog.connection().execute("INSERT INTO catalog_jobs(job_id,kind,params_json,status,started_time_utc_ms) VALUES ('import','inventory',?1,'complete',2)", [r#"{"collection_id":"c","location_id":"l","annex_import":true}"#]).unwrap();
        assert!(check_annex_import(&catalog, "c", "l", false).is_err());
        assert!(check_annex_import(&catalog, "c", "l", true).is_ok());
        catalog
            .connection()
            .execute(
                "UPDATE catalog_jobs SET status='running' WHERE job_id='import'",
                [],
            )
            .unwrap();
        let error = check_annex_import(&catalog, "c", "l", true).unwrap_err();
        assert!(error.to_string().contains("archive job resume import"));
        assert!(check_annex_import(&catalog, "other", "l", false).is_ok());
    }
}
