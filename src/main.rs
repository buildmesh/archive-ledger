use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use archive_ledger::{
    utf8_path, ArchiveRootSnapshot, CachedPolicyStatus, CollectionSnapshot, CopyFilter,
    CopyPageRequest, DeviceCheckIn, DeviceMount, DeviceSnapshot, EventRequest, EventStore,
    EventStoreConfig, EventStoreError, FileFilter, FilePageRequest, LocationSnapshot,
    MetadataDestinationSnapshot, MetadataError, MetadataProtector, MetadataRegistry, PolicyError,
    PolicyEvaluationResult, PolicyFinding, PolicyFindingFilter, PolicyFindingPage, PolicySnapshot,
    ProjectionConfig, ProjectionDb, ProjectionError, Registry, RegistryAction, RegistryChange,
    RegistryError, RegistryPath, ReviewError, RiskAssignment, RiskDomainSnapshot, SiteSnapshot,
};
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use serde_json::json;

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 2;
const EXIT_FINDINGS: u8 = 10;

#[derive(Debug, Parser)]
#[command(name = "archive", version, about = "Review and protect local archives")]
struct Cli {
    /// SQLite materialized-view database.
    #[arg(long, global = true, default_value = ".archive-ledger/archive.db")]
    database: PathBuf,

    /// Canonical event-store directory, used only by mutation commands.
    #[arg(long, global = true, default_value = ".archive-ledger/canonical")]
    events: PathBuf,

    #[arg(long, global = true, default_value = "local-user")]
    actor: String,

    #[arg(long, global = true, default_value = "local-host")]
    host: String,

    /// Emit versioned JSON instead of human-readable output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new empty event store and SQLite projection.
    Init {
        /// Stable archive ID; generated when omitted.
        #[arg(long)]
        archive_id: Option<String>,
    },
    /// Show fast cached preservation status from SQLite.
    Status,
    /// Find, inspect, and audit logical files.
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
    /// Inspect content objects and every logical path that references them.
    Object {
        #[command(subcommand)]
        command: ObjectCommand,
    },
    /// List and inspect physical or service copy claims.
    Copy {
        #[command(subcommand)]
        command: CopyCommand,
    },
    /// Manage sites through canonical full-snapshot events.
    Site {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Manage collections through canonical full-snapshot events.
    Collection {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Manage devices through canonical full-snapshot events.
    Device {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Manage archive roots through canonical full-snapshot events.
    Root {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Manage storage locations through canonical full-snapshot events.
    Location {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Manage shared risk domains through canonical full-snapshot events.
    RiskDomain {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Evaluate preservation policies.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Show integrity and disaster-risk findings.
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Register and check Git destinations for canonical metadata.
    MetadataDestination {
        #[command(subcommand)]
        command: MetadataDestinationCommand,
    },
    /// Record which registered location contains this catalog.
    CatalogLocation { location_id: String },
    /// Create or reconcile a durable metadata checkpoint.
    Checkpoint {
        #[command(subcommand)]
        command: Option<CheckpointCommand>,
        /// Push and observe every active metadata destination.
        #[arg(long)]
        replicate: bool,
    },
    /// Verify canonical event history.
    Events {
        #[command(subcommand)]
        command: EventsCommand,
    },
    /// Check clean-machine restoration from a cloned event repository.
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
}

#[derive(Debug, Subcommand)]
enum MetadataDestinationCommand {
    Add(MetadataDestinationArgs),
    List {
        #[arg(long)]
        all: bool,
    },
    Show {
        id: String,
    },
    Update {
        snapshot: String,
    },
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
    Check {
        destination_id: String,
        checkpoint_id: String,
        #[arg(long)]
        push: bool,
    },
}

#[derive(Debug, Args)]
struct MetadataDestinationArgs {
    #[arg(long)]
    id: Option<String>,
    #[arg(long)]
    name: String,
    #[arg(long)]
    location: String,
    #[arg(long)]
    remote: String,
    #[arg(long)]
    locator: String,
    #[arg(long = "ref", default_value = "refs/heads/archive-ledger")]
    remote_ref: String,
}

#[derive(Debug, Subcommand)]
enum CheckpointCommand {
    Reconcile { checkpoint_id: String },
}

#[derive(Debug, Subcommand)]
enum EventsCommand {
    Verify,
}

#[derive(Debug, Subcommand)]
enum RestoreCommand {
    Check {
        /// Local clone of a canonical event repository.
        event_repository: PathBuf,
        /// New or safely replaceable SQLite projection path.
        #[arg(long)]
        rebuild_database: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum FileCommand {
    /// Find active logical paths from SQLite without scanning storage.
    Find(FileFindArgs),
    /// Show one logical file and all current copy evidence.
    Show { file_ref_id: String },
    /// Show canonical history mirrored in SQLite.
    History {
        file_ref_id: String,
        #[arg(long, default_value_t = 0)]
        after_seq: u64,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum ObjectCommand {
    Show {
        object_id: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long = "continue")]
        continuation: Option<String>,
    },
    History {
        object_id: String,
        #[arg(long, default_value_t = 0)]
        after_seq: u64,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Debug, Subcommand)]
enum CopyCommand {
    List {
        #[arg(long)]
        object: Option<String>,
        #[arg(long)]
        location: Option<String>,
        #[arg(long)]
        device: Option<String>,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        verified_before_utc_ms: Option<u64>,
        #[arg(long)]
        observed_before_utc_ms: Option<u64>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long = "continue")]
        continuation: Option<String>,
    },
    Show {
        copy_claim_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum RegistryEntityCommand {
    /// List active registry entries.
    List {
        #[arg(long)]
        all: bool,
    },
    /// Show one registry entry by stable ID.
    Show { id: String },
    /// Add an entry with friendly flags, or provide a complete JSON snapshot.
    Add(Box<RegistryAddArgs>),
    /// Replace user-controlled fields with a complete JSON snapshot.
    Update { snapshot: String },
    /// Retire an entry with a complete JSON snapshot whose status is retired.
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
    /// Move a device with a full active snapshot containing its new site.
    Move { snapshot: String },
    /// Assign this risk domain to a location, root, device, or site.
    Assign {
        risk_domain_id: String,
        #[arg(long)]
        entity_type: String,
        #[arg(long)]
        entity_id: String,
    },
    /// Remove a risk-domain assignment.
    Unassign {
        risk_domain_id: String,
        #[arg(long)]
        entity_type: String,
        #[arg(long)]
        entity_id: String,
    },
    /// Record a device identity check-in.
    CheckIn {
        device_id: String,
        #[arg(long)]
        fingerprint_status: String,
    },
    /// Record the current host's observation of a device mount.
    Mount {
        device_id: String,
        #[arg(long)]
        mount_id: String,
        #[arg(long)]
        mount_root_uri: String,
        #[arg(long)]
        status: String,
        #[arg(long)]
        fingerprint_status: String,
    },
}

#[derive(Debug, Args)]
struct RegistryAddArgs {
    #[arg(long)]
    snapshot: Option<String>,
    #[arg(long)]
    id: Option<String>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    kind: Option<String>,
    #[arg(long)]
    description: Option<String>,
    #[arg(long)]
    site: Option<String>,
    #[arg(long)]
    policy: Option<String>,
    #[arg(long)]
    device: Option<String>,
    #[arg(long)]
    root: Option<String>,
    #[arg(long)]
    path: Option<String>,
    #[arg(long)]
    fingerprint: Option<String>,
    #[arg(long)]
    fingerprint_kind: Option<String>,
    #[arg(long, default_value = "online")]
    availability: String,
    #[arg(long, default_value = "unknown")]
    encryption: String,
    #[arg(long, default_value = "unknown")]
    trust: String,
    #[arg(long)]
    writable: bool,
}

#[derive(Debug, Clone, Copy)]
enum RegistryKind {
    Site,
    Collection,
    Device,
    Root,
    Location,
    RiskDomain,
    Policy,
}

#[derive(Debug, Args)]
struct FileFindArgs {
    #[arg(long)]
    collection: Option<String>,
    #[arg(long, conflicts_with = "prefix")]
    exact: Option<String>,
    #[arg(long, conflicts_with = "exact")]
    prefix: Option<String>,
    #[arg(long)]
    identity_state: Option<String>,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long = "continue")]
    continuation: Option<String>,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Recompute policy results from the current SQLite snapshot.
    Evaluate,
    List {
        #[arg(long)]
        all: bool,
    },
    Show {
        id: String,
    },
    Add {
        snapshot: String,
    },
    Update {
        snapshot: String,
    },
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    /// Show cached policy and disaster-loss findings.
    Risk(ReportArgs),
    /// Show cached integrity/policy uncertainty and violations.
    Integrity(ReportArgs),
    /// Show cached per-policy totals and validity.
    Policy(ReportSummaryArgs),
    /// Show checkpoint, commit, and independent replication coverage.
    Metadata,
}

#[derive(Debug, Args)]
struct ReportArgs {
    #[arg(long)]
    policy: Option<String>,
    #[arg(long)]
    collection: Option<String>,
    /// Restrict findings to `violated` or `uncertain`.
    #[arg(long = "result")]
    result: Option<String>,
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[arg(long = "continue")]
    continuation: Option<String>,
}

#[derive(Debug, Args)]
struct ReportSummaryArgs {
    #[arg(long)]
    policy: Option<String>,
    #[arg(long)]
    collection: Option<String>,
}

#[derive(Debug)]
enum AppError {
    EventStore(EventStoreError),
    Projection(ProjectionError),
    Review(ReviewError),
    Policy(PolicyError),
    Registry(RegistryError),
    Metadata(MetadataError),
    Json(serde_json::Error),
    Clock,
    Input(String),
}

impl AppError {
    fn code(&self) -> &'static str {
        match self {
            Self::EventStore(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Review(error) => error.code(),
            Self::Policy(error) => error.code(),
            Self::Registry(error) => error.code(),
            Self::Metadata(error) => error.code(),
            Self::Json(_) => "output_json",
            Self::Clock => "clock_invalid",
            Self::Input(_) => "invalid_input",
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EventStore(error) => error.fmt(formatter),
            Self::Projection(error) => error.fmt(formatter),
            Self::Review(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::Registry(error) => error.fmt(formatter),
            Self::Metadata(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
            Self::Input(message) => formatter.write_str(message),
        }
    }
}

impl From<EventStoreError> for AppError {
    fn from(error: EventStoreError) -> Self {
        Self::EventStore(error)
    }
}

impl From<ProjectionError> for AppError {
    fn from(error: ProjectionError) -> Self {
        Self::Projection(error)
    }
}

impl From<ReviewError> for AppError {
    fn from(error: ReviewError) -> Self {
        Self::Review(error)
    }
}

impl From<PolicyError> for AppError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<RegistryError> for AppError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<MetadataError> for AppError {
    fn from(error: MetadataError) -> Self {
        Self::Metadata(error)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug, Serialize)]
struct RiskOutput {
    version: u32,
    filters: PolicyFindingFilter,
    rollup_scope: &'static str,
    status: CachedPolicyStatus,
    findings: PolicyFindingPage,
}

#[derive(Debug, Serialize)]
struct PolicyReportOutput {
    version: u32,
    policy: Option<String>,
    collection: Option<String>,
    rollup_scope: &'static str,
    status: CachedPolicyStatus,
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    version: u32,
    policy: CachedPolicyStatus,
    metadata: archive_ledger::MetadataProtectionStatus,
}

fn main() -> ExitCode {
    let json_requested = std::env::args().any(|argument| argument == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if json_requested {
                let output = json!({
                    "version": 1,
                    "error": {"code": "invalid_input", "message": error.to_string()},
                });
                eprintln!("{output}");
            } else {
                let _ = error.print();
            }
            return ExitCode::from(EXIT_ERROR);
        }
    };
    match execute(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if cli.json {
                eprintln!(
                    "{}",
                    json!({
                        "version": 1,
                        "error": {"code": error.code(), "message": error.to_string()},
                    })
                );
            } else {
                eprintln!("error [{}]: {error}", error.code());
            }
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn execute(cli: &Cli) -> Result<u8, AppError> {
    if let Command::Init { archive_id } = &cli.command {
        return execute_init(cli, archive_id.as_deref());
    }
    if let Command::Restore {
        command:
            RestoreCommand::Check {
                event_repository,
                rebuild_database,
            },
    } = &cli.command
    {
        let result = archive_ledger::restore_check(event_repository, rebuild_database)?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "Restore verified through sequence {} and rebuilt matching SQLite state at {}.",
                result.verified_event_seq,
                rebuild_database.display()
            );
        }
        return Ok(EXIT_OK);
    }
    if let Command::Events {
        command: EventsCommand::Verify,
    } = &cli.command
    {
        return execute_events_verify(cli);
    }
    let database = ProjectionDb::open_existing(&cli.database, ProjectionConfig::default())?;
    match &cli.command {
        Command::Init { .. } => unreachable!("init returned before opening an existing database"),
        Command::Status => execute_status(&database, cli.json),
        Command::File { command } => execute_file(&database, command, cli.json),
        Command::Object { command } => execute_object(&database, command, cli.json),
        Command::Copy { command } => execute_copy(&database, command, cli.json),
        Command::Site { command } => execute_registry(cli, &database, RegistryKind::Site, command),
        Command::Collection { command } => {
            execute_registry(cli, &database, RegistryKind::Collection, command)
        }
        Command::Device { command } => {
            execute_registry(cli, &database, RegistryKind::Device, command)
        }
        Command::Root { command } => execute_registry(cli, &database, RegistryKind::Root, command),
        Command::Location { command } => {
            execute_registry(cli, &database, RegistryKind::Location, command)
        }
        Command::RiskDomain { command } => {
            execute_registry(cli, &database, RegistryKind::RiskDomain, command)
        }
        Command::Policy { command } => match command {
            PolicyCommand::Evaluate => execute_policy_evaluation(&database, cli.json),
            PolicyCommand::List { all } => execute_registry(
                cli,
                &database,
                RegistryKind::Policy,
                &RegistryEntityCommand::List { all: *all },
            ),
            PolicyCommand::Show { id } => execute_registry(
                cli,
                &database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Show { id: id.clone() },
            ),
            PolicyCommand::Add { snapshot } => execute_registry_snapshot(
                cli,
                &database,
                RegistryKind::Policy,
                RegistryAction::Register,
                snapshot,
            ),
            PolicyCommand::Update { snapshot } => execute_registry(
                cli,
                &database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            ),
            PolicyCommand::Retire { snapshot, yes } => execute_registry(
                cli,
                &database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            ),
        },
        Command::Report { command } => match command {
            ReportCommand::Risk(args) | ReportCommand::Integrity(args) => {
                execute_cached_report(&database, args, cli.json)
            }
            ReportCommand::Policy(args) => execute_policy_report(&database, args, cli.json),
            ReportCommand::Metadata => execute_metadata_status(&database, cli.json),
        },
        Command::MetadataDestination { command } => {
            execute_metadata_destination(cli, &database, command)
        }
        Command::CatalogLocation { location_id } => {
            let events = open_event_store(cli)?;
            let seq =
                MetadataRegistry::new(&events, &database).set_catalog_location(location_id)?;
            print_mutation_seq(seq, "Catalog location recorded", cli.json)?;
            Ok(EXIT_OK)
        }
        Command::Checkpoint { command, replicate } => {
            let events = open_event_store(cli)?;
            let protector = MetadataProtector::new(&events, &database);
            let result = match command {
                Some(CheckpointCommand::Reconcile { checkpoint_id }) => {
                    protector.reconcile(checkpoint_id)?
                }
                None => protector.checkpoint(*replicate)?,
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "Checkpoint {} covers sequence {} and is committed as {}.",
                    result.checkpoint_id, result.event_last_seq, result.local_git_commit
                );
                if result.replication_observations == 0 {
                    println!(
                        "No destination was pushed; use --replicate after configuring Git remotes."
                    );
                }
            }
            let replication_failed = *replicate
                && database
                    .metadata_protection_status()?
                    .destinations
                    .iter()
                    .filter(|destination| destination.snapshot.status == "active")
                    .all(|destination| {
                        destination.latest_replication_status.as_deref() != Some("present")
                            || destination.latest_independence_status.as_deref()
                                != Some("independent")
                    });
            Ok(if replication_failed {
                EXIT_FINDINGS
            } else {
                EXIT_OK
            })
        }
        Command::Events { .. } => unreachable!("event verification returned before opening SQLite"),
        Command::Restore { .. } => unreachable!("restore returned before opening SQLite"),
    }
}

fn execute_status(database: &ProjectionDb, as_json: bool) -> Result<u8, AppError> {
    let status = database.cached_policy_status(now_utc_ms()?)?;
    let metadata = database.metadata_protection_status()?;
    let has_findings = metadata.unreplicated_events > 0
        || metadata.catalog_location_id.is_none()
        || !status.unconfigured_collections.is_empty()
        || !status.stale_policies.is_empty()
        || status
            .evaluations
            .iter()
            .any(|policy| policy.files_violated > 0 || policy.files_uncertain > 0);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&StatusOutput {
                version: 1,
                policy: status,
                metadata,
            })?
        );
    } else {
        print_metadata_status(&metadata);
        print_cached_status(&status);
    }
    Ok(if has_findings { EXIT_FINDINGS } else { EXIT_OK })
}

fn execute_object(
    database: &ProjectionDb,
    command: &ObjectCommand,
    as_json: bool,
) -> Result<u8, AppError> {
    match command {
        ObjectCommand::Show {
            object_id,
            limit,
            continuation,
        } => {
            let review = database.review_object(object_id, *limit, continuation.clone())?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&review)?);
            } else {
                println!(
                    "{}:{}  {} bytes  {} logical paths on this page",
                    review.canonical_hash_algo,
                    review.canonical_hash_hex,
                    review.size_bytes,
                    review.files.items.len()
                );
                for file in &review.files.items {
                    println!(
                        "  {}  [{}]",
                        file.logical_path.display, file.collection_name
                    );
                }
                if let Some(next) = review.files.next {
                    println!("More paths: rerun with --continue {next}");
                }
            }
        }
        ObjectCommand::History {
            object_id,
            after_seq,
            limit,
        } => {
            let history = database.object_history(object_id, *after_seq, *limit)?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&history)?);
            } else {
                for event in history.items {
                    println!("{}  {}  {}", event.seq, event.event_type, event.time_utc_ms);
                }
                if let Some(next) = history.next_seq {
                    println!("More history: rerun with --after-seq {next}");
                }
            }
        }
    }
    Ok(EXIT_OK)
}

fn execute_copy(
    database: &ProjectionDb,
    command: &CopyCommand,
    as_json: bool,
) -> Result<u8, AppError> {
    let page = match command {
        CopyCommand::List {
            object,
            location,
            device,
            site,
            state,
            verified_before_utc_ms,
            observed_before_utc_ms,
            limit,
            continuation,
        } => database.list_copies(CopyPageRequest {
            filter: CopyFilter {
                object_id: object.clone(),
                location_id: location.clone(),
                device_id: device.clone(),
                site_id: site.clone(),
                state: state.clone(),
                verified_before_utc_ms: *verified_before_utc_ms,
                observed_before_utc_ms: *observed_before_utc_ms,
                ..CopyFilter::default()
            },
            limit: *limit,
            continuation: continuation.clone(),
        })?,
        CopyCommand::Show { copy_claim_id } => archive_ledger::CopyPage {
            version: 1,
            applied_event_seq: database.status()?.cursor.applied_seq,
            items: vec![database.review_copy(copy_claim_id)?],
            next: None,
        },
    };
    if as_json {
        println!("{}", serde_json::to_string_pretty(&page)?);
    } else {
        for copy in &page.items {
            println!(
                "{}  {}  {}",
                copy.location_name, copy.relative_path.display, copy.state
            );
            println!(
                "  copy: {}  device/site: {} / {}",
                copy.copy_claim_id,
                copy.device_name.as_deref().unwrap_or("service"),
                copy.site_name.as_deref().unwrap_or("unknown")
            );
            println!(
                "  seen: {}  verified: {} ({})",
                optional_time(copy.last_seen_time_utc_ms),
                optional_time(copy.last_verified_time_utc_ms),
                copy.last_verification_result.as_deref().unwrap_or("never")
            );
        }
        if let Some(next) = page.next {
            println!("More copies: rerun with --continue {next}");
        }
    }
    Ok(EXIT_OK)
}

fn execute_metadata_destination(
    cli: &Cli,
    database: &ProjectionDb,
    command: &MetadataDestinationCommand,
) -> Result<u8, AppError> {
    match command {
        MetadataDestinationCommand::List { all } => {
            let mut destinations = database.metadata_protection_status()?.destinations;
            if !all {
                destinations.retain(|destination| destination.snapshot.status == "active");
            }
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"version": 1, "items": destinations}))?
                );
            } else {
                for destination in destinations {
                    print_metadata_destination(&destination);
                }
            }
        }
        MetadataDestinationCommand::Show { id } => {
            let destination = database
                .metadata_protection_status()?
                .destinations
                .into_iter()
                .find(|destination| destination.snapshot.destination_id == *id)
                .ok_or_else(|| AppError::Input(format!("metadata destination not found: {id}")))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&destination)?);
            } else {
                print_metadata_destination(&destination);
            }
        }
        MetadataDestinationCommand::Add(args) => {
            let snapshot = MetadataDestinationSnapshot {
                destination_id: args.id.clone().unwrap_or_else(|| {
                    format!(
                        "metadata_{}",
                        ulid::Ulid::new().to_string().to_ascii_lowercase()
                    )
                }),
                display_name: args.name.clone(),
                location_id: args.location.clone(),
                git_remote_name: args.remote.clone(),
                remote_locator: args.locator.clone(),
                remote_ref: args.remote_ref.clone(),
                status: "active".to_owned(),
            };
            record_metadata_destination(cli, database, RegistryAction::Register, snapshot)?;
            if !cli.json {
                println!(
                    "Next: git -C {} remote add {} {}",
                    cli.events.display(),
                    args.remote,
                    args.locator
                );
            }
        }
        MetadataDestinationCommand::Update { snapshot } => {
            record_metadata_destination(
                cli,
                database,
                RegistryAction::Update,
                parse_snapshot(snapshot)?,
            )?;
        }
        MetadataDestinationCommand::Retire { snapshot, yes } => {
            if !yes {
                return Err(AppError::Input(
                    "retirement requires --yes after reviewing the full snapshot".to_owned(),
                ));
            }
            record_metadata_destination(
                cli,
                database,
                RegistryAction::Retire,
                parse_snapshot(snapshot)?,
            )?;
        }
        MetadataDestinationCommand::Check {
            destination_id,
            checkpoint_id,
            push,
        } => {
            let events = open_event_store(cli)?;
            MetadataProtector::new(&events, database).check_destination(
                checkpoint_id,
                destination_id,
                *push,
            )?;
            let state = database
                .metadata_protection_status()?
                .destinations
                .into_iter()
                .find(|destination| destination.snapshot.destination_id == *destination_id)
                .ok_or_else(|| {
                    AppError::Input(format!("metadata destination not found: {destination_id}"))
                })?;
            let protected = state.latest_replication_status.as_deref() == Some("present")
                && state.latest_independence_status.as_deref() == Some("independent");
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&state)?);
            } else {
                print_metadata_destination(&state);
            }
            return Ok(if protected { EXIT_OK } else { EXIT_FINDINGS });
        }
    }
    Ok(EXIT_OK)
}

fn record_metadata_destination(
    cli: &Cli,
    database: &ProjectionDb,
    action: RegistryAction,
    snapshot: MetadataDestinationSnapshot,
) -> Result<(), AppError> {
    let events = open_event_store(cli)?;
    archive_ledger::initialize_metadata_repository(events.root())?;
    let seq = MetadataRegistry::new(&events, database).record_destination(action, snapshot)?;
    print_mutation_seq(seq, "Metadata destination recorded", cli.json)
}

fn print_metadata_destination(destination: &archive_ledger::MetadataDestinationState) {
    println!(
        "{}  {}  {}",
        destination.snapshot.display_name,
        destination.snapshot.destination_id,
        destination.snapshot.status
    );
    println!(
        "  location: {}  Git: {} -> {}",
        destination.snapshot.location_id,
        destination.snapshot.git_remote_name,
        destination.snapshot.remote_ref
    );
    println!(
        "  latest: {} / {}",
        destination
            .latest_replication_status
            .as_deref()
            .unwrap_or("never checked"),
        destination
            .latest_independence_status
            .as_deref()
            .unwrap_or("unknown independence")
    );
}

fn execute_metadata_status(database: &ProjectionDb, as_json: bool) -> Result<u8, AppError> {
    let status = database.metadata_protection_status()?;
    if as_json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print_metadata_status(&status);
    }
    Ok(
        if status.uncommitted_events > 0
            || status.unreplicated_events > 0
            || status.catalog_location_id.is_none()
        {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

fn print_metadata_status(status: &archive_ledger::MetadataProtectionStatus) {
    println!(
        "Catalog events: projected through {}; checkpointed through {}; committed through {}; independently protected through {}.",
        status.applied_event_seq,
        status.checkpointed_through_seq,
        status.committed_through_seq,
        status.independently_protected_through_seq
    );
    if status.catalog_location_id.is_none() {
        println!("UNKNOWN catalog location. Next: archive catalog-location <location-id>");
    }
    if status.uncheckpointed_events > 0 {
        println!(
            "WARNING {} events are not checkpointed. Next: archive checkpoint",
            status.uncheckpointed_events
        );
    }
    if status.uncommitted_events > 0 {
        println!(
            "WARNING {} events are not committed to Git. Next: archive checkpoint (or archive checkpoint reconcile <checkpoint-id> after an interrupted checkpoint)",
            status.uncommitted_events
        );
    }
    if status.unreplicated_events > 0 {
        println!(
            "WARNING {} events are not independently protected. Next: configure a metadata destination and run archive checkpoint --replicate",
            status.unreplicated_events
        );
    }
}

fn execute_events_verify(cli: &Cli) -> Result<u8, AppError> {
    let report = open_event_store(cli)?.verify()?;
    let output = json!({
        "version": 1,
        "last_seq": report.last_seq,
        "last_event_hash": report.last_event_hash,
        "segments": report.segments.len(),
        "checkpoints": report.checkpoints.len(),
    });
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "Verified {} events, {} segments, and {} checkpoints.",
            report.last_seq,
            report.segments.len(),
            report.checkpoints.len()
        );
    }
    Ok(EXIT_OK)
}

fn open_event_store(cli: &Cli) -> Result<EventStore, AppError> {
    Ok(EventStore::open_or_create(
        &cli.events,
        EventStoreConfig {
            actor_id: cli.actor.clone(),
            host_id: cli.host.clone(),
            ..EventStoreConfig::default()
        },
    )?)
}

fn print_mutation_seq(seq: u64, message: &str, as_json: bool) -> Result<(), AppError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"version": 1, "event_seq": seq}))?
        );
    } else {
        println!("{message} at sequence {seq}.");
    }
    Ok(())
}

fn execute_init(cli: &Cli, archive_id: Option<&str>) -> Result<u8, AppError> {
    if cli.database.exists() || cli.events.exists() {
        return Err(AppError::Input(
            "init target already exists; choose empty --database and --events paths".to_owned(),
        ));
    }
    let archive_id = archive_id
        .map(str::to_owned)
        .unwrap_or_else(|| format!("arc_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    let events = EventStore::open_or_create(
        &cli.events,
        EventStoreConfig {
            actor_id: cli.actor.clone(),
            host_id: cli.host.clone(),
            ..EventStoreConfig::default()
        },
    )?;
    archive_ledger::initialize_metadata_repository(events.root())?;
    let database =
        ProjectionDb::open_or_create(&cli.database, &archive_id, ProjectionConfig::default())?;
    events.append(EventRequest::new(
        "archive_initialized",
        json!({"archive_id": archive_id}),
    ))?;
    database.apply(&events)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "archive_id": archive_id,
                "database": cli.database,
                "events": cli.events,
                "applied_event_seq": 1,
            }))?
        );
    } else {
        println!("Initialized archive {archive_id}");
        println!("  database: {}", cli.database.display());
        println!("  canonical events: {}", cli.events.display());
        println!("Next: register sites, devices, locations, a collection, and a policy.");
    }
    Ok(EXIT_OK)
}

fn execute_registry(
    cli: &Cli,
    database: &ProjectionDb,
    kind: RegistryKind,
    command: &RegistryEntityCommand,
) -> Result<u8, AppError> {
    match command {
        RegistryEntityCommand::List { all } => {
            let state = database.registry_state(*all)?;
            let values = registry_values(kind, &state)?;
            print_registry_values(kind, values, cli.json)?;
        }
        RegistryEntityCommand::Show { id } => {
            let state = database.registry_state(true)?;
            let values = registry_values(kind, &state)?;
            let value = values
                .into_iter()
                .find(|value| registry_id(value) == Some(id.as_str()))
                .ok_or_else(|| AppError::Input(format!("registry entry not found: {id}")))?;
            print_registry_values(kind, vec![value], cli.json)?;
        }
        RegistryEntityCommand::Add(args) => {
            let change = if let Some(snapshot) = &args.snapshot {
                parse_registry_change(kind, RegistryAction::Register, snapshot)?
            } else {
                build_registry_add(kind, args)?
            };
            record_registry_change(cli, database, change)?;
        }
        RegistryEntityCommand::Update { snapshot } => {
            execute_registry_snapshot(cli, database, kind, RegistryAction::Update, snapshot)?;
        }
        RegistryEntityCommand::Retire { snapshot, yes } => {
            if !yes {
                return Err(AppError::Input(
                    "retirement requires --yes after reviewing the full snapshot".to_owned(),
                ));
            }
            execute_registry_snapshot(cli, database, kind, RegistryAction::Retire, snapshot)?;
        }
        RegistryEntityCommand::Move { snapshot } => {
            if !matches!(kind, RegistryKind::Device) {
                return Err(AppError::Input(
                    "move is available only under device".to_owned(),
                ));
            }
            execute_registry_snapshot(cli, database, kind, RegistryAction::Move, snapshot)?;
        }
        RegistryEntityCommand::Assign {
            risk_domain_id,
            entity_type,
            entity_id,
        }
        | RegistryEntityCommand::Unassign {
            risk_domain_id,
            entity_type,
            entity_id,
        } => {
            if !matches!(kind, RegistryKind::RiskDomain) {
                return Err(AppError::Input(
                    "risk assignment commands are available only under risk-domain".to_owned(),
                ));
            }
            let assignment = RiskAssignment {
                entity_type: entity_type.clone(),
                entity_id: entity_id.clone(),
                risk_domain_id: risk_domain_id.clone(),
            };
            let change = if matches!(command, RegistryEntityCommand::Assign { .. }) {
                RegistryChange::AssignRisk(assignment)
            } else {
                RegistryChange::UnassignRisk(assignment)
            };
            record_registry_change(cli, database, change)?;
        }
        RegistryEntityCommand::CheckIn {
            device_id,
            fingerprint_status,
        } => {
            if !matches!(kind, RegistryKind::Device) {
                return Err(AppError::Input(
                    "check-in is available only under device".to_owned(),
                ));
            }
            record_registry_change(
                cli,
                database,
                RegistryChange::DeviceCheckIn(DeviceCheckIn {
                    device_id: device_id.clone(),
                    fingerprint_status: fingerprint_status.clone(),
                }),
            )?;
        }
        RegistryEntityCommand::Mount {
            device_id,
            mount_id,
            mount_root_uri,
            status,
            fingerprint_status,
        } => {
            if !matches!(kind, RegistryKind::Device) {
                return Err(AppError::Input(
                    "mount is available only under device".to_owned(),
                ));
            }
            record_registry_change(
                cli,
                database,
                RegistryChange::DeviceMount(DeviceMount {
                    mount_id: mount_id.clone(),
                    device_id: device_id.clone(),
                    mount_root_uri: mount_root_uri.clone(),
                    status: status.clone(),
                    fingerprint_status: fingerprint_status.clone(),
                }),
            )?;
        }
    }
    Ok(EXIT_OK)
}

fn execute_registry_snapshot(
    cli: &Cli,
    database: &ProjectionDb,
    kind: RegistryKind,
    action: RegistryAction,
    snapshot: &str,
) -> Result<u8, AppError> {
    record_registry_change(
        cli,
        database,
        parse_registry_change(kind, action, snapshot)?,
    )?;
    Ok(EXIT_OK)
}

fn record_registry_change(
    cli: &Cli,
    database: &ProjectionDb,
    change: RegistryChange,
) -> Result<(), AppError> {
    let events = EventStore::open_or_create(
        &cli.events,
        EventStoreConfig {
            actor_id: cli.actor.clone(),
            host_id: cli.host.clone(),
            ..EventStoreConfig::default()
        },
    )?;
    let result = Registry::new(&events, database).record(change)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Recorded event {} at sequence {}; SQLite is current through {}.",
            result.event_id, result.event_seq, result.applied_event_seq
        );
    }
    Ok(())
}

fn build_registry_add(
    kind: RegistryKind,
    args: &RegistryAddArgs,
) -> Result<RegistryChange, AppError> {
    let name = required("--name", args.name.as_deref())?.to_owned();
    let kind_value = required("--kind", args.kind.as_deref())?.to_owned();
    let generated = |prefix: &str| {
        format!(
            "{prefix}_{}",
            ulid::Ulid::new().to_string().to_ascii_lowercase()
        )
    };
    Ok(match kind {
        RegistryKind::Site => RegistryChange::Site(
            RegistryAction::Register,
            SiteSnapshot {
                site_id: args.id.clone().unwrap_or_else(|| generated("site")),
                display_name: name,
                site_kind: kind_value,
                description: args.description.clone(),
                status: "active".to_owned(),
            },
        ),
        RegistryKind::Collection => RegistryChange::Collection(
            RegistryAction::Register,
            CollectionSnapshot {
                collection_id: args.id.clone().unwrap_or_else(|| generated("collection")),
                display_name: name,
                description: args.description.clone(),
                home_site_id: args.site.clone(),
                policy_id: args.policy.clone(),
                status: "active".to_owned(),
            },
        ),
        RegistryKind::Device => RegistryChange::Device(
            RegistryAction::Register,
            DeviceSnapshot {
                device_id: args.id.clone().unwrap_or_else(|| generated("device")),
                display_name: name,
                device_kind: kind_value,
                serial_hint: None,
                hardware_fingerprint: args.fingerprint.clone(),
                fingerprint_kind: args.fingerprint_kind.clone(),
                identity_state: if args.fingerprint.is_some() && args.fingerprint_kind.is_some() {
                    "confirmed"
                } else {
                    "unavailable"
                }
                .to_owned(),
                owner: None,
                status: "active".to_owned(),
                current_site_id: args.site.clone(),
                expected_availability: args.availability.clone(),
            },
        ),
        RegistryKind::Root => RegistryChange::ArchiveRoot(
            RegistryAction::Register,
            ArchiveRootSnapshot {
                archive_root_id: args.id.clone().unwrap_or_else(|| generated("root")),
                device_id: required("--device", args.device.as_deref())?.to_owned(),
                display_name: name,
                root_path_on_device: RegistryPath::utf8(required("--path", args.path.as_deref())?),
                status: "active".to_owned(),
            },
        ),
        RegistryKind::Location => {
            let (archive_root_id, relative_path, device_id, site_id) = if kind_value == "filesystem"
            {
                (
                    Some(required("--root", args.root.as_deref())?.to_owned()),
                    Some(RegistryPath::utf8(args.path.clone().unwrap_or_default())),
                    Some(required("--device", args.device.as_deref())?.to_owned()),
                    None,
                )
            } else if kind_value == "service" {
                (
                    None,
                    None,
                    None,
                    Some(required("--site", args.site.as_deref())?.to_owned()),
                )
            } else {
                return Err(AppError::Input(
                    "location --kind must be filesystem or service".to_owned(),
                ));
            };
            RegistryChange::Location(
                RegistryAction::Register,
                LocationSnapshot {
                    location_id: args.id.clone().unwrap_or_else(|| generated("location")),
                    display_name: name,
                    kind: kind_value,
                    archive_root_id,
                    relative_path,
                    device_id,
                    site_id,
                    encryption_state: Some(args.encryption.clone()),
                    trust_level: Some(args.trust.clone()),
                    expected_availability: args.availability.clone(),
                    is_writable: args.writable,
                    status: "active".to_owned(),
                },
            )
        }
        RegistryKind::RiskDomain => RegistryChange::RiskDomain(
            RegistryAction::Register,
            RiskDomainSnapshot {
                risk_domain_id: args.id.clone().unwrap_or_else(|| generated("risk")),
                display_name: name,
                risk_kind: kind_value,
                description: args.description.clone(),
                status: "active".to_owned(),
            },
        ),
        RegistryKind::Policy => {
            return Err(AppError::Input(
                "policy add requires a complete JSON snapshot with typed requirements".to_owned(),
            ));
        }
    })
}

fn required<'a>(flag: &str, value: Option<&'a str>) -> Result<&'a str, AppError> {
    value.ok_or_else(|| AppError::Input(format!("{flag} is required")))
}

fn registry_values(
    kind: RegistryKind,
    state: &archive_ledger::RegistryState,
) -> Result<Vec<serde_json::Value>, AppError> {
    let value = match kind {
        RegistryKind::Site => serde_json::to_value(&state.sites)?,
        RegistryKind::Collection => serde_json::to_value(&state.collections)?,
        RegistryKind::Device => serde_json::to_value(&state.devices)?,
        RegistryKind::Root => serde_json::to_value(&state.archive_roots)?,
        RegistryKind::Location => serde_json::to_value(&state.locations)?,
        RegistryKind::RiskDomain => serde_json::to_value(&state.risk_domains)?,
        RegistryKind::Policy => serde_json::to_value(&state.policies)?,
    };
    Ok(value.as_array().cloned().unwrap_or_default())
}

fn registry_id(value: &serde_json::Value) -> Option<&str> {
    [
        "site_id",
        "collection_id",
        "device_id",
        "archive_root_id",
        "location_id",
        "risk_domain_id",
        "policy_id",
    ]
    .into_iter()
    .find_map(|key| value[key].as_str())
}

fn print_registry_values(
    kind: RegistryKind,
    values: Vec<serde_json::Value>,
    as_json: bool,
) -> Result<(), AppError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"version": 1, "items": values}))?
        );
    } else {
        for value in values {
            println!(
                "{}  {}  {}",
                value["display_name"].as_str().unwrap_or("unnamed"),
                registry_id(&value).unwrap_or("unknown"),
                value["status"].as_str().unwrap_or("unknown")
            );
            match kind {
                RegistryKind::Site => println!(
                    "  kind: {}",
                    value["site_kind"].as_str().unwrap_or("unknown")
                ),
                RegistryKind::Collection => println!(
                    "  home site: {}  policy: {}",
                    value["home_site_id"].as_str().unwrap_or("unconfigured"),
                    value["policy_id"].as_str().unwrap_or("unconfigured")
                ),
                RegistryKind::Device => println!(
                    "  site: {}  identity: {}  availability: {}",
                    value["current_site_id"].as_str().unwrap_or("unknown"),
                    value["identity_state"].as_str().unwrap_or("unknown"),
                    value["expected_availability"].as_str().unwrap_or("unknown")
                ),
                RegistryKind::Root => println!(
                    "  device: {}  path: {}",
                    value["device_id"].as_str().unwrap_or("unknown"),
                    value["root_path_on_device"]["display"]
                        .as_str()
                        .unwrap_or("unknown")
                ),
                RegistryKind::Location => println!(
                    "  kind: {}  device/site: {} / {}  encryption/trust: {} / {}  availability: {}",
                    value["kind"].as_str().unwrap_or("unknown"),
                    value["device_id"].as_str().unwrap_or("service"),
                    value["site_id"].as_str().unwrap_or("inherited"),
                    value["encryption_state"].as_str().unwrap_or("unknown"),
                    value["trust_level"].as_str().unwrap_or("unknown"),
                    value["expected_availability"].as_str().unwrap_or("unknown")
                ),
                RegistryKind::RiskDomain => println!(
                    "  kind: {}",
                    value["risk_kind"].as_str().unwrap_or("unknown")
                ),
                RegistryKind::Policy => println!(
                    "  version: {}  enabled: {}",
                    value["policy_version"].as_u64().unwrap_or(0),
                    value["enabled"].as_bool().unwrap_or(false)
                ),
            }
        }
    }
    Ok(())
}

fn parse_registry_change(
    kind: RegistryKind,
    action: RegistryAction,
    snapshot: &str,
) -> Result<RegistryChange, AppError> {
    Ok(match kind {
        RegistryKind::Site => {
            RegistryChange::Site(action, parse_snapshot::<SiteSnapshot>(snapshot)?)
        }
        RegistryKind::Collection => {
            RegistryChange::Collection(action, parse_snapshot::<CollectionSnapshot>(snapshot)?)
        }
        RegistryKind::Device => {
            RegistryChange::Device(action, parse_snapshot::<DeviceSnapshot>(snapshot)?)
        }
        RegistryKind::Root => {
            RegistryChange::ArchiveRoot(action, parse_snapshot::<ArchiveRootSnapshot>(snapshot)?)
        }
        RegistryKind::Location => {
            RegistryChange::Location(action, parse_snapshot::<LocationSnapshot>(snapshot)?)
        }
        RegistryKind::RiskDomain => {
            RegistryChange::RiskDomain(action, parse_snapshot::<RiskDomainSnapshot>(snapshot)?)
        }
        RegistryKind::Policy => {
            RegistryChange::Policy(action, parse_snapshot::<PolicySnapshot>(snapshot)?)
        }
    })
}

fn parse_snapshot<T: serde::de::DeserializeOwned>(snapshot: &str) -> Result<T, AppError> {
    serde_json::from_str(snapshot)
        .map_err(|error| AppError::Input(format!("invalid registry snapshot JSON: {error}")))
}

fn execute_file(
    database: &ProjectionDb,
    command: &FileCommand,
    as_json: bool,
) -> Result<u8, AppError> {
    match command {
        FileCommand::Find(args) => {
            let page = database.find_files(FilePageRequest {
                filter: FileFilter {
                    collection_id: args.collection.clone(),
                    exact_path: args.exact.clone().map(utf8_path),
                    path_prefix: args.prefix.clone().map(utf8_path),
                    identity_state: args.identity_state.clone(),
                    ..FileFilter::default()
                },
                limit: args.limit,
                continuation: args.continuation.clone(),
            })?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                for file in &page.items {
                    println!(
                        "{}  [{}]  {} present / {} known copies  {}",
                        file.logical_path.display,
                        file.collection_name,
                        file.present_copy_count,
                        file.current_copy_count,
                        file.identity_state
                    );
                    println!(
                        "  file: {}  object: {}",
                        file.file_ref_id,
                        file.object_id.as_deref().unwrap_or("unresolved")
                    );
                }
                if let Some(next) = page.next {
                    println!("More results: rerun with --continue {next}");
                }
            }
        }
        FileCommand::Show { file_ref_id } => {
            let review = database.review_file(file_ref_id)?;
            let policy = database.review_file_policy(file_ref_id, now_utc_ms()?)?;
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"version": 1, "file_review": review, "policy_review": policy})
                    )?
                );
            } else {
                println!(
                    "{}  [{}]",
                    review.file.logical_path.display, review.file.collection_name
                );
                println!("  identity: {}", review.file.identity_state);
                println!(
                    "  object: {}",
                    review.file.object_id.as_deref().unwrap_or("unresolved")
                );
                if let (Some(namespace), Some(key)) =
                    (&review.external_namespace, &review.external_key)
                {
                    println!("  external identity: {namespace}:{key}");
                }
                if review.copies.is_empty() {
                    println!("  copies: none currently observed");
                }
                if let Some(policy) = &policy {
                    println!(
                        "  policy: {} ({} qualifying copies)",
                        policy.status,
                        policy.qualifying_copies.len()
                    );
                } else {
                    println!("  policy: uncertain — collection has no active policy/home site");
                }
                for copy in &review.copies {
                    let qualifies = policy.as_ref().is_some_and(|policy| {
                        policy
                            .qualifying_copies
                            .iter()
                            .any(|qualified| qualified.copy_claim_id == copy.copy_claim_id)
                    });
                    println!(
                        "  {} — {} — {} ({})",
                        copy.location_name,
                        copy.state,
                        if qualifies {
                            "qualifying"
                        } else {
                            "not qualifying"
                        },
                        copy.copy_claim_id
                    );
                    println!(
                        "    device/site: {} / {}",
                        copy.device_name.as_deref().unwrap_or("service"),
                        copy.site_name.as_deref().unwrap_or("unknown")
                    );
                    println!(
                        "    last seen: {}  verified: {} ({})",
                        optional_time(copy.last_seen_time_utc_ms),
                        optional_time(copy.last_verified_time_utc_ms),
                        copy.last_verification_result.as_deref().unwrap_or("never")
                    );
                    if !qualifies {
                        if let Some(reasons) = policy.as_ref().and_then(|policy| {
                            policy.reasons["nonqualifying_copies"]
                                .as_array()?
                                .iter()
                                .find(|entry| entry["copy_claim_id"] == copy.copy_claim_id)?
                                ["reasons"]
                                .as_array()
                        }) {
                            let reasons = reasons
                                .iter()
                                .filter_map(|reason| reason.as_str())
                                .collect::<Vec<_>>();
                            if !reasons.is_empty() {
                                println!("    does not qualify: {}", reasons.join(", "));
                            }
                        }
                    }
                }
                if let Some(policy) = &policy {
                    if let Some(actions) = policy.recommended_actions.as_array() {
                        for action in actions.iter().filter_map(|action| action.as_str()) {
                            println!("  Next: {action}");
                        }
                    }
                }
            }
        }
        FileCommand::History {
            file_ref_id,
            after_seq,
            limit,
        } => {
            let page = database.file_history(file_ref_id, *after_seq, *limit)?;
            if as_json {
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                for event in &page.items {
                    println!("{}  {}  {}", event.seq, event.event_type, event.time_utc_ms);
                }
                if let Some(next) = page.next_seq {
                    println!("More history: rerun with --after-seq {next}");
                }
            }
        }
    }
    Ok(EXIT_OK)
}

fn execute_policy_evaluation(database: &ProjectionDb, as_json: bool) -> Result<u8, AppError> {
    let evaluation = database.evaluate_policies(now_utc_ms()?)?;
    let has_findings = evaluation
        .evaluations
        .iter()
        .any(|policy| policy.files_violated > 0 || policy.files_uncertain > 0)
        || !evaluation.unconfigured_collections.is_empty();
    if as_json {
        println!("{}", serde_json::to_string_pretty(&evaluation)?);
    } else {
        print_evaluation(&evaluation);
        println!("Cached policy results updated.");
    }
    Ok(if has_findings { EXIT_FINDINGS } else { EXIT_OK })
}

fn execute_policy_report(
    database: &ProjectionDb,
    args: &ReportSummaryArgs,
    as_json: bool,
) -> Result<u8, AppError> {
    let status = filtered_cached_status(
        database,
        database.cached_policy_status(now_utc_ms()?)?,
        args.policy.as_deref(),
        args.collection.as_deref(),
    )?;
    let has_findings = cached_status_has_findings(&status);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&PolicyReportOutput {
                version: 1,
                policy: args.policy.clone(),
                collection: args.collection.clone(),
                rollup_scope: "whole_policy",
                status,
            })?
        );
    } else {
        print_cached_status(&status);
        if args.collection.is_some() {
            println!("Policy totals cover every active collection assigned to the shown policy.");
        }
    }
    Ok(if has_findings { EXIT_FINDINGS } else { EXIT_OK })
}

fn execute_cached_report(
    database: &ProjectionDb,
    args: &ReportArgs,
    as_json: bool,
) -> Result<u8, AppError> {
    let status = filtered_cached_status(
        database,
        database.cached_policy_status(now_utc_ms()?)?,
        args.policy.as_deref(),
        args.collection.as_deref(),
    )?;
    let filters = PolicyFindingFilter {
        policy_id: args.policy.clone(),
        collection_id: args.collection.clone(),
        status: args.result.clone(),
    };
    let findings = database.cached_policy_findings(
        &status,
        &filters,
        args.limit,
        args.continuation.as_deref(),
    )?;
    let has_findings = !findings.items.is_empty()
        || !status.unconfigured_collections.is_empty()
        || !status.stale_policies.is_empty();
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&RiskOutput {
                version: 1,
                filters,
                rollup_scope: "whole_policy",
                status,
                findings,
            })?
        );
    } else {
        print_cached_status(&status);
        if args.collection.is_some() {
            println!(
                "Policy totals cover the whole policy; the finding list is collection-filtered."
            );
        }
        print_finding_groups(&findings.items);
        if let Some(next) = &findings.next {
            println!("More findings: rerun with --continue {next}");
        }
    }
    Ok(if has_findings { EXIT_FINDINGS } else { EXIT_OK })
}

fn print_finding_groups(findings: &[PolicyFinding]) {
    let mut groups: BTreeMap<(String, String), Vec<&PolicyFinding>> = BTreeMap::new();
    for finding in findings {
        let mut causes = Vec::new();
        if let Some(failures) = finding.reasons["failed_requirements"].as_array() {
            causes.extend(failures.iter().filter_map(|failure| {
                failure["requirement"]
                    .as_str()
                    .map(|value| value.to_owned())
            }));
        }
        if let Some(scenarios) = finding.reasons["loss_scenarios"].as_array() {
            causes.extend(
                scenarios
                    .iter()
                    .filter(|scenario| scenario["permanent_loss"] == true)
                    .map(|scenario| {
                        format!(
                            "loss of {}",
                            scenario["domain_name"].as_str().unwrap_or("unknown domain")
                        )
                    }),
            );
        }
        if causes.is_empty() {
            causes.push("uncertain copy evidence".to_owned());
        }
        causes.sort();
        causes.dedup();
        for cause in causes {
            groups
                .entry((cause, finding.collection_name.clone()))
                .or_default()
                .push(finding);
        }
    }
    for ((cause, collection), affected) in groups {
        let known_bytes = affected
            .iter()
            .filter_map(|finding| finding.size_bytes)
            .sum::<u64>();
        let unknown_sizes = affected
            .iter()
            .filter(|finding| finding.size_bytes.is_none())
            .count();
        println!(
            "{} / {} — {} files on this page; {} known bytes; {} unknown sizes",
            collection,
            cause,
            affected.len(),
            known_bytes,
            unknown_sizes
        );
        for finding in affected {
            println!(
                "  {}  {} — {}",
                finding.status.to_ascii_uppercase(),
                finding.logical_path_display,
                summarize_finding(finding)
            );
            if let Some(actions) = finding.recommended_actions.as_array() {
                for action in actions.iter().filter_map(|action| action.as_str()) {
                    println!("    Next: {action}");
                }
            }
        }
    }
}

fn print_evaluation(evaluation: &PolicyEvaluationResult) {
    for collection in &evaluation.unconfigured_collections {
        println!(
            "UNCERTAIN  {} — {}. Next: {}",
            collection.display_name, collection.reason, collection.recommended_action
        );
    }
    for policy in &evaluation.evaluations {
        print_policy_rollup(policy);
    }
}

fn print_cached_status(status: &CachedPolicyStatus) {
    for collection in &status.unconfigured_collections {
        println!(
            "UNCERTAIN  {} — {}. Next: {}",
            collection.display_name, collection.reason, collection.recommended_action
        );
    }
    for policy in &status.stale_policies {
        println!(
            "UNKNOWN  policy {} — {}. Next: archive policy evaluate",
            policy.policy_id, policy.reason
        );
    }
    for policy in &status.evaluations {
        print_policy_rollup(policy);
    }
    if !cached_status_has_findings(status) {
        println!("No current preservation-policy findings.");
    }
}

fn print_policy_rollup(policy: &archive_ledger::PolicyEvaluation) {
    println!(
        "Policy {} v{}: {} safe, {} at risk, {} uncertain ({} files; {} known bytes at risk; {} files of unknown size)",
        policy.policy_id,
        policy.policy_version,
        policy.files_satisfied,
        policy.files_violated,
        policy.files_uncertain,
        policy.files_total,
        policy.bytes_known_at_risk,
        policy.files_size_unknown
    );
}

fn cached_status_has_findings(status: &CachedPolicyStatus) -> bool {
    !status.unconfigured_collections.is_empty()
        || !status.stale_policies.is_empty()
        || status
            .evaluations
            .iter()
            .any(|policy| policy.files_violated > 0 || policy.files_uncertain > 0)
}

fn filtered_cached_status(
    database: &ProjectionDb,
    mut status: CachedPolicyStatus,
    policy_id: Option<&str>,
    collection_id: Option<&str>,
) -> Result<CachedPolicyStatus, AppError> {
    let collection_policy = if let Some(collection_id) = collection_id {
        database
            .registry_state(true)?
            .collections
            .into_iter()
            .find(|collection| collection.collection_id == collection_id)
            .and_then(|collection| collection.policy_id)
    } else {
        None
    };
    let includes_policy = |candidate: &str| {
        policy_id.is_none_or(|policy_id| candidate == policy_id)
            && collection_id.is_none_or(|_| {
                collection_policy
                    .as_deref()
                    .is_some_and(|policy_id| candidate == policy_id)
            })
    };
    status
        .evaluations
        .retain(|evaluation| includes_policy(&evaluation.policy_id));
    status
        .stale_policies
        .retain(|policy| includes_policy(&policy.policy_id));
    if let Some(collection_id) = collection_id {
        status.unconfigured_collections.retain(|collection| {
            collection.collection_id == collection_id
                && policy_id.is_none_or(|policy_id| collection_policy.as_deref() == Some(policy_id))
        });
    } else if policy_id.is_some() {
        status.unconfigured_collections.clear();
    }
    Ok(status)
}

fn summarize_finding(finding: &PolicyFinding) -> String {
    let failures = finding.reasons["failed_requirements"]
        .as_array()
        .map_or(0, Vec::len);
    let permanent = finding.reasons["loss_scenarios"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|scenario| scenario["permanent_loss"] == true)
        .count();
    format!("{failures} policy failures; {permanent} permanent-loss scenarios")
}

fn optional_time(value: Option<u64>) -> String {
    value.map_or_else(|| "never".to_owned(), |value| value.to_string())
}

fn now_utc_ms() -> Result<u64, AppError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::Clock)?
        .as_millis();
    u64::try_from(millis).map_err(|_| AppError::Clock)
}
