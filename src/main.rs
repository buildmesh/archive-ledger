use std::collections::BTreeMap;
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use archive_ledger::{
    central_archive, utf8_path, AnnexImportConfig, AnnexImportError, AnnexImportStatus,
    AnnexImporter, ArchiveRootSnapshot, CachedPolicyStatus, CatalogError, CatalogRegistry,
    CollectionSnapshot, CopyFilter, CopyPageRequest, DeviceCheckIn, DeviceMount, DeviceSnapshot,
    EventReferences, EventRequest, EventStore, EventStoreConfig, EventStoreError, FileFilter,
    FilePageRequest, LocationScanner, LocationSnapshot, MetadataDestinationSnapshot, MetadataError,
    MetadataProtector, MetadataRegistry, PolicyError, PolicyEvaluationResult, PolicyFinding,
    PolicyFindingFilter, PolicyFindingPage, PolicyRequirements, PolicySnapshot, ProjectionConfig,
    ProjectionDb, ProjectionError, Registry, RegistryAction, RegistryChange, RegistryError,
    RegistryPath, ReviewError, RiskAssignment, RiskDomainSnapshot, ScanConfig, ScanError, ScanMode,
    ScanStatus, SiteSnapshot, StatusError, StorageDiscoveryError,
};
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 2;
const EXIT_FINDINGS: u8 = 10;

#[derive(Debug, Parser)]
#[command(name = "archive", version, about = "Review and protect local archives")]
struct Cli {
    /// Select a known Archive by name/ID, or an Archive directory by path.
    #[arg(long, global = true)]
    archive: Option<String>,

    /// Explicit SQLite path for an existing legacy/custom catalog (requires --events).
    #[arg(long, global = true)]
    database: Option<PathBuf>,

    /// Explicit event-store path for an existing legacy/custom catalog (requires --database).
    #[arg(long, global = true)]
    events: Option<PathBuf>,

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

impl Cli {
    fn database_path(&self) -> &Path {
        self.database
            .as_deref()
            .expect("catalog paths are resolved before use")
    }

    fn events_path(&self) -> &Path {
        self.events
            .as_deref()
            .expect("catalog paths are resolved before use")
    }
}

fn resolve_catalog_paths(cli: &mut Cli) -> Result<(), AppError> {
    match (&cli.database, &cli.events) {
        (Some(_), Some(_)) => {
            if cli.archive.is_some() {
                return Err(AppError::Input(
                    "--archive cannot be combined with --database/--events".to_owned(),
                ));
            }
            return Ok(());
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(AppError::Input(
                "--database and --events must be provided together".to_owned(),
            ));
        }
        (None, None) => {}
    }

    let environment_selector = std::env::var("ARCHIVE_LEDGER_ARCHIVE")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let selector = cli.archive.as_deref().or(environment_selector.as_deref());
    let selected = if let Some(selector) = selector.filter(|value| selector_is_path(value)) {
        let root = std::fs::canonicalize(selector).map_err(|error| {
            AppError::Input(format!(
                "cannot resolve Archive directory {selector}: {error}"
            ))
        })?;
        archive_ledger::KnownArchive {
            archive_id: String::new(),
            display_name: selector.to_owned(),
            root,
        }
    } else {
        CatalogRegistry::load()?.resolve(selector)?
    };
    cli.database = Some(selected.database_path());
    cli.events = Some(selected.events_path());
    Ok(())
}

fn selector_is_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        || value.starts_with('.')
        || value.contains(std::path::MAIN_SEPARATOR)
        || (std::path::MAIN_SEPARATOR != '/' && value.contains('/'))
}

fn inspect_archive_root(selector: &str) -> Result<archive_ledger::KnownArchive, AppError> {
    let root = std::fs::canonicalize(selector).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve Archive directory {selector}: {error}"
        ))
    })?;
    let database_path = root.join("archive.db");
    let events_path = root.join("canonical");
    if !events_path.is_dir() {
        return Err(AppError::Input(format!(
            "Archive directory {} has no canonical event store",
            root.display()
        )));
    }
    let status =
        ProjectionDb::open_existing(&database_path, ProjectionConfig::default())?.status()?;
    Ok(archive_ledger::KnownArchive {
        archive_id: status.archive_id,
        display_name: status.archive_display_name,
        root,
    })
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new named Archive catalog without inspecting the current directory.
    Init {
        /// Human-readable Archive name; prompted for on a terminal when omitted.
        #[arg(long)]
        name: Option<String>,
        /// Make this Archive the per-user default even if another default exists.
        #[arg(long)]
        make_default: bool,
        /// Stable archive ID; generated when omitted.
        #[arg(long)]
        archive_id: Option<String>,
        /// Prompt for a starter single-machine topology when attached to a terminal.
        #[arg(long, conflicts_with = "non_interactive", hide = true)]
        guided: bool,
        /// Never prompt; requires --name for a centrally stored Archive.
        #[arg(long)]
        non_interactive: bool,
        /// Create a starter site/device/root/location/collection/policy for this mounted path.
        #[arg(long, hide = true)]
        root_path: Option<PathBuf>,
        #[arg(long, default_value = "Home", hide = true)]
        site_name: String,
        #[arg(long, default_value = "Primary disk", hide = true)]
        device_name: String,
        #[arg(long, default_value = "Archive files", hide = true)]
        collection_name: String,
        #[arg(long, hide = true)]
        fingerprint: Option<String>,
        #[arg(long, hide = true)]
        fingerprint_kind: Option<String>,
    },
    /// Select the default Archive for later commands.
    Use { archive: String },
    /// Rename the selected Archive without changing its stable ID.
    Rename { new_name: String },
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
    /// Inventory regular files without modifying them.
    #[command(hide = true)]
    Scan(ScanArgs),
    /// Verify the bytes behind current copy claims.
    Verify(VerifyArgs),
    /// Import source-specific inventories.
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
    /// Map git-annex remote UUIDs to registered storage locations.
    AnnexRemote {
        #[command(subcommand)]
        command: AnnexRemoteCommand,
    },
    /// Inspect and resume local long-running work.
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    /// Manage sites through canonical full-snapshot events.
    Site {
        #[command(subcommand)]
        command: SiteCommand,
    },
    /// Manage collections through canonical full-snapshot events.
    Collection {
        #[command(subcommand)]
        command: CollectionCommand,
    },
    /// Manage devices through canonical full-snapshot events.
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Manage archive roots through canonical full-snapshot events.
    Root {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Manage storage locations through canonical full-snapshot events.
    Location {
        #[command(subcommand)]
        command: LocationCommand,
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
    /// Apply or rebuild the SQLite materialized view.
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    /// Check clean-machine restoration from a cloned event repository.
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
}

#[derive(Debug, Args, Clone)]
struct ScanArgs {
    /// Registered filesystem location to inventory.
    location: String,
    #[arg(long)]
    collection: String,
    /// Mounted path corresponding exactly to the registered location.
    #[arg(long)]
    path: PathBuf,
    #[arg(long)]
    device: String,
    #[arg(long)]
    root: String,
    #[arg(long)]
    logical_prefix: Option<PathBuf>,
    #[arg(long = "exclude")]
    exclusions: Vec<PathBuf>,
    #[arg(long, default_value = "unavailable")]
    fingerprint_status: String,
    #[arg(long)]
    job_id: Option<String>,
    #[arg(long)]
    scan_id: Option<String>,
    #[arg(long, default_value_t = 1_000)]
    batch_entries: usize,
    /// Stop cleanly after this many files; useful for testing resume.
    #[arg(long, hide = true)]
    max_items: Option<usize>,
}

#[derive(Debug, Args, Clone)]
struct VerifyArgs {
    /// Registered filesystem location whose current copies should be checked.
    location: String,
    /// Mounted path corresponding exactly to the registered location.
    #[arg(long)]
    path: PathBuf,
    /// Verify one claim instead of every current claim at the location.
    #[arg(long)]
    copy: Option<String>,
    #[arg(long, default_value = "unavailable")]
    fingerprint_status: String,
    #[arg(long)]
    job_id: Option<String>,
    #[arg(long, default_value_t = 500)]
    batch_entries: usize,
    /// Stop cleanly after this many claims; useful for testing resume.
    #[arg(long, hide = true)]
    max_items: Option<usize>,
}

#[derive(Debug, Subcommand)]
enum ImportCommand {
    /// Read a git-annex repository without changing it.
    Annex(AnnexArgs),
}

#[derive(Debug, Args, Clone)]
struct AnnexArgs {
    #[arg(default_value = ".")]
    repository: PathBuf,
    #[arg(long)]
    collection: String,
    #[arg(long)]
    worktree_location: String,
    #[arg(long)]
    cas_location: String,
    #[arg(long)]
    device: String,
    #[arg(long)]
    root: String,
    #[arg(long)]
    job_id: Option<String>,
    #[arg(long)]
    import_id: Option<String>,
    #[arg(long, default_value_t = 1_000)]
    batch_entries: usize,
    /// Stop cleanly after this many index entries; useful for testing resume.
    #[arg(long, hide = true)]
    max_items: Option<usize>,
}

#[derive(Debug, Subcommand)]
enum AnnexRemoteCommand {
    List {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        all: bool,
    },
    Map {
        source_annex_uuid: String,
        remote_annex_uuid: String,
        location_id: String,
        #[arg(long)]
        name: Option<String>,
    },
    Unmap {
        source_annex_uuid: String,
        remote_annex_uuid: String,
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum JobCommand {
    List {
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    Show {
        job_id: String,
    },
    Resume {
        job_id: String,
        #[arg(long, hide = true)]
        max_items: Option<usize>,
    },
}

#[derive(Debug, Subcommand)]
enum DbCommand {
    Apply,
    Rebuild {
        /// Rebuild to this path; defaults to safely replacing --database.
        #[arg(long)]
        target: Option<PathBuf>,
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
    /// Inspect a mounted path without registering or changing it.
    Discover { path: PathBuf },
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

#[derive(Debug, Subcommand)]
enum CollectionCommand {
    /// Create a Collection and its initial filesystem Location from cwd or --path.
    Init(CollectionInitArgs),
    /// Rename a Collection without changing its stable ID.
    Rename {
        collection: String,
        new_name: String,
    },
    /// Show a fast SQLite-only Collection summary; infer from cwd when omitted.
    Status { collection: Option<String> },
    /// List active Collections.
    List {
        #[arg(long)]
        all: bool,
    },
    /// Show one Collection by name or stable ID.
    Show { id: String },
    /// Add a Collection with friendly flags, or provide a complete JSON snapshot.
    Add(Box<RegistryAddArgs>),
    /// Replace user-controlled fields with a complete JSON snapshot.
    Update { snapshot: String },
    /// Retire a Collection with a complete JSON snapshot whose status is retired.
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct CollectionInitArgs {
    /// Directory containing the Collection; defaults to the current directory.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Human-readable Collection name; prompted for on a terminal when omitted.
    #[arg(long)]
    name: Option<String>,
    /// Existing Device ID/name, or a name for a new Device.
    #[arg(long)]
    device: Option<String>,
    /// Existing Site ID/name, or a name for a new Site.
    #[arg(long)]
    site: Option<String>,
    /// Override the default `<Collection> on <Device>` Location name.
    #[arg(long)]
    location_name: Option<String>,
    /// Override the mounted filesystem's display name.
    #[arg(long)]
    root_name: Option<String>,
    /// Permit registration when no stable filesystem or partition UUID is available.
    #[arg(long)]
    allow_unidentified_root: bool,
    /// Never prompt; requires every unresolved value as a flag.
    #[arg(long)]
    non_interactive: bool,
    /// Import this directory as a git-annex repository after setup.
    #[arg(long)]
    import_annex: bool,
    #[arg(long, default_value_t = 1_000)]
    batch_entries: usize,
    #[arg(long, requires = "import_annex")]
    job_id: Option<String>,
    #[arg(long, requires = "import_annex")]
    import_id: Option<String>,
}

#[derive(Debug, Subcommand)]
enum LocationCommand {
    /// Register this directory as another filesystem Location of a Collection.
    Init(LocationInitArgs),
    /// Import a git-annex repository as one partial Location of a Collection.
    ImportAnnex(LocationImportAnnexArgs),
    /// Rename a Location without changing its stable ID or path.
    Rename { location: String, new_name: String },
    /// Show a fast SQLite-only Location summary; infer from cwd when omitted.
    Status { location: Option<String> },
    /// Add present files to a Collection without marking unseen files missing.
    Add(LocationAddArgs),
    /// Completely reconcile a Location, including files that are now missing.
    Scan(LocationScanArgs),
    /// Inspect a mounted path without registering or changing it.
    Discover { path: PathBuf },
    /// List active Locations.
    List {
        #[arg(long)]
        all: bool,
    },
    /// Show one Location by name or stable ID.
    Show { id: String },
    /// Low-level compatibility command for registering a Location snapshot.
    #[command(hide = true)]
    Register(Box<RegistryAddArgs>),
    /// Replace user-controlled fields with a complete JSON snapshot.
    Update { snapshot: String },
    /// Retire a Location with a complete JSON snapshot whose status is retired.
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct LocationAddArgs {
    /// Directory to inventory; defaults to the current directory.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Location name or ID; inferred from the path when omitted.
    #[arg(long)]
    location: Option<String>,
    /// Collection name or ID; inferred from existing inventory when omitted.
    #[arg(long)]
    collection: Option<String>,
    #[arg(long = "exclude")]
    exclusions: Vec<PathBuf>,
    #[arg(long)]
    job_id: Option<String>,
    #[arg(long)]
    scan_id: Option<String>,
    #[arg(long, default_value_t = 1_000)]
    batch_entries: usize,
    #[arg(long, hide = true)]
    max_items: Option<usize>,
}

#[derive(Debug, Args)]
struct LocationScanArgs {
    /// Location name or ID; inferred from cwd when omitted.
    location: Option<String>,
    /// Mounted path corresponding exactly to the Location.
    #[arg(long)]
    path: Option<PathBuf>,
    /// Collection name or ID; inferred from existing inventory when omitted.
    #[arg(long)]
    collection: Option<String>,
    #[arg(long = "exclude")]
    exclusions: Vec<PathBuf>,
    #[arg(long)]
    job_id: Option<String>,
    #[arg(long)]
    scan_id: Option<String>,
    #[arg(long, default_value_t = 1_000)]
    batch_entries: usize,
    #[arg(long, hide = true)]
    max_items: Option<usize>,
}

#[derive(Debug, Args)]
struct LocationInitArgs {
    #[arg(default_value = ".")]
    path: PathBuf,
    #[arg(long)]
    collection: String,
    #[arg(long)]
    device: Option<String>,
    #[arg(long)]
    site: Option<String>,
    #[arg(long)]
    location_name: Option<String>,
    #[arg(long)]
    root_name: Option<String>,
    #[arg(long)]
    allow_unidentified_root: bool,
    #[arg(long)]
    non_interactive: bool,
}

#[derive(Debug, Subcommand)]
enum SiteCommand {
    List {
        #[arg(long)]
        all: bool,
    },
    Show {
        id: String,
    },
    Add(Box<RegistryAddArgs>),
    Rename {
        site: String,
        new_name: String,
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
enum DeviceCommand {
    Discover {
        path: PathBuf,
    },
    List {
        #[arg(long)]
        all: bool,
    },
    Show {
        id: String,
    },
    Add(Box<RegistryAddArgs>),
    Rename {
        device: String,
        new_name: String,
    },
    /// Record that a Device is now stored at another Site.
    Move {
        #[arg(
            value_name = "DEVICE",
            required_unless_present = "device_option",
            conflicts_with = "device_option"
        )]
        device_positional: Option<String>,
        #[arg(
            long = "device",
            value_name = "DEVICE",
            required_unless_present = "device_positional",
            conflicts_with = "device_positional"
        )]
        device_option: Option<String>,
        #[arg(long)]
        to: String,
    },
    Update {
        snapshot: String,
    },
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
    CheckIn {
        device_id: String,
        #[arg(long)]
        fingerprint_status: String,
    },
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
struct LocationImportAnnexArgs {
    /// git-annex repository; defaults to the current directory.
    #[arg(default_value = ".")]
    repository: PathBuf,
    /// Existing Collection name or stable ID.
    #[arg(long)]
    collection: String,
    /// Existing Device ID/name, or a name for a new Device.
    #[arg(long)]
    device: Option<String>,
    /// Existing Site ID/name, or a name for a new Site.
    #[arg(long)]
    site: Option<String>,
    #[arg(long)]
    location_name: Option<String>,
    #[arg(long)]
    root_name: Option<String>,
    #[arg(long)]
    allow_unidentified_root: bool,
    #[arg(long)]
    non_interactive: bool,
    #[arg(long, default_value_t = 1_000)]
    batch_entries: usize,
    #[arg(long)]
    job_id: Option<String>,
    #[arg(long)]
    import_id: Option<String>,
}

#[derive(Debug, Args, Clone)]
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
    Catalog(CatalogError),
    EventStore(EventStoreError),
    Projection(ProjectionError),
    Review(ReviewError),
    Policy(PolicyError),
    Registry(RegistryError),
    Metadata(MetadataError),
    Scan(ScanError),
    Annex(AnnexImportError),
    Storage(StorageDiscoveryError),
    Status(StatusError),
    Io(std::io::Error),
    Json(serde_json::Error),
    Clock,
    Input(String),
}

impl AppError {
    fn code(&self) -> &'static str {
        match self {
            Self::Catalog(error) => error.code(),
            Self::EventStore(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Review(error) => error.code(),
            Self::Policy(error) => error.code(),
            Self::Registry(error) => error.code(),
            Self::Metadata(error) => error.code(),
            Self::Scan(error) => error.code(),
            Self::Annex(error) => error.code(),
            Self::Storage(error) => error.code(),
            Self::Status(error) => error.code(),
            Self::Io(_) => "io_error",
            Self::Json(_) => "output_json",
            Self::Clock => "clock_invalid",
            Self::Input(_) => "invalid_input",
        }
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Catalog(error) => error.fmt(formatter),
            Self::EventStore(error) => error.fmt(formatter),
            Self::Projection(error) => error.fmt(formatter),
            Self::Review(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::Registry(error) => error.fmt(formatter),
            Self::Metadata(error) => error.fmt(formatter),
            Self::Scan(error) => error.fmt(formatter),
            Self::Annex(error) => error.fmt(formatter),
            Self::Storage(error) => error.fmt(formatter),
            Self::Status(error) => error.fmt(formatter),
            Self::Io(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
            Self::Clock => formatter.write_str("system clock is before the Unix epoch"),
            Self::Input(message) => formatter.write_str(message),
        }
    }
}

impl From<CatalogError> for AppError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
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

impl From<ScanError> for AppError {
    fn from(error: ScanError) -> Self {
        Self::Scan(error)
    }
}

impl From<AnnexImportError> for AppError {
    fn from(error: AnnexImportError) -> Self {
        Self::Annex(error)
    }
}

impl From<StorageDiscoveryError> for AppError {
    fn from(error: StorageDiscoveryError) -> Self {
        Self::Storage(error)
    }
}

impl From<StatusError> for AppError {
    fn from(error: StatusError) -> Self {
        Self::Status(error)
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
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
    archive_id: String,
    archive_name: String,
    policy: CachedPolicyStatus,
    metadata: archive_ledger::MetadataProtectionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalJob {
    job_id: String,
    job_type: String,
    status: String,
    created_time_utc_ms: u64,
    started_time_utc_ms: Option<u64>,
    finished_time_utc_ms: Option<u64>,
    params: serde_json::Value,
    progress: Option<serde_json::Value>,
    input_version: String,
}

#[derive(Debug)]
struct VerificationTarget {
    copy_claim_id: String,
    location_id: String,
    relative_path: Vec<u8>,
    path_encoding: String,
    path_display: String,
    object_id: Option<String>,
    external_identity_id: Option<String>,
    expected_hash_algo: Option<String>,
    expected_hash_hex: Option<String>,
    size_bytes: Option<u64>,
    file_ref_id: Option<String>,
    collection_id: Option<String>,
    logical_path: Option<Vec<u8>>,
    logical_path_encoding: Option<String>,
    logical_path_display: Option<String>,
    representation: Option<String>,
    modified_time_utc_ms: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VerificationSummary {
    attempted: u64,
    ok: u64,
    hash_mismatch: u64,
    read_error: u64,
    identity_mismatch: u64,
}

fn main() -> ExitCode {
    let json_requested = std::env::args().any(|argument| argument == "--json");
    let mut cli = match Cli::try_parse() {
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
    match execute(&mut cli) {
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

fn execute(cli: &mut Cli) -> Result<u8, AppError> {
    if let Command::Use { archive } = &cli.command {
        let mut registry = CatalogRegistry::load()?;
        let selected = if selector_is_path(archive) {
            let selected = inspect_archive_root(archive)?;
            registry.register(selected.clone(), true)?;
            selected
        } else {
            registry.set_default(archive)?
        };
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 1,
                    "archive_id": selected.archive_id,
                    "archive_name": selected.display_name,
                    "root": selected.root,
                    "default": true,
                }))?
            );
        } else {
            println!(
                "Default Archive is now {} ({}).",
                selected.display_name, selected.archive_id
            );
        }
        return Ok(EXIT_OK);
    }
    if let Command::Init {
        name,
        make_default,
        archive_id,
        guided,
        non_interactive,
        root_path,
        site_name,
        device_name,
        collection_name,
        fingerprint,
        fingerprint_kind,
    } = &cli.command
    {
        return execute_init(
            cli,
            name.as_deref(),
            *make_default,
            archive_id.as_deref(),
            *guided,
            *non_interactive,
            root_path.as_deref(),
            site_name,
            device_name,
            collection_name,
            fingerprint.as_deref(),
            fingerprint_kind.as_deref(),
        );
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
    resolve_catalog_paths(cli)?;
    if let Command::Events {
        command: EventsCommand::Verify,
    } = &cli.command
    {
        return execute_events_verify(cli);
    }
    if let Command::Db { command } = &cli.command {
        return execute_db(cli, command);
    }
    let database = ProjectionDb::open_existing(cli.database_path(), ProjectionConfig::default())?;
    match &cli.command {
        Command::Init { .. } => unreachable!("init returned before opening an existing database"),
        Command::Use { .. } => unreachable!("use returned before opening SQLite"),
        Command::Rename { new_name } => execute_archive_rename(cli, &database, new_name),
        Command::Status => execute_status(&database, cli.json),
        Command::File { command } => execute_file(&database, command, cli.json),
        Command::Object { command } => execute_object(&database, command, cli.json),
        Command::Copy { command } => execute_copy(&database, command, cli.json),
        Command::Scan(args) => execute_scan(cli, &database, args),
        Command::Verify(args) => execute_verify(cli, &database, args),
        Command::Import { command } => match command {
            ImportCommand::Annex(args) => execute_annex_import(cli, &database, args),
        },
        Command::AnnexRemote { command } => execute_annex_remote(cli, &database, command),
        Command::Job { command } => execute_job(cli, &database, command),
        Command::Site { command } => execute_site(cli, &database, command),
        Command::Collection { command } => execute_collection(cli, &database, command),
        Command::Device { command } => execute_device(cli, &database, command),
        Command::Root { command } => execute_registry(cli, &database, RegistryKind::Root, command),
        Command::Location { command } => execute_location(cli, &database, command),
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
        Command::Db { .. } => unreachable!("database command returned before opening SQLite"),
        Command::Restore { .. } => unreachable!("restore returned before opening SQLite"),
    }
}

fn execute_db(cli: &Cli, command: &DbCommand) -> Result<u8, AppError> {
    let events = open_event_store(cli)?;
    match command {
        DbCommand::Apply => {
            let database =
                ProjectionDb::open_existing(cli.database_path(), ProjectionConfig::default())?;
            let stats = database.apply(&events)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 1,
                        "events_applied": stats.events_applied,
                        "transactions": stats.transactions,
                        "caught_up": stats.caught_up,
                        "applied_event_seq": database.status()?.cursor.applied_seq,
                    }))?
                );
            } else {
                println!(
                    "Applied {} events in {} transactions; SQLite is current through sequence {}.",
                    stats.events_applied,
                    stats.transactions,
                    database.status()?.cursor.applied_seq
                );
            }
        }
        DbCommand::Rebuild { target } => {
            let current =
                ProjectionDb::open_existing(cli.database_path(), ProjectionConfig::default())?;
            let archive_id = current.status()?.archive_id;
            drop(current);
            let target = target.as_deref().unwrap_or_else(|| cli.database_path());
            let stats =
                ProjectionDb::rebuild(&events, target, &archive_id, ProjectionConfig::default())?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 1,
                        "database": target,
                        "archive_id": archive_id,
                        "events_applied": stats.events_applied,
                        "caught_up": stats.caught_up,
                    }))?
                );
            } else {
                println!(
                    "Rebuilt {} from {} canonical events.",
                    target.display(),
                    stats.events_applied
                );
            }
        }
    }
    Ok(EXIT_OK)
}

struct ScanExecutionArgs {
    location: String,
    collection: String,
    path: PathBuf,
    device: String,
    root: String,
    location_prefix: Option<PathBuf>,
    logical_prefix: Option<PathBuf>,
    exclusions: Vec<PathBuf>,
    fingerprint_status: String,
    job_id: Option<String>,
    scan_id: Option<String>,
    batch_entries: usize,
    max_items: Option<usize>,
    scan_mode: ScanMode,
}

fn execute_scan(cli: &Cli, database: &ProjectionDb, args: &ScanArgs) -> Result<u8, AppError> {
    execute_scan_run(
        cli,
        database,
        &ScanExecutionArgs {
            location: args.location.clone(),
            collection: args.collection.clone(),
            path: args.path.clone(),
            device: args.device.clone(),
            root: args.root.clone(),
            location_prefix: None,
            logical_prefix: args.logical_prefix.clone(),
            exclusions: args.exclusions.clone(),
            fingerprint_status: args.fingerprint_status.clone(),
            job_id: args.job_id.clone(),
            scan_id: args.scan_id.clone(),
            batch_entries: args.batch_entries,
            max_items: args.max_items,
            scan_mode: ScanMode::Complete,
        },
    )
}

fn execute_scan_run(
    cli: &Cli,
    database: &ProjectionDb,
    args: &ScanExecutionArgs,
) -> Result<u8, AppError> {
    let suffix = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{suffix}"));
    let scan_id = args
        .scan_id
        .clone()
        .unwrap_or_else(|| format!("scan_{suffix}"));
    let root_path = std::fs::canonicalize(&args.path).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve scan path {}: {error}",
            args.path.display()
        ))
    })?;
    let events = open_event_store(cli)?;
    let scanner = LocationScanner::new(
        &events,
        database,
        ScanConfig {
            root_path: root_path.clone(),
            scan_id: scan_id.clone(),
            job_id: job_id.clone(),
            collection_id: args.collection.clone(),
            location_id: args.location.clone(),
            device_id: args.device.clone(),
            archive_root_id: args.root.clone(),
            location_prefix: args.location_prefix.clone(),
            logical_prefix: args.logical_prefix.clone(),
            exclusions: args.exclusions.clone(),
            fingerprint_status: args.fingerprint_status.clone(),
            batch_entries: args.batch_entries,
            scan_mode: args.scan_mode,
        },
    )?;
    start_local_job(
        database,
        &job_id,
        "scan",
        &scan_id,
        &json!({
            "scan_id": scan_id,
            "scan_mode": args.scan_mode.as_str(),
            "root_path": root_path,
            "collection_id": args.collection,
            "location_id": args.location,
            "device_id": args.device,
            "archive_root_id": args.root,
            "location_prefix": args.location_prefix,
            "logical_prefix": args.logical_prefix,
            "exclusion_paths": args.exclusions,
            "fingerprint_status": args.fingerprint_status,
            "batch_entries": args.batch_entries,
        }),
    )?;
    record_job_marker(&events, database, &job_id, "scan", &scan_id, "started")?;
    if !cli.json {
        println!(
            "Starting {} {scan_id} ({job_id})...",
            args.scan_mode.as_str()
        );
    }
    let result = scanner.run_at_most(args.max_items)?;
    let status = match result.status {
        ScanStatus::Complete => "complete",
        ScanStatus::Partial => "partial",
        ScanStatus::Interrupted => "running",
        ScanStatus::Cancelled => "cancelled",
    };
    if status != "running" {
        record_job_marker(&events, database, &job_id, "scan", &scan_id, status)?;
    }
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "job_id": job_id,
                "scan_id": scan_id,
                "scan_mode": args.scan_mode.as_str(),
                "status": status,
                "summary": result.summary,
            }))?
        );
    } else {
        println!(
            "{} {scan_id} ({job_id}): {status}",
            if args.scan_mode == ScanMode::Add {
                "Add"
            } else {
                "Scan"
            }
        );
        println!(
            "  {} files, {} bytes; {} new, {} changed, {} unchanged, {} missing",
            result.summary.files_seen,
            result.summary.bytes_seen,
            result.summary.new_paths,
            result.summary.changed_paths,
            result.summary.unchanged_paths,
            result.summary.missing_paths
        );
        if status == "running" {
            println!("Resume with: archive job resume {job_id}");
        }
    }
    Ok(
        if matches!(result.status, ScanStatus::Partial)
            || result.summary.traversal_errors > 0
            || result.summary.content_read_errors > 0
            || result.summary.concurrent_changes > 0
        {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_location_inventory(
    cli: &Cli,
    database: &ProjectionDb,
    path: Option<&Path>,
    location_selector: Option<&str>,
    collection_selector: Option<&str>,
    exclusions: &[PathBuf],
    job_id: Option<&str>,
    scan_id: Option<&str>,
    batch_entries: usize,
    max_items: Option<usize>,
    scan_mode: ScanMode,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let mut scope = resolve_inventory_location(cli, database, &state, location_selector, path)?;
    if scan_mode == ScanMode::Complete && path.is_none() {
        scope.scan_path = scope.location_path.clone();
    }
    let collection = if let Some(selector) = collection_selector {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_collection_at_location(database, &state, &scope.location.location_id)?
    };
    let relative_prefix = scope
        .scan_path
        .strip_prefix(&scope.location_path)
        .map_err(|_| AppError::Input("inventory path is outside the selected Location".to_owned()))?
        .to_path_buf();
    if scan_mode == ScanMode::Complete && !relative_prefix.as_os_str().is_empty() {
        return Err(AppError::Input(
            "a complete Location scan must start at the Location root; omit --path or provide the registered Location path"
                .to_owned(),
        ));
    }
    let archive_root_id = scope
        .location
        .archive_root_id
        .clone()
        .ok_or_else(|| AppError::Input("filesystem Location has no Archive Root".to_owned()))?;
    let device_id = scope
        .location
        .device_id
        .clone()
        .ok_or_else(|| AppError::Input("filesystem Location has no Device".to_owned()))?;
    let prefix = (!relative_prefix.as_os_str().is_empty()).then_some(relative_prefix);
    execute_scan_run(
        cli,
        database,
        &ScanExecutionArgs {
            location: scope.location.location_id,
            collection: collection.collection_id,
            path: scope.scan_path,
            device: device_id,
            root: archive_root_id,
            location_prefix: prefix.clone(),
            logical_prefix: prefix,
            exclusions: exclusions.to_vec(),
            fingerprint_status: scope.fingerprint_status,
            job_id: job_id.map(ToOwned::to_owned),
            scan_id: scan_id.map(ToOwned::to_owned),
            batch_entries,
            max_items,
            scan_mode,
        },
    )
}

#[derive(Debug, Serialize)]
struct AnnexCommandResult {
    version: u32,
    job_id: String,
    import_id: String,
    status: String,
    annex_uuid: String,
    git_head_commit: String,
    summary: archive_ledger::AnnexSummary,
}

fn execute_annex_import(
    cli: &Cli,
    database: &ProjectionDb,
    args: &AnnexArgs,
) -> Result<u8, AppError> {
    let (exit_code, output) = run_annex_import(cli, database, args)?;
    print_annex_import(&output, cli.json)?;
    Ok(exit_code)
}

fn run_annex_import(
    cli: &Cli,
    database: &ProjectionDb,
    args: &AnnexArgs,
) -> Result<(u8, AnnexCommandResult), AppError> {
    let suffix = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{suffix}"));
    let import_id = args
        .import_id
        .clone()
        .unwrap_or_else(|| format!("import_{suffix}"));
    let repository = std::fs::canonicalize(&args.repository).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve annex repository {}: {error}",
            args.repository.display()
        ))
    })?;
    let events = open_event_store(cli)?;
    let importer = AnnexImporter::new(
        &events,
        database,
        AnnexImportConfig {
            repo_path: repository.clone(),
            import_id: import_id.clone(),
            job_id: job_id.clone(),
            collection_id: args.collection.clone(),
            worktree_location_id: args.worktree_location.clone(),
            cas_location_id: args.cas_location.clone(),
            device_id: args.device.clone(),
            archive_root_id: args.root.clone(),
            batch_entries: args.batch_entries,
        },
    )?;
    let params_value = json!({
        "repository": repository,
        "collection_id": args.collection,
        "worktree_location_id": args.worktree_location,
        "cas_location_id": args.cas_location,
        "device_id": args.device,
        "archive_root_id": args.root,
        "import_id": import_id,
        "batch_entries": args.batch_entries,
    });
    start_local_job(database, &job_id, "annex_import", &import_id, &params_value)?;
    record_job_marker(
        &events,
        database,
        &job_id,
        "annex_import",
        &import_id,
        "started",
    )?;
    let result = importer.run_at_most(args.max_items)?;
    let status = if result.status == AnnexImportStatus::Complete {
        "complete"
    } else {
        "running"
    };
    update_local_job(
        database,
        &job_id,
        status,
        &serde_json::to_value(&result.summary)?,
    )?;
    if status == "complete" {
        record_job_marker(
            &events,
            database,
            &job_id,
            "annex_import",
            &import_id,
            status,
        )?;
    }
    let exit_code = if result.summary.mismatched > 0 || result.summary.read_errors > 0 {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    };
    Ok((
        exit_code,
        AnnexCommandResult {
            version: 1,
            job_id,
            import_id,
            status: status.to_owned(),
            annex_uuid: result.annex_uuid,
            git_head_commit: result.git_head_commit,
            summary: result.summary,
        },
    ))
}

fn print_annex_import(output: &AnnexCommandResult, json_output: bool) -> Result<(), AppError> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(output)?);
    } else {
        println!(
            "Annex import {} ({}): {}",
            output.import_id, output.job_id, output.status
        );
        println!(
            "  {} entries; {} present, {} absent, {} unsupported, {} mismatched, {} read errors",
            output.summary.entries_seen,
            output.summary.present,
            output.summary.absent,
            output.summary.unsupported,
            output.summary.mismatched,
            output.summary.read_errors
        );
        if output.status == "running" {
            println!("Resume with: archive job resume {}", output.job_id);
        }
    }
    Ok(())
}

fn execute_annex_remote(
    cli: &Cli,
    database: &ProjectionDb,
    command: &AnnexRemoteCommand,
) -> Result<u8, AppError> {
    match command {
        AnnexRemoteCommand::List { source, all } => {
            let connection = cli_connection(database)?;
            let mut statement = connection
                .prepare(
                    "WITH known_remotes(source_annex_uuid, remote_annex_uuid, display_name, location_id) AS (
                         SELECT source_annex_uuid, remote_annex_uuid, display_name, location_id
                         FROM annex_remotes
                         UNION ALL
                         SELECT DISTINCT availability.source_repo_id, availability.source_remote_id,
                                NULL, NULL
                         FROM external_availability availability
                         WHERE NOT EXISTS (
                             SELECT 1 FROM annex_remotes mapped
                             WHERE mapped.source_annex_uuid = availability.source_repo_id
                               AND mapped.remote_annex_uuid = availability.source_remote_id
                         )
                     )
                     SELECT source_annex_uuid, remote_annex_uuid, display_name, location_id
                     FROM known_remotes
                     WHERE (?1 IS NULL OR source_annex_uuid = ?1)
                       AND (?2 OR location_id IS NOT NULL)
                     ORDER BY source_annex_uuid, remote_annex_uuid",
                )
                .map_err(|source| cli_sql_error(database, source))?;
            let items = statement
                .query_map(params![source, all], |row| {
                    Ok(json!({
                        "source_annex_uuid": row.get::<_, String>(0)?,
                        "remote_annex_uuid": row.get::<_, String>(1)?,
                        "display_name": row.get::<_, Option<String>>(2)?,
                        "location_id": row.get::<_, Option<String>>(3)?,
                    }))
                })
                .map_err(|source| cli_sql_error(database, source))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|source| cli_sql_error(database, source))?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"version": 1, "items": items}))?
                );
            } else if items.is_empty() {
                println!("No git-annex remote mappings.");
            } else {
                for item in items {
                    println!(
                        "{} / {}  {}  {}",
                        item["source_annex_uuid"].as_str().unwrap_or("unknown"),
                        item["remote_annex_uuid"].as_str().unwrap_or("unknown"),
                        item["display_name"].as_str().unwrap_or("unnamed"),
                        item["location_id"].as_str().unwrap_or("unmapped")
                    );
                }
            }
        }
        AnnexRemoteCommand::Map {
            source_annex_uuid,
            remote_annex_uuid,
            location_id,
            name,
        } => {
            record_annex_remote(
                cli,
                database,
                "annex_remote_mapped",
                json!({
                    "source_annex_uuid": source_annex_uuid,
                    "remote_annex_uuid": remote_annex_uuid,
                    "display_name": name,
                    "location_id": location_id,
                }),
                Some(location_id.clone()),
            )?;
        }
        AnnexRemoteCommand::Unmap {
            source_annex_uuid,
            remote_annex_uuid,
            name,
        } => {
            record_annex_remote(
                cli,
                database,
                "annex_remote_unmapped",
                json!({
                    "source_annex_uuid": source_annex_uuid,
                    "remote_annex_uuid": remote_annex_uuid,
                    "display_name": name,
                }),
                None,
            )?;
        }
    }
    Ok(EXIT_OK)
}

fn record_annex_remote(
    cli: &Cli,
    database: &ProjectionDb,
    event_type: &str,
    payload: serde_json::Value,
    location_id: Option<String>,
) -> Result<(), AppError> {
    for field in ["source_annex_uuid", "remote_annex_uuid"] {
        if payload[field].as_str().is_none_or(str::is_empty) {
            return Err(AppError::Input(format!("{field} must be non-empty")));
        }
    }
    if let Some(location_id) = &location_id {
        let valid: bool = cli_connection(database)?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM locations WHERE location_id = ?1 AND status = 'active')",
                [location_id],
                |row| row.get(0),
            )
            .map_err(|source| cli_sql_error(database, source))?;
        if !valid {
            return Err(AppError::Input(format!(
                "active location not found: {location_id}"
            )));
        }
    }
    let events = open_event_store(cli)?;
    let record = events.append(EventRequest::new(event_type, payload).with_references(
        EventReferences {
            location_id,
            ..EventReferences::default()
        },
    ))?;
    database.apply(&events)?;
    print_mutation_seq(
        record.envelope.seq,
        "Annex remote mapping recorded",
        cli.json,
    )
}

fn execute_job(cli: &Cli, database: &ProjectionDb, command: &JobCommand) -> Result<u8, AppError> {
    match command {
        JobCommand::List { limit } => {
            if *limit == 0 || *limit > 10_000 {
                return Err(AppError::Input(
                    "--limit must be between 1 and 10000".to_owned(),
                ));
            }
            let jobs = list_local_jobs(database, *limit)?;
            print_jobs(cli.json, &jobs)?;
        }
        JobCommand::Show { job_id } => {
            let job = local_job(database, job_id)?
                .ok_or_else(|| AppError::Input(format!("job not found: {job_id}")))?;
            print_jobs(cli.json, &[job])?;
        }
        JobCommand::Resume { job_id, max_items } => {
            let job = local_job(database, job_id)?
                .ok_or_else(|| AppError::Input(format!("job not found: {job_id}")))?;
            if job.status != "running" {
                return Err(AppError::Input(format!(
                    "job {job_id} is {}, not resumable",
                    job.status
                )));
            }
            match job.job_type.as_str() {
                "scan" => {
                    let params = &job.params;
                    let scan_mode = match params["scan_mode"].as_str().unwrap_or("complete") {
                        "add" => ScanMode::Add,
                        "complete" => ScanMode::Complete,
                        other => {
                            return Err(AppError::Input(format!(
                                "job {job_id} has invalid scan mode {other:?}"
                            )))
                        }
                    };
                    return execute_scan_run(
                        cli,
                        database,
                        &ScanExecutionArgs {
                            location: json_string(params, "location_id")?,
                            collection: json_string(params, "collection_id")?,
                            path: PathBuf::from(json_string(params, "root_path")?),
                            device: json_string(params, "device_id")?,
                            root: json_string(params, "archive_root_id")?,
                            location_prefix: params["location_prefix"].as_str().map(PathBuf::from),
                            logical_prefix: params["logical_prefix"].as_str().map(PathBuf::from),
                            exclusions: params["exclusion_paths"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|value| value.as_str().map(PathBuf::from))
                                .collect(),
                            fingerprint_status: params["fingerprint_status"]
                                .as_str()
                                .unwrap_or("match")
                                .to_owned(),
                            job_id: Some(job.job_id),
                            scan_id: Some(job.input_version),
                            batch_entries: params["batch_entries"].as_u64().unwrap_or(1_000)
                                as usize,
                            max_items: *max_items,
                            scan_mode,
                        },
                    );
                }
                "annex_import" => {
                    let params = &job.params;
                    return execute_annex_import(
                        cli,
                        database,
                        &AnnexArgs {
                            repository: PathBuf::from(json_string(params, "repository")?),
                            collection: json_string(params, "collection_id")?,
                            worktree_location: json_string(params, "worktree_location_id")?,
                            cas_location: json_string(params, "cas_location_id")?,
                            device: json_string(params, "device_id")?,
                            root: json_string(params, "archive_root_id")?,
                            job_id: Some(job.job_id),
                            import_id: Some(job.input_version),
                            batch_entries: params["batch_entries"].as_u64().unwrap_or(1_000)
                                as usize,
                            max_items: *max_items,
                        },
                    );
                }
                "verify" => {
                    let params = &job.params;
                    return execute_verify(
                        cli,
                        database,
                        &VerifyArgs {
                            location: json_string(params, "location_id")?,
                            path: PathBuf::from(json_string(params, "root_path")?),
                            copy: params["copy_claim_id"].as_str().map(str::to_owned),
                            fingerprint_status: params["fingerprint_status"]
                                .as_str()
                                .unwrap_or("match")
                                .to_owned(),
                            job_id: Some(job.job_id),
                            batch_entries: params["batch_entries"].as_u64().unwrap_or(500) as usize,
                            max_items: *max_items,
                        },
                    );
                }
                other => return Err(AppError::Input(format!("unsupported job type: {other}"))),
            }
        }
    }
    Ok(EXIT_OK)
}

fn print_jobs(as_json: bool, jobs: &[LocalJob]) -> Result<(), AppError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"version": 1, "items": jobs}))?
        );
    } else if jobs.is_empty() {
        println!("No jobs.");
    } else {
        for job in jobs {
            println!("{}  {}  {}", job.job_id, job.job_type, job.status);
            if job.status == "running" {
                println!("  Resume: archive job resume {}", job.job_id);
            }
        }
    }
    Ok(())
}

fn execute_verify(cli: &Cli, database: &ProjectionDb, args: &VerifyArgs) -> Result<u8, AppError> {
    if args.batch_entries == 0 {
        return Err(AppError::Input(
            "--batch-entries must be greater than zero".to_owned(),
        ));
    }
    if !matches!(
        args.fingerprint_status.as_str(),
        "match" | "unavailable" | "mismatch"
    ) {
        return Err(AppError::Input(
            "--fingerprint-status must be match, unavailable, or mismatch".to_owned(),
        ));
    }
    let root_path = std::fs::canonicalize(&args.path).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve verification path {}: {error}",
            args.path.display()
        ))
    })?;
    let location_valid: bool = cli_connection(database)?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM locations
                            WHERE location_id = ?1 AND kind = 'filesystem' AND status = 'active')",
            [&args.location],
            |row| row.get(0),
        )
        .map_err(|source| cli_sql_error(database, source))?;
    if !location_valid {
        return Err(AppError::Input(format!(
            "active filesystem location not found: {}",
            args.location
        )));
    }
    let suffix = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{suffix}"));
    let input_version = stable_id(
        "verify_input",
        &[
            args.location.as_bytes(),
            root_path.to_string_lossy().as_bytes(),
            args.copy.as_deref().unwrap_or("").as_bytes(),
        ],
    );
    let params_value = json!({
        "location_id": args.location,
        "root_path": root_path,
        "copy_claim_id": args.copy,
        "fingerprint_status": args.fingerprint_status,
        "batch_entries": args.batch_entries,
    });
    start_local_job(database, &job_id, "verify", &input_version, &params_value)?;
    let events = open_event_store(cli)?;
    record_job_marker(
        &events,
        database,
        &job_id,
        "verify",
        &input_version,
        "started",
    )?;
    if !cli.json {
        println!("Starting verification {job_id}...");
    }

    let mut summary: VerificationSummary = local_job(database, &job_id)?
        .and_then(|job| job.progress)
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    let mut after: Option<String> = None;
    let mut new_attempts = 0usize;
    let mut matched_target = false;
    let mut interrupted = false;
    loop {
        let targets = verification_targets(
            database,
            &args.location,
            args.copy.as_deref(),
            after.as_deref(),
            args.batch_entries,
        )?;
        if targets.is_empty() {
            break;
        }
        let mut pending = Vec::with_capacity(targets.len());
        for target in targets {
            matched_target = true;
            after = Some(target.copy_claim_id.clone());
            let operation_key = stable_id(
                "op",
                &[
                    job_id.as_bytes(),
                    input_version.as_bytes(),
                    target.copy_claim_id.as_bytes(),
                    b"verification",
                ],
            );
            if database.has_operation_key(&operation_key)? {
                continue;
            }
            if args.max_items.is_some_and(|limit| new_attempts >= limit) {
                interrupted = true;
                break;
            }
            let attempt = verify_target(&root_path, &target, &args.fingerprint_status)?;
            summary.attempted += 1;
            match attempt.result.as_str() {
                "ok" => summary.ok += 1,
                "hash_mismatch" => summary.hash_mismatch += 1,
                "read_error" => summary.read_error += 1,
                "identity_mismatch" => summary.identity_mismatch += 1,
                _ => unreachable!("verification result is internal"),
            }
            new_attempts += 1;
            let resolved_object_id = target.object_id.clone().or_else(|| {
                (attempt.result == "ok")
                    .then_some(attempt.blake3_hex.as_ref())
                    .flatten()
                    .map(|hash| format!("obj_blake3_{hash}"))
            });
            if target.object_id.is_none() && attempt.result == "ok" {
                let object_id = resolved_object_id
                    .as_ref()
                    .expect("successful verification has a BLAKE3 identity");
                let blake3_hex = attempt
                    .blake3_hex
                    .as_ref()
                    .expect("successful verification has a BLAKE3 hash");
                pending.push(
                    EventRequest::new(
                        "object_observed",
                        json!({
                            "object_id": object_id,
                            "canonical_hash_algo": "blake3",
                            "canonical_hash_hex": blake3_hex,
                            "size_bytes": attempt.bytes_read,
                            "operation_key": verify_operation_key(&job_id, &input_version, &target.copy_claim_id, "object"),
                            "job_type": "verify", "item_type": "object",
                            "item_key": object_id, "outcome_kind": "observed",
                        }),
                    )
                    .with_references(EventReferences {
                        job_id: Some(job_id.clone()),
                        object_id: Some(object_id.clone()),
                        ..EventReferences::default()
                    }),
                );
                if let (Some(algorithm), Some(observed)) =
                    (&target.expected_hash_algo, &attempt.observed_hash_hex)
                {
                    if algorithm != "blake3" {
                        pending.push(
                            EventRequest::new(
                                "object_hash_added",
                                json!({
                                    "object_id": object_id,
                                    "hash_algo": algorithm,
                                    "hash_hex": observed,
                                    "source": "verification",
                                    "operation_key": verify_operation_key(&job_id, &input_version, &target.copy_claim_id, "object_hash"),
                                    "job_type": "verify", "item_type": "object_hash",
                                    "item_key": target.copy_claim_id, "outcome_kind": "verified",
                                }),
                            )
                            .with_references(EventReferences {
                                job_id: Some(job_id.clone()),
                                object_id: Some(object_id.clone()),
                                copy_claim_id: Some(target.copy_claim_id.clone()),
                                ..EventReferences::default()
                            }),
                        );
                    }
                }
                if let Some(external_identity_id) = &target.external_identity_id {
                    pending.push(
                        EventRequest::new(
                            "external_identity_resolved",
                            json!({
                                "external_identity_id": external_identity_id,
                                "object_id": object_id,
                                "operation_key": verify_operation_key(&job_id, &input_version, &target.copy_claim_id, "external_identity"),
                                "job_type": "verify", "item_type": "external_identity",
                                "item_key": external_identity_id, "outcome_kind": "resolved",
                            }),
                        )
                        .with_references(EventReferences {
                            job_id: Some(job_id.clone()),
                            object_id: Some(object_id.clone()),
                            copy_claim_id: Some(target.copy_claim_id.clone()),
                            ..EventReferences::default()
                        }),
                    );
                }
                if let (
                    Some(file_ref_id),
                    Some(collection_id),
                    Some(logical_path),
                    Some(logical_encoding),
                    Some(logical_display),
                ) = (
                    &target.file_ref_id,
                    &target.collection_id,
                    &target.logical_path,
                    &target.logical_path_encoding,
                    &target.logical_path_display,
                ) {
                    pending.push(
                        EventRequest::new(
                            "file_ref_updated",
                            json!({
                                "file_ref_id": file_ref_id,
                                "collection_id": collection_id,
                                "logical_path": lossless_path_json(logical_encoding, logical_path, logical_display)?,
                                "object_id": object_id,
                                "external_identity_id": target.external_identity_id,
                                "identity_state": "resolved",
                                "path_state": "active",
                                "observed_size_bytes": attempt.bytes_read,
                                "operation_key": verify_operation_key(&job_id, &input_version, &target.copy_claim_id, "file_ref"),
                                "job_type": "verify", "item_type": "file_ref",
                                "item_key": file_ref_id, "outcome_kind": "resolved",
                            }),
                        )
                        .with_references(EventReferences {
                            job_id: Some(job_id.clone()),
                            object_id: Some(object_id.clone()),
                            file_ref_id: Some(file_ref_id.clone()),
                            copy_claim_id: Some(target.copy_claim_id.clone()),
                            ..EventReferences::default()
                        }),
                    );
                    pending.push(
                        EventRequest::new(
                            "path_observed",
                            json!({
                                "file_ref_id": file_ref_id,
                                "location_id": target.location_id,
                                "observed_path": lossless_path_json(&target.path_encoding, &target.relative_path, &target.path_display)?,
                                "representation": target.representation.as_deref().unwrap_or("ordinary_file"),
                                "object_id": object_id,
                                "external_identity_id": target.external_identity_id,
                                "state": "present",
                                "observed_size_bytes": attempt.bytes_read,
                                "modified_time_utc_ms": target.modified_time_utc_ms,
                                "operation_key": verify_operation_key(&job_id, &input_version, &target.copy_claim_id, "path"),
                                "job_type": "verify", "item_type": "path",
                                "item_key": file_ref_id, "outcome_kind": "present",
                            }),
                        )
                        .with_references(EventReferences {
                            job_id: Some(job_id.clone()),
                            object_id: Some(object_id.clone()),
                            file_ref_id: Some(file_ref_id.clone()),
                            copy_claim_id: Some(target.copy_claim_id.clone()),
                            location_id: Some(target.location_id.clone()),
                            ..EventReferences::default()
                        }),
                    );
                }
                pending.push(
                    EventRequest::new(
                        "copy_observed",
                        json!({
                            "copy_claim_id": target.copy_claim_id,
                            "location_id": target.location_id,
                            "relative_path": lossless_path_json(&target.path_encoding, &target.relative_path, &target.path_display)?,
                            "object_id": object_id,
                            "external_identity_id": target.external_identity_id,
                            "claim_basis": "observed_bytes",
                            "state": "present",
                            "operation_key": verify_operation_key(&job_id, &input_version, &target.copy_claim_id, "copy"),
                            "job_type": "verify", "item_type": "copy",
                            "item_key": target.copy_claim_id, "outcome_kind": "present",
                        }),
                    )
                    .with_references(EventReferences {
                        job_id: Some(job_id.clone()),
                        object_id: Some(object_id.clone()),
                        file_ref_id: target.file_ref_id.clone(),
                        copy_claim_id: Some(target.copy_claim_id.clone()),
                        location_id: Some(target.location_id.clone()),
                        ..EventReferences::default()
                    }),
                );
            }
            let expected_hash_algo = target
                .expected_hash_algo
                .clone()
                .or_else(|| resolved_object_id.as_ref().map(|_| "blake3".to_owned()));
            let expected_hash_hex = target
                .expected_hash_hex
                .clone()
                .or_else(|| attempt.blake3_hex.clone());
            pending.push(
                EventRequest::new(
                    "copy_verified",
                    json!({
                        "verification_id": stable_id("verify", &[job_id.as_bytes(), target.copy_claim_id.as_bytes()]),
                        "copy_claim_id": target.copy_claim_id,
                        "object_id": resolved_object_id,
                        "location_id": target.location_id,
                        "result": attempt.result,
                        "expected_hash_algo": expected_hash_algo,
                        "expected_hash_hex": expected_hash_hex,
                        "observed_hash_hex": attempt.observed_hash_hex,
                        "size_bytes": target.size_bytes.or(Some(attempt.bytes_read)),
                        "bytes_read": attempt.bytes_read,
                        "duration_ms": attempt.duration_ms,
                        "path_observed": lossless_path_json(
                            &target.path_encoding,
                            &target.relative_path,
                            &target.path_display,
                        )?,
                        "device_fingerprint_status": args.fingerprint_status,
                        "error_code": attempt.error_code,
                        "error_detail": attempt.error_detail,
                        "operation_key": operation_key,
                        "job_type": "verify",
                        "item_type": "copy",
                        "item_key": target.copy_claim_id,
                        "outcome_kind": attempt.result,
                    }),
                )
                .with_references(EventReferences {
                    job_id: Some(job_id.clone()),
                    object_id: resolved_object_id,
                    file_ref_id: target.file_ref_id,
                    copy_claim_id: Some(target.copy_claim_id),
                    location_id: Some(args.location.clone()),
                    ..EventReferences::default()
                }),
            );
        }
        if !pending.is_empty() {
            events.append_batch(pending)?;
            database.apply(&events)?;
        }
        update_local_job(
            database,
            &job_id,
            "running",
            &serde_json::to_value(&summary)?,
        )?;
        if interrupted {
            break;
        }
    }
    if args.copy.is_some() && !matched_target {
        return Err(AppError::Input(format!(
            "current verifiable copy not found at location {}: {}",
            args.location,
            args.copy.as_deref().unwrap_or_default()
        )));
    }
    let status = if interrupted { "running" } else { "complete" };
    update_local_job(database, &job_id, status, &serde_json::to_value(&summary)?)?;
    if !interrupted {
        record_job_marker(
            &events,
            database,
            &job_id,
            "verify",
            &input_version,
            "complete",
        )?;
    }
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "job_id": job_id,
                "status": status,
                "summary": summary,
            }))?
        );
    } else {
        println!("Verification {job_id}: {status}");
        println!(
            "  {} attempted; {} ok, {} mismatched, {} read errors, {} identity mismatches",
            summary.attempted,
            summary.ok,
            summary.hash_mismatch,
            summary.read_error,
            summary.identity_mismatch
        );
        if interrupted {
            println!("Resume with: archive job resume {job_id}");
        }
    }
    Ok(
        if summary.hash_mismatch > 0 || summary.read_error > 0 || summary.identity_mismatch > 0 {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

struct VerificationAttempt {
    result: String,
    blake3_hex: Option<String>,
    observed_hash_hex: Option<String>,
    bytes_read: u64,
    duration_ms: u64,
    error_code: Option<String>,
    error_detail: Option<String>,
}

fn verify_target(
    root: &Path,
    target: &VerificationTarget,
    fingerprint_status: &str,
) -> Result<VerificationAttempt, AppError> {
    let started = Instant::now();
    if fingerprint_status == "mismatch" {
        return Ok(VerificationAttempt {
            result: "identity_mismatch".to_owned(),
            blake3_hex: None,
            observed_hash_hex: None,
            bytes_read: 0,
            duration_ms: 0,
            error_code: Some("device_mismatch".to_owned()),
            error_detail: Some("device fingerprint did not match; bytes were not read".to_owned()),
        });
    }
    if target
        .expected_hash_algo
        .as_deref()
        .is_some_and(|algorithm| !matches!(algorithm, "blake3" | "sha256"))
    {
        return Ok(VerificationAttempt {
            result: "read_error".to_owned(),
            blake3_hex: None,
            observed_hash_hex: None,
            bytes_read: 0,
            duration_ms: 0,
            error_code: Some("unsupported_hash".to_owned()),
            error_detail: Some(format!(
                "unsupported canonical hash algorithm {}",
                target.expected_hash_algo.as_deref().unwrap_or("unknown")
            )),
        });
    }
    let relative = relative_path_from_bytes(&target.path_encoding, &target.relative_path)?;
    if relative.is_absolute()
        || relative.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(AppError::Input(format!(
            "copy {} contains an unsafe relative path",
            target.copy_claim_id
        )));
    }
    let path = root.join(relative);
    let before = match std::fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            return Ok(read_error_attempt(
                started,
                "not_regular_file",
                format!("{} is not a regular file", path.display()),
            ))
        }
        Err(error) => {
            return Ok(read_error_attempt(
                started,
                "content_read_error",
                format!("{}: {error}", path.display()),
            ))
        }
    };
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            return Ok(read_error_attempt(
                started,
                "content_read_error",
                format!("{}: {error}", path.display()),
            ))
        }
    };
    let mut hasher = blake3::Hasher::new();
    let mut sha256 = (target.expected_hash_algo.as_deref() == Some("sha256")).then(Sha256::new);
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut bytes_read = 0_u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                hasher.update(&buffer[..count]);
                if let Some(sha256) = &mut sha256 {
                    sha256.update(&buffer[..count]);
                }
                bytes_read = bytes_read.saturating_add(count as u64);
            }
            Err(error) => {
                return Ok(VerificationAttempt {
                    bytes_read,
                    ..read_error_attempt(
                        started,
                        "content_read_error",
                        format!("{}: {error}", path.display()),
                    )
                })
            }
        }
    }
    let after = std::fs::metadata(&path).ok();
    if after.as_ref().is_none_or(|after| {
        after.len() != before.len() || after.modified().ok() != before.modified().ok()
    }) {
        return Ok(VerificationAttempt {
            bytes_read,
            ..read_error_attempt(
                started,
                "content_changed_during_read",
                format!("{} changed while it was being verified", path.display()),
            )
        });
    }
    let blake3_hex = hasher.finalize().to_hex().to_string();
    let observed = match sha256 {
        Some(sha256) => format!("{:x}", sha256.finalize()),
        None => blake3_hex.clone(),
    };
    let hash_matches = target
        .expected_hash_hex
        .as_deref()
        .is_none_or(|expected| observed.eq_ignore_ascii_case(expected));
    let size_matches = target.size_bytes.is_none_or(|size| bytes_read == size);
    let matches = hash_matches && size_matches;
    Ok(VerificationAttempt {
        result: if matches { "ok" } else { "hash_mismatch" }.to_owned(),
        blake3_hex: Some(blake3_hex),
        observed_hash_hex: Some(observed),
        bytes_read,
        duration_ms: elapsed_ms(started),
        error_code: (!matches).then(|| "content_hash_mismatch".to_owned()),
        error_detail: (!matches)
            .then(|| "observed bytes do not match the recorded object".to_owned()),
    })
}

fn read_error_attempt(started: Instant, code: &str, detail: String) -> VerificationAttempt {
    VerificationAttempt {
        result: "read_error".to_owned(),
        blake3_hex: None,
        observed_hash_hex: None,
        bytes_read: 0,
        duration_ms: elapsed_ms(started),
        error_code: Some(code.to_owned()),
        error_detail: Some(detail),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn verification_targets(
    database: &ProjectionDb,
    location_id: &str,
    copy_claim_id: Option<&str>,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<VerificationTarget>, AppError> {
    let connection = cli_connection(database)?;
    let mut statement = connection
        .prepare(
            "SELECT c.copy_claim_id, c.location_id, c.relative_path_bytes,
                    c.relative_path_encoding, c.relative_path_display,
                    c.object_id, c.external_identity_id,
                    COALESCE(o.canonical_hash_algo, x.expected_hash_algo),
                    COALESCE(o.canonical_hash_hex, x.expected_hash_hex),
                    COALESCE(o.size_bytes, x.expected_size_bytes, f.observed_size_bytes),
                    f.file_ref_id, f.collection_id, f.logical_path_bytes,
                    f.logical_path_encoding, f.logical_path_display,
                    p.representation, p.modified_time_utc_ms
             FROM copy_claims c
             LEFT JOIN objects o ON o.object_id = c.object_id
             LEFT JOIN external_identities x ON x.external_identity_id = c.external_identity_id
             JOIN locations l ON l.location_id = c.location_id
             LEFT JOIN path_observations p
               ON p.location_id = c.location_id
              AND p.observed_path_encoding = c.relative_path_encoding
              AND p.observed_path_bytes = c.relative_path_bytes
              AND p.state = 'present'
             LEFT JOIN file_refs f ON f.file_ref_id = p.file_ref_id AND f.path_state = 'active'
             WHERE c.location_id = ?1
               AND l.kind = 'filesystem' AND l.status = 'active'
               AND c.state IN ('present', 'corrupt', 'unknown')
               AND (?2 IS NULL OR c.copy_claim_id = ?2)
               AND (?3 IS NULL OR c.copy_claim_id > ?3)
             ORDER BY c.copy_claim_id
             LIMIT ?4",
        )
        .map_err(|source| cli_sql_error(database, source))?;
    let rows = statement
        .query_map(
            params![
                location_id,
                copy_claim_id,
                after,
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |row| {
                let size: Option<i64> = row.get(9)?;
                Ok(VerificationTarget {
                    copy_claim_id: row.get(0)?,
                    location_id: row.get(1)?,
                    relative_path: row.get(2)?,
                    path_encoding: row.get(3)?,
                    path_display: row.get(4)?,
                    object_id: row.get(5)?,
                    external_identity_id: row.get(6)?,
                    expected_hash_algo: row.get(7)?,
                    expected_hash_hex: row.get(8)?,
                    size_bytes: size
                        .map(|size| {
                            u64::try_from(size)
                                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(9, size))
                        })
                        .transpose()?,
                    file_ref_id: row.get(10)?,
                    collection_id: row.get(11)?,
                    logical_path: row.get(12)?,
                    logical_path_encoding: row.get(13)?,
                    logical_path_display: row.get(14)?,
                    representation: row.get(15)?,
                    modified_time_utc_ms: row
                        .get::<_, Option<i64>>(16)?
                        .map(|time| {
                            u64::try_from(time)
                                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(16, time))
                        })
                        .transpose()?,
                })
            },
        )
        .map_err(|source| cli_sql_error(database, source))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| cli_sql_error(database, source))?;
    Ok(rows)
}

fn relative_path_from_bytes(encoding: &str, bytes: &[u8]) -> Result<PathBuf, AppError> {
    match encoding {
        "utf8" => Ok(PathBuf::from(std::str::from_utf8(bytes).map_err(
            |error| AppError::Input(format!("invalid UTF-8 path in SQLite: {error}")),
        )?)),
        #[cfg(unix)]
        "unix_bytes" => {
            use std::os::unix::ffi::OsStringExt;
            Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
        }
        other => Err(AppError::Input(format!(
            "path encoding {other} cannot be verified on this platform"
        ))),
    }
}

fn lossless_path_json(
    encoding: &str,
    bytes: &[u8],
    display: &str,
) -> Result<serde_json::Value, AppError> {
    match encoding {
        "utf8" => Ok(json!({
            "encoding": "utf8",
            "text": std::str::from_utf8(bytes).map_err(|error| AppError::Input(error.to_string()))?,
            "display": display,
        })),
        "unix_bytes" | "windows_utf16le" => Ok(json!({
            "encoding": encoding,
            "base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            "display": display,
        })),
        other => Err(AppError::Input(format!(
            "unsupported path encoding: {other}"
        ))),
    }
}

fn start_local_job(
    database: &ProjectionDb,
    job_id: &str,
    job_type: &str,
    input_version: &str,
    params_value: &serde_json::Value,
) -> Result<(), AppError> {
    let now = i64::try_from(now_utc_ms()?).map_err(|_| AppError::Clock)?;
    let params_text = serde_json::to_string(params_value)?;
    let connection = cli_connection(database)?;
    connection
        .execute(
            "INSERT INTO jobs(job_id, job_type, status, created_time_utc_ms,
                              started_time_utc_ms, params_json, input_version)
             VALUES (?1, ?2, 'running', ?4, ?4, ?5, ?3)
             ON CONFLICT(job_id) DO NOTHING",
            params![job_id, job_type, input_version, now, params_text],
        )
        .map_err(|source| cli_sql_error(database, source))?;
    let actual: (String, String) = connection
        .query_row(
            "SELECT job_type, input_version FROM jobs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|source| cli_sql_error(database, source))?;
    if actual != (job_type.to_owned(), input_version.to_owned()) {
        return Err(AppError::Input(format!(
            "job {job_id} belongs to {} input {}, not {job_type} input {input_version}",
            actual.0, actual.1
        )));
    }
    Ok(())
}

fn update_local_job(
    database: &ProjectionDb,
    job_id: &str,
    status: &str,
    progress: &serde_json::Value,
) -> Result<(), AppError> {
    let now = i64::try_from(now_utc_ms()?).map_err(|_| AppError::Clock)?;
    cli_connection(database)?
        .execute(
            "UPDATE jobs SET status = ?2, progress_json = ?3,
                 finished_time_utc_ms = CASE WHEN ?2 = 'running' THEN NULL ELSE ?4 END
             WHERE job_id = ?1",
            params![job_id, status, serde_json::to_string(progress)?, now],
        )
        .map_err(|source| cli_sql_error(database, source))?;
    Ok(())
}

fn record_job_marker(
    events: &EventStore,
    database: &ProjectionDb,
    job_id: &str,
    job_type: &str,
    input_version: &str,
    status: &str,
) -> Result<(), AppError> {
    let event_type = if status == "started" {
        "job_started"
    } else {
        "job_finished"
    };
    let operation_key = stable_id(
        "op",
        &[
            job_id.as_bytes(),
            input_version.as_bytes(),
            status.as_bytes(),
        ],
    );
    if !database.has_operation_key(&operation_key)? {
        events.append(
            EventRequest::new(
                event_type,
                json!({
                    "job_id": job_id,
                    "job_type": job_type,
                    "input_version": input_version,
                    "status": status,
                    "operation_key": operation_key,
                    "item_type": "job",
                    "item_key": job_id,
                    "outcome_kind": status,
                }),
            )
            .with_references(EventReferences {
                job_id: Some(job_id.to_owned()),
                ..EventReferences::default()
            }),
        )?;
        database.apply(events)?;
    }
    Ok(())
}

fn list_local_jobs(database: &ProjectionDb, limit: usize) -> Result<Vec<LocalJob>, AppError> {
    let connection = cli_connection(database)?;
    let mut statement = connection
        .prepare(
            "SELECT job_id, job_type, status, created_time_utc_ms, started_time_utc_ms,
                    finished_time_utc_ms, params_json, progress_json, input_version
             FROM jobs ORDER BY created_time_utc_ms DESC, job_id DESC LIMIT ?1",
        )
        .map_err(|source| cli_sql_error(database, source))?;
    let raw = statement
        .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|source| cli_sql_error(database, source))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| cli_sql_error(database, source))?;
    raw.into_iter()
        .map(|row| {
            Ok(LocalJob {
                job_id: row.0,
                job_type: row.1,
                status: row.2,
                created_time_utc_ms: nonnegative_time(row.3)?,
                started_time_utc_ms: row.4.map(nonnegative_time).transpose()?,
                finished_time_utc_ms: row.5.map(nonnegative_time).transpose()?,
                params: serde_json::from_str(&row.6)?,
                progress: row.7.as_deref().map(serde_json::from_str).transpose()?,
                input_version: row.8,
            })
        })
        .collect()
}

fn local_job(database: &ProjectionDb, job_id: &str) -> Result<Option<LocalJob>, AppError> {
    Ok(list_local_jobs(database, 10_000)?
        .into_iter()
        .find(|job| job.job_id == job_id))
}

fn nonnegative_time(value: i64) -> Result<u64, AppError> {
    u64::try_from(value)
        .map_err(|_| AppError::Input("SQLite contains a negative job time".to_owned()))
}

fn json_string(value: &serde_json::Value, key: &str) -> Result<String, AppError> {
    value[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| AppError::Input(format!("job parameters lack {key}")))
}

fn cli_connection(database: &ProjectionDb) -> Result<Connection, AppError> {
    let connection =
        Connection::open(database.path()).map_err(|source| cli_sql_error(database, source))?;
    connection
        .execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
        .map_err(|source| cli_sql_error(database, source))?;
    Ok(connection)
}

fn cli_sql_error(database: &ProjectionDb, source: rusqlite::Error) -> AppError {
    AppError::Projection(ProjectionError::Sqlite {
        path: database.path().to_path_buf(),
        source,
    })
}

fn stable_id(prefix: &str, pieces: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for piece in pieces {
        hasher.update(&(piece.len() as u64).to_le_bytes());
        hasher.update(piece);
    }
    format!("{prefix}_{}", &hasher.finalize().to_hex()[..32])
}

fn verify_operation_key(job_id: &str, input_version: &str, copy_id: &str, kind: &str) -> String {
    stable_id(
        "op",
        &[
            job_id.as_bytes(),
            input_version.as_bytes(),
            copy_id.as_bytes(),
            kind.as_bytes(),
        ],
    )
}

fn execute_status(database: &ProjectionDb, as_json: bool) -> Result<u8, AppError> {
    let projection = database.status()?;
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
                archive_id: projection.archive_id,
                archive_name: projection.archive_display_name,
                policy: status,
                metadata,
            })?
        );
    } else {
        println!(
            "Archive: {} ({})",
            projection.archive_display_name, projection.archive_id
        );
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
                    cli.events_path().display(),
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
    if !cli.events_path().is_dir() {
        return Err(AppError::Input(format!(
            "canonical event store not found at {}; refusing to create a replacement for an existing catalog (restore it or use init with empty targets)",
            cli.events_path().display()
        )));
    }
    Ok(EventStore::open_or_create(
        cli.events_path(),
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

fn execute_archive_rename(
    cli: &Cli,
    database: &ProjectionDb,
    new_name: &str,
) -> Result<u8, AppError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(AppError::Input("Archive name must not be empty".to_owned()));
    }
    let archive_id = database.status()?.archive_id;
    let events = open_event_store(cli)?;
    let record = events.append(EventRequest::new(
        "archive_updated",
        json!({"archive_id": archive_id, "display_name": new_name}),
    ))?;
    database.apply(&events)?;
    CatalogRegistry::load()?.rename(&archive_id, new_name)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "archive_id": archive_id,
                "archive_name": new_name,
                "event_seq": record.envelope.seq,
            }))?
        );
    } else {
        println!(
            "Renamed Archive to {new_name} at sequence {}.",
            record.envelope.seq
        );
    }
    Ok(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn execute_init(
    cli: &Cli,
    name: Option<&str>,
    make_default: bool,
    archive_id: Option<&str>,
    guided: bool,
    non_interactive: bool,
    root_path: Option<&Path>,
    site_name: &str,
    device_name: &str,
    collection_name: &str,
    fingerprint: Option<&str>,
    fingerprint_kind: Option<&str>,
) -> Result<u8, AppError> {
    if cli.archive.is_some() {
        return Err(AppError::Input(
            "--archive selects an existing catalog and cannot be used with init".to_owned(),
        ));
    }
    let explicit_paths = match (&cli.database, &cli.events) {
        (Some(database), Some(events)) => Some((database.clone(), events.clone())),
        (None, None) => None,
        _ => {
            return Err(AppError::Input(
                "--database and --events must be provided together".to_owned(),
            ))
        }
    };
    let central = explicit_paths.is_none();
    if central
        && (guided || root_path.is_some() || fingerprint.is_some() || fingerprint_kind.is_some())
    {
        return Err(AppError::Input(
            "archive init no longer creates file topology; run archive collection init from the content directory after initialization"
                .to_owned(),
        ));
    }
    let archive_id = archive_id
        .map(str::to_owned)
        .unwrap_or_else(|| format!("arc_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    let archive_name = match name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => name.to_owned(),
        None if central && !non_interactive && std::io::stdin().is_terminal() => {
            prompt_default("Archive name", "Personal Archive")?
        }
        None if central => {
            return Err(AppError::Input(
                "--name is required when archive init is non-interactive".to_owned(),
            ))
        }
        None => archive_id.clone(),
    };
    if archive_name.trim().is_empty() {
        return Err(AppError::Input("Archive name must not be empty".to_owned()));
    }
    let known_archive = central
        .then(|| central_archive(&archive_id, &archive_name))
        .transpose()?;
    let (database_path, events_path) = if let Some(paths) = explicit_paths {
        paths
    } else {
        let archive = known_archive
            .as_ref()
            .expect("central Archive paths were constructed");
        (archive.database_path(), archive.events_path())
    };
    if database_path.exists() || events_path.exists() {
        return Err(AppError::Input(
            "init target already exists; choose empty --database and --events paths".to_owned(),
        ));
    }
    let should_prompt = !central
        && (guided || (!non_interactive && root_path.is_none() && std::io::stdin().is_terminal()));
    let starter = if should_prompt {
        let default_root = std::env::current_dir()?.to_string_lossy().into_owned();
        let selected_root = prompt_default("Mounted archive path", &default_root)?;
        let selected_site = prompt_default("Home site name", site_name)?;
        let selected_device = prompt_default("Primary device name", device_name)?;
        let selected_collection = prompt_default("Collection name", collection_name)?;
        let selected_fingerprint =
            prompt_default("Stable device fingerprint (leave blank if unavailable)", "")?;
        let selected_kind = if selected_fingerprint.is_empty() {
            None
        } else {
            Some(prompt_default("Fingerprint kind", "filesystem_uuid")?)
        };
        Some((
            PathBuf::from(selected_root),
            selected_site,
            selected_device,
            selected_collection,
            (!selected_fingerprint.is_empty()).then_some(selected_fingerprint),
            selected_kind,
        ))
    } else {
        root_path.map(|path| {
            (
                path.to_path_buf(),
                site_name.to_owned(),
                device_name.to_owned(),
                collection_name.to_owned(),
                fingerprint.map(str::to_owned),
                fingerprint_kind.map(str::to_owned),
            )
        })
    };
    if starter
        .as_ref()
        .is_some_and(|starter| starter.4.is_some() != starter.5.is_some())
    {
        return Err(AppError::Input(
            "--fingerprint and --fingerprint-kind must be provided together".to_owned(),
        ));
    }
    let starter = starter
        .map(|mut starter| {
            starter.0 = std::fs::canonicalize(&starter.0).map_err(|error| {
                AppError::Input(format!(
                    "cannot resolve starter root {}: {error}",
                    starter.0.display()
                ))
            })?;
            Ok::<_, AppError>(starter)
        })
        .transpose()?;
    let events = EventStore::open_or_create(
        &events_path,
        EventStoreConfig {
            actor_id: cli.actor.clone(),
            host_id: cli.host.clone(),
            ..EventStoreConfig::default()
        },
    )?;
    archive_ledger::initialize_metadata_repository(events.root())?;
    let database =
        ProjectionDb::open_or_create(&database_path, &archive_id, ProjectionConfig::default())?;
    events.append(EventRequest::new(
        "archive_initialized",
        json!({"archive_id": archive_id, "display_name": archive_name}),
    ))?;
    database.apply(&events)?;
    let starter_ids = if let Some((
        mounted_path,
        site_name,
        device_name,
        collection_name,
        fingerprint,
        fingerprint_kind,
    )) = starter
    {
        let registry = Registry::new(&events, &database);
        registry.record(RegistryChange::Site(
            RegistryAction::Register,
            SiteSnapshot {
                site_id: "site_home".to_owned(),
                display_name: site_name,
                site_kind: "home".to_owned(),
                description: Some("Starter home site".to_owned()),
                status: "active".to_owned(),
            },
        ))?;
        registry.record(RegistryChange::Policy(
            RegistryAction::Register,
            PolicySnapshot {
                policy_id: "policy_starter".to_owned(),
                display_name: "Two copies at two sites".to_owned(),
                policy_version: 1,
                requirements: PolicyRequirements {
                    min_qualifying_copies: 2,
                    min_devices: 2,
                    min_sites: 2,
                    require_offsite_copy: true,
                    require_offline_copy: false,
                    require_encrypted_offsite: false,
                    max_verification_age_days: 365,
                    max_observation_age_days: 365,
                    max_device_checkin_age_days: 365,
                },
                enabled: true,
                status: "active".to_owned(),
            },
        ))?;
        registry.record(RegistryChange::Device(
            RegistryAction::Register,
            DeviceSnapshot {
                device_id: "device_primary".to_owned(),
                display_name: device_name,
                device_kind: "disk".to_owned(),
                serial_hint: None,
                hardware_fingerprint: fingerprint.clone(),
                fingerprint_kind: fingerprint_kind.clone(),
                identity_state: if fingerprint.is_some() {
                    "confirmed"
                } else {
                    "unavailable"
                }
                .to_owned(),
                owner: None,
                status: "active".to_owned(),
                current_site_id: Some("site_home".to_owned()),
                expected_availability: "online".to_owned(),
            },
        ))?;
        registry.record(RegistryChange::ArchiveRoot(
            RegistryAction::Register,
            ArchiveRootSnapshot {
                archive_root_id: "root_primary".to_owned(),
                device_id: "device_primary".to_owned(),
                display_name: mounted_path.display().to_string(),
                root_path_on_device: RegistryPath::utf8("/"),
                status: "active".to_owned(),
                filesystem_fingerprint: None,
                fingerprint_kind: None,
                identity_state: "unavailable".to_owned(),
            },
        ))?;
        registry.record(RegistryChange::Location(
            RegistryAction::Register,
            LocationSnapshot {
                location_id: "location_primary".to_owned(),
                display_name: "Primary archive location".to_owned(),
                kind: "filesystem".to_owned(),
                archive_root_id: Some("root_primary".to_owned()),
                relative_path: Some(RegistryPath::utf8("")),
                device_id: Some("device_primary".to_owned()),
                site_id: None,
                encryption_state: Some("unknown".to_owned()),
                trust_level: Some("trusted".to_owned()),
                expected_availability: "online".to_owned(),
                is_writable: false,
                status: "active".to_owned(),
            },
        ))?;
        registry.record(RegistryChange::Collection(
            RegistryAction::Register,
            CollectionSnapshot {
                collection_id: "collection_primary".to_owned(),
                display_name: collection_name,
                description: Some(format!("Files under {}", mounted_path.display())),
                home_site_id: Some("site_home".to_owned()),
                policy_id: Some("policy_starter".to_owned()),
                status: "active".to_owned(),
            },
        ))?;
        let catalog_location_id = std::fs::canonicalize(events.root())
            .ok()
            .filter(|event_root| event_root.starts_with(&mounted_path))
            .map(|_| "location_primary");
        if let Some(location_id) = catalog_location_id {
            MetadataRegistry::new(&events, &database).set_catalog_location(location_id)?;
        }
        Some(json!({
            "mounted_path": mounted_path,
            "site_id": "site_home",
            "device_id": "device_primary",
            "archive_root_id": "root_primary",
            "location_id": "location_primary",
            "collection_id": "collection_primary",
            "policy_id": "policy_starter",
            "catalog_location_id": catalog_location_id,
        }))
    } else {
        None
    };
    if let Some(known_archive) = known_archive {
        CatalogRegistry::load()?.register(known_archive, make_default)?;
    }
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "archive_id": archive_id,
                "archive_name": archive_name,
                "database": database_path,
                "events": events_path,
                "applied_event_seq": database.status()?.cursor.applied_seq,
                "starter": starter_ids,
            }))?
        );
    } else {
        println!("Initialized Archive {archive_name} ({archive_id})");
        println!("  database: {}", database_path.display());
        println!("  canonical events: {}", events_path.display());
        if starter_ids.is_some() {
            println!("Starter topology created. Next: archive scan location_primary --collection collection_primary --path <mounted-path> --device device_primary --root root_primary");
            if starter_ids
                .as_ref()
                .is_some_and(|starter| starter["catalog_location_id"].is_null())
            {
                println!("The event repository is outside that mounted path, so its catalog location was not guessed. Register its real storage location, then run archive catalog-location <location-id>.");
            }
            println!("Then register an independent offsite copy and a metadata destination.");
        } else {
            println!("Next: cd to your files and run archive collection init --name <name>.");
        }
    }
    Ok(EXIT_OK)
}

fn prompt_default(label: &str, default: &str) -> Result<String, AppError> {
    if default.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label} [{default}]: ");
    }
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();
    Ok(if input.is_empty() {
        default.to_owned()
    } else {
        input.to_owned()
    })
}

fn prompt_confirmation(label: &str) -> Result<bool, AppError> {
    print!("{label} [y/N]: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn execute_site(cli: &Cli, database: &ProjectionDb, command: &SiteCommand) -> Result<u8, AppError> {
    match command {
        SiteCommand::Rename { site, new_name } => {
            execute_registry_rename(cli, database, RegistryKind::Site, site, new_name)
        }
        SiteCommand::List { all } => execute_registry(
            cli,
            database,
            RegistryKind::Site,
            &RegistryEntityCommand::List { all: *all },
        ),
        SiteCommand::Show { id } => execute_registry(
            cli,
            database,
            RegistryKind::Site,
            &RegistryEntityCommand::Show { id: id.clone() },
        ),
        SiteCommand::Add(args) => execute_registry(
            cli,
            database,
            RegistryKind::Site,
            &RegistryEntityCommand::Add(args.clone()),
        ),
        SiteCommand::Update { snapshot } => execute_registry(
            cli,
            database,
            RegistryKind::Site,
            &RegistryEntityCommand::Update {
                snapshot: snapshot.clone(),
            },
        ),
        SiteCommand::Retire { snapshot, yes } => execute_registry(
            cli,
            database,
            RegistryKind::Site,
            &RegistryEntityCommand::Retire {
                snapshot: snapshot.clone(),
                yes: *yes,
            },
        ),
    }
}

fn execute_device(
    cli: &Cli,
    database: &ProjectionDb,
    command: &DeviceCommand,
) -> Result<u8, AppError> {
    match command {
        DeviceCommand::Rename { device, new_name } => {
            execute_registry_rename(cli, database, RegistryKind::Device, device, new_name)
        }
        DeviceCommand::Move {
            device_positional,
            device_option,
            to,
        } => execute_device_move(
            cli,
            database,
            device_positional
                .as_deref()
                .or(device_option.as_deref())
                .expect("clap requires one Device selector"),
            to,
        ),
        DeviceCommand::Discover { path } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::Discover { path: path.clone() },
        ),
        DeviceCommand::List { all } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::List { all: *all },
        ),
        DeviceCommand::Show { id } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::Show { id: id.clone() },
        ),
        DeviceCommand::Add(args) => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::Add(args.clone()),
        ),
        DeviceCommand::Update { snapshot } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::Update {
                snapshot: snapshot.clone(),
            },
        ),
        DeviceCommand::Retire { snapshot, yes } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::Retire {
                snapshot: snapshot.clone(),
                yes: *yes,
            },
        ),
        DeviceCommand::CheckIn {
            device_id,
            fingerprint_status,
        } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::CheckIn {
                device_id: device_id.clone(),
                fingerprint_status: fingerprint_status.clone(),
            },
        ),
        DeviceCommand::Mount {
            device_id,
            mount_id,
            mount_root_uri,
            status,
            fingerprint_status,
        } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::Mount {
                device_id: device_id.clone(),
                mount_id: mount_id.clone(),
                mount_root_uri: mount_root_uri.clone(),
                status: status.clone(),
                fingerprint_status: fingerprint_status.clone(),
            },
        ),
    }
}

fn execute_device_move(
    cli: &Cli,
    database: &ProjectionDb,
    device_selector: &str,
    site_selector: &str,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let mut device = select_device(&state.devices, device_selector)?
        .ok_or_else(|| AppError::Input(format!("Device not found: {device_selector:?}")))?;
    let site = select_site(&state.sites, site_selector)?
        .ok_or_else(|| AppError::Input(format!("Site not found: {site_selector:?}")))?;
    if device.current_site_id.as_deref() == Some(site.site_id.as_str()) {
        return Err(AppError::Input(format!(
            "Device {} is already at Site {}",
            device.display_name, site.display_name
        )));
    }
    device.current_site_id = Some(site.site_id.clone());
    record_registry_change(
        cli,
        database,
        RegistryChange::Device(RegistryAction::Move, device),
    )?;
    Ok(EXIT_OK)
}

fn execute_collection(
    cli: &Cli,
    database: &ProjectionDb,
    command: &CollectionCommand,
) -> Result<u8, AppError> {
    match command {
        CollectionCommand::Init(args) => execute_collection_init(cli, database, args),
        CollectionCommand::Rename {
            collection,
            new_name,
        } => execute_registry_rename(
            cli,
            database,
            RegistryKind::Collection,
            collection,
            new_name,
        ),
        CollectionCommand::Status { collection } => {
            execute_collection_status(cli, database, collection.as_deref())
        }
        CollectionCommand::List { all } => execute_registry(
            cli,
            database,
            RegistryKind::Collection,
            &RegistryEntityCommand::List { all: *all },
        ),
        CollectionCommand::Show { id } => execute_registry(
            cli,
            database,
            RegistryKind::Collection,
            &RegistryEntityCommand::Show { id: id.clone() },
        ),
        CollectionCommand::Add(args) => execute_registry(
            cli,
            database,
            RegistryKind::Collection,
            &RegistryEntityCommand::Add(args.clone()),
        ),
        CollectionCommand::Update { snapshot } => execute_registry(
            cli,
            database,
            RegistryKind::Collection,
            &RegistryEntityCommand::Update {
                snapshot: snapshot.clone(),
            },
        ),
        CollectionCommand::Retire { snapshot, yes } => execute_registry(
            cli,
            database,
            RegistryKind::Collection,
            &RegistryEntityCommand::Retire {
                snapshot: snapshot.clone(),
                yes: *yes,
            },
        ),
    }
}

fn execute_location(
    cli: &Cli,
    database: &ProjectionDb,
    command: &LocationCommand,
) -> Result<u8, AppError> {
    match command {
        LocationCommand::Init(args) => {
            let state = database.registry_state(false)?;
            let collection =
                select_collection(&state.collections, &args.collection)?.ok_or_else(|| {
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
                batch_entries: 1_000,
                job_id: None,
                import_id: None,
            };
            execute_filesystem_setup(
                cli,
                database,
                &setup,
                collection.display_name.clone(),
                Some(collection),
            )
        }
        LocationCommand::ImportAnnex(args) => {
            let state = database.registry_state(false)?;
            let collection =
                select_collection(&state.collections, &args.collection)?.ok_or_else(|| {
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
                batch_entries: args.batch_entries,
                job_id: args.job_id.clone(),
                import_id: args.import_id.clone(),
            };
            execute_filesystem_setup(
                cli,
                database,
                &setup,
                collection.display_name.clone(),
                Some(collection),
            )
        }
        LocationCommand::Rename { location, new_name } => {
            execute_registry_rename(cli, database, RegistryKind::Location, location, new_name)
        }
        LocationCommand::Status { location } => {
            execute_location_status(cli, database, location.as_deref())
        }
        LocationCommand::Add(args) => execute_location_inventory(
            cli,
            database,
            Some(&args.path),
            args.location.as_deref(),
            args.collection.as_deref(),
            &args.exclusions,
            args.job_id.as_deref(),
            args.scan_id.as_deref(),
            args.batch_entries,
            args.max_items,
            ScanMode::Add,
        ),
        LocationCommand::Scan(args) => execute_location_inventory(
            cli,
            database,
            args.path.as_deref(),
            args.location.as_deref(),
            args.collection.as_deref(),
            &args.exclusions,
            args.job_id.as_deref(),
            args.scan_id.as_deref(),
            args.batch_entries,
            args.max_items,
            ScanMode::Complete,
        ),
        LocationCommand::Discover { path } => execute_registry(
            cli,
            database,
            RegistryKind::Device,
            &RegistryEntityCommand::Discover { path: path.clone() },
        ),
        LocationCommand::List { all } => execute_registry(
            cli,
            database,
            RegistryKind::Location,
            &RegistryEntityCommand::List { all: *all },
        ),
        LocationCommand::Show { id } => execute_registry(
            cli,
            database,
            RegistryKind::Location,
            &RegistryEntityCommand::Show { id: id.clone() },
        ),
        LocationCommand::Register(args) => execute_registry(
            cli,
            database,
            RegistryKind::Location,
            &RegistryEntityCommand::Add(args.clone()),
        ),
        LocationCommand::Update { snapshot } => execute_registry(
            cli,
            database,
            RegistryKind::Location,
            &RegistryEntityCommand::Update {
                snapshot: snapshot.clone(),
            },
        ),
        LocationCommand::Retire { snapshot, yes } => execute_registry(
            cli,
            database,
            RegistryKind::Location,
            &RegistryEntityCommand::Retire {
                snapshot: snapshot.clone(),
                yes: *yes,
            },
        ),
    }
}

fn execute_registry_rename(
    cli: &Cli,
    database: &ProjectionDb,
    kind: RegistryKind,
    selector: &str,
    new_name: &str,
) -> Result<u8, AppError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(AppError::Input("new name must be non-empty".to_owned()));
    }
    let state = database.registry_state(false)?;
    let change = match kind {
        RegistryKind::Site => {
            let mut value = select_site(&state.sites, selector)?
                .ok_or_else(|| AppError::Input(format!("Site not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .sites
                    .iter()
                    .map(|site| (&site.site_id, &site.display_name)),
                &value.site_id,
                new_name,
                "Site",
            )?;
            if value.display_name == new_name {
                return Err(AppError::Input("Site already has that name".to_owned()));
            }
            value.display_name = new_name.to_owned();
            RegistryChange::Site(RegistryAction::Update, value)
        }
        RegistryKind::Collection => {
            let mut value = select_collection(&state.collections, selector)?
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .collections
                    .iter()
                    .map(|collection| (&collection.collection_id, &collection.display_name)),
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
            RegistryChange::Collection(RegistryAction::Update, value)
        }
        RegistryKind::Device => {
            let mut value = select_device(&state.devices, selector)?
                .ok_or_else(|| AppError::Input(format!("Device not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .devices
                    .iter()
                    .map(|device| (&device.device_id, &device.display_name)),
                &value.device_id,
                new_name,
                "Device",
            )?;
            if value.display_name == new_name {
                return Err(AppError::Input("Device already has that name".to_owned()));
            }
            value.display_name = new_name.to_owned();
            RegistryChange::Device(RegistryAction::Update, value)
        }
        RegistryKind::Location => {
            let mut value = select_location(&state.locations, selector)?
                .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?;
            ensure_unique_display_name(
                state
                    .locations
                    .iter()
                    .map(|location| (&location.location_id, &location.display_name)),
                &value.location_id,
                new_name,
                "Location",
            )?;
            if value.display_name == new_name {
                return Err(AppError::Input("Location already has that name".to_owned()));
            }
            value.display_name = new_name.to_owned();
            RegistryChange::Location(RegistryAction::Update, value)
        }
        _ => {
            return Err(AppError::Input(
                "rename is not available for this registry type".to_owned(),
            ))
        }
    };
    record_registry_change(cli, database, change)?;
    Ok(EXIT_OK)
}

fn ensure_unique_display_name<'a>(
    mut values: impl Iterator<Item = (&'a String, &'a String)>,
    current_id: &str,
    new_name: &str,
    kind: &str,
) -> Result<(), AppError> {
    if values.any(|(id, name)| id != current_id && name == new_name) {
        return Err(AppError::Input(format!(
            "an active {kind} named {new_name:?} already exists"
        )));
    }
    Ok(())
}

fn execute_collection_status(
    cli: &Cli,
    database: &ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let collection = if let Some(selector) = selector {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        let location = infer_cwd_location(cli, database, &state)?;
        infer_collection_at_location(database, &state, &location.location_id)?
    };
    let summary = database.collection_summary(&collection.collection_id)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "Collection: {} ({})",
            summary.collection_name, summary.collection_id
        );
        println!(
            "  {} files, {} bytes logical; {} unique objects, {} bytes",
            summary.file_count,
            summary.logical_bytes,
            summary.unique_object_count,
            summary.unique_object_bytes
        );
        println!(
            "  {} Locations; {} unresolved identities; {} files with unknown size",
            summary.location_count,
            summary.unresolved_identity_count,
            summary.files_with_unknown_size
        );
        match (summary.violated_files, summary.uncertain_files) {
            (Some(violated), Some(uncertain)) => {
                println!("  current risk: {violated} violated, {uncertain} uncertain");
            }
            _ => println!("  current risk: not evaluated for the latest catalog state"),
        }
    }
    Ok(EXIT_OK)
}

fn execute_location_status(
    cli: &Cli,
    database: &ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let location = if let Some(selector) = selector {
        select_location(&state.locations, selector)?
            .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?
    } else {
        infer_cwd_location(cli, database, &state)?
    };
    let summary = database.location_summary(&location.location_id)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!(
            "Location: {} ({})",
            summary.location_name, summary.location_id
        );
        if let Some(device_name) = &summary.device_name {
            println!(
                "  Device: {}{}",
                device_name,
                summary
                    .site_name
                    .as_ref()
                    .map(|site| format!(" at {site}"))
                    .unwrap_or_default()
            );
        }
        println!("  {} logical file paths", summary.logical_file_count);
        println!(
            "  present: {} ({} bytes); missing: {} ({} bytes)",
            summary.present_count,
            summary.present_bytes,
            summary.missing_count,
            summary.missing_bytes
        );
        println!(
            "  corrupt: {} ({} bytes); unknown: {} ({} bytes)",
            summary.corrupt_count,
            summary.corrupt_bytes,
            summary.unknown_count,
            summary.unknown_bytes
        );
        println!(
            "  unresolved identities: {} present, {} missing",
            summary.unresolved_present_count, summary.unresolved_missing_count
        );
        println!(
            "  last complete inventory: {}; last verification: {}",
            status_optional_time(summary.last_complete_inventory_utc_ms),
            status_optional_time(summary.last_verification_utc_ms)
        );
    }
    Ok(EXIT_OK)
}

fn status_optional_time(value: Option<u64>) -> String {
    value
        .map(|value| format!("{value} UTC ms"))
        .unwrap_or_else(|| "never".to_owned())
}

fn infer_cwd_location(
    cli: &Cli,
    database: &ProjectionDb,
    state: &archive_ledger::RegistryState,
) -> Result<LocationSnapshot, AppError> {
    let cwd = std::fs::canonicalize(std::env::current_dir()?)?;
    infer_location_for_path(cli, database, state, &cwd).map(|scope| scope.location)
}

struct InventoryLocationScope {
    location: LocationSnapshot,
    location_path: PathBuf,
    scan_path: PathBuf,
    fingerprint_status: String,
}

fn resolve_inventory_location(
    cli: &Cli,
    database: &ProjectionDb,
    state: &archive_ledger::RegistryState,
    selector: Option<&str>,
    path: Option<&Path>,
) -> Result<InventoryLocationScope, AppError> {
    let scan_path = path
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(|error| AppError::Input(format!("cannot resolve inventory path: {error}")))?;
    if let Some(selector) = selector {
        let location = select_location(&state.locations, selector)?
            .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?;
        if location.kind != "filesystem" {
            return Err(AppError::Input(format!(
                "Location {} is not a filesystem Location",
                location.display_name
            )));
        }
        let hint = scan_path
            .clone()
            .unwrap_or(std::fs::canonicalize(std::env::current_dir()?)?);
        if let Ok(scope) = scope_for_location_at_path(cli, database, state, &location, &hint) {
            return Ok(InventoryLocationScope {
                scan_path: scan_path.unwrap_or(scope.location_path.clone()),
                ..scope
            });
        }
        if path.is_some() {
            return scope_for_location_at_path(cli, database, state, &location, &hint);
        }
        let mount_root = latest_observed_mount(database, &cli.host, &location)?;
        let relative = location
            .relative_path
            .as_ref()
            .ok_or_else(|| AppError::Input("filesystem Location has no relative path".to_owned()))?
            .to_path_buf()
            .ok_or_else(|| {
                AppError::Input("Location path cannot be represented on this platform".to_owned())
            })?;
        let location_path = std::fs::canonicalize(mount_root.join(relative)).map_err(|error| {
            AppError::Input(format!(
                "the last observed mount for {} is not available: {error}; mount the Device or use --path",
                location.display_name
            ))
        })?;
        return scope_for_location_at_path(cli, database, state, &location, &location_path);
    }

    let scan_path = scan_path.unwrap_or(std::fs::canonicalize(std::env::current_dir()?)?);
    infer_location_for_path(cli, database, state, &scan_path)
}

fn infer_location_for_path(
    cli: &Cli,
    database: &ProjectionDb,
    state: &archive_ledger::RegistryState,
    path: &Path,
) -> Result<InventoryLocationScope, AppError> {
    let root_mounts = active_root_mounts(cli, database, state, path)?;
    let mut matches = state
        .locations
        .iter()
        .filter_map(|location| {
            let root_id = location.archive_root_id.as_deref()?;
            let (mount_root, fingerprint_status) = root_mounts.get(root_id)?;
            let relative = location.relative_path.as_ref()?.to_path_buf()?;
            let location_path = mount_root.join(relative);
            path.starts_with(&location_path).then(|| {
                (
                    location_path.components().count(),
                    location.location_id.clone(),
                    location.clone(),
                    location_path,
                    fingerprint_status.clone(),
                )
            })
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let Some(best) = matches.first() else {
        return Err(AppError::Input(
            "path is not inside a known mounted Location; specify a Location".to_owned(),
        ));
    };
    if matches.get(1).is_some_and(|other| other.0 == best.0) {
        return Err(AppError::Input(
            "path matches multiple Locations equally; specify a Location by name or ID".to_owned(),
        ));
    }
    Ok(InventoryLocationScope {
        location: best.2.clone(),
        location_path: best.3.clone(),
        scan_path: path.to_path_buf(),
        fingerprint_status: best.4.clone(),
    })
}

fn active_root_mounts(
    cli: &Cli,
    database: &ProjectionDb,
    state: &archive_ledger::RegistryState,
    path: &Path,
) -> Result<BTreeMap<String, (PathBuf, String)>, AppError> {
    let mounted = archive_ledger::discover_mounted_filesystem(path)?;
    let mut root_mounts = BTreeMap::new();
    if let (Some(kind), Some(fingerprint)) = (
        mounted.fingerprint_kind.as_deref(),
        mounted.filesystem_fingerprint.as_deref(),
    ) {
        let matching = state
            .archive_roots
            .iter()
            .filter(|root| {
                root.status == "active"
                    && root.identity_state == "confirmed"
                    && root.fingerprint_kind.as_deref() == Some(kind)
                    && root.filesystem_fingerprint.as_deref() == Some(fingerprint)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(AppError::Input(
                "filesystem identity does not uniquely match an active Archive Root; specify and check the Device"
                    .to_owned(),
            ));
        }
        root_mounts.insert(
            matching[0].archive_root_id.clone(),
            (mounted.mount_root, "match".to_owned()),
        );
        return Ok(root_mounts);
    }

    let connection =
        Connection::open(database.path()).map_err(|source| status_sql(database, source))?;
    let mut statement = connection
        .prepare(
            "SELECT archive_root_id, mount_root_uri
             FROM device_mounts
             WHERE host_id = ?1 AND status = 'mounted' AND archive_root_id IS NOT NULL
             ORDER BY observed_time_utc_ms DESC, mount_id DESC",
        )
        .map_err(|source| status_sql(database, source))?;
    let observations = statement
        .query_map([&cli.host], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|source| status_sql(database, source))?;
    for observation in observations {
        let (root_id, mount_root) = observation.map_err(|source| status_sql(database, source))?;
        let root_is_unidentified = state.archive_roots.iter().any(|root| {
            root.archive_root_id == root_id
                && root.status == "active"
                && root.identity_state == "unavailable"
        });
        let mount_root = PathBuf::from(mount_root);
        if root_is_unidentified
            && mount_root == mounted.mount_root
            && !root_mounts.contains_key(&root_id)
        {
            root_mounts.insert(root_id, (mount_root, "unavailable".to_owned()));
        }
    }
    if root_mounts.is_empty() {
        return Err(AppError::Input(
            "filesystem has no stable identity and no matching prior mount observation; specify and check the Device"
                .to_owned(),
        ));
    }
    Ok(root_mounts)
}

fn scope_for_location_at_path(
    cli: &Cli,
    database: &ProjectionDb,
    state: &archive_ledger::RegistryState,
    location: &LocationSnapshot,
    path: &Path,
) -> Result<InventoryLocationScope, AppError> {
    let roots = active_root_mounts(cli, database, state, path)?;
    let root_id = location
        .archive_root_id
        .as_deref()
        .ok_or_else(|| AppError::Input("filesystem Location has no Archive Root".to_owned()))?;
    let (mount_root, fingerprint_status) = roots.get(root_id).ok_or_else(|| {
        AppError::Input(format!(
            "mounted filesystem does not match the Archive Root for {}",
            location.display_name
        ))
    })?;
    let relative = location
        .relative_path
        .as_ref()
        .ok_or_else(|| AppError::Input("filesystem Location has no relative path".to_owned()))?
        .to_path_buf()
        .ok_or_else(|| {
            AppError::Input("Location path cannot be represented on this platform".to_owned())
        })?;
    let location_path = mount_root.join(relative);
    if !path.starts_with(&location_path) {
        return Err(AppError::Input(format!(
            "inventory path {} is outside Location {} at {}",
            path.display(),
            location.display_name,
            location_path.display()
        )));
    }
    Ok(InventoryLocationScope {
        location: location.clone(),
        location_path,
        scan_path: path.to_path_buf(),
        fingerprint_status: fingerprint_status.clone(),
    })
}

fn latest_observed_mount(
    database: &ProjectionDb,
    host_id: &str,
    location: &LocationSnapshot,
) -> Result<PathBuf, AppError> {
    let root_id = location
        .archive_root_id
        .as_deref()
        .ok_or_else(|| AppError::Input("filesystem Location has no Archive Root".to_owned()))?;
    Connection::open(database.path())
        .map_err(|source| status_sql(database, source))?
        .query_row(
            "SELECT mount_root_uri FROM device_mounts
             WHERE host_id = ?1 AND archive_root_id = ?2 AND status = 'mounted'
             ORDER BY observed_time_utc_ms DESC, mount_id DESC LIMIT 1",
            params![host_id, root_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|source| status_sql(database, source))?
        .map(PathBuf::from)
        .ok_or_else(|| {
            AppError::Input(format!(
                "no mount has been observed for {}; mount the Device or use --path",
                location.display_name
            ))
        })
}

fn infer_collection_at_location(
    database: &ProjectionDb,
    state: &archive_ledger::RegistryState,
    location_id: &str,
) -> Result<CollectionSnapshot, AppError> {
    let connection =
        Connection::open(database.path()).map_err(|source| status_sql(database, source))?;
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT collection_id FROM (
               SELECT f.collection_id
               FROM path_observations p
               JOIN file_refs f ON f.file_ref_id = p.file_ref_id
               WHERE p.location_id = ?1
               UNION ALL
               SELECT collection_id FROM annex_imports WHERE location_id = ?1
               UNION ALL
               SELECT collection_id FROM scan_runs WHERE location_id = ?1
             ) ORDER BY collection_id",
        )
        .map_err(|source| status_sql(database, source))?;
    let ids = statement
        .query_map([location_id], |row| row.get::<_, String>(0))
        .map_err(|source| status_sql(database, source))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| status_sql(database, source))?;
    let collections = ids
        .iter()
        .filter_map(|id| {
            state
                .collections
                .iter()
                .find(|collection| collection.collection_id == *id)
        })
        .cloned()
        .collect::<Vec<_>>();
    match collections.as_slice() {
        [collection] => Ok(collection.clone()),
        [] => Err(AppError::Input(
            "cwd Location has no Collection inventory yet; specify a Collection".to_owned(),
        )),
        _ => Err(AppError::Input(
            "cwd Location contains multiple Collections; specify one by name or ID".to_owned(),
        )),
    }
}

fn status_sql(database: &ProjectionDb, source: rusqlite::Error) -> AppError {
    AppError::Status(StatusError::Sqlite {
        path: database.path().to_path_buf(),
        source,
    })
}

fn execute_collection_init(
    cli: &Cli,
    database: &ProjectionDb,
    args: &CollectionInitArgs,
) -> Result<u8, AppError> {
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();
    let collection_name = match args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        Some(name) => name.to_owned(),
        None if interactive => prompt_default("Collection name", "")?,
        None => {
            return Err(AppError::Input(
                "collection init requires --name when input is non-interactive".to_owned(),
            ))
        }
    };
    let collection_name = collection_name.trim().to_owned();
    if collection_name.is_empty() {
        return Err(AppError::Input(
            "Collection name must be non-empty".to_owned(),
        ));
    }
    execute_filesystem_setup(cli, database, args, collection_name, None)
}

fn execute_filesystem_setup(
    cli: &Cli,
    database: &ProjectionDb,
    args: &CollectionInitArgs,
    collection_name: String,
    existing_collection: Option<CollectionSnapshot>,
) -> Result<u8, AppError> {
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();
    for (flag, value) in [
        ("--location-name", args.location_name.as_deref()),
        ("--root-name", args.root_name.as_deref()),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            return Err(AppError::Input(format!("{flag} must be non-empty")));
        }
    }
    if args.import_annex {
        archive_ledger::validate_annex_repository(&args.path)?;
    }

    let mounted = archive_ledger::discover_mounted_filesystem(&args.path)?;
    if mounted.identity_state == "unavailable"
        && !args.allow_unidentified_root
        && (!interactive
            || !prompt_confirmation(
                "No stable filesystem or partition UUID is available. Register this root with unconfirmed identity?",
            )?)
    {
        return Err(AppError::Input(
            "stable filesystem identity is unavailable; inspect the mount and rerun with --allow-unidentified-root to confirm".to_owned(),
        ));
    }

    let state = database.registry_state(false)?;
    if existing_collection.is_none()
        && state
            .collections
            .iter()
            .any(|collection| collection.display_name == collection_name)
    {
        return Err(AppError::Input(format!(
            "an active Collection named {collection_name:?} already exists"
        )));
    }

    let matching_roots = match (
        mounted.fingerprint_kind.as_deref(),
        mounted.filesystem_fingerprint.as_deref(),
    ) {
        (Some(kind), Some(fingerprint)) => state
            .archive_roots
            .iter()
            .filter(|root| {
                root.fingerprint_kind.as_deref() == Some(kind)
                    && root.filesystem_fingerprint.as_deref() == Some(fingerprint)
            })
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    if matching_roots.len() > 1
        || matching_roots
            .iter()
            .any(|root| root.identity_state == "conflict")
    {
        return Err(AppError::Input(
            "the discovered filesystem identity is conflicting; resolve the Archive Root identity before initializing a Collection".to_owned(),
        ));
    }
    let existing_root = matching_roots
        .into_iter()
        .find(|root| root.identity_state == "confirmed")
        .cloned();

    let mut changes = Vec::new();
    let (device, root, site) = if let Some(root) = existing_root {
        let device = state
            .devices
            .iter()
            .find(|device| device.device_id == root.device_id)
            .cloned()
            .ok_or_else(|| AppError::Input("known Archive Root has no active Device".to_owned()))?;
        if let Some(selector) = args.device.as_deref() {
            let selected = select_device(&state.devices, selector)?.ok_or_else(|| {
                AppError::Input(format!(
                    "discovered Archive Root already belongs to {}; --device does not match",
                    device.display_name
                ))
            })?;
            if selected.device_id != device.device_id {
                return Err(AppError::Input(format!(
                    "discovered Archive Root already belongs to {}; --device does not match",
                    device.display_name
                )));
            }
        }
        let site = device
            .current_site_id
            .as_deref()
            .and_then(|site_id| state.sites.iter().find(|site| site.site_id == site_id))
            .cloned()
            .ok_or_else(|| {
                AppError::Input(format!(
                    "known Device {} has no active Site; set it with archive device move before initializing the Collection",
                    device.display_name
                ))
            })?;
        if let Some(selector) = args.site.as_deref() {
            let selected = select_site(&state.sites, selector)?.ok_or_else(|| {
                AppError::Input(format!(
                    "known Device {} is at {}; --site does not match",
                    device.display_name, site.display_name
                ))
            })?;
            if selected.site_id != site.site_id {
                return Err(AppError::Input(format!(
                    "known Device {} is at {}; use archive device move to change its Site",
                    device.display_name, site.display_name
                )));
            }
        }
        (device, root, site)
    } else {
        let device_selector = required_or_prompt(
            args.device.as_deref(),
            interactive,
            "Device name",
            "Primary storage",
            "--device",
        )?;
        let existing_device = select_device(&state.devices, &device_selector)?;
        let device_was_known = existing_device.is_some();
        let site = if let Some(device) = existing_device.as_ref() {
            if let Some(site_id) = device.current_site_id.as_deref() {
                let site = state
                    .sites
                    .iter()
                    .find(|site| site.site_id == site_id)
                    .cloned()
                    .ok_or_else(|| {
                        AppError::Input(format!(
                            "Device {} refers to an inactive or missing Site",
                            device.display_name
                        ))
                    })?;
                if let Some(selector) = args.site.as_deref() {
                    let selected = select_site(&state.sites, selector)?.ok_or_else(|| {
                        AppError::Input(format!(
                            "Device {} is at {}; --site does not match",
                            device.display_name, site.display_name
                        ))
                    })?;
                    if selected.site_id != site.site_id {
                        return Err(AppError::Input(format!(
                            "Device {} is at {}; use archive device move to change its Site",
                            device.display_name, site.display_name
                        )));
                    }
                }
                site
            } else {
                return Err(AppError::Input(format!(
                    "Device {} has no Site; set it with archive device move before initializing the Collection",
                    device.display_name
                )));
            }
        } else {
            let site_selector = required_or_prompt(
                args.site.as_deref(),
                interactive,
                "Site name",
                "Home",
                "--site",
            )?;
            match select_site(&state.sites, &site_selector)? {
                Some(site) => site,
                None => {
                    let site = SiteSnapshot {
                        site_id: generated_id("site"),
                        display_name: site_selector,
                        site_kind: "site".to_owned(),
                        description: None,
                        status: "active".to_owned(),
                    };
                    changes.push(RegistryChange::Site(RegistryAction::Register, site.clone()));
                    site
                }
            }
        };
        let device = if let Some(device) = existing_device {
            device
        } else {
            let device = DeviceSnapshot {
                device_id: generated_id("device"),
                display_name: device_selector,
                device_kind: "disk".to_owned(),
                serial_hint: None,
                hardware_fingerprint: None,
                fingerprint_kind: None,
                identity_state: "unavailable".to_owned(),
                owner: None,
                status: "active".to_owned(),
                current_site_id: Some(site.site_id.clone()),
                expected_availability: "intermittent".to_owned(),
            };
            changes.push(RegistryChange::Device(
                RegistryAction::Register,
                device.clone(),
            ));
            device
        };
        let reusable_unidentified_roots =
            if device_was_known && mounted.identity_state == "unavailable" {
                state
                    .archive_roots
                    .iter()
                    .filter(|root| {
                        root.device_id == device.device_id
                            && root.identity_state == "unavailable"
                            && root.root_path_on_device == RegistryPath::utf8("/")
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
        if reusable_unidentified_roots.len() > 1 {
            return Err(AppError::Input(format!(
                "Device {} has multiple unidentified roots; supply stable filesystem evidence before initializing the Collection",
                device.display_name
            )));
        }
        let root = if let Some(root) = reusable_unidentified_roots.into_iter().next() {
            root
        } else {
            let root = ArchiveRootSnapshot {
                archive_root_id: generated_id("root"),
                device_id: device.device_id.clone(),
                display_name: args
                    .root_name
                    .clone()
                    .unwrap_or_else(|| format!("{} filesystem", device.display_name)),
                root_path_on_device: RegistryPath::utf8("/"),
                status: "active".to_owned(),
                filesystem_fingerprint: mounted.filesystem_fingerprint.clone(),
                fingerprint_kind: mounted.fingerprint_kind.clone(),
                identity_state: mounted.identity_state.clone(),
            };
            changes.push(RegistryChange::ArchiveRoot(
                RegistryAction::Register,
                root.clone(),
            ));
            root
        };
        (device, root, site)
    };

    let relative_path = RegistryPath::from_path(&mounted.relative_path);
    let existing_location = state
        .locations
        .iter()
        .find(|location| {
            location.archive_root_id.as_deref() == Some(root.archive_root_id.as_str())
                && location.relative_path.as_ref() == Some(&relative_path)
        })
        .cloned();
    let location = if let Some(location) = existing_location {
        location
    } else {
        let default_name = format!("{collection_name} on {}", device.display_name);
        let mut display_name = args.location_name.clone().unwrap_or(default_name.clone());
        if state
            .locations
            .iter()
            .any(|location| location.display_name == display_name)
        {
            if args.location_name.is_some() {
                return Err(AppError::Input(format!(
                    "an active Location named {display_name:?} already exists"
                )));
            }
            display_name = format!("{default_name} ({})", relative_path.display);
            if state
                .locations
                .iter()
                .any(|location| location.display_name == display_name)
            {
                return Err(AppError::Input(
                    "the default Location name is ambiguous; provide --location-name".to_owned(),
                ));
            }
        }
        let location = LocationSnapshot {
            location_id: generated_id("location"),
            display_name,
            kind: "filesystem".to_owned(),
            archive_root_id: Some(root.archive_root_id.clone()),
            relative_path: Some(relative_path),
            device_id: Some(device.device_id.clone()),
            site_id: None,
            encryption_state: Some("unknown".to_owned()),
            trust_level: Some("trusted".to_owned()),
            expected_availability: device.expected_availability.clone(),
            is_writable: true,
            status: "active".to_owned(),
        };
        changes.push(RegistryChange::Location(
            RegistryAction::Register,
            location.clone(),
        ));
        location
    };

    let adding_to_existing_collection = existing_collection.is_some();
    let collection = if let Some(collection) = existing_collection {
        collection
    } else {
        let policy = state
            .policies
            .iter()
            .find(|policy| policy.policy_id == "policy_starter")
            .cloned()
            .unwrap_or_else(|| PolicySnapshot {
                policy_id: if state
                    .policies
                    .iter()
                    .any(|policy| policy.policy_id == "policy_starter")
                {
                    generated_id("policy")
                } else {
                    "policy_starter".to_owned()
                },
                display_name: "Two copies at two sites".to_owned(),
                policy_version: 1,
                requirements: PolicyRequirements {
                    min_qualifying_copies: 2,
                    min_devices: 2,
                    min_sites: 2,
                    require_offsite_copy: true,
                    require_offline_copy: false,
                    require_encrypted_offsite: false,
                    max_verification_age_days: 365,
                    max_observation_age_days: 365,
                    max_device_checkin_age_days: 365,
                },
                enabled: true,
                status: "active".to_owned(),
            });
        if !state
            .policies
            .iter()
            .any(|existing| existing.policy_id == policy.policy_id)
        {
            changes.push(RegistryChange::Policy(
                RegistryAction::Register,
                policy.clone(),
            ));
        }
        let collection = CollectionSnapshot {
            collection_id: generated_id("collection"),
            display_name: collection_name,
            description: Some(format!("Files under {}", mounted.path.display())),
            home_site_id: Some(site.site_id.clone()),
            policy_id: Some(policy.policy_id.clone()),
            status: "active".to_owned(),
        };
        changes.push(RegistryChange::Collection(
            RegistryAction::Register,
            collection.clone(),
        ));
        collection
    };
    changes.push(RegistryChange::DeviceMount(DeviceMount {
        mount_id: generated_id("mount"),
        device_id: device.device_id.clone(),
        archive_root_id: Some(root.archive_root_id.clone()),
        mount_root_uri: mounted.mount_root.display().to_string(),
        status: "mounted".to_owned(),
        fingerprint_status: if root.identity_state == "confirmed" {
            "match"
        } else {
            "unavailable"
        }
        .to_owned(),
    }));

    let events = EventStore::open_or_create(
        cli.events_path(),
        EventStoreConfig {
            actor_id: cli.actor.clone(),
            host_id: cli.host.clone(),
            ..EventStoreConfig::default()
        },
    )?;
    let registry = Registry::new(&events, database);
    let mut event_ids = Vec::with_capacity(changes.len());
    for change in changes {
        event_ids.push(registry.record(change)?.event_id);
    }
    let (annex_exit_code, annex_import) = if args.import_annex {
        let annex_args = AnnexArgs {
            repository: mounted.path.clone(),
            collection: collection.collection_id.clone(),
            worktree_location: location.location_id.clone(),
            cas_location: location.location_id.clone(),
            device: device.device_id.clone(),
            root: root.archive_root_id.clone(),
            job_id: args.job_id.clone(),
            import_id: args.import_id.clone(),
            batch_entries: args.batch_entries,
            max_items: None,
        };
        let (exit_code, output) = run_annex_import(cli, database, &annex_args)?;
        (exit_code, Some(output))
    } else {
        (EXIT_OK, None)
    };
    let output = json!({
        "version": 1,
        "collection": collection,
        "location": location,
        "device": device,
        "site": site,
        "archive_root": root,
        "mounted": mounted,
        "events": event_ids,
        "annex_import": annex_import,
    });
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if adding_to_existing_collection {
            println!(
                "Configured Location {} for Collection {} on Device {} at Site {}.",
                location.display_name,
                collection.display_name,
                device.display_name,
                site.display_name
            );
        } else {
            println!(
                "Created Collection {} with Location {} on Device {} at Site {}.",
                collection.display_name,
                location.display_name,
                device.display_name,
                site.display_name
            );
        }
        println!(
            "Mounted root: {}; Location path within root: {}.",
            mounted.mount_root.display(),
            if mounted.relative_path.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                mounted.relative_path.display().to_string()
            }
        );
        if root.identity_state == "confirmed" {
            println!(
                "Root identity: {} {}.",
                root.fingerprint_kind.as_deref().unwrap_or("unknown"),
                root.filesystem_fingerprint.as_deref().unwrap_or("unknown")
            );
        } else {
            println!("Root identity: unavailable (not evidence of independent storage).");
        }
        if let Some(annex_import) = &annex_import {
            print_annex_import(annex_import, false)?;
        } else {
            println!(
                "Next: archive location add . --collection {}",
                collection.collection_id
            );
        }
    }
    Ok(annex_exit_code)
}

fn generated_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        ulid::Ulid::new().to_string().to_ascii_lowercase()
    )
}

fn required_or_prompt(
    value: Option<&str>,
    interactive: bool,
    label: &str,
    default: &str,
    flag: &str,
) -> Result<String, AppError> {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(value.to_owned());
    }
    if interactive {
        return prompt_default(label, default);
    }
    Err(AppError::Input(format!(
        "collection init requires {flag} when the filesystem is not already known and input is non-interactive"
    )))
}

fn select_device(
    devices: &[DeviceSnapshot],
    selector: &str,
) -> Result<Option<DeviceSnapshot>, AppError> {
    select_registry_entity(
        devices,
        selector,
        |device| &device.device_id,
        |device| &device.display_name,
        "Device",
    )
}

fn select_collection(
    collections: &[CollectionSnapshot],
    selector: &str,
) -> Result<Option<CollectionSnapshot>, AppError> {
    select_registry_entity(
        collections,
        selector,
        |collection| &collection.collection_id,
        |collection| &collection.display_name,
        "Collection",
    )
}

fn select_location(
    locations: &[LocationSnapshot],
    selector: &str,
) -> Result<Option<LocationSnapshot>, AppError> {
    select_registry_entity(
        locations,
        selector,
        |location| &location.location_id,
        |location| &location.display_name,
        "Location",
    )
}

fn select_site(sites: &[SiteSnapshot], selector: &str) -> Result<Option<SiteSnapshot>, AppError> {
    select_registry_entity(
        sites,
        selector,
        |site| &site.site_id,
        |site| &site.display_name,
        "Site",
    )
}

fn select_registry_entity<T: Clone>(
    values: &[T],
    selector: &str,
    id: impl Fn(&T) -> &String,
    name: impl Fn(&T) -> &String,
    kind: &str,
) -> Result<Option<T>, AppError> {
    if let Some(exact) = values.iter().find(|value| id(value) == selector) {
        return Ok(Some(exact.clone()));
    }
    let matches = values
        .iter()
        .filter(|value| name(value) == selector)
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        _ => Err(AppError::Input(format!(
            "{kind} name {selector:?} is ambiguous; use its stable ID"
        ))),
    }
}

fn execute_registry(
    cli: &Cli,
    database: &ProjectionDb,
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
            let output = json!({"version": 1, "mounted_filesystem": discovered});
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Path: {}", discovered.path.display());
                println!("  mounted root: {}", discovered.mount_root.display());
                println!(
                    "  relative path: {}",
                    if discovered.relative_path.as_os_str().is_empty() {
                        ".".to_owned()
                    } else {
                        discovered.relative_path.display().to_string()
                    }
                );
                if let (Some(kind), Some(fingerprint)) = (
                    discovered.fingerprint_kind.as_deref(),
                    discovered.filesystem_fingerprint.as_deref(),
                ) {
                    println!("  stable root identity: {kind} {fingerprint}");
                } else {
                    println!("  stable root identity: unavailable");
                    println!("  this mount cannot prove independent storage");
                }
            }
        }
        RegistryEntityCommand::List { all } => {
            let state = database.registry_state(*all)?;
            let values = registry_values(kind, &state)?;
            print_registry_values(kind, values, cli.json)?;
        }
        RegistryEntityCommand::Show { id } => {
            let state = database.registry_state(true)?;
            let values = registry_values(kind, &state)?;
            let value = if let Some(value) = values
                .iter()
                .find(|value| registry_id(value) == Some(id.as_str()))
            {
                value.clone()
            } else {
                let named = values
                    .iter()
                    .filter(|value| {
                        value
                            .get("display_name")
                            .and_then(serde_json::Value::as_str)
                            == Some(id.as_str())
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                match named.as_slice() {
                    [value] => value.clone(),
                    [] => return Err(AppError::Input(format!("registry entry not found: {id}"))),
                    _ => {
                        return Err(AppError::Input(format!(
                            "registry name is ambiguous; use a stable ID: {id}"
                        )))
                    }
                }
            };
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
                    archive_root_id: None,
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
        cli.events_path(),
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
                filesystem_fingerprint: args.fingerprint.clone(),
                fingerprint_kind: args.fingerprint_kind.clone(),
                identity_state: if args.fingerprint.is_some() && args.fingerprint_kind.is_some() {
                    "confirmed"
                } else {
                    "unavailable"
                }
                .to_owned(),
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
