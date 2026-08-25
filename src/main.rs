use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use archive_ledger::{
    central_archive, create_portable_snapshot, fsck_v2_archive, inspect_portable_snapshot,
    install_portable_snapshot, utf8_path, AnnexImportConfig, AnnexImportError, AnnexImportStatus,
    AnnexImporter, ArchiveRootSnapshot, CachedPolicyStatus, CatalogError, CatalogRegistry,
    CollectionSnapshot, CopyFilter, CopyPageRequest, DeviceCheckIn, DeviceMount, DeviceSnapshot,
    DiscoveryItem, EventReferences, EventRequest, EventStore, EventStoreConfig, EventStoreError,
    FileDiscovery, FileFilter, FilePageRequest, LocationScanner, LocationSnapshot, LocationStatus,
    MetadataDestinationSnapshot, MetadataError, MetadataProtector, MetadataRegistry, PolicyError,
    PolicyEvaluationResult, PolicyFinding, PolicyFindingFilter, PolicyFindingPage,
    PolicyRequirements, PolicySnapshot, ProjectionConfig, ProjectionDb, ProjectionError, Registry,
    RegistryAction, RegistryChange, RegistryError, RegistryPath, ReviewError, RiskAssignment,
    RiskDomainSnapshot, SafeCopyError, ScanConfig, ScanError, ScanMode, ScanStatus, SiteSnapshot,
    StageAuditOptions, StageError, StatusError, StorageDiscoveryError, V2FsckError, V2FsckOptions,
    V2OriginStore, V2ProjectionDb, V2ProjectionError, V2Registry, V2StoreError,
};
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use fs2::available_space;
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

    /// Explicit schema-6 SQLite path for diagnostics (requires --events).
    #[arg(long, global = true)]
    database: Option<PathBuf>,

    /// Explicit version 2 event-tree path for diagnostics (requires --database).
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
    if let Ok(database) = V2ProjectionDb::open_existing(&database_path) {
        let status = database.status()?;
        return Ok(archive_ledger::KnownArchive {
            archive_id: status.archive_id,
            display_name: status.archive_name,
            root,
        });
    }
    if !events_path.is_dir() {
        return Err(AppError::Input(format!(
            "Archive directory {} has neither a schema-6 projection nor a canonical event store",
            root.display()
        )));
    }
    Err(AppError::Input(
        "this is a pre-v2 development Archive; recreate it with `archive init <name>` and re-import its files"
            .to_owned(),
    ))
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new named Archive catalog without inspecting the current directory.
    Init {
        /// Human-readable Archive name; prompted for on a terminal when omitted.
        #[arg(value_name = "NAME")]
        name: Option<String>,
        /// Human-readable Archive name (alternative to the positional NAME).
        #[arg(long = "name", value_name = "NAME", conflicts_with = "name")]
        name_option: Option<String>,
        /// Make this Archive the per-user default even if another default exists.
        #[arg(long)]
        make_default: bool,
        /// Stable archive ID; generated when omitted.
        #[arg(long)]
        archive_id: Option<String>,
        /// Prompt for a starter single-machine topology when attached to a terminal.
        #[arg(long, conflicts_with = "non_interactive", hide = true)]
        guided: bool,
        /// Never prompt; requires NAME or --name for a centrally stored Archive.
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
    /// Check Git, signed history, and SQLite health without repairing anything.
    Fsck(FsckArgs),
    /// Audit an external directory without changing ledger state, or import reviewed new files.
    Stage(StageArgs),
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
    /// Copy verified content to a Location, or inspect current Copy claims.
    Copy(CopyArgs),
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
    #[command(visible_alias = "s")]
    Site {
        #[command(subcommand)]
        command: SiteCommand,
    },
    /// Manage file collections.
    #[command(visible_alias = "c")]
    Collection {
        #[command(subcommand)]
        command: CollectionCommand,
    },
    /// Manage devices through canonical full-snapshot events.
    #[command(visible_alias = "d")]
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Manage archive roots through canonical full-snapshot events.
    Root {
        #[command(subcommand)]
        command: RegistryEntityCommand,
    },
    /// Manage where Collection files are stored.
    #[command(visible_alias = "l")]
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
    /// Enroll installations and synchronize their canonical event histories.
    Sync(SyncArgs),
    /// Create and inspect non-authoritative portable SQLite snapshots.
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommand,
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

#[derive(Debug, Args)]
struct FsckArgs {
    /// Also rebuild into a disposable database and compare event-derived tables.
    #[arg(long)]
    full: bool,
    /// Preserve the disposable rebuilt database for diagnosis (requires --full).
    #[arg(long, requires = "full")]
    keep_rebuild: bool,
    /// Directory in which to create the disposable rebuild (requires --full).
    #[arg(long, value_name = "DIRECTORY", requires = "full")]
    rebuild_dir: Option<PathBuf>,
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

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct StageArgs {
    /// Directory to checksum and compare with every Collection in the Archive.
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Store or reuse the non-canonical checksum manifest at this path.
    #[arg(long)]
    manifest: Option<PathBuf>,
    /// Distinguish matches in this Collection from matches in other Collections.
    #[arg(long)]
    collection: Option<String>,
    /// Maximum number of new paths included in command output.
    #[arg(long, default_value_t = 100)]
    limit: usize,
    #[command(subcommand)]
    command: Option<StageCommand>,
}

#[derive(Debug, Subcommand)]
enum StageCommand {
    /// Copy reviewed archive-unknown files into a new subtree of the current Location.
    Import(StageImportArgs),
}

#[derive(Debug, Args)]
struct StageImportArgs {
    /// Previously staged source directory.
    source: PathBuf,
    /// Use this manifest when the source-local default was unavailable.
    #[arg(long)]
    manifest: Option<PathBuf>,
    /// Destination Collection; inferred from the current Location when possible.
    #[arg(long)]
    collection: Option<String>,
    /// Destination Location; inferred from cwd when omitted.
    #[arg(long)]
    location: Option<String>,
    /// New relative subtree beneath cwd; defaults to the source directory name.
    #[arg(long)]
    into: Option<PathBuf>,
    /// Show the reviewed copy plan without writing files or ledger facts.
    #[arg(long)]
    dry_run: bool,
    /// Confirm the mutation without prompting.
    #[arg(long)]
    yes: bool,
    /// Never prompt; requires --yes unless --dry-run is used.
    #[arg(long)]
    non_interactive: bool,
    /// Internal durable job identity used by `archive job resume`.
    #[arg(long, hide = true)]
    job_id: Option<String>,
    /// Internal fixed destination root used by `archive job resume`.
    #[arg(long, hide = true)]
    destination_root: Option<PathBuf>,
    /// Stop cleanly after this many selected files; useful for testing resume.
    #[arg(long, hide = true)]
    max_items: Option<usize>,
    /// Stop cleanly after atomic publication; useful for testing crash recovery.
    #[arg(long, hide = true)]
    stop_after_publish: bool,
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

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct SyncArgs {
    /// Remote to synchronize; inferred when exactly one is configured.
    #[arg(value_name = "REMOTE")]
    remote: Option<String>,
    #[command(subcommand)]
    command: Option<SyncCommand>,
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Clone canonical history and build or install its SQLite materialized view.
    Clone {
        remote: String,
        /// Optional out-of-band portable snapshot directory.
        #[arg(long)]
        snapshot: Option<PathBuf>,
        /// Make the cloned Archive the default even if another default exists.
        #[arg(long)]
        make_default: bool,
    },
    /// Configure the Git transport used for this Archive.
    Remote {
        #[command(subcommand)]
        command: SyncRemoteCommand,
    },
    /// Create a signed public enrollment request on a new installation.
    Enroll {
        /// Human-readable name for this installation, such as "Laptop".
        #[arg(long)]
        name: String,
        /// New file to receive the signed enrollment request.
        #[arg(long, default_value = "archive-ledger-enrollment.json")]
        output: PathBuf,
    },
    /// Approve a signed enrollment request from another installation.
    Approve { request: PathBuf },
    /// Revoke an enrolled installation's future writing authority.
    Revoke {
        client: String,
        /// Confirm this coordination change without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// List enrolled and revoked installations.
    Status,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    /// Create a signed, portable SQLite cache outside canonical Git history.
    Create {
        /// New directory for archive.db and its signed manifest.
        output: Option<PathBuf>,
    },
    /// Validate a snapshot against the selected Archive's canonical history.
    Inspect { snapshot: PathBuf },
}

#[derive(Debug, Subcommand)]
enum SyncRemoteCommand {
    Add {
        name: String,
        locator: String,
    },
    List,
    Show {
        name: String,
    },
    Remove {
        name: String,
        #[arg(long)]
        yes: bool,
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
enum CopyReviewCommand {
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

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct CopyArgs {
    #[command(subcommand)]
    command: Option<CopyReviewCommand>,
    #[command(flatten)]
    mutation: CopyMutationArgs,
}

#[derive(Debug, Args)]
struct CopyMutationArgs {
    /// Destination Location name or stable ID.
    #[arg(long)]
    to: Option<String>,
    /// Source Location; inferred from cwd when omitted.
    #[arg(long)]
    from: Option<String>,
    /// Collection; inferred from the source Location when omitted.
    #[arg(long)]
    collection: Option<String>,
    /// Logical files or directory prefixes; defaults to cwd's Collection subtree.
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// Show the copy plan without writing content or ledger facts.
    #[arg(long)]
    dry_run: bool,
    /// Confirm the mutation without prompting.
    #[arg(long)]
    yes: bool,
    /// Never prompt; requires --yes unless --dry-run is used.
    #[arg(long)]
    non_interactive: bool,
    /// Resume this exact local copy job.
    #[arg(long, hide = true)]
    job_id: Option<String>,
    /// Stop cleanly after this many Objects; used by resume tests.
    #[arg(long, hide = true)]
    max_items: Option<usize>,
    #[arg(skip)]
    logical_filters: Option<Vec<PathBuf>>,
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
    #[command(visible_alias = "ls")]
    List {
        #[arg(long)]
        all: bool,
    },
    /// Show one Collection by name or stable ID.
    Show { id: String },
    /// Add present files to this Collection without marking unseen files missing.
    Add(CollectionAddArgs),
    /// Replace user-controlled fields with a complete JSON snapshot.
    Update { snapshot: String },
    /// Retire a Collection with a complete JSON snapshot whose status is retired.
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args, Clone)]
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
    #[arg(long, hide = true, requires = "import_annex")]
    max_items: Option<usize>,
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
    /// Completely reconcile a Location, including files that are now missing.
    Scan(LocationScanArgs),
    /// Copy verified Objects to another registered Location.
    Copy(CopyMutationArgs),
    /// Inspect a mounted path without registering or changing it.
    Discover { path: PathBuf },
    /// List active Locations.
    #[command(visible_alias = "ls")]
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
struct CollectionAddArgs {
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
    /// Show Site Devices and their cached file, space, and stale-presence totals.
    Status {
        site: Option<String>,
    },
    /// List active Sites.
    #[command(visible_alias = "ls")]
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
    /// Show Device identity, capacity, and cached Location totals.
    Status {
        device: Option<String>,
    },
    Discover {
        path: PathBuf,
    },
    /// List active Devices.
    #[command(visible_alias = "ls")]
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
    #[arg(long, hide = true)]
    max_items: Option<usize>,
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
    /// Update selected policy settings while preserving the others.
    Update(PolicyUpdateArgs),
    Retire {
        snapshot: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct PolicyUpdateArgs {
    /// Policy name or stable ID.
    policy: String,
    /// Change the human-readable policy name.
    #[arg(long)]
    name: Option<String>,
    /// Minimum number of qualifying copies.
    #[arg(long)]
    copies: Option<u64>,
    /// Minimum number of distinct Devices.
    #[arg(long)]
    devices: Option<u64>,
    /// Minimum number of distinct Sites.
    #[arg(long)]
    sites: Option<u64>,
    /// Whether at least one qualifying copy must be outside the home Site.
    #[arg(long, value_name = "BOOL")]
    require_offsite: Option<bool>,
    /// Whether at least one qualifying copy must be offline.
    #[arg(long, value_name = "BOOL")]
    require_offline: Option<bool>,
    /// Whether the offsite qualifying copy must be encrypted.
    #[arg(long, value_name = "BOOL")]
    require_encrypted_offsite: Option<bool>,
    /// Maximum age of successful verification evidence.
    #[arg(long)]
    verification_days: Option<u64>,
    /// Maximum age of presence observations.
    #[arg(long)]
    observation_days: Option<u64>,
    /// Maximum age of Device identity check-ins.
    #[arg(long)]
    device_checkin_days: Option<u64>,
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    /// Show current policy and disaster-loss findings from SQLite.
    Risk(ReportArgs),
    /// Show current integrity/policy uncertainty and violations from SQLite.
    Integrity(ReportArgs),
    /// Show current per-policy totals and validity from SQLite.
    Policy(ReportSummaryArgs),
    /// Show checkpoint, commit, and independent replication coverage.
    Metadata,
    /// Show which Devices and Locations have stale presence evidence.
    StalePresence(StalePresenceArgs),
}

#[derive(Debug, Args)]
struct StalePresenceArgs {
    /// Show Location rollups beneath each Device.
    #[arg(long)]
    locations: bool,
    /// Limit the report to one Collection name or ID.
    #[arg(long)]
    collection: Option<String>,
    /// Override Collection policies with this age in days.
    #[arg(long = "older-than")]
    older_than_days: Option<u64>,
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
    Stage(StageError),
    SafeCopy(SafeCopyError),
    Annex(AnnexImportError),
    Storage(StorageDiscoveryError),
    Status(StatusError),
    V2Store(V2StoreError),
    V2Projection(V2ProjectionError),
    V2Fsck(V2FsckError),
    V2Inventory(archive_ledger::V2InventoryError),
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
            Self::Stage(error) => error.code(),
            Self::SafeCopy(error) => error.code(),
            Self::Annex(error) => error.code(),
            Self::Storage(error) => error.code(),
            Self::Status(error) => error.code(),
            Self::V2Store(error) => error.code(),
            Self::V2Projection(error) => error.code(),
            Self::V2Fsck(error) => error.code(),
            Self::V2Inventory(error) => error.code(),
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
            Self::Stage(error) => error.fmt(formatter),
            Self::SafeCopy(error) => error.fmt(formatter),
            Self::Annex(error) => error.fmt(formatter),
            Self::Storage(error) => error.fmt(formatter),
            Self::Status(error) => error.fmt(formatter),
            Self::V2Store(error) => error.fmt(formatter),
            Self::V2Projection(error) => error.fmt(formatter),
            Self::V2Fsck(error) => error.fmt(formatter),
            Self::V2Inventory(error) => error.fmt(formatter),
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

impl From<StageError> for AppError {
    fn from(error: StageError) -> Self {
        Self::Stage(error)
    }
}

impl From<SafeCopyError> for AppError {
    fn from(error: SafeCopyError) -> Self {
        Self::SafeCopy(error)
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

impl From<V2StoreError> for AppError {
    fn from(error: V2StoreError) -> Self {
        Self::V2Store(error)
    }
}

impl From<V2ProjectionError> for AppError {
    fn from(error: V2ProjectionError) -> Self {
        Self::V2Projection(error)
    }
}

impl From<V2FsckError> for AppError {
    fn from(error: V2FsckError) -> Self {
        Self::V2Fsck(error)
    }
}

impl From<archive_ledger::V2InventoryError> for AppError {
    fn from(error: archive_ledger::V2InventoryError) -> Self {
        Self::V2Inventory(error)
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
    collections: Vec<ArchiveCollectionStatus>,
    policy: CachedPolicyStatus,
    metadata: archive_ledger::MetadataProtectionStatus,
}

#[derive(Debug, Serialize)]
struct ArchiveCollectionStatus {
    collection_id: String,
    collection_name: String,
    file_count: u64,
    files_at_risk: Option<u64>,
    files_uncertain: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DeviceIdentifier {
    kind: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct DeviceCapacity {
    available_bytes: Option<u64>,
    status: String,
    mount_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceStatusOutput {
    version: u32,
    device_id: String,
    device_name: String,
    identifier: DeviceIdentifier,
    site_id: Option<String>,
    site_name: Option<String>,
    file_count: u64,
    space_used_bytes: u64,
    stale_presence_count: Option<u64>,
    capacity: DeviceCapacity,
    locations: Vec<LocationStatus>,
}

#[derive(Debug, Serialize)]
struct SiteDeviceStatus {
    device_id: String,
    device_name: String,
    file_count: u64,
    space_used_bytes: u64,
    stale_presence_count: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SiteStatusOutput {
    version: u32,
    site_id: String,
    site_name: String,
    devices: Vec<SiteDeviceStatus>,
}

struct StaleStatusIndex {
    count_by_location: BTreeMap<String, u64>,
    age_days_by_collection: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct V2CollectionRisk {
    file_count: u64,
    known_size_bytes: u64,
    files_at_risk: u64,
    files_uncertain: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct V2LocationMetrics {
    file_count: u64,
    space_used_bytes: u64,
    stale_presence_count: u64,
    stale_after_days: u64,
}

#[derive(Default)]
struct V2FileRiskAccumulator {
    file_ref_id: String,
    logical_path: String,
    object_known: bool,
    size_bytes: u64,
    qualifying_copies: u64,
    devices: u64,
    sites: u64,
    has_offsite: bool,
    has_offline: bool,
    has_encrypted_offsite: bool,
}

#[derive(Debug, Clone, Serialize)]
struct V2RiskFinding {
    file_ref_id: String,
    logical_path: String,
    object_known: bool,
    qualifying_copies: u64,
    devices: u64,
    sites: u64,
    result: String,
    reasons: Vec<String>,
}

struct TemporaryImportTree {
    path: PathBuf,
    keep: bool,
}

impl Drop for TemporaryImportTree {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
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

#[derive(Debug)]
struct ArchiveCopyItem {
    file_ref_id: String,
    object_id: String,
    blake3_hex: String,
    size_bytes: u64,
    logical_path: PathBuf,
    logical_path_encoding: String,
    logical_path_bytes: Vec<u8>,
    logical_path_display: String,
    source_relative_path: PathBuf,
    destination_has_object: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
struct ArchiveCopySummary {
    selected_logical_files: u64,
    selected_unique_objects: u64,
    already_present_objects: u64,
    bytes_to_copy: u64,
    copied_objects: u64,
    copied_bytes: u64,
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
    let argument_json_requested = std::env::args().any(|argument| argument == "--json");
    let environment_json_requested = match std::env::var("ARCHIVE_LEDGER_OUTPUT") {
        Ok(value) if value.eq_ignore_ascii_case("json") => true,
        Ok(value) if value.is_empty() || value.eq_ignore_ascii_case("human") => false,
        Ok(value) => {
            eprintln!(
                "error [invalid_input]: ARCHIVE_LEDGER_OUTPUT must be 'human' or 'json', not {value:?}"
            );
            return ExitCode::from(EXIT_ERROR);
        }
        Err(std::env::VarError::NotPresent) => false,
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("error [invalid_input]: ARCHIVE_LEDGER_OUTPUT must contain valid Unicode");
            return ExitCode::from(EXIT_ERROR);
        }
    };
    let json_requested = argument_json_requested || environment_json_requested;
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
    cli.json |= environment_json_requested;
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
        name_option,
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
        let name = name.as_deref().or(name_option.as_deref());
        return execute_v2_init(
            cli,
            name,
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
    if let Command::Sync(SyncArgs {
        command:
            Some(SyncCommand::Clone {
                remote,
                snapshot,
                make_default,
            }),
        ..
    }) = &cli.command
    {
        return execute_v2_clone(cli, remote, snapshot.as_deref(), *make_default);
    }
    if let Command::Restore {
        command:
            RestoreCommand::Check {
                event_repository,
                rebuild_database,
            },
    } = &cli.command
    {
        let store = V2OriginStore::open(event_repository)?;
        let verified = store.verification_report()?;
        let rebuilt = V2ProjectionDb::rebuild(&store, rebuild_database)?;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2,
                    "archive_id": verified.archive_id,
                    "verified_records": verified.records,
                    "accepted_frontier_hash": verified.accepted_frontier_hash,
                    "rebuilt_database": rebuild_database,
                    "records_applied": rebuilt.records_applied,
                }))?
            );
        } else {
            println!(
                "Restore verified {} signed records and rebuilt matching SQLite state at {}.",
                verified.records,
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
    if let Command::Snapshot { command } = &cli.command {
        return execute_v2_snapshot(cli, command);
    }
    if let Command::Sync(args) = &cli.command {
        let database = V2ProjectionDb::open_existing(cli.database_path())?;
        return execute_v2_sync(cli, &database, args);
    }
    if let Command::Fsck(args) = &cli.command {
        return execute_v2_fsck(cli, args);
    }
    if let Command::Status = &cli.command {
        return execute_v2_status(cli);
    }
    if let Ok(database) = V2ProjectionDb::open_existing(cli.database_path()) {
        if let Command::File { command } = &cli.command {
            return execute_v2_file(&database, command, cli.json);
        }
        if let Some(result) = execute_v2_registry_command(cli, &database)? {
            return Ok(result);
        }
        return Err(AppError::Input(
            "this command has not yet been converted to the version 2 Archive writer; status, events verify, and db rebuild are available"
                .to_owned(),
        ));
    }
    return Err(AppError::Input(
        "this is a pre-v2 development Archive; recreate it with `archive init <name>` and re-import its files"
            .to_owned(),
    ));
    #[allow(unreachable_code)]
    {
        let database =
            ProjectionDb::open_existing(cli.database_path(), ProjectionConfig::default())?;
        match &cli.command {
            Command::Init { .. } => {
                unreachable!("init returned before opening an existing database")
            }
            Command::Use { .. } => unreachable!("use returned before opening SQLite"),
            Command::Rename { new_name } => execute_archive_rename(cli, &database, new_name),
            Command::Status => execute_status(&database, cli.json),
            Command::Fsck(_) => unreachable!("version 2 fsck returned before opening SQLite"),
            Command::Stage(args) => execute_stage(cli, &database, args),
            Command::File { command } => execute_file(&database, command, cli.json),
            Command::Object { command } => execute_object(&database, command, cli.json),
            Command::Copy(args) => execute_copy(cli, &database, args),
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
            Command::Root { command } => {
                execute_registry(cli, &database, RegistryKind::Root, command)
            }
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
                PolicyCommand::Update(args) => execute_policy_update(cli, &database, args),
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
                ReportCommand::StalePresence(args) => {
                    execute_stale_presence_report(&database, args, cli.json)
                }
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
            Command::Events { .. } => {
                unreachable!("event verification returned before opening SQLite")
            }
            Command::Sync(_) => {
                unreachable!("version 2 sync command returned before opening legacy SQLite")
            }
            Command::Snapshot { .. } => {
                unreachable!("version 2 snapshot command returned before opening legacy SQLite")
            }
            Command::Db { .. } => unreachable!("database command returned before opening SQLite"),
            Command::Restore { .. } => unreachable!("restore returned before opening SQLite"),
        }
    }
}

fn execute_v2_clone(
    cli: &Cli,
    remote: &str,
    snapshot: Option<&Path>,
    make_default: bool,
) -> Result<u8, AppError> {
    if cli.archive.is_some() || cli.database.is_some() || cli.events.is_some() {
        return Err(AppError::Input(
            "sync clone creates a new Archive and cannot be combined with --archive or --database/--events"
                .to_owned(),
        ));
    }
    if remote.trim().is_empty() {
        return Err(AppError::Input("clone remote cannot be empty".to_owned()));
    }
    let archive_parent = central_archive("clone-target", "clone-target")?
        .root
        .parent()
        .expect("central Archive path has a parent")
        .to_path_buf();
    std::fs::create_dir_all(&archive_parent)?;
    let prepared = archive_parent.join(format!(
        ".archive-ledger-clone-{}",
        ulid::Ulid::new().to_string().to_ascii_lowercase()
    ));
    std::fs::create_dir(&prepared)?;
    let result = (|| {
        let canonical = prepared.join("canonical");
        let output = ProcessCommand::new("git")
            .args([
                "clone",
                "--quiet",
                "--branch",
                "archive-ledger",
                "--single-branch",
            ])
            .arg(remote)
            .arg(&canonical)
            .output()?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(AppError::Input(if detail.is_empty() {
                format!("Git could not clone {remote}")
            } else {
                format!("Git could not clone {remote}: {detail}")
            }));
        }
        let store = V2OriginStore::open(&canonical)?;
        let verified = store.verification_report()?;
        let archive_name = store.verify()?.genesis.body.archive_display_name;
        let known = central_archive(&verified.archive_id, &archive_name)?;
        if known.root.exists() {
            return Err(AppError::Input(format!(
                "Archive {} is already installed at {}",
                verified.archive_id,
                known.root.display()
            )));
        }
        let database_path = prepared.join("archive.db");
        let mut snapshot_warning = None;
        let snapshot_install = snapshot.and_then(|artifact| {
            match install_portable_snapshot(&store, artifact, &database_path) {
                Ok(installed) => Some(installed),
                Err(error) => {
                    snapshot_warning = Some(error.to_string());
                    None
                }
            }
        });
        if snapshot_install.is_none() {
            V2ProjectionDb::rebuild(&store, &database_path)?;
        }
        V2ProjectionDb::open_existing(&database_path)?.validate_against_store(&store)?;
        archive_ledger::place_directory_no_replace(&prepared, &known.root)?;
        let mut registry = CatalogRegistry::load()?;
        let became_default = registry.archives().is_empty() || make_default;
        registry.register(known.clone(), make_default)?;
        Ok::<_, AppError>((
            known,
            verified,
            snapshot_install,
            snapshot_warning,
            became_default,
        ))
    })();
    let (known, verified, snapshot_install, snapshot_warning, became_default) = match result {
        Ok(result) => result,
        Err(error) => {
            if prepared.exists() {
                let _ = std::fs::remove_dir_all(&prepared);
            }
            return Err(error);
        }
    };
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "action": "archive_cloned",
                "archive_id": known.archive_id,
                "archive_name": known.display_name,
                "root": known.root,
                "canonical_records": verified.records,
                "accepted_frontier_hash": verified.accepted_frontier_hash,
                "snapshot_used": snapshot_install.is_some(),
                "snapshot": snapshot_install,
                "snapshot_rejection": snapshot_warning,
                "default": became_default,
            }))?
        );
    } else {
        println!("Cloned Archive \"{}\".", known.display_name);
        println!("Verified {} canonical records.", verified.records);
        if let Some(installed) = snapshot_install {
            println!(
                "Installed portable snapshot and applied {} newer records.",
                installed.records_applied
            );
        } else if let Some(reason) = snapshot_warning {
            println!("Portable snapshot was not used: {reason}");
            println!("Rebuilt SQLite safely from canonical events instead.");
        } else {
            println!("Built SQLite from canonical events.");
        }
        if became_default {
            println!("It is now the default Archive.");
        }
        println!("Next: archive sync enroll --name <this-computer>");
    }
    Ok(EXIT_OK)
}

fn execute_v2_snapshot(cli: &Cli, command: &SnapshotCommand) -> Result<u8, AppError> {
    let store = V2OriginStore::open(cli.events_path())?;
    match command {
        SnapshotCommand::Create { output } => {
            let database = V2ProjectionDb::open_existing(cli.database_path())?;
            let output = match output {
                Some(output) => output.clone(),
                None => {
                    let status = database.status()?;
                    let commit = store.canonical_commit()?;
                    PathBuf::from(format!(
                        "archive-ledger-snapshot-{}-{}",
                        status.archive_id,
                        commit.get(..12).unwrap_or(&commit)
                    ))
                }
            };
            let created = create_portable_snapshot(&database, &store, &output)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&created)?);
            } else {
                println!("Created portable snapshot at {}.", output.display());
                println!("Bound canonical commit: {}", created.canonical_git_commit);
                println!("Size: {} bytes", created.database_bytes);
            }
        }
        SnapshotCommand::Inspect { snapshot } => {
            let inspected = inspect_portable_snapshot(&store, snapshot)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&inspected)?);
            } else {
                println!(
                    "Portable snapshot is valid for Archive {}.",
                    inspected.archive_id
                );
                println!("Canonical commit: {}", inspected.canonical_git_commit);
                println!("Accepted frontier: {}", inspected.accepted_frontier_hash);
                println!("Size: {} bytes", inspected.database_bytes);
            }
        }
    }
    Ok(EXIT_OK)
}

fn execute_v2_sync(cli: &Cli, database: &V2ProjectionDb, args: &SyncArgs) -> Result<u8, AppError> {
    let store = V2OriginStore::open(cli.events_path())?;
    let Some(command) = &args.command else {
        let remotes = store.sync_remotes()?;
        let remote = match args.remote.as_deref() {
            Some(remote) if remotes.iter().any(|item| item.name == remote) => remote,
            Some(remote) => {
                return Err(AppError::Input(format!(
                    "synchronization remote not found: {remote}"
                )))
            }
            None if remotes.len() == 1 => &remotes[0].name,
            None if remotes.iter().any(|item| item.name == "origin") => "origin",
            None if remotes.is_empty() => {
                return Err(AppError::Input(
                    "no synchronization remote is configured; run `archive sync remote add <name> <locator>`"
                        .to_owned(),
                ))
            }
            None => {
                return Err(AppError::Input(
                    "more than one synchronization remote is configured; name one with `archive sync <remote>`"
                        .to_owned(),
                ))
            }
        };
        let synced = store.sync_remote(remote)?;
        let applied = database.apply(&store)?;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2,
                    "sync": synced,
                    "projection": applied,
                }))?
            );
        } else {
            println!("Synchronized with {}.", synced.remote);
            println!("Accepted frontier: {}", synced.accepted_frontier_hash);
            println!(
                "Origins: {}; canonical records: {}; projection records applied: {}",
                synced.origins, synced.records, applied.records_applied
            );
            if synced.merged {
                println!("Compatible offline histories were retained in one verified union.");
            } else if !synced.pushed && applied.records_applied == 0 {
                println!("Already up to date.");
            }
        }
        return Ok(EXIT_OK);
    };
    match command {
        SyncCommand::Clone { .. } => {
            unreachable!("clone returned before resolving an existing Archive")
        }
        SyncCommand::Remote { command } => match command {
            SyncRemoteCommand::Add { name, locator } => {
                store.add_sync_remote(name, locator)?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "version": 2,
                            "action": "sync_remote_added",
                            "name": name,
                            "locator": locator,
                        }))?
                    );
                } else {
                    println!("Added synchronization remote {name}.");
                    println!("Next: archive sync {name}");
                }
            }
            SyncRemoteCommand::List => {
                let remotes = store.sync_remotes()?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({"version": 2, "items": remotes}))?
                    );
                } else if remotes.is_empty() {
                    println!("No synchronization remotes configured.");
                } else {
                    for remote in remotes {
                        println!("{}  {}", remote.name, remote.locator);
                    }
                }
            }
            SyncRemoteCommand::Show { name } => {
                let remote = store
                    .sync_remotes()?
                    .into_iter()
                    .find(|remote| remote.name == *name)
                    .ok_or_else(|| {
                        AppError::Input(format!("synchronization remote not found: {name}"))
                    })?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&remote)?);
                } else {
                    println!("Remote: {}", remote.name);
                    println!("Locator: {}", remote.locator);
                }
            }
            SyncRemoteCommand::Remove { name, yes } => {
                if !yes {
                    return Err(AppError::Input(
                        "removing a synchronization remote requires --yes".to_owned(),
                    ));
                }
                store.remove_sync_remote(name)?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "version": 2,
                            "action": "sync_remote_removed",
                            "name": name,
                        }))?
                    );
                } else {
                    println!("Removed synchronization remote {name}.");
                }
            }
        },
        SyncCommand::Enroll { name, output } => {
            if output.exists() {
                return Err(AppError::Input(format!(
                    "refusing to overwrite enrollment request {}",
                    output.display()
                )));
            }
            let request = store.prepare_enrollment(name)?;
            let mut bytes = request.canonical_bytes()?;
            bytes.push(b'\n');
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            if let Some(parent) = output
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                File::open(parent)?.sync_all()?;
            }
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 2,
                        "action": "enrollment_prepared",
                        "client_id": request.body.client_id,
                        "client_name": request.body.display_name,
                        "request": output,
                    }))?
                );
            } else {
                println!("Prepared enrollment for {}.", request.body.display_name);
                println!("Request: {}", output.display());
                println!("Client ID: {}", request.body.client_id);
                println!("Next: transfer this request to an enrolled installation and run:");
                println!("  archive sync approve {}", output.display());
            }
        }
        SyncCommand::Approve { request } => {
            let request_bytes = std::fs::read(request)?;
            let request: archive_ledger::SignedEnrollmentRequest =
                serde_json::from_slice(&request_bytes)?;
            let appended = if store.coordination_required()? {
                let remote = store.coordination_remote()?;
                store.approve_enrollment_coordinated(&remote, &request)?
            } else {
                store.approve_enrollment(&request)?
            };
            let applied = database.apply(&store)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 2,
                        "action": "client_enrolled",
                        "client_id": request.body.client_id,
                        "client_name": request.body.display_name,
                        "batch_id": appended.batch_id,
                        "accepted_frontier_hash": appended.accepted_frontier_hash,
                        "records_applied": applied.records_applied,
                    }))?
                );
            } else {
                println!(
                    "Enrolled {} ({}).",
                    request.body.display_name, request.body.client_id
                );
                println!("Transfer or sync the updated Archive back to that installation before it writes.");
            }
        }
        SyncCommand::Revoke { client, yes } => {
            if !yes {
                return Err(AppError::Input(
                    "revoking an installation requires --yes; accepted history is preserved, but future writes from that client will be refused"
                        .to_owned(),
                ));
            }
            let remote = store.coordination_remote()?;
            let appended = store.revoke_client_coordinated(&remote, client)?;
            let applied = database.apply(&store)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 2,
                        "action": "client_revoked",
                        "client_id": client,
                        "batch_id": appended.batch_id,
                        "accepted_frontier_hash": appended.accepted_frontier_hash,
                        "records_applied": applied.records_applied,
                    }))?
                );
            } else {
                println!("Revoked client {client}.");
                println!("Previously accepted history remains part of the Archive.");
            }
        }
        SyncCommand::Status => {
            let connection = v2_cli_connection(database)?;
            let mut statement = connection
                .prepare(
                    "SELECT client_id, display_name, status, capabilities_json
                     FROM clients ORDER BY display_name, client_id",
                )
                .map_err(|source| v2_cli_sql_error(database, source))?;
            let clients = statement
                .query_map([], |row| {
                    Ok(json!({
                        "client_id": row.get::<_, String>(0)?,
                        "display_name": row.get::<_, String>(1)?,
                        "status": row.get::<_, String>(2)?,
                        "capabilities": serde_json::from_str::<serde_json::Value>(&row.get::<_, String>(3)?)
                            .unwrap_or_else(|_| json!([])),
                    }))
                })
                .map_err(|source| v2_cli_sql_error(database, source))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|source| v2_cli_sql_error(database, source))?;
            let active = store.active_origin_id()?;
            let remotes = store.sync_remotes()?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 2,
                        "active_client_id": active,
                        "clients": clients,
                        "remotes": remotes,
                    }))?
                );
            } else {
                println!("Archive installations:");
                for client in clients {
                    let client_id = client["client_id"].as_str().unwrap_or_default();
                    let marker = if client_id == active {
                        " (this installation)"
                    } else {
                        ""
                    };
                    println!(
                        "  {} — {}{}",
                        client["display_name"].as_str().unwrap_or("Unnamed"),
                        client["status"].as_str().unwrap_or("unknown"),
                        marker
                    );
                    println!("    {client_id}");
                }
                if remotes.is_empty() {
                    println!("Synchronization remotes: none");
                } else {
                    println!("Synchronization remotes:");
                    for remote in remotes {
                        println!("  {}  {}", remote.name, remote.locator);
                    }
                }
            }
        }
    }
    Ok(EXIT_OK)
}

fn execute_db(cli: &Cli, command: &DbCommand) -> Result<u8, AppError> {
    if archive_ledger::is_v2_event_tree(cli.events_path()) {
        let store = V2OriginStore::open(cli.events_path())?;
        match command {
            DbCommand::Apply => {
                let database = V2ProjectionDb::open_existing(cli.database_path())?;
                let stats = database.apply(&store)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&stats)?);
                } else {
                    if stats.records_applied == 0 {
                        println!("SQLite is already current at the accepted frontier.");
                    } else {
                        println!(
                            "Applied {} canonical records; SQLite is current.",
                            stats.records_applied
                        );
                    }
                }
            }
            DbCommand::Rebuild { target } => {
                let target = target.as_deref().unwrap_or_else(|| cli.database_path());
                let stats = V2ProjectionDb::rebuild(&store, target)?;
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&stats)?);
                } else {
                    println!(
                        "Rebuilt SQLite from {} verified canonical records.",
                        stats.records_applied
                    );
                }
            }
        }
        return Ok(EXIT_OK);
    }
    return Err(AppError::Input(
        "this is a pre-v2 development Archive; recreate it with `archive init <name>` and re-import its files"
            .to_owned(),
    ));
    #[allow(unreachable_code)]
    {
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
                let stats = ProjectionDb::rebuild(
                    &events,
                    target,
                    &archive_id,
                    ProjectionConfig::default(),
                )?;
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
        let already_known = result
            .summary
            .files_seen
            .saturating_sub(result.summary.new_paths);
        println!(
            "  {} files observed, {} bytes",
            result.summary.files_seen, result.summary.bytes_seen
        );
        println!(
            "  {} added to this Location; {} already known; {} missing",
            result.summary.new_paths, already_known, result.summary.missing_paths
        );
        println!(
            "  {} integrity-verified now; {} observed without content verification",
            result.summary.integrity_verified_paths,
            result
                .summary
                .files_seen
                .saturating_sub(result.summary.integrity_verified_paths)
        );
        if result.summary.ignored_symlinks > 0 {
            println!(
                "  {} ordinary symlinks ignored (not Archive Ledger Files)",
                result.summary.ignored_symlinks
            );
        }
        if result.summary.content_read_errors > 0 || result.summary.concurrent_changes > 0 {
            println!(
                "  Integrity not confirmed: {} read errors; {} changed during reading",
                result.summary.content_read_errors, result.summary.concurrent_changes
            );
        }
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
    if path_contains_git_metadata(&scope.scan_path) {
        return Err(AppError::Input(
            "generic inventory cannot start inside .git metadata; select the content directory instead"
                .to_owned(),
        ));
    }
    let collection = if let Some(selector) = collection_selector {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_collection_at_location(database, &state, &scope.location.location_id)?
    };
    let imported_annex = database.location_has_completed_annex_import(
        &collection.collection_id,
        &scope.location.location_id,
    )?;
    if !imported_annex && archive_ledger::is_git_annex_repository(&scope.scan_path)? {
        let command = if scan_mode == ScanMode::Add {
            "archive collection add"
        } else {
            "archive location scan"
        };
        return Err(AppError::Input(format!(
            "{command} cannot inventory an unimported git-annex repository; initialize it with --import-annex or use archive location import-annex --collection COLLECTION once"
        )));
    }
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
        if output.summary.ignored_symlinks > 0 {
            println!(
                "  {} ordinary symlinks ignored (not Archive Ledger Files)",
                output.summary.ignored_symlinks
            );
        }
        let other_ignored = output
            .summary
            .ignored_non_annex
            .saturating_sub(output.summary.ignored_symlinks);
        if other_ignored > 0 {
            println!("  {other_ignored} other non-annex entries ignored");
        }
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
                "copy" => {
                    let params = &job.params;
                    let logical_filters = params["logical_filters"]
                        .as_array()
                        .ok_or_else(|| {
                            AppError::Input(format!(
                                "job {job_id} has invalid copy logical filters"
                            ))
                        })?
                        .iter()
                        .map(|value| {
                            value.as_str().map(PathBuf::from).ok_or_else(|| {
                                AppError::Input(format!(
                                    "job {job_id} has a non-string copy logical filter"
                                ))
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    return execute_copy_mutation(
                        cli,
                        database,
                        &CopyMutationArgs {
                            to: Some(json_string(params, "destination_location_id")?),
                            from: Some(json_string(params, "source_location_id")?),
                            collection: Some(json_string(params, "collection_id")?),
                            paths: Vec::new(),
                            dry_run: false,
                            yes: true,
                            non_interactive: true,
                            job_id: Some(job.job_id),
                            max_items: *max_items,
                            logical_filters: Some(logical_filters),
                        },
                    );
                }
                "stage_import" => {
                    let params = &job.params;
                    return execute_stage_import(
                        cli,
                        database,
                        &StageImportArgs {
                            source: PathBuf::from(json_string(params, "source")?),
                            manifest: Some(PathBuf::from(json_string(params, "manifest")?)),
                            collection: Some(json_string(params, "collection_id")?),
                            location: Some(json_string(params, "location_id")?),
                            into: Some(PathBuf::from(json_string(params, "into")?)),
                            dry_run: false,
                            yes: true,
                            non_interactive: true,
                            job_id: Some(job.job_id),
                            destination_root: Some(PathBuf::from(json_string(
                                params,
                                "destination_root",
                            )?)),
                            max_items: *max_items,
                            stop_after_publish: false,
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

fn v2_collection_risk(
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    collection: &CollectionSnapshot,
) -> Result<V2CollectionRisk, AppError> {
    let policy = collection
        .policy_id
        .as_deref()
        .and_then(|id| state.policies.iter().find(|policy| policy.policy_id == id))
        .filter(|policy| policy.enabled && policy.status == "active");
    let connection = v2_cli_connection(database)?;
    let Some(policy) = policy else {
        let values: (i64, i64) = connection
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(COALESCE(o.size_bytes, 0)), 0)
                 FROM file_refs f
                 LEFT JOIN objects o ON o.object_id = f.object_id
                 WHERE f.collection_id = ?1 AND f.path_state = 'active'",
                [&collection.collection_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|source| v2_cli_sql_error(database, source))?;
        let file_count = nonnegative_sql_count(values.0)?;
        return Ok(V2CollectionRisk {
            file_count,
            known_size_bytes: nonnegative_sql_count(values.1)?,
            files_at_risk: 0,
            files_uncertain: file_count,
        });
    };
    let now = i64::try_from(now_utc_ms()?).map_err(|_| AppError::Clock)?;
    let requirements = &policy.requirements;
    let values: (i64, i64, i64, i64) = connection
        .query_row(
            "WITH eligible AS (
                 SELECT DISTINCT c.object_id, c.location_id
                 FROM copy_claims c
                 WHERE c.state = 'present'
                   AND c.last_verification_result = 'ok'
                   AND c.last_seen_time_utc_ms >= ?2
                   AND c.last_verified_time_utc_ms >= ?3
             ), qualifying AS (
                 SELECT e.object_id, l.device_id,
                        COALESCE(d.current_site_id, l.site_id) AS site_id,
                        l.expected_availability, l.encryption_state
                 FROM eligible e
                 JOIN locations l ON l.location_id = e.location_id AND l.status = 'active'
                 LEFT JOIN devices d ON d.device_id = l.device_id AND d.status = 'active'
                 WHERE (
                       l.device_id IS NULL OR
                       (d.device_id IS NOT NULL AND d.last_checkin_time_utc_ms >= ?4)
                   )
             ), coverage AS (
                 SELECT object_id,
                        COUNT(*) AS qualifying_copies,
                        COUNT(DISTINCT device_id) AS devices,
                        COUNT(DISTINCT site_id) AS sites,
                        MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 THEN 1 ELSE 0 END) AS has_offsite,
                        MAX(CASE WHEN expected_availability = 'offline' THEN 1 ELSE 0 END) AS has_offline,
                        MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 AND encryption_state = 'encrypted' THEN 1 ELSE 0 END) AS has_encrypted_offsite
                 FROM qualifying
                 GROUP BY object_id
             )
             SELECT COUNT(*), COALESCE(SUM(COALESCE(o.size_bytes, 0)), 0),
                    COALESCE(SUM(CASE
                        WHEN f.object_id IS NOT NULL AND (
                            COALESCE(c.qualifying_copies, 0) < ?6 OR
                            COALESCE(c.devices, 0) < ?7 OR
                            COALESCE(c.sites, 0) < ?8 OR
                            (?9 = 1 AND COALESCE(c.has_offsite, 0) = 0) OR
                            (?10 = 1 AND COALESCE(c.has_offline, 0) = 0) OR
                            (?11 = 1 AND COALESCE(c.has_encrypted_offsite, 0) = 0)
                        ) THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN f.object_id IS NULL THEN 1 ELSE 0 END), 0)
             FROM file_refs f
             LEFT JOIN objects o ON o.object_id = f.object_id
             LEFT JOIN coverage c ON c.object_id = f.object_id
             WHERE f.collection_id = ?1 AND f.path_state = 'active'",
            params![
                collection.collection_id,
                risk_cutoff(now, requirements.max_observation_age_days),
                risk_cutoff(now, requirements.max_verification_age_days),
                risk_cutoff(now, requirements.max_device_checkin_age_days),
                collection.home_site_id,
                i64::try_from(requirements.min_qualifying_copies).unwrap_or(i64::MAX),
                i64::try_from(requirements.min_devices).unwrap_or(i64::MAX),
                i64::try_from(requirements.min_sites).unwrap_or(i64::MAX),
                i64::from(requirements.require_offsite_copy),
                i64::from(requirements.require_offline_copy),
                i64::from(requirements.require_encrypted_offsite),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    Ok(V2CollectionRisk {
        file_count: nonnegative_sql_count(values.0)?,
        known_size_bytes: nonnegative_sql_count(values.1)?,
        files_at_risk: nonnegative_sql_count(values.2)?,
        files_uncertain: nonnegative_sql_count(values.3)?,
    })
}

fn nonnegative_sql_count(value: i64) -> Result<u64, AppError> {
    u64::try_from(value)
        .map_err(|_| AppError::Input("SQLite contains a negative summary count".to_owned()))
}

fn risk_cutoff(now: i64, max_days: u64) -> i64 {
    now.saturating_sub(i64::try_from(max_days.saturating_mul(86_400_000)).unwrap_or(i64::MAX))
}

fn v2_collection_risk_with_findings(
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    collection: &CollectionSnapshot,
    findings_limit: usize,
) -> Result<(V2CollectionRisk, Vec<V2RiskFinding>), AppError> {
    let policy = collection
        .policy_id
        .as_deref()
        .and_then(|id| state.policies.iter().find(|policy| policy.policy_id == id))
        .filter(|policy| policy.enabled && policy.status == "active");
    let now = i64::try_from(now_utc_ms()?).map_err(|_| AppError::Clock)?;
    let observation_cutoff = policy.map_or(i64::MAX, |policy| {
        now.saturating_sub(
            i64::try_from(
                policy
                    .requirements
                    .max_observation_age_days
                    .saturating_mul(86_400_000),
            )
            .unwrap_or(i64::MAX),
        )
    });
    let verification_cutoff = policy.map_or(i64::MAX, |policy| {
        now.saturating_sub(
            i64::try_from(
                policy
                    .requirements
                    .max_verification_age_days
                    .saturating_mul(86_400_000),
            )
            .unwrap_or(i64::MAX),
        )
    });
    let checkin_cutoff = policy.map_or(i64::MAX, |policy| {
        now.saturating_sub(
            i64::try_from(
                policy
                    .requirements
                    .max_device_checkin_age_days
                    .saturating_mul(86_400_000),
            )
            .unwrap_or(i64::MAX),
        )
    });
    let home_site_id = collection.home_site_id.as_deref();
    let policy_active = i64::from(policy.is_some());
    let connection = v2_cli_connection(database)?;
    let order_clause = if findings_limit == 0 {
        ""
    } else {
        " ORDER BY f.file_ref_id"
    };
    let query = format!(
        "WITH eligible AS (
             SELECT DISTINCT c.object_id, c.location_id
             FROM copy_claims c
             WHERE ?6 = 1
               AND c.state = 'present'
               AND c.last_verification_result = 'ok'
               AND c.last_seen_time_utc_ms >= ?2
               AND c.last_verified_time_utc_ms >= ?3
         ), qualifying AS (
             SELECT e.object_id, l.device_id,
                    COALESCE(d.current_site_id, l.site_id) AS site_id,
                    l.expected_availability, l.encryption_state
             FROM eligible e
             JOIN locations l ON l.location_id = e.location_id AND l.status = 'active'
             LEFT JOIN devices d ON d.device_id = l.device_id AND d.status = 'active'
             WHERE (
                   l.device_id IS NULL OR
                   (d.device_id IS NOT NULL AND d.last_checkin_time_utc_ms >= ?4)
               )
         ), coverage AS (
             SELECT object_id,
                    COUNT(*) AS qualifying_copies,
                    COUNT(DISTINCT device_id) AS devices,
                    COUNT(DISTINCT site_id) AS sites,
                    MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 THEN 1 ELSE 0 END) AS has_offsite,
                    MAX(CASE WHEN expected_availability = 'offline' THEN 1 ELSE 0 END) AS has_offline,
                    MAX(CASE WHEN ?5 IS NOT NULL AND site_id != ?5 AND encryption_state = 'encrypted' THEN 1 ELSE 0 END) AS has_encrypted_offsite
             FROM qualifying
             GROUP BY object_id
         )
         SELECT f.file_ref_id, f.logical_path_display, f.object_id, o.size_bytes,
                COALESCE(c.qualifying_copies, 0), COALESCE(c.devices, 0),
                COALESCE(c.sites, 0), COALESCE(c.has_offsite, 0),
                COALESCE(c.has_offline, 0), COALESCE(c.has_encrypted_offsite, 0)
         FROM file_refs f
         LEFT JOIN objects o ON o.object_id = f.object_id
         LEFT JOIN coverage c ON c.object_id = f.object_id
         WHERE f.collection_id = ?1 AND f.path_state = 'active'{order_clause}"
    );
    let mut statement = connection
        .prepare(&query)
        .map_err(|source| v2_cli_sql_error(database, source))?;
    let mut rows = statement
        .query(params![
            collection.collection_id,
            observation_cutoff,
            verification_cutoff,
            checkin_cutoff,
            home_site_id,
            policy_active,
        ])
        .map_err(|source| v2_cli_sql_error(database, source))?;
    let mut result = V2CollectionRisk::default();
    let mut findings = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|source| v2_cli_sql_error(database, source))?
    {
        let sql_count = |index| -> Result<u64, AppError> {
            let value: i64 = row
                .get(index)
                .map_err(|source| v2_cli_sql_error(database, source))?;
            u64::try_from(value)
                .map_err(|_| AppError::Input("SQLite contains a negative risk count".to_owned()))
        };
        let file = V2FileRiskAccumulator {
            file_ref_id: row
                .get(0)
                .map_err(|source| v2_cli_sql_error(database, source))?,
            logical_path: row
                .get(1)
                .map_err(|source| v2_cli_sql_error(database, source))?,
            object_known: row
                .get::<_, Option<String>>(2)
                .map_err(|source| v2_cli_sql_error(database, source))?
                .is_some(),
            size_bytes: row
                .get::<_, Option<i64>>(3)
                .map_err(|source| v2_cli_sql_error(database, source))?
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
            qualifying_copies: sql_count(4)?,
            devices: sql_count(5)?,
            sites: sql_count(6)?,
            has_offsite: sql_count(7)? != 0,
            has_offline: sql_count(8)? != 0,
            has_encrypted_offsite: sql_count(9)? != 0,
        };
        finalize_v2_file_risk(&mut result, &mut findings, findings_limit, file, policy);
    }
    Ok((result, findings))
}

fn finalize_v2_file_risk(
    result: &mut V2CollectionRisk,
    findings: &mut Vec<V2RiskFinding>,
    findings_limit: usize,
    file: V2FileRiskAccumulator,
    policy: Option<&PolicySnapshot>,
) {
    result.file_count = result.file_count.saturating_add(1);
    result.known_size_bytes = result.known_size_bytes.saturating_add(file.size_bytes);
    let Some(policy) = policy else {
        result.files_uncertain = result.files_uncertain.saturating_add(1);
        push_v2_risk_finding(
            findings,
            findings_limit,
            &file,
            "uncertain",
            vec!["Collection has no active Policy".to_owned()],
        );
        return;
    };
    if !file.object_known {
        result.files_uncertain = result.files_uncertain.saturating_add(1);
        push_v2_risk_finding(
            findings,
            findings_limit,
            &file,
            "uncertain",
            vec!["content identity is unresolved".to_owned()],
        );
        return;
    }
    let requirements = &policy.requirements;
    let copies = file.qualifying_copies;
    let devices = file.devices;
    let sites = file.sites;
    let mut reasons = Vec::new();
    if copies < requirements.min_qualifying_copies {
        reasons.push(format!(
            "{copies} qualifying copies; Policy requires {}",
            requirements.min_qualifying_copies
        ));
    }
    if devices < requirements.min_devices {
        reasons.push(format!(
            "{devices} Devices; Policy requires {}",
            requirements.min_devices
        ));
    }
    if sites < requirements.min_sites {
        reasons.push(format!(
            "{sites} Sites; Policy requires {}",
            requirements.min_sites
        ));
    }
    if requirements.require_offsite_copy && !file.has_offsite {
        reasons.push("no qualifying offsite copy".to_owned());
    }
    if requirements.require_offline_copy && !file.has_offline {
        reasons.push("no qualifying offline copy".to_owned());
    }
    if requirements.require_encrypted_offsite && !file.has_encrypted_offsite {
        reasons.push("no qualifying encrypted offsite copy".to_owned());
    }
    if !reasons.is_empty() {
        result.files_at_risk = result.files_at_risk.saturating_add(1);
        push_v2_risk_finding(findings, findings_limit, &file, "violated", reasons);
    }
}

fn push_v2_risk_finding(
    findings: &mut Vec<V2RiskFinding>,
    limit: usize,
    file: &V2FileRiskAccumulator,
    result: &str,
    reasons: Vec<String>,
) {
    if findings.len() >= limit {
        return;
    }
    findings.push(V2RiskFinding {
        file_ref_id: file.file_ref_id.clone(),
        logical_path: file.logical_path.clone(),
        object_known: file.object_known,
        qualifying_copies: file.qualifying_copies,
        devices: file.devices,
        sites: file.sites,
        result: result.to_owned(),
        reasons,
    });
}

fn v2_location_metrics(
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    location_id: &str,
) -> Result<V2LocationMetrics, AppError> {
    let stale_after_days = state
        .collections
        .iter()
        .filter_map(|collection| collection.policy_id.as_deref())
        .filter_map(|id| state.policies.iter().find(|policy| policy.policy_id == id))
        .filter(|policy| policy.enabled && policy.status == "active")
        .map(|policy| policy.requirements.max_observation_age_days)
        .min()
        .unwrap_or(365);
    let now = i64::try_from(now_utc_ms()?).map_err(|_| AppError::Clock)?;
    let cutoff = now.saturating_sub(
        i64::try_from(stale_after_days.saturating_mul(86_400_000)).unwrap_or(i64::MAX),
    );
    let (files, bytes, stale): (i64, i64, i64) = v2_cli_connection(database)?
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(o.size_bytes), 0),
                    COALESCE(SUM(CASE WHEN c.last_seen_time_utc_ms IS NULL OR c.last_seen_time_utc_ms < ?2 THEN 1 ELSE 0 END), 0)
             FROM copy_claims c
             LEFT JOIN objects o ON o.object_id = c.object_id
             WHERE c.location_id = ?1 AND c.state = 'present'",
            params![location_id, cutoff],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    Ok(V2LocationMetrics {
        file_count: u64::try_from(files).unwrap_or(0),
        space_used_bytes: u64::try_from(bytes).unwrap_or(0),
        stale_presence_count: u64::try_from(stale).unwrap_or(0),
        stale_after_days,
    })
}

fn v2_collection_location_ids(
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    collection_id: &str,
) -> Result<BTreeSet<String>, AppError> {
    let connection = v2_cli_connection(database)?;
    let mut statement = connection
        .prepare(
            "SELECT location_id FROM (
                 SELECT DISTINCT p.location_id
                 FROM path_observations p JOIN file_refs f ON f.file_ref_id = p.file_ref_id
                 WHERE f.collection_id = ?1
                 UNION
                 SELECT DISTINCT location_id FROM scan_runs WHERE collection_id = ?1
                 UNION
                 SELECT DISTINCT worktree_location_id FROM annex_imports WHERE collection_id = ?1
             ) ORDER BY location_id",
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    let mut ids = statement
        .query_map([collection_id], |row| row.get::<_, String>(0))
        .map_err(|source| v2_cli_sql_error(database, source))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()
        .map_err(|source| v2_cli_sql_error(database, source))?;
    if ids.is_empty() && state.collections.len() == 1 {
        ids.extend(
            state
                .locations
                .iter()
                .map(|location| location.location_id.clone()),
        );
    }
    Ok(ids)
}

fn execute_v2_status(cli: &Cli) -> Result<u8, AppError> {
    let database = V2ProjectionDb::open_existing(cli.database_path())?;
    let status = database.status()?;
    let state = database.registry_state(false)?;
    let collections = state
        .collections
        .iter()
        .map(|collection| {
            Ok((
                collection,
                v2_collection_risk(&database, &state, collection)?,
            ))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let has_findings = collections
        .iter()
        .any(|(_, summary)| summary.files_at_risk > 0 || summary.files_uncertain > 0)
        || status.unresolved_conflicts > 0;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "archive_id": status.archive_id,
                "archive_name": status.archive_name,
                "schema_version": status.schema_version,
                "event_tree_version": status.event_tree_version,
                "genesis_hash": status.genesis_hash,
                "accepted_frontier_hash": status.accepted_frontier_hash,
                "applied_frontier_hash": status.applied_frontier_hash,
                "records": status.records,
                "origins": status.origins,
                "collections": collections.iter().map(|(collection, summary)| json!({
                    "collection_id": collection.collection_id,
                    "collection_name": collection.display_name,
                    "file_count": summary.file_count,
                    "known_size_bytes": summary.known_size_bytes,
                    "files_at_risk": summary.files_at_risk,
                    "files_uncertain": summary.files_uncertain,
                })).collect::<Vec<_>>(),
                "collection_count": collections.len(),
                "unresolved_conflicts": status.unresolved_conflicts,
            }))?
        );
    } else {
        println!("Archive: {}", status.archive_name);
        if collections.is_empty() {
            println!("No Collections yet.");
            println!("Next: go to your files and run archive collection init --name <name>");
        } else {
            println!("Collections:");
            for (collection, summary) in &collections {
                println!(
                    "  {} — {} files; {} at risk; {} uncertain",
                    collection.display_name,
                    summary.file_count,
                    summary.files_at_risk,
                    summary.files_uncertain,
                );
            }
        }
        if status.unresolved_conflicts > 0 {
            println!(
                "WARNING: {} unresolved metadata conflicts need review.",
                status.unresolved_conflicts
            );
        }
    }
    Ok(if has_findings { EXIT_FINDINGS } else { EXIT_OK })
}

fn execute_status(database: &ProjectionDb, as_json: bool) -> Result<u8, AppError> {
    let projection = database.status()?;
    let status = current_policy_status(database)?;
    let metadata = database.metadata_protection_status()?;
    let collections = database.registry_state(false)?.collections;
    let collection_statuses = collections
        .iter()
        .map(|collection| database.collection_summary(&collection.collection_id))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let collection_rows = collection_statuses
        .iter()
        .map(|collection| ArchiveCollectionStatus {
            collection_id: collection.collection_id.clone(),
            collection_name: collection.collection_name.clone(),
            file_count: collection.file_count,
            files_at_risk: collection.files_at_risk,
            files_uncertain: collection.uncertain_files,
        })
        .collect::<Vec<_>>();
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
                collections: collection_rows,
                policy: status,
                metadata,
            })?
        );
    } else {
        println!("Archive: {}", projection.archive_display_name);
        if collections.is_empty() {
            println!("No Collections yet.");
            println!("Next: go to your files and run archive collection init --name <name>");
        } else {
            println!("Collections:");
            for collection in &collection_statuses {
                match (collection.files_at_risk, collection.uncertain_files) {
                    (Some(at_risk), Some(uncertain)) => println!(
                        "  {} — {} files; {} at risk; {} uncertain",
                        collection.collection_name, collection.file_count, at_risk, uncertain
                    ),
                    _ => println!(
                        "  {} — {} files; risk unavailable (configure a Policy)",
                        collection.collection_name, collection.file_count
                    ),
                }
            }
            let files_total = collection_statuses
                .iter()
                .map(|collection| collection.file_count)
                .sum::<u64>();
            let files_at_risk = collection_statuses
                .iter()
                .filter_map(|collection| collection.files_at_risk)
                .sum::<u64>();
            let files_uncertain = collection_statuses
                .iter()
                .filter_map(|collection| collection.uncertain_files)
                .sum::<u64>();
            if files_total == 0 {
                if collections.len() == 1 {
                    println!(
                        "Next: go to its Location and run archive collection add . --collection {}",
                        shell_quote(&collections[0].display_name)
                    );
                } else {
                    println!(
                        "Next: go to a registered Location and run archive collection add . --collection COLLECTION"
                    );
                }
            } else if files_at_risk > 0 || files_uncertain > 0 {
                println!("Next: archive report risk");
            }
        }
        if metadata.unreplicated_events > 0 {
            println!(
                "Metadata: {} catalog change(s) are not independently protected. Next: archive report metadata",
                metadata.unreplicated_events
            );
        } else if metadata.catalog_location_id.is_none() {
            println!(
                "Metadata: catalog storage Location is not recorded. Next: archive report metadata"
            );
        } else {
            println!("Metadata: independently protected through the current catalog state.");
        }
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

fn execute_stage(cli: &Cli, database: &ProjectionDb, args: &StageArgs) -> Result<u8, AppError> {
    if let Some(StageCommand::Import(import)) = &args.command {
        return execute_stage_import(cli, database, import);
    }
    if archive_ledger::is_git_annex_repository(&args.path)? {
        return Err(AppError::Input(
            "archive stage does not audit a git-annex worktree; import that repository with archive location import-annex so annex pointers are interpreted safely"
                .to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    let collection_id = args
        .collection
        .as_deref()
        .map(|selector| {
            select_collection(&state.collections, selector)?
                .map(|value| value.collection_id)
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))
        })
        .transpose()?;
    let report = archive_ledger::audit_stage(
        database,
        &StageAuditOptions {
            source: args.path.clone(),
            manifest: args.manifest.clone(),
            collection_id,
            list_limit: args.limit,
        },
    )?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Staged: {}", report.source.display());
        println!(
            "Files: {} ({}); checksums: {} computed, {} reused",
            report.files_seen,
            format_bytes(report.bytes_seen),
            report.checksums_computed,
            report.checksums_reused
        );
        println!(
            "New to this Archive: {} files / {} unique contents",
            report.new_to_archive_files, report.new_to_archive_objects
        );
        if report.selected_collection_id.is_some() {
            println!(
                "Already cataloged: {} in the selected Collection; {} only in other Collections",
                report.known_in_selected_collection, report.known_only_in_other_collections
            );
        } else {
            println!(
                "Already cataloged: {}",
                report
                    .known_in_selected_collection
                    .saturating_add(report.known_only_in_other_collections)
            );
        }
        println!(
            "Protection of cataloged files: {} policy-satisfied; {} at risk; {} unknown",
            report.known_policy_satisfied_files,
            report.known_at_risk_files,
            report.known_policy_unknown_files
        );
        if report.duplicate_files > 0 {
            println!(
                "Duplicate staged paths sharing content: {}",
                report.duplicate_files
            );
        }
        if !report.listed_files.is_empty() {
            println!("New files:");
            for file in &report.listed_files {
                println!(
                    "  {}  ({})",
                    file.path_display,
                    format_bytes(file.size_bytes)
                );
            }
            if report.listed_files_truncated {
                println!(
                    "  …more not shown; rerun with --limit {} or use --json",
                    report.new_to_archive_files
                );
            }
        }
        if report.ignored_symlinks > 0 || report.special_files > 0 {
            println!(
                "Ignored: {} symlinks; {} special files",
                report.ignored_symlinks, report.special_files
            );
        }
        if report.audit_status != "complete" {
            println!(
                "Audit partial: {} traversal errors; {} read errors; {} changed during reading",
                report.traversal_errors, report.content_read_errors, report.concurrent_changes
            );
        }
        println!("Checksum manifest: {}", report.manifest.display());
        if report.source_removal_ready {
            println!(
                "Source removal readiness: READY — every staged file is cataloged and satisfies every active owning Collection policy."
            );
        } else {
            println!("Source removal readiness: NOT READY.");
            if report.known_policy_unknown_files > 0 {
                println!(
                    "Policy evidence is missing or stale for some files. Run archive report risk, then rerun archive stage before considering source removal."
                );
            }
            if report.new_to_archive_files > 0 || report.known_at_risk_files > 0 {
                println!(
                    "Keep the source until new files are imported and every at-risk file has enough verified copies across the required risk domains."
                );
            }
        }
        if !report.manifest_is_source_local {
            println!(
                "The source was not writable. Preserve this manifest and pass --manifest when importing."
            );
        }
        if report.new_to_archive_files > 0 {
            let manifest = if report.manifest_is_source_local {
                String::new()
            } else {
                format!(
                    " --manifest {}",
                    shell_quote(&report.manifest.to_string_lossy())
                )
            };
            println!(
                "Next: from a registered destination Location, run archive stage import {}{}",
                shell_quote(&report.source.to_string_lossy()),
                manifest
            );
        }
    }
    Ok(if !report.source_removal_ready {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    })
}

fn execute_stage_import(
    cli: &Cli,
    database: &ProjectionDb,
    args: &StageImportArgs,
) -> Result<u8, AppError> {
    if args.non_interactive && !args.dry_run && !args.yes {
        return Err(AppError::Input(
            "stage import in non-interactive mode requires --yes (or use --dry-run)".to_owned(),
        ));
    }
    let reviewed_plan =
        archive_ledger::prepare_stage_import(database, &args.source, args.manifest.as_deref())?;
    let source = reviewed_plan.source.clone();
    let manifest = reviewed_plan.manifest.clone();
    let state = database.registry_state(false)?;
    let requested_destination = args
        .destination_root
        .clone()
        .unwrap_or(std::env::current_dir()?);
    let destination_cwd = std::fs::canonicalize(&requested_destination).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve destination directory {}: {error}",
            requested_destination.display()
        ))
    })?;
    let scope = resolve_inventory_location(
        cli,
        database,
        &state,
        args.location.as_deref(),
        Some(&destination_cwd),
    )?;
    let collection = if let Some(selector) = args.collection.as_deref() {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_collection_at_location(database, &state, &scope.location.location_id)?
    };
    if source.starts_with(&destination_cwd) || destination_cwd.starts_with(&source) {
        return Err(AppError::Input(
            "stage source and destination must not contain one another".to_owned(),
        ));
    }
    let into = args.into.clone().unwrap_or_else(|| {
        source
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| "staged-import".into())
    });
    validate_single_destination_component(&into)?;
    let import_root = destination_cwd.join(&into);
    let resuming = args.job_id.is_some();
    if !resuming && std::fs::symlink_metadata(&import_root).is_ok() {
        return Err(AppError::Input(format!(
            "stage import destination already exists; choose a new --into name: {}",
            import_root.display()
        )));
    }
    let total_bytes = reviewed_plan.eligible_bytes;
    let available = available_space(&destination_cwd)?;
    if !resuming && total_bytes > available {
        return Err(AppError::Input(format!(
            "stage import needs {} but only {} is available at the destination",
            format_bytes(total_bytes),
            format_bytes(available)
        )));
    }
    if cli.json && args.dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "status": "planned",
                "source": source,
                "manifest": manifest,
                "destination": import_root,
                "collection_id": collection.collection_id,
                "location_id": scope.location.location_id,
                "files": reviewed_plan.eligible_files,
                "bytes": total_bytes,
                "ledger_changed": false,
            }))?
        );
        return Ok(EXIT_OK);
    }
    if !cli.json {
        println!(
            "Stage import plan: {} new files ({})",
            reviewed_plan.eligible_files,
            format_bytes(total_bytes)
        );
        println!("From: {}", source.display());
        println!("To: {}", import_root.display());
        println!(
            "Collection: {}; Location: {}",
            collection.display_name, scope.location.display_name
        );
        if args.dry_run {
            println!("Dry run: no files or ledger facts were changed.");
            return Ok(EXIT_OK);
        }
    } else if args.dry_run {
        unreachable!("JSON dry run returned above");
    }
    if reviewed_plan.eligible_files == 0 && !resuming {
        if !cli.json {
            println!("Nothing to import; every stable staged file is already cataloged.");
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 1,
                    "status": "nothing_to_import",
                    "source": source,
                    "manifest": manifest,
                    "files": 0,
                    "bytes": 0,
                }))?
            );
        }
        return Ok(EXIT_OK);
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::Input(
                "stage import requires confirmation; rerun with --yes or inspect it first with --dry-run"
                    .to_owned(),
            ));
        }
        if !prompt_confirmation("Copy and verify these new files?")? {
            return Err(AppError::Input("stage import cancelled".to_owned()));
        }
    }

    let suffix = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{suffix}"));
    if !job_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(AppError::Input("invalid stage import job ID".to_owned()));
    }
    let input_version = reviewed_plan.input_version().to_owned();
    let params_value = json!({
        "source": source,
        "manifest": manifest,
        "destination_root": destination_cwd,
        "into": into,
        "collection_id": collection.collection_id,
        "location_id": scope.location.location_id,
    });
    start_local_job(
        database,
        &job_id,
        "stage_import",
        &input_version,
        &params_value,
    )?;
    let stored_job = local_job(database, &job_id)?
        .ok_or_else(|| AppError::Input(format!("stage import job disappeared: {job_id}")))?;
    if stored_job.params != params_value {
        return Err(AppError::Input(format!(
            "stage import job {job_id} belongs to a different source or destination"
        )));
    }
    let plan = archive_ledger::select_stage_import(database, reviewed_plan, &job_id)?;
    let events = open_event_store(cli)?;
    record_job_marker(
        &events,
        database,
        &job_id,
        "stage_import",
        &input_version,
        "started",
    )?;

    if plan.eligible_files == 0 {
        update_local_job(
            database,
            &job_id,
            "complete",
            &json!({"phase": "complete", "files": 0, "bytes": 0}),
        )?;
        record_job_marker(
            &events,
            database,
            &job_id,
            "stage_import",
            &input_version,
            "complete",
        )?;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 1,
                    "job_id": job_id,
                    "status": "nothing_to_import",
                    "files": 0,
                    "bytes": 0,
                }))?
            );
        } else {
            println!("Nothing to import; the reviewed content was cataloged before copying began.");
        }
        return Ok(EXIT_OK);
    }

    let temporary_root = destination_cwd.join(format!(".archive-ledger-import-{job_id}.tmp"));
    let temporary_exists = std::fs::symlink_metadata(&temporary_root).is_ok();
    let published = std::fs::symlink_metadata(&import_root).is_ok();
    if temporary_exists && published {
        return Err(AppError::Input(format!(
            "stage import job {job_id} has both a temporary and published tree; inspect {} and {} before resuming",
            temporary_root.display(),
            import_root.display()
        )));
    }
    if published && !resuming {
        return Err(AppError::Input(format!(
            "stage import destination already exists; refusing to adopt it: {}",
            import_root.display()
        )));
    }
    if !temporary_exists && !published {
        std::fs::create_dir(&temporary_root)?;
    }
    let mut temporary_tree = (!published).then(|| TemporaryImportTree {
        path: temporary_root.clone(),
        keep: temporary_exists,
    });
    let working_root = if published {
        &import_root
    } else {
        &temporary_root
    };
    let mut processed_files = 0_u64;
    let mut processed_bytes = 0_u64;
    let mut processed_this_run = 0_usize;
    let mut interrupted = false;
    let mut cursor = None;
    'pages: loop {
        let page =
            archive_ledger::stage_import_candidates(database, &plan, cursor.as_ref(), 1_000)?;
        for candidate in &page.items {
            if args
                .max_items
                .is_some_and(|limit| processed_this_run >= limit)
            {
                interrupted = true;
                break 'pages;
            }
            let source_path = source.join(&candidate.relative_path);
            let destination_path = working_root.join(&candidate.relative_path);
            if !destination_path.starts_with(working_root) {
                return Err(AppError::Input(format!(
                    "staged path escapes the destination: {}",
                    candidate.path_display
                )));
            }
            let verified = match std::fs::symlink_metadata(&destination_path) {
                Ok(_) => {
                    if let Some(tree) = &mut temporary_tree {
                        tree.keep = true;
                    }
                    archive_ledger::verify_existing_file(&destination_path, &candidate.blake3_hex)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !published => {
                    if let Some(parent) = destination_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    archive_ledger::copy_verified_no_replace(
                        &source_path,
                        &destination_path,
                        &candidate.blake3_hex,
                    )?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AppError::Input(format!(
                        "published stage import is missing reviewed file {}; refusing recovery",
                        candidate.path_display
                    )))
                }
                Err(error) => return Err(error.into()),
            };
            processed_files = processed_files.saturating_add(1);
            processed_bytes = processed_bytes.saturating_add(verified.bytes_copied);
            processed_this_run = processed_this_run.saturating_add(1);
        }
        let Some(next) = page.next else {
            break;
        };
        cursor = Some(next);
    }
    if interrupted {
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
        update_local_job(
            database,
            &job_id,
            "running",
            &json!({
                "phase": "copying",
                "files_verified_this_run": processed_files,
                "bytes_verified_this_run": processed_bytes,
                "eligible_files": plan.eligible_files,
            }),
        )?;
        print_stage_import_running(
            cli.json,
            &job_id,
            "copying",
            processed_files,
            processed_bytes,
        )?;
        return Ok(EXIT_OK);
    }
    if let Err(error) = validate_import_tree(working_root, plan.eligible_files) {
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
        return Err(error);
    }
    if !published {
        archive_ledger::place_directory_no_replace(&temporary_root, &import_root)?;
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
    }
    update_local_job(
        database,
        &job_id,
        "running",
        &json!({
            "phase": "published",
            "files": processed_files,
            "bytes": processed_bytes,
            "destination": import_root,
        }),
    )?;
    if args.stop_after_publish {
        print_stage_import_running(
            cli.json,
            &job_id,
            "published",
            processed_files,
            processed_bytes,
        )?;
        return Ok(EXIT_OK);
    }
    if !cli.json {
        println!(
            "Copied and independently verified {} files ({}). Recording them in the Collection...",
            processed_files,
            format_bytes(processed_bytes)
        );
    }
    let exit_code = execute_location_inventory(
        cli,
        database,
        Some(&import_root),
        Some(&scope.location.location_id),
        Some(&collection.collection_id),
        &[],
        None,
        None,
        1_000,
        None,
        ScanMode::Add,
    )?;
    if exit_code == EXIT_OK {
        update_local_job(
            database,
            &job_id,
            "complete",
            &json!({
                "phase": "complete",
                "files": plan.eligible_files,
                "bytes": plan.eligible_bytes,
                "destination": import_root,
            }),
        )?;
        record_job_marker(
            &events,
            database,
            &job_id,
            "stage_import",
            &input_version,
            "complete",
        )?;
        if !cli.json {
            println!("Stage import complete ({job_id}).");
        }
    } else {
        update_local_job(
            database,
            &job_id,
            "running",
            &json!({"phase": "recording", "destination": import_root}),
        )?;
        if !cli.json {
            println!("Stage import remains resumable: archive job resume {job_id}");
        }
    }
    Ok(exit_code)
}

fn print_stage_import_running(
    as_json: bool,
    job_id: &str,
    phase: &str,
    files: u64,
    bytes: u64,
) -> Result<(), AppError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "job_id": job_id,
                "status": "running",
                "phase": phase,
                "files_verified_this_run": files,
                "bytes_verified_this_run": bytes,
            }))?
        );
    } else {
        println!(
            "Stage import paused after verifying {} files ({}); phase: {}.",
            files,
            format_bytes(bytes),
            phase
        );
        println!("Resume with: archive job resume {job_id}");
    }
    Ok(())
}

fn validate_import_tree(root: &Path, expected_files: u64) -> Result<(), AppError> {
    let mut regular_files = 0_u64;
    let discovery = FileDiscovery::new(root).map_err(|error| {
        AppError::Input(format!(
            "cannot validate stage import tree {}: {error}",
            root.display()
        ))
    })?;
    for item in discovery {
        match item {
            DiscoveryItem::File(_) => regular_files = regular_files.saturating_add(1),
            DiscoveryItem::Excluded(_) => unreachable!("stage import tree has no exclusions"),
            DiscoveryItem::Symlink(path) => {
                return Err(AppError::Input(format!(
                    "stage import tree contains an unexpected symlink: {}",
                    path.display
                )))
            }
            DiscoveryItem::Special(path) => {
                return Err(AppError::Input(format!(
                    "stage import tree contains an unexpected special file: {}",
                    path.display
                )))
            }
            DiscoveryItem::FilesystemBoundary(path) => {
                return Err(AppError::Input(format!(
                    "stage import tree crosses a filesystem boundary: {}",
                    path.display
                )))
            }
            DiscoveryItem::ConcurrentChange(path) => {
                return Err(AppError::Input(format!(
                    "stage import tree changed during validation: {}",
                    path.map(|value| value.display)
                        .unwrap_or_else(|| root.display().to_string())
                )))
            }
            DiscoveryItem::Error {
                relative_path,
                error,
            } => {
                return Err(AppError::Input(format!(
                    "cannot validate stage import tree {}: {error}",
                    relative_path
                        .map(|value| value.display)
                        .unwrap_or_else(|| root.display().to_string())
                )))
            }
        }
    }
    if regular_files != expected_files {
        return Err(AppError::Input(format!(
            "stage import tree contains {regular_files} regular files but the reviewed selection contains {expected_files}; refusing publication or recovery"
        )));
    }
    Ok(())
}

fn validate_single_destination_component(path: &Path) -> Result<(), AppError> {
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(AppError::Input(format!(
            "--into must be one new directory name beneath cwd, not {}",
            path.display()
        )));
    }
    Ok(())
}

fn execute_copy_mutation(
    cli: &Cli,
    database: &ProjectionDb,
    args: &CopyMutationArgs,
) -> Result<u8, AppError> {
    let destination_selector = args.to.as_deref().ok_or_else(|| {
        AppError::Input(
            "archive copy requires --to LOCATION, or use archive copy list|show for review"
                .to_owned(),
        )
    })?;
    if args.non_interactive && !args.dry_run && !args.yes {
        return Err(AppError::Input(
            "copy in non-interactive mode requires --yes (or use --dry-run)".to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    let cwd = std::fs::canonicalize(std::env::current_dir()?)?;
    let source =
        resolve_inventory_location(cli, database, &state, args.from.as_deref(), Some(&cwd))?;
    let destination =
        resolve_inventory_location(cli, database, &state, Some(destination_selector), None)?;
    if source.location.location_id == destination.location.location_id {
        return Err(AppError::Input(
            "copy source and destination must be different Locations".to_owned(),
        ));
    }
    if !destination.location.is_writable {
        return Err(AppError::Input(format!(
            "destination Location {} is registered read-only",
            destination.location.display_name
        )));
    }
    let collection = if let Some(selector) = args.collection.as_deref() {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_collection_at_location(database, &state, &source.location.location_id)?
    };
    let filters = if let Some(filters) = &args.logical_filters {
        filters.clone()
    } else {
        copy_logical_filters(&source.location_path, &cwd, &args.paths)?
    };
    let mut summary = visit_archive_copy_items(
        database,
        &collection.collection_id,
        &source.location.location_id,
        &destination.location.location_id,
        &filters,
        |item| {
            let source_path = source.location_path.join(&item.source_relative_path);
            let metadata = std::fs::symlink_metadata(&source_path).map_err(|error| {
                AppError::Input(format!(
                    "copy source is unavailable at {}: {error}",
                    source_path.display()
                ))
            })?;
            if !metadata.file_type().is_file() {
                return Err(AppError::Input(format!(
                    "copy source is not a regular file: {}",
                    source_path.display()
                )));
            }
            let destination_path = destination.location_path.join(&item.logical_path);
            if !destination_path.starts_with(&destination.location_path) {
                return Err(AppError::Input(format!(
                    "copy destination escapes its Location: {}",
                    item.logical_path_display
                )));
            }
            ensure_safe_destination_parents(&destination.location_path, &item.logical_path)?;
            match std::fs::symlink_metadata(&destination_path) {
                Ok(_) if args.job_id.is_some() => {
                    archive_ledger::verify_existing_file(&destination_path, &item.blake3_hex)?;
                    Ok(())
                }
                Ok(_) => Err(AppError::Input(format!(
                    "copy destination already exists; refusing to overwrite it: {}",
                    destination_path.display()
                ))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        },
    )?;
    if summary.selected_logical_files == 0 {
        return Err(AppError::Input(
            "no cataloged logical files match the requested copy paths".to_owned(),
        ));
    }
    let objects_to_copy = summary
        .selected_unique_objects
        .saturating_sub(summary.already_present_objects);
    if objects_to_copy == 0 {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 1,
                    "status": "nothing_to_copy",
                    "source_location_id": source.location.location_id,
                    "destination_location_id": destination.location.location_id,
                    "collection_id": collection.collection_id,
                    "summary": summary,
                }))?
            );
        } else {
            println!(
                "Nothing to copy; all {} selected unique Objects are already present at {}.",
                summary.selected_unique_objects, destination.location.display_name
            );
        }
        return Ok(EXIT_OK);
    }

    let needed_bytes = summary.bytes_to_copy;
    let available = available_space(&destination.location_path)?;
    if needed_bytes > available {
        return Err(AppError::Input(format!(
            "copy needs {} but only {} is available at the destination",
            format_bytes(needed_bytes),
            format_bytes(available)
        )));
    }
    if cli.json && args.dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "status": "planned",
                "source_location_id": source.location.location_id,
                "destination_location_id": destination.location.location_id,
                "collection_id": collection.collection_id,
                "bytes_to_copy": needed_bytes,
                "summary": summary,
            }))?
        );
        return Ok(EXIT_OK);
    }
    if !cli.json {
        println!(
            "Copy plan: {} unique Objects ({}) from {} to {}.",
            objects_to_copy,
            format_bytes(needed_bytes),
            source.location.display_name,
            destination.location.display_name
        );
        if args.dry_run {
            println!("Dry run: no files or ledger facts were changed.");
            return Ok(EXIT_OK);
        }
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::Input(
                "copy requires confirmation; rerun with --yes or inspect it first with --dry-run"
                    .to_owned(),
            ));
        }
        if !prompt_confirmation("Copy and verify these Objects?")? {
            return Err(AppError::Input("copy cancelled".to_owned()));
        }
    }

    let filter_text = serde_json::to_string(
        &filters
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
    )?;
    let input_version = stable_id(
        "copy_input",
        &[
            collection.collection_id.as_bytes(),
            source.location.location_id.as_bytes(),
            destination.location.location_id.as_bytes(),
            filter_text.as_bytes(),
        ],
    );
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    start_local_job(
        database,
        &job_id,
        "copy",
        &input_version,
        &json!({
            "source_location_id": source.location.location_id,
            "source_location_path": source.location_path,
            "destination_location_id": destination.location.location_id,
            "collection_id": collection.collection_id,
            "logical_filters": filters,
        }),
    )?;
    let events = open_event_store(cli)?;
    record_job_marker(
        &events,
        database,
        &job_id,
        "copy",
        &input_version,
        "started",
    )?;
    let device_id = destination
        .location
        .device_id
        .clone()
        .ok_or_else(|| AppError::Input("destination Location has no Device".to_owned()))?;
    let checkin_operation = stable_id("op", &[job_id.as_bytes(), b"destination_checkin"]);
    if !database.has_operation_key(&checkin_operation)? {
        events.append(
            EventRequest::new(
                "device_checked_in",
                json!({
                    "device_id": device_id,
                    "fingerprint_status": destination.fingerprint_status,
                    "operation_key": checkin_operation,
                    "job_type": "copy", "item_type": "device",
                    "item_key": device_id, "outcome_kind": "checked_in",
                }),
            )
            .with_references(EventReferences {
                job_id: Some(job_id.clone()),
                device_id: Some(device_id.clone()),
                ..EventReferences::default()
            }),
        )?;
        database.apply(&events)?;
    }

    let mut processed_items = 0_usize;
    let mut interrupted = false;
    visit_archive_copy_items(
        database,
        &collection.collection_id,
        &source.location.location_id,
        &destination.location.location_id,
        &filters,
        |item| {
            if args.max_items.is_some_and(|limit| processed_items >= limit) {
                interrupted = true;
                return Ok(());
            }
            processed_items += 1;
            let source_path = source.location_path.join(&item.source_relative_path);
            let destination_path = destination.location_path.join(&item.logical_path);
            if let Some(parent) = destination_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let started = Instant::now();
            let copied = match std::fs::symlink_metadata(&destination_path) {
                Ok(_) if args.job_id.is_some() => {
                    archive_ledger::verify_existing_file(&destination_path, &item.blake3_hex)?
                }
                Ok(_) => {
                    return Err(AppError::Input(format!(
                        "copy destination appeared after planning; refusing to overwrite it: {}",
                        destination_path.display()
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    archive_ledger::copy_verified_no_replace(
                        &source_path,
                        &destination_path,
                        &item.blake3_hex,
                    )?
                }
                Err(error) => return Err(error.into()),
            };
            let relative = RegistryPath::from_path(&item.logical_path);
            let copy_claim_id = stable_id(
                "copy",
                &[
                    destination.location.location_id.as_bytes(),
                    item.logical_path_encoding.as_bytes(),
                    &item.logical_path_bytes,
                ],
            );
            let item_operation = stable_id(
                "op",
                &[
                    job_id.as_bytes(),
                    item.object_id.as_bytes(),
                    destination.location.location_id.as_bytes(),
                ],
            );
            let modified_time = std::fs::metadata(&destination_path)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .and_then(|value| u64::try_from(value.as_millis()).ok());
            let requests = vec![
            EventRequest::new(
                "path_observed",
                json!({
                    "file_ref_id": item.file_ref_id,
                    "location_id": destination.location.location_id,
                    "observed_path": relative,
                    "representation": "ordinary_file",
                    "object_id": item.object_id,
                    "external_identity_id": null,
                    "state": "present",
                    "observed_size_bytes": item.size_bytes,
                    "modified_time_utc_ms": modified_time,
                    "operation_key": format!("{item_operation}_path"),
                    "job_type": "copy", "item_type": "path",
                    "item_key": item.file_ref_id, "outcome_kind": "present",
                }),
            )
            .with_references(EventReferences {
                job_id: Some(job_id.clone()),
                object_id: Some(item.object_id.clone()),
                file_ref_id: Some(item.file_ref_id.clone()),
                location_id: Some(destination.location.location_id.clone()),
                device_id: Some(device_id.clone()),
                ..EventReferences::default()
            }),
            EventRequest::new(
                "copy_observed",
                json!({
                    "copy_claim_id": copy_claim_id,
                    "location_id": destination.location.location_id,
                    "relative_path": relative,
                    "object_id": item.object_id,
                    "external_identity_id": null,
                    "claim_basis": "observed_bytes",
                    "state": "present",
                    "operation_key": format!("{item_operation}_copy"),
                    "job_type": "copy", "item_type": "copy",
                    "item_key": copy_claim_id, "outcome_kind": "present",
                }),
            )
            .with_references(EventReferences {
                job_id: Some(job_id.clone()),
                object_id: Some(item.object_id.clone()),
                file_ref_id: Some(item.file_ref_id.clone()),
                copy_claim_id: Some(copy_claim_id.clone()),
                location_id: Some(destination.location.location_id.clone()),
                device_id: Some(device_id.clone()),
                ..EventReferences::default()
            }),
            EventRequest::new(
                "copy_verified",
                json!({
                    "verification_id": stable_id("verify", &[job_id.as_bytes(), copy_claim_id.as_bytes()]),
                    "copy_claim_id": copy_claim_id,
                    "object_id": item.object_id,
                    "location_id": destination.location.location_id,
                    "result": "ok",
                    "expected_hash_algo": "blake3",
                    "expected_hash_hex": item.blake3_hex,
                    "observed_hash_hex": copied.blake3_hex,
                    "size_bytes": item.size_bytes,
                    "bytes_read": copied.bytes_copied,
                    "duration_ms": elapsed_ms(started),
                    "path_observed": relative,
                    "device_fingerprint_status": destination.fingerprint_status,
                    "error_code": null,
                    "error_detail": null,
                    "operation_key": format!("{item_operation}_verify"),
                    "job_type": "copy", "item_type": "verification",
                    "item_key": copy_claim_id, "outcome_kind": "ok",
                }),
            )
            .with_references(EventReferences {
                job_id: Some(job_id.clone()),
                object_id: Some(item.object_id.clone()),
                file_ref_id: Some(item.file_ref_id.clone()),
                copy_claim_id: Some(copy_claim_id),
                location_id: Some(destination.location.location_id.clone()),
                device_id: Some(device_id.clone()),
                ..EventReferences::default()
            }),
        ];
            events.append_batch(requests)?;
            database.apply(&events)?;
            summary.copied_objects = summary.copied_objects.saturating_add(1);
            summary.copied_bytes = summary.copied_bytes.saturating_add(copied.bytes_copied);
            Ok(())
        },
    )?;
    let status = if interrupted { "running" } else { "complete" };
    update_local_job(database, &job_id, status, &serde_json::to_value(&summary)?)?;
    if !interrupted {
        record_job_marker(
            &events,
            database,
            &job_id,
            "copy",
            &input_version,
            "complete",
        )?;
    }
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "status": status,
                "job_id": job_id,
                "source_location_id": source.location.location_id,
                "destination_location_id": destination.location.location_id,
                "collection_id": collection.collection_id,
                "summary": summary,
            }))?
        );
    } else {
        if interrupted {
            println!(
                "Copy paused after {} Objects. Resume with: archive job resume {}",
                summary.copied_objects, job_id
            );
        } else {
            println!(
                "Copy complete: {} Objects ({}), each verified at {}.",
                summary.copied_objects,
                format_bytes(summary.copied_bytes),
                destination.location.display_name
            );
        }
    }
    Ok(EXIT_OK)
}

fn visit_archive_copy_items(
    database: &ProjectionDb,
    collection_id: &str,
    source_location_id: &str,
    destination_location_id: &str,
    filters: &[PathBuf],
    mut visitor: impl FnMut(&ArchiveCopyItem) -> Result<(), AppError>,
) -> Result<ArchiveCopySummary, AppError> {
    let connection = cli_connection(database)?;
    let mut statement = connection
        .prepare(
            "SELECT f.file_ref_id, f.logical_path_encoding, f.logical_path_bytes,
                    f.logical_path_display, f.object_id, o.canonical_hash_hex,
                    o.size_bytes, source.relative_path_encoding,
                    source.relative_path_bytes, source.relative_path_display,
                    EXISTS(SELECT 1 FROM copy_claims destination
                           WHERE destination.location_id = ?3
                             AND destination.object_id = f.object_id
                             AND destination.state = 'present')
             FROM file_refs f
             LEFT JOIN objects o ON o.object_id = f.object_id
             LEFT JOIN copy_claims source ON source.copy_claim_id = (
                 SELECT candidate.copy_claim_id
                 FROM copy_claims candidate
                 WHERE candidate.location_id = ?2
                   AND candidate.object_id = f.object_id
                   AND candidate.state = 'present'
                 ORDER BY (candidate.last_verification_result = 'ok') DESC,
                          candidate.last_verified_time_utc_ms DESC,
                          candidate.copy_claim_id
                 LIMIT 1
             )
             WHERE f.collection_id = ?1 AND f.path_state = 'active'
             ORDER BY f.object_id, f.logical_path_encoding, f.logical_path_bytes",
        )
        .map_err(|source| cli_sql_error(database, source))?;
    let mut rows = statement
        .query(params![
            collection_id,
            source_location_id,
            destination_location_id
        ])
        .map_err(|source| cli_sql_error(database, source))?;
    let mut summary = ArchiveCopySummary::default();
    let mut current_object: Option<String> = None;
    let mut current_candidate: Option<ArchiveCopyItem> = None;
    let mut publish_candidate = |candidate: Option<ArchiveCopyItem>,
                                 summary: &mut ArchiveCopySummary|
     -> Result<(), AppError> {
        let Some(candidate) = candidate else {
            return Ok(());
        };
        summary.selected_unique_objects = summary.selected_unique_objects.saturating_add(1);
        if candidate.destination_has_object {
            summary.already_present_objects = summary.already_present_objects.saturating_add(1);
            return Ok(());
        }
        summary.bytes_to_copy = summary
            .bytes_to_copy
            .checked_add(candidate.size_bytes)
            .ok_or_else(|| AppError::Input("copy byte total exceeds u64".to_owned()))?;
        visitor(&candidate)
    };
    while let Some(row) = rows
        .next()
        .map_err(|source| cli_sql_error(database, source))?
    {
        let logical_encoding: String = row
            .get(1)
            .map_err(|source| cli_sql_error(database, source))?;
        let logical_bytes: Vec<u8> = row
            .get(2)
            .map_err(|source| cli_sql_error(database, source))?;
        let logical_display: String = row
            .get(3)
            .map_err(|source| cli_sql_error(database, source))?;
        let logical_path = relative_path_from_bytes(&logical_encoding, &logical_bytes)?;
        if !filters.iter().any(|filter| {
            filter.as_os_str().is_empty()
                || logical_path == *filter
                || logical_path.starts_with(filter)
        }) {
            continue;
        }
        summary.selected_logical_files = summary.selected_logical_files.saturating_add(1);
        let object_id: Option<String> = row
            .get(4)
            .map_err(|source| cli_sql_error(database, source))?;
        let object_id = object_id.ok_or_else(|| {
            AppError::Input(format!(
                "selected file has unresolved content and cannot be copied: {logical_display}"
            ))
        })?;
        if current_object.as_deref() != Some(object_id.as_str()) {
            publish_candidate(current_candidate.take(), &mut summary)?;
            current_object = Some(object_id.clone());
        }
        if current_candidate.is_some() {
            continue;
        }
        let source_encoding: Option<String> = row
            .get(7)
            .map_err(|source| cli_sql_error(database, source))?;
        let source_bytes: Option<Vec<u8>> = row
            .get(8)
            .map_err(|source| cli_sql_error(database, source))?;
        let source_relative_path = match (source_encoding, source_bytes) {
            (Some(encoding), Some(bytes)) => relative_path_from_bytes(&encoding, &bytes)?,
            _ => {
                return Err(AppError::Input(format!(
                    "selected content has no present source bytes at the source Location: {}",
                    logical_display
                )))
            }
        };
        let size: i64 = row
            .get(6)
            .map_err(|source| cli_sql_error(database, source))?;
        current_candidate = Some(ArchiveCopyItem {
            file_ref_id: row
                .get(0)
                .map_err(|source| cli_sql_error(database, source))?,
            object_id,
            blake3_hex: row
                .get(5)
                .map_err(|source| cli_sql_error(database, source))?,
            size_bytes: u64::try_from(size)
                .map_err(|_| AppError::Input("negative Object size in catalog".to_owned()))?,
            logical_path,
            logical_path_encoding: logical_encoding,
            logical_path_bytes: logical_bytes,
            logical_path_display: logical_display,
            source_relative_path,
            destination_has_object: row
                .get(10)
                .map_err(|source| cli_sql_error(database, source))?,
        });
    }
    publish_candidate(current_candidate, &mut summary)?;
    Ok(summary)
}

fn copy_logical_filters(
    location_root: &Path,
    cwd: &Path,
    requested: &[PathBuf],
) -> Result<Vec<PathBuf>, AppError> {
    let cwd_relative = cwd
        .strip_prefix(location_root)
        .map_err(|_| AppError::Input("cwd is outside the source Location".to_owned()))?;
    let requested = if requested.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        requested.to_vec()
    };
    requested
        .into_iter()
        .map(|path| {
            let combined = if path.is_absolute() {
                path.strip_prefix(location_root)
                    .map_err(|_| {
                        AppError::Input(format!(
                            "copy path is outside the source Location: {}",
                            path.display()
                        ))
                    })?
                    .to_path_buf()
            } else {
                cwd_relative.join(path)
            };
            normalize_copy_path(&combined)
        })
        .collect()
}

fn normalize_copy_path(path: &Path) -> Result<PathBuf, AppError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => normalized.push(value),
            _ => {
                return Err(AppError::Input(format!(
                    "copy paths must stay within the source Location: {}",
                    path.display()
                )))
            }
        }
    }
    Ok(normalized)
}

fn ensure_safe_destination_parents(root: &Path, relative: &Path) -> Result<(), AppError> {
    let mut current = root.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            let std::path::Component::Normal(value) = component else {
                return Err(AppError::Input(format!(
                    "copy destination path is not contained: {}",
                    relative.display()
                )));
            };
            current.push(value);
            match std::fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                Ok(_) => {
                    return Err(AppError::Input(format!(
                        "copy destination parent is not a directory: {}",
                        current.display()
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn execute_copy_review(
    database: &ProjectionDb,
    command: &CopyReviewCommand,
    as_json: bool,
) -> Result<u8, AppError> {
    let page = match command {
        CopyReviewCommand::List {
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
        CopyReviewCommand::Show { copy_claim_id } => archive_ledger::CopyPage {
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

fn execute_copy(cli: &Cli, database: &ProjectionDb, args: &CopyArgs) -> Result<u8, AppError> {
    if let Some(command) = &args.command {
        execute_copy_review(database, command, cli.json)
    } else {
        execute_copy_mutation(cli, database, &args.mutation)
    }
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
    if archive_ledger::is_v2_event_tree(cli.events_path()) {
        let report = V2OriginStore::open(cli.events_path())?.verification_report()?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!(
                "Verified {} signed records in {} segment across {} origin; accepted frontier and {} frontier manifests are valid.",
                report.records, report.segments, report.origins, report.frontiers
            );
        }
        return Ok(EXIT_OK);
    }
    return Err(AppError::Input(
        "this is a pre-v2 development Archive; recreate it with `archive init <name>` and re-import its files"
            .to_owned(),
    ));
    #[allow(unreachable_code)]
    {
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
}

fn execute_v2_fsck(cli: &Cli, args: &FsckArgs) -> Result<u8, AppError> {
    let store = V2OriginStore::open(cli.events_path())?;
    let report = fsck_v2_archive(
        &store,
        cli.database_path(),
        &V2FsckOptions {
            full: args.full,
            keep_rebuild: args.keep_rebuild,
            rebuild_dir: args.rebuild_dir.clone(),
        },
    )?;
    let exit = report.exit_code();
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Archive health check:");
        for check in &report.checks {
            let marker = match check.status.as_str() {
                "pass" => "OK",
                "skipped" => "--",
                "finding" => "!!",
                _ => "ERROR",
            };
            println!("  [{marker}] {}: {}", check.layer, check.summary);
            if check.status != "pass" {
                if let Some(detail) = &check.detail {
                    println!("       {detail}");
                }
            }
        }
        if let Some(path) = &report.rebuild_path {
            println!(
                "Disposable rebuilt database retained at {}.",
                path.display()
            );
        }
        if report.healthy {
            println!("Archive Git history, signed events, and SQLite projection are healthy.");
        } else {
            println!("Archive health findings need attention; no repair was attempted.");
        }
    }
    Ok(exit)
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
fn execute_v2_init(
    cli: &Cli,
    name: Option<&str>,
    make_default: bool,
    archive_id: Option<&str>,
    guided: bool,
    non_interactive: bool,
    root_path: Option<&Path>,
    _site_name: &str,
    _device_name: &str,
    _collection_name: &str,
    fingerprint: Option<&str>,
    fingerprint_kind: Option<&str>,
) -> Result<u8, AppError> {
    if cli.archive.is_some() {
        return Err(AppError::Input(
            "--archive selects an existing catalog and cannot be used with init".to_owned(),
        ));
    }
    if cli.database.is_some() || cli.events.is_some() {
        return Err(AppError::Input(
            "archive init creates one self-contained named Archive; --database/--events are only for inspecting unsupported development catalogs"
                .to_owned(),
        ));
    }
    if guided || root_path.is_some() || fingerprint.is_some() || fingerprint_kind.is_some() {
        return Err(AppError::Input(
            "archive init no longer creates file topology; run archive collection init from the content directory after initialization"
                .to_owned(),
        ));
    }
    let archive_id = archive_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("arc_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    let archive_name = match name.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => value.to_owned(),
        None if !non_interactive && std::io::stdin().is_terminal() => {
            prompt_default("Archive name", "Personal Archive")?
        }
        None => {
            return Err(AppError::Input(
                "archive init requires NAME or --name when input is non-interactive".to_owned(),
            ))
        }
    };
    let known_archive = central_archive(&archive_id, &archive_name)?;
    if known_archive.root.exists() {
        return Err(AppError::Input(format!(
            "Archive initialization target already exists: {}",
            known_archive.root.display()
        )));
    }
    let parent = known_archive.root.parent().ok_or_else(|| {
        AppError::Input(format!(
            "Archive path {} has no parent directory",
            known_archive.root.display()
        ))
    })?;
    std::fs::create_dir_all(parent)?;
    let prepared = parent.join(format!(
        ".archive-ledger-init-{}",
        ulid::Ulid::new().to_string().to_ascii_lowercase()
    ));
    let result = (|| {
        let initialized = archive_ledger::initialize_v2_archive(
            &prepared,
            &archive_id,
            &archive_name,
            now_utc_ms()?,
        )?;
        let store = V2OriginStore::open(prepared.join("canonical"))?;
        V2ProjectionDb::create_from_store(&store, prepared.join("archive.db"))?;
        V2ProjectionDb::open_existing(prepared.join("archive.db"))?
            .validate_against_store(&store)?;
        archive_ledger::place_directory_no_replace(&prepared, &known_archive.root)?;
        Ok::<_, AppError>(initialized)
    })();
    let initialized = match result {
        Ok(initialized) => initialized,
        Err(error) => {
            if prepared.exists() {
                let _ = std::fs::remove_dir_all(&prepared);
            }
            return Err(error);
        }
    };

    let mut registry = CatalogRegistry::load()?;
    let became_default = registry.archives().is_empty() || make_default;
    registry.register(known_archive.clone(), make_default)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "archive_id": initialized.archive_id,
                "archive_name": initialized.archive_name,
                "origin_id": initialized.origin_id,
                "genesis_hash": initialized.genesis_hash,
                "accepted_frontier_hash": initialized.accepted_frontier_hash,
                "canonical_git_commit": initialized.git_commit,
                "root": known_archive.root,
                "default": became_default,
            }))?
        );
    } else {
        println!("Created Archive \"{archive_name}\".");
        if became_default {
            println!("It is now the default Archive.");
        }
        println!();
        println!("Next: go to the directory containing your files and run:");
        println!("  archive collection init --name <name>");
    }
    Ok(EXIT_OK)
}

#[allow(dead_code, clippy::too_many_arguments)]
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
                "archive init requires NAME or --name when input is non-interactive".to_owned(),
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
            starter_policy("policy_starter".to_owned()),
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
    let mut became_default = false;
    if let Some(known_archive) = known_archive {
        let mut registry = CatalogRegistry::load()?;
        became_default = registry.archives().is_empty() || make_default;
        registry.register(known_archive, make_default)?;
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
        println!("Created Archive \"{archive_name}\".");
        if became_default {
            println!("It is now the default Archive.");
        }
        println!();
        if starter_ids.is_some() {
            println!("Starter topology created.");
            println!("Next: archive collection add .");
            if starter_ids
                .as_ref()
                .is_some_and(|starter| starter["catalog_location_id"].is_null())
            {
                println!("The event repository is outside that mounted path, so its catalog location was not guessed. Register its real storage location, then run archive catalog-location <location-id>.");
            }
        } else {
            println!("Next: go to the directory containing your files and run:");
            println!("  archive collection init --name <name>");
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

fn execute_v2_registry_command(
    cli: &Cli,
    database: &V2ProjectionDb,
) -> Result<Option<u8>, AppError> {
    let result = match &cli.command {
        Command::Rename { new_name } => {
            let name = new_name.trim();
            if name.is_empty() {
                return Err(AppError::Input("Archive name must be non-empty".to_owned()));
            }
            let mut status = database.status()?;
            if status.archive_name == name {
                return Err(AppError::Input("Archive already has that name".to_owned()));
            }
            let store = V2OriginStore::open(cli.events_path())?;
            let coordinated_remote = if store.coordination_required()? {
                let remote = store.coordination_remote()?;
                store.sync_remote(&remote)?;
                database.apply(&store)?;
                status = database.status()?;
                Some(remote)
            } else {
                None
            };
            let context = json!({"archive_id": status.archive_id});
            let items = vec![json!({
                "kind": "archive_updated",
                "archive_id": status.archive_id,
                "archive_display_name": name,
            })];
            let appended = if let Some(remote) = coordinated_remote {
                store.append_coordinated_batch(
                    &remote,
                    "archive_update",
                    1,
                    context,
                    json!({}),
                    items,
                )?
            } else {
                store.append_batch("archive_update", 1, context, json!({}), items)?
            };
            database.apply(&store)?;
            CatalogRegistry::load()?.rename(&status.archive_id, name)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 2,
                        "archive_id": status.archive_id,
                        "archive_name": name,
                        "batch_id": appended.batch_id,
                        "accepted_frontier_hash": appended.accepted_frontier_hash,
                    }))?
                );
            } else {
                println!("Renamed Archive to \"{name}\".");
            }
            EXIT_OK
        }
        Command::Site { command } => match command {
            SiteCommand::List { all } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::List { all: *all },
            )?,
            SiteCommand::Show { id } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            SiteCommand::Add(args) => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Add(args.clone()),
            )?,
            SiteCommand::Update { snapshot } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            SiteCommand::Retire { snapshot, yes } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Site,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            SiteCommand::Rename { site, new_name } => {
                record_v2_registry_change(
                    cli,
                    database,
                    v2_rename_change(database, RegistryKind::Site, site, new_name)?,
                )?;
                EXIT_OK
            }
            SiteCommand::Status { site } => execute_v2_site_status(cli, database, site.as_deref())?,
        },
        Command::Device { command } => match command {
            DeviceCommand::Discover { path } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Discover { path: path.clone() },
            )?,
            DeviceCommand::List { all } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::List { all: *all },
            )?,
            DeviceCommand::Show { id } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            DeviceCommand::Add(args) => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Add(args.clone()),
            )?,
            DeviceCommand::Update { snapshot } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            DeviceCommand::Retire { snapshot, yes } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            DeviceCommand::Rename { device, new_name } => {
                record_v2_registry_change(
                    cli,
                    database,
                    v2_rename_change(database, RegistryKind::Device, device, new_name)?,
                )?;
                EXIT_OK
            }
            DeviceCommand::Move {
                device_positional,
                device_option,
                to,
            } => {
                let selector = device_positional
                    .as_deref()
                    .or(device_option.as_deref())
                    .expect("clap requires one Device selector");
                let state = database.registry_state(false)?;
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
                record_v2_registry_change(
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
                record_v2_registry_change(
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
                record_v2_registry_change(
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
            DeviceCommand::Status { device } => {
                execute_v2_device_status(cli, database, device.as_deref())?
            }
        },
        Command::Root { command } => {
            execute_v2_registry_entity(cli, database, RegistryKind::Root, command)?
        }
        Command::RiskDomain { command } => {
            execute_v2_registry_entity(cli, database, RegistryKind::RiskDomain, command)?
        }
        Command::Collection { command } => match command {
            CollectionCommand::List { all } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Collection,
                &RegistryEntityCommand::List { all: *all },
            )?,
            CollectionCommand::Show { id } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Collection,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            CollectionCommand::Update { snapshot } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Collection,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            CollectionCommand::Retire { snapshot, yes } => execute_v2_registry_entity(
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
                record_v2_registry_change(
                    cli,
                    database,
                    v2_rename_change(database, RegistryKind::Collection, collection, new_name)?,
                )?;
                EXIT_OK
            }
            CollectionCommand::Status { collection } => {
                execute_v2_collection_status(cli, database, collection.as_deref())?
            }
            CollectionCommand::Init(args) => execute_v2_collection_init(cli, database, args)?,
            CollectionCommand::Add(args) => execute_v2_collection_add(cli, database, args)?,
        },
        Command::Location { command } => match command {
            LocationCommand::Discover { path } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Device,
                &RegistryEntityCommand::Discover { path: path.clone() },
            )?,
            LocationCommand::List { all } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::List { all: *all },
            )?,
            LocationCommand::Show { id } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            LocationCommand::Register(args) => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Add(args.clone()),
            )?,
            LocationCommand::Update { snapshot } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Update {
                    snapshot: snapshot.clone(),
                },
            )?,
            LocationCommand::Retire { snapshot, yes } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Location,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            LocationCommand::Rename { location, new_name } => {
                record_v2_registry_change(
                    cli,
                    database,
                    v2_rename_change(database, RegistryKind::Location, location, new_name)?,
                )?;
                EXIT_OK
            }
            LocationCommand::Status { location } => {
                execute_v2_location_status(cli, database, location.as_deref())?
            }
            LocationCommand::Init(args) => {
                validate_setup_source(&args.path, false, SetupCommand::Location)?;
                let state = database.registry_state(false)?;
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
                    batch_entries: 1_000,
                    job_id: None,
                    import_id: None,
                    max_items: None,
                };
                execute_v2_filesystem_setup(cli, database, &setup, Some(collection))?
            }
            LocationCommand::Scan(args) => execute_v2_location_scan(cli, database, args)?,
            LocationCommand::ImportAnnex(args) => {
                let state = database.registry_state(false)?;
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
                    batch_entries: args.batch_entries,
                    job_id: args.job_id.clone(),
                    import_id: args.import_id.clone(),
                    max_items: args.max_items,
                };
                execute_v2_annex_setup(cli, database, &setup, Some(collection))?
            }
            LocationCommand::Copy(args) => execute_v2_copy_mutation(cli, database, args)?,
        },
        Command::Policy { command } => match command {
            PolicyCommand::List { all } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Policy,
                &RegistryEntityCommand::List { all: *all },
            )?,
            PolicyCommand::Show { id } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Show { id: id.clone() },
            )?,
            PolicyCommand::Add { snapshot } => execute_v2_registry_entity(
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
            PolicyCommand::Retire { snapshot, yes } => execute_v2_registry_entity(
                cli,
                database,
                RegistryKind::Policy,
                &RegistryEntityCommand::Retire {
                    snapshot: snapshot.clone(),
                    yes: *yes,
                },
            )?,
            PolicyCommand::Update(args) => execute_v2_policy_update(cli, database, args)?,
            PolicyCommand::Evaluate => execute_v2_report(
                cli,
                database,
                &ReportCommand::Policy(ReportSummaryArgs {
                    policy: None,
                    collection: None,
                }),
            )?,
        },
        Command::Verify(args) => {
            if args.copy.is_some() {
                return Err(AppError::Input(
                    "single-Copy verification is not yet available in v2; omit --copy to verify the Location"
                        .to_owned(),
                ));
            }
            execute_v2_location_scan(
                cli,
                database,
                &LocationScanArgs {
                    location: Some(args.location.clone()),
                    path: Some(args.path.clone()),
                    collection: None,
                    exclusions: Vec::new(),
                    job_id: args.job_id.clone(),
                    scan_id: None,
                    batch_entries: args.batch_entries,
                    max_items: args.max_items,
                },
            )?
        }
        Command::Copy(args) => {
            if args.command.is_some() {
                return Err(AppError::Input(
                    "v2 Copy review is not yet available; use Location and Collection status for current summaries"
                        .to_owned(),
                ));
            }
            execute_v2_copy_mutation(cli, database, &args.mutation)?
        }
        Command::Stage(args) => execute_v2_stage(cli, database, args)?,
        Command::Job { command } => execute_v2_job(cli, database, command)?,
        Command::Report { command } => execute_v2_report(cli, database, command)?,
        _ => return Ok(None),
    };
    Ok(Some(result))
}

fn execute_v2_registry_entity(
    cli: &Cli,
    database: &V2ProjectionDb,
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
                        &json!({"version": 2, "mounted_filesystem": discovered})
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
            let state = database.registry_state(*all)?;
            print_v2_registry_values(kind, registry_values(kind, &state)?, cli.json, true)?;
        }
        RegistryEntityCommand::Show { id } => {
            let state = database.registry_state(true)?;
            let values = registry_values(kind, &state)?;
            let value = select_registry_value(kind, &values, id)?;
            print_v2_registry_values(kind, vec![value], cli.json, false)?;
        }
        RegistryEntityCommand::Add(args) => {
            let change = if let Some(snapshot) = &args.snapshot {
                parse_registry_change(kind, RegistryAction::Register, snapshot)?
            } else {
                build_registry_add(kind, args)?
            };
            record_v2_registry_change(cli, database, change)?;
        }
        RegistryEntityCommand::Update { snapshot } => record_v2_registry_change(
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
            record_v2_registry_change(
                cli,
                database,
                parse_registry_change(kind, RegistryAction::Retire, snapshot)?,
            )?;
        }
        RegistryEntityCommand::Move { snapshot } => record_v2_registry_change(
            cli,
            database,
            parse_registry_change(kind, RegistryAction::Move, snapshot)?,
        )?,
        RegistryEntityCommand::Assign {
            risk_domain_id,
            entity_type,
            entity_id,
        } => record_v2_registry_change(
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
        } => record_v2_registry_change(
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
        } => record_v2_registry_change(
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
        } => record_v2_registry_change(
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

fn select_registry_value(
    kind: RegistryKind,
    values: &[serde_json::Value],
    selector: &str,
) -> Result<serde_json::Value, AppError> {
    if let Some(value) = values
        .iter()
        .find(|value| registry_id(kind, value) == Some(selector))
    {
        return Ok(value.clone());
    }
    let named = values
        .iter()
        .filter(|value| {
            value
                .get("display_name")
                .and_then(serde_json::Value::as_str)
                == Some(selector)
        })
        .cloned()
        .collect::<Vec<_>>();
    match named.as_slice() {
        [value] => Ok(value.clone()),
        [] => Err(AppError::Input(format!(
            "registry entry not found: {selector}"
        ))),
        _ => Err(AppError::Input(format!(
            "registry name is ambiguous; use a stable ID: {selector}"
        ))),
    }
}

fn print_v2_registry_values(
    kind: RegistryKind,
    values: Vec<serde_json::Value>,
    as_json: bool,
    list: bool,
) -> Result<(), AppError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"version": 2, "items": values}))?
        );
    } else if list {
        print_registry_list(kind, values, false)?;
    } else {
        print_registry_values(kind, values, false)?;
    }
    Ok(())
}

fn record_v2_registry_change(
    cli: &Cli,
    database: &V2ProjectionDb,
    change: RegistryChange,
) -> Result<(), AppError> {
    let store = V2OriginStore::open(cli.events_path())?;
    let result = V2Registry::new(&store, database).record(change, &cli.host)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Updated the Archive; SQLite is current.");
    }
    Ok(())
}

fn v2_rename_change(
    database: &V2ProjectionDb,
    kind: RegistryKind,
    selector: &str,
    new_name: &str,
) -> Result<RegistryChange, AppError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(AppError::Input("new name must be non-empty".to_owned()));
    }
    let state = database.registry_state(false)?;
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

fn execute_v2_collection_status(
    cli: &Cli,
    database: &V2ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let collection = if let Some(selector) = selector {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else if state.collections.len() == 1 {
        state.collections[0].clone()
    } else {
        return Err(AppError::Input(
            "cwd does not yet identify one Collection; specify its name or ID".to_owned(),
        ));
    };
    let risk = v2_collection_risk(database, &state, &collection)?;
    let location_ids = v2_collection_location_ids(database, &state, &collection.collection_id)?;
    let locations = state
        .locations
        .iter()
        .filter(|location| location_ids.contains(&location.location_id))
        .map(|location| {
            let device = location
                .device_id
                .as_deref()
                .and_then(|id| state.devices.iter().find(|device| device.device_id == id));
            let site = location
                .site_id
                .as_deref()
                .and_then(|id| state.sites.iter().find(|site| site.site_id == id))
                .or_else(|| {
                    device
                        .and_then(|device| device.current_site_id.as_deref())
                        .and_then(|id| state.sites.iter().find(|site| site.site_id == id))
                });
            Ok(json!({
                "location": location,
                "device": device,
                "site": site,
                "metrics": v2_location_metrics(database, &state, &location.location_id)?,
            }))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "collection": collection,
                "file_count": risk.file_count,
                "known_size_bytes": risk.known_size_bytes,
                "files_at_risk": risk.files_at_risk,
                "files_uncertain": risk.files_uncertain,
                "locations": locations,
            }))?
        );
    } else {
        println!("Collection: {}", collection.display_name);
        println!(
            "Files: {} ({})",
            risk.file_count,
            format_bytes(risk.known_size_bytes)
        );
        println!(
            "At risk: {}; uncertain: {}",
            risk.files_at_risk, risk.files_uncertain
        );
        println!("Locations:");
        for value in &locations {
            let location: LocationSnapshot = serde_json::from_value(value["location"].clone())?;
            let metrics: V2LocationMetrics = serde_json::from_value(value["metrics"].clone())?;
            let device = value["device"]["display_name"].as_str().unwrap_or("none");
            let site = value["site"]["display_name"].as_str().unwrap_or("unknown");
            println!(
                "  {} — {} / {}; {} files; {}; stale {} (older than {} days)",
                location.display_name,
                device,
                site,
                metrics.file_count,
                format_bytes(metrics.space_used_bytes),
                metrics.stale_presence_count,
                metrics.stale_after_days,
            );
        }
    }
    Ok(if risk.files_at_risk > 0 || risk.files_uncertain > 0 {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    })
}

fn execute_v2_stage(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &StageArgs,
) -> Result<u8, AppError> {
    if let Some(StageCommand::Import(import)) = &args.command {
        return execute_v2_stage_import(cli, database, import);
    }
    if archive_ledger::is_git_annex_repository(&args.path)? {
        return Err(AppError::Input(
            "archive stage does not audit a git-annex worktree; import that repository with archive location import-annex so annex pointers are interpreted safely"
                .to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    let collection_id = args
        .collection
        .as_deref()
        .map(|selector| {
            select_collection(&state.collections, selector)?
                .map(|value| value.collection_id)
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))
        })
        .transpose()?;
    let report = archive_ledger::audit_stage_v2(
        database,
        &StageAuditOptions {
            source: args.path.clone(),
            manifest: args.manifest.clone(),
            collection_id,
            list_limit: args.limit,
        },
    )?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Staged: {}", report.source.display());
        println!(
            "Files: {} ({}); checksums: {} computed, {} reused",
            report.files_seen,
            format_bytes(report.bytes_seen),
            report.checksums_computed,
            report.checksums_reused
        );
        println!(
            "New to this Archive: {} files / {} unique contents",
            report.new_to_archive_files, report.new_to_archive_objects
        );
        println!(
            "Already cataloged: {}",
            report
                .known_in_selected_collection
                .saturating_add(report.known_only_in_other_collections)
        );
        if !report.listed_files.is_empty() {
            println!("New files:");
            for file in &report.listed_files {
                println!(
                    "  {}  ({})",
                    file.path_display,
                    format_bytes(file.size_bytes)
                );
            }
            if report.listed_files_truncated {
                println!("  …more not shown; use --limit or --json");
            }
        }
        if report.ignored_symlinks > 0 || report.special_files > 0 {
            println!(
                "Ignored: {} symlinks; {} special files",
                report.ignored_symlinks, report.special_files
            );
        }
        if report.audit_status != "complete" {
            println!(
                "Audit partial: {} traversal errors; {} read errors; {} changed during reading",
                report.traversal_errors, report.content_read_errors, report.concurrent_changes
            );
        }
        println!("Checksum manifest: {}", report.manifest.display());
        println!(
            "Protection of cataloged files: {} policy-satisfied; {} at risk; {} unknown",
            report.known_policy_satisfied_files,
            report.known_at_risk_files,
            report.known_policy_unknown_files
        );
        if report.source_removal_ready {
            println!(
                "Source removal readiness: READY — every staged file is cataloged and satisfies its Collection Policy."
            );
        } else {
            println!("Source removal readiness: NOT READY.");
        }
        if report.new_to_archive_files > 0 {
            println!(
                "Next: from a registered destination Location, run archive stage import {} --yes",
                shell_quote(&report.source.to_string_lossy())
            );
        }
    }
    Ok(if !report.source_removal_ready {
        EXIT_FINDINGS
    } else {
        EXIT_OK
    })
}

fn execute_v2_stage_import(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &StageImportArgs,
) -> Result<u8, AppError> {
    if args.non_interactive && !args.dry_run && !args.yes {
        return Err(AppError::Input(
            "stage import in non-interactive mode requires --yes (or use --dry-run)".to_owned(),
        ));
    }
    let reviewed =
        archive_ledger::prepare_stage_import_v2(database, &args.source, args.manifest.as_deref())?;
    let source = reviewed.source.clone();
    let manifest = reviewed.manifest.clone();
    let requested_destination = args
        .destination_root
        .clone()
        .unwrap_or(std::env::current_dir()?);
    let destination_cwd = std::fs::canonicalize(&requested_destination).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve destination directory {}: {error}",
            requested_destination.display()
        ))
    })?;
    let state = database.registry_state(false)?;
    let (location, location_root, fingerprint_status) = v2_inventory_location_scope(
        cli,
        database,
        &state,
        &destination_cwd,
        args.location.as_deref(),
    )?;
    let collection = if let Some(selector) = args.collection.as_deref() {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_v2_collection_at_location(database, &state, &location.location_id)?
    };
    if source.starts_with(&destination_cwd) || destination_cwd.starts_with(&source) {
        return Err(AppError::Input(
            "stage source and destination must not contain one another".to_owned(),
        ));
    }
    let into = args.into.clone().unwrap_or_else(|| {
        source
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| "staged-import".into())
    });
    validate_single_destination_component(&into)?;
    let import_root = destination_cwd.join(&into);
    let resuming = args.job_id.is_some();
    if !resuming && std::fs::symlink_metadata(&import_root).is_ok() {
        return Err(AppError::Input(format!(
            "stage import destination already exists; choose a new --into name: {}",
            import_root.display()
        )));
    }
    let available = available_space(&destination_cwd)?;
    if !resuming && reviewed.eligible_bytes > available {
        return Err(AppError::Input(format!(
            "stage import needs {} but only {} is available at the destination",
            format_bytes(reviewed.eligible_bytes),
            format_bytes(available)
        )));
    }
    if args.dry_run {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2,
                    "status": "planned",
                    "source": source,
                    "manifest": manifest,
                    "destination": import_root,
                    "collection_id": collection.collection_id,
                    "location_id": location.location_id,
                    "files": reviewed.eligible_files,
                    "bytes": reviewed.eligible_bytes,
                    "ledger_changed": false,
                }))?
            );
        } else {
            println!(
                "Stage import plan: {} new files ({})",
                reviewed.eligible_files,
                format_bytes(reviewed.eligible_bytes)
            );
            println!("From: {}", source.display());
            println!("To: {}", import_root.display());
            println!("Dry run: no files or ledger facts were changed.");
        }
        return Ok(EXIT_OK);
    }
    if reviewed.eligible_files == 0 && !resuming {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2, "status": "nothing_to_import", "files": 0, "bytes": 0
                }))?
            );
        } else {
            println!("Nothing to import; every stable staged file is already cataloged.");
        }
        return Ok(EXIT_OK);
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::Input(
                "stage import requires confirmation; rerun with --yes or inspect it first with --dry-run"
                    .to_owned(),
            ));
        }
        if !prompt_confirmation("Copy and verify these new files?")? {
            return Err(AppError::Input("stage import cancelled".to_owned()));
        }
    }
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    if !job_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(AppError::Input("invalid stage import job ID".to_owned()));
    }
    let plan = archive_ledger::select_stage_import_v2(database, reviewed, &job_id)?;
    let input_version = plan.input_version().to_owned();
    let job_params = json!({
        "source": source,
        "manifest": manifest,
        "destination_root": destination_cwd,
        "into": into,
        "collection": collection.collection_id,
        "location": location.location_id,
    });
    let store = V2OriginStore::open(cli.events_path())?;
    ensure_v2_job_started(
        cli,
        database,
        &store,
        &job_id,
        "stage_import",
        &input_version,
        &job_params,
    )?;
    let temporary_root = destination_cwd.join(format!(".archive-ledger-import-{job_id}.tmp"));
    let temporary_exists = std::fs::symlink_metadata(&temporary_root).is_ok();
    let published = std::fs::symlink_metadata(&import_root).is_ok();
    if temporary_exists && published {
        return Err(AppError::Input(format!(
            "stage import job {job_id} has both a temporary and published tree; inspect {} and {} before resuming",
            temporary_root.display(), import_root.display()
        )));
    }
    if published && !resuming {
        return Err(AppError::Input(format!(
            "stage import destination already exists; refusing to adopt it: {}",
            import_root.display()
        )));
    }
    if !temporary_exists && !published {
        std::fs::create_dir(&temporary_root)?;
    }
    let mut temporary_tree = (!published).then(|| TemporaryImportTree {
        path: temporary_root.clone(),
        keep: temporary_exists,
    });
    let working_root = if published {
        &import_root
    } else {
        &temporary_root
    };
    let mut processed_files = 0_u64;
    let mut processed_bytes = 0_u64;
    let mut processed_this_run = 0_usize;
    let mut interrupted = false;
    let mut cursor = None;
    'pages: loop {
        let page =
            archive_ledger::stage_import_candidates_v2(database, &plan, cursor.as_ref(), 1_000)?;
        for candidate in &page.items {
            if args
                .max_items
                .is_some_and(|limit| processed_this_run >= limit)
            {
                interrupted = true;
                break 'pages;
            }
            ensure_safe_destination_parents(working_root, &candidate.relative_path)?;
            let source_path = source.join(&candidate.relative_path);
            let destination_path = working_root.join(&candidate.relative_path);
            let verified = match std::fs::symlink_metadata(&destination_path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    if let Some(tree) = &mut temporary_tree {
                        tree.keep = true;
                    }
                    archive_ledger::verify_existing_file(&destination_path, &candidate.blake3_hex)?
                }
                Ok(_) => {
                    return Err(AppError::Input(format!(
                        "stage destination is not a regular file: {}",
                        destination_path.display()
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !published => {
                    if let Some(parent) = destination_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    archive_ledger::copy_verified_no_replace(
                        &source_path,
                        &destination_path,
                        &candidate.blake3_hex,
                    )?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AppError::Input(format!(
                        "published stage import is missing reviewed file {}; refusing recovery",
                        candidate.path_display
                    )))
                }
                Err(error) => return Err(error.into()),
            };
            processed_files = processed_files.saturating_add(1);
            processed_bytes = processed_bytes.saturating_add(verified.bytes_copied);
            processed_this_run = processed_this_run.saturating_add(1);
        }
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    if interrupted {
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
        print_stage_import_running(
            cli.json,
            &job_id,
            "copying",
            processed_files,
            processed_bytes,
        )?;
        update_v2_job_progress(
            database,
            &job_id,
            &json!({
                "phase": "copying",
                "files_verified_this_run": processed_files,
                "bytes_verified_this_run": processed_bytes,
            }),
        )?;
        return Ok(EXIT_OK);
    }
    if let Err(error) = validate_import_tree(working_root, plan.eligible_files) {
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
        return Err(error);
    }
    if !published {
        archive_ledger::place_directory_no_replace(&temporary_root, &import_root)?;
        if let Some(tree) = &mut temporary_tree {
            tree.keep = true;
        }
    }
    if args.stop_after_publish {
        update_v2_job_progress(
            database,
            &job_id,
            &json!({"phase": "published", "destination": import_root}),
        )?;
        print_stage_import_running(
            cli.json,
            &job_id,
            "published",
            processed_files,
            processed_bytes,
        )?;
        return Ok(EXIT_OK);
    }
    let destination_prefix = import_root.strip_prefix(&location_root).map_err(|_| {
        AppError::Input("stage destination is outside the registered Location".to_owned())
    })?;
    let mut placements = Vec::with_capacity(1_000);
    let mut cursor = None;
    loop {
        let page =
            archive_ledger::stage_import_candidates_v2(database, &plan, cursor.as_ref(), 1_000)?;
        for candidate in &page.items {
            let relative = destination_prefix.join(&candidate.relative_path);
            let encoded = RegistryPath::from_path(&relative);
            let identity_bytes = registry_path_identity_bytes(&encoded)?;
            let object_id = format!("blake3:{}", candidate.blake3_hex);
            placements.push(archive_ledger::V2Placement {
                collection_id: collection.collection_id.clone(),
                location_id: location.location_id.clone(),
                file_ref_id: stable_id(
                    "file",
                    &[
                        collection.collection_id.as_bytes(),
                        encoded.encoding.as_bytes(),
                        &identity_bytes,
                    ],
                ),
                logical_path: encoded.clone(),
                copy_path: encoded,
                object_id,
                blake3_hex: candidate.blake3_hex.clone(),
                size_bytes: candidate.size_bytes,
                modified_time_utc_ms: candidate.modified_time_utc_ms,
                device_fingerprint_status: fingerprint_status.clone(),
                job_id: job_id.clone(),
                job_type: "stage_import".to_owned(),
                input_version: input_version.clone(),
            });
            if placements.len() == 1_000 {
                archive_ledger::v2_record_placements(&store, database, &placements)?;
                placements.clear();
            }
        }
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    archive_ledger::v2_record_placements(&store, database, &placements)?;
    finish_v2_job(
        database,
        &store,
        &job_id,
        "stage_import",
        &input_version,
        "complete",
        &json!({
            "files": plan.eligible_files,
            "bytes": plan.eligible_bytes,
            "destination": import_root,
        }),
    )?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "status": "complete",
                "job_id": job_id,
                "source": source,
                "destination": import_root,
                "collection_id": collection.collection_id,
                "location_id": location.location_id,
                "files": plan.eligible_files,
                "bytes": plan.eligible_bytes,
            }))?
        );
    } else {
        println!(
            "Stage import complete: {} files ({}) copied, verified, and added to Collection \"{}\".",
            plan.eligible_files,
            format_bytes(plan.eligible_bytes),
            collection.display_name
        );
        println!("The staged source was not changed.");
    }
    Ok(EXIT_OK)
}

fn registry_path_identity_bytes(path: &RegistryPath) -> Result<Vec<u8>, AppError> {
    match path.encoding.as_str() {
        "utf8" => path
            .text
            .as_deref()
            .map(|value| value.as_bytes().to_vec())
            .ok_or_else(|| AppError::Input("UTF-8 path lacks text".to_owned())),
        "unix_bytes" | "windows_utf16le" => path
            .base64
            .as_deref()
            .ok_or_else(|| AppError::Input("lossless path lacks base64 bytes".to_owned()))
            .and_then(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|error| AppError::Input(format!("invalid lossless path: {error}")))
            }),
        other => Err(AppError::Input(format!(
            "unsupported path encoding: {other}"
        ))),
    }
}

fn v2_job_operation_key(job_id: &str, input_version: &str, outcome: &str) -> String {
    stable_id(
        "op",
        &[
            job_id.as_bytes(),
            input_version.as_bytes(),
            b"job",
            outcome.as_bytes(),
        ],
    )
}

fn ensure_v2_job_started(
    cli: &Cli,
    database: &V2ProjectionDb,
    store: &V2OriginStore,
    job_id: &str,
    job_type: &str,
    input_version: &str,
    params_value: &serde_json::Value,
) -> Result<(), AppError> {
    database.apply(store)?;
    let operation_key = v2_job_operation_key(job_id, input_version, "started");
    let connection = v2_cli_connection(database)?;
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_outcomes WHERE operation_key = ?1)",
            [&operation_key],
            |row| row.get(0),
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    if exists {
        let actual: (String, String, String) = connection
            .query_row(
                "SELECT job_type, input_version, params_json FROM jobs WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|source| v2_cli_sql_error(database, source))?;
        if actual.0 != job_type
            || actual.1 != input_version
            || serde_json::from_str::<serde_json::Value>(&actual.2)? != *params_value
        {
            return Err(AppError::Input(format!(
                "job {job_id} belongs to different immutable inputs"
            )));
        }
        return Ok(());
    }
    store.append_batch(
        "job_summary",
        1,
        json!({"job_id": job_id, "job_type": job_type}),
        json!({}),
        vec![json!({
            "kind": "job_started",
            "job_id": job_id,
            "job_type": job_type,
            "input_version": input_version,
            "params": params_value,
            "actor_id": cli.actor,
            "host_id": cli.host,
            "item_type": "job",
            "item_key": job_id,
            "outcome_kind": "started",
            "operation_key": operation_key,
        })],
    )?;
    database.apply(store)?;
    Ok(())
}

fn finish_v2_job(
    database: &V2ProjectionDb,
    store: &V2OriginStore,
    job_id: &str,
    job_type: &str,
    input_version: &str,
    status: &str,
    summary: &serde_json::Value,
) -> Result<(), AppError> {
    database.apply(store)?;
    let operation_key = v2_job_operation_key(job_id, input_version, status);
    let exists: bool = v2_cli_connection(database)?
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM operation_outcomes WHERE operation_key = ?1)",
            [&operation_key],
            |row| row.get(0),
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    if exists {
        return Ok(());
    }
    store.append_batch(
        "job_summary",
        1,
        json!({"job_id": job_id, "job_type": job_type}),
        json!({}),
        vec![json!({
            "kind": "job_finished",
            "job_id": job_id,
            "job_type": job_type,
            "input_version": input_version,
            "status": status,
            "summary": summary,
            "item_type": "job",
            "item_key": job_id,
            "outcome_kind": status,
            "operation_key": operation_key,
        })],
    )?;
    database.apply(store)?;
    Ok(())
}

fn update_v2_job_progress(
    database: &V2ProjectionDb,
    job_id: &str,
    progress: &serde_json::Value,
) -> Result<(), AppError> {
    v2_cli_connection(database)?
        .execute(
            "UPDATE jobs SET progress_json = ?2 WHERE job_id = ?1",
            params![job_id, serde_json::to_string(progress)?],
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    Ok(())
}

fn v2_cli_connection(database: &V2ProjectionDb) -> Result<Connection, AppError> {
    let connection =
        Connection::open(database.path()).map_err(|source| v2_cli_sql_error(database, source))?;
    connection
        .execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
        .map_err(|source| v2_cli_sql_error(database, source))?;
    Ok(connection)
}

fn v2_cli_sql_error(database: &V2ProjectionDb, source: rusqlite::Error) -> AppError {
    AppError::V2Projection(V2ProjectionError::Sqlite {
        path: database.path().to_path_buf(),
        source,
    })
}

fn execute_v2_job(
    cli: &Cli,
    database: &V2ProjectionDb,
    command: &JobCommand,
) -> Result<u8, AppError> {
    match command {
        JobCommand::List { limit } => {
            let jobs = list_v2_jobs(database, *limit)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"version": 2, "items": jobs}))?
                );
            } else if jobs.is_empty() {
                println!("No resumable jobs.");
            } else {
                for job in jobs {
                    println!("{}  {}  {}", job.job_id, job.status, job.job_type);
                }
            }
        }
        JobCommand::Show { job_id } => {
            let job = v2_local_job(database, job_id)?
                .ok_or_else(|| AppError::Input(format!("job not found: {job_id}")))?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&job)?);
            } else {
                println!("Job: {}", job.job_id);
                println!("Type: {}; Status: {}", job.job_type, job.status);
                if let Some(progress) = job.progress {
                    println!("Progress: {progress}");
                }
                if job.status != "complete" {
                    println!("Resume with: archive job resume {}", job.job_id);
                }
            }
        }
        JobCommand::Resume { job_id, max_items } => {
            let job = v2_local_job(database, job_id)?
                .ok_or_else(|| AppError::Input(format!("job not found: {job_id}")))?;
            if matches!(job.status.as_str(), "complete" | "cancelled") {
                return Err(AppError::Input(format!(
                    "job {job_id} is already {}",
                    job.status
                )));
            }
            match job.job_type.as_str() {
                "inventory_add" => {
                    execute_v2_collection_add(
                        cli,
                        database,
                        &CollectionAddArgs {
                            path: job_registry_path(&job.params, "root_path")?,
                            location: Some(json_string(&job.params, "location_id")?),
                            collection: Some(json_string(&job.params, "collection_id")?),
                            exclusions: job_registry_paths(&job.params, "exclusions")?,
                            job_id: Some(job.job_id),
                            scan_id: Some(job.input_version),
                            batch_entries: 1_000,
                            max_items: *max_items,
                        },
                    )?;
                }
                "location_scan" => {
                    execute_v2_location_scan(
                        cli,
                        database,
                        &LocationScanArgs {
                            location: Some(json_string(&job.params, "location_id")?),
                            path: Some(job_registry_path(&job.params, "root_path")?),
                            collection: Some(json_string(&job.params, "collection_id")?),
                            exclusions: job_registry_paths(&job.params, "exclusions")?,
                            job_id: Some(job.job_id),
                            scan_id: Some(job.input_version),
                            batch_entries: 1_000,
                            max_items: *max_items,
                        },
                    )?;
                }
                "annex_import" => {
                    let store = V2OriginStore::open(cli.events_path())?;
                    let importer = archive_ledger::V2AnnexImporter::new(
                        &store,
                        database,
                        AnnexImportConfig {
                            repo_path: job_registry_path(&job.params, "repo_path")?,
                            import_id: job.input_version.clone(),
                            job_id: job.job_id.clone(),
                            collection_id: json_string(&job.params, "collection_id")?,
                            worktree_location_id: json_string(&job.params, "worktree_location_id")?,
                            cas_location_id: json_string(&job.params, "cas_location_id")?,
                            device_id: json_string(&job.params, "device_id")?,
                            archive_root_id: json_string(&job.params, "archive_root_id")?,
                            batch_entries: job.params["batch_entries"]
                                .as_u64()
                                .and_then(|value| usize::try_from(value).ok())
                                .ok_or_else(|| {
                                    AppError::Input(
                                        "annex import job has invalid batch_entries".to_owned(),
                                    )
                                })?,
                        },
                    )?;
                    let result = importer.run_at_most(*max_items)?;
                    let status = if result.status == AnnexImportStatus::Complete {
                        "complete"
                    } else {
                        "running"
                    };
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "version": 2,
                                "job_id": job.job_id,
                                "import_id": job.input_version,
                                "status": status,
                                "annex_uuid": result.annex_uuid,
                                "git_head_commit": result.git_head_commit,
                                "summary": result.summary,
                            }))?
                        );
                    } else if status == "running" {
                        println!(
                            "Annex import paused after {} index entries.",
                            result.summary.entries_seen
                        );
                        println!("Resume with: archive job resume {}", job.job_id);
                    } else {
                        println!(
                            "Annex import complete: {} index entries; {} present; {} absent.",
                            result.summary.entries_seen,
                            result.summary.present,
                            result.summary.absent
                        );
                    }
                }
                "stage_import" => {
                    let source = job_path(&job.params, "source")?;
                    let manifest = Some(job_path(&job.params, "manifest")?);
                    let destination_root = Some(job_path(&job.params, "destination_root")?);
                    let into = Some(job_path(&job.params, "into")?);
                    execute_v2_stage_import(
                        cli,
                        database,
                        &StageImportArgs {
                            source,
                            manifest,
                            collection: Some(json_string(&job.params, "collection")?),
                            location: Some(json_string(&job.params, "location")?),
                            into,
                            dry_run: false,
                            yes: true,
                            non_interactive: true,
                            job_id: Some(job.job_id),
                            destination_root,
                            max_items: *max_items,
                            stop_after_publish: false,
                        },
                    )?;
                }
                "copy" => {
                    let cwd = job_path(&job.params, "cwd")?;
                    std::env::set_current_dir(&cwd).map_err(|error| {
                        AppError::Input(format!(
                            "cannot return to copy job source {}: {error}",
                            cwd.display()
                        ))
                    })?;
                    let logical_filters: Vec<PathBuf> = serde_json::from_value(
                        job.params.get("logical_filters").cloned().ok_or_else(|| {
                            AppError::Input("copy job lacks logical filters".to_owned())
                        })?,
                    )?;
                    execute_v2_copy_mutation(
                        cli,
                        database,
                        &CopyMutationArgs {
                            to: Some(json_string(&job.params, "to")?),
                            from: Some(json_string(&job.params, "from")?),
                            collection: Some(json_string(&job.params, "collection")?),
                            paths: Vec::new(),
                            dry_run: false,
                            yes: true,
                            non_interactive: true,
                            job_id: Some(job.job_id),
                            max_items: *max_items,
                            logical_filters: Some(logical_filters),
                        },
                    )?;
                }
                other => {
                    return Err(AppError::Input(format!(
                        "resume is not yet implemented for v2 job type {other}"
                    )))
                }
            }
        }
    }
    Ok(EXIT_OK)
}

fn list_v2_jobs(database: &V2ProjectionDb, limit: usize) -> Result<Vec<LocalJob>, AppError> {
    let connection = v2_cli_connection(database)?;
    let mut statement = connection
        .prepare(
            "SELECT job_id, job_type, status, created_time_utc_ms, started_time_utc_ms,
                    finished_time_utc_ms, params_json, progress_json, input_version
             FROM jobs ORDER BY created_time_utc_ms DESC, job_id DESC LIMIT ?1",
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    let rows = statement
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
        .map_err(|source| v2_cli_sql_error(database, source))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| v2_cli_sql_error(database, source))?;
    rows.into_iter()
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

fn v2_local_job(database: &V2ProjectionDb, job_id: &str) -> Result<Option<LocalJob>, AppError> {
    Ok(list_v2_jobs(database, 10_000)?
        .into_iter()
        .find(|job| job.job_id == job_id))
}

fn job_path(params: &serde_json::Value, key: &str) -> Result<PathBuf, AppError> {
    serde_json::from_value(
        params
            .get(key)
            .cloned()
            .ok_or_else(|| AppError::Input(format!("job parameters lack {key}")))?,
    )
    .map_err(AppError::Json)
}

fn job_registry_path(params: &serde_json::Value, key: &str) -> Result<PathBuf, AppError> {
    let path: RegistryPath = serde_json::from_value(
        params
            .get(key)
            .cloned()
            .ok_or_else(|| AppError::Input(format!("job parameters lack {key}")))?,
    )?;
    path.to_path_buf()
        .ok_or_else(|| AppError::Input(format!("job path {key} is unavailable on this platform")))
}

fn job_registry_paths(params: &serde_json::Value, key: &str) -> Result<Vec<PathBuf>, AppError> {
    let paths: Vec<RegistryPath> = serde_json::from_value(
        params
            .get(key)
            .cloned()
            .ok_or_else(|| AppError::Input(format!("job parameters lack {key}")))?,
    )?;
    paths
        .into_iter()
        .map(|path| {
            path.to_path_buf().ok_or_else(|| {
                AppError::Input(format!("job path {key} is unavailable on this platform"))
            })
        })
        .collect()
}

fn execute_v2_report(
    cli: &Cli,
    database: &V2ProjectionDb,
    command: &ReportCommand,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    match command {
        ReportCommand::StalePresence(args) => execute_v2_stale_report(cli, database, &state, args),
        ReportCommand::Risk(args) | ReportCommand::Integrity(args) => {
            if args.continuation.is_some() {
                return Err(AppError::Input(
                    "v2 risk summary does not require a continuation token".to_owned(),
                ));
            }
            let selected_collection = args
                .collection
                .as_deref()
                .map(|selector| {
                    select_collection(&state.collections, selector)?.ok_or_else(|| {
                        AppError::Input(format!("Collection not found: {selector:?}"))
                    })
                })
                .transpose()?;
            let mut remaining = args.limit;
            let mut rows = Vec::new();
            for collection in state
                .collections
                .iter()
                .filter(|collection| {
                    selected_collection
                        .as_ref()
                        .is_none_or(|selected| selected.collection_id == collection.collection_id)
                })
                .filter(|collection| {
                    args.policy
                        .as_deref()
                        .is_none_or(|policy| collection.policy_id.as_deref() == Some(policy))
                })
            {
                let (summary, mut findings) =
                    v2_collection_risk_with_findings(database, &state, collection, remaining)?;
                if let Some(result) = args.result.as_deref() {
                    findings.retain(|finding| finding.result == result);
                }
                remaining = remaining.saturating_sub(findings.len());
                rows.push(json!({
                    "collection": collection,
                    "summary": summary,
                    "findings": findings,
                }));
            }
            let filter = args.result.as_deref();
            if !matches!(filter, None | Some("violated") | Some("uncertain")) {
                return Err(AppError::Input(
                    "--result must be violated or uncertain".to_owned(),
                ));
            }
            let total_at_risk = rows
                .iter()
                .map(|row| row["summary"]["files_at_risk"].as_u64().unwrap_or(0))
                .sum::<u64>();
            let total_uncertain = rows
                .iter()
                .map(|row| row["summary"]["files_uncertain"].as_u64().unwrap_or(0))
                .sum::<u64>();
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 2,
                        "kind": match command { ReportCommand::Risk(_) => "risk", _ => "integrity" },
                        "collections": rows,
                        "files_at_risk": total_at_risk,
                        "files_uncertain": total_uncertain,
                        "limit": args.limit,
                    }))?
                );
            } else {
                println!("Risk report:");
                for row in &rows {
                    println!(
                        "  {} — {} files; {} at risk; {} uncertain",
                        row["collection"]["display_name"]
                            .as_str()
                            .unwrap_or("unknown"),
                        row["summary"]["file_count"].as_u64().unwrap_or(0),
                        row["summary"]["files_at_risk"].as_u64().unwrap_or(0),
                        row["summary"]["files_uncertain"].as_u64().unwrap_or(0),
                    );
                    for finding in row["findings"].as_array().into_iter().flatten() {
                        println!(
                            "    {} — {}",
                            finding["logical_path"].as_str().unwrap_or("unknown path"),
                            finding["reasons"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(serde_json::Value::as_str)
                                .collect::<Vec<_>>()
                                .join("; ")
                        );
                    }
                }
                if total_at_risk > 0 {
                    println!(
                        "Next: add verified copies on another Device/Site with archive copy --to LOCATION."
                    );
                }
                if total_uncertain > 0 {
                    println!("Next: mount the relevant Device and run archive location scan.");
                }
            }
            Ok(if total_at_risk > 0 || total_uncertain > 0 {
                EXIT_FINDINGS
            } else {
                EXIT_OK
            })
        }
        ReportCommand::Policy(args) => {
            let rows = state
                .collections
                .iter()
                .filter(|collection| {
                    args.collection.as_deref().is_none_or(|selector| {
                        collection.collection_id == selector || collection.display_name == selector
                    })
                })
                .filter(|collection| {
                    args.policy
                        .as_deref()
                        .is_none_or(|selector| collection.policy_id.as_deref() == Some(selector))
                })
                .map(|collection| {
                    Ok(json!({
                        "collection": collection,
                        "summary": v2_collection_risk(database, &state, collection)?,
                    }))
                })
                .collect::<Result<Vec<_>, AppError>>()?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"version": 2, "collections": rows}))?
                );
            } else {
                for row in rows {
                    println!(
                        "{} — {} at risk; {} uncertain",
                        row["collection"]["display_name"]
                            .as_str()
                            .unwrap_or("unknown"),
                        row["summary"]["files_at_risk"].as_u64().unwrap_or(0),
                        row["summary"]["files_uncertain"].as_u64().unwrap_or(0),
                    );
                }
            }
            Ok(EXIT_OK)
        }
        ReportCommand::Metadata => Err(AppError::Input(
            "metadata checkpoint/replication reporting will be enabled with v2 sync".to_owned(),
        )),
    }
}

fn execute_v2_stale_report(
    cli: &Cli,
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    args: &StalePresenceArgs,
) -> Result<u8, AppError> {
    let collection = args
        .collection
        .as_deref()
        .map(|selector| {
            select_collection(&state.collections, selector)?
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))
        })
        .transpose()?;
    let threshold_days = args.older_than_days.unwrap_or_else(|| {
        collection
            .as_ref()
            .and_then(|collection| collection.policy_id.as_deref())
            .and_then(|id| state.policies.iter().find(|policy| policy.policy_id == id))
            .map(|policy| policy.requirements.max_observation_age_days)
            .or_else(|| {
                state
                    .policies
                    .iter()
                    .filter(|policy| policy.enabled && policy.status == "active")
                    .map(|policy| policy.requirements.max_observation_age_days)
                    .min()
            })
            .unwrap_or(365)
    });
    let cutoff = i64::try_from(now_utc_ms()?)
        .map_err(|_| AppError::Clock)?
        .saturating_sub(
            i64::try_from(threshold_days.saturating_mul(86_400_000)).unwrap_or(i64::MAX),
        );
    let counts = state
        .locations
        .iter()
        .map(|location| {
            Ok((
                location.location_id.clone(),
                v2_stale_location_count(
                    database,
                    &location.location_id,
                    collection
                        .as_ref()
                        .map(|value| value.collection_id.as_str()),
                    cutoff,
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AppError>>()?;
    let devices = state
        .devices
        .iter()
        .map(|device| {
            let locations = state
                .locations
                .iter()
                .filter(|location| location.device_id.as_deref() == Some(&device.device_id))
                .map(|location| {
                    json!({
                        "location_id": location.location_id,
                        "location_name": location.display_name,
                        "stale_presence_count": counts.get(&location.location_id).copied().unwrap_or(0),
                    })
                })
                .collect::<Vec<_>>();
            let total = locations
                .iter()
                .map(|location| location["stale_presence_count"].as_u64().unwrap_or(0))
                .sum::<u64>();
            json!({
                "device_id": device.device_id,
                "device_name": device.display_name,
                "stale_presence_count": total,
                "locations": locations,
            })
        })
        .collect::<Vec<_>>();
    let total = devices
        .iter()
        .map(|device| device["stale_presence_count"].as_u64().unwrap_or(0))
        .sum::<u64>();
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "threshold_days": threshold_days,
                "collection": collection,
                "devices": devices,
                "stale_presence_count": total,
            }))?
        );
    } else {
        println!("Stale presence (older than {threshold_days} days):");
        for device in &devices {
            println!(
                "{} — {} stale",
                device["device_name"].as_str().unwrap_or("unknown Device"),
                device["stale_presence_count"].as_u64().unwrap_or(0)
            );
            if args.locations {
                for location in device["locations"].as_array().into_iter().flatten() {
                    println!(
                        "  {} — {} stale",
                        location["location_name"]
                            .as_str()
                            .unwrap_or("unknown Location"),
                        location["stale_presence_count"].as_u64().unwrap_or(0)
                    );
                }
            }
        }
        if total > 0 {
            println!("Next: mount the listed Device and run archive location scan LOCATION.");
        }
    }
    Ok(if total > 0 { EXIT_FINDINGS } else { EXIT_OK })
}

fn v2_stale_location_count(
    database: &V2ProjectionDb,
    location_id: &str,
    collection_id: Option<&str>,
    cutoff: i64,
) -> Result<u64, AppError> {
    let count: i64 = v2_cli_connection(database)?
        .query_row(
            "SELECT COUNT(DISTINCT c.copy_claim_id)
             FROM copy_claims c
             WHERE c.location_id = ?1 AND c.state = 'present'
               AND (c.last_seen_time_utc_ms IS NULL OR c.last_seen_time_utc_ms < ?3)
               AND (?2 IS NULL OR EXISTS(
                    SELECT 1 FROM file_refs f
                    WHERE f.collection_id = ?2 AND f.object_id = c.object_id
                      AND f.path_state = 'active'
               ))",
            params![location_id, collection_id, cutoff],
            |row| row.get(0),
        )
        .map_err(|source| v2_cli_sql_error(database, source))?;
    Ok(u64::try_from(count).unwrap_or(0))
}

fn execute_v2_collection_add(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &CollectionAddArgs,
) -> Result<u8, AppError> {
    if args.batch_entries == 0 {
        return Err(AppError::Input(
            "--batch-entries must be greater than zero".to_owned(),
        ));
    }
    let scan_path = std::fs::canonicalize(&args.path).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve inventory path {}: {error}",
            args.path.display()
        ))
    })?;
    if path_contains_git_metadata(&scan_path) {
        return Err(AppError::Input(
            "generic inventory cannot start inside .git metadata; select the content directory instead"
                .to_owned(),
        ));
    }
    if archive_ledger::is_git_annex_repository(&scan_path)? {
        return Err(AppError::Input(
            "archive collection add cannot inventory an unimported git-annex repository; use archive location import-annex --collection COLLECTION"
                .to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    let (location, location_path, fingerprint_status) =
        v2_inventory_location_scope(cli, database, &state, &scan_path, args.location.as_deref())?;
    let collection = if let Some(selector) = args.collection.as_deref() {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_v2_collection_at_location(database, &state, &location.location_id)?
    };
    let relative_prefix = scan_path
        .strip_prefix(&location_path)
        .map_err(|_| AppError::Input("inventory path is outside the selected Location".to_owned()))?
        .to_path_buf();
    let prefix = (!relative_prefix.as_os_str().is_empty()).then_some(relative_prefix);
    let suffix = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let store = V2OriginStore::open(cli.events_path())?;
    let result = archive_ledger::v2_add_files(
        &store,
        database,
        &archive_ledger::V2InventoryConfig {
            root_path: scan_path,
            location_prefix: prefix.clone(),
            logical_prefix: prefix,
            exclusions: args.exclusions.clone(),
            collection_id: collection.collection_id.clone(),
            location_id: location.location_id.clone(),
            device_fingerprint_status: fingerprint_status,
            job_id: args
                .job_id
                .clone()
                .unwrap_or_else(|| format!("job_{suffix}")),
            scan_id: args
                .scan_id
                .clone()
                .unwrap_or_else(|| format!("scan_{suffix}")),
            scan_mode: ScanMode::Add,
            max_items: args.max_items,
        },
    )?;
    if result.status == "running" {
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "Inventory paused after {} files ({}).",
                result.summary.files_observed,
                format_bytes(result.summary.bytes_observed)
            );
            println!("Resume with: archive job resume {}", result.job_id);
        }
        return Ok(EXIT_OK);
    }
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Added files to Collection \"{}\".", collection.display_name);
        println!(
            "  {} files observed; {} new to the Collection; {} newly placed at this Location",
            result.summary.files_observed,
            result.summary.new_paths,
            result
                .summary
                .new_paths
                .saturating_add(result.summary.changed_paths)
        );
        println!(
            "  {} files confirmed good; {} bytes verified",
            result.summary.confirmed_good, result.summary.bytes_observed
        );
        if result.summary.ignored_symlinks > 0 {
            println!(
                "  {} symlinks ignored (symlinks are not Archive Ledger Files)",
                result.summary.ignored_symlinks
            );
        }
        if result.summary.read_errors > 0
            || result.summary.concurrent_changes > 0
            || result.summary.traversal_errors > 0
        {
            println!(
                "  Not recorded: {} read errors; {} files changed while reading; {} traversal errors",
                result.summary.read_errors,
                result.summary.concurrent_changes,
                result.summary.traversal_errors
            );
        }
    }
    Ok(
        if result.summary.read_errors > 0
            || result.summary.concurrent_changes > 0
            || result.summary.traversal_errors > 0
        {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

fn execute_v2_location_scan(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &LocationScanArgs,
) -> Result<u8, AppError> {
    if args.batch_entries == 0 {
        return Err(AppError::Input(
            "--batch-entries must be greater than zero".to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    let hint = args
        .path
        .as_deref()
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(|error| AppError::Input(format!("cannot resolve scan path: {error}")))?
        .unwrap_or(std::fs::canonicalize(std::env::current_dir()?)?);
    let scoped =
        v2_inventory_location_scope(cli, database, &state, &hint, args.location.as_deref());
    let (location, location_path, fingerprint_status) = match scoped {
        Ok(value) => value,
        Err(error) if args.path.is_none() && args.location.is_some() => {
            let selector = args.location.as_deref().expect("checked selector");
            let location = select_location(&state.locations, selector)?
                .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?;
            let root_id = location.archive_root_id.as_deref().ok_or_else(|| {
                AppError::Input("complete scan requires a filesystem Location".to_owned())
            })?;
            let connection = Connection::open(database.path()).map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database.path().to_path_buf(),
                    source,
                })
            })?;
            let mount: Option<String> = connection
                .query_row(
                    "SELECT mount_root_uri FROM device_mounts WHERE host_id = ?1 AND archive_root_id = ?2 AND status = 'mounted' ORDER BY observed_time_utc_ms DESC, mount_id DESC LIMIT 1",
                    params![cli.host, root_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|source| {
                    AppError::V2Projection(V2ProjectionError::Sqlite {
                        path: database.path().to_path_buf(),
                        source,
                    })
                })?;
            let mount = mount.ok_or(error)?;
            let relative = location
                .relative_path
                .as_ref()
                .and_then(RegistryPath::to_path_buf)
                .ok_or_else(|| AppError::Input("Location path is not available".to_owned()))?;
            let path =
                std::fs::canonicalize(Path::new(&mount).join(relative)).map_err(|cause| {
                    AppError::Input(format!(
                        "the last observed mount for {} is unavailable: {cause}",
                        location.display_name
                    ))
                })?;
            v2_inventory_location_scope(cli, database, &state, &path, Some(&location.location_id))?
        }
        Err(error) => return Err(error),
    };
    if hint != location_path && args.path.is_some() {
        return Err(AppError::Input(
            "a complete Location scan must start exactly at the registered Location root"
                .to_owned(),
        ));
    }
    let collection = if let Some(selector) = args.collection.as_deref() {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_v2_collection_at_location(database, &state, &location.location_id)?
    };
    if archive_ledger::is_git_annex_repository(&location_path)? {
        let connection = Connection::open(database.path()).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database.path().to_path_buf(),
                source,
            })
        })?;
        let imported: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM annex_imports WHERE collection_id = ?1 AND worktree_location_id = ?2 AND status = 'complete')",
                params![collection.collection_id, location.location_id],
                |row| row.get(0),
            )
            .map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database.path().to_path_buf(),
                    source,
                })
            })?;
        if !imported {
            return Err(AppError::Input(
                "archive location scan cannot scan an unimported git-annex repository; import it once with archive location import-annex"
                    .to_owned(),
            ));
        }
    }
    let suffix = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let store = V2OriginStore::open(cli.events_path())?;
    let result = archive_ledger::v2_add_files(
        &store,
        database,
        &archive_ledger::V2InventoryConfig {
            root_path: location_path,
            location_prefix: None,
            logical_prefix: None,
            exclusions: args.exclusions.clone(),
            collection_id: collection.collection_id.clone(),
            location_id: location.location_id,
            device_fingerprint_status: fingerprint_status,
            job_id: args
                .job_id
                .clone()
                .unwrap_or_else(|| format!("job_{suffix}")),
            scan_id: args
                .scan_id
                .clone()
                .unwrap_or_else(|| format!("scan_{suffix}")),
            scan_mode: ScanMode::Complete,
            max_items: args.max_items,
        },
    )?;
    if result.status == "running" {
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "Location scan paused after {} files ({}).",
                result.summary.files_observed,
                format_bytes(result.summary.bytes_observed)
            );
            println!("Resume with: archive job resume {}", result.job_id);
        }
        return Ok(EXIT_OK);
    }
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Location scan complete for \"{}\".", location.display_name);
        println!(
            "  {} files observed; {} newly added to this Location; {} confirmed good",
            result.summary.files_observed,
            result
                .summary
                .new_paths
                .saturating_add(result.summary.changed_paths),
            result.summary.confirmed_good
        );
        println!("  {} files now missing", result.summary.missing_paths);
        if result.summary.ignored_symlinks > 0 {
            println!(
                "  {} ordinary symlinks ignored",
                result.summary.ignored_symlinks
            );
        }
    }
    Ok(
        if result.summary.read_errors > 0
            || result.summary.concurrent_changes > 0
            || result.summary.traversal_errors > 0
            || result.summary.integrity_mismatches > 0
        {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

fn execute_v2_copy_mutation(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &CopyMutationArgs,
) -> Result<u8, AppError> {
    let destination_selector = args
        .to
        .as_deref()
        .ok_or_else(|| AppError::Input("archive copy requires --to LOCATION".to_owned()))?;
    if args.non_interactive && !args.dry_run && !args.yes {
        return Err(AppError::Input(
            "copy in non-interactive mode requires --yes (or use --dry-run)".to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    let cwd = std::fs::canonicalize(std::env::current_dir()?)?;
    let (source_location, source_root, _) =
        v2_inventory_location_scope(cli, database, &state, &cwd, args.from.as_deref())?;
    let (destination_location, destination_root, destination_fingerprint) =
        v2_mounted_location_by_selector(cli, database, &state, destination_selector)?;
    if source_location.location_id == destination_location.location_id {
        return Err(AppError::Input(
            "copy source and destination must be different Locations".to_owned(),
        ));
    }
    if !destination_location.is_writable {
        return Err(AppError::Input(format!(
            "destination Location {} is registered read-only",
            destination_location.display_name
        )));
    }
    let collection = if let Some(selector) = args.collection.as_deref() {
        select_collection(&state.collections, selector)?
            .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
    } else {
        infer_v2_collection_at_location(database, &state, &source_location.location_id)?
    };
    let filters = if let Some(filters) = &args.logical_filters {
        filters.clone()
    } else {
        copy_logical_filters(&source_root, &cwd, &args.paths)?
    };
    let mut summary = visit_v2_copy_items(
        database.path(),
        &collection.collection_id,
        &source_location.location_id,
        &destination_location.location_id,
        &filters,
        |item| {
            let source = source_root.join(&item.source_relative_path);
            let metadata = std::fs::symlink_metadata(&source).map_err(|error| {
                AppError::Input(format!(
                    "copy source is unavailable at {}: {error}",
                    source.display()
                ))
            })?;
            if !metadata.file_type().is_file() {
                return Err(AppError::Input(format!(
                    "copy source is not a regular file: {}",
                    source.display()
                )));
            }
            let destination = destination_root.join(&item.logical_path);
            if !destination.starts_with(&destination_root) {
                return Err(AppError::Input(format!(
                    "copy destination escapes its Location: {}",
                    item.logical_path_display
                )));
            }
            ensure_safe_destination_parents(&destination_root, &item.logical_path)?;
            match std::fs::symlink_metadata(&destination) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    archive_ledger::verify_existing_file(&destination, &item.blake3_hex)?;
                }
                Ok(_) => {
                    return Err(AppError::Input(format!(
                        "copy destination exists and is not the expected regular file: {}",
                        destination.display()
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(())
        },
    )?;
    if summary.selected_logical_files == 0 {
        return Err(AppError::Input(
            "no cataloged logical files match the requested copy paths".to_owned(),
        ));
    }
    let objects_to_copy = summary
        .selected_unique_objects
        .saturating_sub(summary.already_present_objects);
    if objects_to_copy == 0 {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2,
                    "status": "nothing_to_copy",
                    "source_location_id": source_location.location_id,
                    "destination_location_id": destination_location.location_id,
                    "collection_id": collection.collection_id,
                    "summary": summary,
                }))?
            );
        } else {
            println!("Nothing to copy; the selected Objects are already present.");
        }
        return Ok(EXIT_OK);
    }
    let available = available_space(&destination_root)?;
    if summary.bytes_to_copy > available {
        return Err(AppError::Input(format!(
            "copy needs {} but only {} is available at the destination",
            format_bytes(summary.bytes_to_copy),
            format_bytes(available)
        )));
    }
    if args.dry_run {
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "version": 2,
                    "status": "planned",
                    "source_location_id": source_location.location_id,
                    "destination_location_id": destination_location.location_id,
                    "collection_id": collection.collection_id,
                    "summary": summary,
                }))?
            );
        } else {
            println!(
                "Copy plan: {} unique Objects ({}) from {} to {}.",
                objects_to_copy,
                format_bytes(summary.bytes_to_copy),
                source_location.display_name,
                destination_location.display_name
            );
            println!("Dry run: no files or ledger facts were changed.");
        }
        return Ok(EXIT_OK);
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::Input(
                "copy requires confirmation; rerun with --yes or inspect it first with --dry-run"
                    .to_owned(),
            ));
        }
        if !prompt_confirmation("Copy and verify these Objects?")? {
            return Err(AppError::Input("copy cancelled".to_owned()));
        }
    }
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{}", ulid::Ulid::new().to_string().to_ascii_lowercase()));
    let filter_identity = serde_json::to_vec(
        &filters
            .iter()
            .map(|path| RegistryPath::from_path(path))
            .collect::<Vec<_>>(),
    )?;
    let input_version = stable_id(
        "input",
        &[
            collection.collection_id.as_bytes(),
            source_location.location_id.as_bytes(),
            destination_location.location_id.as_bytes(),
            &filter_identity,
        ],
    );
    let store = V2OriginStore::open(cli.events_path())?;
    let job_params = json!({
        "cwd": cwd,
        "to": destination_location.location_id,
        "from": source_location.location_id,
        "collection": collection.collection_id,
        "logical_filters": filters,
    });
    ensure_v2_job_started(
        cli,
        database,
        &store,
        &job_id,
        "copy",
        &input_version,
        &job_params,
    )?;
    let mut placements = Vec::with_capacity(1_000);
    let mut processed_this_run = 0_usize;
    let mut interrupted = false;
    visit_v2_copy_items(
        database.path(),
        &collection.collection_id,
        &source_location.location_id,
        &destination_location.location_id,
        &filters,
        |item| {
            if args
                .max_items
                .is_some_and(|limit| processed_this_run >= limit)
            {
                interrupted = true;
                return Ok(());
            }
            let source = source_root.join(&item.source_relative_path);
            let destination = destination_root.join(&item.logical_path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let copied = match std::fs::symlink_metadata(&destination) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    archive_ledger::verify_existing_file(&destination, &item.blake3_hex)?
                }
                Ok(_) => {
                    return Err(AppError::Input(format!(
                        "copy destination appeared as a non-file: {}",
                        destination.display()
                    )))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    archive_ledger::copy_verified_no_replace(
                        &source,
                        &destination,
                        &item.blake3_hex,
                    )?
                }
                Err(error) => return Err(error.into()),
            };
            let modified_time = std::fs::metadata(&destination)
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .and_then(|value| u64::try_from(value.as_millis()).ok());
            placements.push(archive_ledger::V2Placement {
                collection_id: collection.collection_id.clone(),
                location_id: destination_location.location_id.clone(),
                file_ref_id: item.file_ref_id.clone(),
                logical_path: RegistryPath::from_path(&item.logical_path),
                copy_path: RegistryPath::from_path(&item.logical_path),
                object_id: item.object_id.clone(),
                blake3_hex: item.blake3_hex.clone(),
                size_bytes: item.size_bytes,
                modified_time_utc_ms: modified_time,
                device_fingerprint_status: destination_fingerprint.clone(),
                job_id: job_id.clone(),
                job_type: "copy".to_owned(),
                input_version: input_version.clone(),
            });
            summary.copied_objects = summary.copied_objects.saturating_add(1);
            summary.copied_bytes = summary.copied_bytes.saturating_add(copied.bytes_copied);
            processed_this_run = processed_this_run.saturating_add(1);
            if placements.len() == 1_000 {
                archive_ledger::v2_record_placements(&store, database, &placements)?;
                placements.clear();
            }
            Ok(())
        },
    )?;
    archive_ledger::v2_record_placements(&store, database, &placements)?;
    if interrupted {
        update_v2_job_progress(
            database,
            &job_id,
            &json!({
                "phase": "copying",
                "objects_copied_this_run": summary.copied_objects,
                "bytes_copied_this_run": summary.copied_bytes,
            }),
        )?;
        print_stage_import_running(
            cli.json,
            &job_id,
            "copying",
            summary.copied_objects,
            summary.copied_bytes,
        )?;
        return Ok(EXIT_OK);
    }
    finish_v2_job(
        database,
        &store,
        &job_id,
        "copy",
        &input_version,
        "complete",
        &serde_json::to_value(&summary)?,
    )?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "status": "complete",
                "job_id": job_id,
                "source_location_id": source_location.location_id,
                "destination_location_id": destination_location.location_id,
                "collection_id": collection.collection_id,
                "summary": summary,
            }))?
        );
    } else {
        println!(
            "Copy complete: {} Objects ({}), each verified at {}.",
            summary.copied_objects,
            format_bytes(summary.copied_bytes),
            destination_location.display_name
        );
    }
    Ok(EXIT_OK)
}

fn v2_mounted_location_by_selector(
    cli: &Cli,
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    selector: &str,
) -> Result<(LocationSnapshot, PathBuf, String), AppError> {
    let location = select_location(&state.locations, selector)?
        .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?;
    let root_id = location
        .archive_root_id
        .as_deref()
        .ok_or_else(|| AppError::Input("copy requires a mounted filesystem Location".to_owned()))?;
    let connection = Connection::open(database.path()).map_err(|source| {
        AppError::V2Projection(V2ProjectionError::Sqlite {
            path: database.path().to_path_buf(),
            source,
        })
    })?;
    let mount: Option<String> = connection
        .query_row(
            "SELECT mount_root_uri FROM device_mounts WHERE host_id = ?1 AND archive_root_id = ?2 AND status = 'mounted' ORDER BY observed_time_utc_ms DESC, mount_id DESC LIMIT 1",
            params![cli.host, root_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database.path().to_path_buf(),
                source,
            })
        })?;
    let mount = mount.ok_or_else(|| {
        AppError::Input(format!(
            "no current mount is known for {}",
            location.display_name
        ))
    })?;
    let relative = location
        .relative_path
        .as_ref()
        .and_then(RegistryPath::to_path_buf)
        .ok_or_else(|| AppError::Input("Location path is unavailable".to_owned()))?;
    let root = std::fs::canonicalize(Path::new(&mount).join(relative)).map_err(|error| {
        AppError::Input(format!(
            "mounted Location {} is unavailable: {error}",
            location.display_name
        ))
    })?;
    v2_inventory_location_scope(cli, database, state, &root, Some(&location.location_id))
}

fn visit_v2_copy_items(
    database_path: &Path,
    collection_id: &str,
    source_location_id: &str,
    destination_location_id: &str,
    filters: &[PathBuf],
    mut visitor: impl FnMut(&ArchiveCopyItem) -> Result<(), AppError>,
) -> Result<ArchiveCopySummary, AppError> {
    let connection = Connection::open(database_path).map_err(|source| {
        AppError::V2Projection(V2ProjectionError::Sqlite {
            path: database_path.to_path_buf(),
            source,
        })
    })?;
    let mut statement = connection
        .prepare(
            "SELECT f.file_ref_id, f.logical_path_encoding, f.logical_path_bytes,
                    f.logical_path_display, f.object_id, o.canonical_hash_hex,
                    o.size_bytes, source.relative_path_encoding,
                    source.relative_path_bytes, source.relative_path_display,
                    EXISTS(SELECT 1 FROM copy_claims destination
                           WHERE destination.location_id = ?3
                             AND destination.object_id = f.object_id
                             AND destination.state = 'present')
             FROM file_refs f
             JOIN objects o ON o.object_id = f.object_id
             LEFT JOIN copy_claims source ON source.copy_claim_id = (
                 SELECT candidate.copy_claim_id FROM copy_claims candidate
                 WHERE candidate.location_id = ?2 AND candidate.object_id = f.object_id
                   AND candidate.state = 'present' AND candidate.last_verification_result = 'ok'
                 ORDER BY candidate.last_verified_time_utc_ms DESC, candidate.copy_claim_id LIMIT 1
             )
             WHERE f.collection_id = ?1 AND f.path_state = 'active'
             ORDER BY f.object_id, f.logical_path_encoding, f.logical_path_bytes",
        )
        .map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
    let mut rows = statement
        .query(params![
            collection_id,
            source_location_id,
            destination_location_id
        ])
        .map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
    let mut summary = ArchiveCopySummary::default();
    let mut current_object: Option<String> = None;
    let mut current_candidate: Option<ArchiveCopyItem> = None;
    let mut publish = |candidate: Option<ArchiveCopyItem>, summary: &mut ArchiveCopySummary| {
        let Some(candidate) = candidate else {
            return Ok(());
        };
        summary.selected_unique_objects = summary.selected_unique_objects.saturating_add(1);
        if candidate.destination_has_object {
            summary.already_present_objects = summary.already_present_objects.saturating_add(1);
            return Ok(());
        }
        summary.bytes_to_copy = summary.bytes_to_copy.saturating_add(candidate.size_bytes);
        visitor(&candidate)
    };
    while let Some(row) = rows.next().map_err(|source| {
        AppError::V2Projection(V2ProjectionError::Sqlite {
            path: database_path.to_path_buf(),
            source,
        })
    })? {
        let encoding: String = row.get(1).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
        let bytes: Vec<u8> = row.get(2).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
        let display: String = row.get(3).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
        let logical = relative_path_from_bytes(&encoding, &bytes)?;
        if !filters.iter().any(|filter| {
            filter.as_os_str().is_empty() || logical == *filter || logical.starts_with(filter)
        }) {
            continue;
        }
        summary.selected_logical_files = summary.selected_logical_files.saturating_add(1);
        let object_id: String = row.get(4).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
        if current_object.as_deref() != Some(&object_id) {
            publish(current_candidate.take(), &mut summary)?;
            current_object = Some(object_id.clone());
        }
        if current_candidate.is_some() {
            continue;
        }
        let source_encoding: Option<String> = row.get(7).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
        let source_bytes: Option<Vec<u8>> = row.get(8).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
        let source_relative_path = match (source_encoding, source_bytes) {
            (Some(encoding), Some(bytes)) => relative_path_from_bytes(&encoding, &bytes)?,
            _ => {
                return Err(AppError::Input(format!(
                "selected content has no verified source bytes at the source Location: {display}"
            )))
            }
        };
        let size: i64 = row.get(6).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database_path.to_path_buf(),
                source,
            })
        })?;
        current_candidate = Some(ArchiveCopyItem {
            file_ref_id: row.get(0).map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database_path.to_path_buf(),
                    source,
                })
            })?,
            object_id,
            blake3_hex: row.get(5).map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database_path.to_path_buf(),
                    source,
                })
            })?,
            size_bytes: u64::try_from(size)
                .map_err(|_| AppError::Input("negative Object size in SQLite".to_owned()))?,
            logical_path: logical,
            logical_path_encoding: encoding,
            logical_path_bytes: bytes,
            logical_path_display: display,
            source_relative_path,
            destination_has_object: row.get(10).map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database_path.to_path_buf(),
                    source,
                })
            })?,
        });
    }
    publish(current_candidate, &mut summary)?;
    Ok(summary)
}

fn v2_inventory_location_scope(
    cli: &Cli,
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    scan_path: &Path,
    selector: Option<&str>,
) -> Result<(LocationSnapshot, PathBuf, String), AppError> {
    let mounted = archive_ledger::discover_mounted_filesystem(scan_path)?;
    let mut roots = BTreeMap::<String, (PathBuf, String)>::new();
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
                "filesystem identity does not uniquely match an active Archive Root".to_owned(),
            ));
        }
        roots.insert(
            matching[0].archive_root_id.clone(),
            (mounted.mount_root, "match".to_owned()),
        );
    } else {
        let connection = Connection::open(database.path()).map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database.path().to_path_buf(),
                source,
            })
        })?;
        let mut statement = connection
            .prepare(
                "SELECT archive_root_id, mount_root_uri FROM device_mounts
                 WHERE host_id = ?1 AND status = 'mounted' AND archive_root_id IS NOT NULL
                 ORDER BY observed_time_utc_ms DESC, mount_id DESC",
            )
            .map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database.path().to_path_buf(),
                    source,
                })
            })?;
        let values = statement
            .query_map([&cli.host], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database.path().to_path_buf(),
                    source,
                })
            })?;
        for value in values {
            let (root_id, root_path) = value.map_err(|source| {
                AppError::V2Projection(V2ProjectionError::Sqlite {
                    path: database.path().to_path_buf(),
                    source,
                })
            })?;
            let unavailable = state.archive_roots.iter().any(|root| {
                root.archive_root_id == root_id
                    && root.status == "active"
                    && root.identity_state == "unavailable"
            });
            if unavailable && Path::new(&root_path) == mounted.mount_root {
                roots
                    .entry(root_id)
                    .or_insert((PathBuf::from(root_path), "unavailable".to_owned()));
            }
        }
    }
    let requested = selector
        .map(|selector| {
            select_location(&state.locations, selector)?
                .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))
        })
        .transpose()?;
    let mut matches = state
        .locations
        .iter()
        .filter(|location| {
            requested
                .as_ref()
                .is_none_or(|requested| requested.location_id == location.location_id)
        })
        .filter_map(|location| {
            let root_id = location.archive_root_id.as_deref()?;
            let (mount_root, fingerprint_status) = roots.get(root_id)?;
            let relative = location.relative_path.as_ref()?.to_path_buf()?;
            let location_path = mount_root.join(relative);
            scan_path.starts_with(&location_path).then(|| {
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
            "path is not inside the selected mounted Location".to_owned(),
        ));
    };
    if matches.get(1).is_some_and(|other| other.0 == best.0) {
        return Err(AppError::Input(
            "path matches multiple Locations equally; specify --location".to_owned(),
        ));
    }
    Ok((best.2.clone(), best.3.clone(), best.4.clone()))
}

fn infer_v2_collection_at_location(
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    location_id: &str,
) -> Result<CollectionSnapshot, AppError> {
    let connection = Connection::open(database.path()).map_err(|source| {
        AppError::V2Projection(V2ProjectionError::Sqlite {
            path: database.path().to_path_buf(),
            source,
        })
    })?;
    let mut statement = connection
        .prepare(
            "SELECT DISTINCT f.collection_id
             FROM path_observations p JOIN file_refs f ON f.file_ref_id = p.file_ref_id
             WHERE p.location_id = ?1 ORDER BY f.collection_id",
        )
        .map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database.path().to_path_buf(),
                source,
            })
        })?;
    let ids = statement
        .query_map([location_id], |row| row.get::<_, String>(0))
        .map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database.path().to_path_buf(),
                source,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|source| {
            AppError::V2Projection(V2ProjectionError::Sqlite {
                path: database.path().to_path_buf(),
                source,
            })
        })?;
    let collections = ids
        .iter()
        .filter_map(|id| {
            state
                .collections
                .iter()
                .find(|value| value.collection_id == *id)
        })
        .cloned()
        .collect::<Vec<_>>();
    match collections.as_slice() {
        [collection] => Ok(collection.clone()),
        [] if state.collections.len() == 1 => Ok(state.collections[0].clone()),
        [] => Err(AppError::Input(
            "Location has no Collection inventory yet; specify --collection".to_owned(),
        )),
        _ => Err(AppError::Input(
            "Location contains multiple Collections; specify --collection".to_owned(),
        )),
    }
}

fn execute_v2_location_status(
    cli: &Cli,
    database: &V2ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let location = if let Some(selector) = selector {
        select_location(&state.locations, selector)?
            .ok_or_else(|| AppError::Input(format!("Location not found: {selector:?}")))?
    } else {
        infer_v2_cwd_location(cli, database, &state)?
    };
    let device = location
        .device_id
        .as_deref()
        .and_then(|id| state.devices.iter().find(|item| item.device_id == id));
    let site = location
        .site_id
        .as_deref()
        .and_then(|id| state.sites.iter().find(|item| item.site_id == id))
        .or_else(|| {
            device
                .and_then(|device| device.current_site_id.as_deref())
                .and_then(|id| state.sites.iter().find(|item| item.site_id == id))
        });
    let metrics = v2_location_metrics(database, &state, &location.location_id)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"version": 2, "location": location, "device": device, "site": site, "metrics": metrics})
            )?
        );
    } else {
        println!("Location: {}", location.display_name);
        println!(
            "Device: {}; Site: {}",
            device.map_or("none", |item| item.display_name.as_str()),
            site.map_or("unknown", |item| item.display_name.as_str())
        );
        println!(
            "Path on Device: {}",
            location
                .relative_path
                .as_ref()
                .map_or("not applicable", |path| path.display.as_str())
        );
        println!("Files: {}", metrics.file_count);
        println!("Space used: {}", format_bytes(metrics.space_used_bytes));
        println!(
            "Stale presence: {} (older than {} days)",
            metrics.stale_presence_count, metrics.stale_after_days
        );
    }
    Ok(EXIT_OK)
}

fn execute_v2_device_status(
    cli: &Cli,
    database: &V2ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let device = if let Some(selector) = selector {
        select_device(&state.devices, selector)?
            .ok_or_else(|| AppError::Input(format!("Device not found: {selector:?}")))?
    } else {
        let location = infer_v2_cwd_location(cli, database, &state)?;
        let id = location.device_id.ok_or_else(|| {
            AppError::Input("cwd Location is a service and has no Device".to_owned())
        })?;
        state
            .devices
            .iter()
            .find(|value| value.device_id == id)
            .cloned()
            .ok_or_else(|| AppError::Input("cwd Device is not active".to_owned()))?
    };
    let site = device
        .current_site_id
        .as_deref()
        .and_then(|id| state.sites.iter().find(|item| item.site_id == id));
    let locations = state
        .locations
        .iter()
        .filter(|item| item.device_id.as_deref() == Some(&device.device_id))
        .collect::<Vec<_>>();
    let location_metrics = locations
        .iter()
        .map(|location| {
            Ok((
                location.location_id.clone(),
                v2_location_metrics(database, &state, &location.location_id)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AppError>>()?;
    let total_files = location_metrics
        .values()
        .map(|metrics| metrics.file_count)
        .sum::<u64>();
    let total_bytes = location_metrics
        .values()
        .map(|metrics| metrics.space_used_bytes)
        .sum::<u64>();
    let total_stale = location_metrics
        .values()
        .map(|metrics| metrics.stale_presence_count)
        .sum::<u64>();
    let (free_space_bytes, capacity_status) = v2_device_capacity(cli, database, &state, &device)?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"version": 2, "device": device, "site": site, "locations": locations.iter().map(|location| json!({"location": location, "metrics": location_metrics.get(&location.location_id)})).collect::<Vec<_>>(), "file_count": total_files, "space_used_bytes": total_bytes, "stale_presence_count": total_stale, "free_space_bytes": free_space_bytes, "capacity_status": capacity_status})
            )?
        );
    } else {
        println!("Device: {}", device.display_name);
        println!(
            "Identifier: {}",
            device
                .hardware_fingerprint
                .as_deref()
                .unwrap_or("unavailable")
        );
        println!(
            "Site: {}",
            site.map_or("unknown", |item| item.display_name.as_str())
        );
        println!("Files in Locations: {total_files}");
        println!("Space used: {}", format_bytes(total_bytes));
        println!("Stale presence: {total_stale}");
        match free_space_bytes {
            Some(bytes) => println!("Free space: {}", format_bytes(bytes)),
            None => println!("Free space: unavailable ({capacity_status})"),
        }
        println!("Locations:");
        for location in locations {
            let metrics = location_metrics
                .get(&location.location_id)
                .expect("metrics were collected for every Location");
            println!(
                "  {} — {} files; {}; stale {} (older than {} days)",
                location.display_name,
                metrics.file_count,
                format_bytes(metrics.space_used_bytes),
                metrics.stale_presence_count,
                metrics.stale_after_days,
            );
        }
    }
    Ok(EXIT_OK)
}

fn v2_device_capacity(
    cli: &Cli,
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
    device: &DeviceSnapshot,
) -> Result<(Option<u64>, String), AppError> {
    let roots = state
        .archive_roots
        .iter()
        .filter(|root| {
            root.device_id == device.device_id
                && root.status == "active"
                && root.identity_state == "confirmed"
        })
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Ok((None, "Device identity is not confirmed".to_owned()));
    }
    let connection = Connection::open(database.path())
        .map_err(|error| AppError::Input(format!("cannot read Device mounts: {error}")))?;
    for root in roots {
        let mount: Option<String> = connection
            .query_row(
                "SELECT mount_root_uri FROM device_mounts
                 WHERE host_id = ?1 AND archive_root_id = ?2 AND status = 'mounted'
                 ORDER BY observed_time_utc_ms DESC, mount_id DESC LIMIT 1",
                params![cli.host, root.archive_root_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| AppError::Input(format!("cannot read Device mounts: {error}")))?;
        let Some(mount) = mount else { continue };
        let mount = PathBuf::from(mount);
        let Ok(discovered) = archive_ledger::discover_mounted_filesystem(&mount) else {
            continue;
        };
        if discovered.fingerprint_kind == root.fingerprint_kind
            && discovered.filesystem_fingerprint == root.filesystem_fingerprint
        {
            return Ok((
                Some(available_space(&mount).map_err(AppError::Io)?),
                "verified mounted filesystem".to_owned(),
            ));
        }
    }
    Ok((
        None,
        "no currently mounted filesystem matches the registered identity".to_owned(),
    ))
}

fn execute_v2_site_status(
    cli: &Cli,
    database: &V2ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let site = if let Some(selector) = selector {
        select_site(&state.sites, selector)?
            .ok_or_else(|| AppError::Input(format!("Site not found: {selector:?}")))?
    } else {
        let location = infer_v2_cwd_location(cli, database, &state)?;
        let site_id = location.site_id.or_else(|| {
            location.device_id.as_deref().and_then(|device_id| {
                state
                    .devices
                    .iter()
                    .find(|value| value.device_id == device_id)
                    .and_then(|value| value.current_site_id.clone())
            })
        });
        let site_id =
            site_id.ok_or_else(|| AppError::Input("cwd Location has no Site".to_owned()))?;
        state
            .sites
            .iter()
            .find(|value| value.site_id == site_id)
            .cloned()
            .ok_or_else(|| AppError::Input("cwd Site is not active".to_owned()))?
    };
    let devices = state
        .devices
        .iter()
        .filter(|item| item.current_site_id.as_deref() == Some(&site.site_id))
        .collect::<Vec<_>>();
    let device_metrics = devices
        .iter()
        .map(|device| {
            let metrics = state
                .locations
                .iter()
                .filter(|location| location.device_id.as_deref() == Some(&device.device_id))
                .map(|location| v2_location_metrics(database, &state, &location.location_id))
                .collect::<Result<Vec<_>, AppError>>()?;
            Ok((
                device.device_id.clone(),
                V2LocationMetrics {
                    file_count: metrics.iter().map(|value| value.file_count).sum(),
                    space_used_bytes: metrics.iter().map(|value| value.space_used_bytes).sum(),
                    stale_presence_count: metrics
                        .iter()
                        .map(|value| value.stale_presence_count)
                        .sum(),
                    stale_after_days: metrics
                        .iter()
                        .map(|value| value.stale_after_days)
                        .min()
                        .unwrap_or(365),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AppError>>()?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"version": 2, "site": site, "devices": devices.iter().map(|device| json!({"device": device, "metrics": device_metrics.get(&device.device_id)})).collect::<Vec<_>>() })
            )?
        );
    } else {
        println!("Site: {}", site.display_name);
        println!("Devices:");
        for device in devices {
            let metrics = device_metrics
                .get(&device.device_id)
                .expect("metrics were collected for every Device");
            println!(
                "  {} — {} files; {}; stale {} (older than {} days)",
                device.display_name,
                metrics.file_count,
                format_bytes(metrics.space_used_bytes),
                metrics.stale_presence_count,
                metrics.stale_after_days,
            );
        }
    }
    Ok(EXIT_OK)
}

fn execute_v2_policy_update(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &PolicyUpdateArgs,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
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
    record_v2_registry_change(
        cli,
        database,
        RegistryChange::Policy(RegistryAction::Update, policy),
    )?;
    Ok(EXIT_OK)
}

fn infer_v2_cwd_location(
    cli: &Cli,
    database: &V2ProjectionDb,
    state: &archive_ledger::RegistryState,
) -> Result<LocationSnapshot, AppError> {
    let cwd = std::fs::canonicalize(std::env::current_dir()?)?;
    let mounted = archive_ledger::discover_mounted_filesystem(&cwd)?;
    let mut roots = BTreeMap::<String, PathBuf>::new();
    if let (Some(kind), Some(fingerprint)) = (
        mounted.fingerprint_kind.as_deref(),
        mounted.filesystem_fingerprint.as_deref(),
    ) {
        for root in state.archive_roots.iter().filter(|root| {
            root.status == "active"
                && root.identity_state == "confirmed"
                && root.fingerprint_kind.as_deref() == Some(kind)
                && root.filesystem_fingerprint.as_deref() == Some(fingerprint)
        }) {
            roots.insert(root.archive_root_id.clone(), mounted.mount_root.clone());
        }
    } else {
        let connection = Connection::open(database.path())
            .map_err(|error| AppError::Input(format!("cannot read mount observations: {error}")))?;
        let mut statement = connection
            .prepare(
                "SELECT archive_root_id, mount_root_uri FROM device_mounts
                 WHERE host_id = ?1 AND status = 'mounted' AND archive_root_id IS NOT NULL
                 ORDER BY observed_time_utc_ms DESC, mount_id DESC",
            )
            .map_err(|error| AppError::Input(format!("cannot read mount observations: {error}")))?;
        let observations = statement
            .query_map([&cli.host], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|error| AppError::Input(format!("cannot read mount observations: {error}")))?;
        for observation in observations {
            let (root_id, mount_root) = observation.map_err(|error| {
                AppError::Input(format!("cannot read mount observations: {error}"))
            })?;
            roots
                .entry(root_id)
                .or_insert_with(|| PathBuf::from(mount_root));
        }
    }
    let mut matches = state
        .locations
        .iter()
        .filter_map(|location| {
            let root_id = location.archive_root_id.as_deref()?;
            let mount_root = roots.get(root_id)?;
            let relative = location.relative_path.as_ref()?.to_path_buf()?;
            let absolute = mount_root.join(relative);
            cwd.starts_with(&absolute).then(|| {
                (
                    absolute.components().count(),
                    location.location_id.clone(),
                    location.clone(),
                )
            })
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let Some(best) = matches.first() else {
        return Err(AppError::Input(
            "cwd is not inside a known mounted Location; specify one by name or ID".to_owned(),
        ));
    };
    if matches.get(1).is_some_and(|other| other.0 == best.0) {
        return Err(AppError::Input(
            "cwd matches multiple Locations equally; specify one by name or ID".to_owned(),
        ));
    }
    Ok(best.2.clone())
}

fn execute_v2_collection_init(
    cli: &Cli,
    database: &V2ProjectionDb,
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
        execute_v2_annex_setup(cli, database, &setup, None)
    } else {
        execute_v2_filesystem_setup(cli, database, &setup, None)
    }
}

struct V2FilesystemSetup {
    collection: CollectionSnapshot,
    location: LocationSnapshot,
    device: DeviceSnapshot,
    site: SiteSnapshot,
    root: ArchiveRootSnapshot,
    policy: Option<PolicySnapshot>,
    mounted: archive_ledger::MountedFilesystem,
    adding_location: bool,
}

fn prepare_v2_filesystem_setup(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &CollectionInitArgs,
    existing_collection: Option<CollectionSnapshot>,
) -> Result<V2FilesystemSetup, AppError> {
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();
    let collection_name = existing_collection
        .as_ref()
        .map(|value| value.display_name.clone())
        .or_else(|| args.name.as_deref().map(str::trim).map(str::to_owned))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Input("Collection name must be non-empty".to_owned()))?;
    let mounted = archive_ledger::discover_mounted_filesystem(&args.path)?;
    if mounted.identity_state == "unavailable"
        && !args.allow_unidentified_root
        && (!interactive
            || !prompt_confirmation(
                "No stable filesystem or partition UUID is available. Register this root with unconfirmed identity?",
            )?)
    {
        return Err(AppError::Input(
            "stable filesystem identity is unavailable; rerun with --allow-unidentified-root to confirm"
                .to_owned(),
        ));
    }
    let state = database.registry_state(false)?;
    if existing_collection.is_none()
        && state
            .collections
            .iter()
            .any(|value| value.display_name == collection_name)
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
                root.status == "active"
                    && root.fingerprint_kind.as_deref() == Some(kind)
                    && root.filesystem_fingerprint.as_deref() == Some(fingerprint)
            })
            .cloned()
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    if matching_roots.len() > 1
        || matching_roots
            .iter()
            .any(|root| root.identity_state != "confirmed")
    {
        return Err(AppError::Input(
            "the filesystem identity is ambiguous or conflicting; resolve the Archive Root before setup"
                .to_owned(),
        ));
    }

    let mut changes = Vec::new();
    let (site, device, root) = if let Some(root) = matching_roots.into_iter().next() {
        let device = state
            .devices
            .iter()
            .find(|value| value.device_id == root.device_id)
            .cloned()
            .ok_or_else(|| AppError::Input("known Archive Root has no active Device".to_owned()))?;
        let site = device
            .current_site_id
            .as_deref()
            .and_then(|id| state.sites.iter().find(|value| value.site_id == id))
            .cloned()
            .ok_or_else(|| AppError::Input("known Device has no active Site".to_owned()))?;
        if args
            .device
            .as_deref()
            .is_some_and(|selector| selector != device.device_id && selector != device.display_name)
            || args
                .site
                .as_deref()
                .is_some_and(|selector| selector != site.site_id && selector != site.display_name)
        {
            return Err(AppError::Input(
                "the supplied Device or Site does not match the known filesystem identity"
                    .to_owned(),
            ));
        }
        (site, device, root)
    } else {
        let device_selector = required_or_prompt(
            args.device.as_deref(),
            interactive,
            "Device name",
            "Primary storage",
            "--device",
        )?;
        let existing_device = select_device(&state.devices, &device_selector)?;
        let site = if let Some(device) = &existing_device {
            let site_id = device.current_site_id.as_deref().ok_or_else(|| {
                AppError::Input(format!("Device {} has no Site", device.display_name))
            })?;
            state
                .sites
                .iter()
                .find(|value| value.site_id == site_id)
                .cloned()
                .ok_or_else(|| AppError::Input("Device Site is missing".to_owned()))?
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
        let device =
            if let Some(device) = existing_device {
                if args.site.as_deref().is_some_and(|selector| {
                    selector != site.site_id && selector != site.display_name
                }) {
                    return Err(AppError::Input(
                        "the supplied Site does not match the existing Device".to_owned(),
                    ));
                }
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
        let reusable_root = (mounted.identity_state == "unavailable")
            .then(|| {
                state.archive_roots.iter().find(|root| {
                    root.device_id == device.device_id
                        && root.identity_state == "unavailable"
                        && root.root_path_on_device == RegistryPath::utf8("/")
                })
            })
            .flatten()
            .cloned();
        let root = if let Some(root) = reusable_root {
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
        (site, device, root)
    };

    let relative_path = RegistryPath::from_path(&mounted.relative_path);
    let location = if let Some(location) = state.locations.iter().find(|value| {
        value.archive_root_id.as_deref() == Some(&root.archive_root_id)
            && value.relative_path.as_ref() == Some(&relative_path)
    }) {
        location.clone()
    } else {
        let location = LocationSnapshot {
            location_id: generated_id("location"),
            display_name: args
                .location_name
                .clone()
                .unwrap_or_else(|| format!("{collection_name} on {}", device.display_name)),
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
    let adding_location = existing_collection.is_some();
    let (collection, policy) = if let Some(collection) = existing_collection {
        let policy = collection
            .policy_id
            .as_deref()
            .and_then(|id| state.policies.iter().find(|value| value.policy_id == id))
            .cloned();
        (collection, policy)
    } else {
        let policy = state
            .policies
            .iter()
            .find(|value| value.policy_id == "policy_starter")
            .cloned()
            .unwrap_or_else(|| starter_policy("policy_starter".to_owned()));
        if !state
            .policies
            .iter()
            .any(|value| value.policy_id == policy.policy_id)
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
        (collection, Some(policy))
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

    let store = V2OriginStore::open(cli.events_path())?;
    let registry = V2Registry::new(&store, database);
    for change in changes {
        registry.record(change, &cli.host)?;
    }
    Ok(V2FilesystemSetup {
        collection,
        location,
        device,
        site,
        root,
        policy,
        mounted,
        adding_location,
    })
}

fn print_v2_filesystem_setup(cli: &Cli, setup: &V2FilesystemSetup) -> Result<(), AppError> {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "collection": setup.collection,
                "location": setup.location,
                "device": setup.device,
                "site": setup.site,
                "archive_root": setup.root,
                "mounted": setup.mounted,
            }))?
        );
    } else {
        if setup.adding_location {
            println!(
                "Configured Location \"{}\" for Collection \"{}\".",
                setup.location.display_name, setup.collection.display_name
            );
        } else {
            println!("Created Collection \"{}\".", setup.collection.display_name);
        }
        println!(
            "Location: \"{}\" (Device \"{}\", Site \"{}\").",
            setup.location.display_name, setup.device.display_name, setup.site.display_name
        );
        if setup.root.identity_state != "confirmed" {
            println!(
                "Storage identity is unconfirmed; this Device cannot yet prove an independent copy."
            );
        }
        if let Some(policy) = &setup.policy {
            print_policy_summary(policy);
        }
        println!(
            "Next: archive collection add . --collection {}",
            shell_quote(&setup.collection.display_name)
        );
    }
    Ok(())
}

fn execute_v2_filesystem_setup(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &CollectionInitArgs,
    existing_collection: Option<CollectionSnapshot>,
) -> Result<u8, AppError> {
    let setup = prepare_v2_filesystem_setup(cli, database, args, existing_collection)?;
    print_v2_filesystem_setup(cli, &setup)?;
    Ok(EXIT_OK)
}

fn execute_v2_annex_setup(
    cli: &Cli,
    database: &V2ProjectionDb,
    args: &CollectionInitArgs,
    existing_collection: Option<CollectionSnapshot>,
) -> Result<u8, AppError> {
    validate_setup_source(&args.path, true, SetupCommand::Collection)?;
    if args.batch_entries == 0 {
        return Err(AppError::Input(
            "--batch-entries must be greater than zero".to_owned(),
        ));
    }
    let setup = prepare_v2_filesystem_setup(cli, database, args, existing_collection)?;
    let suffix = ulid::Ulid::new().to_string().to_ascii_lowercase();
    let job_id = args
        .job_id
        .clone()
        .unwrap_or_else(|| format!("job_{suffix}"));
    let import_id = args
        .import_id
        .clone()
        .unwrap_or_else(|| format!("import_{suffix}"));
    let store = V2OriginStore::open(cli.events_path())?;
    let importer = archive_ledger::V2AnnexImporter::new(
        &store,
        database,
        AnnexImportConfig {
            repo_path: setup.mounted.path.clone(),
            import_id: import_id.clone(),
            job_id: job_id.clone(),
            collection_id: setup.collection.collection_id.clone(),
            worktree_location_id: setup.location.location_id.clone(),
            cas_location_id: setup.location.location_id.clone(),
            device_id: setup.device.device_id.clone(),
            archive_root_id: setup.root.archive_root_id.clone(),
            batch_entries: args.batch_entries,
        },
    )?;
    let result = importer.run_at_most(args.max_items)?;
    let status = if result.status == AnnexImportStatus::Complete {
        "complete"
    } else {
        "running"
    };
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 2,
                "collection": setup.collection,
                "location": setup.location,
                "device": setup.device,
                "site": setup.site,
                "archive_root": setup.root,
                "annex_import": {
                    "job_id": job_id,
                    "import_id": import_id,
                    "status": status,
                    "annex_uuid": result.annex_uuid,
                    "git_head_commit": result.git_head_commit,
                    "summary": result.summary,
                }
            }))?
        );
    } else {
        if result.status == AnnexImportStatus::Interrupted {
            println!(
                "Annex import paused after {} index entries.",
                result.summary.entries_seen
            );
            println!("Resume with: archive job resume {job_id}");
        } else {
            println!(
                "Imported git-annex repository as Location \"{}\" in Collection \"{}\".",
                setup.location.display_name, setup.collection.display_name
            );
        }
        println!(
            "  {} annex entries; {} present here; {} absent here; {} ordinary symlinks ignored",
            result.summary.entries_seen,
            result.summary.present,
            result.summary.absent,
            result.summary.ignored_symlinks
        );
        if result.summary.mismatched > 0 || result.summary.read_errors > 0 {
            println!(
                "  Integrity findings: {} mismatched; {} read errors",
                result.summary.mismatched, result.summary.read_errors
            );
        }
    }
    Ok(
        if result.summary.mismatched > 0 || result.summary.read_errors > 0 {
            EXIT_FINDINGS
        } else {
            EXIT_OK
        },
    )
}

fn execute_site(cli: &Cli, database: &ProjectionDb, command: &SiteCommand) -> Result<u8, AppError> {
    match command {
        SiteCommand::Status { site } => execute_site_status(cli, database, site.as_deref()),
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
        DeviceCommand::Status { device } => execute_device_status(cli, database, device.as_deref()),
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

fn execute_device_status(
    cli: &Cli,
    database: &ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let device = if let Some(selector) = selector {
        select_device(&state.devices, selector)?
            .ok_or_else(|| AppError::Input(format!("Device not found: {selector:?}")))?
    } else {
        let location = infer_cwd_location(cli, database, &state)?;
        let device_id = location.device_id.as_deref().ok_or_else(|| {
            AppError::Input("cwd Location is a service and has no Device".to_owned())
        })?;
        state
            .devices
            .iter()
            .find(|device| device.device_id == device_id)
            .cloned()
            .ok_or_else(|| AppError::Input("cwd Location Device is not active".to_owned()))?
    };
    let stale = stale_status_index(database)?;
    let locations = state
        .locations
        .iter()
        .filter(|location| location.device_id.as_deref() == Some(device.device_id.as_str()))
        .map(|location| enriched_location_status(database, &location.location_id, &stale))
        .collect::<Result<Vec<_>, _>>()?;
    let file_count = locations.iter().fold(0_u64, |total, location| {
        total.saturating_add(location.logical_file_count)
    });
    let space_used_bytes = locations.iter().fold(0_u64, |total, location| {
        total.saturating_add(location.present_bytes)
    });
    let stale_presence_count = aggregate_stale_presence(&locations);
    let site = device
        .current_site_id
        .as_deref()
        .and_then(|site_id| state.sites.iter().find(|site| site.site_id == site_id));
    let output = DeviceStatusOutput {
        version: 1,
        device_id: device.device_id.clone(),
        device_name: device.display_name.clone(),
        identifier: device_identifier(&state, &device),
        site_id: site.map(|site| site.site_id.clone()),
        site_name: site.map(|site| site.display_name.clone()),
        file_count,
        space_used_bytes,
        stale_presence_count,
        capacity: device_capacity(database, &state, &device),
        locations,
    };
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Device: {}", output.device_name);
        println!(
            "Identifier: {} {}",
            output.identifier.kind, output.identifier.value
        );
        println!("Site: {}", output.site_name.as_deref().unwrap_or("unknown"));
        println!("Files in Locations: {}", output.file_count);
        println!("Space used: {}", format_bytes(output.space_used_bytes));
        match output.capacity.available_bytes {
            Some(bytes) => println!("Free space: {}", format_bytes(bytes)),
            None => println!("Free space: unavailable ({})", output.capacity.status),
        }
        println!("Locations:");
        if output.locations.is_empty() {
            println!("  None.");
        }
        for location in &output.locations {
            println!("  {}", location.location_name);
            println!(
                "    Files: {}; Space used: {}; {}",
                location.logical_file_count,
                format_bytes(location.present_bytes),
                format_stale_presence(location)
            );
        }
    }
    Ok(EXIT_OK)
}

fn execute_site_status(
    cli: &Cli,
    database: &ProjectionDb,
    selector: Option<&str>,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let site = if let Some(selector) = selector {
        select_site(&state.sites, selector)?
            .ok_or_else(|| AppError::Input(format!("Site not found: {selector:?}")))?
    } else {
        let location = infer_cwd_location(cli, database, &state)?;
        let site_id = location.site_id.clone().or_else(|| {
            location.device_id.as_deref().and_then(|device_id| {
                state
                    .devices
                    .iter()
                    .find(|device| device.device_id == device_id)
                    .and_then(|device| device.current_site_id.clone())
            })
        });
        let site_id = site_id.ok_or_else(|| {
            AppError::Input("cwd Location has no active Site association".to_owned())
        })?;
        state
            .sites
            .iter()
            .find(|site| site.site_id == site_id)
            .cloned()
            .ok_or_else(|| AppError::Input("cwd Location Site is not active".to_owned()))?
    };
    let stale = stale_status_index(database)?;
    let mut devices = Vec::new();
    for device in state
        .devices
        .iter()
        .filter(|device| device.current_site_id.as_deref() == Some(site.site_id.as_str()))
    {
        let locations = state
            .locations
            .iter()
            .filter(|location| location.device_id.as_deref() == Some(device.device_id.as_str()))
            .map(|location| enriched_location_status(database, &location.location_id, &stale))
            .collect::<Result<Vec<_>, _>>()?;
        devices.push(SiteDeviceStatus {
            device_id: device.device_id.clone(),
            device_name: device.display_name.clone(),
            file_count: locations.iter().fold(0_u64, |total, location| {
                total.saturating_add(location.logical_file_count)
            }),
            space_used_bytes: locations.iter().fold(0_u64, |total, location| {
                total.saturating_add(location.present_bytes)
            }),
            stale_presence_count: aggregate_stale_presence(&locations),
        });
    }
    devices.sort_by(|left, right| {
        left.device_name
            .cmp(&right.device_name)
            .then(left.device_id.cmp(&right.device_id))
    });
    let output = SiteStatusOutput {
        version: 1,
        site_id: site.site_id,
        site_name: site.display_name,
        devices,
    };
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Site: {}", output.site_name);
        println!("Devices:");
        if output.devices.is_empty() {
            println!("  None.");
        }
        for device in &output.devices {
            println!("  {}", device.device_name);
            println!(
                "    Files: {}; Space used: {}; Stale presence: {}",
                device.file_count,
                format_bytes(device.space_used_bytes),
                device
                    .stale_presence_count
                    .map_or_else(|| "unavailable".to_owned(), |count| count.to_string())
            );
        }
    }
    Ok(EXIT_OK)
}

fn aggregate_stale_presence(locations: &[LocationStatus]) -> Option<u64> {
    if locations.is_empty() {
        return Some(0);
    }
    locations.iter().try_fold(0_u64, |total, location| {
        location
            .stale_presence_count
            .map(|count| total.saturating_add(count))
    })
}

fn device_identifier(
    state: &archive_ledger::RegistryState,
    device: &DeviceSnapshot,
) -> DeviceIdentifier {
    if let Some(value) = device.hardware_fingerprint.as_deref() {
        return DeviceIdentifier {
            kind: device
                .fingerprint_kind
                .clone()
                .unwrap_or_else(|| "hardware".to_owned()),
            value: value.to_owned(),
        };
    }
    if let Some(root) = state.archive_roots.iter().find(|root| {
        root.device_id == device.device_id
            && root.status == "active"
            && root.identity_state == "confirmed"
            && root.filesystem_fingerprint.is_some()
    }) {
        return DeviceIdentifier {
            kind: root
                .fingerprint_kind
                .clone()
                .unwrap_or_else(|| "filesystem".to_owned()),
            value: root.filesystem_fingerprint.clone().expect("filtered above"),
        };
    }
    if let Some(serial) = device.serial_hint.as_deref() {
        return DeviceIdentifier {
            kind: "serial_hint".to_owned(),
            value: serial.to_owned(),
        };
    }
    DeviceIdentifier {
        kind: "archive_ledger_id".to_owned(),
        value: device.device_id.clone(),
    }
}

fn device_capacity(
    database: &ProjectionDb,
    state: &archive_ledger::RegistryState,
    device: &DeviceSnapshot,
) -> DeviceCapacity {
    let Ok(Some(mount)) = database.latest_device_mount(&device.device_id) else {
        return unavailable_capacity("Device is not recorded as mounted", None);
    };
    let mount_path = PathBuf::from(&mount.mount_root_uri);
    if !mount_path.is_absolute() {
        return unavailable_capacity(
            "latest mount is not a local filesystem path",
            Some(mount.mount_root_uri),
        );
    }
    let Some(root_id) = mount.archive_root_id.as_deref() else {
        return unavailable_capacity(
            "latest mount lacks Archive Root identity",
            Some(mount.mount_root_uri),
        );
    };
    let Some(root) = state
        .archive_roots
        .iter()
        .find(|root| root.archive_root_id == root_id && root.device_id == device.device_id)
    else {
        return unavailable_capacity(
            "latest mount refers to an inactive Archive Root",
            Some(mount.mount_root_uri),
        );
    };
    let (Some(expected_kind), Some(expected_fingerprint)) = (
        root.fingerprint_kind.as_deref(),
        root.filesystem_fingerprint.as_deref(),
    ) else {
        return unavailable_capacity(
            "Device filesystem identity is unconfirmed",
            Some(mount.mount_root_uri),
        );
    };
    let Ok(observed) = archive_ledger::discover_mounted_filesystem(&mount_path) else {
        return unavailable_capacity(
            "recorded mount is not currently available",
            Some(mount.mount_root_uri),
        );
    };
    if observed.fingerprint_kind.as_deref() != Some(expected_kind)
        || observed.filesystem_fingerprint.as_deref() != Some(expected_fingerprint)
    {
        return unavailable_capacity(
            "mounted filesystem identity does not match the Device",
            Some(mount.mount_root_uri),
        );
    }
    match available_space(&observed.mount_root) {
        Ok(bytes) => DeviceCapacity {
            available_bytes: Some(bytes),
            status: "available".to_owned(),
            mount_path: Some(observed.mount_root.display().to_string()),
        },
        Err(_) => unavailable_capacity(
            "filesystem capacity could not be read",
            Some(observed.mount_root.display().to_string()),
        ),
    }
}

fn unavailable_capacity(status: &str, mount_path: Option<String>) -> DeviceCapacity {
    DeviceCapacity {
        available_bytes: None,
        status: status.to_owned(),
        mount_path,
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
        CollectionCommand::Add(args) => execute_location_inventory(
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
            validate_setup_source(&args.path, false, SetupCommand::Location)?;
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
                max_items: None,
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
                max_items: args.max_items,
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
        LocationCommand::Copy(args) => execute_copy_mutation(cli, database, args),
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
    current_policy_status(database)?;
    let mut summary = database.collection_summary(&collection.collection_id)?;
    let stale = stale_status_index(database)?;
    summary.locations = database
        .collection_location_ids(&collection.collection_id)?
        .into_iter()
        .map(|location_id| enriched_location_status(database, &location_id, &stale))
        .collect::<Result<Vec<_>, _>>()?;
    summary.location_count = summary.locations.len() as u64;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("Collection: {}", summary.collection_name);
        match (summary.violated_files, summary.uncertain_files) {
            (Some(violated), Some(uncertain)) => {
                println!(
                    "Files: {} total; {violated} at risk; {uncertain} uncertain",
                    summary.file_count
                );
            }
            _ => println!(
                "Files: {} total; risk unavailable (configure a Policy)",
                summary.file_count
            ),
        }
        println!("Locations:");
        if summary.locations.is_empty() {
            println!("  None with inventory yet.");
        }
        for location in &summary.locations {
            println!("  {}", location.location_name);
            println!(
                "    Device: {}; Site: {}",
                location.device_name.as_deref().unwrap_or("service"),
                location.site_name.as_deref().unwrap_or("unknown")
            );
            println!(
                "    Files: {}; Space used: {}; {}",
                location.logical_file_count,
                format_bytes(location.present_bytes),
                format_stale_presence(location)
            );
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
    let stale = stale_status_index(database)?;
    let summary = enriched_location_status(database, &location.location_id, &stale)?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("Location: {}", summary.location_name);
        println!(
            "Device: {}; Site: {}",
            summary.device_name.as_deref().unwrap_or("service"),
            summary.site_name.as_deref().unwrap_or("unknown")
        );
        println!(
            "Path on Device: {}",
            summary
                .relative_path_display
                .as_deref()
                .unwrap_or("not applicable")
        );
        println!("Files: {}", summary.logical_file_count);
        println!("Space used: {}", format_bytes(summary.present_bytes));
        println!("{}", format_stale_presence(&summary));
    }
    Ok(EXIT_OK)
}

fn stale_status_index(database: &ProjectionDb) -> Result<StaleStatusIndex, AppError> {
    let report = database.stale_presence_report(now_utc_ms()?, None, None)?;
    let mut count_by_location = BTreeMap::new();
    for device in report.devices {
        for location in device.locations {
            count_by_location.insert(location.location_id, location.stale_object_count);
        }
    }
    Ok(StaleStatusIndex {
        count_by_location,
        age_days_by_collection: report
            .thresholds
            .into_iter()
            .map(|threshold| (threshold.collection_id, threshold.max_observation_age_days))
            .collect(),
    })
}

fn enriched_location_status(
    database: &ProjectionDb,
    location_id: &str,
    stale: &StaleStatusIndex,
) -> Result<LocationStatus, AppError> {
    let mut status = database.location_summary(location_id)?;
    let collection_ids = database.location_collection_ids(location_id)?;
    let configured_ages = collection_ids
        .iter()
        .filter_map(|collection_id| stale.age_days_by_collection.get(collection_id).copied())
        .collect::<Vec<_>>();
    if !configured_ages.is_empty() {
        status.stale_presence_count = Some(
            stale
                .count_by_location
                .get(location_id)
                .copied()
                .unwrap_or(0),
        );
        status.stale_presence_minimum_age_days = configured_ages.iter().copied().min();
        status.stale_presence_maximum_age_days = configured_ages.iter().copied().max();
    }
    status.stale_presence_policy_complete =
        !collection_ids.is_empty() && configured_ages.len() == collection_ids.len();
    Ok(status)
}

fn format_stale_presence(status: &LocationStatus) -> String {
    let Some(count) = status.stale_presence_count else {
        return "Stale presence: unavailable (configure a Collection Policy)".to_owned();
    };
    let threshold = match (
        status.stale_presence_minimum_age_days,
        status.stale_presence_maximum_age_days,
    ) {
        (Some(minimum), Some(maximum)) if minimum == maximum => {
            format!("older than {minimum} days")
        }
        (Some(minimum), Some(maximum)) => {
            format!("policy thresholds {minimum}–{maximum} days")
        }
        _ => "policy threshold".to_owned(),
    };
    let partial = if status.stale_presence_policy_complete {
        ""
    } else {
        "; partial because some Collections lack a Policy"
    };
    format!("Stale presence: {count} ({threshold}{partial})")
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
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
        [] if state.collections.len() == 1 => Ok(state.collections[0].clone()),
        [] => Err(AppError::Input(
            "cwd Location has no Collection inventory yet; specify one with --collection"
                .to_owned(),
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
    validate_setup_source(&args.path, args.import_annex, SetupCommand::Collection)?;
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

#[derive(Clone, Copy)]
enum SetupCommand {
    Collection,
    Location,
}

fn validate_setup_source(
    path: &Path,
    import_annex: bool,
    command: SetupCommand,
) -> Result<(), AppError> {
    let entity = match command {
        SetupCommand::Collection => "Collection",
        SetupCommand::Location => "Location",
    };
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        AppError::Input(format!(
            "cannot resolve {entity} path {}: {error}",
            path.display()
        ))
    })?;
    if path_contains_git_metadata(&canonical) {
        return Err(AppError::Input(format!(
            "cannot initialize a {entity} from inside .git metadata; select the content directory instead"
        )));
    }
    if !import_annex && archive_ledger::is_git_annex_repository(&canonical)? {
        return Err(AppError::Input(match command {
            SetupCommand::Collection =>
                "this path is a git-annex repository; rerun collection init with --import-annex so annex keys, unavailable files, and content locations are imported correctly"
                    .to_owned(),
            SetupCommand::Location =>
                "this path is a git-annex repository; use archive location import-annex --collection COLLECTION so annex keys, unavailable files, and content locations are imported correctly"
                    .to_owned(),
        }));
    }
    Ok(())
}

fn path_contains_git_metadata(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == ".git")
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
    let (collection, assigned_policy) = if let Some(collection) = existing_collection {
        let policy = collection
            .policy_id
            .as_deref()
            .and_then(|policy_id| {
                state
                    .policies
                    .iter()
                    .find(|policy| policy.policy_id == policy_id)
            })
            .cloned();
        (collection, policy)
    } else {
        let policy = state
            .policies
            .iter()
            .find(|policy| policy.policy_id == "policy_starter")
            .cloned()
            .unwrap_or_else(|| {
                let policy_id = if state
                    .policies
                    .iter()
                    .any(|policy| policy.policy_id == "policy_starter")
                {
                    generated_id("policy")
                } else {
                    "policy_starter".to_owned()
                };
                starter_policy(policy_id)
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
        (collection, Some(policy))
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
                "Configured Location \"{}\" for Collection \"{}\".",
                location.display_name, collection.display_name,
            );
        } else {
            println!("Created Collection \"{}\".", collection.display_name);
        }
        println!(
            "Location: \"{}\" (Device \"{}\", Site \"{}\").",
            location.display_name, device.display_name, site.display_name
        );
        if root.identity_state != "confirmed" {
            println!(
                "Storage identity is unconfirmed; this Device cannot yet prove an independent copy."
            );
        }
        if let Some(policy) = &assigned_policy {
            print_policy_summary(policy);
            if !adding_to_existing_collection {
                println!(
                    "  To change it before adding files, run archive policy list, then archive policy update POLICY --help."
                );
            }
        }
        if let Some(annex_import) = &annex_import {
            print_annex_import(annex_import, false)?;
        } else {
            println!(
                "Next: archive collection add . --collection {}",
                shell_quote(&collection.display_name)
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn starter_policy(policy_id: String) -> PolicySnapshot {
    PolicySnapshot {
        policy_id,
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
    }
}

fn print_policy_summary(policy: &PolicySnapshot) {
    let requirements = &policy.requirements;
    let offsite = if requirements.require_offsite_copy {
        ", including an offsite copy"
    } else {
        ""
    };
    println!(
        "Policy: {} — {} copies on {} Devices at {} Sites{}.",
        policy.display_name,
        requirements.min_qualifying_copies,
        requirements.min_devices,
        requirements.min_sites,
        offsite
    );
    println!(
        "  Evidence must be no older than {} days for verification, {} days for presence, and {} days for Device check-in.",
        requirements.max_verification_age_days,
        requirements.max_observation_age_days,
        requirements.max_device_checkin_age_days
    );
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

fn select_policy(
    policies: &[PolicySnapshot],
    selector: &str,
) -> Result<Option<PolicySnapshot>, AppError> {
    select_registry_entity(
        policies,
        selector,
        |policy| &policy.policy_id,
        |policy| &policy.display_name,
        "Policy",
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
            print_registry_list(kind, values, cli.json)?;
        }
        RegistryEntityCommand::Show { id } => {
            let state = database.registry_state(true)?;
            let values = registry_values(kind, &state)?;
            let value = if let Some(value) = values
                .iter()
                .find(|value| registry_id(kind, value) == Some(id.as_str()))
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

fn registry_id(kind: RegistryKind, value: &serde_json::Value) -> Option<&str> {
    value[match kind {
        RegistryKind::Site => "site_id",
        RegistryKind::Collection => "collection_id",
        RegistryKind::Device => "device_id",
        RegistryKind::Root => "archive_root_id",
        RegistryKind::Location => "location_id",
        RegistryKind::RiskDomain => "risk_domain_id",
        RegistryKind::Policy => "policy_id",
    }]
    .as_str()
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
                registry_id(kind, &value).unwrap_or("unknown"),
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
                RegistryKind::Policy => {
                    println!(
                        "  version: {}  enabled: {}",
                        value["policy_version"].as_u64().unwrap_or(0),
                        value["enabled"].as_bool().unwrap_or(false)
                    );
                    let requirements = &value["requirements"];
                    println!(
                        "  requires: {} copies on {} Devices at {} Sites; offsite: {}",
                        requirements["min_qualifying_copies"].as_u64().unwrap_or(0),
                        requirements["min_devices"].as_u64().unwrap_or(0),
                        requirements["min_sites"].as_u64().unwrap_or(0),
                        requirements["require_offsite_copy"]
                            .as_bool()
                            .unwrap_or(false)
                    );
                    println!(
                        "  evidence age: verification {} days; presence {} days; Device check-in {} days",
                        requirements["max_verification_age_days"].as_u64().unwrap_or(0),
                        requirements["max_observation_age_days"].as_u64().unwrap_or(0),
                        requirements["max_device_checkin_age_days"].as_u64().unwrap_or(0)
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_registry_list(
    kind: RegistryKind,
    values: Vec<serde_json::Value>,
    as_json: bool,
) -> Result<(), AppError> {
    if as_json {
        return print_registry_values(kind, values, true);
    }
    if values.is_empty() {
        println!(
            "No {}.",
            match kind {
                RegistryKind::Collection => "Collections",
                RegistryKind::Location => "Locations",
                RegistryKind::Device => "Devices",
                RegistryKind::Site => "Sites",
                RegistryKind::Root => "Archive Roots",
                RegistryKind::RiskDomain => "Risk Domains",
                RegistryKind::Policy => "Policies",
            }
        );
        return Ok(());
    }
    for value in values {
        let name = value["display_name"].as_str().unwrap_or("unnamed");
        if value["status"].as_str() == Some("active") {
            println!("{name}");
        } else {
            println!("{name} (retired)");
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

fn execute_v2_file(
    database: &V2ProjectionDb,
    command: &FileCommand,
    as_json: bool,
) -> Result<u8, AppError> {
    match command {
        FileCommand::Find(args) => {
            let collection_id = args
                .collection
                .as_deref()
                .map(|selector| {
                    let state = database.registry_state(false)?;
                    select_collection(&state.collections, selector)?.ok_or_else(|| {
                        AppError::Input(format!("Collection not found: {selector:?}"))
                    })
                })
                .transpose()?
                .map(|collection| collection.collection_id);
            let page = database.find_files(FilePageRequest {
                filter: FileFilter {
                    collection_id,
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
            } else if page.items.is_empty() {
                println!("No Files matched.");
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
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "version": 2,
                        "file_review": review,
                    }))?
                );
            } else {
                println!(
                    "{}  [{}]",
                    review.file.logical_path.display, review.file.collection_name
                );
                println!("  File: {}", review.file.file_ref_id);
                println!("  Identity: {}", review.file.identity_state);
                println!(
                    "  Object: {}",
                    review.file.object_id.as_deref().unwrap_or("unresolved")
                );
                if let (Some(namespace), Some(key)) =
                    (&review.external_namespace, &review.external_key)
                {
                    println!("  External identity: {namespace}:{key}");
                }
                if review.copies.is_empty() {
                    println!("  Copies: none currently observed");
                } else {
                    println!("  Copies:");
                    for copy in &review.copies {
                        println!(
                            "    {} — {} ({})",
                            copy.location_name, copy.state, copy.copy_claim_id
                        );
                        println!(
                            "      Device/Site: {} / {}",
                            copy.device_name.as_deref().unwrap_or("service"),
                            copy.site_name.as_deref().unwrap_or("unknown")
                        );
                        println!(
                            "      Last seen: {}  verified: {} ({})",
                            optional_time(copy.last_seen_time_utc_ms),
                            optional_time(copy.last_verified_time_utc_ms),
                            copy.last_verification_result.as_deref().unwrap_or("never")
                        );
                    }
                    if review.copies_truncated {
                        println!(
                            "  Showing the first {} of {} current Copy claims.",
                            review.copies.len(),
                            review.file.current_copy_count
                        );
                    }
                }
            }
        }
        FileCommand::History { .. } => {
            return Err(AppError::Input(
                "file history is not yet available for version 2 Archives".to_owned(),
            ));
        }
    }
    Ok(EXIT_OK)
}

fn execute_policy_update(
    cli: &Cli,
    database: &ProjectionDb,
    args: &PolicyUpdateArgs,
) -> Result<u8, AppError> {
    let state = database.registry_state(false)?;
    let mut policy = select_policy(&state.policies, &args.policy)?
        .ok_or_else(|| AppError::Input(format!("Policy not found: {:?}", args.policy)))?;
    let original = policy.clone();

    if let Some(name) = args.name.as_deref() {
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::Input("Policy name must not be empty".to_owned()));
        }
        if state.policies.iter().any(|candidate| {
            candidate.policy_id != policy.policy_id && candidate.display_name == name
        }) {
            return Err(AppError::Input(format!(
                "an active Policy named {name:?} already exists"
            )));
        }
        policy.display_name = name.to_owned();
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
    if policy == original {
        return Err(AppError::Input(
            "no policy changes were specified, or the requested settings are already active"
                .to_owned(),
        ));
    }
    PolicyRequirements::from_json(
        &policy.policy_id,
        &serde_json::to_string(&policy.requirements)?,
    )?;
    policy.policy_version = policy
        .policy_version
        .checked_add(1)
        .ok_or_else(|| AppError::Input("Policy version is too large to update".to_owned()))?;

    let events = open_event_store(cli)?;
    let result = Registry::new(&events, database).record(RegistryChange::Policy(
        RegistryAction::Update,
        policy.clone(),
    ))?;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "version": 1,
                "policy": policy,
                "event_seq": result.event_seq,
                "applied_event_seq": result.applied_event_seq,
            }))?
        );
    } else {
        println!("Updated Policy \"{}\".", policy.display_name);
        print_policy_summary(&policy);
        println!("Risk reports will refresh this assessment automatically.");
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
        print_evaluation(database, &evaluation)?;
        println!("Cached policy results updated.");
    }
    Ok(if has_findings { EXIT_FINDINGS } else { EXIT_OK })
}

fn current_policy_status(database: &ProjectionDb) -> Result<CachedPolicyStatus, AppError> {
    let now = now_utc_ms()?;
    let mut status = database.cached_policy_status(now)?;
    if !status.stale_policies.is_empty() {
        database.evaluate_policies(now)?;
        status = database.cached_policy_status(now)?;
    }
    Ok(status)
}

fn execute_policy_report(
    database: &ProjectionDb,
    args: &ReportSummaryArgs,
    as_json: bool,
) -> Result<u8, AppError> {
    let status = filtered_cached_status(
        database,
        current_policy_status(database)?,
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
        print_cached_status(database, &status)?;
        if args.collection.is_some() {
            println!("Policy totals cover every active collection assigned to the shown policy.");
        }
    }
    Ok(if has_findings { EXIT_FINDINGS } else { EXIT_OK })
}

fn execute_stale_presence_report(
    database: &ProjectionDb,
    args: &StalePresenceArgs,
    as_json: bool,
) -> Result<u8, AppError> {
    let collection_id = if let Some(selector) = args.collection.as_deref() {
        let state = database.registry_state(false)?;
        Some(
            select_collection(&state.collections, selector)?
                .ok_or_else(|| AppError::Input(format!("Collection not found: {selector:?}")))?
                .collection_id,
        )
    } else {
        None
    };
    let report = database.stale_presence_report(
        now_utc_ms()?,
        collection_id.as_deref(),
        args.older_than_days,
    )?;
    let has_findings = report.stale_object_count > 0
        || report.unresolved_present_count > 0
        || report.unresolved_missing_count > 0
        || report.unresolved_unknown_count > 0
        || !report.unconfigured_collections.is_empty();
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        match (
            report.threshold_source.as_str(),
            report.minimum_age_days,
            report.maximum_age_days,
        ) {
            ("override", Some(days), _) => {
                println!("Presence is stale after {days} days (--older-than override).");
            }
            (_, Some(minimum), Some(maximum)) if minimum == maximum => {
                println!(
                    "Presence is stale after {minimum} days (Collection policy threshold)."
                );
            }
            (_, Some(minimum), Some(maximum)) => {
                println!(
                    "Presence thresholds come from Collection policies and range from {minimum} to {maximum} days."
                );
            }
            _ => println!(
                "No applicable presence-age threshold is configured; use --older-than or assign Collection policies."
            ),
        }
        if report.threshold_source == "collection_policies" {
            for threshold in &report.thresholds {
                println!(
                    "  {}: {} days ({})",
                    threshold.collection_name,
                    threshold.max_observation_age_days,
                    threshold.policy_name.as_deref().unwrap_or("policy")
                );
            }
        }
        if !report.unconfigured_collections.is_empty() {
            println!(
                "  No active policy: {}",
                report.unconfigured_collections.join(", ")
            );
        }
        if report.devices.is_empty() {
            println!("No stale or unresolved presence records match this report.");
        }
        for device in &report.devices {
            let site = device
                .site_name
                .as_ref()
                .map(|site| format!(" at {site}"))
                .unwrap_or_default();
            println!(
                "{}{}: {} stale Objects; {} unresolved present, {} unresolved missing, {} unresolved unknown ({})",
                device.device_name,
                site,
                device.stale_object_count,
                device.unresolved_present_count,
                device.unresolved_missing_count,
                device.unresolved_unknown_count,
                device.expected_availability
            );
            if args.locations {
                for location in &device.locations {
                    println!(
                        "  {}: {} stale Objects; {} unresolved present, {} unresolved missing, {} unresolved unknown",
                        location.location_name,
                        location.stale_object_count,
                        location.unresolved_present_count,
                        location.unresolved_missing_count,
                        location.unresolved_unknown_count
                    );
                    println!(
                        "    last complete inventory: {}; oldest stale observation: {}",
                        status_optional_time(location.last_complete_inventory_utc_ms),
                        status_optional_time(location.oldest_positive_observation_utc_ms)
                    );
                    println!("    Next: {}", location.suggested_action);
                }
            } else {
                println!("  Next: {}", device.suggested_action);
            }
        }
        if report.unmapped_unresolved_present_count > 0
            || report.unmapped_unresolved_missing_count > 0
            || report.unmapped_unresolved_unknown_count > 0
        {
            println!(
                "Unmapped annex identities: {} present, {} missing, {} unknown; map remotes before choosing a Device.",
                report.unmapped_unresolved_present_count,
                report.unmapped_unresolved_missing_count,
                report.unmapped_unresolved_unknown_count
            );
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
        current_policy_status(database)?,
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
        print_cached_status(database, &status)?;
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

fn policy_display_names(database: &ProjectionDb) -> Result<BTreeMap<String, String>, AppError> {
    Ok(database
        .registry_state(true)?
        .policies
        .into_iter()
        .map(|policy| (policy.policy_id, policy.display_name))
        .collect())
}

fn print_evaluation(
    database: &ProjectionDb,
    evaluation: &PolicyEvaluationResult,
) -> Result<(), AppError> {
    let names = policy_display_names(database)?;
    for collection in &evaluation.unconfigured_collections {
        println!(
            "UNCERTAIN  {} — {}. Next: {}",
            collection.display_name, collection.reason, collection.recommended_action
        );
    }
    for policy in &evaluation.evaluations {
        print_policy_rollup(policy, names.get(&policy.policy_id).map(String::as_str));
    }
    Ok(())
}

fn print_cached_status(
    database: &ProjectionDb,
    status: &CachedPolicyStatus,
) -> Result<(), AppError> {
    let names = policy_display_names(database)?;
    for collection in &status.unconfigured_collections {
        println!(
            "UNCERTAIN  {} — {}. Next: {}",
            collection.display_name, collection.reason, collection.recommended_action
        );
    }
    for policy in &status.stale_policies {
        println!(
            "UNKNOWN  policy {} — {}. Next: archive policy evaluate",
            names
                .get(&policy.policy_id)
                .map(String::as_str)
                .unwrap_or(&policy.policy_id),
            policy.reason
        );
    }
    for policy in &status.evaluations {
        print_policy_rollup(policy, names.get(&policy.policy_id).map(String::as_str));
    }
    if !cached_status_has_findings(status) {
        println!("No current preservation-policy findings.");
    }
    Ok(())
}

fn print_policy_rollup(policy: &archive_ledger::PolicyEvaluation, display_name: Option<&str>) {
    println!(
        "Policy {} v{}: {} safe, {} at risk, {} uncertain ({} files; {} known bytes at risk; {} files of unknown size)",
        display_name.unwrap_or(&policy.policy_id),
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
