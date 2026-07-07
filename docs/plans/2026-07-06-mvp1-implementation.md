# Archive Ledger MVP 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust CLI (`archive`) that initializes a canonical JSONL event stream + SQLite materialized view, registers archive entities, imports existing git-annex repos read-only (verify SHA-512/256, compute BLAKE3), checkpoints segments into git, and produces status/risk/verification reports.

**Architecture:** Append-only hash-chained JSONL event stream is canonical truth (docs/specs/2026-07-06-event-stream.md); SQLite (docs/specs/2026-07-06-schema.md) is a derived projection rebuilt by replay. Every CLI mutation mints events, then applies them to SQLite via the projector. git-annex CAS is read in place and never mutated.

**Tech Stack:** Rust 2021, clap 4 (derive), serde/serde_json 1, rusqlite 0.31 (bundled), blake3 1, sha2 0.10, ulid 1, hex 0.4, chrono 0.4, walkdir 2, fs2 0.4, anyhow 1. Dev: tempfile 3, assert_cmd 2, predicates 3. Git operations shell out to the `git` binary.

## Global Constraints

Copied from the specs; every task implicitly includes these.

- Envelope version is `v: 1`. Stream is `stream_primary`. `seq` starts at 1, increments by exactly 1. Single writer, enforced with an exclusive lock file.
- An event's hash is `"blake3:" + lowercase hex of BLAKE3 over the exact UTF-8 bytes of its line, excluding the trailing newline`. Events never embed their own hash; event N's hash is event N+1's `previous_event_hash`. Genesis (`archive_initialized`, seq 1) has `previous_event_hash: null`. No JSON canonicalization anywhere: the on-disk line bytes are the canonical form and are never rewritten.
- Segment files: `events/stream_primary/seg-<first_seq zero-padded to 12>.jsonl`. Close at 100,000 events (constant `SEGMENT_MAX_EVENTS`) or when a checkpoint forces it. Closed segment = sidecar manifest exists in `manifests/stream_primary/`. Closed files are immutable.
- SQLite `schema_version` is `2`. Tables and DDL are exactly the schema canvas (docs/specs/2026-07-06-schema.md). Derived tables must be rebuilt exactly by replay; `archive_meta`, `jobs`, `job_items`, `policy_status`, `policy_rollup` are local-operational.
- Object identity: `object_id = "blake3:" + hex`. git-annex SHA-512/SHA-256 hashes are alternate hashes (`object_hashes`, source `git-annex-key`).
- Never write inside any git-annex repo (`.git/annex/objects` is read-only).
- IDs are prefixed ULIDs: `evt_`, `job_`, `fref_`, `anneximp_`, `chk_`, `sqlsnap_`. User-supplied entity IDs (devices, sites, locations, collections, risk domains, archive roots) are taken as-is from the CLI.
- `logical_path` = `<collection_id>/<path relative to worktree>`. `path_observations.observed_path` and `copy_observed` paths are relative to their location's URI.
- Binary name: `archive`. Global flag `--archive <dir>` (default `.`) locates the archive; `--actor` defaults to `$USER`.
- Timestamps are integer UTC milliseconds. `event_time_text` in SQLite is derived from `time_utc_ms` at apply time (RFC 3339, milliseconds, `Z`).

## File Structure

```
Cargo.toml
src/
  main.rs           CLI definition (clap) and command dispatch only
  ids.rs            prefixed-ULID generation, now_ms()
  hash.rs           line-hash rule, streaming file hasher (SHA-512 + BLAKE3 one pass)
  event.rs          Event envelope struct, EventDraft builder, line (de)serialization
  store.rs          EventStore: lock, open segment, append batches, tail recovery
  segment.rs        segment naming, manifest read/write, close, full chain verification
  db.rs             SQLite open, embedded DDL, archive_meta get/set
  projector.rs      apply one event to SQLite (exhaustive over the catalog)
  apply.rs          apply-new-events, full rebuild, table dump for determinism tests
  gitutil.rs        shell-out helpers: git init/add/commit
  registry.rs       registry command implementations (mint event + apply)
  annex/
    mod.rs
    key.rs          git-annex key parser (SHA512E/SHA256E/SHA512/SHA256)
    walk.rs         worktree walker: find annexed symlinks, resolve into CAS
    import.rs       import pipeline: hash, verify, mint events
  checkpoint.rs     checkpoint: force-close, checkpoint file, git commit
  report.rs         status / risk / verification report queries
tests/
  cli_init.rs, cli_registry.rs, cli_import.rs, cli_checkpoint.rs, cli_report.rs
  common/mod.rs     test helpers (init temp archive, build fake annex fixture)
```

Archive directory layout (created by `archive init`):

```
<archive>/
  .git/                       (git init run here)
  .gitignore                  (catalog.sqlite, *.sqlite-*, .archive.lock, snapshots/)
  events/stream_primary/      (open segment untracked; closed segments committed)
  manifests/stream_primary/
  checkpoints/
  catalog.sqlite              (ignored, local)
  .archive.lock               (ignored, exclusive writer lock)
```

---

### Task 1: Cargo scaffold and ids module

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/ids.rs`
- Test: unit tests inline in `src/ids.rs`

**Interfaces:**
- Produces: `ids::new_id(prefix: &str) -> String` (e.g. `new_id("evt")` → `"evt_01hz…"`, 26-char lowercase ULID after the underscore, monotonically sortable); `ids::now_ms() -> i64` (UTC ms since epoch).

- [ ] **Step 1: Scaffold the crate**

```bash
cd /home/ubuntu/archive-ledger && cargo init --name archive-ledger
```

Replace `Cargo.toml` with:

```toml
[package]
name = "archive-ledger"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "archive"
path = "src/main.rs"

[dependencies]
anyhow = "1"
blake3 = "1"
chrono = "0.4"
clap = { version = "4", features = ["derive"] }
fs2 = "0.4"
hex = "0.4"
rusqlite = { version = "0.31", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
ulid = "1"
walkdir = "2"

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

Replace `src/main.rs` with a stub (the real CLI arrives in Task 10):

```rust
mod ids;

fn main() {
    println!("archive-ledger");
}
```

Append to the repo `.gitignore` (create if missing): `target/`

- [ ] **Step 2: Write the failing test**

Create `src/ids.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_has_prefix_and_ulid_shape() {
        let id = new_id("evt");
        assert!(id.starts_with("evt_"));
        assert_eq!(id.len(), 4 + 26);
        assert_eq!(id, id.to_lowercase());
    }

    #[test]
    fn ids_are_unique_and_sortable() {
        let a = new_id("evt");
        let b = new_id("evt");
        assert_ne!(a, b);
        assert!(a < b, "ULIDs must sort by creation order: {a} vs {b}");
    }

    #[test]
    fn now_ms_is_plausible() {
        assert!(now_ms() > 1_700_000_000_000);
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test ids`
Expected: compile error, `new_id` not found.

- [ ] **Step 4: Write minimal implementation**

Prepend to `src/ids.rs`:

```rust
use std::sync::Mutex;
use ulid::Generator;

static GEN: Mutex<Option<Generator>> = Mutex::new(None);

/// Prefixed, lowercase, monotonic ULID: "evt_01hz...".
pub fn new_id(prefix: &str) -> String {
    let mut guard = GEN.lock().unwrap();
    let generator = guard.get_or_insert_with(Generator::new);
    let ulid = generator.generate().expect("ulid generation");
    format!("{prefix}_{}", ulid.to_string().to_lowercase())
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test ids`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock .gitignore src/main.rs src/ids.rs
git commit -m "feat: cargo scaffold and prefixed-ULID id generation"
```

---

### Task 2: hash module — line hash rule and streaming file hasher

**Files:**
- Create: `src/hash.rs`
- Modify: `src/main.rs` (add `mod hash;`)
- Test: unit tests inline in `src/hash.rs`

**Interfaces:**
- Produces: `hash::line_hash(line: &str) -> String` — BLAKE3 of the exact UTF-8 bytes excluding any trailing `\n`, returned as `"blake3:<hex>"`; `hash::FileHashes { blake3_hex: String, sha512_hex: String, sha256_hex: String, size_bytes: u64 }`; `hash::hash_file(path: &Path) -> anyhow::Result<FileHashes>` — one streaming read computing all three digests.

- [ ] **Step 1: Write the failing test**

Create `src/hash.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Well-known digests of the empty input.
    const BLAKE3_EMPTY: &str =
        "af1349b9f5f9a1a6a0404dee36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const SHA512_EMPTY: &str =
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    #[test]
    fn line_hash_of_empty_line_is_blake3_of_empty() {
        assert_eq!(line_hash(""), format!("blake3:{BLAKE3_EMPTY}"));
    }

    #[test]
    fn line_hash_ignores_single_trailing_newline_only() {
        assert_eq!(line_hash("{\"a\":1}\n"), line_hash("{\"a\":1}"));
        assert_ne!(line_hash("{\"a\":1}\n\n"), line_hash("{\"a\":1}"));
        assert_ne!(line_hash("{\"a\":1}"), line_hash("{\"a\":2}"));
    }

    #[test]
    fn hash_file_computes_all_digests_and_size() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"").unwrap();
        let h = hash_file(f.path()).unwrap();
        assert_eq!(h.blake3_hex, BLAKE3_EMPTY);
        assert_eq!(h.sha512_hex, SHA512_EMPTY);
        assert_eq!(h.size_bytes, 0);

        let mut f2 = tempfile::NamedTempFile::new().unwrap();
        f2.write_all(b"hello archive").unwrap();
        let h2 = hash_file(f2.path()).unwrap();
        assert_eq!(h2.size_bytes, 13);
        assert_eq!(h2.blake3_hex.len(), 64);
        assert_eq!(h2.sha512_hex.len(), 128);
        assert_eq!(h2.sha256_hex.len(), 64);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test hash`
Expected: compile error, `line_hash` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/hash.rs`:

```rust
use anyhow::Result;
use sha2::Digest;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Event-stream hash rule: BLAKE3 of the exact line bytes, excluding the
/// trailing newline. Spec: docs/specs/2026-07-06-event-stream.md.
pub fn line_hash(line: &str) -> String {
    let bytes = line.strip_suffix('\n').unwrap_or(line).as_bytes();
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

pub struct FileHashes {
    pub blake3_hex: String,
    pub sha512_hex: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
}

/// Single streaming pass computing BLAKE3 + SHA-512 + SHA-256.
pub fn hash_file(path: &Path) -> Result<FileHashes> {
    let mut file = File::open(path)?;
    let mut b3 = blake3::Hasher::new();
    let mut s512 = sha2::Sha512::new();
    let mut s256 = sha2::Sha256::new();
    let mut size: u64 = 0;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        b3.update(&buf[..n]);
        s512.update(&buf[..n]);
        s256.update(&buf[..n]);
        size += n as u64;
    }
    Ok(FileHashes {
        blake3_hex: b3.finalize().to_hex().to_string(),
        sha512_hex: hex::encode(s512.finalize()),
        sha256_hex: hex::encode(s256.finalize()),
        size_bytes: size,
    })
}
```

Add `mod hash;` to `src/main.rs` under `mod ids;`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test hash`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/hash.rs src/main.rs
git commit -m "feat: line-hash rule and streaming multi-digest file hasher"
```

---

### Task 3: Event envelope model and line serialization

**Files:**
- Create: `src/event.rs`
- Modify: `src/main.rs` (add `mod event;`)
- Test: unit tests inline in `src/event.rs`

**Interfaces:**
- Consumes: `ids::new_id`, `ids::now_ms`.
- Produces:
  - `event::Event` — the full envelope, all fields `pub`: `v: u32, stream_id: String, seq: u64, event_id: String, event_type: String, time_utc_ms: i64, actor_id: Option<String>, host_id: Option<String>, job_id: Option<String>, object_id: Option<String>, location_id: Option<String>, device_id: Option<String>, site_id: Option<String>, previous_event_hash: Option<String>, payload: serde_json::Value`.
  - `event::EventDraft` — everything the caller decides; struct with `pub event_type: String, pub actor_id: Option<String>, pub host_id: Option<String>, pub job_id: Option<String>, pub object_id: Option<String>, pub location_id: Option<String>, pub device_id: Option<String>, pub site_id: Option<String>, pub payload: serde_json::Value` and `EventDraft::new(event_type: &str, payload: serde_json::Value) -> EventDraft`.
  - `Event::to_line(&self) -> String` (single line, no trailing newline), `Event::from_line(line: &str) -> anyhow::Result<Event>`, `event::time_text(ms: i64) -> String` (RFC 3339 with milliseconds, `Z`).

**Design notes for the implementer:** serde_json serializes struct fields in declaration order, so `to_line` output is deterministic for a given Event value. That determinism only matters at append time — once written, the on-disk bytes are canonical and are re-parsed, never re-serialized, for hashing (Global Constraints). `payload` stays a `serde_json::Value`; the projector (Task 7/8) matches on `event_type` and reads payload fields by name.

- [ ] **Step 1: Write the failing test**

Create `src/event.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Event {
        Event {
            v: 1,
            stream_id: "stream_primary".into(),
            seq: 42,
            event_id: "evt_01hzzzzzzzzzzzzzzzzzzzzzzzzz".into(),
            event_type: "object_verified".into(),
            time_utc_ms: 1781042405123,
            actor_id: Some("alice".into()),
            host_id: None,
            job_id: None,
            object_id: Some("blake3:2c7f".into()),
            location_id: Some("loc_x".into()),
            device_id: None,
            site_id: None,
            previous_event_hash: Some("blake3:a91e".into()),
            payload: json!({"result": "ok", "bytes_read": 1}),
        }
    }

    #[test]
    fn to_line_is_single_line_and_round_trips() {
        let e = sample();
        let line = e.to_line();
        assert!(!line.contains('\n'));
        assert!(line.starts_with("{\"v\":1,\"stream_id\":\"stream_primary\",\"seq\":42,"));
        let back = Event::from_line(&line).unwrap();
        assert_eq!(back.event_id, e.event_id);
        assert_eq!(back.payload, e.payload);
        assert_eq!(back.previous_event_hash, e.previous_event_hash);
    }

    #[test]
    fn serialization_is_deterministic() {
        assert_eq!(sample().to_line(), sample().to_line());
    }

    #[test]
    fn draft_new_fills_defaults() {
        let d = EventDraft::new("site_registered", json!({"site": {"site_id": "site_home"}}));
        assert_eq!(d.event_type, "site_registered");
        assert!(d.object_id.is_none());
    }

    #[test]
    fn time_text_is_rfc3339_millis_z() {
        assert_eq!(time_text(1781042405123), "2026-06-09T18:00:05.123Z");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test event`
Expected: compile error, `Event` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/event.rs`:

```rust
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Canonical envelope, v=1. Field order here IS the serialized field order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub v: u32,
    pub stream_id: String,
    pub seq: u64,
    pub event_id: String,
    pub event_type: String,
    pub time_utc_ms: i64,
    pub actor_id: Option<String>,
    pub host_id: Option<String>,
    pub job_id: Option<String>,
    pub object_id: Option<String>,
    pub location_id: Option<String>,
    pub device_id: Option<String>,
    pub site_id: Option<String>,
    pub previous_event_hash: Option<String>,
    pub payload: serde_json::Value,
}

impl Event {
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("event serialization cannot fail")
    }

    pub fn from_line(line: &str) -> Result<Event> {
        Ok(serde_json::from_str(line.trim_end_matches('\n'))?)
    }
}

#[derive(Debug, Clone)]
pub struct EventDraft {
    pub event_type: String,
    pub actor_id: Option<String>,
    pub host_id: Option<String>,
    pub job_id: Option<String>,
    pub object_id: Option<String>,
    pub location_id: Option<String>,
    pub device_id: Option<String>,
    pub site_id: Option<String>,
    pub payload: serde_json::Value,
}

impl EventDraft {
    pub fn new(event_type: &str, payload: serde_json::Value) -> EventDraft {
        EventDraft {
            event_type: event_type.to_string(),
            actor_id: None,
            host_id: None,
            job_id: None,
            object_id: None,
            location_id: None,
            device_id: None,
            site_id: None,
            payload,
        }
    }
}

/// RFC 3339 with milliseconds and Z, derived from time_utc_ms at apply time.
pub fn time_text(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .expect("valid ms timestamp")
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}
```

Add `mod event;` to `src/main.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test event`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/event.rs src/main.rs
git commit -m "feat: event envelope model with deterministic line serialization"
```

---

### Task 4: EventStore — locked append with hash chaining and tail recovery

**Files:**
- Create: `src/store.rs`
- Modify: `src/main.rs` (add `mod store;`)
- Test: unit tests inline in `src/store.rs`

**Interfaces:**
- Consumes: `event::{Event, EventDraft}`, `hash::line_hash`, `ids::{new_id, now_ms}`.
- Produces:
  - `store::EventStore` with:
    - `EventStore::open(archive_dir: &Path) -> anyhow::Result<EventStore>` — takes the exclusive lock (`<archive>/.archive.lock` via fs2 `try_lock_exclusive`; a second opener errors with "archive is locked by another process"), creates `events/stream_primary/` if missing, recovers the tail (next seq + previous hash) by reading the last line of the open segment.
    - `append_batch(&mut self, drafts: Vec<EventDraft>) -> anyhow::Result<Vec<Event>>` — assigns seq/event_id/time/prev-hash, writes lines + `\n`, fsyncs once per batch, rolls to a new segment when the open one reaches `SEGMENT_MAX_EVENTS` (Task 5 provides `close_open_segment`; until then rolling logic lives here but manifest writing is a callback — see design note).
    - `append(&mut self, draft: EventDraft) -> anyhow::Result<Event>` — convenience for a 1-element batch.
    - `next_seq(&self) -> u64`, `tail_hash(&self) -> Option<String>`.
  - `store::read_all_events(archive_dir: &Path) -> anyhow::Result<Vec<Event>>` — every event in seq order across all segment files (sorted by filename), no lock needed.
  - `store::STREAM_ID: &str = "stream_primary"`, `store::SEGMENT_MAX_EVENTS: u64 = 100_000`, `store::segment_file_name(first_seq: u64) -> String` (`"seg-000000000001.jsonl"`).

**Design note:** in this task, when a segment fills, `append_batch` simply starts writing the next segment file; it does NOT write manifests (Task 5 adds `segment::close_open_segment` and the store calls it from Task 5's step 4 wiring). The open segment is the highest-numbered `seg-*.jsonl`; on `open()`, if no segment exists, the first append creates `seg-<next_seq padded>.jsonl`.

- [ ] **Step 1: Write the failing test**

Create `src/store.rs` with tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventDraft;
    use crate::hash::line_hash;
    use serde_json::json;

    fn draft(t: &str) -> EventDraft {
        EventDraft::new(t, json!({}))
    }

    #[test]
    fn appends_chain_and_assign_seq() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EventStore::open(dir.path()).unwrap();
        assert_eq!(s.next_seq(), 1);
        assert_eq!(s.tail_hash(), None);

        let evs = s
            .append_batch(vec![draft("archive_initialized"), draft("site_registered")])
            .unwrap();
        assert_eq!(evs[0].seq, 1);
        assert_eq!(evs[0].previous_event_hash, None);
        assert_eq!(evs[1].seq, 2);
        assert_eq!(
            evs[1].previous_event_hash,
            Some(line_hash(&evs[0].to_line()))
        );

        let all = read_all_events(dir.path()).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].event_type, "site_registered");
    }

    #[test]
    fn reopen_recovers_tail() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut s = EventStore::open(dir.path()).unwrap();
            s.append(draft("archive_initialized")).unwrap();
        }
        let mut s2 = EventStore::open(dir.path()).unwrap();
        assert_eq!(s2.next_seq(), 2);
        assert!(s2.tail_hash().is_some());
        let e2 = s2.append(draft("site_registered")).unwrap();
        let all = read_all_events(dir.path()).unwrap();
        assert_eq!(
            e2.previous_event_hash,
            Some(line_hash(&all[0].to_line()))
        );
    }

    #[test]
    fn second_open_is_rejected_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let _s = EventStore::open(dir.path()).unwrap();
        let err = EventStore::open(dir.path()).unwrap_err();
        assert!(err.to_string().contains("locked"));
    }

    #[test]
    fn segment_file_names_are_padded() {
        assert_eq!(segment_file_name(1), "seg-000000000001.jsonl");
        assert_eq!(segment_file_name(100_001), "seg-000000100001.jsonl");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test store`
Expected: compile error, `EventStore` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/store.rs`:

```rust
use crate::event::{Event, EventDraft};
use crate::hash::line_hash;
use crate::ids::{new_id, now_ms};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub const STREAM_ID: &str = "stream_primary";
pub const SEGMENT_MAX_EVENTS: u64 = 100_000;

pub fn segment_file_name(first_seq: u64) -> String {
    format!("seg-{first_seq:012}.jsonl")
}

pub fn stream_dir(archive_dir: &Path) -> PathBuf {
    archive_dir.join("events").join(STREAM_ID)
}

fn segment_paths_sorted(archive_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = stream_dir(archive_dir);
    let mut paths: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("seg-") && n.ends_with(".jsonl"))
                    .unwrap_or(false)
            })
            .collect(),
        Err(_) => vec![],
    };
    paths.sort();
    Ok(paths)
}

pub fn read_all_events(archive_dir: &Path) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    for path in segment_paths_sorted(archive_dir)? {
        let reader = BufReader::new(File::open(&path)?);
        for line in reader.lines() {
            events.push(Event::from_line(&line?)?);
        }
    }
    Ok(events)
}

pub struct EventStore {
    archive_dir: PathBuf,
    _lock: File,
    next_seq: u64,
    tail_hash: Option<String>,
    open_segment: Option<PathBuf>,
    open_segment_events: u64,
}

impl EventStore {
    pub fn open(archive_dir: &Path) -> Result<EventStore> {
        fs::create_dir_all(stream_dir(archive_dir))?;
        let lock = OpenOptions::new()
            .create(true)
            .write(true)
            .open(archive_dir.join(".archive.lock"))?;
        lock.try_lock_exclusive()
            .map_err(|_| anyhow::anyhow!("archive is locked by another process"))?;

        let mut next_seq = 1u64;
        let mut tail_hash = None;
        let mut open_segment = None;
        let mut open_segment_events = 0u64;

        if let Some(last_path) = segment_paths_sorted(archive_dir)?.last() {
            let reader = BufReader::new(File::open(last_path)?);
            let mut last_line = None;
            let mut count = 0u64;
            for line in reader.lines() {
                last_line = Some(line?);
                count += 1;
            }
            if let Some(line) = last_line {
                let ev = Event::from_line(&line)
                    .context("corrupt tail line in open segment")?;
                next_seq = ev.seq + 1;
                tail_hash = Some(line_hash(&line));
            }
            open_segment = Some(last_path.clone());
            open_segment_events = count;
        }

        Ok(EventStore {
            archive_dir: archive_dir.to_path_buf(),
            _lock: lock,
            next_seq,
            tail_hash,
            open_segment,
            open_segment_events,
        })
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn tail_hash(&self) -> Option<String> {
        self.tail_hash.clone()
    }

    pub fn archive_dir(&self) -> &Path {
        &self.archive_dir
    }

    /// Path of the segment currently being appended, if any.
    pub fn open_segment_path(&self) -> Option<PathBuf> {
        self.open_segment.clone()
    }

    /// Called after a segment is closed externally (Task 5) so the next
    /// append starts a fresh segment.
    pub fn reset_open_segment(&mut self) {
        self.open_segment = None;
        self.open_segment_events = 0;
    }

    pub fn append(&mut self, draft: EventDraft) -> Result<Event> {
        Ok(self.append_batch(vec![draft])?.pop().unwrap())
    }

    pub fn append_batch(&mut self, drafts: Vec<EventDraft>) -> Result<Vec<Event>> {
        if drafts.is_empty() {
            return Ok(vec![]);
        }
        let mut written = Vec::with_capacity(drafts.len());
        // Group writes per segment file; fsync once per file touched.
        let mut file: Option<(PathBuf, File)> = None;
        for draft in drafts {
            if self.open_segment.is_none()
                || self.open_segment_events >= SEGMENT_MAX_EVENTS
            {
                if self.open_segment_events >= SEGMENT_MAX_EVENTS {
                    // Task 5 wires manifest-on-roll via checkpointing; here we
                    // just start the next file.
                    self.reset_open_segment();
                }
                let path = stream_dir(&self.archive_dir)
                    .join(segment_file_name(self.next_seq));
                self.open_segment = Some(path);
            }
            let path = self.open_segment.clone().unwrap();
            let needs_new_handle = match &file {
                Some((p, _)) => *p != path,
                None => true,
            };
            if needs_new_handle {
                if let Some((_, f)) = file.take() {
                    f.sync_all()?;
                }
                let f = OpenOptions::new().create(true).append(true).open(&path)?;
                file = Some((path.clone(), f));
            }

            let event = Event {
                v: 1,
                stream_id: STREAM_ID.to_string(),
                seq: self.next_seq,
                event_id: new_id("evt"),
                event_type: draft.event_type,
                time_utc_ms: now_ms(),
                actor_id: draft.actor_id,
                host_id: draft.host_id,
                job_id: draft.job_id,
                object_id: draft.object_id,
                location_id: draft.location_id,
                device_id: draft.device_id,
                site_id: draft.site_id,
                previous_event_hash: self.tail_hash.clone(),
                payload: draft.payload,
            };
            let line = event.to_line();
            if line.contains('\n') {
                bail!("event serialized to multiple lines");
            }
            let (_, f) = file.as_mut().unwrap();
            f.write_all(line.as_bytes())?;
            f.write_all(b"\n")?;

            self.tail_hash = Some(line_hash(&line));
            self.next_seq += 1;
            self.open_segment_events += 1;
            written.push(event);
        }
        if let Some((_, f)) = file {
            f.sync_all()?;
        }
        Ok(written)
    }
}
```

Add `mod store;` to `src/main.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test store`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/store.rs src/main.rs
git commit -m "feat: locked event store with hash chaining and tail recovery"
```

---

### Task 5: Segment manifests, close, and full chain verification

**Files:**
- Create: `src/segment.rs`
- Modify: `src/main.rs` (add `mod segment;`)
- Test: unit tests inline in `src/segment.rs`

**Interfaces:**
- Consumes: `store::{EventStore, STREAM_ID, stream_dir, read_all_events, segment_file_name}`, `event::Event`, `hash::line_hash`.
- Produces:
  - `segment::Manifest` (serde struct): `manifest_v: u32, stream_id: String, segment_file: String, first_seq: u64, last_seq: u64, first_event_id: String, last_event_id: String, last_event_hash: String, event_count: u64, segment_size_bytes: u64, segment_blake3: String` (paths repo-relative, e.g. `events/stream_primary/seg-….jsonl`).
  - `segment::manifests_dir(archive_dir: &Path) -> PathBuf` (`manifests/stream_primary/`).
  - `segment::close_open_segment(store: &mut EventStore) -> anyhow::Result<Option<Manifest>>` — writes `manifests/stream_primary/seg-<…>.manifest.json` for the store's open segment (None if no open segment / zero events), calls `store.reset_open_segment()`. A closed segment is one with a manifest.
  - `segment::verify_chain(archive_dir: &Path) -> anyhow::Result<ChainReport>` where `ChainReport { events: u64, segments: u64, closed_segments: u64 }` — implements the spec's three-step verification: manifest blake3 vs file bytes; per-line rehash vs successor's `previous_event_hash` including across segment boundaries and manifest `last_event_hash`; seq continuity from 1 with no gaps. Any failure is an `Err` naming segment file and seq.

- [ ] **Step 1: Write the failing test**

Create `src/segment.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventDraft;
    use crate::store::EventStore;
    use serde_json::json;
    use std::fs;

    fn seed(dir: &std::path::Path, n: usize) {
        let mut s = EventStore::open(dir).unwrap();
        let drafts = (0..n)
            .map(|i| {
                EventDraft::new(
                    if i == 0 { "archive_initialized" } else { "site_registered" },
                    json!({ "i": i }),
                )
            })
            .collect();
        s.append_batch(drafts).unwrap();
    }

    #[test]
    fn close_writes_manifest_and_verify_passes() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path(), 5);
        let mut s = EventStore::open(dir.path()).unwrap();
        let m = close_open_segment(&mut s).unwrap().unwrap();
        assert_eq!(m.first_seq, 1);
        assert_eq!(m.last_seq, 5);
        assert_eq!(m.event_count, 5);
        assert!(manifests_dir(dir.path())
            .join("seg-000000000001.manifest.json")
            .exists());

        // Next append starts a new segment.
        s.append(EventDraft::new("site_registered", json!({}))).unwrap();
        drop(s);
        assert!(crate::store::stream_dir(dir.path())
            .join("seg-000000000006.jsonl")
            .exists());

        let report = verify_chain(dir.path()).unwrap();
        assert_eq!(report.events, 6);
        assert_eq!(report.segments, 2);
        assert_eq!(report.closed_segments, 1);
    }

    #[test]
    fn verify_detects_tampered_byte() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path(), 3);
        let seg = crate::store::stream_dir(dir.path()).join("seg-000000000001.jsonl");
        let mut bytes = fs::read(&seg).unwrap();
        let idx = bytes.len() / 2;
        bytes[idx] = if bytes[idx] == b'a' { b'b' } else { b'a' };
        fs::write(&seg, bytes).unwrap();
        assert!(verify_chain(dir.path()).is_err());
    }

    #[test]
    fn verify_detects_seq_gap() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path(), 3);
        let seg = crate::store::stream_dir(dir.path()).join("seg-000000000001.jsonl");
        let content = fs::read_to_string(&seg).unwrap();
        let kept: Vec<&str> = content.lines().filter(|l| !l.contains("\"seq\":2")).collect();
        fs::write(&seg, kept.join("\n") + "\n").unwrap();
        let err = verify_chain(dir.path()).unwrap_err();
        assert!(err.to_string().contains("seq"), "got: {err}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test segment`
Expected: compile error, `close_open_segment` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/segment.rs`:

```rust
use crate::event::Event;
use crate::hash::line_hash;
use crate::store::{stream_dir, EventStore, STREAM_ID};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_v: u32,
    pub stream_id: String,
    pub segment_file: String,
    pub first_seq: u64,
    pub last_seq: u64,
    pub first_event_id: String,
    pub last_event_id: String,
    pub last_event_hash: String,
    pub event_count: u64,
    pub segment_size_bytes: u64,
    pub segment_blake3: String,
}

pub fn manifests_dir(archive_dir: &Path) -> PathBuf {
    archive_dir.join("manifests").join(STREAM_ID)
}

fn manifest_path_for(archive_dir: &Path, segment_path: &Path) -> PathBuf {
    let stem = segment_path.file_stem().unwrap().to_str().unwrap();
    manifests_dir(archive_dir).join(format!("{stem}.manifest.json"))
}

/// Close the store's open segment by writing its sidecar manifest.
pub fn close_open_segment(store: &mut EventStore) -> Result<Option<Manifest>> {
    let Some(seg_path) = store.open_segment_path() else {
        return Ok(None);
    };
    let archive_dir = store.archive_dir().to_path_buf();
    let bytes = fs::read(&seg_path)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    let segment_blake3 = format!("blake3:{}", blake3::hash(&bytes).to_hex());

    let mut first: Option<Event> = None;
    let mut last_line = String::new();
    let mut count = 0u64;
    for line in BufReader::new(&bytes[..]).lines() {
        let line = line?;
        if first.is_none() {
            first = Some(Event::from_line(&line)?);
        }
        last_line = line;
        count += 1;
    }
    let first = first.unwrap();
    let last = Event::from_line(&last_line)?;

    let manifest = Manifest {
        manifest_v: 1,
        stream_id: STREAM_ID.to_string(),
        segment_file: format!(
            "events/{STREAM_ID}/{}",
            seg_path.file_name().unwrap().to_str().unwrap()
        ),
        first_seq: first.seq,
        last_seq: last.seq,
        first_event_id: first.event_id,
        last_event_id: last.event_id,
        last_event_hash: line_hash(&last_line),
        event_count: count,
        segment_size_bytes: bytes.len() as u64,
        segment_blake3,
    };

    fs::create_dir_all(manifests_dir(&archive_dir))?;
    let mpath = manifest_path_for(&archive_dir, &seg_path);
    fs::write(&mpath, serde_json::to_string_pretty(&manifest)? + "\n")?;
    File::open(&mpath)?.sync_all()?;
    store.reset_open_segment();
    Ok(Some(manifest))
}

pub struct ChainReport {
    pub events: u64,
    pub segments: u64,
    pub closed_segments: u64,
}

/// Spec verification procedure (event-stream spec, "Serialization and Hashing").
pub fn verify_chain(archive_dir: &Path) -> Result<ChainReport> {
    let dir = stream_dir(archive_dir);
    let mut seg_paths: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|e| e == "jsonl").unwrap_or(false))
            .collect(),
        Err(_) => vec![],
    };
    seg_paths.sort();

    let mut expected_seq = 1u64;
    let mut prev_hash: Option<String> = None;
    let mut events = 0u64;
    let mut closed = 0u64;

    for seg_path in &seg_paths {
        let name = seg_path.file_name().unwrap().to_str().unwrap().to_string();
        let bytes = fs::read(seg_path)?;

        let mpath = manifest_path_for(archive_dir, seg_path);
        let manifest: Option<Manifest> = if mpath.exists() {
            closed += 1;
            let m: Manifest = serde_json::from_str(&fs::read_to_string(&mpath)?)
                .with_context(|| format!("bad manifest for {name}"))?;
            let actual = format!("blake3:{}", blake3::hash(&bytes).to_hex());
            if actual != m.segment_blake3 {
                bail!("segment {name}: file bytes do not match manifest segment_blake3");
            }
            Some(m)
        } else {
            None
        };

        let mut last_hash_in_seg = None;
        for line in BufReader::new(&bytes[..]).lines() {
            let line = line?;
            let ev = Event::from_line(&line)
                .with_context(|| format!("segment {name}: unparseable line"))?;
            if ev.seq != expected_seq {
                bail!(
                    "segment {name}: seq discontinuity, expected {expected_seq} got {}",
                    ev.seq
                );
            }
            if ev.previous_event_hash != prev_hash {
                bail!("segment {name}: broken hash chain at seq {}", ev.seq);
            }
            prev_hash = Some(line_hash(&line));
            last_hash_in_seg = prev_hash.clone();
            expected_seq += 1;
            events += 1;
        }

        if let (Some(m), Some(h)) = (&manifest, &last_hash_in_seg) {
            if &m.last_event_hash != h {
                bail!("segment {name}: manifest last_event_hash mismatch");
            }
            if m.last_seq != expected_seq - 1 {
                bail!("segment {name}: manifest last_seq mismatch");
            }
        }
    }

    Ok(ChainReport {
        events,
        segments: seg_paths.len() as u64,
        closed_segments: closed,
    })
}
```

Add `mod segment;` to `src/main.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test segment`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/segment.rs src/main.rs
git commit -m "feat: segment manifests, close, and full chain verification"
```

---

### Task 6: SQLite open, embedded schema DDL, archive_meta

**Files:**
- Create: `src/db.rs`
- Modify: `src/main.rs` (add `mod db;`)
- Test: unit tests inline in `src/db.rs`

**Interfaces:**
- Consumes: nothing internal.
- Produces:
  - `db::open(archive_dir: &Path) -> anyhow::Result<rusqlite::Connection>` — opens `<archive>/catalog.sqlite`, sets `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`, creates all tables if absent, sets `schema_version` to `2` in `archive_meta`.
  - `db::meta_get(conn: &Connection, key: &str) -> anyhow::Result<Option<String>>`
  - `db::meta_set(conn: &Connection, key: &str, value: &str) -> anyhow::Result<()>`
  - `db::applied_seq(conn: &Connection) -> anyhow::Result<u64>` (0 when unset).

- [ ] **Step 1: Write the failing test**

Create `src/db.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_all_tables_and_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(dir.path()).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (
                 'archive_meta','events','objects','object_hashes','collections',
                 'file_refs','path_observations','devices','device_mounts',
                 'device_site_history','archive_roots','sites','risk_domains',
                 'entity_risk_domains','locations','object_locations',
                 'verification_results','quarantine_items','policies','policy_status',
                 'policy_rollup','jobs','job_items','git_annex_imports',
                 'git_annex_keys','checkpoints','sqlite_snapshots','external_indexes')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 28);
        assert_eq!(meta_get(&conn, "schema_version").unwrap().unwrap(), "2");
        assert_eq!(applied_seq(&conn).unwrap(), 0);
    }

    #[test]
    fn meta_set_get_roundtrip_and_reopen_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = open(dir.path()).unwrap();
            meta_set(&conn, "applied_event_seq", "42").unwrap();
        }
        let conn = open(dir.path()).unwrap();
        assert_eq!(applied_seq(&conn).unwrap(), 42);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test db`
Expected: compile error, `open` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/db.rs`. `SCHEMA_SQL` is the DDL from docs/specs/2026-07-06-schema.md verbatim, wrapped in `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS` / `CREATE UNIQUE INDEX IF NOT EXISTS` form. Copy every table and index from the canvas (all 28 tables listed in the test above; the canvas is the source of truth — transcribe it exactly, changing only `CREATE TABLE` → `CREATE TABLE IF NOT EXISTS` and likewise for indexes):

```rust
use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

const SCHEMA_SQL: &str = r#"
-- Transcribed verbatim from docs/specs/2026-07-06-schema.md with
-- IF NOT EXISTS added. See that canvas for tier and semantics notes.
CREATE TABLE IF NOT EXISTS archive_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  stream_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  event_time_utc_ms INTEGER NOT NULL,
  event_time_text TEXT NOT NULL,
  actor_id TEXT,
  host_id TEXT,
  job_id TEXT,
  object_id TEXT,
  location_id TEXT,
  device_id TEXT,
  site_id TEXT,
  payload_json TEXT,
  previous_event_hash TEXT,
  event_hash TEXT NOT NULL,
  PRIMARY KEY (stream_id, seq)
);
-- ... every remaining table and index from the schema canvas, verbatim ...
"#;

pub fn open(archive_dir: &Path) -> Result<Connection> {
    let conn = Connection::open(archive_dir.join("catalog.sqlite"))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(SCHEMA_SQL)?;
    if meta_get(&conn, "schema_version")?.is_none() {
        meta_set(&conn, "schema_version", "2")?;
    }
    Ok(conn)
}

pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare("SELECT value FROM archive_meta WHERE key = ?1")?;
    let mut rows = stmt.query([key])?;
    Ok(match rows.next()? {
        Some(row) => Some(row.get(0)?),
        None => None,
    })
}

pub fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO archive_meta(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

pub fn applied_seq(conn: &Connection) -> Result<u64> {
    Ok(meta_get(conn, "applied_event_seq")?
        .map(|v| v.parse().unwrap_or(0))
        .unwrap_or(0))
}
```

The `-- ...` comment above is a transcription instruction for THIS step only, not a placeholder to ship: before running the test, paste in the remaining 26 tables and all indexes from docs/specs/2026-07-06-schema.md (objects, object_hashes, collections, file_refs + its partial unique index `idx_file_refs_active_path`, path_observations, devices, device_mounts, device_site_history, archive_roots, sites, risk_domains, entity_risk_domains, locations, object_locations, verification_results, quarantine_items, policies, policy_status, policy_rollup, jobs, job_items, git_annex_imports, git_annex_keys, checkpoints, sqlite_snapshots, external_indexes). The test's 28-table count fails if any are missing.

Add `mod db;` to `src/main.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test db`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/db.rs src/main.rs
git commit -m "feat: sqlite open with embedded schema v2 and archive_meta"
```

---

### Task 7: Projector part 1 — events mirror and registry events

**Files:**
- Create: `src/projector.rs`
- Modify: `src/main.rs` (add `mod projector;`)
- Test: unit tests inline in `src/projector.rs`

**Interfaces:**
- Consumes: `event::{Event, time_text}`, `hash::line_hash`, `db`.
- Produces: `projector::apply_event(conn: &Connection, event: &Event) -> anyhow::Result<()>` — inserts the events-mirror row (computing `event_hash` from the line and `event_time_text` from ms) then dispatches on `event_type`. Unknown event types are an error (`bail!`), keeping the projector exhaustive. This task implements: `archive_initialized`, `collection_registered`/`collection_updated`, `site_registered`/`site_updated`, `risk_domain_registered`/`risk_domain_updated`, `risk_assigned`/`risk_unassigned`, `device_registered`/`device_updated`, `device_moved`, `device_checked_in`, `device_mount_observed`, `archive_root_registered`/`archive_root_updated`, `location_registered`/`location_updated`, `policy_registered`/`policy_updated`, `external_index_registered`. Task 8 adds the content-fact arms; until then those arms `bail!("not yet implemented: {type}")`.

**Payload contracts** (from the event-stream spec): registry payloads carry a full entity snapshot under a key named for the entity, e.g. `{"site": {"site_id": …, "display_name": …, "site_kind": …, "description": …}}`. `device_moved` carries `{"device": {...}, "from_site_id": …, "to_site_id": …}`. `risk_assigned` carries `{"entity_type", "entity_id", "risk_domain_id"}`. `policy_registered` carries `selector`/`requirements` as JSON objects — store them serialized with `serde_json::to_string`.

**Projector conventions (apply to Task 8 as well):**
- All writes are UPSERTs keyed by the entity's primary key (`INSERT ... ON CONFLICT(pk) DO UPDATE SET ...`) so replay is idempotent per event and `X_updated` shares the `X_registered` arm.
- `first_seen_event_id`/`created_event_id` columns: set on insert, never overwritten on conflict (`COALESCE` pattern shown below). `last_*` columns always take the newest event.
- Helper `fn s(payload: &Value, key: &str) -> Option<String>` and `fn i(payload: &Value, key: &str) -> Option<i64>` extract optional string/int fields; `fn req(payload: &Value, key: &str) -> Result<String>` for required ones.

- [ ] **Step 1: Write the failing test**

Create `src/projector.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::event::{Event, EventDraft};
    use crate::store::EventStore;
    use serde_json::json;

    /// Append drafts to a temp store and apply them; returns (conn, events).
    fn run(drafts: Vec<EventDraft>) -> (rusqlite::Connection, Vec<Event>) {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EventStore::open(dir.path()).unwrap();
        let mut all = vec![EventDraft::new(
            "archive_initialized",
            json!({"archive_id": "arch_test", "display_name": "Test"}),
        )];
        all.extend(drafts);
        let events = s.append_batch(all).unwrap();
        let conn = db::open(dir.path()).unwrap();
        for e in &events {
            apply_event(&conn, e).unwrap();
        }
        (conn, events)
    }

    fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn events_mirror_row_written_with_hash_and_time_text() {
        let (conn, events) = run(vec![]);
        let (hash, text): (String, String) = conn
            .query_row(
                "SELECT event_hash, event_time_text FROM events WHERE seq = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(hash, crate::hash::line_hash(&events[0].to_line()));
        assert!(text.ends_with('Z'));
        assert_eq!(
            crate::db::meta_get(&conn, "archive_id").unwrap().unwrap(),
            "arch_test"
        );
    }

    #[test]
    fn site_and_device_registration_and_move() {
        let (conn, _) = run(vec![
            EventDraft::new("site_registered", json!({"site":
                {"site_id": "site_home", "display_name": "Home",
                 "site_kind": "home", "description": null}})),
            EventDraft::new("site_registered", json!({"site":
                {"site_id": "site_bank", "display_name": "Bank",
                 "site_kind": "safe_deposit_box", "description": null}})),
            EventDraft::new("device_registered", json!({"device":
                {"device_id": "dev_usb_a", "display_name": "USB A",
                 "device_kind": "usb_hdd", "serial_hint": null,
                 "hardware_fingerprint": null, "owner": "alice",
                 "status": "active", "current_site_id": "site_home"}})),
            EventDraft::new("device_moved", json!({"device":
                {"device_id": "dev_usb_a", "display_name": "USB A",
                 "device_kind": "usb_hdd", "serial_hint": null,
                 "hardware_fingerprint": null, "owner": "alice",
                 "status": "active", "current_site_id": "site_bank"},
                "from_site_id": "site_home", "to_site_id": "site_bank"})),
        ]);
        assert_eq!(count(&conn, "SELECT count(*) FROM sites"), 2);
        let site: String = conn
            .query_row(
                "SELECT current_site_id FROM devices WHERE device_id='dev_usb_a'",
                [], |r| r.get(0),
            )
            .unwrap();
        assert_eq!(site, "site_bank");
        // History: home row closed, bank row open.
        assert_eq!(count(&conn,
            "SELECT count(*) FROM device_site_history WHERE device_id='dev_usb_a'"), 2);
        assert_eq!(count(&conn,
            "SELECT count(*) FROM device_site_history
             WHERE device_id='dev_usb_a' AND site_id='site_home'
             AND departed_time_utc_ms IS NOT NULL"), 1);
        assert_eq!(count(&conn,
            "SELECT count(*) FROM device_site_history
             WHERE device_id='dev_usb_a' AND site_id='site_bank'
             AND departed_time_utc_ms IS NULL"), 1);
    }

    #[test]
    fn risk_assignment_and_unassignment() {
        let (conn, _) = run(vec![
            EventDraft::new("risk_domain_registered", json!({"risk_domain":
                {"risk_domain_id": "risk_fire", "display_name": "Home fire",
                 "risk_kind": "fire", "description": null}})),
            EventDraft::new("risk_assigned", json!({
                "entity_type": "site", "entity_id": "site_home",
                "risk_domain_id": "risk_fire"})),
            EventDraft::new("risk_assigned", json!({
                "entity_type": "device", "entity_id": "dev_nas",
                "risk_domain_id": "risk_fire"})),
            EventDraft::new("risk_unassigned", json!({
                "entity_type": "device", "entity_id": "dev_nas",
                "risk_domain_id": "risk_fire"})),
        ]);
        assert_eq!(count(&conn, "SELECT count(*) FROM entity_risk_domains"), 1);
    }

    #[test]
    fn registration_is_idempotent_and_updates_win() {
        let (conn, _) = run(vec![
            EventDraft::new("collection_registered", json!({"collection":
                {"collection_id": "photos", "display_name": "Photos",
                 "description": null}})),
            EventDraft::new("collection_updated", json!({"collection":
                {"collection_id": "photos", "display_name": "Photos v2",
                 "description": "All photos"}})),
        ]);
        assert_eq!(count(&conn, "SELECT count(*) FROM collections"), 1);
        let name: String = conn
            .query_row("SELECT display_name FROM collections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "Photos v2");
    }

    #[test]
    fn unknown_event_type_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EventStore::open(dir.path()).unwrap();
        let evs = s
            .append_batch(vec![EventDraft::new("mystery_event", json!({}))])
            .unwrap();
        let conn = db::open(dir.path()).unwrap();
        assert!(apply_event(&conn, &evs[0]).is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test projector`
Expected: compile error, `apply_event` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/projector.rs`:

```rust
use crate::db::meta_set;
use crate::event::{time_text, Event};
use crate::hash::line_hash;
use anyhow::{bail, Result};
use rusqlite::{params, Connection};
use serde_json::Value;

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(String::from)
}

fn i(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| x.as_i64())
}

fn req(v: &Value, key: &str) -> Result<String> {
    s(v, key).ok_or_else(|| anyhow::anyhow!("payload missing required field {key}"))
}

fn obj<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    v.get(key)
        .ok_or_else(|| anyhow::anyhow!("payload missing object {key}"))
}

pub fn apply_event(conn: &Connection, event: &Event) -> Result<()> {
    // 1. Events mirror row.
    let line = event.to_line();
    conn.execute(
        "INSERT INTO events (stream_id, seq, event_id, event_type,
           event_time_utc_ms, event_time_text, actor_id, host_id, job_id,
           object_id, location_id, device_id, site_id, payload_json,
           previous_event_hash, event_hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        params![
            event.stream_id, event.seq, event.event_id, event.event_type,
            event.time_utc_ms, time_text(event.time_utc_ms), event.actor_id,
            event.host_id, event.job_id, event.object_id, event.location_id,
            event.device_id, event.site_id,
            serde_json::to_string(&event.payload)?,
            event.previous_event_hash, line_hash(&line),
        ],
    )?;

    // 2. Type-specific projection.
    let p = &event.payload;
    match event.event_type.as_str() {
        "archive_initialized" => {
            meta_set(conn, "archive_id", &req(p, "archive_id")?)?;
        }
        "collection_registered" | "collection_updated" => {
            let c = obj(p, "collection")?;
            conn.execute(
                "INSERT INTO collections (collection_id, display_name, description)
                 VALUES (?1,?2,?3)
                 ON CONFLICT(collection_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   description = excluded.description",
                params![req(c, "collection_id")?, req(c, "display_name")?,
                        s(c, "description")],
            )?;
        }
        "site_registered" | "site_updated" => {
            let x = obj(p, "site")?;
            conn.execute(
                "INSERT INTO sites (site_id, display_name, site_kind, description)
                 VALUES (?1,?2,?3,?4)
                 ON CONFLICT(site_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   site_kind = excluded.site_kind,
                   description = excluded.description",
                params![req(x, "site_id")?, req(x, "display_name")?,
                        req(x, "site_kind")?, s(x, "description")],
            )?;
        }
        "risk_domain_registered" | "risk_domain_updated" => {
            let x = obj(p, "risk_domain")?;
            conn.execute(
                "INSERT INTO risk_domains (risk_domain_id, display_name, risk_kind,
                   description) VALUES (?1,?2,?3,?4)
                 ON CONFLICT(risk_domain_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   risk_kind = excluded.risk_kind,
                   description = excluded.description",
                params![req(x, "risk_domain_id")?, req(x, "display_name")?,
                        req(x, "risk_kind")?, s(x, "description")],
            )?;
        }
        "risk_assigned" => {
            conn.execute(
                "INSERT OR IGNORE INTO entity_risk_domains
                   (entity_type, entity_id, risk_domain_id) VALUES (?1,?2,?3)",
                params![req(p, "entity_type")?, req(p, "entity_id")?,
                        req(p, "risk_domain_id")?],
            )?;
        }
        "risk_unassigned" => {
            conn.execute(
                "DELETE FROM entity_risk_domains
                 WHERE entity_type=?1 AND entity_id=?2 AND risk_domain_id=?3",
                params![req(p, "entity_type")?, req(p, "entity_id")?,
                        req(p, "risk_domain_id")?],
            )?;
        }
        "device_registered" | "device_updated" | "device_moved" => {
            let d = obj(p, "device")?;
            conn.execute(
                "INSERT INTO devices (device_id, display_name, device_kind,
                   serial_hint, hardware_fingerprint, owner, status,
                   current_site_id, last_checkin_event_id, last_checkin_time_utc_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL,NULL)
                 ON CONFLICT(device_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   device_kind = excluded.device_kind,
                   serial_hint = excluded.serial_hint,
                   hardware_fingerprint = excluded.hardware_fingerprint,
                   owner = excluded.owner,
                   status = excluded.status,
                   current_site_id = excluded.current_site_id",
                params![req(d, "device_id")?, req(d, "display_name")?,
                        req(d, "device_kind")?, s(d, "serial_hint"),
                        s(d, "hardware_fingerprint"), s(d, "owner"),
                        req(d, "status")?, s(d, "current_site_id")],
            )?;
            let device_id = req(d, "device_id")?;
            if event.event_type == "device_moved" {
                conn.execute(
                    "UPDATE device_site_history SET departed_time_utc_ms = ?1
                     WHERE device_id = ?2 AND departed_time_utc_ms IS NULL",
                    params![event.time_utc_ms, device_id],
                )?;
                conn.execute(
                    "INSERT OR REPLACE INTO device_site_history
                       (device_id, site_id, arrived_time_utc_ms,
                        departed_time_utc_ms, moved_event_id)
                     VALUES (?1,?2,?3,NULL,?4)",
                    params![device_id, req(p, "to_site_id")?,
                            event.time_utc_ms, event.event_id],
                )?;
            } else if let Some(site) = s(d, "current_site_id") {
                // First registration with a site opens history.
                conn.execute(
                    "INSERT OR IGNORE INTO device_site_history
                       (device_id, site_id, arrived_time_utc_ms,
                        departed_time_utc_ms, moved_event_id)
                     VALUES (?1,?2,?3,NULL,?4)",
                    params![device_id, site, event.time_utc_ms, event.event_id],
                )?;
            }
        }
        "device_checked_in" => {
            conn.execute(
                "UPDATE devices SET last_checkin_event_id = ?1,
                   last_checkin_time_utc_ms = ?2 WHERE device_id = ?3",
                params![event.event_id, event.time_utc_ms,
                        event.device_id.as_deref().unwrap_or_default()],
            )?;
        }
        "device_mount_observed" => {
            let m = obj(p, "mount")?;
            conn.execute(
                "INSERT INTO device_mounts (mount_id, device_id, host_id,
                   mount_root_uri, observed_time_utc_ms, observed_event_id, status)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(mount_id) DO UPDATE SET
                   mount_root_uri = excluded.mount_root_uri,
                   observed_time_utc_ms = excluded.observed_time_utc_ms,
                   observed_event_id = excluded.observed_event_id,
                   status = excluded.status",
                params![req(m, "mount_id")?, req(m, "device_id")?,
                        req(m, "host_id")?, req(m, "mount_root_uri")?,
                        event.time_utc_ms, event.event_id, req(m, "status")?],
            )?;
        }
        "archive_root_registered" | "archive_root_updated" => {
            let r = obj(p, "archive_root")?;
            conn.execute(
                "INSERT INTO archive_roots (archive_root_id, device_id, display_name,
                   root_path_on_device, last_resolved_root_uri, status,
                   created_event_id, last_seen_event_id, last_seen_time_utc_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?7,?8)
                 ON CONFLICT(archive_root_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   root_path_on_device = excluded.root_path_on_device,
                   last_resolved_root_uri = excluded.last_resolved_root_uri,
                   status = excluded.status,
                   last_seen_event_id = excluded.last_seen_event_id,
                   last_seen_time_utc_ms = excluded.last_seen_time_utc_ms",
                params![req(r, "archive_root_id")?, req(r, "device_id")?,
                        req(r, "display_name")?, req(r, "root_path_on_device")?,
                        s(r, "last_resolved_root_uri"), req(r, "status")?,
                        event.event_id, event.time_utc_ms],
            )?;
        }
        "location_registered" | "location_updated" => {
            let l = obj(p, "location")?;
            conn.execute(
                "INSERT INTO locations (location_id, display_name, kind,
                   last_resolved_uri, archive_root_id, relative_path, device_id,
                   site_id, encryption_state, trust_level, is_writable, is_online,
                   created_event_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                 ON CONFLICT(location_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   kind = excluded.kind,
                   last_resolved_uri = excluded.last_resolved_uri,
                   archive_root_id = excluded.archive_root_id,
                   relative_path = excluded.relative_path,
                   device_id = excluded.device_id,
                   site_id = excluded.site_id,
                   encryption_state = excluded.encryption_state,
                   trust_level = excluded.trust_level,
                   is_writable = excluded.is_writable,
                   is_online = excluded.is_online",
                params![req(l, "location_id")?, req(l, "display_name")?,
                        req(l, "kind")?, s(l, "last_resolved_uri"),
                        s(l, "archive_root_id"), s(l, "relative_path"),
                        s(l, "device_id"), s(l, "site_id"),
                        s(l, "encryption_state"), s(l, "trust_level"),
                        i(l, "is_writable").unwrap_or(0),
                        i(l, "is_online").unwrap_or(0), event.event_id],
            )?;
        }
        "policy_registered" | "policy_updated" => {
            let x = obj(p, "policy")?;
            conn.execute(
                "INSERT INTO policies (policy_id, display_name, selector_json,
                   requirements_json, enabled, last_updated_event_id)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(policy_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   selector_json = excluded.selector_json,
                   requirements_json = excluded.requirements_json,
                   enabled = excluded.enabled,
                   last_updated_event_id = excluded.last_updated_event_id",
                params![req(x, "policy_id")?, req(x, "display_name")?,
                        serde_json::to_string(obj(x, "selector")?)?,
                        serde_json::to_string(obj(x, "requirements")?)?,
                        i(x, "enabled").unwrap_or(1), event.event_id],
            )?;
        }
        "external_index_registered" => {
            let x = obj(p, "external_index")?;
            conn.execute(
                "INSERT INTO external_indexes (external_index_id, display_name,
                   index_kind, database_uri, owner_app, created_event_id,
                   last_seen_event_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?6)
                 ON CONFLICT(external_index_id) DO UPDATE SET
                   display_name = excluded.display_name,
                   index_kind = excluded.index_kind,
                   database_uri = excluded.database_uri,
                   owner_app = excluded.owner_app,
                   last_seen_event_id = excluded.last_seen_event_id",
                params![req(x, "external_index_id")?, req(x, "display_name")?,
                        req(x, "index_kind")?, s(x, "database_uri"),
                        s(x, "owner_app"), event.event_id],
            )?;
        }
        other => bail!("projector: unknown event type {other}"),
    }
    Ok(())
}
```

Add `mod projector;` to `src/main.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test projector`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/projector.rs src/main.rs
git commit -m "feat: projector for events mirror and registry events"
```

---

### Task 8: Projector part 2 — content facts, coverage, jobs, annex, lifecycle

**Files:**
- Modify: `src/projector.rs` (replace the `other => bail!` arm's neighbors: add arms above it)
- Test: additional unit tests in `src/projector.rs`

**Interfaces:**
- Consumes/Produces: same `apply_event` signature; adds arms for `object_observed`, `object_hash_added`, `file_ref_added`, `file_ref_updated`, `file_ref_removed`, `path_observed`, `path_missing`, `copy_observed`, `copy_missing`, `object_verified`, `location_scanned`, `job_started`, `job_finished`, `annex_import_started`, `annex_key_mapped`, `annex_import_completed`, `checkpoint_created`, `snapshot_created`.

**Payload contracts** (event-stream spec): see spec section "Event Catalog". Key projections:
- `object_observed` `{object:{object_id,size_bytes,media_type,extension_hint}}` → upsert `objects` (first_seen from this event) + `object_hashes` row `(object_id,'blake3',<hex after prefix>,'computed',event_id)`.
- `object_hash_added` `{hash_algo,hash_hex,source}` (envelope `object_id`) → upsert `object_hashes`.
- `file_ref_added`/`file_ref_updated` `{file_ref:{file_ref_id,collection_id,object_id,logical_path,original_name,created_time_utc_ms,modified_time_utc_ms,observed_size_bytes}}` → upsert `file_refs` with `path_state='active'`; `file_ref_removed` `{file_ref_id,...}` → set `path_state='removed'`, `removed_event_id`.
- `path_observed` `{file_ref_id,observed_path,observed_size_bytes,modified_time_utc_ms}` (envelope `object_id`,`location_id`) → upsert `path_observations` state `present`; `path_missing` → state `removed`, `removed_event_id`.
- `copy_observed` `{path}` (envelope `object_id`,`location_id`) → upsert `object_locations` state `present` (first_seen kept, last_seen updated, `last_observed_path`).
- `copy_missing` `{last_known_path}` → `object_locations.state='missing'`.
- `object_verified` `{result,expected_hash_algo,expected_hash_hex,observed_hash_hex,size_bytes,bytes_read,duration_ms,path_observed,error_message}` → insert `verification_results` (verification_id = `"ver_" + event_id[4..]`); on `ok` update `object_locations` `last_verified_*` + state `present`; on `hash_mismatch` state `corrupt` + `last_error`; on `read_error` `last_error` only.
- `location_scanned`, `job_started`, `job_finished`: events-mirror row only (jobs are local-operational; the CLI writes `jobs` directly, not the projector — replay must not resurrect them).
- `annex_import_started` `{import:{import_id,repo_path,collection_id,worktree_location_id,cas_location_id,annex_objects_path,git_head_commit,annex_uuid}}` → upsert `git_annex_imports` (started event id); `annex_import_completed` `{import_id,keys_mapped,objects_new,objects_existing,errors}` → set completed event id + `imported_time_utc_ms`, `notes` = summary JSON.
- `annex_key_mapped` `{annex_key,backend,annex_size_bytes,annex_extension,parsed_hash_algo,parsed_hash_hex,content_path,import_id}` (envelope `object_id`) → upsert `git_annex_keys` (`verified_event_id` = this event).
- `checkpoint_created` `{checkpoint_id,event_first_seq,event_last_seq,event_last_hash,manifest_path,git_commit}` → insert `checkpoints`; `snapshot_created` per its payload → insert `sqlite_snapshots`.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/projector.rs`:

```rust
    fn object_payload(id: &str, size: i64) -> serde_json::Value {
        json!({"object": {"object_id": id, "size_bytes": size,
               "media_type": "image/jpeg", "extension_hint": "jpg"}})
    }

    #[test]
    fn content_fact_lifecycle() {
        let oid = "blake3:aa11";
        let mut d1 = EventDraft::new("object_observed", object_payload(oid, 100));
        d1.object_id = Some(oid.into());
        let mut d2 = EventDraft::new("copy_observed", json!({"path": "x/y.jpg"}));
        d2.object_id = Some(oid.into());
        d2.location_id = Some("loc_cas".into());
        let mut d3 = EventDraft::new(
            "object_verified",
            json!({"result": "ok", "expected_hash_algo": "sha512",
                   "expected_hash_hex": "beef", "observed_hash_hex": "beef",
                   "size_bytes": 100, "bytes_read": 100, "duration_ms": 5,
                   "path_observed": "x/y.jpg", "error_message": null}),
        );
        d3.object_id = Some(oid.into());
        d3.location_id = Some("loc_cas".into());
        let mut d4 = EventDraft::new(
            "object_verified",
            json!({"result": "hash_mismatch", "expected_hash_algo": "blake3",
                   "expected_hash_hex": "aa11", "observed_hash_hex": "dead",
                   "size_bytes": 100, "bytes_read": 100, "duration_ms": 5,
                   "path_observed": "x/y.jpg", "error_message": null}),
        );
        d4.object_id = Some(oid.into());
        d4.location_id = Some("loc_cas".into());

        let (conn, _) = run(vec![d1, d2, d3, d4]);
        assert_eq!(count(&conn, "SELECT count(*) FROM objects"), 1);
        assert_eq!(count(&conn,
            "SELECT count(*) FROM object_hashes WHERE hash_algo='blake3'"), 1);
        assert_eq!(count(&conn, "SELECT count(*) FROM verification_results"), 2);
        let (state, verified): (String, Option<i64>) = conn
            .query_row(
                "SELECT state, last_verified_time_utc_ms FROM object_locations
                 WHERE object_id=?1 AND location_id='loc_cas'",
                [oid], |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "corrupt");
        assert!(verified.is_some(), "ok verification recorded before corruption");
    }

    #[test]
    fn file_ref_and_path_observation_lifecycle() {
        let oid = "blake3:bb22";
        let mut d1 = EventDraft::new("object_observed", object_payload(oid, 1));
        d1.object_id = Some(oid.into());
        let d2 = EventDraft::new("file_ref_added", json!({"file_ref":
            {"file_ref_id": "fref_1", "collection_id": "photos",
             "object_id": oid, "logical_path": "photos/a.jpg",
             "original_name": "a.jpg", "created_time_utc_ms": null,
             "modified_time_utc_ms": 5, "observed_size_bytes": 1}}));
        let mut d3 = EventDraft::new("path_observed", json!({
            "file_ref_id": "fref_1", "observed_path": "a.jpg",
            "observed_size_bytes": 1, "modified_time_utc_ms": 5}));
        d3.object_id = Some(oid.into());
        d3.location_id = Some("loc_wt".into());
        let mut d4 = EventDraft::new("path_missing", json!({
            "file_ref_id": "fref_1", "observed_path": "a.jpg"}));
        d4.location_id = Some("loc_wt".into());
        let d5 = EventDraft::new("file_ref_removed", json!({
            "file_ref_id": "fref_1", "collection_id": "photos",
            "logical_path": "photos/a.jpg"}));

        let (conn, _) = run(vec![d1, d2, d3, d4, d5]);
        let (fr_state, removed): (String, Option<String>) = conn
            .query_row(
                "SELECT path_state, removed_event_id FROM file_refs
                 WHERE file_ref_id='fref_1'",
                [], |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(fr_state, "removed");
        assert!(removed.is_some());
        let po_state: String = conn
            .query_row(
                "SELECT state FROM path_observations
                 WHERE file_ref_id='fref_1' AND location_id='loc_wt'",
                [], |r| r.get(0),
            )
            .unwrap();
        assert_eq!(po_state, "removed");
    }

    #[test]
    fn annex_import_events_project() {
        let oid = "blake3:cc33";
        let d1 = EventDraft::new("annex_import_started", json!({"import":
            {"import_id": "anneximp_1", "repo_path": "/r",
             "collection_id": "photos", "worktree_location_id": "loc_wt",
             "cas_location_id": "loc_cas", "annex_objects_path": "/r/.git/annex/objects",
             "git_head_commit": null, "annex_uuid": null}}));
        let mut d2 = EventDraft::new("annex_key_mapped", json!({
            "annex_key": "SHA512E-s1--ff.jpg", "backend": "SHA512E",
            "annex_size_bytes": 1, "annex_extension": "jpg",
            "parsed_hash_algo": "sha512", "parsed_hash_hex": "ff",
            "content_path": "ab/cd/SHA512E-s1--ff.jpg/SHA512E-s1--ff.jpg",
            "import_id": "anneximp_1"}));
        d2.object_id = Some(oid.into());
        let d3 = EventDraft::new("annex_import_completed", json!({
            "import_id": "anneximp_1", "keys_mapped": 1, "objects_new": 1,
            "objects_existing": 0, "errors": []}));
        let mut dob = EventDraft::new("object_observed", object_payload(oid, 1));
        dob.object_id = Some(oid.into());

        let (conn, _) = run(vec![d1, dob, d2, d3]);
        assert_eq!(count(&conn, "SELECT count(*) FROM git_annex_keys"), 1);
        let completed: Option<String> = conn
            .query_row(
                "SELECT import_completed_event_id FROM git_annex_imports
                 WHERE import_id='anneximp_1'",
                [], |r| r.get(0),
            )
            .unwrap();
        assert!(completed.is_some());
    }

    #[test]
    fn job_and_scan_events_are_mirror_only() {
        let d1 = EventDraft::new("job_started",
            json!({"job_id": "job_1", "job_type": "scan", "params": {}}));
        let d2 = EventDraft::new("location_scanned", json!({
            "scan_started_time_utc_ms": 1, "scan_finished_time_utc_ms": 2,
            "files_seen": 0, "bytes_seen": 0, "new_paths": 0,
            "changed_paths": 0, "missing_paths": 0, "unchanged_paths": 0}));
        let d3 = EventDraft::new("job_finished",
            json!({"job_id": "job_1", "status": "complete", "summary": {}}));
        let (conn, _) = run(vec![d1, d2, d3]);
        assert_eq!(count(&conn, "SELECT count(*) FROM jobs"), 0);
        assert_eq!(count(&conn,
            "SELECT count(*) FROM events WHERE event_type='location_scanned'"), 1);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test projector`
Expected: the 4 new tests FAIL with "projector: unknown event type object_observed" (etc.); the 5 Task 7 tests still pass.

- [ ] **Step 3: Implement the new arms**

In `src/projector.rs`, insert above the `other => bail!` arm:

```rust
        "object_observed" => {
            let o = obj(p, "object")?;
            let object_id = req(o, "object_id")?;
            conn.execute(
                "INSERT INTO objects (object_id, canonical_hash_algo,
                   canonical_hash_hex, size_bytes, first_seen_event_id,
                   first_seen_time_utc_ms, media_type, extension_hint)
                 VALUES (?1,'blake3',?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(object_id) DO UPDATE SET
                   media_type = COALESCE(excluded.media_type, objects.media_type),
                   extension_hint = COALESCE(excluded.extension_hint,
                                             objects.extension_hint)",
                params![object_id,
                        object_id.strip_prefix("blake3:").unwrap_or(&object_id),
                        i(o, "size_bytes").unwrap_or(0), event.event_id,
                        event.time_utc_ms, s(o, "media_type"),
                        s(o, "extension_hint")],
            )?;
            conn.execute(
                "INSERT OR IGNORE INTO object_hashes
                   (object_id, hash_algo, hash_hex, source, verified_event_id)
                 VALUES (?1,'blake3',?2,'computed',?3)",
                params![object_id,
                        object_id.strip_prefix("blake3:").unwrap_or(&object_id),
                        event.event_id],
            )?;
        }
        "object_hash_added" => {
            conn.execute(
                "INSERT OR IGNORE INTO object_hashes
                   (object_id, hash_algo, hash_hex, source, verified_event_id)
                 VALUES (?1,?2,?3,?4,?5)",
                params![event.object_id, req(p, "hash_algo")?, req(p, "hash_hex")?,
                        s(p, "source"), event.event_id],
            )?;
        }
        "file_ref_added" | "file_ref_updated" => {
            let f = obj(p, "file_ref")?;
            conn.execute(
                "INSERT INTO file_refs (file_ref_id, collection_id, object_id,
                   logical_path, original_name, path_state, first_seen_event_id,
                   last_seen_event_id, removed_event_id, created_time_utc_ms,
                   modified_time_utc_ms, observed_size_bytes)
                 VALUES (?1,?2,?3,?4,?5,'active',?6,?6,NULL,?7,?8,?9)
                 ON CONFLICT(file_ref_id) DO UPDATE SET
                   object_id = excluded.object_id,
                   original_name = excluded.original_name,
                   path_state = 'active',
                   last_seen_event_id = excluded.last_seen_event_id,
                   removed_event_id = NULL,
                   modified_time_utc_ms = excluded.modified_time_utc_ms,
                   observed_size_bytes = excluded.observed_size_bytes",
                params![req(f, "file_ref_id")?, req(f, "collection_id")?,
                        req(f, "object_id")?, req(f, "logical_path")?,
                        s(f, "original_name"), event.event_id,
                        i(f, "created_time_utc_ms"),
                        i(f, "modified_time_utc_ms"),
                        i(f, "observed_size_bytes")],
            )?;
        }
        "file_ref_removed" => {
            conn.execute(
                "UPDATE file_refs SET path_state='removed', removed_event_id=?1,
                   last_seen_event_id=?1 WHERE file_ref_id=?2",
                params![event.event_id, req(p, "file_ref_id")?],
            )?;
        }
        "path_observed" => {
            conn.execute(
                "INSERT INTO path_observations (file_ref_id, location_id,
                   object_id, observed_path, state, first_seen_event_id,
                   last_seen_event_id, removed_event_id, last_seen_time_utc_ms,
                   observed_size_bytes, modified_time_utc_ms)
                 VALUES (?1,?2,?3,?4,'present',?5,?5,NULL,?6,?7,?8)
                 ON CONFLICT(file_ref_id, location_id) DO UPDATE SET
                   object_id = excluded.object_id,
                   observed_path = excluded.observed_path,
                   state = 'present',
                   last_seen_event_id = excluded.last_seen_event_id,
                   removed_event_id = NULL,
                   last_seen_time_utc_ms = excluded.last_seen_time_utc_ms,
                   observed_size_bytes = excluded.observed_size_bytes,
                   modified_time_utc_ms = excluded.modified_time_utc_ms",
                params![req(p, "file_ref_id")?, event.location_id,
                        event.object_id, req(p, "observed_path")?,
                        event.event_id, event.time_utc_ms,
                        i(p, "observed_size_bytes"), i(p, "modified_time_utc_ms")],
            )?;
        }
        "path_missing" => {
            conn.execute(
                "UPDATE path_observations SET state='removed', removed_event_id=?1
                 WHERE file_ref_id=?2 AND location_id=?3",
                params![event.event_id, req(p, "file_ref_id")?, event.location_id],
            )?;
        }
        "copy_observed" => {
            conn.execute(
                "INSERT INTO object_locations (object_id, location_id, state,
                   first_seen_event_id, last_seen_event_id, last_verified_event_id,
                   last_verified_time_utc_ms, last_observed_path, last_error,
                   quarantine_ref)
                 VALUES (?1,?2,'present',?3,?3,NULL,NULL,?4,NULL,NULL)
                 ON CONFLICT(object_id, location_id) DO UPDATE SET
                   state = 'present',
                   last_seen_event_id = excluded.last_seen_event_id,
                   last_observed_path = excluded.last_observed_path,
                   last_error = NULL",
                params![event.object_id, event.location_id, event.event_id,
                        s(p, "path")],
            )?;
        }
        "copy_missing" => {
            conn.execute(
                "INSERT INTO object_locations (object_id, location_id, state,
                   first_seen_event_id, last_seen_event_id, last_observed_path)
                 VALUES (?1,?2,'missing',?3,?3,?4)
                 ON CONFLICT(object_id, location_id) DO UPDATE SET
                   state = 'missing',
                   last_seen_event_id = excluded.last_seen_event_id",
                params![event.object_id, event.location_id, event.event_id,
                        s(p, "last_known_path")],
            )?;
        }
        "object_verified" => {
            let result = req(p, "result")?;
            conn.execute(
                "INSERT INTO verification_results (verification_id, event_id,
                   object_id, location_id, result, expected_hash_algo,
                   expected_hash_hex, observed_hash_hex, size_bytes, bytes_read,
                   duration_ms, verified_time_utc_ms, path_observed, error_message)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
                params![format!("ver_{}", &event.event_id[4..]), event.event_id,
                        event.object_id, event.location_id, result,
                        req(p, "expected_hash_algo")?, req(p, "expected_hash_hex")?,
                        s(p, "observed_hash_hex"), i(p, "size_bytes"),
                        i(p, "bytes_read"), i(p, "duration_ms"),
                        event.time_utc_ms, s(p, "path_observed"),
                        s(p, "error_message")],
            )?;
            match result.as_str() {
                "ok" => {
                    conn.execute(
                        "INSERT INTO object_locations (object_id, location_id,
                           state, first_seen_event_id, last_seen_event_id,
                           last_verified_event_id, last_verified_time_utc_ms,
                           last_observed_path)
                         VALUES (?1,?2,'present',?3,?3,?3,?4,?5)
                         ON CONFLICT(object_id, location_id) DO UPDATE SET
                           state = 'present',
                           last_seen_event_id = excluded.last_seen_event_id,
                           last_verified_event_id = excluded.last_verified_event_id,
                           last_verified_time_utc_ms =
                             excluded.last_verified_time_utc_ms,
                           last_error = NULL",
                        params![event.object_id, event.location_id,
                                event.event_id, event.time_utc_ms,
                                s(p, "path_observed")],
                    )?;
                }
                "hash_mismatch" => {
                    conn.execute(
                        "UPDATE object_locations SET state='corrupt',
                           last_error='hash_mismatch', last_seen_event_id=?1
                         WHERE object_id=?2 AND location_id=?3",
                        params![event.event_id, event.object_id,
                                event.location_id],
                    )?;
                }
                _ => {
                    conn.execute(
                        "UPDATE object_locations SET last_error=?1
                         WHERE object_id=?2 AND location_id=?3",
                        params![s(p, "error_message")
                                    .unwrap_or_else(|| "read_error".into()),
                                event.object_id, event.location_id],
                    )?;
                }
            }
        }
        // Coverage and job events are mirror-only: jobs/job_items are
        // local-operational (decision doc, Decision 2) and must NOT be
        // resurrected by replay.
        "location_scanned" | "job_started" | "job_finished" => {}
        "annex_import_started" => {
            let im = obj(p, "import")?;
            conn.execute(
                "INSERT INTO git_annex_imports (import_id, repo_path,
                   collection_id, worktree_location_id, cas_location_id,
                   annex_objects_path, git_head_commit, annex_uuid,
                   import_started_event_id, import_completed_event_id,
                   imported_time_utc_ms, notes)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,NULL,NULL)
                 ON CONFLICT(import_id) DO UPDATE SET
                   git_head_commit = excluded.git_head_commit,
                   annex_uuid = excluded.annex_uuid",
                params![req(im, "import_id")?, req(im, "repo_path")?,
                        req(im, "collection_id")?,
                        req(im, "worktree_location_id")?,
                        req(im, "cas_location_id")?,
                        req(im, "annex_objects_path")?,
                        s(im, "git_head_commit"), s(im, "annex_uuid"),
                        event.event_id],
            )?;
        }
        "annex_key_mapped" => {
            conn.execute(
                "INSERT INTO git_annex_keys (annex_key, object_id, backend,
                   annex_size_bytes, annex_extension, parsed_hash_algo,
                   parsed_hash_hex, import_id, content_path, verified_event_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(annex_key) DO UPDATE SET
                   object_id = excluded.object_id,
                   content_path = excluded.content_path,
                   verified_event_id = excluded.verified_event_id",
                params![req(p, "annex_key")?, event.object_id, s(p, "backend"),
                        i(p, "annex_size_bytes"), s(p, "annex_extension"),
                        s(p, "parsed_hash_algo"), s(p, "parsed_hash_hex"),
                        req(p, "import_id")?, s(p, "content_path"),
                        event.event_id],
            )?;
        }
        "annex_import_completed" => {
            conn.execute(
                "UPDATE git_annex_imports SET import_completed_event_id=?1,
                   imported_time_utc_ms=?2, notes=?3 WHERE import_id=?4",
                params![event.event_id, event.time_utc_ms,
                        serde_json::to_string(p)?, req(p, "import_id")?],
            )?;
        }
        "checkpoint_created" => {
            conn.execute(
                "INSERT OR IGNORE INTO checkpoints (checkpoint_id,
                   created_time_utc_ms, stream_id, event_first_seq,
                   event_last_seq, event_last_hash, git_commit, manifest_path,
                   created_event_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![req(p, "checkpoint_id")?, event.time_utc_ms,
                        event.stream_id, i(p, "event_first_seq"),
                        i(p, "event_last_seq").unwrap_or(0),
                        req(p, "event_last_hash")?, s(p, "git_commit"),
                        req(p, "manifest_path")?, event.event_id],
            )?;
        }
        "snapshot_created" => {
            conn.execute(
                "INSERT OR IGNORE INTO sqlite_snapshots (snapshot_id,
                   created_time_utc_ms, snapshot_path, includes_stream_id,
                   includes_event_seq, includes_event_hash, snapshot_hash_algo,
                   snapshot_hash_hex, storage_location_id, created_event_id)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![req(p, "snapshot_id")?, event.time_utc_ms,
                        req(p, "snapshot_path")?, event.stream_id,
                        i(p, "includes_event_seq").unwrap_or(0),
                        req(p, "includes_event_hash")?,
                        req(p, "snapshot_hash_algo")?,
                        req(p, "snapshot_hash_hex")?,
                        s(p, "storage_location_id"), event.event_id],
            )?;
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test projector`
Expected: 9 passed.

- [ ] **Step 5: Commit**

```bash
git add src/projector.rs
git commit -m "feat: projector arms for content facts, verification, annex, lifecycle"
```

---

### Task 9: apply-new-events, full rebuild, and replay determinism

**Files:**
- Create: `src/apply.rs`
- Modify: `src/main.rs` (add `mod apply;`)
- Test: unit tests inline in `src/apply.rs`

**Interfaces:**
- Consumes: `store::read_all_events`, `projector::apply_event`, `db::{open, applied_seq, meta_set}`, `hash::line_hash`.
- Produces:
  - `apply::apply_new_events(conn: &mut Connection, archive_dir: &Path) -> anyhow::Result<u64>` — reads all events with `seq > applied_event_seq`, applies each inside one transaction per 10,000 events, updates `archive_meta` keys `applied_event_seq` and `applied_event_hash` (line hash of the last applied line) in the same transaction, returns count applied.
  - `apply::rebuild(archive_dir: &Path) -> anyhow::Result<u64>` — deletes `catalog.sqlite` (and `-wal`/`-shm` siblings), reopens via `db::open`, applies everything.
  - `apply::dump_derived_tables(conn: &Connection) -> anyhow::Result<String>` — deterministic dump (every derived table, rows ordered by primary key, tab-separated) used by determinism tests and by Task 10's `db verify`.

- [ ] **Step 1: Write the failing test**

Create `src/apply.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::event::EventDraft;
    use crate::store::EventStore;
    use serde_json::json;

    fn seed(dir: &std::path::Path) {
        let mut s = EventStore::open(dir).unwrap();
        s.append_batch(vec![
            EventDraft::new("archive_initialized",
                json!({"archive_id": "arch_t", "display_name": "T"})),
            EventDraft::new("site_registered", json!({"site":
                {"site_id": "site_home", "display_name": "Home",
                 "site_kind": "home", "description": null}})),
        ])
        .unwrap();
    }

    #[test]
    fn apply_is_incremental_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        let mut conn = db::open(dir.path()).unwrap();
        assert_eq!(apply_new_events(&mut conn, dir.path()).unwrap(), 2);
        assert_eq!(db::applied_seq(&conn).unwrap(), 2);
        // Re-apply: nothing new.
        assert_eq!(apply_new_events(&mut conn, dir.path()).unwrap(), 0);
        // Append one more, apply picks up exactly it.
        {
            drop(conn);
            let mut s = EventStore::open(dir.path()).unwrap();
            s.append(EventDraft::new("site_registered", json!({"site":
                {"site_id": "site_bank", "display_name": "Bank",
                 "site_kind": "safe_deposit_box", "description": null}})))
                .unwrap();
        }
        let mut conn = db::open(dir.path()).unwrap();
        assert_eq!(apply_new_events(&mut conn, dir.path()).unwrap(), 1);
        assert_eq!(db::applied_seq(&conn).unwrap(), 3);
    }

    #[test]
    fn rebuild_matches_incremental_apply() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        let mut conn = db::open(dir.path()).unwrap();
        apply_new_events(&mut conn, dir.path()).unwrap();
        let incremental = dump_derived_tables(&conn).unwrap();
        drop(conn);

        rebuild(dir.path()).unwrap();
        let conn2 = db::open(dir.path()).unwrap();
        let rebuilt = dump_derived_tables(&conn2).unwrap();
        assert_eq!(incremental, rebuilt, "replay must rebuild identical state");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test apply`
Expected: compile error, `apply_new_events` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/apply.rs`:

```rust
use crate::db::{self, applied_seq, meta_set};
use crate::hash::line_hash;
use crate::projector::apply_event;
use crate::store::read_all_events;
use anyhow::Result;
use rusqlite::Connection;
use std::fs;
use std::path::Path;

const BATCH: usize = 10_000;

/// Derived tables in the two-tier taxonomy (schema canvas, "Table Tiers").
/// jobs/job_items/policy_status/policy_rollup/archive_meta are excluded.
const DERIVED_TABLES: &[(&str, &str)] = &[
    ("events", "stream_id, seq"),
    ("objects", "object_id"),
    ("object_hashes", "object_id, hash_algo, hash_hex"),
    ("collections", "collection_id"),
    ("file_refs", "file_ref_id"),
    ("path_observations", "file_ref_id, location_id"),
    ("devices", "device_id"),
    ("device_mounts", "mount_id"),
    ("device_site_history", "device_id, arrived_time_utc_ms"),
    ("archive_roots", "archive_root_id"),
    ("sites", "site_id"),
    ("risk_domains", "risk_domain_id"),
    ("entity_risk_domains", "entity_type, entity_id, risk_domain_id"),
    ("locations", "location_id"),
    ("object_locations", "object_id, location_id"),
    ("verification_results", "verification_id"),
    ("quarantine_items", "quarantine_id"),
    ("policies", "policy_id"),
    ("checkpoints", "checkpoint_id"),
    ("sqlite_snapshots", "snapshot_id"),
    ("git_annex_imports", "import_id"),
    ("git_annex_keys", "annex_key"),
    ("external_indexes", "external_index_id"),
];

pub fn apply_new_events(conn: &mut Connection, archive_dir: &Path) -> Result<u64> {
    let from = applied_seq(conn)?;
    let events: Vec<_> = read_all_events(archive_dir)?
        .into_iter()
        .filter(|e| e.seq > from)
        .collect();
    let mut applied = 0u64;
    for chunk in events.chunks(BATCH) {
        let tx = conn.transaction()?;
        for e in chunk {
            apply_event(&tx, e)?;
        }
        let last = chunk.last().unwrap();
        meta_set(&tx, "applied_event_seq", &last.seq.to_string())?;
        meta_set(&tx, "applied_event_hash", &line_hash(&last.to_line()))?;
        tx.commit()?;
        applied += chunk.len() as u64;
    }
    Ok(applied)
}

pub fn rebuild(archive_dir: &Path) -> Result<u64> {
    for suffix in ["", "-wal", "-shm"] {
        let p = archive_dir.join(format!("catalog.sqlite{suffix}"));
        if p.exists() {
            fs::remove_file(&p)?;
        }
    }
    let mut conn = db::open(archive_dir)?;
    apply_new_events(&mut conn, archive_dir)
}

pub fn dump_derived_tables(conn: &Connection) -> Result<String> {
    let mut out = String::new();
    for (table, order) in DERIVED_TABLES {
        out.push_str(&format!("== {table}\n"));
        let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
        let ncols = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let mut fields = Vec::with_capacity(ncols);
            for idx in 0..ncols {
                let v: rusqlite::types::Value = row.get(idx)?;
                fields.push(match v {
                    rusqlite::types::Value::Null => "∅".to_string(),
                    rusqlite::types::Value::Integer(x) => x.to_string(),
                    rusqlite::types::Value::Real(x) => x.to_string(),
                    rusqlite::types::Value::Text(x) => x,
                    rusqlite::types::Value::Blob(x) => hex::encode(x),
                });
            }
            out.push_str(&fields.join("\t"));
            out.push('\n');
        }
    }
    Ok(out)
}
```

Add `mod apply;` to `src/main.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test apply`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/apply.rs src/main.rs
git commit -m "feat: incremental apply, full rebuild, and determinism dump"
```

---

### Task 10: CLI skeleton — init, events verify, db apply/rebuild, config

**Files:**
- Create: `src/gitutil.rs`, `tests/common/mod.rs`, `tests/cli_init.rs`
- Modify: `src/main.rs` (replace stub with real CLI)
- Test: `tests/cli_init.rs`

**Interfaces:**
- Consumes: everything from Tasks 1–9.
- Produces:
  - `gitutil::git(archive_dir: &Path, args: &[&str]) -> anyhow::Result<String>` — runs `git -C <dir> <args>`, errors with stderr on nonzero exit. `gitutil::ensure_repo(archive_dir)` — `git init -b main` if `.git` missing.
  - CLI commands: `archive [--archive <dir>] [--actor <id>] init --archive-id <id> --name <display>`, `archive events verify`, `archive db apply`, `archive db rebuild`, `archive config set <key> <value>`, `archive config get <key>` (config = `archive_meta`; the only meaningful key in MVP 1 is `host_device_id`, used as `host_id` on subsequent events).
  - A shared context helper in `main.rs`: `struct Ctx { archive_dir: PathBuf, actor: String }` and `fn mint_and_apply(ctx: &Ctx, drafts: Vec<EventDraft>) -> anyhow::Result<Vec<Event>>` — opens store, stamps `actor_id` (from `--actor`/`$USER`) and `host_id` (from `archive_meta.host_device_id` if set) on every draft, appends, then opens db and runs `apply::apply_new_events`. Every later mutating command (Tasks 11, 14, 15) goes through `mint_and_apply`.
  - Test helper `tests/common/mod.rs`: `fn init_archive() -> (tempfile::TempDir, PathBuf)` — runs `archive init` via assert_cmd and returns the archive dir; `fn archive_cmd(dir: &Path) -> assert_cmd::Command` — the binary with `--archive <dir>` preset.

`archive init` behavior: create dirs (`events/stream_primary`, `manifests/stream_primary`, `checkpoints`), write `.gitignore` (`catalog.sqlite*\n.archive.lock\nsnapshots/\n`), `gitutil::ensure_repo`, append genesis `archive_initialized` event `{archive_id, display_name}`, open db, apply. Refuses (error, exit non-zero) if a genesis event already exists.

- [ ] **Step 1: Write the failing test**

Create `tests/common/mod.rs`:

```rust
use assert_cmd::Command;
use std::path::{Path, PathBuf};

pub fn archive_cmd(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("archive").unwrap();
    c.arg("--archive").arg(dir).arg("--actor").arg("test");
    c
}

pub fn init_archive() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    archive_cmd(&dir)
        .args(["init", "--archive-id", "arch_test", "--name", "Test Archive"])
        .assert()
        .success();
    (tmp, dir)
}
```

Create `tests/cli_init.rs`:

```rust
mod common;
use common::{archive_cmd, init_archive};
use predicates::prelude::*;

#[test]
fn init_creates_archive_and_is_not_repeatable() {
    let (_tmp, dir) = init_archive();
    assert!(dir.join(".git").exists());
    assert!(dir.join("catalog.sqlite").exists());
    assert!(dir
        .join("events/stream_primary/seg-000000000001.jsonl")
        .exists());
    // Second init refuses.
    archive_cmd(&dir)
        .args(["init", "--archive-id", "arch_test", "--name", "Test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already initialized"));
}

#[test]
fn events_verify_and_db_commands_work() {
    let (_tmp, dir) = init_archive();
    archive_cmd(&dir)
        .args(["events", "verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 events"));
    archive_cmd(&dir).args(["db", "apply"]).assert().success();
    archive_cmd(&dir).args(["db", "rebuild"]).assert().success();
}

#[test]
fn config_set_get_roundtrip() {
    let (_tmp, dir) = init_archive();
    archive_cmd(&dir)
        .args(["config", "set", "host_device_id", "dev_primary_pc"])
        .assert()
        .success();
    archive_cmd(&dir)
        .args(["config", "get", "host_device_id"])
        .assert()
        .success()
        .stdout(predicate::str::contains("dev_primary_pc"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli_init`
Expected: FAIL — the stub binary has no subcommands.

- [ ] **Step 3: Implement gitutil and the CLI**

Create `src/gitutil.rs`:

```rust
use anyhow::{bail, Result};
use std::path::Path;
use std::process::Command;

pub fn git(archive_dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").arg("-C").arg(archive_dir).args(args).output()?;
    if !out.status.success() {
        bail!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn ensure_repo(archive_dir: &Path) -> Result<()> {
    if !archive_dir.join(".git").exists() {
        git(archive_dir, &["init", "-b", "main"])?;
    }
    // Repo-local fallback identity so `git commit` works in fresh
    // environments (CI, test sandboxes) with no global git config.
    if git(archive_dir, &["config", "user.email"]).is_err() {
        git(archive_dir, &["config", "user.email", "archive-ledger@localhost"])?;
        git(archive_dir, &["config", "user.name", "archive-ledger"])?;
    }
    Ok(())
}
```

Replace `src/main.rs`:

```rust
mod apply;
mod db;
mod event;
mod gitutil;
mod hash;
mod ids;
mod projector;
mod segment;
mod store;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use event::{Event, EventDraft};
use serde_json::json;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "archive", about = "Archive Ledger")]
struct Cli {
    /// Archive directory
    #[arg(long, global = true, default_value = ".")]
    archive: PathBuf,
    /// Actor recorded on events (defaults to $USER)
    #[arg(long, global = true)]
    actor: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialize a new archive (git repo, genesis event, catalog)
    Init {
        #[arg(long)]
        archive_id: String,
        #[arg(long)]
        name: String,
    },
    /// Event stream operations
    Events {
        #[command(subcommand)]
        cmd: EventsCmd,
    },
    /// Catalog database operations
    Db {
        #[command(subcommand)]
        cmd: DbCmd,
    },
    /// Local archive_meta configuration
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
}

#[derive(Subcommand)]
enum EventsCmd {
    /// Verify the full hash chain, manifests, and seq continuity
    Verify,
}

#[derive(Subcommand)]
enum DbCmd {
    /// Apply canonical events newer than applied_event_seq
    Apply,
    /// Delete and rebuild the catalog by full replay
    Rebuild,
}

#[derive(Subcommand)]
enum ConfigCmd {
    Set { key: String, value: String },
    Get { key: String },
}

pub struct Ctx {
    pub archive_dir: PathBuf,
    pub actor: String,
}

impl Ctx {
    fn new(cli: &Cli) -> Ctx {
        Ctx {
            archive_dir: cli.archive.clone(),
            actor: cli
                .actor
                .clone()
                .or_else(|| std::env::var("USER").ok())
                .unwrap_or_else(|| "unknown".to_string()),
        }
    }
}

/// Append drafts (stamped with actor/host) and apply them to the catalog.
pub fn mint_and_apply(ctx: &Ctx, drafts: Vec<EventDraft>) -> Result<Vec<Event>> {
    let mut conn = db::open(&ctx.archive_dir)?;
    let host = db::meta_get(&conn, "host_device_id")?;
    let stamped = drafts
        .into_iter()
        .map(|mut d| {
            d.actor_id = Some(ctx.actor.clone());
            if d.host_id.is_none() {
                d.host_id = host.clone();
            }
            d
        })
        .collect();
    let events = {
        let mut store = store::EventStore::open(&ctx.archive_dir)?;
        store.append_batch(stamped)?
    }; // lock released before apply
    apply::apply_new_events(&mut conn, &ctx.archive_dir)?;
    Ok(events)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let ctx = Ctx::new(&cli);
    match &cli.command {
        Cmd::Init { archive_id, name } => cmd_init(&ctx, archive_id, name),
        Cmd::Events { cmd: EventsCmd::Verify } => {
            let r = segment::verify_chain(&ctx.archive_dir)?;
            println!(
                "chain OK: {} events, {} segments ({} closed)",
                r.events, r.segments, r.closed_segments
            );
            Ok(())
        }
        Cmd::Db { cmd } => match cmd {
            DbCmd::Apply => {
                let mut conn = db::open(&ctx.archive_dir)?;
                let n = apply::apply_new_events(&mut conn, &ctx.archive_dir)?;
                println!("applied {n} events");
                Ok(())
            }
            DbCmd::Rebuild => {
                let n = apply::rebuild(&ctx.archive_dir)?;
                println!("rebuilt catalog from {n} events");
                Ok(())
            }
        },
        Cmd::Config { cmd } => {
            let conn = db::open(&ctx.archive_dir)?;
            match cmd {
                ConfigCmd::Set { key, value } => db::meta_set(&conn, key, value),
                ConfigCmd::Get { key } => {
                    match db::meta_get(&conn, key)? {
                        Some(v) => println!("{v}"),
                        None => println!(),
                    }
                    Ok(())
                }
            }
        }
    }
}

fn cmd_init(ctx: &Ctx, archive_id: &str, name: &str) -> Result<()> {
    let dir = &ctx.archive_dir;
    if !store::read_all_events(dir).unwrap_or_default().is_empty() {
        bail!("archive already initialized at {}", dir.display());
    }
    std::fs::create_dir_all(dir.join("checkpoints"))?;
    std::fs::create_dir_all(segment::manifests_dir(dir))?;
    std::fs::write(
        dir.join(".gitignore"),
        "catalog.sqlite*\n.archive.lock\nsnapshots/\n",
    )?;
    gitutil::ensure_repo(dir)?;
    mint_and_apply(
        ctx,
        vec![EventDraft::new(
            "archive_initialized",
            json!({"archive_id": archive_id, "display_name": name}),
        )],
    )?;
    println!("initialized archive {archive_id} at {}", dir.display());
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: all unit tests plus 3 cli_init tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/gitutil.rs tests/common/mod.rs tests/cli_init.rs
git commit -m "feat: CLI init, events verify, db apply/rebuild, config"
```

---

### Task 11: Registry CLI commands

**Files:**
- Create: `src/registry.rs`, `tests/cli_registry.rs`
- Modify: `src/main.rs` (add `mod registry;`, new subcommands)
- Test: `tests/cli_registry.rs`

**Interfaces:**
- Consumes: `mint_and_apply`, `Ctx` (Task 10), `event::EventDraft`.
- Produces `registry::` functions, each minting one full-snapshot event via `mint_and_apply` and setting the matching envelope ref field (`device_id`, `site_id`, `location_id`):
  - `register_site(ctx, site_id, name, kind, description) -> Result<()>`
  - `register_collection(ctx, collection_id, name, description) -> Result<()>`
  - `register_risk_domain(ctx, id, name, kind, description) -> Result<()>`
  - `assign_risk(ctx, entity_type, entity_id, risk_domain_id) -> Result<()>` / `unassign_risk(...)`
  - `register_device(ctx, device_id, name, kind, site_id: Option<&str>, owner: Option<&str>) -> Result<()>` (status `active`)
  - `move_device(ctx, device_id, to_site_id) -> Result<()>` — reads the device's current row from the catalog to build the full snapshot + from/to; errors if device unknown.
  - `register_archive_root(ctx, root_id, device_id, name, root_path_on_device) -> Result<()>` (status `active`)
  - `register_location(ctx, location_id, name, kind, archive_root_id: Option<&str>, relative_path: Option<&str>, device_id: Option<&str>, site_id: Option<&str>, uri: Option<&str>, trust_level: Option<&str>, encryption_state: Option<&str>) -> Result<()>`
- CLI shape (clap subcommands under `Cmd::Register`, `Cmd::Device`, `Cmd::Risk`):
  - `archive register site <id> --name <n> --kind <k> [--description <d>]`
  - `archive register collection <id> --name <n> [--description <d>]`
  - `archive register risk-domain <id> --name <n> --kind <k> [--description <d>]`
  - `archive register device <id> --name <n> --kind <k> [--site <site_id>] [--owner <o>]`
  - `archive register archive-root <id> --device <device_id> --name <n> --path <root_path_on_device>`
  - `archive register location <id> --name <n> --kind <k> [--archive-root <id>] [--relative-path <p>] [--device <id>] [--site <id>] [--uri <u>] [--trust <t>] [--encryption <e>]`
  - `archive device move <device_id> --to <site_id>`
  - `archive risk assign <risk_domain_id> --entity-type <t> --entity-id <id>` / `archive risk unassign …`

Payload shapes are exactly the Task 7 test payloads (full snapshots under `site`/`device`/`collection`/`risk_domain`/`archive_root`/`location` keys). `register_location` validation: error if both `device_id` and `site_id` are provided non-null with `device_id` set (site comes through the device — schema principle 8); error if `kind` is not one of `filesystem_tree|git_annex_worktree|git_annex_cas|cloud|ingest_staging`.

- [ ] **Step 1: Write the failing test**

Create `tests/cli_registry.rs`:

```rust
mod common;
use common::{archive_cmd, init_archive};
use predicates::prelude::*;

// NOTE: rusqlite will not coerce INTEGER results into String, so count
// queries below CAST explicitly.
fn q(dir: &std::path::Path, sql: &str) -> String {
    let conn = rusqlite::Connection::open(dir.join("catalog.sqlite")).unwrap();
    conn.query_row(sql, [], |r| r.get::<_, String>(0)).unwrap()
}

#[test]
fn full_registry_flow() {
    let (_tmp, dir) = init_archive();
    archive_cmd(&dir)
        .args(["register", "site", "site_home", "--name", "Home", "--kind", "home"])
        .assert().success();
    archive_cmd(&dir)
        .args(["register", "site", "site_bank", "--name", "Bank",
               "--kind", "safe_deposit_box"])
        .assert().success();
    archive_cmd(&dir)
        .args(["register", "collection", "photos", "--name", "Photos"])
        .assert().success();
    archive_cmd(&dir)
        .args(["register", "risk-domain", "risk_fire", "--name", "Home fire",
               "--kind", "fire"])
        .assert().success();
    archive_cmd(&dir)
        .args(["risk", "assign", "risk_fire",
               "--entity-type", "site", "--entity-id", "site_home"])
        .assert().success();
    archive_cmd(&dir)
        .args(["register", "device", "dev_usb_a", "--name", "USB A",
               "--kind", "usb_hdd", "--site", "site_home"])
        .assert().success();
    archive_cmd(&dir)
        .args(["register", "archive-root", "root_usb_a", "--device", "dev_usb_a",
               "--name", "USB A root", "--path", "/archive"])
        .assert().success();
    archive_cmd(&dir)
        .args(["register", "location", "loc_usb_a_photos", "--name", "USB A photos",
               "--kind", "filesystem_tree", "--archive-root", "root_usb_a",
               "--relative-path", "photos", "--device", "dev_usb_a",
               "--trust", "backup", "--encryption", "fde"])
        .assert().success();

    assert_eq!(q(&dir,
        "SELECT current_site_id FROM devices WHERE device_id='dev_usb_a'"),
        "site_home");
    assert_eq!(q(&dir,
        "SELECT device_id FROM locations WHERE location_id='loc_usb_a_photos'"),
        "dev_usb_a");

    archive_cmd(&dir)
        .args(["device", "move", "dev_usb_a", "--to", "site_bank"])
        .assert().success();
    assert_eq!(q(&dir,
        "SELECT current_site_id FROM devices WHERE device_id='dev_usb_a'"),
        "site_bank");
    assert_eq!(q(&dir,
        "SELECT CAST(count(*) AS TEXT) FROM device_site_history
         WHERE device_id='dev_usb_a'"),
        "2");
}

#[test]
fn location_kind_is_validated() {
    let (_tmp, dir) = init_archive();
    archive_cmd(&dir)
        .args(["register", "location", "loc_x", "--name", "X", "--kind", "bogus"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("kind"));
}

#[test]
fn device_move_requires_known_device() {
    let (_tmp, dir) = init_archive();
    archive_cmd(&dir)
        .args(["device", "move", "dev_ghost", "--to", "site_home"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown device"));
}
```

Add `rusqlite` usable from tests: it is already a dependency of the crate, and integration tests link the library — add to `Cargo.toml` under `[dev-dependencies]` nothing extra; instead expose the library: create `src/lib.rs`:

```rust
pub mod apply;
pub mod db;
pub mod event;
pub mod gitutil;
pub mod hash;
pub mod ids;
pub mod projector;
pub mod segment;
pub mod store;
```

and change `src/main.rs` module declarations to `use archive_ledger::{apply, db, event, gitutil, hash, ids, projector, segment, store};` — delete the `mod X;` lines (add `[lib] name = "archive_ledger"` plus `path = "src/lib.rs"` to `Cargo.toml`). The test above uses `rusqlite` directly: add `rusqlite = { version = "0.31", features = ["bundled"] }` to `[dev-dependencies]` too.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli_registry`
Expected: FAIL — subcommands don't exist.

- [ ] **Step 3: Implement registry commands**

Create `src/registry.rs` with one function per command; each builds the payload exactly as in the Task 7 tests and calls `mint_and_apply`. Representative implementations (write all of them following these patterns):

```rust
// registry.rs is a module of the BINARY crate (declared `mod registry;` in
// main.rs), so lib items come from `archive_ledger::` while mint_and_apply
// and Ctx come from `crate::` (main.rs).
use archive_ledger::{db, event::EventDraft};
use crate::{mint_and_apply, Ctx};
use anyhow::{bail, Result};
use serde_json::json;

const LOCATION_KINDS: &[&str] = &[
    "filesystem_tree", "git_annex_worktree", "git_annex_cas",
    "cloud", "ingest_staging",
];

pub fn register_site(
    ctx: &Ctx, site_id: &str, name: &str, kind: &str, description: Option<&str>,
) -> Result<()> {
    let mut d = EventDraft::new(
        "site_registered",
        json!({"site": {"site_id": site_id, "display_name": name,
               "site_kind": kind, "description": description}}),
    );
    d.site_id = Some(site_id.to_string());
    mint_and_apply(ctx, vec![d])?;
    Ok(())
}

pub fn move_device(ctx: &Ctx, device_id: &str, to_site_id: &str) -> Result<()> {
    let conn = db::open(&ctx.archive_dir)?;
    let row: Option<(String, String, Option<String>, Option<String>,
                     Option<String>, String, Option<String>)> = conn
        .query_row(
            "SELECT display_name, device_kind, serial_hint, hardware_fingerprint,
                    owner, status, current_site_id
             FROM devices WHERE device_id = ?1",
            [device_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?,
                    r.get(5)?, r.get(6)?)),
        )
        .ok();
    let Some((name, kind, serial, fp, owner, status, from_site)) = row else {
        bail!("unknown device {device_id}");
    };
    let mut d = EventDraft::new(
        "device_moved",
        json!({"device": {"device_id": device_id, "display_name": name,
               "device_kind": kind, "serial_hint": serial,
               "hardware_fingerprint": fp, "owner": owner, "status": status,
               "current_site_id": to_site_id},
              "from_site_id": from_site, "to_site_id": to_site_id}),
    );
    d.device_id = Some(device_id.to_string());
    d.site_id = Some(to_site_id.to_string());
    mint_and_apply(ctx, vec![d])?;
    Ok(())
}

pub fn register_location(
    ctx: &Ctx, location_id: &str, name: &str, kind: &str,
    archive_root_id: Option<&str>, relative_path: Option<&str>,
    device_id: Option<&str>, site_id: Option<&str>, uri: Option<&str>,
    trust_level: Option<&str>, encryption_state: Option<&str>,
) -> Result<()> {
    if !LOCATION_KINDS.contains(&kind) {
        bail!("invalid location kind {kind}; expected one of {LOCATION_KINDS:?}");
    }
    if device_id.is_some() && site_id.is_some() {
        bail!("device-backed locations inherit site via the device; \
               set --site only for device-less locations");
    }
    let mut d = EventDraft::new(
        "location_registered",
        json!({"location": {"location_id": location_id, "display_name": name,
               "kind": kind, "last_resolved_uri": uri,
               "archive_root_id": archive_root_id,
               "relative_path": relative_path, "device_id": device_id,
               "site_id": site_id, "encryption_state": encryption_state,
               "trust_level": trust_level, "is_writable": 0, "is_online": 1}}),
    );
    d.location_id = Some(location_id.to_string());
    d.device_id = device_id.map(String::from);
    mint_and_apply(ctx, vec![d])?;
    Ok(())
}
```

Implement the remaining functions the same way: `register_collection` (`collection_registered`), `register_risk_domain` (`risk_domain_registered`), `assign_risk`/`unassign_risk` (`risk_assigned`/`risk_unassigned` with flat payload), `register_device` (`device_registered`, status `active`, `current_site_id` from `--site`), `register_archive_root` (`archive_root_registered`, status `active`, payload keys exactly `archive_root_id, device_id, display_name, root_path_on_device, last_resolved_root_uri: null, status`). Wire the clap subcommands in `src/main.rs` (`Register { … }` enum with per-entity variants, `Device { Move }`, `Risk { Assign, Unassign }`) mapping 1:1 onto these functions.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: all tests pass, including 3 cli_registry tests.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/lib.rs src/main.rs src/registry.rs tests/cli_registry.rs
git commit -m "feat: registry CLI commands minting full-snapshot events"
```

---

### Task 12: git-annex key parser

**Files:**
- Create: `src/annex/mod.rs`, `src/annex/key.rs`
- Modify: `src/lib.rs` (add `pub mod annex;`)
- Test: unit tests inline in `src/annex/key.rs`

**Interfaces:**
- Consumes: nothing internal.
- Produces: `annex::key::AnnexKey { backend: String, size_bytes: Option<u64>, hash_algo: String, hash_hex: String, extension: Option<String> }`; `annex::key::parse(key: &str) -> anyhow::Result<AnnexKey>`.

**git-annex key format** (reference: git-annex internals docs): `BACKEND-sSIZE[-Schunk-Cnum]--HASH[.ext]`. Supported backends for MVP 1: `SHA512E`, `SHA512`, `SHA256E`, `SHA256`. `E` backends append the original file extension after the hash (`--<hex>.jpg`); the extension is part of the key string. Chunked keys (`-S`/`-C` fields present) and other backends (`WORM`, `URL`, `MD5`, `BLAKE2*`) are rejected with a descriptive error — the import counts them as skipped.

- [ ] **Step 1: Write the failing test**

Create `src/annex/mod.rs`:

```rust
pub mod key;
```

Create `src/annex/key.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sha512e_with_extension() {
        let k = parse("SHA512E-s42391551--a83d2bffee00c11a9f2d.jpg").unwrap();
        assert_eq!(k.backend, "SHA512E");
        assert_eq!(k.size_bytes, Some(42391551));
        assert_eq!(k.hash_algo, "sha512");
        assert_eq!(k.hash_hex, "a83d2bffee00c11a9f2d");
        assert_eq!(k.extension.as_deref(), Some("jpg"));
    }

    #[test]
    fn parses_sha256_without_extension() {
        let k = parse("SHA256-s99--deadbeef").unwrap();
        assert_eq!(k.backend, "SHA256");
        assert_eq!(k.hash_algo, "sha256");
        assert_eq!(k.hash_hex, "deadbeef");
        assert_eq!(k.extension, None);
    }

    #[test]
    fn rejects_chunked_and_unsupported_backends() {
        assert!(parse("SHA512E-s10-S5-C1--abcd.jpg").is_err());
        assert!(parse("WORM-s10-m1234--file.jpg").is_err());
        assert!(parse("URL--http://x").is_err());
        assert!(parse("garbage").is_err());
    }

    #[test]
    fn extension_with_dots_takes_last_component() {
        let k = parse("SHA256E-s5--cafe.tar.gz").unwrap();
        // git-annex keeps up to the last two short components; MVP takes the
        // full trailing extension string after the first dot.
        assert_eq!(k.extension.as_deref(), Some("tar.gz"));
        assert_eq!(k.hash_hex, "cafe");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test annex::key`
Expected: compile error, `parse` not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `src/annex/key.rs`:

```rust
use anyhow::{bail, Result};

#[derive(Debug, PartialEq)]
pub struct AnnexKey {
    pub backend: String,
    pub size_bytes: Option<u64>,
    pub hash_algo: String,
    pub hash_hex: String,
    pub extension: Option<String>,
}

/// Parse a git-annex key: BACKEND-sSIZE[-...fields]--HASH[.ext]
/// MVP supports SHA512(E)/SHA256(E), unchunked.
pub fn parse(key: &str) -> Result<AnnexKey> {
    let Some((prefix, hash_part)) = key.split_once("--") else {
        bail!("not a git-annex key (no '--'): {key}");
    };
    let mut fields = prefix.split('-');
    let backend = fields.next().unwrap_or_default().to_string();
    let hash_algo = match backend.as_str() {
        "SHA512" | "SHA512E" => "sha512",
        "SHA256" | "SHA256E" => "sha256",
        other => bail!("unsupported git-annex backend {other} in key {key}"),
    }
    .to_string();

    let mut size_bytes = None;
    for f in fields {
        if let Some(sz) = f.strip_prefix('s') {
            size_bytes = Some(sz.parse()?);
        } else if f.starts_with('S') || f.starts_with('C') {
            bail!("chunked git-annex keys are not supported: {key}");
        }
    }

    let (hash_hex, extension) = if backend.ends_with('E') {
        match hash_part.split_once('.') {
            Some((h, ext)) => (h.to_string(), Some(ext.to_string())),
            None => (hash_part.to_string(), None),
        }
    } else {
        (hash_part.to_string(), None)
    };

    if hash_hex.is_empty() || !hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid hash hex in git-annex key {key}");
    }

    Ok(AnnexKey {
        backend,
        size_bytes,
        hash_algo,
        hash_hex: hash_hex.to_lowercase(),
        extension,
    })
}
```

Add `pub mod annex;` to `src/lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test annex`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/annex src/lib.rs
git commit -m "feat: git-annex key parser (SHA512/SHA256, E-variants, unchunked)"
```

---

### Task 13: git-annex worktree walker

**Files:**
- Create: `src/annex/walk.rs`
- Modify: `src/annex/mod.rs` (add `pub mod walk;`)
- Test: unit tests inline in `src/annex/walk.rs`

**Interfaces:**
- Consumes: `annex::key::{parse, AnnexKey}`.
- Produces:
  - `annex::walk::AnnexEntry { worktree_rel_path: String, annex_key: String, parsed: AnnexKey, content_abs_path: PathBuf, content_present: bool, cas_rel_path: String, modified_time_utc_ms: Option<i64> }`
  - `annex::walk::WalkOutcome { entries: Vec<AnnexEntry>, non_annex_files: u64, unsupported_keys: Vec<(String, String)> }` (path, reason)
  - `annex::walk::walk_worktree(repo_root: &Path) -> anyhow::Result<WalkOutcome>` — walks the repo root (skipping `.git/`), classifies each regular file/symlink: symlink whose target path contains `.git/annex/objects/` → annexed entry (key = final path component of target; `cas_rel_path` = target path relative to `.git/annex/objects/`; `content_present` = target file exists); other files → `non_annex_files` count; keys that fail `key::parse` → `unsupported_keys`. Never opens or writes anything under `.git/annex/objects` beyond `exists()`/metadata.

**Test fixture note:** tests build a fake annex repo by hand — plain directories and symlinks, no git or git-annex binaries needed. The fixture builder lives here and is reused by Task 14's tests via `pub fn fixture_repo(...)` under `#[cfg(any(test, feature = "testfixtures"))]`; simpler: make it a normal `pub fn` in a `pub mod fixture` submodule guarded by `#[doc(hidden)]` so integration tests can call it.

- [ ] **Step 1: Write the failing test**

Create `src/annex/walk.rs`:

```rust
/// Test-support fixture builder: builds a fake git-annex repo layout with
/// plain dirs + symlinks. Used by this module's tests and tests/cli_import.rs.
#[doc(hidden)]
pub mod fixture {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    /// Adds one annexed file. content=None simulates dropped content
    /// (symlink present, CAS file absent).
    pub fn add_annexed_file(
        repo: &Path, rel_path: &str, key: &str, content: Option<&[u8]>,
    ) {
        // git-annex hashdir-mixed layout: .git/annex/objects/xx/yy/KEY/KEY
        let hashdir = format!("{}/{}", &key_dir_a(key), &key_dir_b(key));
        let obj_dir = repo
            .join(".git/annex/objects")
            .join(&hashdir)
            .join(key);
        if let Some(bytes) = content {
            fs::create_dir_all(&obj_dir).unwrap();
            fs::write(obj_dir.join(key), bytes).unwrap();
        }
        let file_path = repo.join(rel_path);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        let depth = rel_path.matches('/').count();
        let up = "../".repeat(depth);
        symlink(
            format!("{up}.git/annex/objects/{hashdir}/{key}/{key}"),
            &file_path,
        )
        .unwrap();
    }

    // Deterministic fake hashdir components (real git-annex uses a hash of
    // the key; the walker must not care what the components are).
    pub fn key_dir_a(key: &str) -> String {
        format!("{:02x}", key.len() as u8)
    }
    pub fn key_dir_b(key: &str) -> String {
        format!("{:02x}", (key.len() as u8).wrapping_mul(7))
    }

    pub fn add_plain_file(repo: &Path, rel_path: &str, content: &[u8]) {
        let p = repo.join(rel_path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    #[test]
    fn classifies_annexed_plain_and_unsupported() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        add_annexed_file(
            repo, "2024/a.jpg",
            "SHA256E-s5--aaaa.jpg", Some(b"hello"),
        );
        add_annexed_file(repo, "b.jpg", "SHA256E-s3--bbbb.jpg", None);
        add_annexed_file(repo, "c.dat", "WORM-s3-m17--c.dat", Some(b"xxx"));
        add_plain_file(repo, "README.md", b"hi");
        add_plain_file(repo, ".git/config", b"[core]");

        let out = walk_worktree(repo).unwrap();
        assert_eq!(out.entries.len(), 2);
        assert_eq!(out.non_annex_files, 1, ".git contents must be skipped");
        assert_eq!(out.unsupported_keys.len(), 1);

        let a = out
            .entries
            .iter()
            .find(|e| e.worktree_rel_path == "2024/a.jpg")
            .unwrap();
        assert_eq!(a.annex_key, "SHA256E-s5--aaaa.jpg");
        assert!(a.content_present);
        assert!(a.cas_rel_path.ends_with(
            "/SHA256E-s5--aaaa.jpg/SHA256E-s5--aaaa.jpg"));
        assert!(a.content_abs_path.exists());

        let b = out
            .entries
            .iter()
            .find(|e| e.worktree_rel_path == "b.jpg")
            .unwrap();
        assert!(!b.content_present);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test annex::walk`
Expected: compile error, `walk_worktree` not found.

- [ ] **Step 3: Write minimal implementation**

Add above the fixture module in `src/annex/walk.rs`:

```rust
use crate::annex::key::{parse, AnnexKey};
use anyhow::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct AnnexEntry {
    pub worktree_rel_path: String,
    pub annex_key: String,
    pub parsed: AnnexKey,
    pub content_abs_path: PathBuf,
    pub content_present: bool,
    pub cas_rel_path: String,
    pub modified_time_utc_ms: Option<i64>,
}

pub struct WalkOutcome {
    pub entries: Vec<AnnexEntry>,
    pub non_annex_files: u64,
    pub unsupported_keys: Vec<(String, String)>,
}

pub fn walk_worktree(repo_root: &Path) -> Result<WalkOutcome> {
    let mut out = WalkOutcome {
        entries: vec![],
        non_annex_files: 0,
        unsupported_keys: vec![],
    };
    let annex_objects = repo_root.join(".git/annex/objects");

    for entry in WalkDir::new(repo_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git")
    {
        let entry = entry?;
        let ft = entry.file_type();
        let rel = entry
            .path()
            .strip_prefix(repo_root)?
            .to_string_lossy()
            .to_string();

        if ft.is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            let target_str = target.to_string_lossy();
            let Some(idx) = target_str.find(".git/annex/objects/") else {
                out.non_annex_files += 1;
                continue;
            };
            let cas_rel = target_str[idx + ".git/annex/objects/".len()..].to_string();
            let key = Path::new(cas_rel.as_str())
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            match parse(&key) {
                Ok(parsed) => {
                    let content_abs = annex_objects.join(&cas_rel);
                    let meta = std::fs::metadata(&content_abs).ok();
                    out.entries.push(AnnexEntry {
                        worktree_rel_path: rel,
                        annex_key: key,
                        parsed,
                        content_present: meta.is_some(),
                        modified_time_utc_ms: meta.and_then(|m| {
                            m.modified().ok().map(|t| {
                                t.duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as i64
                            })
                        }),
                        content_abs_path: content_abs,
                        cas_rel_path: cas_rel,
                    });
                }
                Err(e) => out.unsupported_keys.push((rel, e.to_string())),
            }
        } else if ft.is_file() {
            out.non_annex_files += 1;
        }
    }
    out.entries.sort_by(|a, b| a.worktree_rel_path.cmp(&b.worktree_rel_path));
    Ok(out)
}
```

Add `pub mod walk;` to `src/annex/mod.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test annex`
Expected: 5 passed (4 key + 1 walk).

- [ ] **Step 5: Commit**

```bash
git add src/annex
git commit -m "feat: git-annex worktree walker with hand-built fixture support"
```

---

### Task 14: Annex import pipeline and CLI command

**Files:**
- Create: `src/annex/import.rs`, `tests/cli_import.rs`
- Modify: `src/annex/mod.rs` (add `pub mod import;`), `src/main.rs` (add `annex import` subcommand)
- Test: `tests/cli_import.rs`

**Interfaces:**
- Consumes: `annex::walk::walk_worktree`, `annex::key`, `hash::hash_file`, `mint_and_apply` pattern (but batching directly against `EventStore` + `apply_new_events` for throughput), `db`, `ids`, `store`, `registry::register_location`.
- Produces:
  - `annex::import::ImportParams { repo_path: PathBuf, collection_id: String, device_id: String, archive_root_id: String, worktree_location_id: String, cas_location_id: String, actor: String }`
  - `annex::import::run_import(archive_dir: &Path, params: &ImportParams) -> anyhow::Result<ImportSummary>` where `ImportSummary { keys_mapped: u64, objects_new: u64, objects_existing: u64, content_absent: u64, unsupported: u64, hash_mismatches: u64 }`
  - CLI: `archive annex import --repo <path> --collection <id> --device <device_id> --archive-root <root_id>` — derives `worktree_location_id` = `loc_annex_<collection>_<sanitized repo dirname>_worktree` and `cas_location_id` = same with `_cas` suffix (print both).

**Pipeline (per event-stream spec + Decision 5/6):**
1. Look up collection, device, archive root in catalog; error if any missing. Compute the repo's path relative to the archive root is NOT required for MVP — locations record `relative_path` as the repo dirname under the root if derivable, else the absolute repo path in `last_resolved_uri` only.
2. Register the two locations if not already in the catalog (`git_annex_worktree` kind with `last_resolved_uri = file://<repo>`; `git_annex_cas` kind with `last_resolved_uri = file://<repo>/.git/annex/objects`), via `location_registered` events. Idempotent: skip if location_id exists.
3. `job_started` (job_type `import_git_annex`) + `annex_import_started` events; insert `jobs` row directly (local-operational).
4. Walk the worktree. For each supported entry with content present:
   - `hash_file` the CAS content once (streaming, all digests).
   - If the annex key's hash algo digest ≠ parsed key hash → count `hash_mismatches`, add to errors list, emit NO per-file events, continue.
   - `object_id = "blake3:" + blake3_hex`. Change-only: query catalog for existing object / annex key / file_ref / observations and emit only missing facts:
     - `object_observed` if object unknown;
     - `object_hash_added` (sha512/sha256 from key, source `git-annex-key`) if that hash row missing;
     - `annex_key_mapped` if key unmapped;
     - `file_ref_added` if no active file_ref at `(collection, logical_path)` (logical_path = `<collection_id>/<worktree_rel_path>`; file_ref_id = `ids::new_id("fref")`), `file_ref_updated` if active but different object;
     - `path_observed` (worktree location) if no present observation of that file_ref/location with same object;
     - `copy_observed` (CAS location, path = `cas_rel_path`) if no present object_location row.
   - Entries with content absent: count only.
   - Batch: accumulate drafts, `append_batch` + `apply_new_events` every 1,000 files.
5. `annex_import_completed` + `job_finished`; update `jobs` row.

Re-running an import is therefore a cheap no-op (everything exists → zero per-file events) — this is the MVP 1 resume story.

- [ ] **Step 1: Write the failing test**

Create `tests/cli_import.rs`:

```rust
mod common;
use archive_ledger::annex::walk::fixture::{add_annexed_file, add_plain_file};
use common::{archive_cmd, init_archive};
use predicates::prelude::*;
use std::path::Path;

fn count(dir: &Path, sql: &str) -> i64 {
    let conn = rusqlite::Connection::open(dir.join("catalog.sqlite")).unwrap();
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

/// sha256 of b"hello" (well-known test vector).
const HELLO_SHA256: &str =
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

fn setup_repo(repo: &Path) {
    add_annexed_file(
        repo, "2024/a.jpg",
        &format!("SHA256E-s5--{HELLO_SHA256}.jpg"), Some(b"hello"),
    );
    // Same content at a second path: same object, second file_ref.
    add_annexed_file(
        repo, "2024/a_copy.jpg",
        &format!("SHA256E-s5--{HELLO_SHA256}.jpg"), Some(b"hello"),
    );
    // Key whose hash does not match its bytes.
    add_annexed_file(
        repo, "bad.jpg",
        &format!("SHA256E-s6--{}.jpg", "ab".repeat(32)), Some(b"WRONG!"),
    );
    // Dropped content.
    add_annexed_file(repo, "gone.jpg", "SHA256E-s1--cccc.jpg", None);
    add_plain_file(repo, "README.md", b"not annexed");
}

fn registered_archive_with_repo() -> (tempfile::TempDir, std::path::PathBuf,
                                      tempfile::TempDir) {
    let (tmp, dir) = init_archive();
    let repo_tmp = tempfile::tempdir().unwrap();
    setup_repo(repo_tmp.path());
    for args in [
        vec!["register", "site", "site_home", "--name", "Home", "--kind", "home"],
        vec!["register", "collection", "photos", "--name", "Photos"],
        vec!["register", "device", "dev_pc", "--name", "PC", "--kind", "pc",
             "--site", "site_home"],
        vec!["register", "archive-root", "root_pc", "--device", "dev_pc",
             "--name", "PC root", "--path", "/"],
    ] {
        archive_cmd(&dir).args(&args).assert().success();
    }
    (tmp, dir, repo_tmp)
}

#[test]
fn import_ingests_dedupes_and_is_idempotent() {
    let (_tmp, dir, repo) = registered_archive_with_repo();
    let repo_path = repo.path().to_str().unwrap().to_string();

    archive_cmd(&dir)
        .args(["annex", "import", "--repo", &repo_path, "--collection", "photos",
               "--device", "dev_pc", "--archive-root", "root_pc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keys_mapped: 1"))
        .stdout(predicate::str::contains("objects_new: 1"))
        .stdout(predicate::str::contains("hash_mismatches: 1"))
        .stdout(predicate::str::contains("content_absent: 1"));

    // One unique object, two file_refs, alternate sha256 hash preserved.
    assert_eq!(count(&dir, "SELECT count(*) FROM objects"), 1);
    assert_eq!(count(&dir,
        "SELECT count(*) FROM file_refs WHERE path_state='active'"), 2);
    assert_eq!(count(&dir,
        "SELECT count(*) FROM object_hashes WHERE hash_algo='sha256'
         AND source='git-annex-key'"), 1);
    assert_eq!(count(&dir, "SELECT count(*) FROM git_annex_keys"), 1);
    assert_eq!(count(&dir, "SELECT count(*) FROM path_observations"), 2);
    // Copy present at the CAS location only (one object, one CAS row).
    assert_eq!(count(&dir,
        "SELECT count(*) FROM object_locations WHERE state='present'"), 1);
    // Locations were auto-registered.
    assert_eq!(count(&dir,
        "SELECT count(*) FROM locations WHERE kind LIKE 'git_annex_%'"), 2);
    // Import recorded and completed.
    assert_eq!(count(&dir,
        "SELECT count(*) FROM git_annex_imports
         WHERE import_completed_event_id IS NOT NULL"), 1);

    let events_before = count(&dir, "SELECT count(*) FROM events");
    // Re-import: change-only means no new per-file events; only job/import
    // bracketing events are added.
    archive_cmd(&dir)
        .args(["annex", "import", "--repo", &repo_path, "--collection", "photos",
               "--device", "dev_pc", "--archive-root", "root_pc"])
        .assert()
        .success()
        .stdout(predicate::str::contains("objects_new: 0"));
    let events_after = count(&dir, "SELECT count(*) FROM events");
    assert!(
        events_after - events_before <= 4,
        "re-import must mint only bracketing events, got {} new",
        events_after - events_before
    );
    // Chain still verifies after import.
    archive_cmd(&dir).args(["events", "verify"]).assert().success();
}

#[test]
fn import_requires_registered_prerequisites() {
    let (_tmp, dir) = init_archive();
    let repo = tempfile::tempdir().unwrap();
    archive_cmd(&dir)
        .args(["annex", "import", "--repo", repo.path().to_str().unwrap(),
               "--collection", "photos", "--device", "dev_pc",
               "--archive-root", "root_pc"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("collection"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli_import`
Expected: FAIL — `annex` subcommand doesn't exist.

- [ ] **Step 3: Implement the pipeline**

Create `src/annex/import.rs`:

```rust
use crate::annex::walk::{walk_worktree, AnnexEntry};
use crate::apply::apply_new_events;
use crate::db;
use crate::event::EventDraft;
use crate::hash::hash_file;
use crate::ids::{new_id, now_ms};
use crate::store::EventStore;
use anyhow::{bail, Result};
use rusqlite::Connection;
use serde_json::json;
use std::path::{Path, PathBuf};

pub struct ImportParams {
    pub repo_path: PathBuf,
    pub collection_id: String,
    pub device_id: String,
    pub archive_root_id: String,
    pub worktree_location_id: String,
    pub cas_location_id: String,
    pub actor: String,
}

#[derive(Default)]
pub struct ImportSummary {
    pub keys_mapped: u64,
    pub objects_new: u64,
    pub objects_existing: u64,
    pub content_absent: u64,
    pub unsupported: u64,
    pub hash_mismatches: u64,
}

const APPLY_EVERY: usize = 1_000;

fn exists(conn: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> Result<bool> {
    let mut stmt = conn.prepare(sql)?;
    Ok(stmt.exists(params)?)
}

pub fn run_import(archive_dir: &Path, params: &ImportParams) -> Result<ImportSummary> {
    let mut conn = db::open(archive_dir)?;
    let host = db::meta_get(&conn, "host_device_id")?;

    // 1. Prerequisites.
    for (what, sql, id) in [
        ("collection", "SELECT 1 FROM collections WHERE collection_id=?1",
         &params.collection_id),
        ("device", "SELECT 1 FROM devices WHERE device_id=?1", &params.device_id),
        ("archive-root", "SELECT 1 FROM archive_roots WHERE archive_root_id=?1",
         &params.archive_root_id),
    ] {
        if !exists(&conn, sql, &[id])? {
            bail!("unknown {what} {id}; register it first");
        }
    }
    if !params.repo_path.join(".git/annex/objects").exists() {
        bail!("{} is not a git-annex repo (no .git/annex/objects)",
              params.repo_path.display());
    }

    let mut store = EventStore::open(archive_dir)?;
    let stamp = |mut d: EventDraft, actor: &str, host: &Option<String>| {
        d.actor_id = Some(actor.to_string());
        d.host_id = host.clone();
        d
    };
    let mut pending: Vec<EventDraft> = vec![];

    // 2. Locations (idempotent).
    let repo_uri = format!("file://{}", params.repo_path.display());
    for (loc_id, kind, uri) in [
        (&params.worktree_location_id, "git_annex_worktree", repo_uri.clone()),
        (&params.cas_location_id, "git_annex_cas",
         format!("{repo_uri}/.git/annex/objects")),
    ] {
        if !exists(&conn, "SELECT 1 FROM locations WHERE location_id=?1", &[loc_id])? {
            let mut d = EventDraft::new(
                "location_registered",
                json!({"location": {"location_id": loc_id, "display_name": loc_id,
                       "kind": kind, "last_resolved_uri": uri,
                       "archive_root_id": params.archive_root_id,
                       "relative_path": null, "device_id": params.device_id,
                       "site_id": null, "encryption_state": null,
                       "trust_level": "primary", "is_writable": 0,
                       "is_online": 1}}),
            );
            d.location_id = Some(loc_id.to_string());
            d.device_id = Some(params.device_id.clone());
            pending.push(stamp(d, &params.actor, &host));
        }
    }

    // 3. Job + import bracketing.
    let job_id = new_id("job");
    let import_id = new_id("anneximp");
    conn.execute(
        "INSERT INTO jobs (job_id, job_type, status, created_time_utc_ms,
           started_time_utc_ms, actor_id, host_id, params_json)
         VALUES (?1,'import_git_annex','running',?2,?2,?3,?4,?5)",
        rusqlite::params![job_id, now_ms(), params.actor, host,
            json!({"repo_path": params.repo_path.display().to_string(),
                   "collection_id": params.collection_id}).to_string()],
    )?;
    let mut d = EventDraft::new("job_started", json!({"job_id": job_id,
        "job_type": "import_git_annex",
        "params": {"repo_path": params.repo_path.display().to_string()}}));
    d.job_id = Some(job_id.clone());
    pending.push(stamp(d, &params.actor, &host));
    let mut d = EventDraft::new("annex_import_started", json!({"import":
        {"import_id": import_id, "repo_path": params.repo_path.display().to_string(),
         "collection_id": params.collection_id,
         "worktree_location_id": params.worktree_location_id,
         "cas_location_id": params.cas_location_id,
         "annex_objects_path":
            params.repo_path.join(".git/annex/objects").display().to_string(),
         "git_head_commit": null, "annex_uuid": null}}));
    d.job_id = Some(job_id.clone());
    pending.push(stamp(d, &params.actor, &host));
    store.append_batch(std::mem::take(&mut pending))?;
    apply_new_events(&mut conn, archive_dir)?;

    // 4. Walk and ingest.
    let walk = walk_worktree(&params.repo_path)?;
    let mut summary = ImportSummary {
        unsupported: walk.unsupported_keys.len() as u64,
        ..Default::default()
    };
    let mut errors: Vec<serde_json::Value> = walk
        .unsupported_keys
        .iter()
        .map(|(p, r)| json!({"path": p, "reason": r}))
        .collect();

    for entry in &walk.entries {
        if !entry.content_present {
            summary.content_absent += 1;
            continue;
        }
        let drafts = ingest_entry(&conn, params, &job_id, &import_id, entry,
                                  &mut summary, &mut errors)?;
        pending.extend(drafts.into_iter().map(|d| stamp(d, &params.actor, &host)));
        if pending.len() >= APPLY_EVERY {
            store.append_batch(std::mem::take(&mut pending))?;
            apply_new_events(&mut conn, archive_dir)?;
        }
    }

    // 5. Completion bracketing.
    let mut d = EventDraft::new("annex_import_completed", json!({
        "import_id": import_id, "keys_mapped": summary.keys_mapped,
        "objects_new": summary.objects_new,
        "objects_existing": summary.objects_existing, "errors": errors}));
    d.job_id = Some(job_id.clone());
    pending.push(stamp(d, &params.actor, &host));
    let mut d = EventDraft::new("job_finished", json!({"job_id": job_id,
        "status": "complete", "summary": {
            "keys_mapped": summary.keys_mapped,
            "objects_new": summary.objects_new,
            "content_absent": summary.content_absent,
            "unsupported": summary.unsupported,
            "hash_mismatches": summary.hash_mismatches}}));
    d.job_id = Some(job_id.clone());
    pending.push(stamp(d, &params.actor, &host));
    store.append_batch(pending)?;
    apply_new_events(&mut conn, archive_dir)?;
    conn.execute(
        "UPDATE jobs SET status='complete', finished_time_utc_ms=?1 WHERE job_id=?2",
        rusqlite::params![now_ms(), job_id],
    )?;
    Ok(summary)
}

/// Change-only ingest of one annexed file; returns the missing-fact drafts.
fn ingest_entry(
    conn: &Connection, params: &ImportParams, job_id: &str, import_id: &str,
    entry: &AnnexEntry, summary: &mut ImportSummary,
    errors: &mut Vec<serde_json::Value>,
) -> Result<Vec<EventDraft>> {
    let h = hash_file(&entry.content_abs_path)?;
    let legacy_ok = match entry.parsed.hash_algo.as_str() {
        "sha512" => h.sha512_hex == entry.parsed.hash_hex,
        "sha256" => h.sha256_hex == entry.parsed.hash_hex,
        _ => false,
    };
    if !legacy_ok {
        summary.hash_mismatches += 1;
        errors.push(json!({"path": entry.worktree_rel_path,
                           "reason": "annex key hash mismatch"}));
        return Ok(vec![]);
    }

    let object_id = format!("blake3:{}", h.blake3_hex);
    let mut drafts = vec![];
    let set_ids = |mut d: EventDraft, oid: Option<&str>, loc: Option<&str>| {
        d.object_id = oid.map(String::from);
        d.location_id = loc.map(String::from);
        d.job_id = Some(job_id.to_string());
        d
    };

    if !exists(conn, "SELECT 1 FROM objects WHERE object_id=?1", &[&object_id])? {
        summary.objects_new += 1;
        drafts.push(set_ids(
            EventDraft::new("object_observed", json!({"object":
                {"object_id": object_id, "size_bytes": h.size_bytes,
                 "media_type": null,
                 "extension_hint": entry.parsed.extension}})),
            Some(&object_id), None,
        ));
    } else {
        summary.objects_existing += 1;
    }

    if !exists(conn,
        "SELECT 1 FROM object_hashes WHERE object_id=?1 AND hash_algo=?2
         AND hash_hex=?3",
        &[&object_id, &entry.parsed.hash_algo, &entry.parsed.hash_hex])?
    {
        drafts.push(set_ids(
            EventDraft::new("object_hash_added", json!({
                "hash_algo": entry.parsed.hash_algo,
                "hash_hex": entry.parsed.hash_hex,
                "source": "git-annex-key"})),
            Some(&object_id), None,
        ));
    }

    if !exists(conn, "SELECT 1 FROM git_annex_keys WHERE annex_key=?1",
               &[&entry.annex_key])?
    {
        summary.keys_mapped += 1;
        drafts.push(set_ids(
            EventDraft::new("annex_key_mapped", json!({
                "annex_key": entry.annex_key, "backend": entry.parsed.backend,
                "annex_size_bytes": entry.parsed.size_bytes,
                "annex_extension": entry.parsed.extension,
                "parsed_hash_algo": entry.parsed.hash_algo,
                "parsed_hash_hex": entry.parsed.hash_hex,
                "content_path": entry.cas_rel_path, "import_id": import_id})),
            Some(&object_id), None,
        ));
    }

    let logical_path = format!("{}/{}", params.collection_id, entry.worktree_rel_path);
    let existing_ref: Option<(String, String)> = conn
        .query_row(
            "SELECT file_ref_id, object_id FROM file_refs
             WHERE collection_id=?1 AND logical_path=?2 AND path_state='active'",
            rusqlite::params![params.collection_id, logical_path],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let original_name = Path::new(&entry.worktree_rel_path)
        .file_name().unwrap_or_default().to_string_lossy().to_string();
    let file_ref_id = match existing_ref {
        None => {
            let id = new_id("fref");
            drafts.push(set_ids(
                EventDraft::new("file_ref_added", json!({"file_ref":
                    {"file_ref_id": id, "collection_id": params.collection_id,
                     "object_id": object_id, "logical_path": logical_path,
                     "original_name": original_name,
                     "created_time_utc_ms": null,
                     "modified_time_utc_ms": entry.modified_time_utc_ms,
                     "observed_size_bytes": h.size_bytes}})),
                Some(&object_id), None,
            ));
            id
        }
        Some((id, obj)) if obj != object_id => {
            drafts.push(set_ids(
                EventDraft::new("file_ref_updated", json!({"file_ref":
                    {"file_ref_id": id, "collection_id": params.collection_id,
                     "object_id": object_id, "logical_path": logical_path,
                     "original_name": original_name,
                     "created_time_utc_ms": null,
                     "modified_time_utc_ms": entry.modified_time_utc_ms,
                     "observed_size_bytes": h.size_bytes},
                    "previous_object_id": obj})),
                Some(&object_id), None,
            ));
            id
        }
        Some((id, _)) => id,
    };

    if !exists(conn,
        "SELECT 1 FROM path_observations WHERE file_ref_id=?1 AND location_id=?2
         AND state='present' AND object_id=?3",
        &[&file_ref_id, &params.worktree_location_id, &object_id])?
    {
        drafts.push(set_ids(
            EventDraft::new("path_observed", json!({
                "file_ref_id": file_ref_id,
                "observed_path": entry.worktree_rel_path,
                "observed_size_bytes": h.size_bytes,
                "modified_time_utc_ms": entry.modified_time_utc_ms})),
            Some(&object_id), Some(&params.worktree_location_id),
        ));
    }

    if !exists(conn,
        "SELECT 1 FROM object_locations WHERE object_id=?1 AND location_id=?2
         AND state='present'",
        &[&object_id, &params.cas_location_id])?
    {
        drafts.push(set_ids(
            EventDraft::new("copy_observed", json!({"path": entry.cas_rel_path})),
            Some(&object_id), Some(&params.cas_location_id),
        ));
    }

    Ok(drafts)
}
```

Add `pub mod import;` to `src/annex/mod.rs`. Wire the CLI in `src/main.rs`: subcommand `Annex { Import { repo: PathBuf, collection: String, device: String, archive_root: String } }`; the handler derives location IDs (`loc_annex_{collection}_{dirname}_worktree` / `_cas`, dirname sanitized to `[a-z0-9_]`), builds `ImportParams` with `actor` from `Ctx`, calls `run_import`, then prints the summary exactly as:

```text
keys_mapped: N
objects_new: N
objects_existing: N
content_absent: N
unsupported: N
hash_mismatches: N
```

**Note on the change-only queries:** `ingest_entry` checks the catalog, but drafts within one batch are not yet applied — two paths to the same NEW object in one batch would both emit `object_observed`. Prevent this with an in-memory `HashSet<String>` of object/key/path facts already drafted in the current batch, consulted alongside the SQL checks (add `seen_objects: &mut HashSet<String>` etc. to `ingest_entry`'s signature; the projector's upserts make duplicates harmless, but the dedup keeps `objects_new` counts correct — the test's `a_copy.jpg` exercises exactly this).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: all tests pass, including 2 cli_import tests.

- [ ] **Step 5: Commit**

```bash
git add src/annex src/main.rs tests/cli_import.rs
git commit -m "feat: read-only git-annex import with change-only event minting"
```

---

### Task 15: Checkpoint command

**Files:**
- Create: `src/checkpoint.rs`, `tests/cli_checkpoint.rs`
- Modify: `src/lib.rs` (add `pub mod checkpoint;`), `src/main.rs` (add `checkpoint` subcommand)
- Test: `tests/cli_checkpoint.rs`

**Interfaces:**
- Consumes: `store::EventStore`, `segment::{close_open_segment, manifests_dir, verify_chain, Manifest}`, `gitutil::git`, `event::EventDraft`, `ids::{new_id, now_ms}`, `apply::apply_new_events`, `db`.
- Produces: `checkpoint::create(archive_dir: &Path, actor: &str) -> anyhow::Result<String>` returning the checkpoint_id. CLI: `archive checkpoint`.

**Flow (event-stream spec, "Segment and Checkpoint Layout"):**
1. Open the store; call `segment::close_open_segment` (force-close even if small). If there was nothing to close AND a checkpoint already covers the current tail seq, error "nothing to checkpoint".
2. Read all manifests in `manifests/stream_primary/` (sorted); build the checkpoint file `checkpoints/chk_<UTCyyyymmdd>_<seq padded 6>.json` with `checkpoint_v: 1`, `checkpoint_id`, `created_time_utc_ms`, `stream_id`, `event_first_seq: 1`, `event_last_seq` and `event_last_hash` from the newest manifest, and `segments: [{file, manifest, segment_blake3}]` for every closed segment.
3. Mint `checkpoint_created` (payload per spec: `checkpoint_id, event_first_seq, event_last_seq, event_last_hash, manifest_path` = the checkpoint file's repo-relative path, `git_commit: null`) — this event opens the NEXT segment. Apply to catalog.
4. `git add` all closed segment files, all manifests, the checkpoint file, `.gitignore`; `git commit -m "checkpoint <id>: events through seq <N>"`.
5. Print checkpoint id, covered seq, and the git commit hash (`git rev-parse HEAD`).

- [ ] **Step 1: Write the failing test**

Create `tests/cli_checkpoint.rs`:

```rust
mod common;
use common::{archive_cmd, init_archive};
use predicates::prelude::*;

#[test]
fn checkpoint_closes_segment_commits_and_chains_next_segment() {
    let (_tmp, dir) = init_archive();
    archive_cmd(&dir)
        .args(["register", "site", "site_home", "--name", "Home", "--kind", "home"])
        .assert().success();

    archive_cmd(&dir)
        .args(["checkpoint"])
        .assert()
        .success()
        .stdout(predicate::str::contains("chk_"));

    // Segment closed: manifest exists; checkpoint file exists.
    let manifests: Vec<_> = std::fs::read_dir(dir.join("manifests/stream_primary"))
        .unwrap().collect();
    assert_eq!(manifests.len(), 1);
    let checkpoints: Vec<_> = std::fs::read_dir(dir.join("checkpoints"))
        .unwrap().collect();
    assert_eq!(checkpoints.len(), 1);

    // Git commit exists and includes the closed segment.
    let log = std::process::Command::new("git")
        .args(["-C", dir.to_str().unwrap(), "log", "--oneline"])
        .output().unwrap();
    assert!(String::from_utf8_lossy(&log.stdout).contains("checkpoint"));

    // checkpoint_created landed in the NEXT segment and the chain verifies
    // across the boundary.
    let segs: Vec<_> = std::fs::read_dir(dir.join("events/stream_primary"))
        .unwrap().collect();
    assert_eq!(segs.len(), 2);
    archive_cmd(&dir)
        .args(["events", "verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 closed"));

    // checkpoints table row projected.
    let conn = rusqlite::Connection::open(dir.join("catalog.sqlite")).unwrap();
    let n: i64 = conn
        .query_row("SELECT count(*) FROM checkpoints", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);

    // A second checkpoint right away has new events (the checkpoint_created
    // event itself), so it succeeds and closes the second segment.
    archive_cmd(&dir).args(["checkpoint"]).assert().success();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli_checkpoint`
Expected: FAIL — `checkpoint` subcommand doesn't exist.

- [ ] **Step 3: Write the implementation**

Create `src/checkpoint.rs`:

```rust
use crate::apply::apply_new_events;
use crate::db;
use crate::event::EventDraft;
use crate::gitutil::git;
use crate::ids::now_ms;
use crate::segment::{close_open_segment, manifests_dir, Manifest};
use crate::store::{EventStore, STREAM_ID};
use anyhow::{bail, Result};
use serde_json::json;
use std::fs;
use std::path::Path;

pub fn create(archive_dir: &Path, actor: &str) -> Result<String> {
    let mut store = EventStore::open(archive_dir)?;
    let closed_now = close_open_segment(&mut store)?;

    // Collect all manifests, sorted by segment file name.
    let mut manifests: Vec<Manifest> = vec![];
    for entry in fs::read_dir(manifests_dir(archive_dir))? {
        let p = entry?.path();
        if p.extension().map(|e| e == "json").unwrap_or(false) {
            manifests.push(serde_json::from_str(&fs::read_to_string(&p)?)?);
        }
    }
    manifests.sort_by(|a, b| a.first_seq.cmp(&b.first_seq));
    let Some(newest) = manifests.last() else {
        bail!("nothing to checkpoint: no closed segments");
    };
    if closed_now.is_none() {
        bail!("nothing to checkpoint: no new events since last checkpoint");
    }

    let created = now_ms();
    let date = chrono::DateTime::from_timestamp_millis(created)
        .unwrap()
        .format("%Y%m%d");
    let checkpoint_id = format!("chk_{date}_{:06}", newest.last_seq);
    let file_rel = format!("checkpoints/{checkpoint_id}.json");

    let checkpoint_json = json!({
        "checkpoint_v": 1,
        "checkpoint_id": checkpoint_id,
        "created_time_utc_ms": created,
        "stream_id": STREAM_ID,
        "event_first_seq": 1,
        "event_last_seq": newest.last_seq,
        "event_last_hash": newest.last_event_hash,
        "segments": manifests.iter().map(|m| json!({
            "file": m.segment_file,
            "manifest": format!("manifests/{STREAM_ID}/{}",
                Path::new(&m.segment_file).file_stem().unwrap()
                    .to_str().unwrap().to_string() + ".manifest.json"),
            "segment_blake3": m.segment_blake3,
        })).collect::<Vec<_>>(),
    });
    fs::create_dir_all(archive_dir.join("checkpoints"))?;
    fs::write(
        archive_dir.join(&file_rel),
        serde_json::to_string_pretty(&checkpoint_json)? + "\n",
    )?;

    // checkpoint_created opens the next segment.
    let mut draft = EventDraft::new(
        "checkpoint_created",
        json!({"checkpoint_id": checkpoint_id, "event_first_seq": 1,
               "event_last_seq": newest.last_seq,
               "event_last_hash": newest.last_event_hash,
               "manifest_path": file_rel, "git_commit": null}),
    );
    draft.actor_id = Some(actor.to_string());
    store.append(draft)?;
    drop(store);
    let mut conn = db::open(archive_dir)?;
    apply_new_events(&mut conn, archive_dir)?;

    // Commit canonical artifacts.
    git(archive_dir, &["add", "--", "events", "manifests", "checkpoints",
        ".gitignore"])?;
    git(archive_dir, &["commit", "-m",
        &format!("checkpoint {checkpoint_id}: events through seq {}",
                 newest.last_seq)])?;
    Ok(checkpoint_id)
}
```

Wire `Cmd::Checkpoint` in `src/main.rs`: call `checkpoint::create(&ctx.archive_dir, &ctx.actor)`, then print:

```rust
let id = checkpoint::create(&ctx.archive_dir, &ctx.actor)?;
let commit = gitutil::git(&ctx.archive_dir, &["rev-parse", "HEAD"])?;
println!("checkpoint {id} committed as {commit}");
```

**Wait — `git add -- events` would stage the new OPEN segment too** (it now contains `checkpoint_created`). Stage explicitly instead: replace the `git add` call with per-file adds — every `m.segment_file` from `manifests`, every manifest path, the checkpoint file, and `.gitignore`:

```rust
    let mut add_args: Vec<String> = vec!["add".into(), "--".into()];
    for m in &manifests {
        add_args.push(m.segment_file.clone());
        add_args.push(format!("manifests/{STREAM_ID}/{}",
            Path::new(&m.segment_file).file_stem().unwrap()
                .to_str().unwrap().to_string() + ".manifest.json"));
    }
    add_args.push(file_rel.clone());
    add_args.push(".gitignore".into());
    let arg_refs: Vec<&str> = add_args.iter().map(String::as_str).collect();
    git(archive_dir, &arg_refs)?;
```

Use this explicit form in the final implementation (the earlier snippet's directory-level `git add` is superseded).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: all tests pass, including cli_checkpoint. Note the test asserts the open segment (containing `checkpoint_created`) exists but only 1 segment is closed.

- [ ] **Step 5: Commit**

```bash
git add src/checkpoint.rs src/lib.rs src/main.rs tests/cli_checkpoint.rs
git commit -m "feat: checkpoint command closing segments and committing to git"
```

---

### Task 16: Reports — status, risk, verification

**Files:**
- Create: `src/report.rs`, `tests/cli_report.rs`
- Modify: `src/lib.rs` (add `pub mod report;`), `src/main.rs` (add `status` and `report` subcommands)
- Test: `tests/cli_report.rs`

**Interfaces:**
- Consumes: `db::open`.
- Produces (each takes `conn: &Connection`, returns `anyhow::Result<String>` — plain-text report printed by the CLI):
  - `report::status(conn)` — archive_id, applied seq; objects (count, total bytes); active file_refs per collection; locations with present-copy counts; verification summary (verified / never-verified object-location pairs).
  - `report::risk(conn)` — per risk domain: exposed present copies, and the SPOF list: objects ALL of whose present copies fall inside that risk domain (capped at 20 object ids, plus a total count). Risk resolution per Decision 3: a location's risk domains = direct location mappings ∪ device mappings ∪ device's current site mappings ∪ (device-less) location site mappings.
  - `report::verification(conn)` — object-location pairs never verified; verified pairs with age buckets (<30d, 30–365d, >365d) computed against `now_ms()`; oldest 10 verified pairs. Freshness is computed at query time (Decision 4) — nothing is read from a stored freshness state.
- CLI: `archive status`, `archive report risk`, `archive report verification`.

**The risk SQL** (the one non-obvious query — location's effective risk domains as a CTE):

```sql
WITH loc_risk AS (
  SELECT l.location_id, erd.risk_domain_id
  FROM locations l
  JOIN entity_risk_domains erd
    ON (erd.entity_type = 'location' AND erd.entity_id = l.location_id)
    OR (erd.entity_type = 'device'   AND erd.entity_id = l.device_id)
    OR (erd.entity_type = 'site'     AND erd.entity_id = COALESCE(
          (SELECT d.current_site_id FROM devices d
            WHERE d.device_id = l.device_id), l.site_id))
),
present AS (
  SELECT object_id, location_id FROM object_locations WHERE state = 'present'
)
SELECT rd.risk_domain_id, rd.display_name,
  (SELECT count(*) FROM present p JOIN loc_risk lr
     ON lr.location_id = p.location_id
     WHERE lr.risk_domain_id = rd.risk_domain_id) AS exposed_copies,
  (SELECT count(*) FROM (
     SELECT p.object_id FROM present p
     GROUP BY p.object_id
     HAVING count(*) = sum(EXISTS (
       SELECT 1 FROM loc_risk lr WHERE lr.location_id = p.location_id
         AND lr.risk_domain_id = rd.risk_domain_id))
  )) AS spof_objects
FROM risk_domains rd
ORDER BY rd.risk_domain_id;
```

- [ ] **Step 1: Write the failing test**

Create `tests/cli_report.rs`:

```rust
mod common;
use archive_ledger::annex::walk::fixture::add_annexed_file;
use common::{archive_cmd, init_archive};
use predicates::prelude::*;

/// sha256 of b"hello".
const HELLO_SHA256: &str =
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

#[test]
fn status_and_reports_reflect_an_imported_archive() {
    let (_tmp, dir) = init_archive();
    let repo = tempfile::tempdir().unwrap();
    add_annexed_file(
        repo.path(), "a.jpg",
        &format!("SHA256E-s5--{HELLO_SHA256}.jpg"), Some(b"hello"),
    );
    for args in [
        vec!["register", "site", "site_home", "--name", "Home", "--kind", "home"],
        vec!["register", "collection", "photos", "--name", "Photos"],
        vec!["register", "risk-domain", "risk_fire", "--name", "Home fire",
             "--kind", "fire"],
        vec!["risk", "assign", "risk_fire",
             "--entity-type", "site", "--entity-id", "site_home"],
        vec!["register", "device", "dev_pc", "--name", "PC", "--kind", "pc",
             "--site", "site_home"],
        vec!["register", "archive-root", "root_pc", "--device", "dev_pc",
             "--name", "PC root", "--path", "/"],
    ] {
        archive_cmd(&dir).args(&args).assert().success();
    }
    let repo_path = repo.path().to_str().unwrap().to_string();
    archive_cmd(&dir)
        .args(["annex", "import", "--repo", &repo_path, "--collection", "photos",
               "--device", "dev_pc", "--archive-root", "root_pc"])
        .assert().success();

    archive_cmd(&dir)
        .args(["status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("objects: 1"))
        .stdout(predicate::str::contains("photos"));

    // Every copy is at home => 1 SPOF object under risk_fire.
    archive_cmd(&dir)
        .args(["report", "risk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("risk_fire"))
        .stdout(predicate::str::contains("spof_objects: 1"));

    // Nothing verified yet.
    archive_cmd(&dir)
        .args(["report", "verification"])
        .assert()
        .success()
        .stdout(predicate::str::contains("never_verified: 1"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test cli_report`
Expected: FAIL — `status`/`report` subcommands don't exist.

- [ ] **Step 3: Write the implementation**

Create `src/report.rs`. `status` and `verification` are straightforward aggregate queries over `objects`, `file_refs`, `object_locations`, `locations`, `verification_results`, `archive_meta`; format each section as `key: value` lines (the tests match `objects: 1`, `never_verified: 1`). `risk` runs the CTE query above once per output row and prints, per domain:

```text
risk_fire (Home fire)
  exposed_copies: 1
  spof_objects: 1
```

plus up to 20 SPOF object ids indented beneath (query: same `HAVING` subselect with `LIMIT 20`). Representative skeleton:

```rust
use anyhow::Result;
use rusqlite::Connection;

pub fn status(conn: &Connection) -> Result<String> {
    let mut out = String::new();
    let archive_id: String = crate::db::meta_get(conn, "archive_id")?
        .unwrap_or_default();
    let applied: u64 = crate::db::applied_seq(conn)?;
    out.push_str(&format!("archive: {archive_id}\napplied_seq: {applied}\n"));
    let (n_obj, bytes): (i64, i64) = conn.query_row(
        "SELECT count(*), COALESCE(sum(size_bytes),0) FROM objects",
        [], |r| Ok((r.get(0)?, r.get(1)?)))?;
    out.push_str(&format!("objects: {n_obj}\ntotal_bytes: {bytes}\n"));
    out.push_str("collections:\n");
    let mut stmt = conn.prepare(
        "SELECT collection_id, count(*) FROM file_refs
         WHERE path_state='active' GROUP BY collection_id ORDER BY 1")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let (c, n): (String, i64) = (row.get(0)?, row.get(1)?);
        out.push_str(&format!("  {c}: {n} active refs\n"));
    }
    out.push_str("locations:\n");
    let mut stmt = conn.prepare(
        "SELECT l.location_id, l.kind,
                (SELECT count(*) FROM object_locations ol
                  WHERE ol.location_id = l.location_id AND ol.state='present')
         FROM locations l ORDER BY 1")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let (l, k, n): (String, String, i64) =
            (row.get(0)?, row.get(1)?, row.get(2)?);
        out.push_str(&format!("  {l} [{k}]: {n} present copies\n"));
    }
    let (verified, never): (i64, i64) = conn.query_row(
        "SELECT
           count(CASE WHEN last_verified_time_utc_ms IS NOT NULL THEN 1 END),
           count(CASE WHEN last_verified_time_utc_ms IS NULL THEN 1 END)
         FROM object_locations WHERE state='present'",
        [], |r| Ok((r.get(0)?, r.get(1)?)))?;
    out.push_str(&format!("verified_pairs: {verified}\nnever_verified: {never}\n"));
    Ok(out)
}
```

Implement `risk(conn)` and `verification(conn)` with the same pattern (SQL given above; verification age buckets computed in SQL as `CASE WHEN ?now - last_verified_time_utc_ms < 30*86400000 THEN ...`). Wire `Cmd::Status` and `Cmd::Report { Risk, Verification }` in `src/main.rs`, printing the returned string.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: all tests pass, including cli_report.

- [ ] **Step 5: Full-suite gate and commit**

Run: `cargo test && cargo build --release`
Expected: everything green; release binary builds.

```bash
git add src/report.rs src/lib.rs src/main.rs tests/cli_report.rs
git commit -m "feat: status, risk, and verification reports"
```

---

## MVP 1 Acceptance Walkthrough (manual, after all tasks)

Against a real git-annex repo (read-only; run from any scratch directory):

```bash
mkdir ~/archive-catalog && cd ~/archive-catalog
archive init --archive-id arch_main --name "Main Archive"
archive register site site_home --name Home --kind home
archive register collection photos --name Photos
archive register risk-domain risk_home_fire --name "Home fire" --kind fire
archive risk assign risk_home_fire --entity-type site --entity-id site_home
archive register device dev_primary_pc --name "Primary PC" --kind pc --site site_home
archive config set host_device_id dev_primary_pc
archive register archive-root root_home_data --device dev_primary_pc \
  --name "Home data" --path /home/<user>/data
archive annex import --repo /home/<user>/data/photos --collection photos \
  --device dev_primary_pc --archive-root root_home_data
archive status
archive report risk
archive report verification
archive events verify
archive checkpoint
archive db rebuild && archive status   # state identical after full replay
```

Expected: import reports match repo contents; `.git/annex/objects` mtimes unchanged (read-only promise); `events verify` passes; the checkpoint git commit contains segments + manifests + checkpoint file; rebuild reproduces identical status output.

## Out of Scope (MVP 2+)

Scanning (`location_scanned` minting beyond import), verification jobs, `job_items` queue/resume, policies evaluation (`policy_status`/`policy_rollup` stay empty), safe copy/repair/drop, quarantine, snapshots (`snapshot_created` never minted in MVP 1), pruning, daemon.







