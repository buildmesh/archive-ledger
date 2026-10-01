#!/usr/bin/env python3
"""Measure disposable, distinct-key annex imports and canonical rebuilds.

Linux /proc measurements cover the CLI process, with separate live process-tree
memory peaks. No git-annex installation or real archive/content is needed. Results
and command logs remain under --work-dir; the caller owns cleanup. Run a release
binary, sequentially, on an otherwise quiet machine for useful comparisons.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import sqlite3
import subprocess
import sys
import time


INTERVAL = 0.1
COMPACT_TABLES = {
    "content_objects", "checksums", "content_checksums", "source_identities",
    "annex_sources", "source_availability", "file_objects", "file_locations",
    "copy_bindings", "checks", "check_errors",
}
LOCAL_METADATA = (
    "projection_generation", "policy_input_generation", "last_verified_checkpoint_id",
    "last_verified_checkpoint_frontier_hash",
)
# Deliberately omitted by schema 7, rather than silently intersecting columns.
RETIRED_COLUMNS = {
    "objects": {"media_type"},
    "external_identities": {"source_detail_json"},
    "file_refs": {"created_time_utc_ms"},
    "copy_claims": {"last_verified_record_id"},
}


def read_text(path):
    try:
        return path.read_text()
    except (OSError, UnicodeError):
        return ""


def counters(path):
    values = {}
    for line in read_text(path).splitlines():
        parts = line.replace(":", "").split()
        if len(parts) >= 2 and parts[1].isdigit():
            values[parts[0]] = int(parts[1])
    return values


def git_commit_ref(canonical):
    """Read this disposable repository's current commit without launching Git."""
    git_dir = canonical / ".git"
    head = read_text(git_dir / "HEAD").strip()
    if not head.startswith("ref: "):
        return head
    ref = head.removeprefix("ref: ")
    loose = read_text(git_dir / ref).strip()
    if loose:
        return loose
    for line in read_text(git_dir / "packed-refs").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == ref:
            return fields[0]
    return ""


def process_sample(pid):
    root = Path("/proc") / str(pid)
    status = counters(root / "status")
    stat = read_text(root / "stat").rpartition(") ")[2].split()
    result = {"rss_kib": status.get("VmRSS", 0), "swap_kib": status.get("VmSwap", 0)}
    if len(stat) > 12:
        result["cpu_seconds"] = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
    for key, value in counters(root / "io").items():
        result[key] = value
    return result


def tree_memory(pid):
    totals = {"rss_kib": 0, "swap_kib": 0, "processes": 0}
    pending = [pid]
    while pending:
        current = pending.pop()
        sample = process_sample(current)
        totals["rss_kib"] += sample["rss_kib"]
        totals["swap_kib"] += sample["swap_kib"]
        totals["processes"] += 1
        children = read_text(Path(f"/proc/{current}/task/{current}/children"))
        pending.extend(int(child) for child in children.split())
    return totals


def connect_readonly(path):
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0)


def batch_progress(path):
    try:
        connection = connect_readonly(path)
        try:
            return connection.execute(
                "SELECT item_count, state FROM batch_runs WHERE operation_kind='annex_import'"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error:
        return None


def spool_finished(path):
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - 65536))
            tail = stream.read()
        if not tail.endswith(b"\n"):
            return False
        return json.loads(tail.splitlines()[-1]).get("kind") == "job_finished"
    except (OSError, ValueError, IndexError):
        return False


def stop_process(process):
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def run_command(command, stage, label, env, timeout, archive=None, rebuild=False):
    print(f"{stage.name}: {label}", file=sys.stderr, flush=True)
    start = time.monotonic()
    result = {"command": [str(arg) for arg in command], "sample_interval_seconds": INTERVAL,
              "samples": [], "progress": [], "boundaries": {}, "root_process_peaks": {},
              "live_process_tree_peaks": {}, "host_vmstat_start": counters(Path("/proc/vmstat"))}
    head = archive / "canonical/frontiers/v2/HEAD" if archive else None
    previous_head = read_text(head) if head else ""
    previous_commit = git_commit_ref(archive / "canonical") if archive else ""
    previous_progress = None
    with (stage / f"{label}.stdout").open("w") as stdout, (stage / f"{label}.stderr").open("w") as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            while process.poll() is None:
                elapsed = time.monotonic() - start
                if elapsed >= timeout:
                    result["timed_out"] = True
                    stop_process(process)
                    break
                if archive:
                    sample = {"seconds": elapsed, "root": process_sample(process.pid),
                              "live_tree": tree_memory(process.pid)}
                    result["samples"].append(sample)
                    for scope, peak_key in [("root", "root_process_peaks"), ("live_tree", "live_process_tree_peaks")]:
                        for key, value in sample[scope].items():
                            result[peak_key][key] = max(value, result[peak_key].get(key, 0))
                    if not rebuild:
                        current_head = read_text(head)
                        current_commit = git_commit_ref(archive / "canonical")
                        boundaries = result["boundaries"]
                        if "spool_ready_seconds" not in boundaries and spool_finished(
                            archive / "local/jobs/job_benchmark/annex-items.jsonl"
                        ):
                            boundaries["spool_ready_seconds"] = elapsed
                            boundaries["head_before_spool_ready"] = previous_head.strip()
                            boundaries["git_commit_before_spool_ready"] = previous_commit
                        if ("spool_ready_seconds" in boundaries and "frontier_written_seconds" not in boundaries
                                and current_head and current_head.strip() != boundaries["head_before_spool_ready"]):
                            boundaries["frontier_written_seconds"] = elapsed
                        if ("spool_ready_seconds" in boundaries and "publication_done_seconds" not in boundaries
                                and current_commit and current_commit != boundaries["git_commit_before_spool_ready"]):
                            boundaries["publication_done_seconds"] = elapsed
                            boundaries["published_git_commit"] = current_commit
                        previous_head = current_head
                        previous_commit = current_commit
                    databases = sorted(archive.glob(".archive-ledger-rebuild-*.db")) if rebuild else [archive / "archive.db"]
                    if databases:
                        progress = batch_progress(databases[0])
                        if progress and progress != previous_progress:
                            result["progress"].append({"seconds": elapsed, "batches": progress})
                            previous_progress = progress
                time.sleep(INTERVAL)
            result["returncode"] = process.wait()
        except BaseException:
            stop_process(process)
            raise
        finally:
            result["seconds"] = time.monotonic() - start
            result["host_vmstat_end"] = counters(Path("/proc/vmstat"))
            (stage / f"{label}.json").write_text(json.dumps(result, indent=2) + "\n")
    if result["returncode"] != 0 or result.get("timed_out"):
        raise RuntimeError(f"{label} failed or timed out; see {stage}/{label}.stderr and .json")
    return result


def database_state(path):
    connection = connect_readonly(path)
    try:
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        counts = {table: connection.execute('SELECT COUNT(*) FROM "' + table.replace('"', '""') + '"').fetchone()[0]
                  for table in tables}
        settings = {key: connection.execute(f"PRAGMA {key}").fetchone()[0]
                    for key in ["journal_mode", "synchronous", "cache_size", "page_size", "page_count", "freelist_count"]}
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        if integrity != [("ok",)] or foreign_keys:
            raise RuntimeError(f"Database integrity failed: {integrity!r}, {foreign_keys[:5]!r}")
        schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
        if schema_version not in (6, 7):
            raise RuntimeError(f"Unsupported benchmark projection schema: {schema_version}")
        integrity_matches = connection.execute(
            "SELECT COUNT(*) FROM checks WHERE integrity=1" if schema_version == 7
            else "SELECT COUNT(*) FROM verification_results WHERE result='ok'"
        ).fetchone()[0]
        return {"counts": counts, "settings_on_observer_connection": settings, "bytes": path.stat().st_size,
                "schema_version": schema_version, "integrity_matches": integrity_matches,
                "integrity_check": "ok", "foreign_key_check": "ok"}
    finally:
        connection.close()


def assert_equivalent_databases(reference, target, *, ignore_local_state=False, allow_schema_change=False):
    """Compare logical row multisets; physical allocation IDs are not canonical facts."""
    expected = database_state(reference)
    actual = database_state(target)
    cross_schema = actual["schema_version"] != expected["schema_version"]
    if cross_schema:
        assert allow_schema_change, "Different schemas require --compare-baseline-core-facts"
        assert {actual["schema_version"], expected["schema_version"]} == {6, 7}, "Unsupported schema comparison"
    excluded = set(COMPACT_TABLES)
    if ignore_local_state or cross_schema:
        excluded.update(("jobs", "job_items"))
    if cross_schema:
        excluded.update(("verification_results", "file_checks"))
    tables = sorted(set(actual["counts"]) - excluded)
    assert set(tables) == set(expected["counts"]) - excluded, "Logical model names differ"
    assert all(actual["counts"][table] == expected["counts"][table] for table in tables), "Table counts differ"
    assert actual["integrity_matches"] == expected["integrity_matches"], "Successful integrity-check counts differ"
    connection = connect_readonly(target)
    try:
        connection.execute("ATTACH DATABASE ? AS reference", (reference.as_uri() + "?mode=ro",))
        schema = "SELECT type, name, tbl_name, sql FROM {}.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        if not cross_schema:
            assert connection.execute(schema.format("main")).fetchall() == connection.execute(schema.format("reference")).fetchall(), "Schema differs"
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            ignored_columns = {"id"} if table in ("records", "collections", "locations") else set()
            if table in ("path_observations", "file_checks"):
                ignored_columns.update(("id", "rowid"))
            if cross_schema:
                ignored_columns.update(RETIRED_COLUMNS.get(table, ()))
            columns = {}
            for database in ("main", "reference"):
                columns[database] = [row[1] for row in connection.execute(f"PRAGMA {database}.table_info({quoted})")
                                     if row[1] not in ignored_columns]
            assert columns["main"] == columns["reference"], (table, "Logical columns differ")
            selected = ",".join(
                "CASE WHEN claim_basis='source_metadata' THEN NULL ELSE last_seen_time_utc_ms END"
                if cross_schema and table == "copy_claims" and name == "last_seen_time_utc_ms"
                else '"' + name.replace('"', '""') + '"'
                for name in columns["main"])
            # Schema 6 dated an unchecked inventory claim. Schema 7 deliberately
            # leaves physical presence freshness unknown until an actual check.
            ignored_metadata = list(LOCAL_METADATA) if ignore_local_state or cross_schema else []
            if cross_schema:
                ignored_metadata.append("schema_version")
            where = " WHERE key NOT IN (" + ",".join("'" + key + "'" for key in ignored_metadata) + ")" if table == "archive_meta" and ignored_metadata else ""
            # GROUP BY preserves duplicate multiplicities in semantic check history.
            query = f"SELECT {selected},COUNT(*) FROM {{}}.{quoted}{where} GROUP BY {selected}"
            for left, right in [("main", "reference"), ("reference", "main")]:
                assert connection.execute(query.format(left) + " EXCEPT " + query.format(right) + " LIMIT 1").fetchone() is None, (table, left)
    finally:
        connection.close()
    return "cross_schema_retained_facts" if cross_schema else "same_schema_logical_rows_and_schema"


def fixture(stage, size, env, timeout, full_content=False):
    repo = stage / "annex-repo"
    repo.mkdir()
    for index, args in enumerate([["init", "-b", "main"], ["config", "user.name", "Benchmark"],
                                  ["config", "user.email", "benchmark@example.invalid"],
                                  ["config", "annex.uuid", "benchmark-annex-fixture"],
                                  # Keep fixture creation from spawning background
                                  # packing that competes with the measured CLI.
                                  ["config", "gc.auto", "0"],
                                  ["config", "maintenance.auto", "false"]]):
        run_command(["git", "-C", repo, *args], stage, f"git-setup-{index}", env, timeout)
    for index in range(size):
        directory = repo / f"files-{index // 1000:04}"
        if index % 1000 == 0:
            directory.mkdir()
        content = f"benchmark-{index}".encode().ljust(1024, b"\0")
        digest = hashlib.sha256(content if full_content else f"benchmark-{index}".encode()).hexdigest()
        key = f"SHA256E-s1024--{digest}.dat"
        if full_content:
            object_path = repo / ".git/annex/objects/aa/bb" / key / key
            object_path.parent.mkdir(parents=True)
            object_path.write_bytes(content)
        (directory / f"file-{index:08}.dat").symlink_to(f"../.git/annex/objects/aa/bb/{key}/{key}")
    for label, args in [("git-add", ["add", "."]), ("git-commit", ["commit", "-m", "Disposable annex fixture"])]:
        run_command(["git", "-C", repo, *args], stage, label, env, timeout)
    return repo


def benchmark(args, size):
    stage = args.work_dir / f"annex-{size}"
    stage.mkdir()  # Exclusive: never reuse or overwrite an existing workload.
    print(f"{stage.name}: creating {size} disposable annex references", file=sys.stderr, flush=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith("ARCHIVE_")}
    env.update(XDG_DATA_HOME=str(stage / "data"), XDG_CONFIG_HOME=str(stage / "config"),
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    start = time.monotonic()
    repo = fixture(stage, size, env, args.timeout, args.full_content)
    fixture_seconds = time.monotonic() - start
    run_command([args.binary, "init", "Benchmark", "--archive-id", "arc_benchmark", "--non-interactive"],
                stage, "archive-init", env, args.timeout)
    archive = stage / "data/archive-ledger/archives/arc_benchmark"
    import_command = [args.binary, "--json", "collection", "init", repo, "--name", "Files",
                            "--device", "Fixture", "--site", "Fixture", "--allow-unidentified-root",
                            "--non-interactive", "--import-annex", "--job-id", "job_benchmark"]
    if not args.full_content:
        import_command.append("--inventory-only")
    imported = run_command(import_command,
                           stage, "import", env, args.timeout, archive)
    before = database_state(archive / "archive.db")
    assert before["counts"]["external_identities"] == size, before["counts"]
    assert before["counts"]["file_refs"] == size, before["counts"]
    assert before["counts"]["objects"] == before["integrity_matches"] == (size if args.full_content else 0), before
    if before["schema_version"] == 7:
        assert before["counts"]["checks"] == (size if args.full_content else 0), before["counts"]
    # A SQLite backup also handles a future WAL import without losing sidecars.
    reference = stage / "before-rebuild.db"
    source_connection = connect_readonly(archive / "archive.db")
    destination = sqlite3.connect(reference)
    try:
        source_connection.backup(destination)
    finally:
        destination.close()
        source_connection.close()
    canonical_head = git_commit_ref(archive / "canonical")
    baseline = None
    baseline_comparison = None
    if args.baseline_binary:
        baseline_target = stage / "baseline.db"
        baseline = run_command([args.baseline_binary, "--json", "--database", reference,
                                "--events", archive / "canonical", "db", "rebuild", "--target", baseline_target],
                               stage, "baseline-rebuild", env, args.timeout, stage, True)
        baseline_comparison = assert_equivalent_databases(
            reference, baseline_target, ignore_local_state=True, allow_schema_change=args.compare_baseline_core_facts)
    rebuilt = run_command([args.binary, "--json", "db", "rebuild"], stage, "rebuild", env, args.timeout, archive, True)
    after = database_state(archive / "archive.db")
    assert_equivalent_databases(reference, archive / "archive.db", ignore_local_state=True)
    if baseline:
        assert_equivalent_databases(baseline_target, archive / "archive.db",
                                    allow_schema_change=args.compare_baseline_core_facts)
    assert git_commit_ref(archive / "canonical") == canonical_head, "Rebuild changed canonical HEAD"
    run_command([args.binary, "--json", "fsck"], stage, "fsck", env, args.timeout)
    boundaries = imported["boundaries"]
    phases = {"preparation_and_spooling_seconds": boundaries.get("spool_ready_seconds")}
    if "publication_done_seconds" in boundaries:
        phases["publication_seconds"] = boundaries["publication_done_seconds"] - boundaries["spool_ready_seconds"]
        phases["projection_and_finalization_seconds"] = imported["seconds"] - boundaries["publication_done_seconds"]
    result = {"size": size, "full_content": args.full_content, "stage": str(stage), "fixture_seconds": fixture_seconds,
              "import_seconds": imported["seconds"], "rebuild_seconds": rebuilt["seconds"], "approximate_import_phases": phases,
              "baseline_rebuild_seconds": baseline["seconds"] if baseline else None,
              "baseline_rebuild_peaks": baseline["root_process_peaks"] if baseline else None,
              "logical_rows_and_schema_equal": True,
              "ignored_live_tables": ["jobs", "job_items"],
              "ignored_live_metadata_keys": ["projection_generation", "policy_input_generation",
                                             "last_verified_checkpoint_id", "last_verified_checkpoint_frontier_hash"],
              "baseline_comparison": baseline_comparison, "canonical_head_unchanged": True,
              "measurement_notes": ["Phase boundaries are observed at 100 ms intervals, include scheduling delay, and may be missed.",
                                    "Spool-ready observes complete final JSONL, before fsync completion; frontier-written precedes final verification and Git commit.",
                                    "Publication-done observes the canonical Git commit ref advance; Git command finalization may overlap the next phase estimate.",
                                    "CPU and IO counters cover the root CLI only; tree peaks sum currently live processes, not reaped children.",
                                    "Observer connection cache_size and synchronous may differ from application connection settings.",
                                    "Schema-7 equality compares logical views, semantic file_checks (including duplicate counts), and control tables without local integer IDs; physical integrity/FKs are checked separately.",
                                    "Cross-schema baseline mode compares retained logical facts and successful-check counts, not physical schemas or historical verification/check rows; omitted columns are explicitly listed in RETIRED_COLUMNS, and unchecked source-metadata presence dates are normalized to NULL.",
                                    "Rebuild follows import on a warm filesystem cache; host VM counters include unrelated processes."],
              "before_rebuild": before, "after_rebuild": after,
              "canonical_bytes": sum(path.stat().st_size for path in (archive / "canonical").rglob("*") if path.is_file()),
              "root_process_peaks": {"import": imported["root_process_peaks"], "rebuild": rebuilt["root_process_peaks"]},
              "live_process_tree_peaks": {"import": imported["live_process_tree_peaks"], "rebuild": rebuilt["live_process_tree_peaks"]}}
    (stage / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


def compare_cache(args):
    """Compare isolated replay variants; never change the source archive."""
    size = args.compare_cache_at
    source_stage = args.work_dir / f"annex-{size}"
    source = source_stage / "data/archive-ledger/archives/arc_benchmark/canonical"
    expected = json.loads((source_stage / "result.json").read_text())["after_rebuild"]["counts"]
    source_tip = git_commit_ref(source)
    if not source_tip or expected["external_identities"] != size:
        raise RuntimeError("Expected completed benchmark artifacts with the requested distinct-key count")
    work = args.work_dir / f"cache-{size}"
    work.mkdir()  # Refuse reuse: every variant starts from the same pristine base.
    canonical = work / "canonical"
    env = {key: value for key, value in os.environ.items() if not key.startswith("ARCHIVE_")}
    env.update(XDG_DATA_HOME=str(work / "data"), XDG_CONFIG_HOME=str(work / "config"),
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    run_command(["git", "clone", "--quiet", "--no-hardlinks", "--", source, canonical],
                work, "clone", env, args.timeout)
    if git_commit_ref(canonical) != source_tip:
        raise RuntimeError("Cloned canonical HEAD differs from source")
    run_command(["git", "-C", canonical, "checkout", "--quiet", "--detach", "HEAD^"],
                work, "checkout-base", env, args.timeout)
    base = work / "base.db"
    run_command([args.binary, "--json", "--database", base, "--events", canonical, "db", "rebuild"],
                work, "base-rebuild", env, args.timeout)
    base_state = database_state(base)
    run_command(["git", "-C", canonical, "checkout", "--quiet", "--detach", source_tip],
                work, "checkout-tip", env, args.timeout)
    results = []
    for label, cache_pages, journal in [
        ("default", None, "delete"), ("cache64", 16384, "delete"),
        ("wal2", None, "wal"), ("wal64", 16384, "wal"), ("default-repeat", None, "delete")
    ]:
        stage = work / label
        stage.mkdir()
        database = stage / "archive.db"
        shutil.copyfile(base, database)
        connection = sqlite3.connect(database)
        try:
            if connection.execute(f"PRAGMA journal_mode={journal}").fetchone()[0] != journal:
                raise RuntimeError(f"Could not set {journal} journal mode")
            connection.execute("PRAGMA synchronous=FULL")
            if cache_pages is not None:
                # Diagnostic only: this deprecated setting persists in this
                # disposable DB, so fresh CLI connections inherit the cache size.
                connection.execute(f"PRAGMA default_cache_size={cache_pages}")
        finally:
            connection.close()
        before = database_state(database)
        settings = before["settings_on_observer_connection"]
        if before["counts"] != base_state["counts"] or settings["synchronous"] != 2:
            raise RuntimeError("Variant differs from baseline rows or FULL synchronization")
        if cache_pages is not None and (settings["cache_size"] != cache_pages or settings["page_size"] != 4096):
            raise RuntimeError("Expected 16384 cache pages of 4096 bytes (64 MiB)")
        applied = run_command([args.binary, "--json", "--database", database, "--events", canonical, "db", "apply"],
                              stage, "apply", env, args.timeout, stage)
        after = database_state(database)
        if after["counts"] != expected:
            raise RuntimeError(f"{label} replay table counts differ from original full rebuild")
        assert_equivalent_databases(source.parent / "archive.db", database, ignore_local_state=True)
        if git_commit_ref(canonical) != source_tip or git_commit_ref(source) != source_tip:
            raise RuntimeError("Canonical HEAD changed during replay")
        result = {"size": size, "label": label, "stage": str(stage), "settings": settings,
                  "seconds": applied["seconds"], "before_apply": before, "after_apply": after,
                  "canonical_head": source_tip, "root_process_peaks": applied["root_process_peaks"],
                  "live_process_tree_peaks": applied["live_process_tree_peaks"],
                  "measurement_notes": [
                      "Each variant applies the same import onto a copy of the projection rebuilt at HEAD^.",
                      "default_cache_size is a deprecated persistent diagnostic technique, not a production configuration recommendation.",
                      "An explicit application cache_size overrides default_cache_size; current replay uses 64 MiB, so these variants do not vary its effective cache.",
                      "All observer connections retain default FULL synchronous=2; synchronous is connection-local, not a persistent DB setting.",
                      "Fresh application connections use their normal synchronization policy; this experiment does not weaken durability.",
                      "Sequential warm-cache measurements include a final default repeat to expose order-related timing variation."]}
        results.append(result)
        (work / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Absolute path to a built archive CLI")
    parser.add_argument("--baseline-binary", type=Path,
                        help="Optional original CLI to time rebuilding the same canonical history")
    parser.add_argument("--compare-baseline-core-facts", action="store_true",
                        help="Allow schema 6/7 baseline comparison of retained logical facts, excluding changed check history")
    parser.add_argument("--work-dir", type=Path, required=True, help="Existing, task-owned disposable staging directory")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sizes", type=int, nargs="+", default=[5000, 10000, 25000, 50000])
    mode.add_argument("--compare-cache-at", type=int, metavar="N",
                      help="Compare replay cache/journal variants using existing work-dir/annex-N artifacts")
    parser.add_argument("--timeout", type=float, default=600, help="Timeout seconds per command")
    parser.add_argument("--full-content", action="store_true",
                        help="Create valid 1024-byte annex contents and verify them during collection init")
    args = parser.parse_args()
    if not args.binary.is_absolute() or not args.binary.is_file():
        parser.error("--binary must be an absolute path to an existing executable")
    if args.baseline_binary and (not args.baseline_binary.is_absolute() or not args.baseline_binary.is_file()):
        parser.error("--baseline-binary must be an absolute path to an existing executable")
    if args.compare_baseline_core_facts and not args.baseline_binary:
        parser.error("--compare-baseline-core-facts requires --baseline-binary")
    args.work_dir = args.work_dir.resolve(strict=True)
    if not args.work_dir.is_dir() or args.timeout <= 0 or any(size <= 0 for size in args.sizes):
        parser.error("work directory must exist, and sizes/timeout must be positive")
    if len(set(args.sizes)) != len(args.sizes):
        parser.error("sizes must be distinct")
    if args.compare_cache_at is not None:
        if args.compare_cache_at <= 0:
            parser.error("--compare-cache-at must be positive")
        compare_cache(args)
        return
    for size in args.sizes:
        benchmark(args, size)


if __name__ == "__main__":
    main()
