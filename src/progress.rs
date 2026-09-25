//! Ephemeral job progress for annex imports and Location scans. No display
//! state is persisted as archive evidence.

use std::io::{self, IsTerminal, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::annex::AnnexSummary;
use crate::v2_inventory::V2InventorySummary;
use crate::v2_projection::V2ApplyProgress;
use crate::v2_store::V2AppendProgress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressKind {
    AnnexImport,
    LocationScan,
}

#[derive(Clone)]
pub struct Progress {
    state: Arc<Mutex<ProgressState>>,
}

#[derive(Clone)]
struct ProgressState {
    phase: &'static str,
    inspected: u64,
    count: Option<(&'static str, u64, u64)>,
    counters: Counters,
    bytes_read: u64,
}

#[derive(Clone)]
enum Counters {
    Annex(AnnexSummary),
    Scan(V2InventorySummary),
}

impl Progress {
    fn new(kind: ProgressKind) -> Self {
        let counters = match kind {
            ProgressKind::AnnexImport => Counters::Annex(AnnexSummary::default()),
            ProgressKind::LocationScan => Counters::Scan(V2InventorySummary::default()),
        };
        Self {
            state: Arc::new(Mutex::new(ProgressState {
                phase: "",
                inspected: 0,
                count: None,
                counters,
                bytes_read: 0,
            })),
        }
    }

    pub fn phase(&self, phase: &'static str) {
        let mut state = self.state.lock().unwrap();
        state.phase = phase;
        state.inspected = 0;
        state.count = None;
    }

    fn continue_phase(&self, phase: &'static str) {
        self.state.lock().unwrap().phase = phase;
    }

    fn counted_phase(&self, phase: &'static str, label: &'static str, done: u64, total: u64) {
        let mut state = self.state.lock().unwrap();
        state.phase = phase;
        state.inspected = 0;
        state.count = Some((label, done, total));
    }

    pub(crate) fn append_progress(&self, update: V2AppendProgress) {
        match update {
            V2AppendProgress::Verifying => self.phase("Verifying existing catalog events"),
            V2AppendProgress::ReadingSpool {
                bytes_read,
                total_bytes,
            } => {
                self.counted_phase(
                    "Saving catalog events",
                    "spool bytes read",
                    bytes_read,
                    total_bytes,
                );
            }
            V2AppendProgress::Publishing => self.continue_phase("Finalizing catalog events"),
        }
    }

    pub(crate) fn apply_progress(&self, update: V2ApplyProgress) {
        match update {
            V2ApplyProgress::Verifying => self.phase("Verifying catalog events"),
            V2ApplyProgress::Applying {
                records_applied,
                total_records,
            } => {
                // Each segment is verified before replay; gaps between these
                // updates can therefore still be verification work.
                self.counted_phase(
                    "Verifying and updating catalog index",
                    "records replayed this pass",
                    records_applied,
                    total_records,
                );
            }
            V2ApplyProgress::Finalizing => self.continue_phase("Finalizing catalog index"),
        }
    }

    pub fn inspected_entry(&self) {
        self.state.lock().unwrap().inspected += 1;
    }

    pub fn summary(&self, summary: &AnnexSummary) {
        self.state.lock().unwrap().counters = Counters::Annex(summary.clone());
    }

    pub(crate) fn scan_summary(&self, summary: &V2InventorySummary) {
        self.state.lock().unwrap().counters = Counters::Scan(summary.clone());
    }

    pub fn read_bytes(&self, count: usize) {
        let mut state = self.state.lock().unwrap();
        state.bytes_read = state.bytes_read.saturating_add(count as u64);
    }

    fn snapshot(&self, elapsed: Duration) -> Snapshot {
        let state = self.state.lock().unwrap().clone();
        let count = match state.count {
            Some((label, done, total)) => format!("{done} / {total} {label}"),
            None if state.inspected > 0 => format!("{} inspected", state.inspected),
            None => String::new(),
        };
        let (title, counters) = match &state.counters {
            Counters::Annex(summary) => (
                "Annex import",
                [
                    vec![
                        format!("{} entries", summary.entries_seen),
                        format!("{} verified", summary.present),
                        format!("{} absent", summary.absent),
                    ],
                    vec![
                        format!("{} unchecked", summary.unchecked),
                        format!(
                            "{} skipped links + {} other",
                            summary.ignored_symlinks,
                            summary
                                .ignored_non_annex
                                .saturating_sub(summary.ignored_symlinks)
                        ),
                        format!("{} errors", summary.mismatched + summary.read_errors),
                    ],
                    vec![format!("{} read this run", gib(state.bytes_read))],
                ],
            ),
            // No total is known during a walk, so show counts and elapsed time
            // rather than a percentage. Counts include work resumed from a checkpoint.
            Counters::Scan(summary) => (
                "Location scan",
                [
                    vec![
                        format!("{} files", summary.files_observed),
                        format!("{} observed", gib(summary.bytes_observed)),
                        // Moves during a long single-file hash, when file counts cannot.
                        format!("{} read this run", gib(state.bytes_read)),
                    ],
                    vec![
                        format!("{} new", summary.new_paths),
                        format!("{} changed", summary.changed_paths),
                        format!("{} confirmed good", summary.confirmed_good),
                    ],
                    vec![
                        format!("{} integrity mismatches", summary.integrity_mismatches),
                        format!(
                            "{} read errors",
                            summary.read_errors + summary.concurrent_changes
                        ),
                    ],
                ],
            ),
        };
        let [first, second, third] = counters;
        Snapshot {
            heading: format!("{title}: {}", state.phase),
            elapsed: format!("{}s", elapsed.as_secs()),
            rows: [vec![count], first, second, third],
        }
    }
}

fn gib(bytes: u64) -> String {
    format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// A heading plus four display rows, each a list of `|`-separated fields.
struct Snapshot {
    heading: String,
    elapsed: String,
    rows: [Vec<String>; 4],
}

/// A heartbeat continues even while Git, a content read, or catalog publication blocks.
/// Dropping it stops the thread immediately and leaves a final, newline-ended status.
pub struct ProgressReporter {
    progress: Progress,
    stop: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
    finished: bool,
}

impl ProgressReporter {
    /// Terminals get a redrawn status block; redirected stderr gets a periodic log line.
    pub fn start(kind: ProgressKind) -> io::Result<Self> {
        let terminal = io::stderr().is_terminal();
        Self::with_writer(
            kind,
            io::stderr(),
            terminal,
            Duration::from_secs(if terminal { 1 } else { 30 }),
        )
    }

    fn with_writer(
        kind: ProgressKind,
        mut writer: impl Write + Send + 'static,
        terminal: bool,
        interval: Duration,
    ) -> io::Result<Self> {
        let progress = Progress::new(kind);
        progress.phase("Preparing");
        let start = Instant::now();
        let mut rendered = false;
        render(
            &mut writer,
            &progress.snapshot(start.elapsed()),
            terminal,
            false,
            &mut rendered,
        );
        let (stop, receiver) = mpsc::channel();
        let display = progress.clone();
        let worker = thread::Builder::new()
            .name("job-progress".to_owned())
            .spawn(move || loop {
                let finished =
                    receiver.recv_timeout(interval) != Err(mpsc::RecvTimeoutError::Timeout);
                render(
                    &mut writer,
                    &display.snapshot(start.elapsed()),
                    terminal,
                    finished,
                    &mut rendered,
                );
                if finished {
                    break;
                }
            })?;
        Ok(Self {
            progress,
            stop,
            worker: Some(worker),
            finished: false,
        })
    }

    pub fn progress(&self) -> &Progress {
        &self.progress
    }

    pub fn finish(mut self, phase: &'static str) {
        self.progress.continue_phase(phase);
        self.finished = true;
    }
}

impl Drop for ProgressReporter {
    fn drop(&mut self) {
        if !self.finished {
            self.progress.continue_phase("Stopped before completion");
        }
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn render(
    writer: &mut impl Write,
    snapshot: &Snapshot,
    terminal: bool,
    finished: bool,
    rendered: &mut bool,
) {
    // Keep a compact five-line display on terminals instead of repeatedly wrapping
    // a long status line. Redirected logs get plain, newline-delimited snapshots.
    // Display failures must not fail or interrupt an otherwise valid job.
    let joined = |values: &[String]| {
        values
            .iter()
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(" | ")
    };
    if terminal {
        if *rendered {
            let _ = write!(writer, "\x1b[4A");
        }
        let _ = write!(
            writer,
            "\r\x1b[2K{} | {}",
            snapshot.heading, snapshot.elapsed
        );
        for row in &snapshot.rows {
            let _ = write!(writer, "\n\r\x1b[2K{}", joined(row));
        }
        if finished {
            let _ = writeln!(writer);
        }
    } else {
        let mut fields = vec![snapshot.heading.clone()];
        fields.extend(snapshot.rows.iter().flatten().cloned());
        fields.push(snapshot.elapsed.clone());
        let _ = writeln!(writer, "{}", joined(&fields));
    }
    *rendered = true;
    let _ = writer.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn publication_counters_use_phase_units_and_survive_finalization() {
        let progress = Progress::new(ProgressKind::AnnexImport);
        progress.phase("Rechecking source metadata");
        progress.inspected_entry();
        progress.summary(&AnnexSummary {
            entries_seen: 12,
            unchecked: 12,
            ..Default::default()
        });
        progress.append_progress(V2AppendProgress::Verifying);
        assert!(progress.snapshot(Duration::ZERO).rows[0][0].is_empty());
        progress.append_progress(V2AppendProgress::ReadingSpool {
            bytes_read: 256,
            total_bytes: 512,
        });
        let snapshot = progress.snapshot(Duration::ZERO);
        assert_eq!(snapshot.rows[0][0], "256 / 512 spool bytes read");
        assert_eq!(snapshot.rows[1][0], "12 entries");
        progress.append_progress(V2AppendProgress::ReadingSpool {
            bytes_read: 512,
            total_bytes: 512,
        });
        progress.append_progress(V2AppendProgress::Publishing);
        assert_eq!(
            progress.snapshot(Duration::ZERO).heading,
            "Annex import: Finalizing catalog events"
        );
        assert_eq!(
            progress.snapshot(Duration::ZERO).rows[0][0],
            "512 / 512 spool bytes read"
        );
        progress.apply_progress(V2ApplyProgress::Verifying);
        assert!(progress.snapshot(Duration::ZERO).rows[0][0].is_empty());
        progress.apply_progress(V2ApplyProgress::Applying {
            records_applied: 2,
            total_records: 5,
        });
        assert_eq!(
            progress.snapshot(Duration::ZERO).rows[0][0],
            "2 / 5 records replayed this pass"
        );
        progress.apply_progress(V2ApplyProgress::Applying {
            records_applied: 5,
            total_records: 5,
        });
        progress.apply_progress(V2ApplyProgress::Finalizing);
        assert_eq!(
            progress.snapshot(Duration::ZERO).heading,
            "Annex import: Finalizing catalog index"
        );
        assert_eq!(
            progress.snapshot(Duration::ZERO).rows[0][0],
            "5 / 5 records replayed this pass"
        );
        progress.continue_phase("Stopped before completion");
        let mut log = Vec::new();
        render(
            &mut log,
            &progress.snapshot(Duration::ZERO),
            false,
            true,
            &mut false,
        );
        let log = String::from_utf8(log).unwrap();
        assert!(log.contains("Stopped before completion | 5 / 5 records replayed this pass"));
        assert!(!log.contains("inspected"));
    }

    #[test]
    fn scan_counters_render_without_a_percentage_and_fit_80_columns() {
        let progress = Progress::new(ProgressKind::LocationScan);
        progress.phase("Scanning files");
        progress.scan_summary(&V2InventorySummary {
            files_observed: 1_234_567,
            bytes_observed: 3 * 1024 * 1024 * 1024,
            new_paths: 1_000_000,
            changed_paths: 12,
            confirmed_good: 234_555,
            integrity_mismatches: 1,
            read_errors: 2,
            concurrent_changes: 1,
            ..Default::default()
        });
        progress.read_bytes(1536 * 1024 * 1024);
        let snapshot = progress.snapshot(Duration::from_secs(7));
        assert_eq!(snapshot.heading, "Location scan: Scanning files");
        let mut output = Vec::new();
        render(&mut output, &snapshot, true, true, &mut false);
        let text = String::from_utf8(output).unwrap();
        let rows: Vec<_> = text
            .lines()
            .map(|row| row.trim_start_matches("\r\x1b[2K"))
            .collect();
        assert_eq!(
            rows,
            [
                "Location scan: Scanning files | 7s",
                "",
                "1234567 files | 3.00 GiB observed | 1.50 GiB read this run",
                "1000000 new | 12 changed | 234555 confirmed good",
                "1 integrity mismatches | 3 read errors",
            ]
        );
        assert!(rows.iter().all(|row| row.len() <= 80));
        assert!(!text.contains('%'));

        progress.append_progress(V2AppendProgress::ReadingSpool {
            bytes_read: 10,
            total_bytes: 20,
        });
        let mut log = Vec::new();
        render(
            &mut log,
            &progress.snapshot(Duration::from_secs(8)),
            false,
            false,
            &mut false,
        );
        assert_eq!(
            String::from_utf8(log).unwrap(),
            "Location scan: Saving catalog events | 10 / 20 spool bytes read | 1234567 files | 3.00 GiB observed | 1.50 GiB read this run | 1000000 new | 12 changed | 234555 confirmed good | 1 integrity mismatches | 3 read errors | 8s\n"
        );
    }

    #[test]
    fn heartbeat_reports_idle_phase_and_bytes_without_polluting_log_output() {
        let capture = Capture::default();
        let reporter = ProgressReporter::with_writer(
            ProgressKind::AnnexImport,
            capture.clone(),
            false,
            Duration::from_millis(5),
        )
        .unwrap();
        reporter.progress().phase("Reading content");
        reporter.progress().read_bytes(1024 * 1024 * 1024);
        reporter.progress().summary(&AnnexSummary {
            entries_seen: 9,
            present: 2,
            ignored_non_annex: 6,
            ignored_symlinks: 5,
            ..AnnexSummary::default()
        });
        // Wait for an actual heartbeat, not a timing-sensitive fixed sleep assertion.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if String::from_utf8_lossy(&capture.0.lock().unwrap()).contains("Reading content") {
                break;
            }
            assert!(Instant::now() < deadline, "heartbeat did not arrive");
            thread::sleep(Duration::from_millis(5));
        }
        reporter.finish("Complete");
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("Preparing"));
        assert!(text.contains("9 entries | 2 verified"));
        assert!(text.contains("5 skipped links + 1 other"));
        assert!(text.contains("1.00 GiB read this run"));
        assert!(text.lines().last().unwrap().contains("Complete"));
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\r'));
    }

    #[test]
    fn terminal_counter_layout_fits_80_columns_and_redraws_all_rows() {
        let progress = Progress::new(ProgressKind::AnnexImport);
        progress.summary(&AnnexSummary {
            entries_seen: 800_000,
            present: 800_000,
            ..Default::default()
        });
        progress.apply_progress(V2ApplyProgress::Applying {
            records_applied: 800,
            total_records: 802,
        });
        let mut output = Vec::new();
        let mut rendered = false;
        render(
            &mut output,
            &progress.snapshot(Duration::ZERO),
            true,
            false,
            &mut rendered,
        );
        let text = String::from_utf8(output.clone()).unwrap();
        let rows: Vec<_> = text.split('\n').collect();
        assert!(
            rows.iter()
                .all(|row| row.trim_start_matches("\r\x1b[2K").len() <= 80),
            "{text:?}"
        );
        assert_eq!(rows.len(), 5);
        assert!(rows[1].ends_with("800 / 802 records replayed this pass"));
        assert!(rows[2].contains("800000 entries"));

        output.clear();
        progress.phase("Verifying catalog events");
        render(
            &mut output,
            &progress.snapshot(Duration::ZERO),
            true,
            true,
            &mut rendered,
        );
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("\x1b[4A"));
        assert_eq!(text.matches("\r\x1b[2K").count(), 5);
        assert!(text.lines().nth(1).unwrap().ends_with("\x1b[2K"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn terminal_reporter_cleans_up_on_error_without_claiming_completion() {
        let capture = Capture::default();
        let reporter = ProgressReporter::with_writer(
            ProgressKind::AnnexImport,
            capture.clone(),
            true,
            Duration::from_secs(30),
        )
        .unwrap();
        drop(reporter);
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(text.starts_with("\r\x1b[2K"));
        assert!(text.contains("Stopped before completion"));
        assert!(text.ends_with('\n'));
    }
}
