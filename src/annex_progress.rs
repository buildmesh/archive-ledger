//! Ephemeral annex-import progress. No display state is persisted as archive evidence.

use std::io::{self, IsTerminal, Write};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::annex::AnnexSummary;

#[derive(Clone, Default)]
pub struct AnnexProgress {
    state: Arc<Mutex<ProgressState>>,
}

#[derive(Clone, Default)]
struct ProgressState {
    phase: &'static str,
    inspected: u64,
    summary: AnnexSummary,
    bytes_read: u64,
}

impl AnnexProgress {
    pub fn phase(&self, phase: &'static str) {
        let mut state = self.state.lock().unwrap();
        state.phase = phase;
        state.inspected = 0;
    }

    pub fn inspected_entry(&self) {
        self.state.lock().unwrap().inspected += 1;
    }

    pub fn summary(&self, summary: &AnnexSummary) {
        self.state.lock().unwrap().summary = summary.clone();
    }

    pub fn read_bytes(&self, count: usize) {
        let mut state = self.state.lock().unwrap();
        state.bytes_read = state.bytes_read.saturating_add(count as u64);
    }

    fn fields(&self, elapsed: Duration) -> [String; 10] {
        let state = self.state.lock().unwrap().clone();
        let summary = &state.summary;
        [
            format!("Annex import: {}", state.phase),
            format!("{} inspected", state.inspected),
            format!("{} entries", summary.entries_seen),
            format!("{} verified", summary.present),
            format!("{} absent", summary.absent),
            format!("{} unchecked", summary.unchecked),
            format!(
                "{} skipped links + {} other",
                summary.ignored_symlinks,
                summary
                    .ignored_non_annex
                    .saturating_sub(summary.ignored_symlinks)
            ),
            format!("{} errors", summary.mismatched + summary.read_errors),
            format!(
                "{:.2} GiB read this run",
                state.bytes_read as f64 / (1024.0 * 1024.0 * 1024.0)
            ),
            format!("{}s", elapsed.as_secs()),
        ]
    }
}

/// A heartbeat continues even while Git, a content read, or catalog publication blocks.
/// Dropping it stops the thread immediately and leaves a final, newline-ended status.
pub struct AnnexProgressReporter {
    progress: AnnexProgress,
    stop: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
    finished: bool,
}

impl AnnexProgressReporter {
    pub fn start() -> io::Result<Self> {
        let terminal = io::stderr().is_terminal();
        Self::with_writer(
            io::stderr(),
            terminal,
            Duration::from_secs(if terminal { 1 } else { 30 }),
        )
    }

    fn with_writer(
        mut writer: impl Write + Send + 'static,
        terminal: bool,
        interval: Duration,
    ) -> io::Result<Self> {
        let progress = AnnexProgress::default();
        progress.phase("Preparing");
        let start = Instant::now();
        let mut rendered = false;
        render(
            &mut writer,
            &progress.fields(start.elapsed()),
            terminal,
            false,
            &mut rendered,
        );
        let (stop, receiver) = mpsc::channel();
        let display = progress.clone();
        let worker = thread::Builder::new()
            .name("annex-progress".to_owned())
            .spawn(move || loop {
                let finished =
                    receiver.recv_timeout(interval) != Err(mpsc::RecvTimeoutError::Timeout);
                render(
                    &mut writer,
                    &display.fields(start.elapsed()),
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

    pub fn progress(&self) -> &AnnexProgress {
        &self.progress
    }

    pub fn finish(mut self, phase: &'static str) {
        self.progress.phase(phase);
        self.finished = true;
    }
}

impl Drop for AnnexProgressReporter {
    fn drop(&mut self) {
        if !self.finished {
            self.progress.phase("Stopped before completion");
        }
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn render(
    writer: &mut impl Write,
    fields: &[String; 10],
    terminal: bool,
    finished: bool,
    rendered: &mut bool,
) {
    // Keep a compact four-line display on terminals instead of repeatedly wrapping
    // a long status line. Redirected logs get plain, newline-delimited snapshots.
    // Display failures must not fail or interrupt an otherwise valid import.
    if terminal {
        if *rendered {
            let _ = write!(writer, "\x1b[3A");
        }
        let _ = write!(writer, "\r\x1b[2K{} | {}\n", fields[0], fields[9]);
        let _ = write!(
            writer,
            "\r\x1b[2K{} | {} | {} | {}\n",
            fields[1], fields[2], fields[3], fields[4]
        );
        let _ = write!(
            writer,
            "\r\x1b[2K{} | {} | {}\n",
            fields[5], fields[6], fields[7]
        );
        let _ = write!(writer, "\r\x1b[2K{}", fields[8]);
        if finished {
            let _ = writeln!(writer);
        }
    } else {
        let _ = writeln!(writer, "{}", fields.join(" | "));
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
    fn heartbeat_reports_idle_phase_and_bytes_without_polluting_log_output() {
        let capture = Capture::default();
        let reporter =
            AnnexProgressReporter::with_writer(capture.clone(), false, Duration::from_millis(5))
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
    fn terminal_reporter_cleans_up_on_error_without_claiming_completion() {
        let capture = Capture::default();
        let reporter =
            AnnexProgressReporter::with_writer(capture.clone(), true, Duration::from_secs(30))
                .unwrap();
        drop(reporter);
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(text.starts_with("\r\x1b[2K"));
        assert!(text.contains("Stopped before completion"));
        assert!(text.ends_with('\n'));
    }
}
