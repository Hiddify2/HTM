//! Background work and how it reports back.
//!
//! Every remote operation is blocking: SSH round trips, installs, benchmark
//! runs. They all execute on worker threads and talk to the UI through a
//! channel of [`JobEvent`]s, which the GUI drains once per frame.
//!
//! Cancellation is cooperative. A worker checks [`Reporter::is_cancelled`]
//! between steps and inside its read loops, so pressing *Cancel* takes effect
//! within a second or two rather than at the next natural boundary.
//!
//! This module deliberately knows nothing about egui: the GUI polls, rather
//! than the core pushing repaints.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::model::{BenchRun, ServerFacts, TunnelInstance, TunnelSide, TunnelStatus};
use crate::provider::InstalledVersion;

/// Severity of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Success,
    Warn,
    Error,
}

impl LogLevel {
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Success => "OK",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// One line of progress output.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub at: chrono::DateTime<chrono::Local>,
    pub level: LogLevel,
    /// Which server the line came from, when it came from one.
    pub scope: Option<String>,
    pub text: String,
}

impl LogLine {
    pub fn render(&self) -> String {
        let ts = self.at.format("%H:%M:%S");
        match &self.scope {
            Some(s) => format!("{ts}  {:<5}  [{s}] {}", self.level.label(), self.text),
            None => format!("{ts}  {:<5}  {}", self.level.label(), self.text),
        }
    }
}

/// Typed results a job hands back, in addition to its log stream.
#[derive(Debug, Clone)]
pub enum JobPayload {
    /// A server was probed successfully.
    Facts {
        server_id: String,
        facts: Box<ServerFacts>,
        host_key_sha256: String,
        priv_mode: String,
    },
    /// The provider was found or installed on a server.
    Installed {
        server_id: String,
        version: InstalledVersion,
    },
    /// A benchmark run advanced. Carries the whole run so the UI can simply
    /// replace what it is showing.
    BenchProgress(Box<BenchRun>),
    /// A benchmark run finished, was aborted or was cancelled.
    BenchFinished(Box<BenchRun>),
    /// A tunnel was deployed.
    TunnelCreated(Box<TunnelInstance>),
    /// A tunnel's files and units were removed from both servers.
    TunnelRemoved { instance_id: String },
    /// Fresh status for zero or more tunnels.
    Status(Vec<TunnelStatus>),
    /// New journal lines for one side of a tunnel.
    Logs {
        instance_id: String,
        side: TunnelSide,
        lines: Vec<String>,
        /// Journal cursor to continue from on the next poll.
        cursor: Option<String>,
    },
    /// The server presented a host key HTM has not pinned. The UI shows the
    /// fingerprint and asks whether to trust it.
    HostKeyPrompt {
        server_id: String,
        host: String,
        port: u16,
        key_type: String,
        sha256: String,
        md5: String,
        /// Set when a *different* key was already pinned, which is the
        /// dangerous case and gets a much louder dialog.
        previous_sha256: Option<String>,
    },
}

/// How a job ended.
#[derive(Debug, Clone)]
pub enum JobOutcome {
    Success(String),
    Failed(String),
    Cancelled,
}

impl JobOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, JobOutcome::Success(_))
    }
}

/// Anything a job emits.
#[derive(Debug, Clone)]
pub enum JobEvent {
    Log(LogLine),
    /// A named phase started, e.g. "Installing dependencies".
    Stage(String),
    Progress {
        done: u32,
        total: u32,
    },
    Payload(JobPayload),
    Finished(JobOutcome),
}

/// What a job is doing, so the UI can route its events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    TestConnection,
    Install,
    Uninstall,
    Benchmark,
    CreateTunnel,
    ControlTunnel,
    RemoveTunnel,
    RefreshStatus,
    FetchLogs,
    Diagnostics,
}

impl JobKind {
    pub fn label(self) -> &'static str {
        match self {
            JobKind::TestConnection => "Connection test",
            JobKind::Install => "Install",
            JobKind::Uninstall => "Uninstall",
            JobKind::Benchmark => "Benchmark",
            JobKind::CreateTunnel => "Create tunnel",
            JobKind::ControlTunnel => "Tunnel control",
            JobKind::RemoveTunnel => "Remove tunnel",
            JobKind::RefreshStatus => "Refresh status",
            JobKind::FetchLogs => "Fetch logs",
            JobKind::Diagnostics => "Diagnostics",
        }
    }

    /// Jobs the user should not have to see in the activity list.
    pub fn is_background(self) -> bool {
        matches!(self, JobKind::RefreshStatus | JobKind::FetchLogs)
    }
}

/// How a worker reports progress and checks for cancellation.
///
/// Passed as `&dyn Reporter` so the deep call chain (provider, orchestrator,
/// benchmark engine) never has to be generic over it.
pub trait Reporter: Send + Sync {
    fn emit(&self, event: JobEvent);
    fn is_cancelled(&self) -> bool;

    /// The one logging entry point. Kept `&str`-only so the trait stays
    /// object-safe and can be passed around as `&dyn Reporter`.
    fn log_line(&self, level: LogLevel, scope: Option<&str>, text: &str) {
        self.emit(JobEvent::Log(LogLine {
            at: chrono::Local::now(),
            level,
            scope: scope.map(|s| s.to_string()),
            text: text.to_string(),
        }));
    }

    fn info(&self, text: &str) {
        self.log_line(LogLevel::Info, None, text);
    }
    fn success(&self, text: &str) {
        self.log_line(LogLevel::Success, None, text);
    }
    fn warn(&self, text: &str) {
        self.log_line(LogLevel::Warn, None, text);
    }
    fn error(&self, text: &str) {
        self.log_line(LogLevel::Error, None, text);
    }
    fn debug(&self, text: &str) {
        self.log_line(LogLevel::Debug, None, text);
    }

    /// Scoped variants, used when the line belongs to a specific server.
    fn info_on(&self, scope: &str, text: &str) {
        self.log_line(LogLevel::Info, Some(scope), text);
    }
    fn success_on(&self, scope: &str, text: &str) {
        self.log_line(LogLevel::Success, Some(scope), text);
    }
    fn warn_on(&self, scope: &str, text: &str) {
        self.log_line(LogLevel::Warn, Some(scope), text);
    }
    fn error_on(&self, scope: &str, text: &str) {
        self.log_line(LogLevel::Error, Some(scope), text);
    }
    fn debug_on(&self, scope: &str, text: &str) {
        self.log_line(LogLevel::Debug, Some(scope), text);
    }

    fn stage(&self, name: &str) {
        self.emit(JobEvent::Stage(name.to_string()));
    }

    fn progress(&self, done: u32, total: u32) {
        self.emit(JobEvent::Progress { done, total });
    }

    fn payload(&self, payload: JobPayload) {
        self.emit(JobEvent::Payload(payload));
    }

    /// `Err(Error::Cancelled)` when the user asked to stop. Call this between
    /// steps so long operations abort promptly.
    fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// The [`Reporter`] that feeds a [`JobHandle`].
pub struct ChannelReporter {
    tx: Sender<JobEvent>,
    cancel: Arc<AtomicBool>,
}

impl ChannelReporter {
    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }
}

impl Reporter for ChannelReporter {
    fn emit(&self, event: JobEvent) {
        // A closed receiver means the UI dropped the job; the worker will find
        // out at its next cancellation check, so dropping the event is fine.
        let _ = self.tx.send(event);
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// A [`Reporter`] that throws everything away. Useful in tests and for
/// operations that run without a UI.
pub struct NullReporter;

impl Reporter for NullReporter {
    fn emit(&self, _event: JobEvent) {}
    fn is_cancelled(&self) -> bool {
        false
    }
}

static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

/// The UI's handle on a running job.
pub struct JobHandle {
    pub id: u64,
    pub kind: JobKind,
    pub label: String,
    rx: Receiver<JobEvent>,
    cancel: Arc<AtomicBool>,
    finished: bool,
    started: Instant,
    /// Last stage name seen, for the activity list.
    pub stage: String,
    pub progress: Option<(u32, u32)>,
}

impl JobHandle {
    /// Drain everything the worker has produced since the last call.
    ///
    /// Tracks stage and progress internally so the UI does not have to.
    pub fn drain(&mut self) -> Vec<JobEvent> {
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(event) => {
                    match &event {
                        JobEvent::Stage(s) => self.stage = s.clone(),
                        JobEvent::Progress { done, total } => {
                            self.progress = Some((*done, *total))
                        }
                        JobEvent::Finished(_) => self.finished = true,
                        _ => {}
                    }
                    out.push(event);
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // The worker thread ended without a Finished event, which
                    // means it panicked. Synthesise a failure so the UI does
                    // not wait forever.
                    if !self.finished {
                        self.finished = true;
                        out.push(JobEvent::Finished(JobOutcome::Failed(
                            "the worker thread stopped unexpectedly. See htm.log for details."
                                .to_string(),
                        )));
                    }
                    break;
                }
            }
        }
        out
    }

    /// Ask the worker to stop at its next checkpoint.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelling(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Run `work` on a worker thread.
///
/// The closure returns the success message; any error is turned into a
/// `Failed` outcome, except [`Error::Cancelled`], which becomes `Cancelled`.
pub fn spawn<F>(kind: JobKind, label: impl Into<String>, work: F) -> JobHandle
where
    F: FnOnce(&ChannelReporter) -> Result<String> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let id = NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed);
    let label = label.into();

    let reporter = ChannelReporter {
        tx,
        cancel: Arc::clone(&cancel),
    };

    let thread_label = label.clone();
    let _worker = std::thread::Builder::new()
        .name(format!("htm-job-{id}"))
        .spawn(move || {
            let outcome = match work(&reporter) {
                Ok(message) => JobOutcome::Success(message),
                Err(Error::Cancelled) => JobOutcome::Cancelled,
                Err(e) => {
                    log::warn!("job '{thread_label}' failed: {e}");
                    JobOutcome::Failed(e.to_string())
                }
            };
            reporter.emit(JobEvent::Finished(outcome));
        })
        // Failing to spawn a thread means the process is out of resources;
        // there is no useful way to continue.
        .expect("HTM could not spawn a worker thread");

    JobHandle {
        id,
        kind,
        label,
        rx,
        cancel,
        finished: false,
        started: Instant::now(),
        stage: String::new(),
        progress: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_successful_job_reports_its_message() {
        let mut handle = spawn(JobKind::Diagnostics, "test", |r| {
            r.info("working");
            Ok("all good".to_string())
        });
        // Wait for the worker; the channel closes when the thread exits.
        let mut events = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() && Instant::now() < deadline {
            events.extend(handle.drain());
            std::thread::sleep(Duration::from_millis(10));
        }
        events.extend(handle.drain());
        assert!(handle.is_finished());
        let finished = events
            .iter()
            .find_map(|e| match e {
                JobEvent::Finished(o) => Some(o.clone()),
                _ => None,
            })
            .expect("a Finished event");
        assert!(finished.is_success());
    }

    #[test]
    fn cancellation_is_visible_to_the_worker() {
        let cancel_seen = Arc::new(AtomicBool::new(false));
        let probe = Arc::clone(&cancel_seen);
        let mut handle = spawn(JobKind::Diagnostics, "cancel", move |r| {
            for _ in 0..500 {
                if r.is_cancelled() {
                    probe.store(true, Ordering::Relaxed);
                    return Err(Error::Cancelled);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(String::new())
        });
        std::thread::sleep(Duration::from_millis(30));
        handle.cancel();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !handle.is_finished() && Instant::now() < deadline {
            handle.drain();
            std::thread::sleep(Duration::from_millis(10));
        }
        handle.drain();
        assert!(cancel_seen.load(Ordering::Relaxed));
    }
}
