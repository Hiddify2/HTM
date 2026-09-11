//! The tunnel provider abstraction.
//!
//! HTM ships with CandyTunnel, but nothing outside [`candytunnel`] knows that.
//! The GUI, the benchmark engine, the deployment orchestrator and the state
//! store all talk to a [`TunnelProvider`] through this trait and the
//! provider-agnostic [`OptionMap`](crate::model::OptionMap) type.
//!
//! To add another tunnel implementation:
//!
//! 1. Create `provider/<name>/mod.rs` implementing [`TunnelProvider`].
//! 2. Declare its settings in [`TunnelProvider::option_space`], marking the
//!    ones worth sweeping as `benchmarkable`.
//! 3. Register it in [`registry::all`].
//!
//! No other file needs to change. The matrix builder, the results table, the
//! deployment flow and the systemd controls all work off the trait.

pub mod candytunnel;
pub mod registry;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::jobs::Reporter;
use crate::model::{
    BenchVariant, MatrixSelection, OptionMap, OptionSpace, PackageManager, ServerFacts, TunnelPlan,
    TunnelSide,
};
use crate::ssh::SshClient;

/// How the provider's software should get onto a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallMethod {
    /// Pick the best option for the host: a published binary when one matches
    /// its architecture, otherwise a source build.
    Auto,
    /// Download a released binary. Fast, and needs no toolchain.
    PrebuiltBinary,
    /// Clone the repository and compile it. Slower and needs a Rust toolchain,
    /// but works on any architecture and always matches the latest source.
    BuildFromSource,
}

impl Default for InstallMethod {
    fn default() -> Self {
        InstallMethod::Auto
    }
}

impl InstallMethod {
    pub fn display_name(self) -> &'static str {
        match self {
            InstallMethod::Auto => "Automatic (recommended)",
            InstallMethod::PrebuiltBinary => "Download prebuilt binary",
            InstallMethod::BuildFromSource => "Build from source",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            InstallMethod::Auto => {
                "Download the released binary on x86_64 hosts, and compile from source on any \
                 other architecture."
            }
            InstallMethod::PrebuiltBinary => {
                "Fetch the latest release asset. Takes seconds, but only x86_64 Linux binaries \
                 are published."
            }
            InstallMethod::BuildFromSource => {
                "Install a Rust toolchain on the server and compile. Takes several minutes and \
                 needs roughly 1 GiB of RAM and 2 GiB of disk."
            }
        }
    }

    pub const ALL: [InstallMethod; 3] = [
        InstallMethod::Auto,
        InstallMethod::PrebuiltBinary,
        InstallMethod::BuildFromSource,
    ];
}

/// What is installed on a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledVersion {
    /// Version string as reported by the software, or the release tag.
    pub version: String,
    /// Absolute path to the executable.
    pub binary_path: String,
    /// How it got there: `release binary v4.1.0`, `built from source`, ...
    pub origin: String,
}

impl InstalledVersion {
    pub fn summary(&self) -> String {
        format!("{} ({})", self.version, self.origin)
    }
}

/// A file the provider wants written on a remote host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    pub path: String,
    pub content: String,
    /// Octal mode string, e.g. `0600`.
    pub mode: String,
    /// Shown in the "review configuration" pane.
    pub description: String,
}

/// Everything one side of a tunnel needs on disk, plus its unit name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedSide {
    pub side: TunnelSide,
    pub files: Vec<RemoteFile>,
    /// The systemd unit to start, e.g. `candytunnel@my-tunnel.service`.
    pub service: String,
}

/// A ready-made benchmark matrix, offered in the UI so the user does not have
/// to assemble one from scratch.
#[derive(Debug, Clone, PartialEq)]
pub struct MatrixPreset {
    /// Stable id, used to remember the last choice.
    pub id: String,
    pub name: String,
    /// What it measures and when it is worth running.
    pub description: String,
    pub selection: MatrixSelection,
}

/// How the orchestrator decides a freshly started tunnel is actually working.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    /// Journal substrings meaning the tunnel is carrying traffic.
    pub ready_markers: Vec<String>,
    /// Journal substrings meaning it will never come up, so waiting is futile.
    pub fatal_markers: Vec<String>,
}

impl Default for Readiness {
    fn default() -> Self {
        Self {
            ready_markers: Vec::new(),
            fatal_markers: Vec::new(),
        }
    }
}

/// One server, ready for a provider to act on.
pub struct HostCtx<'a> {
    pub client: &'a SshClient,
    pub facts: &'a ServerFacts,
    pub side: TunnelSide,
    /// Label used as the log scope, normally the server's name.
    pub scope: &'a str,
    pub reporter: &'a dyn Reporter,
    pub cancel: &'a Arc<AtomicBool>,
}

impl<'a> HostCtx<'a> {
    pub fn info(&self, text: &str) {
        self.reporter
            .log_line(crate::jobs::LogLevel::Info, Some(self.scope), text);
    }
    pub fn success(&self, text: &str) {
        self.reporter
            .log_line(crate::jobs::LogLevel::Success, Some(self.scope), text);
    }
    pub fn warn(&self, text: &str) {
        self.reporter
            .log_line(crate::jobs::LogLevel::Warn, Some(self.scope), text);
    }
    pub fn debug(&self, text: &str) {
        self.reporter
            .log_line(crate::jobs::LogLevel::Debug, Some(self.scope), text);
    }
    pub fn check(&self) -> Result<()> {
        self.reporter.check()
    }
}

/// A tunnel implementation HTM can install, configure, benchmark and run.
pub trait TunnelProvider: Send + Sync {
    /// Stable machine identifier, used in saved state.
    fn id(&self) -> &'static str;
    /// Name shown in the UI.
    fn name(&self) -> &'static str;
    /// One or two sentences describing what it does.
    fn description(&self) -> &'static str;
    /// Upstream project URL.
    fn homepage(&self) -> &'static str;

    /// Every setting this provider understands.
    fn option_space(&self) -> OptionSpace;

    /// Settings a brand new tunnel should start from.
    fn default_options(&self) -> OptionMap {
        self.option_space().defaults()
    }

    /// Reject option combinations the software cannot run, with a message the
    /// user can act on.
    fn validate_options(&self, options: &OptionMap) -> std::result::Result<(), String>;

    /// Turn a matrix selection into the variants actually worth measuring,
    /// dropping invalid and duplicate combinations.
    fn expand_variants(&self, selection: &MatrixSelection) -> Vec<BenchVariant>;

    /// A sensible starting matrix for someone who just wants to press *Run*.
    fn default_matrix(&self) -> MatrixSelection;

    /// Ready-made matrices covering the questions people commonly ask.
    fn matrix_presets(&self) -> Vec<MatrixPreset> {
        vec![MatrixPreset {
            id: "default".into(),
            name: "Default".into(),
            description: "The provider's recommended starting matrix.".into(),
            selection: self.default_matrix(),
        }]
    }

    /// Packages this provider needs, named for the given package manager.
    fn required_packages(&self, manager: PackageManager) -> Vec<String>;

    /// Is the software already present, and at what version?
    fn detect(&self, ctx: &HostCtx<'_>) -> Result<Option<InstalledVersion>>;

    /// Install or update the software.
    fn install(&self, ctx: &HostCtx<'_>, method: InstallMethod) -> Result<InstalledVersion>;

    /// Remove the software and all of its instances.
    fn uninstall(&self, ctx: &HostCtx<'_>) -> Result<()>;

    /// Render, but do not deploy, one side of a plan. Used by the
    /// "review configuration" pane as well as by deployment.
    fn render(&self, plan: &TunnelPlan, side: TunnelSide) -> Result<RenderedSide>;

    /// Write the rendered files and install the systemd unit.
    fn deploy(&self, ctx: &HostCtx<'_>, plan: &TunnelPlan) -> Result<RenderedSide>;

    /// Delete one instance's files and unit from this host.
    fn remove_instance(&self, ctx: &HostCtx<'_>, instance: &str) -> Result<()>;

    /// The systemd unit name for an instance.
    fn service_name(&self, instance: &str) -> String;

    /// Where the instance's configuration lives, for display and diffing.
    fn config_path(&self, instance: &str) -> String;

    /// Instance names currently configured on a host.
    fn list_instances(&self, ctx: &HostCtx<'_>) -> Result<Vec<String>>;

    /// How to tell a started tunnel is working.
    fn readiness(&self) -> Readiness {
        Readiness::default()
    }

    /// Settings that must be identical on both sides. Surfaced in the UI so a
    /// mismatch is explained rather than just failing.
    fn symmetric_option_keys(&self) -> Vec<&'static str> {
        Vec::new()
    }
}

/// A convenient alias for the shared trait object.
pub type ProviderRef = Arc<dyn TunnelProvider>;
