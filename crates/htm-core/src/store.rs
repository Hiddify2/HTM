//! Where HTM keeps its files, and the persisted application state.
//!
//! Layout (`%APPDATA%\HTM` on Windows, `~/.config/htm` on Linux):
//!
//! ```text
//! state.json        servers, tunnels, benchmark history, preferences
//! secrets.bin       the encrypted vault (see `crypto.rs`)
//! device.key        random key used when no master password is set
//! known_hosts.json  pinned SSH host keys
//! htm.log           application log
//! ```
//!
//! Nothing secret is ever written to `state.json`; profiles only record
//! *whether* a password exists, never the password itself.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::{BenchRun, BenchSettings, ServerProfile, TunnelInstance, TunnelSide};
use crate::provider::InstallMethod;

/// The on-disk layout, resolved once at startup.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    /// The platform configuration directory, with an environment override for
    /// portable installs and tests.
    pub fn discover() -> Result<Self> {
        if let Ok(custom) = std::env::var("HTM_HOME") {
            if !custom.trim().is_empty() {
                return Ok(Self::at(PathBuf::from(custom)));
            }
        }
        let base = dirs::config_dir().ok_or_else(|| {
            Error::Store(
                "could not determine this platform's configuration directory; set HTM_HOME to \
                 choose one explicitly"
                    .to_string(),
            )
        })?;
        Ok(Self::at(base.join("HTM")))
    }

    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        Ok(())
    }

    pub fn state(&self) -> PathBuf {
        self.root.join("state.json")
    }
    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets.bin")
    }
    pub fn device_key(&self) -> PathBuf {
        self.root.join("device.key")
    }
    pub fn known_hosts(&self) -> PathBuf {
        self.root.join("known_hosts.json")
    }
    pub fn log(&self) -> PathBuf {
        self.root.join("htm.log")
    }
    /// Directory holding exported benchmark reports.
    pub fn exports(&self) -> PathBuf {
        self.root.join("exports")
    }
}

/// Write a file without leaving a half-written one behind if the process dies.
///
/// When `private` is set the file is created with owner-only permissions on
/// Unix before any content reaches it.
pub fn write_file_atomic(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", crate::util::random_hex(6)));

    {
        use std::io::Write as _;
        let mut file = create_file(&tmp, private)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    // Windows rejects a rename onto an existing file, so clear the way first.
    #[cfg(windows)]
    {
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(Error::Io(e))
        }
    }
}

#[cfg(unix)]
fn create_file(path: &Path, private: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts.mode(if private { 0o600 } else { 0o644 });
    Ok(opts.open(path)?)
}

#[cfg(not(unix))]
fn create_file(path: &Path, _private: bool) -> Result<std::fs::File> {
    // Windows inherits the parent directory's ACL, which for a per-user
    // AppData folder already restricts access to that user.
    Ok(std::fs::File::create(path)?)
}

/// Preferences that are not tied to a specific server or tunnel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppSettings {
    /// Which tunnel implementation is currently selected.
    pub provider_id: String,
    /// How the provider should be installed on the servers.
    pub install_method: InstallMethod,
    /// Benchmark configuration, remembered between runs.
    pub bench: BenchSettings,
    /// Seconds between automatic tunnel status refreshes. 0 disables.
    pub auto_refresh_secs: u32,
    /// Journal lines fetched per log poll.
    pub log_lines: u32,
    /// Number of benchmark runs to retain.
    pub keep_bench_runs: usize,
    /// Ask before stopping or removing a tunnel.
    pub confirm_destructive: bool,
    /// Dark theme. HTM defaults to dark: it is a tool people leave open next to
    /// a terminal.
    #[serde(default = "default_true")]
    pub dark_mode: bool,
    /// Whether the secret vault is protected by a master password. When false,
    /// `device.key` is used and the UI says so plainly.
    pub vault_uses_master_password: bool,
    /// Base TUN slot for newly created tunnels.
    pub next_tun_slot_hint: u16,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            provider_id: "candytunnel".to_string(),
            install_method: InstallMethod::default(),
            bench: BenchSettings::default(),
            auto_refresh_secs: 15,
            log_lines: 300,
            keep_bench_runs: 20,
            confirm_destructive: true,
            dark_mode: true,
            vault_uses_master_password: false,
            next_tun_slot_hint: 0,
        }
    }
}

fn default_true() -> bool {
    true
}

/// Current schema version of `state.json`.
pub const STATE_VERSION: u32 = 1;

/// Everything HTM remembers between runs, minus secrets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppState {
    #[serde(default = "default_state_version")]
    pub version: u32,
    #[serde(default)]
    pub servers: Vec<ServerProfile>,
    #[serde(default)]
    pub tunnels: Vec<TunnelInstance>,
    #[serde(default)]
    pub bench_runs: Vec<BenchRun>,
    #[serde(default)]
    pub settings: AppSettings,
}

fn default_state_version() -> u32 {
    STATE_VERSION
}

impl Default for AppState {
    fn default() -> Self {
        // A fresh install starts with the two servers the workflow needs, so
        // the user only has to fill them in.
        Self {
            version: STATE_VERSION,
            servers: vec![
                ServerProfile::new(TunnelSide::Server),
                ServerProfile::new(TunnelSide::Client),
            ],
            tunnels: Vec::new(),
            bench_runs: Vec::new(),
            settings: AppSettings::default(),
        }
    }
}

impl AppState {
    /// Load state, falling back to defaults when the file does not exist.
    ///
    /// A corrupt file is moved aside rather than deleted, and reported, so the
    /// user can recover it by hand.
    pub fn load(paths: &Paths) -> Result<(Self, Option<String>)> {
        let path = paths.state();
        if !path.exists() {
            return Ok((Self::default(), None));
        }
        let raw = std::fs::read_to_string(&path)?;
        if raw.trim().is_empty() {
            return Ok((Self::default(), None));
        }
        match serde_json::from_str::<AppState>(&raw) {
            Ok(mut state) => {
                state.migrate();
                Ok((state, None))
            }
            Err(e) => {
                let backup = path.with_extension(format!(
                    "corrupt-{}.json",
                    chrono::Utc::now().format("%Y%m%d-%H%M%S")
                ));
                let note = match std::fs::rename(&path, &backup) {
                    Ok(()) => format!(
                        "state.json could not be read ({e}). It was moved to {} and HTM started \
                         with empty settings.",
                        backup.display()
                    ),
                    Err(move_err) => format!(
                        "state.json could not be read ({e}) and could not be moved aside \
                         ({move_err}). HTM started with empty settings and will overwrite it on \
                         the next save."
                    ),
                };
                Ok((Self::default(), Some(note)))
            }
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        paths.ensure()?;
        let json = serde_json::to_string_pretty(self)?;
        write_file_atomic(&paths.state(), json.as_bytes(), false)
    }

    /// Bring an older file up to the current shape.
    fn migrate(&mut self) {
        if self.version == 0 {
            self.version = STATE_VERSION;
        }
        // Guarantee exactly one profile per side exists so the UI always has
        // something to bind its two server cards to.
        for side in [TunnelSide::Server, TunnelSide::Client] {
            if !self.servers.iter().any(|s| s.side == side) {
                self.servers.push(ServerProfile::new(side));
            }
        }
        self.settings.bench.weights = self.settings.bench.weights.clamped();
        if self.settings.keep_bench_runs == 0 {
            self.settings.keep_bench_runs = 20;
        }
        self.trim_bench_runs();
    }

    /// The profile acting as one side of the tunnel.
    pub fn server(&self, side: TunnelSide) -> Option<&ServerProfile> {
        self.servers.iter().find(|s| s.side == side)
    }

    pub fn server_mut(&mut self, side: TunnelSide) -> Option<&mut ServerProfile> {
        self.servers.iter_mut().find(|s| s.side == side)
    }

    pub fn server_by_id(&self, id: &str) -> Option<&ServerProfile> {
        self.servers.iter().find(|s| s.id == id)
    }

    pub fn tunnel(&self, id: &str) -> Option<&TunnelInstance> {
        self.tunnels.iter().find(|t| t.id == id)
    }

    pub fn tunnel_mut(&mut self, id: &str) -> Option<&mut TunnelInstance> {
        self.tunnels.iter_mut().find(|t| t.id == id)
    }

    /// TUN slots already spoken for.
    pub fn used_tun_slots(&self) -> Vec<crate::model::TunSlot> {
        self.tunnels
            .iter()
            .map(|t| crate::model::TunSlot(t.tun_slot))
            .collect()
    }

    /// Instance names already in use, so a new tunnel does not clash.
    pub fn used_instance_names(&self) -> Vec<String> {
        self.tunnels.iter().map(|t| t.plan.instance.clone()).collect()
    }

    /// Wire ports already in use by deployed tunnels.
    pub fn used_data_ports(&self) -> Vec<u16> {
        self.tunnels.iter().map(|t| t.plan.data_port).collect()
    }

    pub fn push_bench_run(&mut self, run: BenchRun) {
        self.bench_runs.push(run);
        self.trim_bench_runs();
    }

    fn trim_bench_runs(&mut self) {
        let keep = self.settings.keep_bench_runs.max(1);
        if self.bench_runs.len() > keep {
            let drop = self.bench_runs.len() - keep;
            self.bench_runs.drain(..drop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_has_both_sides() {
        let s = AppState::default();
        assert!(s.server(TunnelSide::Client).is_some());
        assert!(s.server(TunnelSide::Server).is_some());
    }

    #[test]
    fn migrate_restores_a_missing_side() {
        let mut s = AppState::default();
        s.servers.retain(|p| p.side == TunnelSide::Client);
        s.migrate();
        assert!(s.server(TunnelSide::Server).is_some());
        assert_eq!(s.servers.len(), 2);
    }

    #[test]
    fn bench_history_is_trimmed() {
        let mut s = AppState::default();
        s.settings.keep_bench_runs = 2;
        for i in 0..5 {
            s.push_bench_run(BenchRun {
                id: format!("run-{i}"),
                provider_id: "candytunnel".into(),
                settings: BenchSettings::default(),
                selection: Default::default(),
                results: Vec::new(),
                started_at: chrono::Utc::now(),
                finished_at: None,
                aborted_reason: None,
            });
        }
        assert_eq!(s.bench_runs.len(), 2);
        assert_eq!(s.bench_runs[0].id, "run-3");
    }
}
