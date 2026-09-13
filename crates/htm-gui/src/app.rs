//! The application shell: state, the job pump, and action dispatch.
//!
//! Views never perform work directly. They push an [`Action`] onto a queue,
//! which is drained after drawing. That keeps every view a pure function of
//! state plus a list of intents, and it sidesteps the borrow conflicts that
//! come from mutating the app while iterating over part of it.
//!
//! All remote work happens on worker threads owned by
//! [`htm_core::jobs`]. The UI only ever drains their event channels.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use egui::Context;

use htm_core::crypto::{KeySource, Vault};
use htm_core::jobs::{
    self, JobEvent, JobHandle, JobKind, JobOutcome, JobPayload, LogLevel, LogLine, Reporter,
};
use htm_core::model::{
    ServerCredentials, ServerSecrets, ServiceAction, SpoofPlan, TunSlot, TunnelInstance,
    TunnelSide,
};
use htm_core::orchestrator::{self, bench as bench_engine, PlanInputs};
use htm_core::provider::{registry, ProviderRef};
use htm_core::ssh::{HostKeyPolicy, KnownHosts};
use htm_core::store::{AppState, Paths};
use htm_core::util;

use crate::state::{
    BenchUi, ConfirmedAction, InstallUi, LogsUi, Modal, ServersUi, SettingsUi, Tab, Toast,
    TrafficHistory, TunnelsUi, WizardUi,
};
use crate::theme::Palette;
use crate::views;

/// Something the user asked for, carried out after the frame is drawn.
#[derive(Debug, Clone)]
pub enum Action {
    SwitchTab(Tab),
    SaveNow,

    TestConnection(TunnelSide),
    TestBothConnections,
    TrustHostKey {
        server_id: String,
        sha256: String,
    },
    ForgetHostKey {
        host: String,
        port: u16,
    },

    InstallProvider,
    UninstallProvider,

    ApplyBenchPreset(String),
    RunBenchmark,
    ShowBenchRun(Option<usize>),

    OpenWizard {
        from_variant: Option<String>,
    },
    CloseWizard,
    PreviewWizardConfig,
    CreateTunnel,

    ControlTunnel {
        instance_id: String,
        action: ServiceAction,
    },
    RemoveTunnel(String),
    RefreshStatuses,
    PreviewTunnelConfig {
        instance_id: String,
        side: TunnelSide,
    },
    ClosePreview,
    PollRemoteLogs,

    CancelJob(u64),
    CancelAllJobs,

    SetMasterPassword(String),
    RemoveMasterPassword,
    /// Open an existing vault that is protected by a master password.
    UnlockVault(String),
    ClearVault,

    Confirm(Box<ConfirmedAction>),
    DismissModal,
}

/// The whole application.
pub struct HtmApp {
    pub paths: Paths,
    pub state: AppState,
    pub vault: Vault,
    pub key_source: KeySource,
    pub palette: Palette,
    pub provider: ProviderRef,

    pub tab: Tab,
    pub jobs: Vec<JobHandle>,
    pub log: VecDeque<LogLine>,
    pub toasts: Vec<Toast>,
    pub modal: Option<Modal>,
    pub actions: Vec<Action>,

    pub servers_ui: ServersUi,
    pub install_ui: InstallUi,
    pub bench_ui: BenchUi,
    pub tunnels_ui: TunnelsUi,
    pub wizard: WizardUi,
    pub logs_ui: LogsUi,
    pub settings_ui: SettingsUi,

    /// Fingerprints the user has explicitly approved, consumed by the next
    /// connection to that server.
    trust_overrides: HashMap<String, String>,

    /// True while the credential file on disk cannot be read — either it is
    /// waiting for a master password, or it failed to decrypt. HTM never
    /// overwrites a vault it could not open, so nothing is lost by carrying on
    /// without it.
    pub vault_locked: bool,

    dirty: bool,
    last_save: Instant,
    saved_once: bool,
    pub startup_note: Option<String>,
}

impl std::fmt::Debug for HtmApp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HtmApp")
            .field("tab", &self.tab)
            .field("jobs", &self.jobs.len())
            .field("tunnels", &self.state.tunnels.len())
            .finish()
    }
}

/// Maximum lines kept in the in-app log. Older lines are dropped.
const LOG_CAPACITY: usize = 6000;
/// How long changes sit before being written to disk.
const SAVE_DEBOUNCE: Duration = Duration::from_secs(2);

impl HtmApp {
    pub fn new(
        paths: Paths,
        state: AppState,
        vault: Vault,
        key_source: KeySource,
        startup_note: Option<String>,
    ) -> Self {
        let provider = registry::get_or_default(&state.settings.provider_id);

        let mut servers_ui = ServersUi::default();
        for profile in &state.servers {
            servers_ui
                .secrets
                .insert(profile.id.clone(), vault.secrets(&profile.id));
        }

        let mut bench_ui = BenchUi::default();
        // Seed the matrix from the provider's own recommendation so the
        // benchmark tab is usable the moment it is opened.
        if let Some(preset) = provider
            .matrix_presets()
            .into_iter()
            .find(|p| p.id == bench_ui.preset_id)
        {
            bench_ui.selection = preset.selection;
        } else {
            bench_ui.selection = provider.default_matrix();
        }

        let wizard = WizardUi {
            options: provider.default_options(),
            pre_shared_key: util::generate_psk(),
            ..WizardUi::default()
        };

        Self {
            palette: Palette::for_theme(true),
            paths,
            state,
            vault,
            key_source,
            provider,
            tab: Tab::Servers,
            jobs: Vec::new(),
            log: VecDeque::with_capacity(512),
            toasts: Vec::new(),
            modal: None,
            actions: Vec::new(),
            servers_ui,
            install_ui: InstallUi {
                with_benchmark_tools: true,
                ..InstallUi::default()
            },
            bench_ui,
            tunnels_ui: TunnelsUi::default(),
            wizard,
            logs_ui: LogsUi::default(),
            settings_ui: SettingsUi::default(),
            trust_overrides: HashMap::new(),
            vault_locked: false,
            dirty: false,
            last_save: Instant::now(),
            saved_once: true,
            startup_note,
        }
    }

    // ── Small helpers used by every view ────────────────────────────────────

    pub fn push(&mut self, action: Action) {
        self.actions.push(action);
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        self.saved_once = false;
    }

    pub fn toast(&mut self, level: LogLevel, text: impl Into<String>) {
        self.toasts.push(Toast::new(level, text));
    }

    pub fn known_hosts_path(&self) -> PathBuf {
        self.paths.known_hosts()
    }

    /// Is a job of this kind currently running?
    pub fn busy_with(&self, kind: JobKind) -> bool {
        self.jobs
            .iter()
            .any(|j| j.kind == kind && !j.is_finished())
    }

    pub fn any_foreground_job(&self) -> bool {
        self.jobs
            .iter()
            .any(|j| !j.is_finished() && !j.kind.is_background())
    }

    /// Both servers have been probed successfully.
    pub fn both_servers_ready(&self) -> bool {
        TunnelSide::ORDERED.iter().all(|side| {
            self.state
                .server(*side)
                .and_then(|p| p.facts.as_ref())
                .map(|f| f.blockers().is_empty())
                .unwrap_or(false)
        })
    }

    /// The provider is installed on both servers, as far as HTM knows.
    pub fn provider_installed(&self) -> bool {
        self.install_ui.versions.len() == 2
    }

    /// Join a profile with its secrets.
    pub fn credentials(&self, side: TunnelSide) -> Result<ServerCredentials, String> {
        let profile = self
            .state
            .server(side)
            .ok_or_else(|| format!("No {} is configured.", side.display_name()))?
            .clone();
        profile.validate()?;
        let secrets = self
            .servers_ui
            .secrets
            .get(&profile.id)
            .cloned()
            .unwrap_or_default();

        if profile.auth_kind == htm_core::model::AuthKind::Password && secrets.password.is_empty() {
            return Err(format!("{}: a password is required.", profile.label));
        }
        Ok(ServerCredentials::new(profile, secrets))
    }

    /// The host key policy to use for a server: normally strict, but honouring
    /// a fingerprint the user just approved.
    fn policy_for(&self, server_id: &str) -> HostKeyPolicy {
        match self.trust_overrides.get(server_id) {
            Some(sha256) => HostKeyPolicy::Trust {
                sha256: sha256.clone(),
            },
            None => HostKeyPolicy::Strict,
        }
    }

    fn log_line(&mut self, line: LogLine) {
        if self.log.len() >= LOG_CAPACITY {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }

    fn note(&mut self, level: LogLevel, text: impl Into<String>) {
        let line = LogLine {
            at: chrono::Local::now(),
            level,
            scope: None,
            text: text.into(),
        };
        self.log_line(line);
    }

    // ── Persistence ─────────────────────────────────────────────────────────

    /// Copy the edited secrets into the vault and write both files.
    pub fn save(&mut self) {
        // Keep the "has a password" flags on the profiles honest.
        let ids: Vec<String> = self.state.servers.iter().map(|s| s.id.clone()).collect();
        for id in ids {
            let secrets = self
                .servers_ui
                .secrets
                .get(&id)
                .cloned()
                .unwrap_or_default();
            if let Some(profile) = self.state.servers.iter_mut().find(|s| s.id == id) {
                profile.has_password = !secrets.password.is_empty();
                profile.has_key_passphrase = !secrets.key_passphrase.is_empty();
                profile.has_sudo_password = !secrets.sudo_password.is_empty();
                profile.proxy.has_password = !secrets.proxy_password.is_empty();
            }
            self.vault.set_secrets(&id, secrets);
        }

        self.state.settings.provider_id = self.provider.id().to_string();
        self.state.settings.vault_uses_master_password = self.key_source.is_master_password();

        if let Err(e) = self.state.save(&self.paths) {
            self.toast(LogLevel::Error, format!("Could not save settings: {e}"));
            return;
        }
        // Refuse to write over a vault we were never able to read: doing so
        // would silently destroy the user's stored passwords.
        if !self.vault_locked {
            let secrets_path = self.paths.secrets();
            if let Err(e) = self.vault.save(&secrets_path, &self.key_source) {
                self.toast(LogLevel::Error, format!("Could not save credentials: {e}"));
                return;
            }
        }

        self.dirty = false;
        self.saved_once = true;
        self.last_save = Instant::now();
    }

    fn maybe_save(&mut self) {
        if self.dirty && self.last_save.elapsed() >= SAVE_DEBOUNCE {
            self.save();
        }
    }

    // ── Job pump ────────────────────────────────────────────────────────────

    fn pump_jobs(&mut self) {
        let mut events: Vec<(JobKind, JobEvent)> = Vec::new();
        for job in &mut self.jobs {
            let kind = job.kind;
            for event in job.drain() {
                events.push((kind, event));
            }
        }

        for (kind, event) in events {
            match event {
                JobEvent::Log(line) => self.log_line(line),
                JobEvent::Stage(_) | JobEvent::Progress { .. } => {
                    // Tracked on the handle itself; nothing else to do.
                }
                JobEvent::Payload(payload) => self.apply_payload(payload),
                JobEvent::Finished(outcome) => self.finish_job(kind, outcome),
            }
        }

        self.jobs.retain(|j| !j.is_finished());
        self.toasts.retain(|t| !t.expired());
    }

    fn finish_job(&mut self, kind: JobKind, outcome: JobOutcome) {
        match outcome {
            JobOutcome::Success(message) => {
                if !message.is_empty() {
                    self.note(LogLevel::Success, message.clone());
                    if !kind.is_background() {
                        self.toast(LogLevel::Success, message);
                    }
                }
            }
            JobOutcome::Cancelled => {
                self.note(LogLevel::Warn, format!("{} cancelled.", kind.label()));
                if !kind.is_background() {
                    self.toast(LogLevel::Warn, format!("{} cancelled.", kind.label()));
                }
            }
            JobOutcome::Failed(message) => {
                self.note(LogLevel::Error, message.clone());
                match kind {
                    JobKind::TestConnection => {
                        // The servers view shows this inline, next to the card
                        // it belongs to, which is more useful than a toast.
                        self.toast(LogLevel::Error, util::truncate(&message, 140));
                    }
                    JobKind::RefreshStatus | JobKind::FetchLogs => {
                        self.tunnels_ui.last_error = Some(message);
                    }
                    JobKind::Install => {
                        self.install_ui.last_error = Some(message.clone());
                        self.toast(LogLevel::Error, util::truncate(&message, 140));
                    }
                    _ => {
                        // Long failures deserve a dialog the user can read and
                        // copy from, not a toast that vanishes.
                        if message.len() > 220 {
                            self.modal = Some(Modal::Error {
                                title: format!("{} failed", kind.label()),
                                body: message,
                            });
                        } else {
                            self.toast(LogLevel::Error, message);
                        }
                    }
                }
            }
        }
    }

    fn apply_payload(&mut self, payload: JobPayload) {
        match payload {
            JobPayload::Facts {
                server_id,
                facts,
                host_key_sha256,
                priv_mode,
            } => {
                self.servers_ui.last_error.remove(&server_id);
                self.trust_overrides.remove(&server_id);
                if let Some(profile) =
                    self.state.servers.iter_mut().find(|s| s.id == server_id)
                {
                    profile.facts = Some(*facts);
                    profile.last_checked = Some(chrono::Utc::now());
                }
                self.note(
                    LogLevel::Debug,
                    format!("{server_id}: key SHA256:{host_key_sha256}, {priv_mode}"),
                );
                self.mark_dirty();
            }

            JobPayload::Installed { server_id, version } => {
                let side = self.state.server_by_id(&server_id).map(|p| p.side);
                if let Some(side) = side {
                    self.install_ui.versions.insert(side, version);
                }
                self.install_ui.last_error = None;
            }

            JobPayload::BenchProgress(run) => {
                self.bench_ui.history_index = None;
                self.bench_ui.current = Some(*run);
            }

            JobPayload::BenchFinished(run) => {
                self.bench_ui.history_index = None;
                let run = *run;
                self.bench_ui.current = Some(run.clone());
                self.state.push_bench_run(run);
                self.mark_dirty();
                self.save();
            }

            JobPayload::TunnelCreated(instance) => {
                let instance = *instance;
                let name = instance.plan.instance.clone();
                self.state.tunnels.retain(|t| t.id != instance.id);
                self.state.tunnels.push(instance);
                self.mark_dirty();
                self.save();
                self.wizard.open = false;
                self.tab = Tab::Tunnels;
                self.toast(LogLevel::Success, format!("Tunnel '{name}' is running."));
                self.push(Action::RefreshStatuses);
            }

            JobPayload::TunnelRemoved { instance_id } => {
                self.state.tunnels.retain(|t| t.id != instance_id);
                self.tunnels_ui.statuses.remove(&instance_id);
                self.tunnels_ui.traffic.remove(&instance_id);
                if self.tunnels_ui.expanded.as_deref() == Some(instance_id.as_str()) {
                    self.tunnels_ui.expanded = None;
                }
                self.mark_dirty();
                self.save();
            }

            JobPayload::Status(statuses) => {
                self.tunnels_ui.last_error = None;
                for status in statuses {
                    let (rx, tx) = status.total_bytes();
                    let history = self
                        .tunnels_ui
                        .traffic
                        .entry(status.instance_id.clone())
                        .or_insert_with(TrafficHistory::default);
                    history.push_total(rx.saturating_add(tx));
                    self.tunnels_ui
                        .statuses
                        .insert(status.instance_id.clone(), status);
                }
                self.tunnels_ui.last_refresh = Some(Instant::now());
            }

            JobPayload::Logs {
                instance_id,
                side,
                lines,
                cursor,
            } => {
                let key = (instance_id, side);
                if let Some(cursor) = cursor {
                    self.logs_ui.remote_cursor.insert(key.clone(), cursor);
                }
                if !lines.is_empty() {
                    let buffer = self.logs_ui.remote_lines.entry(key).or_default();
                    buffer.extend(lines);
                    // A journal that is spewing should not grow the heap
                    // without limit.
                    if buffer.len() > 4000 {
                        let excess = buffer.len() - 4000;
                        buffer.drain(..excess);
                    }
                }
            }

            JobPayload::HostKeyPrompt {
                server_id,
                host,
                port,
                key_type,
                sha256,
                md5,
                previous_sha256,
            } => {
                self.modal = Some(Modal::HostKey {
                    server_id,
                    host,
                    port,
                    key_type,
                    sha256,
                    md5,
                    previous_sha256,
                });
            }
        }
    }

    // ── Action dispatch ─────────────────────────────────────────────────────

    fn run_actions(&mut self) {
        let actions = std::mem::take(&mut self.actions);
        for action in actions {
            self.run_action(action);
        }
    }

    fn run_action(&mut self, action: Action) {
        match action {
            Action::SwitchTab(tab) => {
                self.tab = tab;
                if tab == Tab::Tunnels {
                    self.push(Action::RefreshStatuses);
                }
            }
            Action::SaveNow => self.save(),

            Action::TestConnection(side) => self.spawn_test_connection(side),
            Action::TestBothConnections => {
                self.spawn_test_connection(TunnelSide::Server);
                self.spawn_test_connection(TunnelSide::Client);
            }

            Action::TrustHostKey { server_id, sha256 } => {
                // The fingerprint is consumed by the next connection to this
                // server, which pins it. Retry straight away so accepting the
                // dialog visibly does something.
                let side = self.state.server_by_id(&server_id).map(|p| p.side);
                self.trust_overrides.insert(server_id, sha256);
                self.modal = None;
                if let Some(side) = side {
                    self.spawn_test_connection(side);
                }
            }

            Action::ForgetHostKey { host, port } => match self.forget_host_key(&host, port) {
                Ok(true) => self.toast(
                    LogLevel::Success,
                    format!("Forgot the pinned key for {host}:{port}."),
                ),
                Ok(false) => self.toast(
                    LogLevel::Info,
                    format!("No key was pinned for {host}:{port}."),
                ),
                Err(e) => self.toast(LogLevel::Error, e),
            },

            Action::InstallProvider => self.spawn_install(),
            Action::UninstallProvider => self.spawn_uninstall(),

            Action::ApplyBenchPreset(id) => {
                if let Some(preset) =
                    self.provider.matrix_presets().into_iter().find(|p| p.id == id)
                {
                    self.bench_ui.preset_id = preset.id;
                    self.bench_ui.selection = preset.selection;
                }
            }
            Action::RunBenchmark => self.spawn_benchmark(),
            Action::ShowBenchRun(index) => {
                self.bench_ui.history_index = index;
                self.bench_ui.selected_variant = None;
                self.bench_ui.current = match index {
                    Some(i) => self.state.bench_runs.get(i).cloned(),
                    None => self.bench_ui.current.clone(),
                };
            }

            Action::OpenWizard { from_variant } => self.open_wizard(from_variant),
            Action::CloseWizard => {
                self.wizard.open = false;
                self.wizard.preview = None;
            }
            Action::PreviewWizardConfig => self.preview_wizard(),
            Action::CreateTunnel => self.spawn_create_tunnel(),

            Action::ControlTunnel {
                instance_id,
                action,
            } => self.spawn_control(instance_id, action),
            Action::RemoveTunnel(instance_id) => self.spawn_remove(instance_id),
            Action::RefreshStatuses => self.spawn_refresh(),
            Action::PreviewTunnelConfig { instance_id, side } => {
                self.preview_tunnel(&instance_id, side)
            }
            Action::ClosePreview => self.tunnels_ui.preview = None,
            Action::PollRemoteLogs => self.spawn_remote_logs(),

            Action::CancelJob(id) => {
                if let Some(job) = self.jobs.iter().find(|j| j.id == id) {
                    job.cancel();
                }
            }
            Action::CancelAllJobs => {
                for job in &self.jobs {
                    job.cancel();
                }
            }

            Action::SetMasterPassword(password) => self.set_master_password(password),
            Action::RemoveMasterPassword => self.remove_master_password(),
            Action::UnlockVault(password) => self.unlock_vault(password),
            Action::ClearVault => {
                self.vault.clear();
                for secrets in self.servers_ui.secrets.values_mut() {
                    *secrets = ServerSecrets::default();
                }
                self.mark_dirty();
                self.save();
                self.toast(LogLevel::Success, "All stored credentials were removed.");
            }

            Action::Confirm(confirmed) => self.run_confirmed(*confirmed),
            Action::DismissModal => self.modal = None,
        }
    }

    fn run_confirmed(&mut self, action: ConfirmedAction) {
        self.modal = None;
        match action {
            ConfirmedAction::StopTunnel(id) => self.spawn_control(id, ServiceAction::Stop),
            ConfirmedAction::RemoveTunnel(id) => self.spawn_remove(id),
            ConfirmedAction::UninstallProvider => self.spawn_uninstall(),
            ConfirmedAction::ClearVault => self.run_action(Action::ClearVault),
            ConfirmedAction::ForgetHostKey { host, port } => {
                self.run_action(Action::ForgetHostKey { host, port })
            }
        }
    }

    fn forget_host_key(&self, host: &str, port: u16) -> Result<bool, String> {
        let path = self.known_hosts_path();
        let mut known = KnownHosts::load(&path).map_err(|e| e.to_string())?;
        let removed = known.remove(host, port).is_some();
        if removed {
            known.save().map_err(|e| e.to_string())?;
        }
        Ok(removed)
    }

    // ── Vault ───────────────────────────────────────────────────────────────

    /// Open a vault that is protected by a master password.
    fn unlock_vault(&mut self, password: String) {
        let source = KeySource::MasterPassword(password);
        match Vault::open(&self.paths.secrets(), &source) {
            Ok(vault) => {
                self.vault = vault;
                self.key_source = source;
                self.vault_locked = false;
                self.state.settings.vault_uses_master_password = true;

                let ids: Vec<String> =
                    self.state.servers.iter().map(|s| s.id.clone()).collect();
                for id in ids {
                    let secrets = self.vault.secrets(&id);
                    self.servers_ui.secrets.insert(id, secrets);
                }

                self.modal = None;
                self.toast(LogLevel::Success, "Credentials unlocked.");
            }
            Err(e) => {
                let message = e.to_string();
                if let Some(Modal::Unlock { error, .. }) = self.modal.as_mut() {
                    *error = Some(message.clone());
                } else {
                    self.toast(LogLevel::Error, message);
                }
            }
        }
    }

    fn set_master_password(&mut self, password: String) {
        if password.len() < 8 {
            self.settings_ui.vault_error =
                Some("A master password must be at least 8 characters.".to_string());
            return;
        }
        self.key_source = KeySource::MasterPassword(password);
        self.state.settings.vault_uses_master_password = true;
        // Setting a password means we now own the file again.
        self.vault_locked = false;
        self.mark_dirty();
        self.save();
        self.settings_ui.vault_error = None;
        self.settings_ui.vault_message = Some(
            "Credentials are now encrypted with your master password. You will be asked for it \
             the next time HTM starts."
                .to_string(),
        );
        self.settings_ui.new_master_password.clear();
        self.settings_ui.confirm_master_password.clear();
    }

    fn remove_master_password(&mut self) {
        match htm_core::crypto::load_or_create_device_key(&self.paths.device_key()) {
            Ok(key) => {
                self.key_source = KeySource::DeviceKey(key);
                self.state.settings.vault_uses_master_password = false;
                self.vault_locked = false;
                self.mark_dirty();
                self.save();
                self.settings_ui.vault_error = None;
                self.settings_ui.vault_message = Some(
                    "The master password was removed. Credentials are now protected only by the \
                     device key file, which anyone able to read your user profile can also read."
                        .to_string(),
                );
            }
            Err(e) => self.settings_ui.vault_error = Some(e.to_string()),
        }
    }

    // ── Job builders ────────────────────────────────────────────────────────

    fn spawn_test_connection(&mut self, side: TunnelSide) {
        let credentials = match self.credentials(side) {
            Ok(c) => c,
            Err(e) => {
                if let Some(profile) = self.state.server(side) {
                    self.servers_ui
                        .last_error
                        .insert(profile.id.clone(), e.clone());
                }
                self.toast(LogLevel::Error, e);
                return;
            }
        };

        let server_id = credentials.profile.id.clone();
        let label = credentials.profile.label.clone();
        let known_path = self.known_hosts_path();
        let policy = self.policy_for(&server_id);

        self.servers_ui.last_error.remove(&server_id);

        let handle = jobs::spawn(
            JobKind::TestConnection,
            format!("Testing {label}"),
            move |reporter| {
                reporter.stage(&format!("Connecting to {label}"));
                match orchestrator::connect_one(
                    &credentials,
                    &known_path,
                    &policy,
                    reporter,
                    true,
                ) {
                    Ok((client, facts)) => {
                        reporter.payload(JobPayload::Facts {
                            server_id: server_id.clone(),
                            facts: Box::new(facts),
                            host_key_sha256: client.host_key_sha256().to_string(),
                            priv_mode: client.priv_mode().describe().to_string(),
                        });
                        Ok(format!("{label} is reachable."))
                    }
                    Err(htm_core::Error::HostKeyUnknown {
                        host,
                        port,
                        key_type,
                        sha256,
                        md5,
                    }) => {
                        reporter.payload(JobPayload::HostKeyPrompt {
                            server_id: server_id.clone(),
                            host,
                            port,
                            key_type,
                            sha256,
                            md5,
                            previous_sha256: None,
                        });
                        Err(htm_core::Error::msg(
                            "Waiting for you to confirm the server's host key.",
                        ))
                    }
                    Err(htm_core::Error::HostKeyMismatch {
                        host,
                        port,
                        expected_sha256,
                        actual_sha256,
                    }) => {
                        reporter.payload(JobPayload::HostKeyPrompt {
                            server_id: server_id.clone(),
                            host,
                            port,
                            key_type: String::new(),
                            sha256: actual_sha256,
                            md5: String::new(),
                            previous_sha256: Some(expected_sha256),
                        });
                        Err(htm_core::Error::msg(
                            "The server's host key has changed. Confirm before continuing.",
                        ))
                    }
                    Err(e) => Err(e),
                }
            },
        );
        self.jobs.push(handle);
    }

    /// Build the credentials for both sides, reporting the first problem.
    fn pair_credentials(&mut self) -> Option<(ServerCredentials, ServerCredentials)> {
        let relay = match self.credentials(TunnelSide::Client) {
            Ok(c) => c,
            Err(e) => {
                self.toast(LogLevel::Error, e);
                return None;
            }
        };
        let exit = match self.credentials(TunnelSide::Server) {
            Ok(c) => c,
            Err(e) => {
                self.toast(LogLevel::Error, e);
                return None;
            }
        };
        Some((relay, exit))
    }

    fn spawn_install(&mut self) {
        let Some((relay, exit)) = self.pair_credentials() else {
            return;
        };
        let provider = self.provider.clone();
        let method = self.state.settings.install_method;
        let with_tools = self.install_ui.with_benchmark_tools;
        let known_path = self.known_hosts_path();
        let policy = HostKeyPolicy::Strict;
        let relay_id = relay.profile.id.clone();
        let exit_id = exit.profile.id.clone();

        self.install_ui.last_error = None;

        let handle = jobs::spawn(
            JobKind::Install,
            format!("Installing {}", provider.name()),
            move |reporter| {
                reporter.stage("Connecting");
                let pair =
                    orchestrator::connect_pair(&relay, &exit, &known_path, &policy, reporter)?;
                let cancel = reporter.cancel_flag();

                let installed = orchestrator::install_on_pair(
                    &pair, &provider, method, with_tools, reporter, &cancel,
                )?;

                for (side, version) in &installed {
                    let server_id = match side {
                        TunnelSide::Client => relay_id.clone(),
                        TunnelSide::Server => exit_id.clone(),
                    };
                    reporter.payload(JobPayload::Installed {
                        server_id,
                        version: version.clone(),
                    });
                }

                Ok(format!(
                    "{} is installed on both servers.",
                    provider.name()
                ))
            },
        );
        self.jobs.push(handle);
    }

    fn spawn_uninstall(&mut self) {
        let Some((relay, exit)) = self.pair_credentials() else {
            return;
        };
        let provider = self.provider.clone();
        let known_path = self.known_hosts_path();

        let handle = jobs::spawn(
            JobKind::Uninstall,
            format!("Removing {}", provider.name()),
            move |reporter| {
                let pair = orchestrator::connect_pair(
                    &relay,
                    &exit,
                    &known_path,
                    &HostKeyPolicy::Strict,
                    reporter,
                )?;
                let cancel = reporter.cancel_flag();
                for side in TunnelSide::ORDERED {
                    reporter.check()?;
                    let ctx = pair.ctx(side, reporter, &cancel);
                    provider.uninstall(&ctx)?;
                }
                Ok(format!("{} was removed from both servers.", provider.name()))
            },
        );
        self.jobs.push(handle);
    }

    fn spawn_benchmark(&mut self) {
        let Some((relay, exit)) = self.pair_credentials() else {
            return;
        };
        let provider = self.provider.clone();
        let variants = provider.expand_variants(&self.bench_ui.selection);

        if variants.is_empty() {
            self.toast(
                LogLevel::Error,
                "The matrix produced nothing to measure. Select at least one value to vary.",
            );
            return;
        }

        let ctx = bench_engine::BenchContext::new(
            relay.profile.clone(),
            exit.profile.clone(),
            provider.id(),
            self.state.settings.bench.clone(),
            self.bench_ui.selection.clone(),
        );
        let known_path = self.known_hosts_path();
        let count = variants.len();

        self.bench_ui.current = None;
        self.bench_ui.history_index = None;
        self.bench_ui.selected_variant = None;

        let handle = jobs::spawn(
            JobKind::Benchmark,
            format!("Benchmarking {count} configurations"),
            move |reporter| {
                reporter.stage("Connecting");
                let pair = orchestrator::connect_pair(
                    &relay,
                    &exit,
                    &known_path,
                    &HostKeyPolicy::Strict,
                    reporter,
                )?;
                orchestrator::assert_deployable(&pair)?;
                let cancel = reporter.cancel_flag();
                let run = bench_engine::run(&pair, &provider, variants, &ctx, reporter, &cancel)?;
                let completed = run.completed().count();
                Ok(format!(
                    "Measured {completed} of {count} configurations."
                ))
            },
        );
        self.jobs.push(handle);
    }

    fn spawn_create_tunnel(&mut self) {
        let inputs = match self.wizard_inputs() {
            Ok(i) => i,
            Err(e) => {
                self.wizard.error = Some(e);
                return;
            }
        };
        self.wizard.error = None;

        let Some((relay, exit)) = self.pair_credentials() else {
            return;
        };
        let provider = self.provider.clone();
        let known_path = self.known_hosts_path();
        let start_on_boot = self.wizard.start_on_boot;
        let handshake_timeout =
            Duration::from_secs(self.state.settings.bench.handshake_timeout_secs.max(30) as u64);

        let relay_id = relay.profile.id.clone();
        let exit_id = exit.profile.id.clone();
        let slot = inputs.tun_slot;
        let source_variant = self.wizard.source_variant.clone();
        let expected_up = self.wizard.expected_up;
        let expected_down = self.wizard.expected_down;
        let expected_latency = self.wizard.expected_latency;

        let handle = jobs::spawn(
            JobKind::CreateTunnel,
            format!("Creating tunnel '{}'", inputs.instance),
            move |reporter| {
                reporter.stage("Connecting");
                let pair = orchestrator::connect_pair(
                    &relay,
                    &exit,
                    &known_path,
                    &HostKeyPolicy::Strict,
                    reporter,
                )?;
                orchestrator::assert_deployable(&pair)?;

                let plan = orchestrator::build_plan(&inputs)?;
                let cancel = reporter.cancel_flag();

                orchestrator::deploy_and_start(
                    &pair,
                    &provider,
                    &plan,
                    start_on_boot,
                    handshake_timeout,
                    reporter,
                    &cancel,
                )?;

                let instance = TunnelInstance {
                    id: util::new_id("tun"),
                    client_server_id: relay_id,
                    server_server_id: exit_id,
                    tun_slot: slot.0,
                    plan: plan.clone(),
                    created_at: chrono::Utc::now(),
                    updated_at: None,
                    source_variant,
                    expected_uplink_bps: expected_up,
                    expected_downlink_bps: expected_down,
                    expected_latency_ms: expected_latency,
                    notes: String::new(),
                    start_on_boot,
                };
                let name = instance.plan.instance.clone();
                reporter.payload(JobPayload::TunnelCreated(Box::new(instance)));
                Ok(format!("Tunnel '{name}' is up."))
            },
        );
        self.jobs.push(handle);
    }

    fn spawn_control(&mut self, instance_id: String, action: ServiceAction) {
        let Some(instance) = self.state.tunnel(&instance_id).cloned() else {
            return;
        };
        let Some((relay, exit)) = self.pair_credentials() else {
            return;
        };
        let provider = self.provider.clone();
        let known_path = self.known_hosts_path();
        let name = instance.plan.instance.clone();

        let handle = jobs::spawn(
            JobKind::ControlTunnel,
            format!("{} '{}'", action.verb(), name),
            move |reporter| {
                let pair = orchestrator::connect_pair(
                    &relay,
                    &exit,
                    &known_path,
                    &HostKeyPolicy::Strict,
                    reporter,
                )?;
                orchestrator::control_pair(&pair, &provider, &name, action, reporter)?;
                Ok(format!("{} succeeded for '{name}'.", action.verb()))
            },
        );
        self.jobs.push(handle);
    }

    fn spawn_remove(&mut self, instance_id: String) {
        let Some(instance) = self.state.tunnel(&instance_id).cloned() else {
            return;
        };
        let Some((relay, exit)) = self.pair_credentials() else {
            return;
        };
        let provider = self.provider.clone();
        let known_path = self.known_hosts_path();
        let name = instance.plan.instance.clone();
        let id = instance.id.clone();

        let handle = jobs::spawn(
            JobKind::RemoveTunnel,
            format!("Removing '{name}'"),
            move |reporter| {
                let pair = orchestrator::connect_pair(
                    &relay,
                    &exit,
                    &known_path,
                    &HostKeyPolicy::Strict,
                    reporter,
                )?;
                let cancel = reporter.cancel_flag();
                orchestrator::remove_tunnel(&pair, &provider, &name, reporter, &cancel)?;
                reporter.payload(JobPayload::TunnelRemoved { instance_id: id });
                Ok(format!("Tunnel '{name}' was removed from both servers."))
            },
        );
        self.jobs.push(handle);
    }

    fn spawn_refresh(&mut self) {
        if self.state.tunnels.is_empty() || self.busy_with(JobKind::RefreshStatus) {
            return;
        }
        let Ok(relay) = self.credentials(TunnelSide::Client) else {
            return;
        };
        let Ok(exit) = self.credentials(TunnelSide::Server) else {
            return;
        };
        let provider = self.provider.clone();
        let known_path = self.known_hosts_path();
        let tunnels = self.state.tunnels.clone();

        let handle = jobs::spawn(
            JobKind::RefreshStatus,
            "Refreshing tunnel status",
            move |reporter| {
                let pair = orchestrator::connect_pair(
                    &relay,
                    &exit,
                    &known_path,
                    &HostKeyPolicy::Strict,
                    reporter,
                )?;
                let mut statuses = Vec::with_capacity(tunnels.len());
                for instance in &tunnels {
                    reporter.check()?;
                    statuses.push(orchestrator::tunnel_status(
                        &pair, &provider, instance, true,
                    ));
                }
                reporter.payload(JobPayload::Status(statuses));
                Ok(String::new())
            },
        );
        self.jobs.push(handle);
    }

    fn spawn_remote_logs(&mut self) {
        let Some(instance_id) = self.logs_ui.remote_instance.clone() else {
            return;
        };
        if self.busy_with(JobKind::FetchLogs) {
            return;
        }
        let Some(instance) = self.state.tunnel(&instance_id).cloned() else {
            return;
        };
        let side = self.logs_ui.remote_side;
        let cursor = self
            .logs_ui
            .remote_cursor
            .get(&(instance_id.clone(), side))
            .cloned();

        let creds = match side {
            TunnelSide::Client => self.credentials(TunnelSide::Client),
            TunnelSide::Server => self.credentials(TunnelSide::Server),
        };
        let Ok(credentials) = creds else {
            return;
        };

        let provider = self.provider.clone();
        let known_path = self.known_hosts_path();
        let lines = self.state.settings.log_lines.clamp(50, 2000);
        let name = instance.plan.instance.clone();
        let unit = provider.service_name(&name);

        self.logs_ui.last_remote_poll = Some(Instant::now());

        let handle = jobs::spawn(JobKind::FetchLogs, "Reading the journal", move |reporter| {
            // Only one host is involved, so this connects to just that one
            // rather than going through `connect_pair`.
            let mut known = KnownHosts::load(&known_path)?;
            let client = htm_core::ssh::SshClient::connect(
                &credentials,
                &mut known,
                &HostKeyPolicy::Strict,
            )?;
            let chunk =
                htm_core::remote::systemd::journal(&client, &unit, lines, cursor.as_deref())?;
            reporter.payload(JobPayload::Logs {
                instance_id,
                side,
                lines: chunk.lines,
                cursor: chunk.cursor,
            });
            Ok(String::new())
        });
        self.jobs.push(handle);
    }

    // ── Wizard ──────────────────────────────────────────────────────────────

    fn open_wizard(&mut self, from_variant: Option<String>) {
        let mut options = self.provider.default_options();
        let mut source_variant = None;
        let mut expected = (None, None, None);

        if let (Some(variant_id), Some(run)) = (&from_variant, &self.bench_ui.current) {
            if let Some(result) = run
                .results
                .iter()
                .find(|r| &r.variant.id == variant_id)
            {
                options = result.variant.options.clone();
                source_variant = Some(result.variant.label.clone());
                if let Some(m) = result.outcome.metrics() {
                    expected = (
                        Some(m.uplink_bps),
                        Some(m.downlink_bps),
                        Some(m.latency_avg_ms),
                    );
                }
            }
        }

        let used = self.state.used_instance_names();
        let mut name = "main".to_string();
        let mut n = 2;
        while used.contains(&name) {
            name = format!("tunnel{n}");
            n += 1;
        }

        // Keep new tunnels off ports already in use by existing ones.
        let used_ports = self.state.used_data_ports();
        let mut data_port = 8443u16;
        while used_ports.contains(&data_port) && data_port < 65000 {
            data_port += 1;
        }

        self.wizard = WizardUi {
            open: true,
            name,
            data_port,
            pre_shared_key: util::generate_psk(),
            options,
            source_variant,
            expected_up: expected.0,
            expected_down: expected.1,
            expected_latency: expected.2,
            ..WizardUi::default()
        };
    }

    /// Turn the wizard's fields into plan inputs, or explain what is wrong.
    pub fn wizard_inputs(&self) -> Result<PlanInputs, String> {
        let relay = self
            .state
            .server(TunnelSide::Client)
            .cloned()
            .ok_or("No relay server is configured.")?;
        let exit = self
            .state
            .server(TunnelSide::Server)
            .cloned()
            .ok_or("No exit server is configured.")?;

        let name = util::sanitize_instance_name(&self.wizard.name)
            .ok_or("The tunnel name must contain a letter or digit.")?;
        if self
            .state
            .tunnels
            .iter()
            .any(|t| t.plan.instance == name)
        {
            return Err(format!(
                "A tunnel named '{name}' already exists. Pick a different name."
            ));
        }

        let forward_ports = util::parse_port_list(&self.wizard.forward_ports_text)?;

        if self.wizard.pre_shared_key.len() < 16 {
            return Err("The pre-shared key must be at least 16 characters.".to_string());
        }

        // The two source-address modes. In forged mode the single list the
        // user typed is split between the two servers, because each side has
        // to claim addresses the other does not.
        let spoofing = if self.wizard.spoofing.is_forged() {
            let addresses = parse_address_list(&self.wizard.spoof_pool_text);
            if addresses.is_empty() {
                return Err(
                    "Forged mode is selected but no addresses were given. Enter at least two, \
                     or switch back to using the servers' own addresses."
                        .to_string(),
                );
            }
            let plan = SpoofPlan::from_list(&addresses);
            plan.validate()?;
            plan
        } else {
            SpoofPlan::default()
        };

        self.provider.validate_options(&self.wizard.options)?;

        let slot = TunSlot::first_free(&self.state.used_tun_slots());

        let mut inputs = PlanInputs::new(
            name,
            self.provider.id(),
            relay,
            exit,
            slot,
            self.wizard.options.clone(),
        );
        inputs.data_port = self.wizard.data_port;
        inputs.pre_shared_key = self.wizard.pre_shared_key.clone();
        inputs.forward_ports = forward_ports;
        inputs.mtu = self.wizard.mtu;
        inputs.tun_mtu = self.wizard.mtu;
        inputs.log_level = self.wizard.log_level.clone();
        inputs.spoofing = spoofing;

        Ok(inputs)
    }

    /// Render both sides of what the wizard currently describes.
    ///
    /// Split out from [`Self::preview_wizard`] so the rendering borrows `self`
    /// immutably and has finished by the time the result is stored.
    fn render_wizard_preview(&self) -> Result<(String, String), String> {
        let inputs = self.wizard_inputs()?;
        let plan = orchestrator::build_plan(&inputs).map_err(|e| e.to_string())?;

        let relay = self
            .provider
            .render(&plan, TunnelSide::Client)
            .map_err(|e| e.to_string())?;
        let exit = self
            .provider
            .render(&plan, TunnelSide::Server)
            .map_err(|e| e.to_string())?;

        let first_file = |rendered: &htm_core::provider::RenderedSide| {
            rendered
                .files
                .first()
                .map(|f| f.content.clone())
                .unwrap_or_default()
        };
        Ok((first_file(&relay), first_file(&exit)))
    }

    fn preview_wizard(&mut self) {
        match self.render_wizard_preview() {
            Ok(preview) => {
                self.wizard.preview = Some(preview);
                self.wizard.error = None;
            }
            Err(e) => {
                self.wizard.preview = None;
                self.wizard.error = Some(e);
            }
        }
    }

    fn preview_tunnel(&mut self, instance_id: &str, side: TunnelSide) {
        // Take an owned copy of the plan so nothing borrows the state while
        // the rendered text is stored back into the UI.
        let Some(plan) = self.state.tunnel(instance_id).map(|t| t.plan.clone()) else {
            return;
        };
        match self.provider.render(&plan, side) {
            Ok(rendered) => {
                let text = rendered
                    .files
                    .first()
                    .map(|f| f.content.clone())
                    .unwrap_or_default();
                self.tunnels_ui.preview = Some((instance_id.to_string(), side, text));
            }
            Err(e) => self.toast(LogLevel::Error, e.to_string()),
        }
    }

    // ── Periodic work ───────────────────────────────────────────────────────

    fn tick(&mut self) {
        // Automatic status refresh while the tunnels tab is open.
        let interval = self.state.settings.auto_refresh_secs;
        if interval > 0 && self.tab == Tab::Tunnels && !self.state.tunnels.is_empty() {
            let due = self
                .tunnels_ui
                .last_refresh
                .map(|t| t.elapsed() >= Duration::from_secs(interval as u64))
                .unwrap_or(true);
            if due && !self.busy_with(JobKind::RefreshStatus) {
                self.push(Action::RefreshStatuses);
            }
        }

        // Journal polling while the user is following a log.
        if self.logs_ui.follow_remote && self.logs_ui.remote_instance.is_some() {
            let due = self
                .logs_ui
                .last_remote_poll
                .map(|t| t.elapsed() >= Duration::from_millis(2500))
                .unwrap_or(true);
            if due && !self.busy_with(JobKind::FetchLogs) {
                self.push(Action::PollRemoteLogs);
            }
        }
    }
}

impl eframe::App for HtmApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // The theme is a stored preference; recomputing it every frame means
        // toggling it takes effect immediately.
        self.palette = Palette::for_theme(self.state.settings.dark_mode);
        crate::theme::apply(ctx, &self.palette);

        self.pump_jobs();
        self.tick();

        views::shell::show(self, ctx);

        self.run_actions();
        self.maybe_save();

        // A final write when the window is closing, so nothing typed in the
        // last two seconds is lost.
        if ctx.input(|i| i.viewport().close_requested()) && !self.saved_once {
            self.save();
        }

        // Keep animating while anything is in flight.
        if !self.jobs.is_empty() || !self.toasts.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
    }
}

/// Split a free-text list of IPv4 addresses on commas and whitespace.
///
/// Shared by the wizard's validation and its live preview so the two can never
/// disagree about what the user typed.
pub fn parse_address_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}
