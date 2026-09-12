//! UI-side state: which tab is open, what is typed into the wizard, what the
//! tables are sorted by. None of this is persisted except where it is copied
//! into `htm_core::store::AppState`.

use std::collections::HashMap;

use htm_core::model::{
    BenchRun, MatrixSelection, OptionMap, ServerSecrets, SpoofPlan, TunnelSide, TunnelStatus,
};
use htm_core::provider::InstalledVersion;

/// Top-level navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tab {
    Servers,
    Install,
    Benchmark,
    Tunnels,
    Logs,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Servers,
        Tab::Install,
        Tab::Benchmark,
        Tab::Tunnels,
        Tab::Logs,
        Tab::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Servers => "Servers",
            Tab::Install => "Install",
            Tab::Benchmark => "Benchmark",
            Tab::Tunnels => "Tunnels",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
        }
    }

    /// One line explaining what the tab is for, shown under its heading.
    pub fn subtitle(self) -> &'static str {
        match self {
            Tab::Servers => {
                "Enter the SSH details for both VPS hosts and check that HTM can reach them."
            }
            Tab::Install => "Put the tunnel software on both servers.",
            Tab::Benchmark => {
                "Measure real configurations across the real link, then pick the one you want."
            }
            Tab::Tunnels => "Create, control and watch the tunnels you have deployed.",
            Tab::Logs => "HTM's own activity log, and the journal from either server.",
            Tab::Settings => "Preferences, stored credentials and pinned host keys.",
        }
    }

    pub fn step_number(self) -> Option<u8> {
        match self {
            Tab::Servers => Some(1),
            Tab::Install => Some(2),
            Tab::Benchmark => Some(3),
            Tab::Tunnels => Some(4),
            _ => None,
        }
    }
}

/// Which column the benchmark results are ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchSort {
    Score,
    Uplink,
    Downlink,
    Latency,
    Jitter,
    Loss,
    Handshake,
    Label,
}

impl BenchSort {
    pub const ALL: [BenchSort; 8] = [
        BenchSort::Score,
        BenchSort::Uplink,
        BenchSort::Downlink,
        BenchSort::Latency,
        BenchSort::Jitter,
        BenchSort::Loss,
        BenchSort::Handshake,
        BenchSort::Label,
    ];

    pub fn title(self) -> &'static str {
        match self {
            BenchSort::Score => "Score",
            BenchSort::Uplink => "Up",
            BenchSort::Downlink => "Down",
            BenchSort::Latency => "Latency",
            BenchSort::Jitter => "Jitter",
            BenchSort::Loss => "Loss",
            BenchSort::Handshake => "Startup",
            BenchSort::Label => "Configuration",
        }
    }

    /// True when a larger value is the better one.
    pub fn higher_is_better(self) -> bool {
        matches!(self, BenchSort::Score | BenchSort::Uplink | BenchSort::Downlink)
    }
}

/// State for the servers tab.
#[derive(Debug, Default)]
pub struct ServersUi {
    /// Secrets being edited, keyed by server profile id. Mirrors the vault.
    pub secrets: HashMap<String, ServerSecrets>,
    /// Expanded state of the proxy section, per side.
    pub show_proxy: HashMap<String, bool>,
    /// Expanded state of the advanced overrides, per side.
    pub show_advanced: HashMap<String, bool>,
    /// Last probe result per server id, for the facts panel.
    pub last_error: HashMap<String, String>,
}

impl ServersUi {
    /// The expander flag for one server, created as false the first time it is
    /// asked for. An associated function rather than a method so the caller can
    /// borrow two of these maps at once.
    pub fn flag(map: &mut HashMap<String, bool>, id: &str) -> &mut bool {
        map.entry(id.to_string()).or_insert(false)
    }
}

/// State for the install tab.
#[derive(Debug, Default)]
pub struct InstallUi {
    /// Versions detected or installed, per side.
    pub versions: HashMap<TunnelSide, InstalledVersion>,
    /// Whether to install iperf3 and python3 at the same time.
    pub with_benchmark_tools: bool,
    pub last_error: Option<String>,
}

/// State for the benchmark tab.
#[derive(Debug)]
pub struct BenchUi {
    /// Which values are selected for each swept dimension.
    pub selection: MatrixSelection,
    /// The preset last applied, for the combo box.
    pub preset_id: String,
    /// The run currently displayed, whether live or from history.
    pub current: Option<BenchRun>,
    /// Index into `state.bench_runs` when viewing history; `None` means live.
    pub history_index: Option<usize>,
    pub sort: BenchSort,
    pub sort_descending: bool,
    /// Variant id of the row whose details are open.
    pub selected_variant: Option<String>,
    pub show_settings: bool,
    pub show_matrix: bool,
    /// Hide rows that did not complete.
    pub hide_failed: bool,
    /// Expansion of `selection`, cached so the matrix is not re-expanded on
    /// every frame. The exhaustive preset crosses hundreds of combinations,
    /// which is cheap once and wasteful sixty times a second.
    pub preview_variants: Vec<htm_core::model::BenchVariant>,
    cached_for: Option<MatrixSelection>,
}

impl BenchUi {
    /// Recompute the variant preview if the selection changed.
    pub fn refresh_preview(&mut self, provider: &htm_core::provider::ProviderRef) {
        if self.cached_for.as_ref() == Some(&self.selection) {
            return;
        }
        self.preview_variants = provider.expand_variants(&self.selection);
        self.cached_for = Some(self.selection.clone());
    }

    /// Force the next `refresh_preview` to recompute, e.g. after the provider
    /// changed.
    pub fn invalidate_preview(&mut self) {
        self.cached_for = None;
    }
}

impl Default for BenchUi {
    fn default() -> Self {
        Self {
            selection: MatrixSelection::default(),
            preset_id: "transports-mux".to_string(),
            current: None,
            history_index: None,
            sort: BenchSort::Score,
            sort_descending: true,
            selected_variant: None,
            show_settings: false,
            show_matrix: true,
            hide_failed: false,
            preview_variants: Vec::new(),
            cached_for: None,
        }
    }
}

/// A short history of traffic counters, so the tunnel card can draw a
/// sparkline without asking the server for history it does not keep.
#[derive(Debug, Default, Clone)]
pub struct TrafficHistory {
    /// Bytes per second, most recent last.
    pub samples: Vec<f64>,
    last_total: Option<u64>,
    last_at: Option<std::time::Instant>,
}

impl TrafficHistory {
    pub const CAPACITY: usize = 60;

    /// Feed a cumulative byte counter; the rate is derived from the delta.
    pub fn push_total(&mut self, total: u64) {
        let now = std::time::Instant::now();
        if let (Some(prev), Some(at)) = (self.last_total, self.last_at) {
            let seconds = now.duration_since(at).as_secs_f64();
            if seconds > 0.05 {
                // A counter that went backwards means the interface was
                // recreated; start the series again rather than drawing a
                // meaningless spike.
                let rate = if total >= prev {
                    (total - prev) as f64 * 8.0 / seconds
                } else {
                    0.0
                };
                self.samples.push(rate);
                if self.samples.len() > Self::CAPACITY {
                    let excess = self.samples.len() - Self::CAPACITY;
                    self.samples.drain(..excess);
                }
            }
        }
        self.last_total = Some(total);
        self.last_at = Some(now);
    }

    pub fn latest(&self) -> f64 {
        self.samples.last().copied().unwrap_or(0.0)
    }
}

/// State for the tunnels tab.
#[derive(Debug, Default)]
pub struct TunnelsUi {
    /// Latest status per instance id.
    pub statuses: HashMap<String, TunnelStatus>,
    /// Traffic history per instance id.
    pub traffic: HashMap<String, TrafficHistory>,
    /// Which tunnel's details are expanded.
    pub expanded: Option<String>,
    /// Rendered configuration being previewed, if any.
    pub preview: Option<(String, TunnelSide, String)>,
    pub last_refresh: Option<std::time::Instant>,
    pub last_error: Option<String>,
}

/// The new-tunnel wizard.
#[derive(Debug)]
pub struct WizardUi {
    pub open: bool,
    pub name: String,
    pub forward_ports_text: String,
    pub data_port: u16,
    pub mtu: u32,
    pub pre_shared_key: String,
    pub log_level: String,
    pub start_on_boot: bool,
    pub spoofing: SpoofPlan,
    pub spoof_pool_text: String,
    pub options: OptionMap,
    /// Variant this was seeded from, when it came from benchmark results.
    pub source_variant: Option<String>,
    pub expected_up: Option<f64>,
    pub expected_down: Option<f64>,
    pub expected_latency: Option<f64>,
    pub show_advanced: bool,
    pub preview: Option<(String, String)>,
    pub error: Option<String>,
}

impl Default for WizardUi {
    fn default() -> Self {
        Self {
            open: false,
            name: "main".to_string(),
            forward_ports_text: String::new(),
            data_port: 8443,
            mtu: 1380,
            pre_shared_key: String::new(),
            log_level: "info".to_string(),
            start_on_boot: true,
            spoofing: SpoofPlan::default(),
            spoof_pool_text: String::new(),
            options: OptionMap::new(),
            source_variant: None,
            expected_up: None,
            expected_down: None,
            expected_latency: None,
            show_advanced: false,
            preview: None,
            error: None,
        }
    }
}

/// State for the logs tab.
#[derive(Debug)]
pub struct LogsUi {
    pub min_level: u8,
    pub filter: String,
    pub autoscroll: bool,
    /// Which tunnel's remote journal is being followed.
    pub remote_instance: Option<String>,
    pub remote_side: TunnelSide,
    /// Journal lines per (instance id, side).
    pub remote_lines: HashMap<(String, TunnelSide), Vec<String>>,
    /// Journal cursor per (instance id, side).
    pub remote_cursor: HashMap<(String, TunnelSide), String>,
    pub follow_remote: bool,
    pub last_remote_poll: Option<std::time::Instant>,
}

impl Default for LogsUi {
    fn default() -> Self {
        Self {
            min_level: 1,
            filter: String::new(),
            autoscroll: true,
            remote_instance: None,
            remote_side: TunnelSide::Client,
            remote_lines: HashMap::new(),
            remote_cursor: HashMap::new(),
            follow_remote: false,
            last_remote_poll: None,
        }
    }
}

/// State for the settings tab.
#[derive(Debug, Default)]
pub struct SettingsUi {
    pub new_master_password: String,
    pub confirm_master_password: String,
    pub vault_message: Option<String>,
    pub vault_error: Option<String>,
    pub show_known_hosts: bool,
}

/// A transient message shown in the corner.
#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub level: htm_core::jobs::LogLevel,
    pub created: std::time::Instant,
}

impl Toast {
    pub const LIFETIME: std::time::Duration = std::time::Duration::from_secs(6);

    pub fn new(level: htm_core::jobs::LogLevel, text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level,
            created: std::time::Instant::now(),
        }
    }

    pub fn expired(&self) -> bool {
        self.created.elapsed() > Self::LIFETIME
    }
}

/// A modal dialog that blocks the rest of the interface.
#[derive(Debug, Clone)]
pub enum Modal {
    /// The server presented a host key HTM has not seen before.
    HostKey {
        server_id: String,
        host: String,
        port: u16,
        key_type: String,
        sha256: String,
        md5: String,
        previous_sha256: Option<String>,
    },
    /// A destructive action needs confirming.
    Confirm {
        title: String,
        body: String,
        confirm_label: String,
        action: Box<ConfirmedAction>,
    },
    /// Something went wrong and deserves more than a toast.
    Error { title: String, body: String },
    /// The vault is locked and needs a master password.
    Unlock {
        password: String,
        error: Option<String>,
    },
}

/// What a confirmation dialog will do when accepted.
#[derive(Debug, Clone)]
pub enum ConfirmedAction {
    StopTunnel(String),
    RemoveTunnel(String),
    UninstallProvider,
    ClearVault,
    ForgetHostKey { host: String, port: u16 },
}
