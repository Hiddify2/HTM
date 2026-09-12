//! Everything HTM knows about a remote VPS.
//!
//! A [`ServerProfile`] holds only non-secret data and is what gets written to
//! `state.json`. Passwords and passphrases live separately in the encrypted
//! vault as [`ServerSecrets`], keyed by the profile id. The two are joined at
//! connect time into [`ServerCredentials`].

use serde::{Deserialize, Serialize};

/// Which end of the tunnel a server acts as.
///
/// The names mirror CandyTunnel's own `role` setting so the generated configs
/// read the same as the upstream documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelSide {
    /// The relay users actually connect to. It owns the forwarded ports and
    /// installs the iptables DNAT rules that push traffic into the tunnel.
    Client,
    /// The exit node the tunnel terminates on.
    Server,
}

impl TunnelSide {
    /// The literal written into a provider config file.
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelSide::Client => "client",
            TunnelSide::Server => "server",
        }
    }

    /// A label for the UI that explains the role rather than just naming it.
    pub fn display_name(self) -> &'static str {
        match self {
            TunnelSide::Client => "Client (relay / entry)",
            TunnelSide::Server => "Server (exit)",
        }
    }

    /// The opposite side.
    pub fn peer(self) -> TunnelSide {
        match self {
            TunnelSide::Client => TunnelSide::Server,
            TunnelSide::Server => TunnelSide::Client,
        }
    }

    /// Both sides, in the order operations should generally be applied:
    /// the exit is brought up first so the relay has something to reach.
    pub const ORDERED: [TunnelSide; 2] = [TunnelSide::Server, TunnelSide::Client];
}

/// How HTM authenticates to a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// Plain password authentication, falling back to keyboard-interactive
    /// when the server only offers that.
    Password,
    /// An OpenSSH private key file on this machine, optionally passphrase
    /// protected.
    PrivateKey,
    /// Whatever identities the local SSH agent holds.
    Agent,
}

impl AuthKind {
    pub fn display_name(self) -> &'static str {
        match self {
            AuthKind::Password => "Password",
            AuthKind::PrivateKey => "Private key file",
            AuthKind::Agent => "SSH agent",
        }
    }

    pub const ALL: [AuthKind; 3] = [AuthKind::Password, AuthKind::PrivateKey, AuthKind::Agent];
}

/// Proxy used to reach the SSH port. Optional, but frequently required when
/// the operator's own connection is filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyKind {
    /// Connect directly, no proxy.
    None,
    /// SOCKS5 with optional username/password auth (RFC 1928 / 1929).
    Socks5,
    /// SOCKS4a with an optional user id.
    Socks4,
    /// HTTP `CONNECT` with optional Basic auth.
    Http,
}

impl ProxyKind {
    pub fn display_name(self) -> &'static str {
        match self {
            ProxyKind::None => "No proxy (direct)",
            ProxyKind::Socks5 => "SOCKS5",
            ProxyKind::Socks4 => "SOCKS4a",
            ProxyKind::Http => "HTTP CONNECT",
        }
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, ProxyKind::None)
    }

    pub const ALL: [ProxyKind; 4] = [
        ProxyKind::None,
        ProxyKind::Socks5,
        ProxyKind::Socks4,
        ProxyKind::Http,
    ];
}

/// Non-secret half of the proxy settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Whether a proxy password is stored in the vault for this profile.
    #[serde(default)]
    pub has_password: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            kind: ProxyKind::None,
            host: String::new(),
            port: 1080,
            username: String::new(),
            has_password: false,
        }
    }
}

impl ProxyConfig {
    /// `host:port`, for log lines and error messages.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.kind.is_enabled() {
            return Ok(());
        }
        if self.host.trim().is_empty() {
            return Err("Proxy host must not be empty.".into());
        }
        if self.port == 0 {
            return Err("Proxy port must be between 1 and 65535.".into());
        }
        if self.kind == ProxyKind::Socks4 && self.has_password {
            return Err("SOCKS4a has no password authentication; clear the proxy password.".into());
        }
        Ok(())
    }
}

/// Which package manager the remote distribution uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Apk,
    Zypper,
    /// Nothing recognised; HTM will refuse to install packages and say so.
    ///
    /// This is the default so that a `ServerFacts` that has not been filled in
    /// yet cannot be mistaken for a host we know how to install on.
    #[default]
    Unknown,
}

impl PackageManager {
    pub fn display_name(self) -> &'static str {
        match self {
            PackageManager::Apt => "apt",
            PackageManager::Dnf => "dnf",
            PackageManager::Yum => "yum",
            PackageManager::Pacman => "pacman",
            PackageManager::Apk => "apk",
            PackageManager::Zypper => "zypper",
            PackageManager::Unknown => "unknown",
        }
    }
}

/// A snapshot of what a remote host looks like, gathered in one round trip.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerFacts {
    /// `ID` from `/etc/os-release`, e.g. `debian`, `ubuntu`, `almalinux`.
    pub os_id: String,
    /// `PRETTY_NAME` from `/etc/os-release`.
    pub os_pretty: String,
    /// `VERSION_ID` from `/etc/os-release`.
    pub os_version: String,
    /// `uname -r`.
    pub kernel: String,
    /// `uname -m`, normalised to `x86_64` / `aarch64` / ...
    pub arch: String,

    /// First `model name` line from `/proc/cpuinfo`.
    pub cpu_model: String,
    /// Logical CPU count.
    pub cpu_cores: u32,
    /// `MemTotal` in kibibytes.
    pub mem_total_kb: u64,

    /// The login user HTM authenticated as.
    pub login_user: String,
    /// True when that user is uid 0.
    pub is_root: bool,
    /// True when `sudo -n true` succeeded, i.e. no sudo password is needed.
    pub passwordless_sudo: bool,
    /// True when privileged commands are possible at all (root or working sudo).
    pub can_escalate: bool,

    /// Detected package manager.
    pub package_manager: PackageManager,
    /// True when `systemctl` is present and PID 1 is systemd.
    pub has_systemd: bool,

    /// Interface carrying the default route, e.g. `eth0`.
    pub default_iface: String,
    /// The IPv4 address configured on `default_iface`.
    pub local_ipv4: String,
    /// The address the outside world sees, discovered via an echo service.
    /// Equals `local_ipv4` on a directly-addressed VPS.
    pub public_ipv4: String,
    /// MTU of `default_iface`.
    pub iface_mtu: u32,

    /// `/dev/net/tun` exists or the `tun` module can be loaded.
    pub has_tun: bool,
    /// `iptables` is callable.
    pub has_iptables: bool,
    /// `iperf3` is installed.
    pub has_iperf3: bool,
    /// `python3` is installed (used by the bundled throughput probe).
    pub has_python3: bool,
    /// `curl` is installed.
    pub has_curl: bool,
    /// Free space on `/` in kibibytes.
    pub root_free_kb: u64,
    /// Uptime in seconds.
    pub uptime_secs: u64,
}

impl ServerFacts {
    /// A one-line summary for the server card.
    pub fn summary(&self) -> String {
        let mem_gb = self.mem_total_kb as f64 / 1024.0 / 1024.0;
        format!(
            "{} · {} · {} cores · {:.1} GiB RAM",
            if self.os_pretty.is_empty() {
                "unknown OS"
            } else {
                &self.os_pretty
            },
            self.arch,
            self.cpu_cores,
            mem_gb
        )
    }

    /// Problems that will block deployment, in the order worth fixing them.
    pub fn blockers(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.can_escalate {
            out.push(
                "No root access. Log in as root, or give the account sudo rights and supply \
                 the sudo password."
                    .to_string(),
            );
        }
        if !self.has_systemd {
            out.push(
                "systemd was not found. HTM manages tunnels as systemd units, so this host \
                 cannot be used."
                    .to_string(),
            );
        }
        if self.arch != "x86_64" {
            out.push(format!(
                "CPU architecture is '{}'. CandyTunnel publishes x86_64 Linux binaries only, \
                 so the binary must be built from source on this host.",
                self.arch
            ));
        }
        if !self.has_tun {
            out.push(
                "/dev/net/tun is missing. The host or container must expose the TUN device."
                    .to_string(),
            );
        }
        if !self.has_iptables {
            out.push(
                "iptables was not found. It is required for client-side port forwarding."
                    .to_string(),
            );
        }
        if self.package_manager == PackageManager::Unknown {
            out.push(
                "No supported package manager was detected, so HTM cannot install \
                 dependencies automatically."
                    .to_string(),
            );
        }
        out
    }

    /// Non-fatal remarks worth surfacing.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.public_ipv4.is_empty()
            && !self.local_ipv4.is_empty()
            && self.public_ipv4 != self.local_ipv4
        {
            out.push(format!(
                "This host is behind NAT: the interface holds {} but the internet sees {}. \
                 HTM uses the interface address for raw sockets and the public address as the \
                 peer target.",
                self.local_ipv4, self.public_ipv4
            ));
        }
        if self.mem_total_kb > 0 && self.mem_total_kb < 400_000 {
            out.push(
                "Less than 400 MiB of RAM. Building CandyTunnel from source will likely run \
                 out of memory; prefer the prebuilt binary."
                    .to_string(),
            );
        }
        if self.root_free_kb > 0 && self.root_free_kb < 300_000 {
            out.push("Less than 300 MiB free on /. Installation may fail.".to_string());
        }
        out
    }
}

/// The persisted, non-secret description of one server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerProfile {
    pub id: String,
    /// Free-form name shown in the UI.
    pub label: String,
    /// Which end of the tunnel this host is.
    pub side: TunnelSide,

    pub host: String,
    pub port: u16,
    pub username: String,

    pub auth_kind: AuthKind,
    /// Path on *this* machine to the private key, when `auth_kind` is
    /// [`AuthKind::PrivateKey`].
    #[serde(default)]
    pub private_key_path: String,
    /// Whether a login password is stored in the vault.
    #[serde(default)]
    pub has_password: bool,
    /// Whether a key passphrase is stored in the vault.
    #[serde(default)]
    pub has_key_passphrase: bool,
    /// Whether a sudo password is stored in the vault.
    #[serde(default)]
    pub has_sudo_password: bool,

    #[serde(default)]
    pub proxy: ProxyConfig,

    /// TCP + SSH handshake budget.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Per-command budget for ordinary remote commands.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_secs: u64,

    /// Override for the interface raw sockets bind to. Empty means "use the
    /// detected default route interface".
    #[serde(default)]
    pub iface_override: String,
    /// Override for the address written as `real_ip`. Empty means "detected".
    #[serde(default)]
    pub local_ip_override: String,
    /// Override for the address the peer dials. Empty means "detected".
    #[serde(default)]
    pub public_ip_override: String,

    /// Last successful probe, if any.
    #[serde(default)]
    pub facts: Option<ServerFacts>,
    #[serde(default)]
    pub last_checked: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_connect_timeout() -> u64 {
    20
}
fn default_command_timeout() -> u64 {
    120
}

impl ServerProfile {
    /// A fresh profile for the given side, with sensible defaults.
    pub fn new(side: TunnelSide) -> Self {
        Self {
            id: crate::util::new_id("srv"),
            label: match side {
                TunnelSide::Client => "Relay server".to_string(),
                TunnelSide::Server => "Exit server".to_string(),
            },
            side,
            host: String::new(),
            port: 22,
            username: "root".to_string(),
            auth_kind: AuthKind::Password,
            private_key_path: String::new(),
            has_password: false,
            has_key_passphrase: false,
            has_sudo_password: false,
            proxy: ProxyConfig::default(),
            connect_timeout_secs: default_connect_timeout(),
            command_timeout_secs: default_command_timeout(),
            iface_override: String::new(),
            local_ip_override: String::new(),
            public_ip_override: String::new(),
            facts: None,
            last_checked: None,
        }
    }

    /// `user@host:port`, for logs.
    pub fn endpoint(&self) -> String {
        format!("{}@{}:{}", self.username, self.host, self.port)
    }

    /// The interface raw sockets should bind to.
    pub fn effective_iface(&self) -> String {
        if !self.iface_override.trim().is_empty() {
            return self.iface_override.trim().to_string();
        }
        self.facts
            .as_ref()
            .map(|f| f.default_iface.clone())
            .unwrap_or_default()
    }

    /// The address to write as `real_ip` in the provider config: the address
    /// actually configured on the interface.
    pub fn effective_local_ip(&self) -> String {
        if !self.local_ip_override.trim().is_empty() {
            return self.local_ip_override.trim().to_string();
        }
        self.facts
            .as_ref()
            .map(|f| f.local_ipv4.clone())
            .unwrap_or_default()
    }

    /// The address the *peer* must send packets to.
    pub fn effective_public_ip(&self) -> String {
        if !self.public_ip_override.trim().is_empty() {
            return self.public_ip_override.trim().to_string();
        }
        if let Some(f) = &self.facts {
            if !f.public_ipv4.is_empty() {
                return f.public_ipv4.clone();
            }
            if !f.local_ipv4.is_empty() {
                return f.local_ipv4.clone();
            }
        }
        self.host.clone()
    }

    /// Validate everything that can be checked without touching the network.
    pub fn validate(&self) -> Result<(), String> {
        if self.host.trim().is_empty() {
            return Err(format!("{}: host must not be empty.", self.label));
        }
        if self.host.contains(char::is_whitespace) {
            return Err(format!("{}: host must not contain spaces.", self.label));
        }
        if self.port == 0 {
            return Err(format!("{}: SSH port must be 1-65535.", self.label));
        }
        if self.username.trim().is_empty() {
            return Err(format!("{}: username must not be empty.", self.label));
        }
        if self.auth_kind == AuthKind::PrivateKey && self.private_key_path.trim().is_empty() {
            return Err(format!(
                "{}: a private key file path is required for key authentication.",
                self.label
            ));
        }
        if self.auth_kind == AuthKind::PrivateKey {
            let p = std::path::Path::new(self.private_key_path.trim());
            if !p.is_file() {
                return Err(format!(
                    "{}: private key file '{}' does not exist.",
                    self.label,
                    self.private_key_path.trim()
                ));
            }
        }
        self.proxy
            .validate()
            .map_err(|e| format!("{}: {e}", self.label))?;
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > 600 {
            return Err(format!(
                "{}: connect timeout must be 1-600 seconds.",
                self.label
            ));
        }
        Ok(())
    }
}

/// The secret half of a server profile. Never serialised into `state.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSecrets {
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub key_passphrase: String,
    #[serde(default)]
    pub sudo_password: String,
    #[serde(default)]
    pub proxy_password: String,
}

impl ServerSecrets {
    pub fn is_empty(&self) -> bool {
        self.password.is_empty()
            && self.key_passphrase.is_empty()
            && self.sudo_password.is_empty()
            && self.proxy_password.is_empty()
    }
}

/// A profile joined with its secrets — what the SSH layer actually needs.
#[derive(Debug, Clone)]
pub struct ServerCredentials {
    pub profile: ServerProfile,
    pub secrets: ServerSecrets,
}

impl ServerCredentials {
    pub fn new(profile: ServerProfile, secrets: ServerSecrets) -> Self {
        Self { profile, secrets }
    }

    /// The password used for `sudo -S`. Falls back to the login password,
    /// which is what it is on the overwhelming majority of setups.
    pub fn sudo_password(&self) -> &str {
        if !self.secrets.sudo_password.is_empty() {
            &self.secrets.sudo_password
        } else {
            &self.secrets.password
        }
    }
}

/// A pinned SSH host key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyRecord {
    pub host: String,
    pub port: u16,
    pub key_type: String,
    /// Base64 of the raw key blob.
    pub key_base64: String,
    /// OpenSSH-style base64 SHA-256 fingerprint, without the `SHA256:` prefix.
    pub sha256: String,
    pub first_seen: chrono::DateTime<chrono::Utc>,
}

impl HostKeyRecord {
    /// The key used to look a record up.
    pub fn lookup_key(host: &str, port: u16) -> String {
        format!("{host}:{port}")
    }

    pub fn key(&self) -> String {
        Self::lookup_key(&self.host, self.port)
    }
}
