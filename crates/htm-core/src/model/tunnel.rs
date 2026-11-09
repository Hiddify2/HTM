//! The description of a tunnel and its runtime state.
//!
//! A [`TunnelPlan`] is the complete, provider-agnostic recipe for one tunnel:
//! both endpoints, the point-to-point TUN addressing, the shared secret, the
//! forwarded ports and the provider's own settings. Rendering a plan into
//! actual config files is the provider's job; everything else in HTM works on
//! the plan.

use serde::{Deserialize, Serialize};

use super::options::OptionMap;
use super::server::TunnelSide;

/// Per-side addressing for one tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointPlan {
    pub side: TunnelSide,
    /// Interface raw sockets bind to, e.g. `eth0`.
    pub iface: String,
    /// The IPv4 configured on `iface`. Written as the provider's "real" address.
    pub real_ip: String,
    /// The address the peer must send packets to. Differs from `real_ip` only
    /// when the host sits behind NAT.
    pub public_ip: String,
    /// This side's address on the point-to-point TUN link.
    pub tun_ip: String,
    /// The forged source address this side stamps on outgoing packets. Equal
    /// to `real_ip` when faking is disabled.
    pub faked_ip: String,
}

impl EndpointPlan {
    /// The address the peer should treat as this side's source.
    pub fn peer_target(&self) -> &str {
        if self.public_ip.is_empty() {
            &self.real_ip
        } else {
            &self.public_ip
        }
    }
}

/// How each side fills in the source address of the packets it sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FakeMode {
    /// Each server sends packets from its own real address.
    ///
    /// This is what works on ordinary VPS hosting, because providers apply
    /// egress filtering (BCP 38) and silently drop packets whose source
    /// address does not belong to the customer.
    Original,
    /// Each server forges its source address from a list you supply.
    ///
    /// Traffic then appears to come from somewhere else entirely, which is the
    /// point on a network that fingerprints endpoints. It only works if
    /// *both* providers allow forged source addresses to leave their network.
    Forged,
}

impl FakeMode {
    pub fn display_name(self) -> &'static str {
        match self {
            FakeMode::Original => "Use the servers' own addresses",
            FakeMode::Forged => "Forge source addresses from a list",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            FakeMode::Original => {
                "Each server sends from its real address. This is the mode that works on \
                 ordinary VPS hosting, and it is the right choice unless you have specifically \
                 confirmed your providers do not filter outgoing source addresses."
            }
            FakeMode::Forged => {
                "Each server stamps an address from your list onto every packet it sends, and \
                 accepts the addresses the other side was given. Both providers must allow \
                 forged source addresses to leave their network, which most do not."
            }
        }
    }

    pub const ALL: [FakeMode; 2] = [FakeMode::Original, FakeMode::Forged];
}

/// Source-address settings for a tunnel.
///
/// In [`FakeMode::Forged`] the two sides must never claim the same address:
/// each end identifies its peer partly by the source address it sees, so a
/// shared address makes the two indistinguishable. The pools are therefore
/// kept separate, and [`FakePlan::from_list`] splits a single user-supplied
/// list between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakePlan {
    pub mode: FakeMode,
    /// Addresses the relay may send from. Empty in [`FakeMode::Original`].
    #[serde(default)]
    pub client_pool: Vec<String>,
    /// Addresses the exit may send from. Empty in [`FakeMode::Original`].
    #[serde(default)]
    pub server_pool: Vec<String>,
}

impl Default for FakePlan {
    fn default() -> Self {
        Self {
            mode: FakeMode::Original,
            client_pool: Vec::new(),
            server_pool: Vec::new(),
        }
    }
}

impl FakePlan {
    /// True when source addresses are being forged.
    pub fn is_forged(&self) -> bool {
        self.mode == FakeMode::Forged
    }

    /// Split one list of addresses between the two sides.
    ///
    /// Entries alternate, so a list of two gives each side one address and a
    /// list of four gives each side two to rotate between. Alternating rather
    /// than halving keeps the split stable when the user appends one more
    /// address: the first entry stays with the relay either way.
    pub fn from_list(addresses: &[String]) -> Self {
        let mut client_pool = Vec::new();
        let mut server_pool = Vec::new();
        for (index, address) in addresses.iter().enumerate() {
            if index % 2 == 0 {
                client_pool.push(address.clone());
            } else {
                server_pool.push(address.clone());
            }
        }
        Self {
            mode: FakeMode::Forged,
            client_pool,
            server_pool,
        }
    }

    /// The addresses one side may send from.
    pub fn pool_for(&self, side: TunnelSide) -> &[String] {
        match side {
            TunnelSide::Client => &self.client_pool,
            TunnelSide::Server => &self.server_pool,
        }
    }

    /// The address a side presents by default, before any rotation.
    pub fn primary_for(&self, side: TunnelSide) -> Option<&String> {
        self.pool_for(side).first()
    }

    /// Every address in the plan, in the order the user gave them.
    pub fn all_addresses(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut client = self.client_pool.iter();
        let mut server = self.server_pool.iter();
        loop {
            match (client.next(), server.next()) {
                (None, None) => break,
                (c, s) => {
                    if let Some(c) = c {
                        out.push(c.clone());
                    }
                    if let Some(s) = s {
                        out.push(s.clone());
                    }
                }
            }
        }
        out
    }

    /// Check the plan is usable, with a message explaining what to fix.
    pub fn validate(&self) -> Result<(), String> {
        if !self.is_forged() {
            return Ok(());
        }
        if self.client_pool.is_empty() || self.server_pool.is_empty() {
            return Err(
                "Forging source addresses needs at least two addresses: one for each server. \
                 Add another to the list."
                    .to_string(),
            );
        }
        for address in self.client_pool.iter().chain(self.server_pool.iter()) {
            if !is_ipv4(address) {
                return Err(format!("'{address}' is not a valid IPv4 address."));
            }
        }
        // The two sides identify each other partly by source address, so an
        // address appearing on both sides would make them ambiguous.
        for address in &self.client_pool {
            if self.server_pool.contains(address) {
                return Err(format!(
                    "'{address}' was given to both servers. Every address must be used by only \
                     one of them; remove the duplicate."
                ));
            }
        }
        let mut seen: Vec<&String> = Vec::new();
        for address in self.client_pool.iter().chain(self.server_pool.iter()) {
            if seen.contains(&address) {
                return Err(format!("'{address}' appears more than once in the list."));
            }
            seen.push(address);
        }
        Ok(())
    }
}

/// The complete recipe for one tunnel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelPlan {
    /// systemd instance name; also the config file stem. Sanitised.
    pub instance: String,
    /// Which provider renders and runs this tunnel.
    pub provider_id: String,

    pub client: EndpointPlan,
    pub server: EndpointPlan,

    /// Netmask of the point-to-point TUN link, normally a /30.
    pub tun_netmask: String,
    /// TUN interface name on both hosts.
    pub tun_name: String,
    /// Wire port for UDP/TCP transports.
    pub data_port: u16,
    /// Shared authentication secret. Rendered into both config files.
    pub pre_shared_key: String,
    /// Ports on the client host that are pushed through the tunnel. Empty
    /// means "forward everything", which the provider warns about.
    pub forward_ports: Vec<u16>,
    /// Wire MTU.
    pub mtu: u32,
    /// TUN MTU; clamped to `mtu` by the provider.
    pub tun_mtu: u32,
    pub log_level: String,

    #[serde(default)]
    pub faking: FakePlan,
    /// Provider-specific settings.
    #[serde(default)]
    pub options: OptionMap,
}

impl TunnelPlan {
    /// The endpoint description for one side.
    pub fn endpoint(&self, side: TunnelSide) -> &EndpointPlan {
        match side {
            TunnelSide::Client => &self.client,
            TunnelSide::Server => &self.server,
        }
    }

    /// Mutable access to one side's endpoint.
    pub fn endpoint_mut(&mut self, side: TunnelSide) -> &mut EndpointPlan {
        match side {
            TunnelSide::Client => &mut self.client,
            TunnelSide::Server => &mut self.server,
        }
    }

    /// Checks that do not need a network round trip.
    pub fn validate(&self) -> Result<(), String> {
        if self.instance.trim().is_empty() {
            return Err("Instance name must not be empty.".into());
        }
        if self.pre_shared_key.len() < 16 {
            return Err("Pre-shared key must be at least 16 characters.".into());
        }
        if self.data_port == 0 {
            return Err("Data port must be 1-65535.".into());
        }
        if self.mtu < 576 || self.mtu > 9000 {
            return Err("MTU must be between 576 and 9000.".into());
        }
        if self.tun_mtu < 576 || self.tun_mtu > self.mtu {
            return Err(format!(
                "TUN MTU must be between 576 and the wire MTU ({}).",
                self.mtu
            ));
        }
        for (side, ep) in [
            (TunnelSide::Client, &self.client),
            (TunnelSide::Server, &self.server),
        ] {
            let who = side.display_name();
            if ep.iface.trim().is_empty() {
                return Err(format!("{who}: network interface is unknown."));
            }
            for (what, value) in [
                ("real IP", &ep.real_ip),
                ("TUN IP", &ep.tun_ip),
                ("faked IP", &ep.faked_ip),
            ] {
                if !is_ipv4(value) {
                    return Err(format!("{who}: {what} '{value}' is not a valid IPv4 address."));
                }
            }
            if !ep.public_ip.is_empty() && !is_ipv4(&ep.public_ip) {
                return Err(format!(
                    "{who}: public IP '{}' is not a valid IPv4 address.",
                    ep.public_ip
                ));
            }
        }
        if self.client.tun_ip == self.server.tun_ip {
            return Err("Both sides were given the same TUN address.".into());
        }
        if !is_ipv4(&self.tun_netmask) {
            return Err(format!(
                "TUN netmask '{}' is not a valid IPv4 mask.",
                self.tun_netmask
            ));
        }
        if self.client.peer_target() == self.server.peer_target() {
            return Err(
                "Both servers resolve to the same public address; they must be distinct hosts."
                    .into(),
            );
        }
        self.faking.validate()?;
        if self.faking.is_forged() && self.client.faked_ip == self.server.faked_ip {
            return Err(
                "Both servers were given the same forged source address. Each needs its own."
                    .into(),
            );
        }
        Ok(())
    }
}

/// A very small IPv4 dotted-quad check. Deliberately strict: no leading zeros,
/// no whitespace, exactly four octets.
pub fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if p.len() > 1 && p.starts_with('0') {
            return false;
        }
        match p.parse::<u32>() {
            Ok(v) if v <= 255 => {}
            _ => return false,
        }
    }
    true
}

/// Point-to-point addressing for one tunnel.
///
/// Slot `n` yields `10.<54 + n>.21.1` for the exit and `10.<54 + n>.21.2` for
/// the relay, on a /30.
///
/// The hosts are always `.1` and `.2` of a `.0` network, and tunnels are told
/// apart by the **second** octet rather than by moving along within a subnet.
/// That is deliberate: addressing that only varied the low octets was found not
/// to work reliably in practice, while this layout does, and it matches the
/// shape of CandyTunnel's own example configuration. Counting up the second
/// octet gives 200 usable tunnels, which is far more than anyone will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunSlot(pub u16);

impl TunSlot {
    /// First octet of every tunnel address.
    pub const BASE_A: u8 = 10;
    /// Second octet of slot 0. Later slots count up from here.
    pub const BASE_B: u8 = 54;
    /// Third octet, the same for every slot.
    pub const BASE_C: u8 = 21;
    pub const NETMASK: &'static str = "255.255.255.252";

    /// Slot reserved for benchmark runs so it can never collide with a tunnel
    /// the user deployed.
    ///
    /// This is slot 0 — `10.54.21.x` — on purpose. The benchmark is the first
    /// thing that runs and the thing that has to work before anything else is
    /// worth doing, so it gets the addresses confirmed to work in practice.
    /// User tunnels count up from slot 1.
    pub const BENCHMARK: TunSlot = TunSlot(0);
    /// Highest usable slot: `10.254.21.x`.
    pub const MAX: u16 = 200;

    /// The second octet, which is what distinguishes one tunnel from another.
    pub fn second_octet(self) -> u8 {
        Self::BASE_B.saturating_add((self.0 % (Self::MAX + 1)) as u8)
    }

    /// `.1` — the exit side.
    pub fn server_ip(self) -> String {
        format!(
            "{}.{}.{}.1",
            Self::BASE_A,
            self.second_octet(),
            Self::BASE_C
        )
    }

    /// `.2` — the relay side.
    pub fn client_ip(self) -> String {
        format!(
            "{}.{}.{}.2",
            Self::BASE_A,
            self.second_octet(),
            Self::BASE_C
        )
    }

    /// The address of one side.
    pub fn ip_for(self, side: TunnelSide) -> String {
        match side {
            TunnelSide::Client => self.client_ip(),
            TunnelSide::Server => self.server_ip(),
        }
    }

    /// The network address, for display.
    pub fn network(self) -> String {
        format!(
            "{}.{}.{}.0/30",
            Self::BASE_A,
            self.second_octet(),
            Self::BASE_C
        )
    }

    /// The lowest slot not present in `used`.
    pub fn first_free(used: &[TunSlot]) -> TunSlot {
        let mut n: u16 = 0;
        while n <= Self::MAX {
            let candidate = TunSlot(n);
            if candidate != Self::BENCHMARK && !used.contains(&candidate) {
                return candidate;
            }
            n += 1;
        }
        TunSlot(0)
    }
}

/// A tunnel the user has deployed, as persisted in `state.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelInstance {
    pub id: String,
    /// Profile id of the relay host.
    pub client_server_id: String,
    /// Profile id of the exit host.
    pub server_server_id: String,
    /// The /30 slot this tunnel owns.
    pub tun_slot: u16,
    pub plan: TunnelPlan,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Label of the benchmark variant this configuration came from, when it
    /// was picked from benchmark results rather than hand-built.
    #[serde(default)]
    pub source_variant: Option<String>,
    /// Measured figures from the benchmark run that produced it, for later
    /// comparison against reality.
    #[serde(default)]
    pub expected_uplink_bps: Option<f64>,
    #[serde(default)]
    pub expected_downlink_bps: Option<f64>,
    #[serde(default)]
    pub expected_latency_ms: Option<f64>,
    #[serde(default)]
    pub notes: String,
    /// Whether the units were enabled to start at boot.
    #[serde(default = "default_true")]
    pub start_on_boot: bool,
}

fn default_true() -> bool {
    true
}

impl TunnelInstance {
    /// Profile id for one side.
    pub fn server_id(&self, side: TunnelSide) -> &str {
        match side {
            TunnelSide::Client => &self.client_server_id,
            TunnelSide::Server => &self.server_server_id,
        }
    }
}

/// systemd's view of one unit.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceStatus {
    /// `loaded`, `not-found`, `masked`, ...
    pub load_state: String,
    /// `active`, `inactive`, `failed`, `activating`, `deactivating`.
    pub active_state: String,
    /// `running`, `dead`, `exited`, `failed`, ...
    pub sub_state: String,
    /// `systemctl is-enabled` result.
    pub enabled: bool,
    pub pid: Option<u32>,
    pub memory_bytes: Option<u64>,
    /// Seconds since the unit entered its current active state.
    pub since_secs: Option<u64>,
    pub restarts: Option<u32>,
    /// Last recorded exit code, when the unit failed.
    pub exit_code: Option<i32>,
    /// TUN interface counters, when the interface exists.
    pub iface: Option<IfaceStats>,
    /// Populated when the status query itself failed.
    pub query_error: Option<String>,
}

impl ServiceStatus {
    pub fn is_active(&self) -> bool {
        self.active_state == "active"
    }
    pub fn is_failed(&self) -> bool {
        self.active_state == "failed"
    }
    pub fn exists(&self) -> bool {
        self.load_state == "loaded"
    }
}

/// Counters for a TUN interface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfaceStats {
    pub name: String,
    pub up: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub mtu: u32,
}

/// An overall verdict for a tunnel, derived from both units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Health {
    /// Both sides active.
    Up,
    /// One side active, the other not.
    Partial,
    /// Neither side active, and neither failed.
    Down,
    /// At least one side is in the failed state.
    Failed,
    /// Not queried yet, or the query itself failed.
    Unknown,
}

impl Health {
    pub fn label(self) -> &'static str {
        match self {
            Health::Up => "Running",
            Health::Partial => "Partial",
            Health::Down => "Stopped",
            Health::Failed => "Failed",
            Health::Unknown => "Unknown",
        }
    }
}

/// Both units' status plus the derived verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub instance_id: String,
    pub client: ServiceStatus,
    pub server: ServiceStatus,
    pub checked_at: chrono::DateTime<chrono::Utc>,
    /// Round-trip time measured across the TUN link, when it could be probed.
    #[serde(default)]
    pub link_rtt_ms: Option<f64>,
}

impl TunnelStatus {
    pub fn side(&self, side: TunnelSide) -> &ServiceStatus {
        match side {
            TunnelSide::Client => &self.client,
            TunnelSide::Server => &self.server,
        }
    }

    pub fn health(&self) -> Health {
        if self.client.query_error.is_some() && self.server.query_error.is_some() {
            return Health::Unknown;
        }
        if self.client.is_failed() || self.server.is_failed() {
            return Health::Failed;
        }
        match (self.client.is_active(), self.server.is_active()) {
            (true, true) => Health::Up,
            (false, false) => Health::Down,
            _ => Health::Partial,
        }
    }

    /// Total bytes moved across both TUN interfaces.
    pub fn total_bytes(&self) -> (u64, u64) {
        let mut rx = 0u64;
        let mut tx = 0u64;
        for s in [&self.client, &self.server] {
            if let Some(i) = &s.iface {
                rx = rx.saturating_add(i.rx_bytes);
                tx = tx.saturating_add(i.tx_bytes);
            }
        }
        (rx, tx)
    }
}

/// What a control action should do to a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    Enable,
    Disable,
}

impl ServiceAction {
    pub fn verb(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
            ServiceAction::Enable => "enable",
            ServiceAction::Disable => "disable",
        }
    }

    /// Bring the exit up before the relay, and take the relay down first.
    pub fn side_order(self) -> [TunnelSide; 2] {
        match self {
            ServiceAction::Stop | ServiceAction::Disable => {
                [TunnelSide::Client, TunnelSide::Server]
            }
            _ => [TunnelSide::Server, TunnelSide::Client],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_validation() {
        assert!(is_ipv4("10.0.0.1"));
        assert!(is_ipv4("255.255.255.252"));
        assert!(!is_ipv4("10.0.0"));
        assert!(!is_ipv4("10.0.0.256"));
        assert!(!is_ipv4("10.0.0.01"));
        assert!(!is_ipv4(" 10.0.0.1"));
    }

    #[test]
    fn slot_zero_is_the_known_good_pair() {
        // This exact pair is the one confirmed to work in practice, which is
        // why the benchmark claims it.
        assert_eq!(TunSlot(0).server_ip(), "10.54.21.1");
        assert_eq!(TunSlot(0).client_ip(), "10.54.21.2");
        assert_eq!(TunSlot(0).network(), "10.54.21.0/30");
    }

    #[test]
    fn further_tunnels_count_up_the_second_octet() {
        assert_eq!(TunSlot(1).server_ip(), "10.55.21.1");
        assert_eq!(TunSlot(1).client_ip(), "10.55.21.2");
        assert_eq!(TunSlot(2).server_ip(), "10.56.21.1");
    }

    #[test]
    fn every_slot_puts_the_hosts_at_dot_one_and_dot_two() {
        // The low octets never move: that is the whole point of the layout.
        for n in 0..=TunSlot::MAX {
            let slot = TunSlot(n);
            assert!(slot.server_ip().ends_with(".21.1"), "{}", slot.server_ip());
            assert!(slot.client_ip().ends_with(".21.2"), "{}", slot.client_ip());
            assert!(is_ipv4(&slot.server_ip()));
            assert!(is_ipv4(&slot.client_ip()));
        }
    }

    #[test]
    fn slots_never_collide() {
        let mut seen: Vec<String> = Vec::new();
        for n in 0..=TunSlot::MAX {
            let ip = TunSlot(n).server_ip();
            assert!(!seen.contains(&ip), "{ip} was handed out twice");
            seen.push(ip);
        }
    }

    #[test]
    fn first_free_skips_used_and_benchmark() {
        let used = vec![TunSlot(1), TunSlot(2)];
        assert_eq!(TunSlot::first_free(&used), TunSlot(3));

        // The benchmark slot is never handed to a user tunnel.
        let all: Vec<TunSlot> = (0..TunSlot::BENCHMARK.0).map(TunSlot).collect();
        assert_ne!(TunSlot::first_free(&all), TunSlot::BENCHMARK);
    }

    #[test]
    fn the_benchmark_gets_the_known_good_addresses() {
        // The benchmark gets the known-good pair; user tunnels start above it.
        assert_eq!(TunSlot::BENCHMARK.server_ip(), "10.54.21.1");
        assert_eq!(TunSlot::BENCHMARK.client_ip(), "10.54.21.2");
        assert_eq!(TunSlot::first_free(&[]), TunSlot(1));
    }
}
