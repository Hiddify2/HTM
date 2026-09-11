//! The operations the GUI actually invokes: connect to a pair of servers,
//! install a provider on both, deploy a tunnel, control it, watch it, remove
//! it.
//!
//! Everything here is provider-agnostic. Ordering rules that matter are
//! encoded once, in one place: the exit node is always brought up before the
//! relay and taken down after it, because the relay's handshake needs
//! something to reach.

pub mod bench;

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::jobs::{JobPayload, LogLevel, Reporter};
use crate::model::{
    OptionMap, ServerCredentials, ServerFacts, ServerProfile, ServiceAction, ServiceStatus,
    SpoofPlan, TunSlot, TunnelInstance, TunnelPlan, TunnelSide, TunnelStatus,
};
use crate::provider::{HostCtx, InstallMethod, InstalledVersion, ProviderRef};
use crate::remote::{facts, net, pkg, systemd};
use crate::ssh::{HostKeyPolicy, KnownHosts, SshClient};
use crate::util;

/// Both ends of a tunnel, connected and identified.
#[derive(Debug)]
pub struct Pair {
    relay: SshClient,
    exit: SshClient,
    relay_facts: ServerFacts,
    exit_facts: ServerFacts,
    relay_label: String,
    exit_label: String,
}

impl Pair {
    /// The SSH connection for one side.
    pub fn client(&self, side: TunnelSide) -> &SshClient {
        match side {
            TunnelSide::Client => &self.relay,
            TunnelSide::Server => &self.exit,
        }
    }

    pub fn facts(&self, side: TunnelSide) -> &ServerFacts {
        match side {
            TunnelSide::Client => &self.relay_facts,
            TunnelSide::Server => &self.exit_facts,
        }
    }

    pub fn label(&self, side: TunnelSide) -> &str {
        match side {
            TunnelSide::Client => &self.relay_label,
            TunnelSide::Server => &self.exit_label,
        }
    }

    /// Build the per-host context a provider operates through.
    pub fn ctx<'a>(
        &'a self,
        side: TunnelSide,
        reporter: &'a dyn Reporter,
        cancel: &'a Arc<AtomicBool>,
    ) -> HostCtx<'a> {
        HostCtx {
            client: self.client(side),
            facts: self.facts(side),
            side,
            scope: self.label(side),
            reporter,
            cancel,
        }
    }
}

/// Connect to one server and probe it.
pub fn connect_one(
    credentials: &ServerCredentials,
    known_hosts_path: &Path,
    policy: &HostKeyPolicy,
    reporter: &dyn Reporter,
    discover_public_ip: bool,
) -> Result<(SshClient, ServerFacts)> {
    let label = credentials.profile.label.clone();
    let mut known = KnownHosts::load(known_hosts_path)?;

    reporter.log_line(
        LogLevel::Info,
        Some(&label),
        &format!("Connecting to {}.", credentials.profile.endpoint()),
    );
    if credentials.profile.proxy.kind.is_enabled() {
        reporter.log_line(
            LogLevel::Info,
            Some(&label),
            &format!(
                "Via {} proxy {}.",
                credentials.profile.proxy.kind.display_name(),
                credentials.profile.proxy.endpoint()
            ),
        );
    }

    let client = SshClient::connect(credentials, &mut known, policy)?;

    reporter.log_line(
        LogLevel::Success,
        Some(&label),
        &format!(
            "Connected. Host key SHA256:{} ({}), privileges: {}.",
            client.host_key_sha256(),
            client.host_key_type(),
            client.priv_mode().describe()
        ),
    );

    reporter.check()?;
    reporter.log_line(LogLevel::Info, Some(&label), "Probing the host.");
    let facts = facts::gather(&client, discover_public_ip)?;
    reporter.log_line(LogLevel::Info, Some(&label), &facts.summary());

    for warning in facts.warnings() {
        reporter.log_line(LogLevel::Warn, Some(&label), &warning);
    }
    for blocker in facts.blockers() {
        reporter.log_line(LogLevel::Error, Some(&label), &blocker);
    }

    Ok((client, facts))
}

/// Connect to both servers, exit node first.
pub fn connect_pair(
    relay: &ServerCredentials,
    exit: &ServerCredentials,
    known_hosts_path: &Path,
    policy: &HostKeyPolicy,
    reporter: &dyn Reporter,
) -> Result<Pair> {
    let (exit_client, exit_facts) =
        connect_one(exit, known_hosts_path, policy, reporter, true)?;
    reporter.check()?;
    let (relay_client, relay_facts) =
        connect_one(relay, known_hosts_path, policy, reporter, true)?;

    Ok(Pair {
        relay: relay_client,
        exit: exit_client,
        relay_facts,
        exit_facts,
        relay_label: relay.profile.label.clone(),
        exit_label: exit.profile.label.clone(),
    })
}

/// Refuse to go further when a host cannot run a tunnel at all.
pub fn assert_deployable(pair: &Pair) -> Result<()> {
    for side in TunnelSide::ORDERED {
        let blockers = pair.facts(side).blockers();
        if !blockers.is_empty() {
            return Err(Error::Unsupported {
                detail: format!("{}: {}", pair.label(side), blockers.join(" ")),
            });
        }
    }
    Ok(())
}

/// Ensure the provider and HTM's own prerequisites are installed on both hosts.
pub fn install_on_pair(
    pair: &Pair,
    provider: &ProviderRef,
    method: InstallMethod,
    include_benchmark_tools: bool,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<Vec<(TunnelSide, InstalledVersion)>> {
    assert_deployable(pair)?;

    let mut out = Vec::new();
    let total = 2u32;

    for (index, side) in TunnelSide::ORDERED.into_iter().enumerate() {
        reporter.check()?;
        reporter.progress(index as u32, total);
        let label = pair.label(side).to_string();
        reporter.stage(&format!("Preparing {label}"));

        let ctx = pair.ctx(side, reporter, cancel);

        // Runtime prerequisites first: without `ip` and `iptables` the tunnel
        // cannot come up even if the binary installs perfectly.
        let mut wanted: Vec<&str> = pkg::RUNTIME_PACKAGES.to_vec();
        if include_benchmark_tools {
            wanted.extend_from_slice(pkg::BENCHMARK_PACKAGES);
        }
        let report = pkg::install(
            ctx.client,
            ctx.facts.package_manager,
            &wanted,
            &label,
            reporter,
            cancel,
        )?;
        if !report.is_ok() {
            let names: Vec<String> = report.failed.iter().map(|(p, _)| p.clone()).collect();
            reporter.log_line(
                LogLevel::Warn,
                Some(&label),
                &format!(
                    "These packages could not be installed: {}. HTM will continue, but features \
                     that need them will not work.",
                    names.join(", ")
                ),
            );
        }

        // TUN has to exist before a tunnel can be built on it.
        reporter.check()?;
        if !facts::ensure_tun_available(ctx.client)? {
            return Err(Error::Unsupported {
                detail: format!(
                    "{label}: /dev/net/tun is not available and the module could not be loaded. \
                     A container needs the TUN device passed through before it can run a tunnel."
                ),
            });
        }

        reporter.check()?;
        reporter.stage(&format!("Installing {} on {label}", provider.name()));

        let existing = provider.detect(&ctx)?;
        let version = match existing {
            Some(v) if method == InstallMethod::Auto => {
                reporter.log_line(
                    LogLevel::Success,
                    Some(&label),
                    &format!("{} is already installed: {}.", provider.name(), v.summary()),
                );
                v
            }
            _ => provider.install(&ctx, method)?,
        };

        out.push((side, version));
    }

    reporter.progress(total, total);
    Ok(out)
}

/// Everything needed to turn a choice of settings into a concrete tunnel.
#[derive(Debug, Clone)]
pub struct PlanInputs {
    pub instance: String,
    pub provider_id: String,
    pub relay: ServerProfile,
    pub exit: ServerProfile,
    pub tun_slot: TunSlot,
    pub data_port: u16,
    pub pre_shared_key: String,
    pub forward_ports: Vec<u16>,
    pub mtu: u32,
    pub tun_mtu: u32,
    pub log_level: String,
    pub spoofing: SpoofPlan,
    pub options: OptionMap,
}

impl PlanInputs {
    /// Reasonable defaults for a new tunnel between two known servers.
    pub fn new(
        instance: impl Into<String>,
        provider_id: impl Into<String>,
        relay: ServerProfile,
        exit: ServerProfile,
        tun_slot: TunSlot,
        options: OptionMap,
    ) -> Self {
        Self {
            instance: instance.into(),
            provider_id: provider_id.into(),
            relay,
            exit,
            tun_slot,
            data_port: 8443,
            pre_shared_key: util::generate_psk(),
            forward_ports: Vec::new(),
            mtu: 1380,
            tun_mtu: 1380,
            log_level: "info".to_string(),
            spoofing: SpoofPlan::default(),
            options,
        }
    }
}

/// Assemble a [`TunnelPlan`] from the two server profiles and the chosen
/// settings.
pub fn build_plan(inputs: &PlanInputs) -> Result<TunnelPlan> {
    let instance = util::sanitize_instance_name(&inputs.instance).ok_or_else(|| {
        Error::invalid(
            "The instance name must contain at least one letter, digit, dash or underscore.",
        )
    })?;

    // Catch an unusable address list before any of the per-side work, so the
    // message names the real problem rather than a symptom of it.
    inputs.spoofing.validate().map_err(Error::Validation)?;

    let mut endpoints = Vec::new();
    for (side, profile) in [
        (TunnelSide::Client, &inputs.relay),
        (TunnelSide::Server, &inputs.exit),
    ] {
        let iface = profile.effective_iface();
        let real_ip = profile.effective_local_ip();
        let public_ip = profile.effective_public_ip();

        if iface.is_empty() {
            return Err(Error::invalid(format!(
                "{}: the network interface is unknown. Test the connection first, or set an \
                 interface override.",
                profile.label
            )));
        }
        if real_ip.is_empty() {
            return Err(Error::invalid(format!(
                "{}: the interface address is unknown. Test the connection first, or set an \
                 address override.",
                profile.label
            )));
        }

        // In Original mode each side stamps its own real address, which is
        // what works on providers that filter forged source addresses. In
        // Forged mode it takes the first address from its own half of the
        // list; the rest of that half becomes its rotation pool.
        let spoofed_ip = match inputs.spoofing.primary_for(side) {
            Some(address) if inputs.spoofing.is_forged() => address.clone(),
            _ => real_ip.clone(),
        };

        endpoints.push(crate::model::EndpointPlan {
            side,
            iface,
            real_ip,
            public_ip,
            tun_ip: inputs.tun_slot.ip_for(side),
            spoofed_ip,
        });
    }

    let plan = TunnelPlan {
        instance: instance.clone(),
        provider_id: inputs.provider_id.clone(),
        client: endpoints[0].clone(),
        server: endpoints[1].clone(),
        tun_netmask: TunSlot::NETMASK.to_string(),
        tun_name: tun_name_for(inputs.tun_slot),
        data_port: inputs.data_port,
        pre_shared_key: inputs.pre_shared_key.clone(),
        forward_ports: inputs.forward_ports.clone(),
        mtu: inputs.mtu,
        tun_mtu: inputs.tun_mtu.min(inputs.mtu),
        log_level: inputs.log_level.clone(),
        spoofing: inputs.spoofing.clone(),
        options: inputs.options.clone(),
    };

    plan.validate().map_err(Error::Validation)?;
    Ok(plan)
}

/// The TUN interface name for a slot. Linux caps interface names at 15
/// characters, and these stay well inside that.
pub fn tun_name_for(slot: TunSlot) -> String {
    format!("candy{}", slot.0)
}

/// Deploy a plan to both hosts and start it.
///
/// Returns how long the tunnel took to start carrying traffic.
pub fn deploy_and_start(
    pair: &Pair,
    provider: &ProviderRef,
    plan: &TunnelPlan,
    enable_at_boot: bool,
    readiness_timeout: Duration,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<f64> {
    deploy_only(pair, provider, plan, reporter, cancel)?;

    reporter.check()?;
    reporter.stage("Starting");
    start_pair(pair, provider, plan, enable_at_boot, reporter)?;

    reporter.check()?;
    reporter.stage("Waiting for the tunnel to come up");
    let seconds = wait_until_ready(pair, provider, plan, readiness_timeout, reporter, cancel)?;
    reporter.log_line(
        LogLevel::Success,
        None,
        &format!("Tunnel '{}' is up after {seconds:.1}s.", plan.instance),
    );
    Ok(seconds)
}

/// Write the configuration and unit files on both hosts, without starting.
pub fn deploy_only(
    pair: &Pair,
    provider: &ProviderRef,
    plan: &TunnelPlan,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    reporter.stage("Writing configuration");
    for side in TunnelSide::ORDERED {
        reporter.check()?;
        let ctx = pair.ctx(side, reporter, cancel);
        provider.deploy(&ctx, plan)?;
    }
    Ok(())
}

/// Start both units, exit node first.
pub fn start_pair(
    pair: &Pair,
    provider: &ProviderRef,
    plan: &TunnelPlan,
    enable_at_boot: bool,
    reporter: &dyn Reporter,
) -> Result<()> {
    let unit = provider.service_name(&plan.instance);

    for side in ServiceAction::Start.side_order() {
        let label = pair.label(side);
        if enable_at_boot {
            if let Err(e) = systemd::control(pair.client(side), &unit, "enable") {
                reporter.log_line(
                    LogLevel::Warn,
                    Some(label),
                    &format!("Could not enable the unit for boot: {e}"),
                );
            }
        }
        systemd::control(pair.client(side), &unit, "start").map_err(|e| {
            Error::msg(format!("{label}: could not start {unit}: {e}"))
        })?;
        reporter.log_line(LogLevel::Info, Some(label), &format!("Started {unit}."));
    }
    Ok(())
}

/// Stop both units, relay first.
pub fn stop_pair(pair: &Pair, provider: &ProviderRef, instance: &str, reporter: &dyn Reporter) {
    let unit = provider.service_name(instance);
    for side in ServiceAction::Stop.side_order() {
        if let Err(e) = systemd::control(pair.client(side), &unit, "stop") {
            reporter.log_line(
                LogLevel::Debug,
                Some(pair.label(side)),
                &format!("Stopping {unit} reported: {e}"),
            );
        }
    }
}

/// Apply a control action to both sides of a tunnel, in the right order.
pub fn control_pair(
    pair: &Pair,
    provider: &ProviderRef,
    instance: &str,
    action: ServiceAction,
    reporter: &dyn Reporter,
) -> Result<()> {
    let unit = provider.service_name(instance);
    let mut failures: Vec<String> = Vec::new();

    for side in action.side_order() {
        let label = pair.label(side).to_string();
        match systemd::control(pair.client(side), &unit, action.verb()) {
            Ok(()) => reporter.log_line(
                LogLevel::Success,
                Some(&label),
                &format!("{} succeeded for {unit}.", action.verb()),
            ),
            Err(e) => {
                reporter.log_line(
                    LogLevel::Error,
                    Some(&label),
                    &format!("{} failed for {unit}: {e}", action.verb()),
                );
                failures.push(format!("{label}: {e}"));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::msg(failures.join("; ")))
    }
}

/// Poll until the tunnel actually carries traffic, or give up.
///
/// Being "active" in systemd's eyes is not enough: CandyTunnel reports active
/// while its handshake is still in progress, and a misconfigured pair can stay
/// active forever without passing a packet. The authoritative test is an ICMP
/// echo across the TUN link.
pub fn wait_until_ready(
    pair: &Pair,
    provider: &ProviderRef,
    plan: &TunnelPlan,
    timeout: Duration,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<f64> {
    let unit = provider.service_name(&plan.instance);
    let readiness = provider.readiness();
    let started = Instant::now();
    let target = &plan.server.tun_ip;

    let mut cursor: Option<String> = None;
    let mut last_note = Instant::now();

    while started.elapsed() < timeout {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }

        // A unit that has already failed will never become ready.
        for side in TunnelSide::ORDERED {
            let status = systemd::status(pair.client(side), &unit, None)?;
            if status.is_failed() {
                let logs = tail_journal(pair.client(side), &unit, 40);
                return Err(Error::msg(format!(
                    "{}: the tunnel unit failed to start.\n{}",
                    pair.label(side),
                    util::truncate(&logs, 1200)
                )));
            }
            if !status.exists() {
                return Err(Error::msg(format!(
                    "{}: the unit {unit} does not exist. The deployment did not complete.",
                    pair.label(side)
                )));
            }
        }

        // Look for a fatal message before spending the whole timeout.
        let chunk = systemd::journal(pair.client(TunnelSide::Client), &unit, 60, cursor.as_deref())
            .unwrap_or_default();
        cursor = chunk.cursor.clone();
        for line in &chunk.lines {
            for marker in &readiness.fatal_markers {
                if line.contains(marker.as_str()) {
                    return Err(Error::msg(format!(
                        "The relay reported a fatal error: {}",
                        util::truncate(line.trim(), 400)
                    )));
                }
            }
        }

        // The real test.
        if net::ping_once(pair.client(TunnelSide::Client), target, 2).unwrap_or(false) {
            return Ok(started.elapsed().as_secs_f64());
        }

        if last_note.elapsed() >= Duration::from_secs(10) {
            last_note = Instant::now();
            reporter.log_line(
                LogLevel::Debug,
                None,
                &format!(
                    "Still waiting for {target} to answer ({:.0}s elapsed).",
                    started.elapsed().as_secs_f64()
                ),
            );
        }

        std::thread::sleep(Duration::from_millis(1200));
    }

    let relay_logs = tail_journal(pair.client(TunnelSide::Client), &unit, 30);
    let exit_logs = tail_journal(pair.client(TunnelSide::Server), &unit, 30);
    Err(Error::Timeout {
        what: format!(
            "the tunnel to carry traffic.\n--- relay journal ---\n{}\n--- exit journal ---\n{}",
            util::truncate(&relay_logs, 1000),
            util::truncate(&exit_logs, 1000)
        ),
        seconds: timeout.as_secs(),
    })
}

/// Best-effort journal tail, for error reports.
pub fn tail_journal(client: &SshClient, unit: &str, lines: u32) -> String {
    systemd::journal(client, unit, lines, None)
        .map(|c| c.lines.join("\n"))
        .unwrap_or_else(|e| format!("(the journal could not be read: {e})"))
}

/// Current status of one tunnel on both hosts.
pub fn tunnel_status(
    pair: &Pair,
    provider: &ProviderRef,
    instance: &TunnelInstance,
    probe_link: bool,
) -> TunnelStatus {
    let unit = provider.service_name(&instance.plan.instance);
    let iface = Some(instance.plan.tun_name.as_str());

    let query = |side: TunnelSide| -> ServiceStatus {
        systemd::status(pair.client(side), &unit, iface).unwrap_or_else(|e| ServiceStatus {
            query_error: Some(e.to_string()),
            ..Default::default()
        })
    };

    let client_status = query(TunnelSide::Client);
    let server_status = query(TunnelSide::Server);

    let link_rtt_ms = if probe_link && client_status.is_active() && server_status.is_active() {
        net::ping(
            pair.client(TunnelSide::Client),
            &instance.plan.server.tun_ip,
            3,
            200,
            None,
        )
        .ok()
        .filter(|s| s.is_usable())
        .map(|s| s.avg_ms)
    } else {
        None
    };

    TunnelStatus {
        instance_id: instance.id.clone(),
        client: client_status,
        server: server_status,
        checked_at: chrono::Utc::now(),
        link_rtt_ms,
    }
}

/// Remove a tunnel from both hosts.
pub fn remove_tunnel(
    pair: &Pair,
    provider: &ProviderRef,
    instance: &str,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<()> {
    let mut failures = Vec::new();
    for side in ServiceAction::Stop.side_order() {
        let ctx = pair.ctx(side, reporter, cancel);
        if let Err(e) = provider.remove_instance(&ctx, instance) {
            failures.push(format!("{}: {e}", pair.label(side)));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::msg(failures.join("; ")))
    }
}

/// Read new journal lines for one side of a tunnel and report them.
pub fn fetch_logs(
    pair: &Pair,
    provider: &ProviderRef,
    instance_id: &str,
    instance_name: &str,
    side: TunnelSide,
    lines: u32,
    cursor: Option<&str>,
    reporter: &dyn Reporter,
) -> Result<()> {
    let unit = provider.service_name(instance_name);
    let chunk = systemd::journal(pair.client(side), &unit, lines, cursor)?;
    reporter.payload(JobPayload::Logs {
        instance_id: instance_id.to_string(),
        side,
        lines: chunk.lines,
        cursor: chunk.cursor,
    });
    Ok(())
}

/// Make sure the measurement tooling is present, choosing a backend.
///
/// Falls back to the bundled probe rather than failing, so a host where
/// packages cannot be installed can still be benchmarked.
pub fn prepare_measurement(
    pair: &Pair,
    prefer_iperf3: bool,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<net::Backend> {
    if prefer_iperf3 {
        let mut both_have_it = true;
        for side in TunnelSide::ORDERED {
            reporter.check()?;
            let client = pair.client(side);
            if client.has_command("iperf3")? {
                continue;
            }
            let label = pair.label(side).to_string();
            reporter.log_line(LogLevel::Info, Some(&label), "Installing iperf3.");
            let report = pkg::install(
                client,
                pair.facts(side).package_manager,
                &[pkg::logical::IPERF3],
                &label,
                reporter,
                cancel,
            );
            let installed = matches!(report, Ok(r) if r.is_ok())
                && client.has_command("iperf3").unwrap_or(false);
            if !installed {
                reporter.log_line(
                    LogLevel::Warn,
                    Some(&label),
                    "iperf3 is not available here, so HTM will use its own bundled probe instead.",
                );
                both_have_it = false;
            }
        }
        if both_have_it {
            return Ok(net::Backend::Iperf3);
        }
    }

    // The probe needs python3 on both hosts.
    for side in TunnelSide::ORDERED {
        reporter.check()?;
        let client = pair.client(side);
        let label = pair.label(side).to_string();
        if !client.has_command("python3")? {
            reporter.log_line(
                LogLevel::Info,
                Some(&label),
                "Installing python3 for the bundled throughput probe.",
            );
            let _ = pkg::install(
                client,
                pair.facts(side).package_manager,
                &[pkg::logical::PYTHON3],
                &label,
                reporter,
                cancel,
            );
            if !client.has_command("python3")? {
                return Err(Error::Unsupported {
                    detail: format!(
                        "{label}: neither iperf3 nor python3 is available, so throughput cannot \
                         be measured. Install one of them and try again."
                    ),
                });
            }
        }
        net::ensure_probe_installed(client)?;
    }

    Ok(net::Backend::Probe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AuthKind;

    fn profile(side: TunnelSide, iface: &str, ip: &str, public: &str) -> ServerProfile {
        let mut p = ServerProfile::new(side);
        p.host = public.to_string();
        p.username = "root".into();
        p.auth_kind = AuthKind::Password;
        p.iface_override = iface.to_string();
        p.local_ip_override = ip.to_string();
        p.public_ip_override = public.to_string();
        p
    }

    #[test]
    fn plans_place_each_side_on_its_own_tun_address() {
        let inputs = PlanInputs::new(
            "my tunnel",
            "candytunnel",
            profile(TunnelSide::Client, "eth0", "192.0.2.10", "192.0.2.10"),
            profile(TunnelSide::Server, "ens3", "198.51.100.5", "198.51.100.5"),
            TunSlot(3),
            OptionMap::new(),
        );
        let plan = build_plan(&inputs).expect("plan");
        assert_eq!(plan.instance, "my-tunnel");
        assert_eq!(plan.client.tun_ip, TunSlot(3).client_ip());
        assert_eq!(plan.server.tun_ip, TunSlot(3).server_ip());
        assert_eq!(plan.tun_name, "candy3");
        // Spoofing is off by default, so each side uses its own address.
        assert_eq!(plan.client.spoofed_ip, "192.0.2.10");
        assert_eq!(plan.server.spoofed_ip, "198.51.100.5");
    }

    #[test]
    fn a_missing_interface_is_caught_before_deployment() {
        let mut relay = profile(TunnelSide::Client, "", "192.0.2.10", "192.0.2.10");
        relay.iface_override = String::new();
        let inputs = PlanInputs::new(
            "t",
            "candytunnel",
            relay,
            profile(TunnelSide::Server, "ens3", "198.51.100.5", "198.51.100.5"),
            TunSlot(0),
            OptionMap::new(),
        );
        assert!(build_plan(&inputs).is_err());
    }

    #[test]
    fn two_servers_on_the_same_address_are_rejected() {
        let inputs = PlanInputs::new(
            "t",
            "candytunnel",
            profile(TunnelSide::Client, "eth0", "192.0.2.10", "192.0.2.10"),
            profile(TunnelSide::Server, "ens3", "192.0.2.10", "192.0.2.10"),
            TunSlot(0),
            OptionMap::new(),
        );
        assert!(build_plan(&inputs).is_err());
    }

    #[test]
    fn tun_names_fit_within_the_kernel_limit() {
        assert!(tun_name_for(TunSlot(TunSlot::MAX)).len() <= 15);
    }

    #[test]
    fn unnameable_instances_are_refused() {
        let inputs = PlanInputs::new(
            "!!!",
            "candytunnel",
            profile(TunnelSide::Client, "eth0", "192.0.2.10", "192.0.2.10"),
            profile(TunnelSide::Server, "ens3", "198.51.100.5", "198.51.100.5"),
            TunSlot(0),
            OptionMap::new(),
        );
        assert!(build_plan(&inputs).is_err());
    }
}
