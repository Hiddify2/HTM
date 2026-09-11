//! The benchmark engine.
//!
//! Each candidate configuration is deployed to the real pair of servers,
//! started, waited for, measured across the live tunnel and torn down again.
//! Nothing is simulated or extrapolated: the numbers are what the tunnel
//! actually did.
//!
//! Runs are strictly sequential. Measuring two configurations at once would
//! have them compete for the same link and produce numbers that mean nothing.
//!
//! Everything happens under a dedicated instance name on a reserved TUN slot,
//! so a benchmark can never disturb a tunnel the user deployed, and the
//! measurement instance is removed from both hosts when the run ends — however
//! it ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::jobs::{JobPayload, LogLevel, Reporter};
use crate::model::{
    score_results, BenchMetrics, BenchOutcome, BenchResult, BenchRun, BenchSettings, BenchVariant,
    MatrixSelection, ServerProfile, SpoofPlan, TunSlot, TunnelPlan, TunnelSide,
};
use crate::provider::ProviderRef;
use crate::remote::net::{self, Backend};
use crate::util;

use super::{build_plan, Pair, PlanInputs};

/// Instance name used for measurement. Distinct from anything a user would
/// pick, and removed when the run finishes.
pub const BENCH_INSTANCE: &str = "htm-benchmark";
/// Wire port for the measurement tunnel.
pub const BENCH_DATA_PORT: u16 = 8472;
/// Port the throughput tools listen on, inside the tunnel.
pub const MEASURE_PORT: u16 = 5301;
/// UDP datagram size, comfortably under the tunnel MTU so nothing fragments.
pub const UDP_DATAGRAM: u32 = 1200;

/// Everything the engine needs that is not a variant.
#[derive(Debug, Clone)]
pub struct BenchContext {
    pub relay: ServerProfile,
    pub exit: ServerProfile,
    pub provider_id: String,
    pub settings: BenchSettings,
    pub selection: MatrixSelection,
    /// Wire MTU used for every measurement, so variants stay comparable.
    pub mtu: u32,
}

impl BenchContext {
    pub fn new(
        relay: ServerProfile,
        exit: ServerProfile,
        provider_id: impl Into<String>,
        settings: BenchSettings,
        selection: MatrixSelection,
    ) -> Self {
        Self {
            relay,
            exit,
            provider_id: provider_id.into(),
            settings,
            selection,
            mtu: 1380,
        }
    }
}

/// Measure every variant and return the completed run.
///
/// The run is emitted through `reporter` after each variant so the UI can fill
/// its table as results arrive rather than waiting for the end.
pub fn run(
    pair: &Pair,
    provider: &ProviderRef,
    variants: Vec<BenchVariant>,
    ctx: &BenchContext,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<BenchRun> {
    ctx.settings.validate().map_err(Error::Validation)?;

    if variants.is_empty() {
        return Err(Error::Validation(
            "The benchmark matrix produced no configurations to measure. Select at least one \
             option to vary."
                .to_string(),
        ));
    }

    let mut run = BenchRun {
        id: util::new_id("bench"),
        provider_id: ctx.provider_id.clone(),
        settings: ctx.settings.clone(),
        selection: ctx.selection.clone(),
        results: variants.iter().cloned().map(BenchResult::pending).collect(),
        started_at: chrono::Utc::now(),
        finished_at: None,
        aborted_reason: None,
    };

    let total = variants.len() as u32;
    reporter.stage("Preparing measurement tools");
    let backend = super::prepare_measurement(
        pair,
        ctx.settings.tool == crate::model::ThroughputTool::PreferIperf3,
        reporter,
        cancel,
    )?;
    reporter.log_line(
        LogLevel::Info,
        None,
        &format!(
            "Measuring with {}. Estimated total time: {}.",
            backend.name(),
            util::human_duration_secs(
                (ctx.settings.seconds_per_variant() * variants.len() as f64) as u64
            )
        ),
    );

    // A single secret for the whole run: every variant is the same tunnel with
    // different settings, so the key never needs to change.
    let psk = util::generate_psk();
    let mut consecutive_failures = 0u32;

    for (index, variant) in variants.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            run.aborted_reason = Some("Cancelled.".to_string());
            for result in run.results.iter_mut().skip(index) {
                result.outcome = BenchOutcome::Cancelled;
            }
            break;
        }

        reporter.progress(index as u32, total);
        reporter.stage(&format!(
            "[{}/{}] {}",
            index + 1,
            total,
            variant.label
        ));

        run.results[index].outcome = BenchOutcome::Running;
        run.results[index].started_at = Some(chrono::Utc::now());
        reporter.payload(JobPayload::BenchProgress(Box::new(run.clone())));

        let started = Instant::now();
        let outcome = measure_variant(pair, provider, variant, ctx, &psk, backend, reporter, cancel);
        let elapsed = started.elapsed().as_secs_f64();

        // Whatever happened, leave nothing running before the next variant.
        super::stop_pair(pair, provider, BENCH_INSTANCE, reporter);

        run.results[index].elapsed_secs = elapsed;
        run.results[index].outcome = match outcome {
            Ok(metrics) => {
                consecutive_failures = 0;
                reporter.log_line(
                    LogLevel::Success,
                    None,
                    &format!(
                        "{}: up {} / down {} / {} / loss {:.2}%",
                        variant.label,
                        util::human_bits_per_sec(metrics.uplink_bps),
                        util::human_bits_per_sec(metrics.downlink_bps),
                        util::human_ms(metrics.latency_avg_ms),
                        metrics.effective_loss_pct(),
                    ),
                );
                BenchOutcome::Completed(metrics)
            }
            Err(Error::Cancelled) => {
                run.aborted_reason = Some("Cancelled.".to_string());
                BenchOutcome::Cancelled
            }
            Err(e) => {
                consecutive_failures += 1;
                reporter.log_line(
                    LogLevel::Warn,
                    None,
                    &format!("{}: {}", variant.label, util::truncate(&e.to_string(), 300)),
                );
                let excerpt = super::tail_journal(
                    pair.client(TunnelSide::Client),
                    &provider.service_name(BENCH_INSTANCE),
                    25,
                );
                BenchOutcome::Failed {
                    reason: e.to_string(),
                    log_excerpt: util::truncate(&excerpt, 4000),
                }
            }
        };

        reporter.payload(JobPayload::BenchProgress(Box::new(run.clone())));

        if matches!(run.results[index].outcome, BenchOutcome::Cancelled) {
            for result in run.results.iter_mut().skip(index + 1) {
                result.outcome = BenchOutcome::Cancelled;
            }
            break;
        }

        let limit = ctx.settings.abort_after_failures;
        if limit > 0 && consecutive_failures >= limit {
            let reason = format!(
                "Stopped after {consecutive_failures} configurations failed in a row. The \
                 servers are probably not able to reach each other at all; check the exit \
                 node's firewall and that both hosts allow raw IP traffic."
            );
            reporter.log_line(LogLevel::Error, None, &reason);
            run.aborted_reason = Some(reason);
            for result in run.results.iter_mut().skip(index + 1) {
                result.outcome = BenchOutcome::Skipped {
                    reason: "Run aborted after repeated failures.".to_string(),
                };
            }
            break;
        }
    }

    reporter.progress(total, total);
    reporter.stage("Cleaning up");
    cleanup(pair, provider, reporter, cancel);

    score_results(&mut run.results, &ctx.settings.weights);
    run.finished_at = Some(chrono::Utc::now());

    let completed = run.completed().count();
    reporter.log_line(
        if completed > 0 {
            LogLevel::Success
        } else {
            LogLevel::Error
        },
        None,
        &format!(
            "Benchmark finished: {completed} of {} configurations measured successfully.",
            run.results.len()
        ),
    );
    reporter.payload(JobPayload::BenchFinished(Box::new(run.clone())));

    Ok(run)
}

/// Build the plan used to measure one variant.
fn bench_plan(
    variant: &BenchVariant,
    ctx: &BenchContext,
    psk: &str,
) -> Result<TunnelPlan> {
    let mut inputs = PlanInputs::new(
        BENCH_INSTANCE,
        ctx.provider_id.clone(),
        ctx.relay.clone(),
        ctx.exit.clone(),
        TunSlot::BENCHMARK,
        variant.options.clone(),
    );
    inputs.data_port = BENCH_DATA_PORT;
    inputs.pre_shared_key = psk.to_string();
    // No port forwarding during measurement: iptables DNAT rules on the relay
    // would capture the measurement traffic itself.
    inputs.forward_ports = Vec::new();
    inputs.mtu = ctx.mtu;
    inputs.tun_mtu = ctx.mtu;
    // `warn` keeps the journal readable while still showing real problems;
    // `debug` on a fast link produces enough output to affect the result.
    inputs.log_level = "warn".to_string();
    inputs.spoofing = SpoofPlan::default();

    build_plan(&inputs)
}

/// Deploy, start, measure and tear down one variant.
#[allow(clippy::too_many_arguments)]
fn measure_variant(
    pair: &Pair,
    provider: &ProviderRef,
    variant: &BenchVariant,
    ctx: &BenchContext,
    psk: &str,
    backend: Backend,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<BenchMetrics> {
    let plan = bench_plan(variant, ctx, psk)?;
    let repeats = ctx.settings.repeats.max(1);
    let mut best: Option<BenchMetrics> = None;
    let mut last_error: Option<Error> = None;

    for attempt in 1..=repeats {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if repeats > 1 {
            reporter.log_line(
                LogLevel::Debug,
                None,
                &format!("{}: attempt {attempt} of {repeats}", variant.label),
            );
        }

        // Start clean; a previous attempt may have left the unit running.
        super::stop_pair(pair, provider, BENCH_INSTANCE, reporter);

        match measure_once(pair, provider, &plan, ctx, backend, reporter, cancel) {
            Ok(metrics) => {
                let better = match &best {
                    None => true,
                    Some(current) => metrics.total_bps() > current.total_bps(),
                };
                if better {
                    best = Some(metrics);
                }
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(e) => last_error = Some(e),
        }
    }

    match best {
        Some(metrics) => Ok(metrics),
        None => Err(last_error
            .unwrap_or_else(|| Error::msg("the configuration could not be measured"))),
    }
}

/// One full measurement pass.
fn measure_once(
    pair: &Pair,
    provider: &ProviderRef,
    plan: &TunnelPlan,
    ctx: &BenchContext,
    backend: Backend,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) -> Result<BenchMetrics> {
    let settings = &ctx.settings;
    let mut metrics = BenchMetrics::default();

    super::deploy_only(pair, provider, plan, reporter, cancel)?;
    super::start_pair(pair, provider, plan, false, reporter)?;

    metrics.handshake_secs = super::wait_until_ready(
        pair,
        provider,
        plan,
        Duration::from_secs(settings.handshake_timeout_secs as u64),
        reporter,
        cancel,
    )?;

    if settings.settle_secs > 0 {
        std::thread::sleep(Duration::from_secs(settings.settle_secs as u64));
    }
    reporter.check()?;

    let relay = pair.client(TunnelSide::Client);
    let relay_tun = plan.client.tun_ip.clone();
    let exit_tun = plan.server.tun_ip.clone();

    // ── Latency ─────────────────────────────────────────────────────────────
    let ping = net::ping(
        relay,
        &exit_tun,
        settings.ping_count,
        settings.ping_interval_ms,
        Some(&relay_tun),
    )?;
    if !ping.is_usable() {
        return Err(Error::msg(format!(
            "the tunnel came up but lost every ICMP probe ({}% loss), so it is not usable",
            ping.loss_pct
        )));
    }
    metrics.latency_min_ms = ping.min_ms;
    metrics.latency_avg_ms = ping.avg_ms;
    metrics.latency_max_ms = ping.max_ms;
    metrics.latency_mdev_ms = ping.mdev_ms;
    metrics.icmp_loss_pct = ping.loss_pct;

    // ── TCP, relay to exit ──────────────────────────────────────────────────
    reporter.check()?;
    let uplink = measure_tcp(
        pair,
        backend,
        &exit_tun,
        &relay_tun,
        settings.throughput_secs,
        settings.parallel_streams,
        false,
        cancel,
    )?;
    metrics.uplink_bps = uplink.bits_per_second;
    metrics.retransmits = uplink.retransmits;

    // ── TCP, exit to relay ──────────────────────────────────────────────────
    if settings.test_downlink {
        reporter.check()?;
        let downlink = measure_tcp(
            pair,
            backend,
            &exit_tun,
            &relay_tun,
            settings.throughput_secs,
            settings.parallel_streams,
            true,
            cancel,
        )?;
        metrics.downlink_bps = downlink.bits_per_second;
        metrics.downlink_tested = true;
    }

    // ── UDP jitter and loss ─────────────────────────────────────────────────
    if settings.test_udp {
        reporter.check()?;
        match measure_udp(
            pair,
            backend,
            &exit_tun,
            &relay_tun,
            settings.throughput_secs,
            settings.udp_target_mbits,
            cancel,
        ) {
            Ok(udp) => {
                metrics.udp_bps = udp.bits_per_second;
                metrics.udp_jitter_ms = udp.jitter_ms;
                metrics.udp_loss_pct = udp.lost_percent;
                metrics.udp_tested = true;
            }
            Err(e) => {
                // A failed UDP test should not invalidate throughput figures
                // that were measured successfully.
                reporter.log_line(
                    LogLevel::Warn,
                    None,
                    &format!(
                        "The UDP test did not complete, so jitter and loss come from ICMP \
                         instead: {}",
                        util::truncate(&e.to_string(), 200)
                    ),
                );
            }
        }
    }

    Ok(metrics)
}

/// Run one TCP throughput measurement in a single direction.
#[allow(clippy::too_many_arguments)]
fn measure_tcp(
    pair: &Pair,
    backend: Backend,
    exit_tun: &str,
    relay_tun: &str,
    seconds: u32,
    streams: u32,
    reverse: bool,
    cancel: &Arc<AtomicBool>,
) -> Result<net::ThroughputSample> {
    let relay = pair.client(TunnelSide::Client);
    let exit = pair.client(TunnelSide::Server);

    net::free_port(exit, MEASURE_PORT);
    let handle = net::start_server(
        exit,
        backend,
        exit_tun,
        MEASURE_PORT,
        false,
        seconds,
        streams,
        UDP_DATAGRAM,
    )?;

    // Give the listener a moment to bind before connecting.
    std::thread::sleep(Duration::from_millis(700));

    let client_result = net::run_tcp_client(
        relay,
        backend,
        exit_tun,
        MEASURE_PORT,
        seconds,
        streams,
        reverse,
        Some(relay_tun),
        cancel,
    );

    let outcome = match client_result {
        Ok(sample) => {
            // iperf3's client JSON already reports both directions, so it is
            // authoritative on its own. The bundled probe only knows its own
            // side, so for an uplink test the receiver is the exit node and
            // its result file is the number that counts.
            if backend == Backend::Probe && !reverse {
                match net::read_server_result(exit, &handle, false) {
                    Some(server_sample) if server_sample.bits_per_second > 0.0 => {
                        Ok(server_sample)
                    }
                    _ => Ok(sample),
                }
            } else {
                Ok(sample)
            }
        }
        Err(e) => Err(e),
    };

    net::stop_server(exit, &handle);
    outcome
}

/// Run the UDP jitter and loss measurement.
fn measure_udp(
    pair: &Pair,
    backend: Backend,
    exit_tun: &str,
    relay_tun: &str,
    seconds: u32,
    mbits: u32,
    cancel: &Arc<AtomicBool>,
) -> Result<net::ThroughputSample> {
    let relay = pair.client(TunnelSide::Client);
    let exit = pair.client(TunnelSide::Server);

    net::free_port(exit, MEASURE_PORT);
    let handle = net::start_server(
        exit,
        backend,
        exit_tun,
        MEASURE_PORT,
        true,
        seconds,
        1,
        UDP_DATAGRAM,
    )?;
    std::thread::sleep(Duration::from_millis(700));

    let client_result = net::run_udp_client(
        relay,
        backend,
        exit_tun,
        MEASURE_PORT,
        seconds,
        mbits,
        UDP_DATAGRAM,
        Some(relay_tun),
        cancel,
    );

    let outcome = match client_result {
        Ok(sample) => {
            // Only the receiver can know how much arrived and how evenly, so
            // the server's figures win whenever they are available.
            match net::read_server_result(exit, &handle, true) {
                Some(mut server_sample) => {
                    if server_sample.bits_per_second <= 0.0 {
                        server_sample.bits_per_second = sample.bits_per_second;
                    }
                    Ok(server_sample)
                }
                None if backend == Backend::Iperf3 => Ok(sample),
                None => Err(Error::msg(
                    "the receiving side produced no UDP result, so loss and jitter are unknown",
                )),
            }
        }
        Err(e) => Err(e),
    };

    net::stop_server(exit, &handle);
    outcome
}

/// Remove the measurement instance from both hosts.
///
/// Runs even after a cancellation, so a stopped benchmark never leaves a
/// half-configured tunnel behind.
pub fn cleanup(
    pair: &Pair,
    provider: &ProviderRef,
    reporter: &dyn Reporter,
    cancel: &Arc<AtomicBool>,
) {
    super::stop_pair(pair, provider, BENCH_INSTANCE, reporter);

    // Cleanup must happen even when the user cancelled, so it is deliberately
    // given a cancel flag that is already clear.
    let uncancelled = Arc::new(AtomicBool::new(false));
    let _ = cancel;

    for side in TunnelSide::ORDERED {
        let ctx = pair.ctx(side, reporter, &uncancelled);
        if let Err(e) = provider.remove_instance(&ctx, BENCH_INSTANCE) {
            reporter.log_line(
                LogLevel::Warn,
                Some(pair.label(side)),
                &format!("The measurement instance could not be fully removed: {e}"),
            );
        }
        net::stop_server(
            pair.client(side),
            &net::ServerHandle {
                backend: Backend::Iperf3,
                port: MEASURE_PORT,
                result_path: String::new(),
            },
        );
        net::stop_server(
            pair.client(side),
            &net::ServerHandle {
                backend: Backend::Probe,
                port: MEASURE_PORT,
                result_path: String::new(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthKind, OptionMap};

    fn profile(side: TunnelSide, ip: &str) -> ServerProfile {
        let mut p = ServerProfile::new(side);
        p.host = ip.to_string();
        p.auth_kind = AuthKind::Password;
        p.iface_override = "eth0".into();
        p.local_ip_override = ip.to_string();
        p.public_ip_override = ip.to_string();
        p
    }

    fn context() -> BenchContext {
        BenchContext::new(
            profile(TunnelSide::Client, "192.0.2.10"),
            profile(TunnelSide::Server, "198.51.100.5"),
            "candytunnel",
            BenchSettings::default(),
            MatrixSelection::default(),
        )
    }

    #[test]
    fn the_bench_plan_is_isolated_from_real_tunnels() {
        let variant = BenchVariant {
            id: "v1".into(),
            label: "udp".into(),
            description: String::new(),
            options: OptionMap::new(),
        };
        let plan = bench_plan(&variant, &context(), "0123456789abcdef0123456789abcdef")
            .expect("plan");

        assert_eq!(plan.instance, BENCH_INSTANCE);
        assert_eq!(plan.data_port, BENCH_DATA_PORT);
        assert_eq!(plan.client.tun_ip, TunSlot::BENCHMARK.client_ip());
        assert_eq!(plan.server.tun_ip, TunSlot::BENCHMARK.server_ip());
        // Port forwarding would DNAT the measurement traffic itself.
        assert!(plan.forward_ports.is_empty());
    }

    #[test]
    fn the_reserved_slot_never_collides_with_a_user_tunnel() {
        let used: Vec<TunSlot> = (0..100).map(TunSlot).collect();
        for _ in 0..50 {
            assert_ne!(TunSlot::first_free(&used), TunSlot::BENCHMARK);
        }
    }

    #[test]
    fn invalid_settings_are_rejected_before_any_server_is_touched() {
        let mut settings = BenchSettings::default();
        settings.throughput_secs = 0;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn the_time_estimate_grows_with_the_work_requested() {
        let quick = BenchSettings {
            throughput_secs: 5,
            test_downlink: false,
            test_udp: false,
            ..BenchSettings::default()
        };
        let thorough = BenchSettings {
            throughput_secs: 30,
            test_downlink: true,
            test_udp: true,
            repeats: 3,
            ..BenchSettings::default()
        };
        assert!(thorough.seconds_per_variant() > quick.seconds_per_variant() * 3.0);
    }
}
