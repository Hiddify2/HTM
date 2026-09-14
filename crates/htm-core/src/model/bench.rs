//! Benchmark inputs, measurements and scoring.
//!
//! The benchmark engine brings one candidate configuration up at a time,
//! measures it across the real tunnel, tears it down and moves on. Everything
//! it records lands in a [`BenchResult`]; [`score_results`] then ranks the
//! completed ones against each other.

use serde::{Deserialize, Serialize};

use super::options::{OptValue, OptionMap};

/// One measured configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BenchMetrics {
    /// Seconds from starting both units to the tunnel carrying traffic.
    pub handshake_secs: f64,

    /// ICMP round-trip across the TUN link.
    pub latency_min_ms: f64,
    pub latency_avg_ms: f64,
    pub latency_max_ms: f64,
    /// Mean deviation reported by `ping`, i.e. latency jitter.
    pub latency_mdev_ms: f64,
    /// ICMP loss over the ping run, as a percentage.
    pub icmp_loss_pct: f64,

    /// TCP throughput relay to exit, bits per second.
    pub uplink_bps: f64,
    /// TCP throughput exit to relay, bits per second.
    pub downlink_bps: f64,
    /// TCP retransmissions observed during the uplink test, when the tool
    /// reports them.
    pub retransmits: u64,

    /// UDP jitter in milliseconds, when the UDP test ran.
    pub udp_jitter_ms: f64,
    /// UDP datagram loss percentage, when the UDP test ran.
    pub udp_loss_pct: f64,
    /// UDP goodput in bits per second, when the UDP test ran.
    pub udp_bps: f64,

    /// Whether the UDP test actually ran.
    pub udp_tested: bool,
    /// Whether the reverse (downlink) test actually ran.
    pub downlink_tested: bool,
}

impl BenchMetrics {
    /// Combined bidirectional throughput, used as the headline figure.
    pub fn total_bps(&self) -> f64 {
        self.uplink_bps + self.downlink_bps
    }

    /// The jitter figure worth ranking on: the UDP measurement when available,
    /// otherwise ping's mean deviation.
    pub fn effective_jitter_ms(&self) -> f64 {
        if self.udp_tested && self.udp_jitter_ms > 0.0 {
            self.udp_jitter_ms
        } else {
            self.latency_mdev_ms
        }
    }

    /// The loss figure worth ranking on.
    pub fn effective_loss_pct(&self) -> f64 {
        if self.udp_tested {
            self.udp_loss_pct.max(self.icmp_loss_pct)
        } else {
            self.icmp_loss_pct
        }
    }
}

/// How a benchmark variant ended.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BenchOutcome {
    /// Not attempted yet.
    Pending,
    /// Currently being measured.
    Running,
    /// Measured successfully.
    Completed(BenchMetrics),
    /// The tunnel came up but a measurement failed, or it never came up.
    Failed {
        reason: String,
        /// Tail of the remote journal, so the user can see why.
        log_excerpt: String,
    },
    /// Deliberately not run, e.g. the transport is unavailable on this host.
    Skipped { reason: String },
    /// The run was cancelled before this variant finished.
    Cancelled,
}

impl BenchOutcome {
    pub fn is_completed(&self) -> bool {
        matches!(self, BenchOutcome::Completed(_))
    }

    pub fn metrics(&self) -> Option<&BenchMetrics> {
        match self {
            BenchOutcome::Completed(m) => Some(m),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            BenchOutcome::Pending => "Queued",
            BenchOutcome::Running => "Measuring",
            BenchOutcome::Completed(_) => "Done",
            BenchOutcome::Failed { .. } => "Failed",
            BenchOutcome::Skipped { .. } => "Skipped",
            BenchOutcome::Cancelled => "Cancelled",
        }
    }
}

/// One candidate configuration to measure, produced by a provider from a
/// [`MatrixSelection`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchVariant {
    /// Stable identifier derived from the option values, so the same
    /// configuration always gets the same id.
    pub id: String,
    /// Compact human label, e.g. `udp · mux · xor`.
    pub label: String,
    /// Longer explanation shown in the details pane.
    pub description: String,
    /// The provider settings this variant represents.
    pub options: OptionMap,
}

/// A measured (or attempted) variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchResult {
    pub variant: BenchVariant,
    pub outcome: BenchOutcome,
    /// Score in 0..=100, assigned by [`score_results`]. `None` until scored or
    /// when the variant did not complete.
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub elapsed_secs: f64,
}

impl BenchResult {
    pub fn pending(variant: BenchVariant) -> Self {
        Self {
            variant,
            outcome: BenchOutcome::Pending,
            score: None,
            started_at: None,
            elapsed_secs: 0.0,
        }
    }
}

/// Relative importance of each measured dimension. All weights are clamped to
/// `0..=10` and normalised before use, so only their ratios matter.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScoreWeights {
    pub uplink: f32,
    pub downlink: f32,
    pub latency: f32,
    pub jitter: f32,
    pub loss: f32,
    /// Rewards tunnels that came up quickly, a decent proxy for reliability.
    pub handshake: f32,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        // Throughput dominates, but latency matters enough that a marginally
        // faster but far laggier transport does not automatically win.
        Self {
            uplink: 3.0,
            downlink: 3.0,
            latency: 2.0,
            jitter: 1.0,
            loss: 2.0,
            handshake: 0.5,
        }
    }
}

impl ScoreWeights {
    /// A preset tuned for bulk transfer.
    pub fn throughput() -> Self {
        Self {
            uplink: 4.0,
            downlink: 4.0,
            latency: 1.0,
            jitter: 0.5,
            loss: 1.5,
            handshake: 0.25,
        }
    }

    /// A preset tuned for interactive traffic and gaming.
    pub fn latency() -> Self {
        Self {
            uplink: 1.0,
            downlink: 1.0,
            latency: 4.0,
            jitter: 3.0,
            loss: 3.0,
            handshake: 0.5,
        }
    }

    pub fn total(&self) -> f32 {
        self.uplink + self.downlink + self.latency + self.jitter + self.loss + self.handshake
    }

    /// Clamp every weight into range.
    pub fn clamped(self) -> Self {
        let c = |v: f32| crate::util::clamp_f64(v as f64, 0.0, 10.0) as f32;
        Self {
            uplink: c(self.uplink),
            downlink: c(self.downlink),
            latency: c(self.latency),
            jitter: c(self.jitter),
            loss: c(self.loss),
            handshake: c(self.handshake),
        }
    }
}

/// Which measurement tool the engine should prefer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputTool {
    /// Use iperf3, installing it if necessary; fall back to the bundled probe.
    PreferIperf3,
    /// Always use the small Python probe HTM uploads itself. Installs nothing.
    BundledProbe,
}

impl ThroughputTool {
    pub fn display_name(self) -> &'static str {
        match self {
            ThroughputTool::PreferIperf3 => "iperf3 (install if missing)",
            ThroughputTool::BundledProbe => "Bundled probe (no installs)",
        }
    }

    pub const ALL: [ThroughputTool; 2] =
        [ThroughputTool::PreferIperf3, ThroughputTool::BundledProbe];
}

/// Knobs for how thoroughly each variant is measured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchSettings {
    /// Seconds per throughput direction.
    pub throughput_secs: u32,
    /// Number of ICMP probes.
    pub ping_count: u32,
    /// Interval between ICMP probes, in milliseconds.
    pub ping_interval_ms: u32,
    /// Run the reverse-direction throughput test.
    pub test_downlink: bool,
    /// Run the UDP jitter/loss test.
    pub test_udp: bool,
    /// Target rate for the UDP test, in megabits per second.
    pub udp_target_mbits: u32,
    /// Parallel TCP streams.
    pub parallel_streams: u32,
    /// Port the throughput tools listen on inside the tunnel.
    ///
    /// This port is also written into the relay's `forward_ports`, so the
    /// measurement runs over a relay configured exactly the way a deployed
    /// tunnel would be — IP forwarding on, reverse-path filtering off on the
    /// TUN device, and the DNAT rules in place. Measuring without that would
    /// be measuring a different machine from the one you are going to run.
    pub measure_port: u16,
    /// Seconds to wait after the tunnel reports ready before measuring, so
    /// routing and the first handshake settle.
    pub settle_secs: u32,
    /// Seconds to wait for the tunnel to carry traffic before declaring the
    /// variant failed.
    pub handshake_timeout_secs: u32,
    pub tool: ThroughputTool,
    /// Re-measure each variant this many times and keep the best result.
    pub repeats: u32,
    /// Stop the whole run after this many consecutive failures. 0 disables.
    pub abort_after_failures: u32,
    pub weights: ScoreWeights,
}

impl Default for BenchSettings {
    fn default() -> Self {
        Self {
            throughput_secs: 8,
            ping_count: 20,
            ping_interval_ms: 200,
            test_downlink: true,
            test_udp: true,
            udp_target_mbits: 50,
            parallel_streams: 4,
            measure_port: 5301,
            settle_secs: 2,
            handshake_timeout_secs: 45,
            tool: ThroughputTool::PreferIperf3,
            repeats: 1,
            abort_after_failures: 0,
            weights: ScoreWeights::default(),
        }
    }
}

impl BenchSettings {
    /// Roughly how long one variant takes, for the time estimate in the UI.
    pub fn seconds_per_variant(&self) -> f64 {
        let directions = 1 + u32::from(self.test_downlink);
        let throughput = (self.throughput_secs * directions) as f64;
        let udp = if self.test_udp {
            self.throughput_secs as f64
        } else {
            0.0
        };
        let ping = (self.ping_count * self.ping_interval_ms) as f64 / 1000.0;
        // Deploy, start, wait for readiness, tear down: measured at about 14s
        // of fixed overhead on a typical VPS pair.
        let overhead = 14.0 + self.settle_secs as f64;
        (throughput + udp + ping + overhead) * self.repeats.max(1) as f64
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.throughput_secs == 0 || self.throughput_secs > 120 {
            return Err("Throughput duration must be 1-120 seconds.".into());
        }
        if self.ping_count == 0 || self.ping_count > 500 {
            return Err("Ping count must be 1-500.".into());
        }
        if self.ping_interval_ms < 20 || self.ping_interval_ms > 5000 {
            return Err("Ping interval must be 20-5000 ms.".into());
        }
        if self.parallel_streams == 0 || self.parallel_streams > 64 {
            return Err("Parallel streams must be 1-64.".into());
        }
        if self.measure_port < 1024 {
            return Err(
                "The measurement port must be 1024 or above, so the tools do not need extra                  privileges to bind it."
                    .into(),
            );
        }
        if self.test_udp && (self.udp_target_mbits == 0 || self.udp_target_mbits > 10_000) {
            return Err("UDP target rate must be 1-10000 Mbit/s.".into());
        }
        if self.handshake_timeout_secs < 5 || self.handshake_timeout_secs > 600 {
            return Err("Handshake timeout must be 5-600 seconds.".into());
        }
        if self.repeats == 0 || self.repeats > 10 {
            return Err("Repeats must be 1-10.".into());
        }
        Ok(())
    }
}

/// The user's choice of which dimensions to sweep and which values to try.
///
/// Keys are provider option keys; values are the set of values to cross. A
/// dimension absent from the map is held at its default.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MatrixSelection {
    pub dimensions: std::collections::BTreeMap<String, Vec<OptValue>>,
    /// Settings pinned for every variant, overriding provider defaults.
    #[serde(default)]
    pub fixed: OptionMap,
}

impl MatrixSelection {
    /// Number of variants the cross product would produce, before the provider
    /// drops invalid combinations.
    pub fn raw_combination_count(&self) -> usize {
        self.dimensions
            .values()
            .map(|v| v.len().max(1))
            .product::<usize>()
            .max(1)
    }

    /// Every combination of the selected dimensions, merged over `fixed`.
    pub fn expand(&self, base: &OptionMap) -> Vec<OptionMap> {
        let mut out: Vec<OptionMap> = vec![{
            let mut m = base.clone();
            for (k, v) in &self.fixed {
                m.insert(k.clone(), v.clone());
            }
            m
        }];

        for (key, values) in &self.dimensions {
            if values.is_empty() {
                continue;
            }
            let mut next: Vec<OptionMap> = Vec::with_capacity(out.len() * values.len());
            for existing in &out {
                for value in values {
                    let mut m = existing.clone();
                    m.insert(key.clone(), value.clone());
                    next.push(m);
                }
            }
            out = next;
        }
        out
    }
}

/// A complete benchmark run: what was asked for and what came back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchRun {
    pub id: String,
    pub provider_id: String,
    pub settings: BenchSettings,
    pub selection: MatrixSelection,
    pub results: Vec<BenchResult>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Set when the run stopped early.
    #[serde(default)]
    pub aborted_reason: Option<String>,
}

impl BenchRun {
    pub fn completed(&self) -> impl Iterator<Item = &BenchResult> {
        self.results.iter().filter(|r| r.outcome.is_completed())
    }

    /// Results ordered best first. Completed variants sort above everything
    /// else; incomplete ones keep their original order at the bottom.
    pub fn ranked(&self) -> Vec<&BenchResult> {
        let mut done: Vec<&BenchResult> = self.completed().collect();
        done.sort_by(|a, b| {
            b.score
                .unwrap_or(0.0)
                .partial_cmp(&a.score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let rest: Vec<&BenchResult> = self
            .results
            .iter()
            .filter(|r| !r.outcome.is_completed())
            .collect();
        done.into_iter().chain(rest).collect()
    }

    pub fn best(&self) -> Option<&BenchResult> {
        self.ranked().into_iter().next().filter(|r| r.outcome.is_completed())
    }

    pub fn progress(&self) -> (usize, usize) {
        let done = self
            .results
            .iter()
            .filter(|r| !matches!(r.outcome, BenchOutcome::Pending | BenchOutcome::Running))
            .count();
        (done, self.results.len())
    }
}

/// Assign a 0-100 score to every completed result, relative to the others.
///
/// Each dimension is min-max normalised across the completed set, then
/// combined with the weights. With a single completed result every dimension
/// normalises to 1.0 and the score is 100 — correct, since there is nothing to
/// compare it against.
pub fn score_results(results: &mut [BenchResult], weights: &ScoreWeights) {
    let weights = weights.clamped();
    let total_weight = weights.total();

    let indices: Vec<usize> = results
        .iter()
        .enumerate()
        .filter(|(_, r)| r.outcome.is_completed())
        .map(|(i, _)| i)
        .collect();

    if indices.is_empty() {
        return;
    }
    if total_weight <= 0.0 {
        for i in indices {
            results[i].score = Some(0.0);
        }
        return;
    }

    // Collect each dimension across the completed set, in `indices` order.
    let uplink = gather(results, &indices, |m| m.uplink_bps);
    let downlink = gather(results, &indices, |m| m.downlink_bps);
    let latency = gather(results, &indices, |m| m.latency_avg_ms);
    let jitter = gather(results, &indices, |m| m.effective_jitter_ms());
    let loss = gather(results, &indices, |m| m.effective_loss_pct());
    let handshake = gather(results, &indices, |m| m.handshake_secs);

    for (pos, &idx) in indices.iter().enumerate() {
        let score = weights.uplink * norm_high(&uplink, pos)
            + weights.downlink * norm_high(&downlink, pos)
            + weights.latency * norm_low(&latency, pos)
            + weights.jitter * norm_low(&jitter, pos)
            + weights.loss * norm_low(&loss, pos)
            + weights.handshake * norm_low(&handshake, pos);
        results[idx].score = Some((score / total_weight * 100.0) as f64);
    }
}

/// Pull one metric out of every completed result named by `indices`.
fn gather<F>(results: &[BenchResult], indices: &[usize], f: F) -> Vec<f64>
where
    F: Fn(&BenchMetrics) -> f64,
{
    indices
        .iter()
        .map(|&i| {
            results[i]
                .outcome
                .metrics()
                .map(|m| {
                    let v = f(m);
                    if v.is_finite() {
                        v
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0)
        })
        .collect()
}

/// Normalise where a larger value is better.
fn norm_high(values: &[f64], pos: usize) -> f32 {
    let (min, max) = min_max(values);
    if (max - min).abs() < f64::EPSILON {
        return 1.0;
    }
    (((values[pos] - min) / (max - min)) as f32).clamp(0.0, 1.0)
}

/// Normalise where a smaller value is better.
fn norm_low(values: &[f64], pos: usize) -> f32 {
    let (min, max) = min_max(values);
    if (max - min).abs() < f64::EPSILON {
        return 1.0;
    }
    (((max - values[pos]) / (max - min)) as f32).clamp(0.0, 1.0)
}

fn min_max(values: &[f64]) -> (f64, f64) {
    let mut min = f64::INFINITY;
    let mut max = f64::NEG_INFINITY;
    for &v in values {
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    if !min.is_finite() || !max.is_finite() {
        return (0.0, 0.0);
    }
    (min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variant(id: &str) -> BenchVariant {
        BenchVariant {
            id: id.to_string(),
            label: id.to_string(),
            description: String::new(),
            options: OptionMap::new(),
        }
    }

    fn completed(id: &str, up: f64, down: f64, lat: f64) -> BenchResult {
        BenchResult {
            variant: variant(id),
            outcome: BenchOutcome::Completed(BenchMetrics {
                uplink_bps: up,
                downlink_bps: down,
                latency_avg_ms: lat,
                ..Default::default()
            }),
            score: None,
            started_at: None,
            elapsed_secs: 0.0,
        }
    }

    #[test]
    fn best_throughput_and_latency_wins() {
        let weights = ScoreWeights::default();
        let mut rows = vec![
            completed("fast", 100e6, 100e6, 10.0),
            completed("slow", 10e6, 10e6, 90.0),
        ];
        score_results(&mut rows, &weights);
        let fast = rows[0].score.unwrap();
        let slow = rows[1].score.unwrap();

        assert!(fast > slow, "fast={fast} slow={slow}");
        assert!((fast - 100.0).abs() < 0.001, "fast={fast}");

        // The loser does not score zero. These two rows differ only on uplink,
        // downlink and latency; they *tie* at zero on jitter, loss and startup,
        // and a dimension where every result is identical gives everyone full
        // marks, because it tells you nothing about which is better. The loser
        // therefore keeps exactly the weight of the tied dimensions.
        let tied = (weights.jitter + weights.loss + weights.handshake) / weights.total();
        let expected = f64::from(tied) * 100.0;
        assert!(
            (slow - expected).abs() < 0.001,
            "slow={slow}, expected the tied share {expected}"
        );
    }

    #[test]
    fn a_dimension_everyone_ties_on_cannot_separate_them() {
        // Identical on every measured axis: neither is better at anything, so
        // both score full marks rather than both scoring nothing.
        let mut rows = vec![
            completed("a", 50e6, 50e6, 20.0),
            completed("b", 50e6, 50e6, 20.0),
        ];
        score_results(&mut rows, &ScoreWeights::default());
        for row in &rows {
            assert!((row.score.unwrap() - 100.0).abs() < 0.001);
        }
    }

    #[test]
    fn weights_decide_how_much_a_dimension_is_worth() {
        // Same two rows, but scored as if only throughput mattered: the loser
        // now keeps only the weight of latency, jitter, loss and startup, all
        // of which it ties on except latency, which it loses.
        let weights = ScoreWeights {
            uplink: 1.0,
            downlink: 1.0,
            latency: 0.0,
            jitter: 0.0,
            loss: 0.0,
            handshake: 0.0,
        };
        let mut rows = vec![
            completed("fast", 100e6, 100e6, 10.0),
            completed("slow", 10e6, 10e6, 90.0),
        ];
        score_results(&mut rows, &weights);
        assert!((rows[0].score.unwrap() - 100.0).abs() < 0.001);
        assert!(rows[1].score.unwrap().abs() < 0.001);
    }

    #[test]
    fn single_result_scores_full_marks() {
        let mut rows = vec![completed("only", 1.0, 1.0, 1.0)];
        score_results(&mut rows, &ScoreWeights::default());
        assert!((rows[0].score.unwrap() - 100.0).abs() < 0.001);
    }

    #[test]
    fn failed_variants_are_not_scored() {
        let mut rows = vec![
            completed("ok", 1.0, 1.0, 1.0),
            BenchResult {
                variant: variant("bad"),
                outcome: BenchOutcome::Failed {
                    reason: "no handshake".into(),
                    log_excerpt: String::new(),
                },
                score: None,
                started_at: None,
                elapsed_secs: 0.0,
            },
        ];
        score_results(&mut rows, &ScoreWeights::default());
        assert!(rows[0].score.is_some());
        assert!(rows[1].score.is_none());
    }

    #[test]
    fn matrix_expands_to_cross_product() {
        let mut sel = MatrixSelection::default();
        sel.dimensions.insert(
            "a".into(),
            vec![OptValue::Bool(false), OptValue::Bool(true)],
        );
        sel.dimensions.insert(
            "b".into(),
            vec![
                OptValue::Choice("x".into()),
                OptValue::Choice("y".into()),
                OptValue::Choice("z".into()),
            ],
        );
        assert_eq!(sel.raw_combination_count(), 6);
        assert_eq!(sel.expand(&OptionMap::new()).len(), 6);
    }
}
