//! Turning a matrix selection into the list of configurations worth measuring.
//!
//! The cross product of every option would be enormous and mostly pointless,
//! because many settings are ignored by some transports. Expansion therefore
//! runs each combination through [`config::normalize`] first and then
//! de-duplicates, so two selections that the binary would treat identically
//! collapse into one measurement instead of costing a minute each.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::config::{self, keys};
use crate::model::{BenchVariant, MatrixSelection, OptValue, OptionMap, OptionMapExt};
use crate::provider::MatrixPreset;

/// A short, stable identifier for a configuration.
///
/// Derived from the normalised options, so the same configuration always gets
/// the same id across runs and can be matched up between benchmark history and
/// a deployed tunnel.
pub fn variant_id(options: &OptionMap) -> String {
    let mut hasher = Sha256::new();
    for (key, value) in options {
        hasher.update(key.as_bytes());
        hasher.update(b"=");
        hasher.update(value.short_display().as_bytes());
        hasher.update(b";");
    }
    let digest = hasher.finalize();
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// Expand a selection into distinct, valid variants.
pub fn expand(selection: &MatrixSelection) -> Vec<BenchVariant> {
    let base = config::option_space().defaults();

    // When the user sweeps the uplink transport but leaves the downlink alone,
    // keep the two in step. Sweeping them independently is possible, but only
    // if they explicitly ask for it by selecting the downlink dimension too.
    let mirror_downlink = selection.dimensions.contains_key(keys::UPLINK)
        && !selection.dimensions.contains_key(keys::DOWNLINK);

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<BenchVariant> = Vec::new();

    for mut combo in selection.expand(&base) {
        if mirror_downlink {
            let uplink = combo.str_or(keys::UPLINK, "udp");
            combo.insert(keys::DOWNLINK.into(), OptValue::Choice(uplink));
        }

        let normalized = config::normalize(&combo);
        if config::validate(&normalized).is_err() {
            continue;
        }

        let id = variant_id(&normalized);
        if !seen.insert(id.clone()) {
            continue;
        }

        out.push(BenchVariant {
            id,
            label: config::describe(&normalized),
            description: config::explain(&normalized),
            options: normalized,
        });
    }

    out
}

fn protocols_dimension() -> Vec<OptValue> {
    config::PROTOCOLS
        .iter()
        .map(|(id, _)| OptValue::Choice((*id).to_string()))
        .collect()
}

fn bools() -> Vec<OptValue> {
    vec![OptValue::Bool(false), OptValue::Bool(true)]
}

/// The matrix used when the user just presses *Run benchmark*.
///
/// Every transport, each with multiplexing on and off. After normalisation
/// that is twelve distinct measurements: five transports carry multiplexing so
/// they appear twice, and TCP and QUIC appear once each.
pub fn default_matrix() -> MatrixSelection {
    let mut selection = MatrixSelection::default();
    selection
        .dimensions
        .insert(keys::UPLINK.to_string(), protocols_dimension());
    selection
        .dimensions
        .insert(keys::MULTIPLEX.to_string(), bools());
    selection
}

/// Ready-made matrices covering the questions people actually ask.
pub fn presets() -> Vec<MatrixPreset> {
    let mut out = Vec::new();

    // 1. Which transport gets through, and how fast?
    {
        let mut s = MatrixSelection::default();
        s.dimensions
            .insert(keys::UPLINK.to_string(), protocols_dimension());
        out.push(MatrixPreset {
            id: "transports".into(),
            name: "Transport sweep".into(),
            description:
                "Each of the seven transports once, everything else at its default. The fastest \
                 way to find out which protocols your route allows at all."
                    .into(),
            selection: s,
        });
    }

    // 2. The default: transports crossed with multiplexing.
    out.push(MatrixPreset {
        id: "transports-mux".into(),
        name: "Transports x multiplexing".into(),
        description:
            "Every transport with multiplexing both on and off. A good default: multiplexing is \
             the single setting that most often changes the answer."
                .into(),
        selection: default_matrix(),
    });

    // 3. Does obfuscation cost anything?
    {
        let mut s = MatrixSelection::default();
        s.fixed
            .insert(keys::UPLINK.to_string(), OptValue::Choice("udp".into()));
        s.fixed
            .insert(keys::DOWNLINK.to_string(), OptValue::Choice("udp".into()));
        s.dimensions.insert(keys::PADDING.to_string(), bools());
        s.dimensions.insert(keys::TTL_JITTER.to_string(), bools());
        s.dimensions.insert(keys::RANDOM_DSCP.to_string(), bools());
        out.push(MatrixPreset {
            id: "obfuscation".into(),
            name: "Obfuscation cost".into(),
            description:
                "UDP throughout, with padding, TTL jitter and DSCP marking in every combination. \
                 Shows what evading inspection costs in throughput and latency."
                    .into(),
            selection: s,
        });
    }

    // 4. Tuning, once a transport has been chosen.
    {
        let mut s = MatrixSelection::default();
        s.fixed
            .insert(keys::UPLINK.to_string(), OptValue::Choice("udp".into()));
        s.fixed
            .insert(keys::DOWNLINK.to_string(), OptValue::Choice("udp".into()));
        s.fixed
            .insert(keys::MULTIPLEX.to_string(), OptValue::Bool(true));
        s.dimensions.insert(
            keys::TUNNEL_COUNT.to_string(),
            vec![
                OptValue::Int(1),
                OptValue::Int(2),
                OptValue::Int(4),
                OptValue::Int(8),
            ],
        );
        s.dimensions.insert(
            keys::PERF_MODE.to_string(),
            vec![
                OptValue::Choice("balanced".into()),
                OptValue::Choice("throughput".into()),
                OptValue::Choice("latency".into()),
            ],
        );
        out.push(MatrixPreset {
            id: "tuning".into(),
            name: "Parallelism & profile".into(),
            description:
                "UDP with multiplexing, sweeping one to eight parallel tunnels against all three \
                 performance profiles. Run this after you know which transport works."
                    .into(),
            selection: s,
        });
    }

    // 5. Loss recovery, for links that are up but lossy.
    {
        let mut s = MatrixSelection::default();
        s.fixed
            .insert(keys::UPLINK.to_string(), OptValue::Choice("udp".into()));
        s.fixed
            .insert(keys::DOWNLINK.to_string(), OptValue::Choice("udp".into()));
        s.fixed
            .insert(keys::MULTIPLEX.to_string(), OptValue::Bool(true));
        s.dimensions.insert(keys::FEC.to_string(), bools());
        s.dimensions.insert(
            keys::FEC_GROUP.to_string(),
            vec![OptValue::Int(2), OptValue::Int(4), OptValue::Int(8)],
        );
        out.push(MatrixPreset {
            id: "fec".into(),
            name: "Error correction".into(),
            description:
                "Forward error correction off, and on with group sizes of two, four and eight. \
                 Worth running when the link shows packet loss."
                    .into(),
            selection: s,
        });
    }

    // 6. The cost of encryption.
    {
        let mut s = MatrixSelection::default();
        s.dimensions
            .insert(keys::UPLINK.to_string(), protocols_dimension());
        s.dimensions.insert(keys::XOR.to_string(), bools());
        out.push(MatrixPreset {
            id: "encryption".into(),
            name: "Encryption cost".into(),
            description:
                "Every transport with ChaCha20 encryption on and off. Useful on very small VPS \
                 instances where the cipher may be the bottleneck. Keep encryption on in \
                 production regardless of the numbers."
                    .into(),
            selection: s,
        });
    }

    // 7. Everything that matters, for people with time.
    {
        let mut s = MatrixSelection::default();
        s.dimensions
            .insert(keys::UPLINK.to_string(), protocols_dimension());
        s.dimensions.insert(keys::MULTIPLEX.to_string(), bools());
        s.dimensions.insert(keys::FEC.to_string(), bools());
        s.dimensions.insert(
            keys::PERF_MODE.to_string(),
            vec![
                OptValue::Choice("balanced".into()),
                OptValue::Choice("throughput".into()),
                OptValue::Choice("latency".into()),
            ],
        );
        s.dimensions.insert(
            keys::TUNNEL_COUNT.to_string(),
            vec![OptValue::Int(2), OptValue::Int(4), OptValue::Int(8)],
        );
        out.push(MatrixPreset {
            id: "exhaustive".into(),
            name: "Exhaustive".into(),
            description:
                "Transports, multiplexing, error correction, all three performance profiles and \
                 three parallelism levels. Thorough, and long: expect this to run for hours."
                    .into(),
            selection: s,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_matrix_collapses_to_twelve_distinct_variants() {
        let variants = expand(&default_matrix());
        // 5 multiplex-capable transports x 2, plus tcp and quic once each.
        assert_eq!(variants.len(), 12, "{:?}", labels(&variants));
    }

    #[test]
    fn sweeping_the_uplink_alone_mirrors_the_downlink() {
        let variants = expand(&default_matrix());
        for v in &variants {
            assert_eq!(
                v.options.str_or(keys::UPLINK, "?"),
                v.options.str_or(keys::DOWNLINK, "?"),
                "{}",
                v.label
            );
        }
    }

    #[test]
    fn a_transport_sweep_yields_one_variant_per_transport() {
        let preset = presets()
            .into_iter()
            .find(|p| p.id == "transports")
            .expect("preset");
        assert_eq!(expand(&preset.selection).len(), config::PROTOCOLS.len());
    }

    #[test]
    fn variant_ids_are_stable_and_unique() {
        let a = expand(&default_matrix());
        let b = expand(&default_matrix());
        let ids_a: Vec<&str> = a.iter().map(|v| v.id.as_str()).collect();
        let ids_b: Vec<&str> = b.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids_a, ids_b);

        let mut sorted = ids_a.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids_a.len());
    }

    #[test]
    fn invalid_combinations_never_reach_the_queue() {
        // Ask for QUIC with port shuffling; normalisation must resolve it and
        // nothing invalid may survive.
        let mut s = MatrixSelection::default();
        s.dimensions
            .insert(keys::UPLINK.to_string(), protocols_dimension());
        s.dimensions.insert(keys::SHUFFLE_PORT.to_string(), bools());
        for v in expand(&s) {
            assert!(config::validate(&v.options).is_ok(), "{}", v.label);
        }
    }

    #[test]
    fn every_preset_expands_to_something() {
        for preset in presets() {
            let variants = expand(&preset.selection);
            assert!(!variants.is_empty(), "{} produced nothing", preset.id);
        }
    }

    #[test]
    fn fec_group_sizes_only_multiply_when_fec_is_on() {
        let preset = presets().into_iter().find(|p| p.id == "fec").unwrap();
        // off collapses to one; on gives three group sizes.
        assert_eq!(expand(&preset.selection).len(), 4);
    }

    fn labels(variants: &[BenchVariant]) -> Vec<String> {
        variants.iter().map(|v| v.label.clone()).collect()
    }
}
