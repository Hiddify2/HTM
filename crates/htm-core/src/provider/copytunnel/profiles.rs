//! Turning a matrix selection into the CopyTunnel configurations worth
//! measuring. CopyTunnel has a small option space — the cipher and the
//! obfuscation layer are what change throughput — so expansion is simple:
//! normalise, then de-duplicate so two selections the binary would treat
//! identically collapse into one measurement.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::config::{self, keys};
use crate::model::{BenchVariant, MatrixSelection, OptValue, OptionMap};
use crate::provider::MatrixPreset;

/// A short, stable id derived from the normalised options.
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
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<BenchVariant> = Vec::new();

    for combo in selection.expand(&base) {
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

fn cipher_dimension() -> Vec<OptValue> {
    config::CIPHERS
        .iter()
        .map(|(id, _)| OptValue::Choice((*id).to_string()))
        .collect()
}

fn aead_dimension() -> Vec<OptValue> {
    config::AEAD_CIPHERS
        .iter()
        .map(|id| OptValue::Choice((*id).to_string()))
        .collect()
}

fn bools() -> Vec<OptValue> {
    vec![OptValue::Bool(false), OptValue::Bool(true)]
}

/// The matrix used when the user just presses *Run benchmark*: every cipher
/// once, which answers the question people actually have — which cipher is
/// fastest over this route.
pub fn default_matrix() -> MatrixSelection {
    let mut selection = MatrixSelection::default();
    selection
        .dimensions
        .insert(keys::CIPHER.to_string(), cipher_dimension());
    selection
}

/// Ready-made matrices.
pub fn presets() -> Vec<MatrixPreset> {
    let mut out = Vec::new();

    out.push(MatrixPreset {
        id: "ciphers".into(),
        name: "Cipher sweep".into(),
        description: "Each of the six wire ciphers once. The fastest way to find the cipher your \
                      CPU and route handle best. Keep an AEAD cipher in production regardless."
            .into(),
        selection: default_matrix(),
    });

    {
        let mut s = MatrixSelection::default();
        s.dimensions
            .insert(keys::CIPHER.to_string(), aead_dimension());
        out.push(MatrixPreset {
            id: "aead-ciphers".into(),
            name: "Secure ciphers only".into(),
            description: "The four authenticated (AEAD) ciphers, leaving out the obfuscation-only \
                          'xor' and the plaintext 'none'. Compare only options safe for real use."
                .into(),
            selection: s,
        });
    }

    {
        let mut s = MatrixSelection::default();
        s.fixed.insert(
            keys::CIPHER.to_string(),
            OptValue::Choice("chacha20poly1305".into()),
        );
        s.dimensions.insert(keys::OBFUSCATE.to_string(), bools());
        out.push(MatrixPreset {
            id: "obfuscation".into(),
            name: "Obfuscation cost".into(),
            description: "ChaCha20-Poly1305 with the whole-frame obfuscation layer on and off. \
                          Shows what breaking the frame's fixed structure costs in throughput."
                .into(),
            selection: s,
        });
    }

    {
        let mut s = MatrixSelection::default();
        s.dimensions
            .insert(keys::CIPHER.to_string(), cipher_dimension());
        s.dimensions.insert(keys::OBFUSCATE.to_string(), bools());
        out.push(MatrixPreset {
            id: "exhaustive".into(),
            name: "Exhaustive".into(),
            description: "Every cipher with obfuscation on and off. Thorough; twelve measurements."
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
    fn the_default_matrix_is_one_variant_per_cipher() {
        let variants = expand(&default_matrix());
        assert_eq!(variants.len(), config::CIPHERS.len());
    }

    #[test]
    fn the_exhaustive_preset_crosses_cipher_and_obfuscation() {
        let preset = presets()
            .into_iter()
            .find(|p| p.id == "exhaustive")
            .unwrap();
        assert_eq!(expand(&preset.selection).len(), config::CIPHERS.len() * 2);
    }

    #[test]
    fn variant_ids_are_stable_and_unique() {
        let a = expand(&default_matrix());
        let b = expand(&default_matrix());
        let ids_a: Vec<&str> = a.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids_a, b.iter().map(|v| v.id.as_str()).collect::<Vec<_>>());
        let mut sorted = ids_a.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids_a.len());
    }

    #[test]
    fn every_preset_expands_to_something() {
        for preset in presets() {
            assert!(!expand(&preset.selection).is_empty(), "{}", preset.id);
        }
    }
}
