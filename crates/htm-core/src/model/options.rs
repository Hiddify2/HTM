//! A tiny dynamic value type for provider-specific tunnel settings.
//!
//! HTM's GUI, benchmark engine and persistence layer are all provider-agnostic:
//! they never name a CandyTunnel option. Instead a provider publishes an
//! [`OptionSpec`] list describing what it accepts, and settings travel around
//! as an [`OptionMap`]. Adding a second tunnel implementation therefore needs
//! no changes outside its own module.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One provider setting value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", content = "v", rename_all = "lowercase")]
pub enum OptValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    /// One of the choices declared by the matching [`OptionSpec`].
    Choice(String),
    IntList(Vec<i64>),
    TextList(Vec<String>),
}

impl OptValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            OptValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            OptValue::Int(i) => Some(*i),
            OptValue::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_float(&self) -> Option<f64> {
        match self {
            OptValue::Float(f) => Some(*f),
            OptValue::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            OptValue::Text(s) | OptValue::Choice(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_int_list(&self) -> Option<&[i64]> {
        match self {
            OptValue::IntList(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    pub fn as_text_list(&self) -> Option<&[String]> {
        match self {
            OptValue::TextList(v) => Some(v.as_slice()),
            _ => None,
        }
    }

    /// How the value appears in a compact variant label.
    pub fn short_display(&self) -> String {
        match self {
            OptValue::Bool(b) => if *b { "on" } else { "off" }.to_string(),
            OptValue::Int(i) => i.to_string(),
            OptValue::Float(f) => format!("{f}"),
            OptValue::Text(s) | OptValue::Choice(s) => s.clone(),
            OptValue::IntList(v) => v
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("+"),
            OptValue::TextList(v) => v.join("+"),
        }
    }
}

/// An ordered bag of provider settings. `BTreeMap` so that two maps with the
/// same contents always hash and render identically, which the benchmark
/// de-duplicator relies on.
pub type OptionMap = BTreeMap<String, OptValue>;

/// Read helpers that fall back to a default instead of erroring, so a provider
/// can evolve its option set without breaking saved tunnels.
pub trait OptionMapExt {
    fn bool_or(&self, key: &str, default: bool) -> bool;
    fn int_or(&self, key: &str, default: i64) -> i64;
    fn float_or(&self, key: &str, default: f64) -> f64;
    fn str_or(&self, key: &str, default: &str) -> String;
    fn int_list_or(&self, key: &str, default: &[i64]) -> Vec<i64>;
    fn text_list(&self, key: &str) -> Vec<String>;
}

impl OptionMapExt for OptionMap {
    fn bool_or(&self, key: &str, default: bool) -> bool {
        self.get(key).and_then(OptValue::as_bool).unwrap_or(default)
    }
    fn int_or(&self, key: &str, default: i64) -> i64 {
        self.get(key).and_then(OptValue::as_int).unwrap_or(default)
    }
    fn float_or(&self, key: &str, default: f64) -> f64 {
        self.get(key).and_then(OptValue::as_float).unwrap_or(default)
    }
    fn str_or(&self, key: &str, default: &str) -> String {
        self.get(key)
            .and_then(OptValue::as_str)
            .unwrap_or(default)
            .to_string()
    }
    fn int_list_or(&self, key: &str, default: &[i64]) -> Vec<i64> {
        self.get(key)
            .and_then(OptValue::as_int_list)
            .map(|v| v.to_vec())
            .unwrap_or_else(|| default.to_vec())
    }
    fn text_list(&self, key: &str) -> Vec<String> {
        self.get(key)
            .and_then(OptValue::as_text_list)
            .map(|v| v.to_vec())
            .unwrap_or_default()
    }
}

/// What kind of control the GUI should draw for a setting, and what values are
/// legal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OptionKind {
    /// A checkbox.
    Toggle,
    /// An integer with inclusive bounds.
    Int { min: i64, max: i64 },
    /// A free text field.
    Text,
    /// A dropdown. Each entry is `(value, human label)`.
    Choice { choices: Vec<(String, String)> },
}

/// A provider's description of one setting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptionSpec {
    /// Stable machine key used in [`OptionMap`].
    pub key: String,
    /// Label shown in the UI.
    pub label: String,
    /// One or two sentences explaining the trade-off.
    pub help: String,
    /// Grouping header in the UI, e.g. "Transport" or "Obfuscation".
    pub group: String,
    pub kind: OptionKind,
    pub default: OptValue,
    /// When true, the benchmark matrix builder offers this setting as a
    /// dimension to sweep. When false it is a fixed deployment setting.
    pub benchmarkable: bool,
    /// Values the matrix builder offers for this dimension. Empty means
    /// "derive from `kind`" (both booleans for a toggle, all choices for a
    /// choice).
    #[serde(default)]
    pub bench_values: Vec<OptValue>,
}

impl OptionSpec {
    /// The values a benchmark sweep should consider for this setting.
    pub fn sweep_values(&self) -> Vec<OptValue> {
        if !self.bench_values.is_empty() {
            return self.bench_values.clone();
        }
        match &self.kind {
            OptionKind::Toggle => vec![OptValue::Bool(false), OptValue::Bool(true)],
            OptionKind::Choice { choices } => choices
                .iter()
                .map(|(v, _)| OptValue::Choice(v.clone()))
                .collect(),
            OptionKind::Int { min, max } => {
                vec![OptValue::Int(*min), OptValue::Int(*max)]
            }
            OptionKind::Text => vec![self.default.clone()],
        }
    }

    /// Human label for a particular value of this setting.
    pub fn label_for(&self, value: &OptValue) -> String {
        if let OptionKind::Choice { choices } = &self.kind {
            if let Some(v) = value.as_str() {
                for (cv, cl) in choices {
                    if cv == v {
                        return cl.clone();
                    }
                }
            }
        }
        value.short_display()
    }
}

/// The full set of settings a provider understands.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OptionSpace {
    pub specs: Vec<OptionSpec>,
}

impl OptionSpace {
    pub fn get(&self, key: &str) -> Option<&OptionSpec> {
        self.specs.iter().find(|s| s.key == key)
    }

    /// Every setting at its default value.
    pub fn defaults(&self) -> OptionMap {
        self.specs
            .iter()
            .map(|s| (s.key.clone(), s.default.clone()))
            .collect()
    }

    /// The settings the matrix builder can sweep, in declaration order.
    pub fn benchmarkable(&self) -> Vec<&OptionSpec> {
        self.specs.iter().filter(|s| s.benchmarkable).collect()
    }

    /// Group names in first-appearance order.
    pub fn groups(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for s in &self.specs {
            if !seen.iter().any(|g| g == &s.group) {
                seen.push(s.group.clone());
            }
        }
        seen
    }

    /// Fill in any setting missing from `map` with its default, and drop keys
    /// the provider no longer knows about.
    pub fn normalize(&self, map: &OptionMap) -> OptionMap {
        let mut out = OptionMap::new();
        for spec in &self.specs {
            let value = map.get(&spec.key).cloned().unwrap_or_else(|| spec.default.clone());
            out.insert(spec.key.clone(), value);
        }
        out
    }
}
