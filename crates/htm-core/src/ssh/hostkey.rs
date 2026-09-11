//! Host key pinning.
//!
//! HTM keeps its own pin file rather than reading `~/.ssh/known_hosts`, so that
//! the desktop app never silently inherits or mutates the operator's OpenSSH
//! configuration. The policy is trust-on-first-use: an unknown key stops the
//! connection and is reported to the UI, which shows the fingerprint and asks.
//! A key that *changed* is never accepted without an explicit, separate
//! decision.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::model::HostKeyRecord;
use crate::util;

/// What checking a presented key against the pin file concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// The key matches the stored pin.
    Trusted,
    /// Nothing is pinned for this host yet.
    Unknown { sha256: String },
    /// A different key is pinned. This is the dangerous case.
    Changed {
        expected_sha256: String,
        actual_sha256: String,
    },
}

/// How a connection attempt should treat the host key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyPolicy {
    /// Fail on anything that is not already pinned. The default.
    Strict,
    /// Pin whatever the server presents, if nothing is pinned yet. A key that
    /// changed is still rejected.
    AcceptNew,
    /// Accept and pin this exact fingerprint, even replacing a different pin.
    /// Used only after the user confirmed the fingerprint in the UI.
    Trust { sha256: String },
}

impl Default for HostKeyPolicy {
    fn default() -> Self {
        HostKeyPolicy::Strict
    }
}

/// The pin file: a JSON map of `host:port` to the pinned key.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    path: PathBuf,
    entries: BTreeMap<String, HostKeyRecord>,
}

impl KnownHosts {
    /// Load the pin file, treating a missing file as an empty set.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Ok(Self {
                path,
                entries: BTreeMap::new(),
            });
        }
        let raw = std::fs::read_to_string(&path)?;
        if raw.trim().is_empty() {
            return Ok(Self {
                path,
                entries: BTreeMap::new(),
            });
        }
        let entries: BTreeMap<String, HostKeyRecord> = serde_json::from_str(&raw)
            .map_err(|e| Error::Store(format!("{} is not valid JSON: {e}", path.display())))?;
        Ok(Self { path, entries })
    }

    /// An in-memory set with no backing file. Used in tests.
    pub fn in_memory() -> Self {
        Self {
            path: PathBuf::new(),
            entries: BTreeMap::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write the pin file, creating parent directories as needed.
    pub fn save(&self) -> Result<()> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)?;
        crate::store::write_file_atomic(&self.path, json.as_bytes(), false)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn all(&self) -> impl Iterator<Item = &HostKeyRecord> {
        self.entries.values()
    }

    pub fn get(&self, host: &str, port: u16) -> Option<&HostKeyRecord> {
        self.entries.get(&HostKeyRecord::lookup_key(host, port))
    }

    pub fn remove(&mut self, host: &str, port: u16) -> Option<HostKeyRecord> {
        self.entries.remove(&HostKeyRecord::lookup_key(host, port))
    }

    pub fn insert(&mut self, record: HostKeyRecord) {
        self.entries.insert(record.key(), record);
    }

    /// Compare a presented key blob against the pin.
    pub fn verify(&self, host: &str, port: u16, key_blob: &[u8]) -> HostKeyVerdict {
        let actual = fingerprint_sha256(key_blob);
        match self.get(host, port) {
            None => HostKeyVerdict::Unknown { sha256: actual },
            Some(pinned) if pinned.sha256 == actual => HostKeyVerdict::Trusted,
            Some(pinned) => HostKeyVerdict::Changed {
                expected_sha256: pinned.sha256.clone(),
                actual_sha256: actual,
            },
        }
    }

    /// Apply `policy` to a presented key.
    ///
    /// Returns `Ok(true)` when the pin file changed and should be saved.
    pub fn apply_policy(
        &mut self,
        host: &str,
        port: u16,
        key_type: &str,
        key_blob: &[u8],
        md5: &str,
        policy: &HostKeyPolicy,
    ) -> Result<bool> {
        let verdict = self.verify(host, port, key_blob);
        match (&verdict, policy) {
            (HostKeyVerdict::Trusted, _) => Ok(false),

            // A brand new host.
            (HostKeyVerdict::Unknown { sha256 }, HostKeyPolicy::AcceptNew) => {
                self.pin(host, port, key_type, key_blob, sha256.clone());
                Ok(true)
            }
            (HostKeyVerdict::Unknown { sha256 }, HostKeyPolicy::Trust { sha256: approved }) => {
                if approved == sha256 {
                    self.pin(host, port, key_type, key_blob, sha256.clone());
                    Ok(true)
                } else {
                    Err(Error::HostKeyMismatch {
                        host: host.to_string(),
                        port,
                        expected_sha256: approved.clone(),
                        actual_sha256: sha256.clone(),
                    })
                }
            }
            (HostKeyVerdict::Unknown { sha256 }, HostKeyPolicy::Strict) => {
                Err(Error::HostKeyUnknown {
                    host: host.to_string(),
                    port,
                    key_type: key_type.to_string(),
                    sha256: sha256.clone(),
                    md5: md5.to_string(),
                })
            }

            // The pinned key no longer matches. Only an explicit approval of
            // the new fingerprint gets through.
            (
                HostKeyVerdict::Changed {
                    expected_sha256,
                    actual_sha256,
                },
                HostKeyPolicy::Trust { sha256: approved },
            ) if approved == actual_sha256 => {
                let _ = expected_sha256;
                self.pin(host, port, key_type, key_blob, actual_sha256.clone());
                Ok(true)
            }
            (
                HostKeyVerdict::Changed {
                    expected_sha256,
                    actual_sha256,
                },
                _,
            ) => Err(Error::HostKeyMismatch {
                host: host.to_string(),
                port,
                expected_sha256: expected_sha256.clone(),
                actual_sha256: actual_sha256.clone(),
            }),
        }
    }

    fn pin(&mut self, host: &str, port: u16, key_type: &str, key_blob: &[u8], sha256: String) {
        self.insert(HostKeyRecord {
            host: host.to_string(),
            port,
            key_type: key_type.to_string(),
            key_base64: base64::engine::general_purpose::STANDARD.encode(key_blob),
            sha256,
            first_seen: chrono::Utc::now(),
        });
    }
}

/// The OpenSSH-style SHA-256 fingerprint of a key blob, without the `SHA256:`
/// prefix and without base64 padding — the same text `ssh-keygen -lf` prints.
pub fn fingerprint_sha256(key_blob: &[u8]) -> String {
    let digest = Sha256::digest(key_blob);
    util::ssh_fingerprint_sha256(&digest)
}

/// Render a host key type for display.
pub fn key_type_name(kind: ssh2::HostKeyType) -> &'static str {
    match kind {
        ssh2::HostKeyType::Rsa => "ssh-rsa",
        ssh2::HostKeyType::Dss => "ssh-dss",
        ssh2::HostKeyType::Ecdsa256 => "ecdsa-sha2-nistp256",
        ssh2::HostKeyType::Ecdsa384 => "ecdsa-sha2-nistp384",
        ssh2::HostKeyType::Ecdsa521 => "ecdsa-sha2-nistp521",
        ssh2::HostKeyType::Ed25519 => "ssh-ed25519",
        ssh2::HostKeyType::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_host_is_rejected_under_strict_policy() {
        let mut kh = KnownHosts::in_memory();
        let err = kh
            .apply_policy(
                "example.com",
                22,
                "ssh-ed25519",
                b"key-bytes",
                "",
                &HostKeyPolicy::Strict,
            )
            .unwrap_err();
        assert!(err.is_host_key_question());
    }

    #[test]
    fn tofu_pins_then_trusts() {
        let mut kh = KnownHosts::in_memory();
        assert!(kh
            .apply_policy(
                "example.com",
                22,
                "ssh-ed25519",
                b"key-bytes",
                "",
                &HostKeyPolicy::AcceptNew
            )
            .unwrap());
        // Second time it is already trusted and nothing changes.
        assert!(!kh
            .apply_policy(
                "example.com",
                22,
                "ssh-ed25519",
                b"key-bytes",
                "",
                &HostKeyPolicy::Strict
            )
            .unwrap());
    }

    #[test]
    fn changed_key_is_refused_even_under_accept_new() {
        let mut kh = KnownHosts::in_memory();
        kh.apply_policy(
            "example.com",
            22,
            "ssh-ed25519",
            b"key-one",
            "",
            &HostKeyPolicy::AcceptNew,
        )
        .unwrap();
        let err = kh
            .apply_policy(
                "example.com",
                22,
                "ssh-ed25519",
                b"key-two",
                "",
                &HostKeyPolicy::AcceptNew,
            )
            .unwrap_err();
        assert!(matches!(err, Error::HostKeyMismatch { .. }));
    }

    #[test]
    fn explicit_trust_replaces_a_changed_pin() {
        let mut kh = KnownHosts::in_memory();
        kh.apply_policy(
            "example.com",
            22,
            "ssh-ed25519",
            b"key-one",
            "",
            &HostKeyPolicy::AcceptNew,
        )
        .unwrap();
        let new_fp = fingerprint_sha256(b"key-two");
        assert!(kh
            .apply_policy(
                "example.com",
                22,
                "ssh-ed25519",
                b"key-two",
                "",
                &HostKeyPolicy::Trust { sha256: new_fp },
            )
            .unwrap());
        assert_eq!(
            kh.verify("example.com", 22, b"key-two"),
            HostKeyVerdict::Trusted
        );
    }
}
