//! The local secret vault.
//!
//! SSH passwords, key passphrases, sudo passwords and proxy passwords are kept
//! in `secrets.bin`, encrypted with AES-256-GCM. The key comes from one of two
//! places:
//!
//! * **A master password** the user types at startup, stretched with Argon2id.
//!   This is real protection: without the password the file is useless.
//! * **A device key** — 32 random bytes in `device.key`, owner-readable only.
//!   This protects against casual reading and against the file being copied
//!   somewhere else, but anyone who can read `device.key` can read the vault.
//!   The UI says exactly that rather than implying more.
//!
//! File format, all little-endian, no padding:
//!
//! ```text
//! offset  size  field
//! 0       8     magic "HTMVAULT"
//! 8       1     format version (1)
//! 9       1     key source (1 = master password, 2 = device key)
//! 10      16    salt
//! 26      12    nonce
//! 38      ..    AES-256-GCM ciphertext, 16-byte tag included
//! ```
//!
//! The header is authenticated as additional data, so the key-source byte
//! cannot be flipped to trick HTM into trying the wrong key silently.

use std::collections::BTreeMap;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::ServerSecrets;
use crate::store::write_file_atomic;

const MAGIC: &[u8; 8] = b"HTMVAULT";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 8 + 1 + 1 + SALT_LEN + NONCE_LEN;
const DEVICE_KEY_LEN: usize = 32;

const SOURCE_MASTER: u8 = 1;
const SOURCE_DEVICE: u8 = 2;

/// Where the encryption key comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Derived from a password the user types.
    MasterPassword(String),
    /// Derived from `device.key`.
    DeviceKey(Vec<u8>),
}

impl KeySource {
    fn tag(&self) -> u8 {
        match self {
            KeySource::MasterPassword(_) => SOURCE_MASTER,
            KeySource::DeviceKey(_) => SOURCE_DEVICE,
        }
    }

    fn material(&self) -> &[u8] {
        match self {
            KeySource::MasterPassword(p) => p.as_bytes(),
            KeySource::DeviceKey(k) => k.as_slice(),
        }
    }

    pub fn is_master_password(&self) -> bool {
        matches!(self, KeySource::MasterPassword(_))
    }
}

/// Load `device.key`, creating it with 32 random bytes the first time.
pub fn load_or_create_device_key(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() >= 16 {
            return Ok(bytes);
        }
        // A truncated key file would silently weaken everything; refuse rather
        // than regenerate, because regenerating would orphan the vault.
        return Err(Error::Vault(format!(
            "{} is only {} bytes long and cannot be a valid device key. Delete it together with \
             secrets.bin to start over, or restore both from a backup.",
            path.display(),
            bytes.len()
        )));
    }

    let mut key = vec![0u8; DEVICE_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    write_file_atomic(path, &key, true)?;
    Ok(key)
}

/// The decrypted contents of the vault.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VaultData {
    /// Server profile id to its secrets.
    #[serde(default)]
    pub servers: BTreeMap<String, ServerSecrets>,
}

/// An open vault. Kept in memory in plaintext for the life of the process,
/// which is unavoidable: the passwords have to be usable.
#[derive(Debug, Clone, Default)]
pub struct Vault {
    data: VaultData,
    dirty: bool,
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decrypt `path`. A missing file yields an empty vault.
    pub fn open(path: &Path, source: &KeySource) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read(path)?;
        if raw.is_empty() {
            return Ok(Self::default());
        }
        let data = decrypt(&raw, source)?;
        Ok(Self { data, dirty: false })
    }

    /// Report which key source a vault file was written with, without needing
    /// the key. Used at startup to decide whether to prompt for a password.
    pub fn peek_key_source(path: &Path) -> Result<Option<u8>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(path)?;
        if raw.len() < HEADER_LEN {
            return Ok(None);
        }
        if &raw[..8] != MAGIC {
            return Err(Error::Vault(format!(
                "{} does not look like an HTM vault file.",
                path.display()
            )));
        }
        Ok(Some(raw[9]))
    }

    /// True when the vault file was written with a master password.
    pub fn file_needs_master_password(path: &Path) -> Result<bool> {
        Ok(Self::peek_key_source(path)? == Some(SOURCE_MASTER))
    }

    pub fn save(&mut self, path: &Path, source: &KeySource) -> Result<()> {
        let blob = encrypt(&self.data, source)?;
        write_file_atomic(path, &blob, true)?;
        self.dirty = false;
        Ok(())
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Secrets for a server, or an empty set when none are stored.
    pub fn secrets(&self, server_id: &str) -> ServerSecrets {
        self.data.servers.get(server_id).cloned().unwrap_or_default()
    }

    pub fn has_secrets(&self, server_id: &str) -> bool {
        self.data
            .servers
            .get(server_id)
            .map(|s| !s.is_empty())
            .unwrap_or(false)
    }

    pub fn set_secrets(&mut self, server_id: &str, secrets: ServerSecrets) {
        if secrets.is_empty() {
            self.data.servers.remove(server_id);
        } else {
            self.data.servers.insert(server_id.to_string(), secrets);
        }
        self.dirty = true;
    }

    pub fn remove(&mut self, server_id: &str) {
        if self.data.servers.remove(server_id).is_some() {
            self.dirty = true;
        }
    }

    /// Drop every stored secret. Used when the user resets the vault.
    pub fn clear(&mut self) {
        self.data.servers.clear();
        self.dirty = true;
    }

    pub fn server_ids(&self) -> Vec<String> {
        self.data.servers.keys().cloned().collect()
    }
}

/// Stretch the key material into a 32-byte AES key.
fn derive_key(source: &KeySource, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    // Argon2id with the crate's defaults: 19 MiB, 2 passes, 1 lane — the
    // parameters OWASP recommends as a baseline.
    argon2::Argon2::default()
        .hash_password_into(source.material(), salt, &mut key)
        .map_err(|e| Error::Vault(format!("key derivation failed: {e}")))?;
    Ok(key)
}

fn encrypt(data: &VaultData, source: &KeySource) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(data)?;

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.push(source.tag());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce_bytes);

    let key_bytes = derive_key(source, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| Error::Vault("encryption failed".to_string()))?;

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(raw: &[u8], source: &KeySource) -> Result<VaultData> {
    if raw.len() < HEADER_LEN + 16 {
        return Err(Error::Vault(
            "the vault file is too short to be valid.".to_string(),
        ));
    }
    if &raw[..8] != MAGIC {
        return Err(Error::Vault(
            "the vault file does not start with the expected marker.".to_string(),
        ));
    }
    let version = raw[8];
    if version != VERSION {
        return Err(Error::Vault(format!(
            "the vault file uses format version {version}, but this build understands version \
             {VERSION}."
        )));
    }
    let stored_source = raw[9];
    if stored_source != source.tag() {
        return Err(Error::Vault(match stored_source {
            SOURCE_MASTER => "this vault is protected by a master password.".to_string(),
            SOURCE_DEVICE => {
                "this vault is protected by the device key, not a master password.".to_string()
            }
            other => format!("this vault uses an unknown key source ({other})."),
        }));
    }

    let salt = &raw[10..10 + SALT_LEN];
    let nonce_bytes = &raw[10 + SALT_LEN..HEADER_LEN];
    let header = &raw[..HEADER_LEN];
    let ciphertext = &raw[HEADER_LEN..];

    let key_bytes = derive_key(source, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|_| {
            Error::Vault(if source.is_master_password() {
                "wrong master password, or the vault file has been altered.".to_string()
            } else {
                "the vault could not be decrypted. device.key may have been replaced or the file \
                 copied from another machine."
                    .to_string()
            })
        })?;

    Ok(serde_json::from_slice(&plaintext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultData {
        let mut data = VaultData::default();
        data.servers.insert(
            "srv-1".to_string(),
            ServerSecrets {
                password: "hunter2".into(),
                key_passphrase: String::new(),
                sudo_password: "sudo-pw".into(),
                proxy_password: String::new(),
            },
        );
        data
    }

    #[test]
    fn round_trips_with_a_master_password() {
        let source = KeySource::MasterPassword("correct horse".into());
        let blob = encrypt(&sample(), &source).unwrap();
        let back = decrypt(&blob, &source).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let blob = encrypt(&sample(), &KeySource::MasterPassword("right".into())).unwrap();
        let err = decrypt(&blob, &KeySource::MasterPassword("wrong".into())).unwrap_err();
        assert!(matches!(err, Error::Vault(_)));
    }

    #[test]
    fn key_source_mismatch_is_reported_clearly() {
        let blob = encrypt(&sample(), &KeySource::MasterPassword("pw".into())).unwrap();
        let err = decrypt(&blob, &KeySource::DeviceKey(vec![7u8; 32])).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("master password"), "{text}");
    }

    #[test]
    fn tampering_with_the_header_is_detected() {
        let source = KeySource::DeviceKey(vec![3u8; 32]);
        let mut blob = encrypt(&sample(), &source).unwrap();
        // Flip a salt byte: the header is authenticated, so this must fail.
        blob[12] ^= 0xFF;
        assert!(decrypt(&blob, &source).is_err());
    }

    #[test]
    fn empty_vault_round_trips() {
        let source = KeySource::DeviceKey(vec![1u8; 32]);
        let blob = encrypt(&VaultData::default(), &source).unwrap();
        assert_eq!(decrypt(&blob, &source).unwrap(), VaultData::default());
    }
}
