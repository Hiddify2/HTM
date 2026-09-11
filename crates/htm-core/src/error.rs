//! Error type shared by every layer of `htm-core`.
//!
//! Everything that can fail funnels into [`Error`]. The variants are chosen so
//! the GUI can react differently per case — most importantly
//! [`Error::HostKeyUnknown`] and [`Error::HostKeyMismatch`], which drive the
//! trust-on-first-use dialog instead of being shown as a plain failure.

use std::fmt;

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while managing servers and tunnels.
#[derive(Debug)]
pub enum Error {
    /// Local I/O failure (config files, key files, temp files).
    Io(std::io::Error),

    /// Failure reported by libssh2.
    Ssh(ssh2::Error),

    /// TCP connect / proxy negotiation failed before SSH could start.
    Connect { target: String, reason: String },

    /// The proxy refused or mishandled the CONNECT request.
    Proxy { proxy: String, reason: String },

    /// SSH authentication was rejected.
    Auth { user: String, reason: String },

    /// The host key is not yet known. Carries what the GUI needs to ask the
    /// user whether to trust it.
    HostKeyUnknown {
        host: String,
        port: u16,
        key_type: String,
        sha256: String,
        md5: String,
    },

    /// The host key changed since it was pinned. This is never auto-accepted.
    HostKeyMismatch {
        host: String,
        port: u16,
        expected_sha256: String,
        actual_sha256: String,
    },

    /// A remote command exited non-zero.
    Remote {
        command: String,
        status: i32,
        stdout: String,
        stderr: String,
    },

    /// Output from a remote command could not be understood.
    Parse { what: String, detail: String },

    /// The remote host is missing something HTM requires.
    Unsupported { detail: String },

    /// User input failed validation before anything was sent to a server.
    Validation(String),

    /// The local state store or secret vault could not be used.
    Store(String),

    /// Wrong master password, or the vault file is corrupt.
    Vault(String),

    /// A provider-specific failure.
    Provider { provider: String, detail: String },

    /// A benchmark variant could not be measured.
    Benchmark { variant: String, detail: String },

    /// The operation was cancelled from the UI.
    Cancelled,

    /// An operation exceeded its deadline.
    Timeout { what: String, seconds: u64 },

    /// Catch-all with a human-readable message.
    Other(String),
}

impl Error {
    /// Build an [`Error::Other`] from anything printable.
    pub fn msg(m: impl Into<String>) -> Self {
        Error::Other(m.into())
    }

    /// Build an [`Error::Validation`].
    pub fn invalid(m: impl Into<String>) -> Self {
        Error::Validation(m.into())
    }

    /// True when retrying the same operation might plausibly succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::Interrupted
            ),
            Error::Connect { .. } | Error::Ssh(_) | Error::Timeout { .. } => true,
            _ => false,
        }
    }

    /// True when the user must make a trust decision before we can continue.
    pub fn is_host_key_question(&self) -> bool {
        matches!(self, Error::HostKeyUnknown { .. })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Ssh(e) => write!(f, "ssh error: {e}"),
            Error::Connect { target, reason } => {
                write!(f, "could not connect to {target}: {reason}")
            }
            Error::Proxy { proxy, reason } => write!(f, "proxy {proxy} failed: {reason}"),
            Error::Auth { user, reason } => {
                write!(f, "authentication failed for user '{user}': {reason}")
            }
            Error::HostKeyUnknown {
                host,
                port,
                key_type,
                sha256,
                ..
            } => write!(
                f,
                "host key for {host}:{port} is not trusted yet ({key_type}, SHA256:{sha256})"
            ),
            Error::HostKeyMismatch {
                host,
                port,
                expected_sha256,
                actual_sha256,
            } => write!(
                f,
                "HOST KEY CHANGED for {host}:{port} — pinned SHA256:{expected_sha256}, \
                 server offered SHA256:{actual_sha256}"
            ),
            Error::Remote {
                command,
                status,
                stdout,
                stderr,
            } => {
                let detail = if !stderr.trim().is_empty() {
                    stderr.trim()
                } else {
                    stdout.trim()
                };
                write!(
                    f,
                    "remote command failed (exit {status}): {}\n{}",
                    shorten(command, 160),
                    shorten(detail, 600)
                )
            }
            Error::Parse { what, detail } => write!(f, "could not parse {what}: {detail}"),
            Error::Unsupported { detail } => write!(f, "unsupported remote host: {detail}"),
            Error::Validation(m) => write!(f, "{m}"),
            Error::Store(m) => write!(f, "state store error: {m}"),
            Error::Vault(m) => write!(f, "secret vault error: {m}"),
            Error::Provider { provider, detail } => write!(f, "[{provider}] {detail}"),
            Error::Benchmark { variant, detail } => {
                write!(f, "benchmark '{variant}' failed: {detail}")
            }
            Error::Cancelled => write!(f, "cancelled"),
            Error::Timeout { what, seconds } => {
                write!(f, "timed out after {seconds}s waiting for {what}")
            }
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Ssh(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ssh2::Error> for Error {
    fn from(e: ssh2::Error) -> Self {
        Error::Ssh(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Store(format!("json: {e}"))
    }
}

fn shorten(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max).collect();
    format!("{kept}…")
}
