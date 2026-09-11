//! SSH transport: dialing (optionally through a proxy), host key pinning, and
//! the authenticated client every remote operation runs through.

pub mod dial;
pub mod hostkey;
pub mod session;

pub use hostkey::{fingerprint_sha256, HostKeyPolicy, HostKeyVerdict, KnownHosts};
pub use session::{CommandOutput, PrivMode, SshClient};
