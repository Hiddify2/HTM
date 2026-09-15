//! Operations performed on a remote host: identifying it, installing packages,
//! driving systemd, and measuring the network.

pub mod diagnostics;
pub mod facts;
pub mod net;
pub mod pkg;
pub mod systemd;

pub use diagnostics::{report as diagnose_tunnel, HostDiagnostics};
pub use facts::{gather as gather_facts, normalize_arch};
pub use net::{Backend as MeasureBackend, PingSample, ThroughputSample};
pub use pkg::InstallReport;
pub use systemd::JournalChunk;
