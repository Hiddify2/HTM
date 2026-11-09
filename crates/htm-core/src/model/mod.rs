//! Plain data types shared by every layer. Nothing here touches the network or
//! the filesystem, so it is all trivially testable.

pub mod bench;
pub mod options;
pub mod server;
pub mod tunnel;

pub use bench::{
    score_results, BenchMetrics, BenchOutcome, BenchResult, BenchRun, BenchSettings, BenchVariant,
    MatrixSelection, ScoreWeights, ThroughputTool,
};
pub use options::{OptValue, OptionKind, OptionMap, OptionMapExt, OptionSpace, OptionSpec};
pub use server::{
    AuthKind, HostKeyRecord, PackageManager, ProxyConfig, ProxyKind, ServerCredentials,
    ServerFacts, ServerProfile, ServerSecrets, TunnelSide,
};
pub use tunnel::{
    is_ipv4, EndpointPlan, Health, IfaceStats, ServiceAction, ServiceStatus, FakeMode,
    FakePlan, TunSlot, TunnelInstance, TunnelPlan, TunnelStatus,
};
