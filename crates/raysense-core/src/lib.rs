pub mod facts;
pub mod graph;
pub mod health;
pub mod profile;
pub mod scanner;

pub use facts::{
    CallEdgeFact, CallFact, EntryPointFact, EntryPointKind, FileFact, FunctionFact, ImportFact,
    ImportResolution, Language, ScanReport, SnapshotFact,
};
pub use graph::GraphMetrics;
pub use health::{
    compute_health, compute_health_with_config, BoundaryConfig, ConfigError, FileHotspot,
    ForbiddenEdgeConfig, HealthSummary, RaysenseConfig, ResolutionBreakdown, RuleConfig,
};
pub use health::{RuleFinding, RuleSeverity};
pub use profile::ProjectProfile;
pub use scanner::{scan_path, ScanError};
