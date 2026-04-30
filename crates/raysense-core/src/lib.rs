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
pub use health::{compute_health, FileHotspot, HealthSummary, ResolutionBreakdown};
pub use health::{RuleFinding, RuleSeverity};
pub use profile::ProjectProfile;
pub use scanner::{scan_path, ScanError};
