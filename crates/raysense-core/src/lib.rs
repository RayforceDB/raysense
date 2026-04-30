pub mod facts;
pub mod graph;
pub mod health;
pub mod scanner;

pub use facts::{
    FileFact, FunctionFact, ImportFact, ImportResolution, Language, ScanReport, SnapshotFact,
};
pub use graph::GraphMetrics;
pub use health::{compute_health, FileHotspot, HealthSummary, ResolutionBreakdown};
pub use scanner::{scan_path, ScanError};
