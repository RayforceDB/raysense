/*
 *   Copyright (c) 2025-2026 Anton Kundenko <singaraiona@gmail.com>
 *   All rights reserved.
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in all
 *   copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *   SOFTWARE.
 */

pub mod baseline;
pub mod facts;
pub mod graph;
pub mod health;
pub mod profile;
pub mod scanner;

pub use baseline::{
    build_baseline, diff_baselines, BaselineDiff, BaselineModuleEdge, ModuleEdgeDelta,
    ProjectBaseline,
};
pub use facts::{
    CallEdgeFact, CallFact, EntryPointFact, EntryPointKind, FileFact, FunctionFact, ImportFact,
    ImportResolution, Language, ScanReport, SnapshotFact,
};
pub use graph::GraphMetrics;
pub use health::{
    compute_health, compute_health_with_config, is_foundation_file, BoundaryConfig,
    ComplexityMetrics, ConfigError, DuplicateFunctionGroup, FileHotspot, ForbiddenEdgeConfig,
    FunctionComplexityMetric, HealthSummary, LanguagePluginConfig, LayerConfig,
    ModuleDistanceMetric, RaysenseConfig, Remediation, ResolutionBreakdown, RuleConfig, ScanConfig,
    ScoreConfig, TestGapCandidate, TestGapMetrics, TrendMetrics,
};
pub use health::{RuleFinding, RuleSeverity};
pub use profile::ProjectProfile;
pub use scanner::{scan_path, scan_path_with_config, standard_language_plugins, ScanError};
