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

use crate::facts::{EntryPointKind, FileFact, ImportResolution, ScanReport};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RaysenseConfig {
    pub scan: ScanConfig,
    pub rules: RuleConfig,
    pub boundaries: BoundaryConfig,
    pub score: ScoreConfig,
    pub grades: GradeThresholds,
}

impl RaysenseConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&content).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub ignored_paths: Vec<String>,
    pub generated_paths: Vec<String>,
    pub enabled_languages: Vec<String>,
    pub disabled_languages: Vec<String>,
    pub module_roots: Vec<String>,
    pub test_roots: Vec<String>,
    pub public_api_paths: Vec<String>,
    pub plugins: Vec<LanguagePluginConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GradeThresholds {
    pub a: f64,
    pub b: f64,
    pub c: f64,
    pub d: f64,
}

impl Default for GradeThresholds {
    fn default() -> Self {
        Self {
            a: 0.9,
            b: 0.8,
            c: 0.7,
            d: 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScoreConfig {
    pub modularity_weight: f64,
    pub acyclicity_weight: f64,
    pub depth_weight: f64,
    pub equality_weight: f64,
    pub redundancy_weight: f64,
    pub structural_uniformity_weight: f64,
}

impl Default for ScoreConfig {
    fn default() -> Self {
        Self {
            modularity_weight: 1.0,
            acyclicity_weight: 1.0,
            depth_weight: 1.0,
            equality_weight: 1.0,
            redundancy_weight: 1.0,
            // Default 0.0 keeps existing scores byte-exact; raise to opt the
            // structural-distribution dimension into quality_signal.
            structural_uniformity_weight: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LanguagePluginConfig {
    pub name: String,
    pub grammar: Option<String>,
    pub grammar_path: Option<String>,
    pub grammar_symbol: Option<String>,
    pub extensions: Vec<String>,
    pub file_names: Vec<String>,
    pub function_prefixes: Vec<String>,
    pub import_prefixes: Vec<String>,
    pub call_suffixes: Vec<String>,
    pub abstract_type_prefixes: Vec<String>,
    pub concrete_type_prefixes: Vec<String>,
    pub tags_query: Option<String>,
    pub package_index_files: Vec<String>,
    pub test_path_patterns: Vec<String>,
    pub source_roots: Vec<String>,
    pub ignored_paths: Vec<String>,
    pub local_import_prefixes: Vec<String>,
    pub max_function_complexity: Option<usize>,
    pub max_cognitive_complexity: Option<usize>,
    pub max_file_lines: Option<usize>,
    pub max_function_lines: Option<usize>,
    /// Files whose contents declare path aliases (e.g. `tsconfig.json`,
    /// `.cargo/config.toml`). Consumed by import resolution.
    pub resolver_alias_files: Vec<String>,
    /// Module-name separator used by the language (e.g. "." for Python,
    /// "::" for Rust). Used when joining/splitting module paths.
    pub namespace_separator: Option<String>,
    /// File names that introduce a module by their location (e.g.
    /// `mod.rs`, `__init__.py`).
    pub module_prefix_files: Vec<String>,
    /// Source-line directives that declare a module name (e.g. `package `,
    /// `module `).
    pub module_prefix_directives: Vec<String>,
    /// Symbol names that should be treated as entry points (e.g. `main`,
    /// `init`).
    pub entry_point_patterns: Vec<String>,
    /// Path patterns matching test modules (in addition to `test_path_patterns`).
    pub test_module_patterns: Vec<String>,
    /// Source-line attributes/decorators that mark a function as a test
    /// (e.g. `#[test]`, `@Test`).
    pub test_attribute_patterns: Vec<String>,
    /// Tree-sitter node kinds representing function parameter declarations.
    pub parameter_node_kinds: Vec<String>,
    /// Tree-sitter node kinds that increment cyclomatic complexity (`if`,
    /// `while`, `match_arm`, ...).
    pub complexity_node_kinds: Vec<String>,
    /// Tree-sitter node kinds for logical operators that contribute to
    /// cognitive complexity (`&&`, `||`).
    pub logical_operator_kinds: Vec<String>,
    /// Built-in or well-known abstract base class names for the language.
    pub abstract_base_classes: Vec<String>,
}

impl Default for LanguagePluginConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            grammar: None,
            grammar_path: None,
            grammar_symbol: None,
            extensions: Vec::new(),
            file_names: Vec::new(),
            function_prefixes: vec![
                "function ".to_string(),
                "def ".to_string(),
                "fn ".to_string(),
            ],
            import_prefixes: vec![
                "import ".to_string(),
                "use ".to_string(),
                "require ".to_string(),
            ],
            call_suffixes: vec!["(".to_string()],
            abstract_type_prefixes: Vec::new(),
            concrete_type_prefixes: Vec::new(),
            tags_query: None,
            package_index_files: Vec::new(),
            test_path_patterns: Vec::new(),
            source_roots: Vec::new(),
            ignored_paths: Vec::new(),
            local_import_prefixes: vec![".".to_string()],
            max_function_complexity: None,
            max_cognitive_complexity: None,
            max_file_lines: None,
            max_function_lines: None,
            resolver_alias_files: Vec::new(),
            namespace_separator: None,
            module_prefix_files: Vec::new(),
            module_prefix_directives: Vec::new(),
            entry_point_patterns: Vec::new(),
            test_module_patterns: Vec::new(),
            test_attribute_patterns: Vec::new(),
            parameter_node_kinds: Vec::new(),
            complexity_node_kinds: Vec::new(),
            logical_operator_kinds: Vec::new(),
            abstract_base_classes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    pub min_quality_signal: u32,
    pub min_modularity: f64,
    pub min_acyclicity: f64,
    pub min_depth: f64,
    pub min_equality: f64,
    pub min_redundancy: f64,
    pub max_cycles: usize,
    pub max_coupling_ratio: f64,
    pub max_function_complexity: usize,
    pub max_cognitive_complexity: usize,
    pub max_file_lines: usize,
    pub max_function_lines: usize,
    pub no_god_files: bool,
    pub high_file_fan_in: usize,
    pub high_file_fan_out: usize,
    pub large_file_lines: usize,
    pub max_large_file_findings: usize,
    pub low_call_resolution_min_calls: usize,
    pub low_call_resolution_ratio: f64,
    pub high_function_fan_in: usize,
    pub high_function_fan_out: usize,
    pub max_call_hotspot_findings: usize,
    pub max_upward_layer_violations: usize,
    pub no_tests_detected: bool,
    /// Per-language overrides keyed by `language_name` (case-insensitive).
    /// Each override field, when set, takes precedence over the matching
    /// global field for files in that language. Useful when one language's
    /// idioms make a global threshold either too strict or too lax (e.g.
    /// Rust `match` arms inflate cyclomatic vs Python's flat conditionals).
    pub language_overrides: BTreeMap<String, LanguageRuleOverride>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LanguageRuleOverride {
    pub max_function_complexity: Option<usize>,
    pub max_cognitive_complexity: Option<usize>,
    pub max_file_lines: Option<usize>,
    pub max_function_lines: Option<usize>,
    pub high_file_fan_in: Option<usize>,
    pub high_file_fan_out: Option<usize>,
    pub large_file_lines: Option<usize>,
    pub high_function_fan_in: Option<usize>,
    pub high_function_fan_out: Option<usize>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            min_quality_signal: 0,
            min_modularity: 0.0,
            min_acyclicity: 0.0,
            min_depth: 0.0,
            min_equality: 0.0,
            min_redundancy: 0.0,
            high_file_fan_in: 50,
            high_file_fan_out: 15,
            max_cycles: 0,
            max_coupling_ratio: 1.0,
            max_function_complexity: 15,
            max_cognitive_complexity: 0,
            max_file_lines: 0,
            max_function_lines: 0,
            no_god_files: true,
            large_file_lines: 500,
            max_large_file_findings: 20,
            low_call_resolution_min_calls: 100,
            low_call_resolution_ratio: 0.5,
            high_function_fan_in: 200,
            high_function_fan_out: 100,
            max_call_hotspot_findings: 5,
            max_upward_layer_violations: 0,
            no_tests_detected: true,
            language_overrides: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BoundaryConfig {
    pub forbidden_edges: Vec<ForbiddenEdgeConfig>,
    pub layers: Vec<LayerConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ForbiddenEdgeConfig {
    pub from: String,
    pub to: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerConfig {
    pub name: String,
    pub path: String,
    pub order: i32,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub score: u8,
    pub quality_signal: u32,
    pub coverage_score: u8,
    pub structural_score: u8,
    pub root_causes: RootCauseScores,
    #[serde(default)]
    pub grades: GradeSummary,
    pub metrics: MetricsSummary,
    pub resolution: ResolutionBreakdown,
    pub hotspots: Vec<FileHotspot>,
    pub rules: Vec<RuleFinding>,
    pub remediations: Vec<Remediation>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GradeSummary {
    pub overall: String,
    pub modularity: String,
    pub acyclicity: String,
    pub depth: String,
    pub equality: String,
    pub redundancy: String,
    pub structural_uniformity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub coupling: CouplingMetrics,
    pub calls: CallMetrics,
    pub architecture: ArchitectureMetrics,
    pub complexity: ComplexityMetrics,
    pub size: SizeMetrics,
    pub entry_points: EntryPointMetrics,
    pub test_gap: TestGapMetrics,
    pub dsm: DsmMetrics,
    pub evolution: EvolutionMetrics,
    pub trend: TrendMetrics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootCauseScores {
    pub modularity: f64,
    pub acyclicity: f64,
    pub depth: f64,
    pub equality: f64,
    pub redundancy: f64,
    pub structural_uniformity: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArchitectureMetrics {
    pub module_depth: usize,
    pub max_blast_radius: usize,
    pub max_blast_radius_file: String,
    pub max_non_foundation_blast_radius: usize,
    pub max_non_foundation_blast_radius_file: String,
    pub attack_surface_files: usize,
    pub attack_surface_ratio: f64,
    pub total_graph_files: usize,
    pub average_distance_from_main_sequence: f64,
    pub levels: BTreeMap<String, usize>,
    pub upward_violations: Vec<DependencyViolationMetric>,
    pub upward_violation_ratio: f64,
    pub unstable_modules: Vec<ModuleStabilityMetric>,
    pub stable_foundations: Vec<ModuleStabilityMetric>,
    pub distance_metrics: Vec<ModuleDistanceMetric>,
    pub cycles: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleStabilityMetric {
    pub module: String,
    pub fan_in: usize,
    pub fan_out: usize,
    pub instability: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleDistanceMetric {
    pub module: String,
    pub abstractness: f64,
    pub instability: f64,
    pub distance: f64,
    pub abstract_count: usize,
    pub total_types: usize,
    pub fan_in: usize,
    pub fan_out: usize,
    pub is_foundation: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DependencyViolationMetric {
    pub from_file_id: usize,
    pub from_path: String,
    pub from_level: usize,
    pub to_file_id: usize,
    pub to_path: String,
    pub to_level: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    pub max_function_complexity: usize,
    pub max_cognitive_complexity: usize,
    pub average_function_complexity: f64,
    pub average_cognitive_complexity: f64,
    pub complexity_gini: f64,
    pub complexity_entropy: f64,
    pub complexity_entropy_bits: f64,
    pub all_functions: Vec<FunctionComplexityMetric>,
    pub complex_functions: Vec<FunctionComplexityMetric>,
    pub dead_functions: Vec<FunctionComplexityMetric>,
    pub duplicate_groups: Vec<DuplicateFunctionGroup>,
    pub semantic_duplicate_groups: Vec<DuplicateFunctionGroup>,
    pub redundancy_ratio: f64,
    pub public_api_functions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionComplexityMetric {
    pub function_id: usize,
    pub file_id: usize,
    pub path: String,
    pub name: String,
    pub value: usize,
    pub cognitive_value: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateFunctionGroup {
    pub fingerprint: String,
    pub name: String,
    pub functions: Vec<FunctionComplexityMetric>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CouplingMetrics {
    pub local_edges: usize,
    pub cross_module_edges: usize,
    pub cross_unstable_edges: usize,
    pub cross_module_ratio: f64,
    pub cross_unstable_ratio: f64,
    pub entropy: f64,
    pub entropy_bits: f64,
    pub entropy_pairs: usize,
    pub average_module_cohesion: Option<f64>,
    pub cohesive_module_count: usize,
    pub god_files: Vec<FileCouplingMetric>,
    pub unstable_hotspots: Vec<FileCouplingMetric>,
    pub most_unstable_files: Vec<FileInstabilityMetric>,
    pub max_fan_in: usize,
    pub max_fan_out: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileCouplingMetric {
    pub file_id: usize,
    pub path: String,
    pub fan_in: usize,
    pub fan_out: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileInstabilityMetric {
    pub file_id: usize,
    pub path: String,
    pub fan_in: usize,
    pub fan_out: usize,
    pub instability: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallMetrics {
    pub total_calls: usize,
    pub resolved_edges: usize,
    pub resolution_ratio: f64,
    pub max_function_fan_in: usize,
    pub max_function_fan_out: usize,
    pub top_called_functions: Vec<FunctionCallMetric>,
    pub top_calling_functions: Vec<FunctionCallMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCallMetric {
    pub function_id: usize,
    pub file_id: usize,
    pub path: String,
    pub name: String,
    pub calls: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SizeMetrics {
    pub max_file_lines: usize,
    pub max_function_lines: usize,
    pub large_files: usize,
    pub long_functions: usize,
    pub file_size_entropy: f64,
    pub file_size_entropy_bits: f64,
    #[serde(default)]
    pub total_lines: usize,
    #[serde(default)]
    pub total_comment_lines: usize,
    #[serde(default)]
    pub comment_ratio: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryPointMetrics {
    pub binaries: usize,
    pub examples: usize,
    pub tests: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TestGapMetrics {
    pub production_files: usize,
    pub test_files: usize,
    pub files_without_nearby_tests: usize,
    pub candidates: Vec<TestGapCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestGapCandidate {
    pub file_id: usize,
    pub path: String,
    pub framework: String,
    pub expected_tests: Vec<String>,
    pub matched_tests: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrendMetrics {
    pub available: bool,
    pub samples: usize,
    pub score_delta: i16,
    pub quality_signal_delta: i32,
    pub rule_delta: isize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub code: String,
    pub path: String,
    pub action: String,
    pub command: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DsmMetrics {
    pub module_count: usize,
    pub module_edges: usize,
    pub top_module_edges: Vec<ModuleEdgeMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEdgeMetric {
    pub from_module: String,
    pub to_module: String,
    pub edges: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvolutionMetrics {
    pub available: bool,
    pub reason: String,
    pub commits_sampled: usize,
    pub changed_files: usize,
    pub top_changed_files: Vec<EvolutionFileMetric>,
    #[serde(default)]
    pub author_count: usize,
    #[serde(default)]
    pub top_authors: Vec<EvolutionAuthorMetric>,
    #[serde(default)]
    pub file_ownership: Vec<EvolutionFileOwnership>,
    #[serde(default)]
    pub temporal_hotspots: Vec<EvolutionTemporalHotspot>,
    #[serde(default)]
    pub file_ages: Vec<EvolutionFileAge>,
    #[serde(default)]
    pub change_coupling: Vec<EvolutionChangeCoupling>,
    /// Count of sampled commits whose subject matches a bug-fix pattern
    /// (`^(fix|bugfix|hotfix|revert)(\([^)]*\))?[:!]?\s`).
    #[serde(default)]
    pub bug_fix_commits: usize,
    /// Top files ranked by absolute bug-fix-commit count, then by ratio.
    #[serde(default)]
    pub bug_prone_files: Vec<EvolutionBugProneFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionFileMetric {
    pub path: String,
    pub commits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionAuthorMetric {
    pub author: String,
    pub commits: usize,
}

/// `risk_score = commits * max_cyclomatic_complexity` - high values flag files
/// that are both volatile and intricate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionTemporalHotspot {
    pub path: String,
    pub commits: usize,
    pub max_complexity: usize,
    pub risk_score: usize,
}

/// Per-file commit-age window. Timestamps are bounded by the git log lookback,
/// so `first_commit_unix` is the oldest commit *within the sample*, not
/// necessarily the file's true creation date.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionFileAge {
    pub path: String,
    pub first_commit_unix: i64,
    pub last_commit_unix: i64,
    pub age_days: u64,
    pub last_changed_days: u64,
}

/// Pair of files that change together. `coupling_strength` is the Jaccard
/// similarity of their commit sets in `[0, 1]` (1.0 = always co-changed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionChangeCoupling {
    pub left: String,
    pub right: String,
    pub co_commits: usize,
    pub coupling_strength: f64,
}

/// Per-file bug-fix concentration. Files with a high `bug_fix_ratio`
/// are unstable areas of the codebase: most of their churn is undoing
/// previous changes rather than adding capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionBugProneFile {
    pub path: String,
    pub bug_fix_commits: usize,
    pub total_commits: usize,
    pub bug_fix_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionFileOwnership {
    pub path: String,
    pub top_author: String,
    pub top_author_commits: usize,
    pub total_commits: usize,
    pub author_count: usize,
    /// Minimum number of authors needed to cover at least 80% of commits to
    /// this file. Lower values mean higher key-person risk.
    pub bus_factor: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolutionBreakdown {
    pub local: usize,
    pub external: usize,
    pub system: usize,
    pub unresolved: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHotspot {
    pub file_id: usize,
    pub path: String,
    pub module: String,
    pub fan_in: usize,
    pub fan_out: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFinding {
    pub severity: RuleSeverity,
    pub code: String,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSeverity {
    Info,
    Warning,
    Error,
}

pub fn compute_health(report: &ScanReport) -> HealthSummary {
    compute_health_with_config(report, &RaysenseConfig::default())
}

pub fn compute_health_with_config(report: &ScanReport, config: &RaysenseConfig) -> HealthSummary {
    let resolution = resolution_breakdown(report);
    let hotspots = hotspots(report);
    let metrics = metrics(report, &hotspots, config);
    let rules = rules(report, &hotspots, &metrics, config);
    let remediations = remediations(&rules, &metrics);
    let root_causes = root_causes(report, &metrics);
    let quality_signal = quality_signal(&root_causes, &config.score);
    let score = ((quality_signal as f64 / 10000.0) * 100.0).round() as u8;
    let grades = compute_grades(score, &root_causes, &config.grades);

    HealthSummary {
        score,
        quality_signal,
        coverage_score: coverage_score(report, &resolution),
        structural_score: structural_score(report, &rules),
        root_causes,
        grades,
        metrics,
        resolution,
        hotspots,
        rules,
        remediations,
    }
}

fn compute_grades(
    score: u8,
    root_causes: &RootCauseScores,
    thresholds: &GradeThresholds,
) -> GradeSummary {
    let overall = grade_for(score as f64 / 100.0, thresholds).to_string();
    GradeSummary {
        overall,
        modularity: grade_for(root_causes.modularity, thresholds).to_string(),
        acyclicity: grade_for(root_causes.acyclicity, thresholds).to_string(),
        depth: grade_for(root_causes.depth, thresholds).to_string(),
        equality: grade_for(root_causes.equality, thresholds).to_string(),
        redundancy: grade_for(root_causes.redundancy, thresholds).to_string(),
        structural_uniformity: grade_for(root_causes.structural_uniformity, thresholds).to_string(),
    }
}

fn grade_for(value: f64, thresholds: &GradeThresholds) -> &'static str {
    if value >= thresholds.a {
        "A"
    } else if value >= thresholds.b {
        "B"
    } else if value >= thresholds.c {
        "C"
    } else if value >= thresholds.d {
        "D"
    } else {
        "F"
    }
}

fn resolution_breakdown(report: &ScanReport) -> ResolutionBreakdown {
    let mut breakdown = ResolutionBreakdown::default();
    for import in &report.imports {
        match import.resolution {
            ImportResolution::External => breakdown.external += 1,
            ImportResolution::Local => breakdown.local += 1,
            ImportResolution::System => breakdown.system += 1,
            ImportResolution::Unresolved => breakdown.unresolved += 1,
        }
    }
    breakdown
}

fn coverage_score(report: &ScanReport, resolution: &ResolutionBreakdown) -> u8 {
    let mut score = 100i32;
    if report.snapshot.import_count > 0 {
        let unresolved_pct = (resolution.unresolved as f64 / report.snapshot.import_count as f64
            * 100.0)
            .round() as i32;
        score -= unresolved_pct.min(70);
    }
    score.clamp(0, 100) as u8
}

fn structural_score(report: &ScanReport, rules: &[RuleFinding]) -> u8 {
    let mut score = 100i32;
    score -= (report.graph.cycle_count as i32 * 20).min(80);
    score -= rule_penalty(rules);
    score.clamp(0, 100) as u8
}

fn rule_penalty(rules: &[RuleFinding]) -> i32 {
    rules
        .iter()
        .map(|rule| match rule.severity {
            RuleSeverity::Info => 0,
            RuleSeverity::Warning => 4,
            RuleSeverity::Error => 10,
        })
        .sum::<i32>()
        .min(40)
}

fn hotspots(report: &ScanReport) -> Vec<FileHotspot> {
    let mut fan_in: HashMap<usize, usize> = HashMap::new();
    let mut fan_out: HashMap<usize, usize> = HashMap::new();

    for import in &report.imports {
        if let Some(to_file) = import.resolved_file {
            if to_file == import.from_file {
                continue;
            }
            *fan_in.entry(to_file).or_default() += 1;
            *fan_out.entry(import.from_file).or_default() += 1;
        }
    }

    let mut hotspots: Vec<FileHotspot> = report
        .files
        .iter()
        .map(|file| FileHotspot {
            file_id: file.file_id,
            path: file.path.to_string_lossy().into_owned(),
            module: file.module.clone(),
            fan_in: fan_in.get(&file.file_id).copied().unwrap_or(0),
            fan_out: fan_out.get(&file.file_id).copied().unwrap_or(0),
        })
        .filter(|hotspot| hotspot.fan_in > 0 || hotspot.fan_out > 0)
        .collect();

    hotspots.sort_by(|a, b| {
        let a_total = a.fan_in + a.fan_out;
        let b_total = b.fan_in + b.fan_out;
        b_total
            .cmp(&a_total)
            .then_with(|| b.fan_in.cmp(&a.fan_in))
            .then_with(|| a.path.cmp(&b.path))
    });
    hotspots.truncate(10);
    hotspots
}

fn metrics(
    report: &ScanReport,
    hotspots: &[FileHotspot],
    config: &RaysenseConfig,
) -> MetricsSummary {
    let complexity = complexity_metrics(report, config);
    let evolution = evolution_metrics(report, &complexity);
    MetricsSummary {
        coupling: coupling_metrics(report, hotspots, config),
        calls: call_metrics(report),
        architecture: architecture_metrics(report, config),
        complexity,
        size: size_metrics(report),
        entry_points: entry_point_metrics(report),
        test_gap: test_gap_metrics(report, config),
        dsm: dsm_metrics(report, config),
        evolution,
        trend: trend_metrics(report),
    }
}

fn coupling_metrics(
    report: &ScanReport,
    hotspots: &[FileHotspot],
    config: &RaysenseConfig,
) -> CouplingMetrics {
    let local_edges = report
        .imports
        .iter()
        .filter(|import| import.resolution == ImportResolution::Local)
        .count();
    let cross_module_edges = report
        .imports
        .iter()
        .filter(|import| {
            let Some(to_file_id) = import.resolved_file else {
                return false;
            };
            if to_file_id == import.from_file {
                return false;
            }
            let Some(from_file) = report.files.get(import.from_file) else {
                return false;
            };
            let Some(to_file) = report.files.get(to_file_id) else {
                return false;
            };
            module_group(from_file, config) != module_group(to_file, config)
        })
        .count();
    let stable_foundations = stable_foundation_modules(report, config);
    let (entropy, entropy_bits, entropy_pairs) =
        coupling_entropy(report, config, &stable_foundations);
    let (average_module_cohesion, cohesive_module_count) = module_cohesion(report, config);
    let (god_files, unstable_hotspots, most_unstable_files) = file_coupling_metrics(report, config);
    let cross_unstable_edges = report
        .imports
        .iter()
        .filter(|import| {
            let Some(to_file_id) = import.resolved_file else {
                return false;
            };
            if to_file_id == import.from_file {
                return false;
            }
            let Some(from_file) = report.files.get(import.from_file) else {
                return false;
            };
            let Some(to_file) = report.files.get(to_file_id) else {
                return false;
            };
            let from = module_group(from_file, config);
            let to = module_group(to_file, config);
            from != to && !stable_foundations.contains(&to)
        })
        .count();

    CouplingMetrics {
        local_edges,
        cross_module_edges,
        cross_unstable_edges,
        cross_module_ratio: ratio(cross_module_edges, local_edges),
        cross_unstable_ratio: ratio(cross_unstable_edges, local_edges),
        entropy,
        entropy_bits,
        entropy_pairs,
        average_module_cohesion,
        cohesive_module_count,
        god_files,
        unstable_hotspots,
        most_unstable_files,
        max_fan_in: hotspots
            .iter()
            .map(|hotspot| hotspot.fan_in)
            .max()
            .unwrap_or(0),
        max_fan_out: hotspots
            .iter()
            .map(|hotspot| hotspot.fan_out)
            .max()
            .unwrap_or(0),
    }
}

fn coupling_entropy(
    report: &ScanReport,
    config: &RaysenseConfig,
    stable_foundations: &HashSet<String>,
) -> (f64, f64, usize) {
    let mut pair_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut cross_count = 0usize;

    for import in &report.imports {
        if import.resolution != ImportResolution::Local {
            continue;
        }
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from = module_group(from_file, config);
        let to = module_group(to_file, config);
        if from == to || stable_foundations.contains(&to) {
            continue;
        }
        *pair_counts.entry((from, to)).or_default() += 1;
        cross_count += 1;
    }

    let entropy_pairs = pair_counts.len();
    if cross_count == 0 || entropy_pairs <= 1 {
        return (0.0, 0.0, entropy_pairs);
    }

    let total = cross_count as f64;
    let entropy_bits = pair_counts
        .values()
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum::<f64>();
    let max_entropy = (entropy_pairs as f64).log2();
    let entropy = if max_entropy > 0.0 {
        entropy_bits / max_entropy
    } else {
        0.0
    };

    (round3(entropy), round3(entropy_bits), entropy_pairs)
}

fn module_cohesion(report: &ScanReport, config: &RaysenseConfig) -> (Option<f64>, usize) {
    let mut files_by_module: HashMap<String, Vec<usize>> = HashMap::new();
    for file in &report.files {
        let path = normalize_rule_path(&file.path);
        if is_test_path_configured(&path, config) {
            continue;
        }
        files_by_module
            .entry(module_group(file, config))
            .or_default()
            .push(file.file_id);
    }

    let mut module_edges: HashMap<String, HashSet<(usize, usize)>> = HashMap::new();
    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file || import.resolution != ImportResolution::Local {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let module = module_group(from_file, config);
        if module == module_group(to_file, config) {
            module_edges
                .entry(module)
                .or_default()
                .insert((import.from_file, to_file_id));
        }
    }

    for edge in &report.call_edges {
        let Some(caller) = report.functions.get(edge.caller_function) else {
            continue;
        };
        let Some(callee) = report.functions.get(edge.callee_function) else {
            continue;
        };
        if caller.file_id == callee.file_id {
            continue;
        }
        let Some(from_file) = report.files.get(caller.file_id) else {
            continue;
        };
        let Some(to_file) = report.files.get(callee.file_id) else {
            continue;
        };
        let module = module_group(from_file, config);
        if module == module_group(to_file, config) {
            module_edges
                .entry(module)
                .or_default()
                .insert((caller.file_id, callee.file_id));
        }
    }

    let mut total = 0.0;
    let mut count = 0usize;
    for (module, files) in files_by_module {
        if files.len() < 2 {
            continue;
        }
        let expected = files.len() - 1;
        let actual = module_edges.get(&module).map(HashSet::len).unwrap_or(0);
        total += (actual as f64 / expected as f64).min(1.0);
        count += 1;
    }

    if count == 0 {
        (None, 0)
    } else {
        (Some(round3(total / count as f64)), count)
    }
}

fn file_coupling_metrics(
    report: &ScanReport,
    config: &RaysenseConfig,
) -> (
    Vec<FileCouplingMetric>,
    Vec<FileCouplingMetric>,
    Vec<FileInstabilityMetric>,
) {
    let mut fan_in: HashMap<usize, usize> = HashMap::new();
    let mut fan_out: HashMap<usize, usize> = HashMap::new();
    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file || import.resolution != ImportResolution::Local {
            continue;
        }
        *fan_out.entry(import.from_file).or_default() += 1;
        *fan_in.entry(to_file_id).or_default() += 1;
    }

    let mut coupling = Vec::new();
    let mut instability = Vec::new();
    for file in &report.files {
        let path = normalize_rule_path(&file.path);
        if is_test_path_configured(&path, config) {
            continue;
        }
        let incoming = fan_in.get(&file.file_id).copied().unwrap_or(0);
        let outgoing = fan_out.get(&file.file_id).copied().unwrap_or(0);
        if incoming > 0 || outgoing > 0 {
            coupling.push(FileCouplingMetric {
                file_id: file.file_id,
                path: path.clone(),
                fan_in: incoming,
                fan_out: outgoing,
            });
            instability.push(FileInstabilityMetric {
                file_id: file.file_id,
                path,
                fan_in: incoming,
                fan_out: outgoing,
                instability: if incoming + outgoing == 0 {
                    0.5
                } else {
                    ratio(outgoing, incoming + outgoing)
                },
            });
        }
    }

    let fan_out_limit = |metric: &FileCouplingMetric| -> usize {
        report
            .files
            .get(metric.file_id)
            .map(|file| high_file_fan_out_limit(file, config))
            .unwrap_or(config.rules.high_file_fan_out)
    };
    let fan_in_limit = |metric: &FileCouplingMetric| -> usize {
        report
            .files
            .get(metric.file_id)
            .map(|file| high_file_fan_in_limit(file, config))
            .unwrap_or(config.rules.high_file_fan_in)
    };
    let mut god_files: Vec<FileCouplingMetric> = coupling
        .iter()
        .filter(|metric| {
            metric.fan_out >= fan_out_limit(metric) && !is_package_index_path(&metric.path)
        })
        .cloned()
        .collect();
    god_files.sort_by(|a, b| b.fan_out.cmp(&a.fan_out).then_with(|| a.path.cmp(&b.path)));
    god_files.truncate(10);

    let mut unstable_hotspots: Vec<FileCouplingMetric> = coupling
        .iter()
        .filter(|metric| {
            metric.fan_in >= fan_in_limit(metric)
                && !is_package_index_path(&metric.path)
                && ratio(metric.fan_out, metric.fan_in + metric.fan_out) >= 0.15
        })
        .cloned()
        .collect();
    unstable_hotspots.sort_by(|a, b| {
        b.fan_in
            .cmp(&a.fan_in)
            .then_with(|| b.fan_out.cmp(&a.fan_out))
            .then_with(|| a.path.cmp(&b.path))
    });
    unstable_hotspots.truncate(10);

    instability.sort_by(|a, b| {
        b.instability
            .partial_cmp(&a.instability)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.fan_out.cmp(&a.fan_out))
            .then_with(|| a.path.cmp(&b.path))
    });
    instability.truncate(10);

    (god_files, unstable_hotspots, instability)
}

fn call_metrics(report: &ScanReport) -> CallMetrics {
    let mut fan_in: HashMap<usize, usize> = HashMap::new();
    let mut fan_out: HashMap<usize, usize> = HashMap::new();

    for edge in &report.call_edges {
        *fan_in.entry(edge.callee_function).or_default() += 1;
        *fan_out.entry(edge.caller_function).or_default() += 1;
    }

    CallMetrics {
        total_calls: report.calls.len(),
        resolved_edges: report.call_edges.len(),
        resolution_ratio: ratio(report.call_edges.len(), report.calls.len()),
        max_function_fan_in: fan_in.values().copied().max().unwrap_or(0),
        max_function_fan_out: fan_out.values().copied().max().unwrap_or(0),
        top_called_functions: function_call_metrics(report, &fan_in),
        top_calling_functions: function_call_metrics(report, &fan_out),
    }
}

fn function_call_metrics(
    report: &ScanReport,
    counts: &HashMap<usize, usize>,
) -> Vec<FunctionCallMetric> {
    let mut metrics: Vec<FunctionCallMetric> = counts
        .iter()
        .filter_map(|(function_id, calls)| {
            let function = report.functions.get(*function_id)?;
            let file = report.files.get(function.file_id)?;
            Some(FunctionCallMetric {
                function_id: *function_id,
                file_id: function.file_id,
                path: file.path.to_string_lossy().into_owned(),
                name: function.name.clone(),
                calls: *calls,
            })
        })
        .collect();

    metrics.sort_by(|a, b| {
        b.calls
            .cmp(&a.calls)
            .then_with(|| a.path.cmp(&b.path))
            .then_with(|| a.name.cmp(&b.name))
    });
    metrics.truncate(10);
    metrics
}

fn architecture_metrics(report: &ScanReport, config: &RaysenseConfig) -> ArchitectureMetrics {
    let adjacency = file_adjacency(report);
    let reverse = reverse_adjacency(&adjacency);
    let foundation_files = foundation_file_ids(report, config);
    let distance_metrics = module_distance_metrics(report, config);
    let (attack_surface_files, total_graph_files) = attack_surface_metrics(report, &adjacency);
    let levels = dependency_levels(report, &adjacency, &reverse);
    let upward_violations = upward_violations(report, &adjacency, &levels);
    let non_foundation_distance: Vec<f64> = distance_metrics
        .iter()
        .filter(|metric| !metric.is_foundation)
        .map(|metric| metric.distance)
        .collect();
    let mut max_blast_radius = 0usize;
    let mut max_blast_radius_file = String::new();
    let mut max_non_foundation_blast_radius = 0usize;
    let mut max_non_foundation_blast_radius_file = String::new();
    for file in &report.files {
        let radius = reachable_count(file.file_id, &reverse);
        if radius > max_blast_radius {
            max_blast_radius = radius;
            max_blast_radius_file = file.path.to_string_lossy().into_owned();
        }
        if !foundation_files.contains(&file.file_id) && radius > max_non_foundation_blast_radius {
            max_non_foundation_blast_radius = radius;
            max_non_foundation_blast_radius_file = file.path.to_string_lossy().into_owned();
        }
    }

    ArchitectureMetrics {
        module_depth: report
            .files
            .iter()
            .map(|file| file.module.split('.').count())
            .max()
            .unwrap_or(0),
        max_blast_radius,
        max_blast_radius_file,
        max_non_foundation_blast_radius,
        max_non_foundation_blast_radius_file,
        attack_surface_files,
        attack_surface_ratio: ratio(attack_surface_files, total_graph_files),
        total_graph_files,
        average_distance_from_main_sequence: if non_foundation_distance.is_empty() {
            0.0
        } else {
            round3(
                non_foundation_distance.iter().sum::<f64>() / non_foundation_distance.len() as f64,
            )
        },
        levels,
        upward_violation_ratio: ratio(upward_violations.len(), report.imports.len()),
        upward_violations,
        unstable_modules: module_stability(report, config),
        stable_foundations: stable_foundation_metrics(report, config),
        distance_metrics,
        cycles: cycle_components(report, &adjacency),
    }
}

fn complexity_metrics(report: &ScanReport, config: &RaysenseConfig) -> ComplexityMetrics {
    let mut incoming_by_function: HashMap<usize, usize> = HashMap::new();
    let sources = source_cache(report);
    for edge in &report.call_edges {
        *incoming_by_function
            .entry(edge.callee_function)
            .or_default() += 1;
    }

    let mut values = Vec::new();
    let mut cognitive_values = Vec::new();
    let mut all_functions = Vec::new();
    let mut complex_functions = Vec::new();
    let mut dead_functions = Vec::new();
    let mut by_name: BTreeMap<String, Vec<FunctionComplexityMetric>> = BTreeMap::new();
    let mut by_fingerprint: BTreeMap<String, Vec<FunctionComplexityMetric>> = BTreeMap::new();
    let mut by_semantic_shape: BTreeMap<String, Vec<FunctionComplexityMetric>> = BTreeMap::new();
    let mut public_api_functions = 0usize;

    for function in &report.functions {
        let Some(file) = report.files.get(function.file_id) else {
            continue;
        };
        let path = file.path.to_string_lossy().into_owned();
        let source = sources
            .get(&function.file_id)
            .map(String::as_str)
            .unwrap_or("");
        let body = function_body(source, function);
        let value = lexical_complexity(&body, &file.language_name);
        let cognitive_value = cognitive_complexity(&body, &file.language_name);
        values.push(value as f64);
        cognitive_values.push(cognitive_value as f64);
        let metric = FunctionComplexityMetric {
            function_id: function.function_id,
            file_id: function.file_id,
            path,
            name: function.name.clone(),
            value,
            cognitive_value,
        };
        all_functions.push(metric.clone());
        by_name
            .entry(function.name.clone())
            .or_default()
            .push(metric.clone());
        let public_api_like = is_public_api_like(file, function, &body, config);
        if public_api_like {
            public_api_functions += 1;
        }
        if let Some(fingerprint) = normalized_body_fingerprint(&body) {
            by_fingerprint
                .entry(fingerprint)
                .or_default()
                .push(metric.clone());
        }
        if let Some(shape) = semantic_shape_fingerprint(&body) {
            by_semantic_shape
                .entry(shape)
                .or_default()
                .push(metric.clone());
        }
        if value >= 10 {
            complex_functions.push(metric.clone());
        }
        if incoming_by_function
            .get(&function.function_id)
            .copied()
            .unwrap_or(0)
            == 0
            && !is_entry_like_function(&function.name)
            && !public_api_like
        {
            dead_functions.push(metric);
        }
    }

    complex_functions.sort_by(|a, b| b.value.cmp(&a.value).then_with(|| a.path.cmp(&b.path)));
    complex_functions.truncate(20);
    dead_functions.sort_by(|a, b| b.value.cmp(&a.value).then_with(|| a.path.cmp(&b.path)));
    dead_functions.truncate(50);

    let mut duplicate_groups: Vec<DuplicateFunctionGroup> = by_fingerprint
        .into_iter()
        .filter(|(_, functions)| functions.len() > 1)
        .map(|(fingerprint, functions)| DuplicateFunctionGroup {
            fingerprint,
            name: shared_duplicate_name(&functions),
            functions,
        })
        .collect();
    duplicate_groups.extend(
        by_name
            .into_iter()
            .filter(|(_, functions)| functions.len() > 1)
            .map(|(name, functions)| DuplicateFunctionGroup {
                fingerprint: format!("name:{name}"),
                name,
                functions,
            }),
    );
    duplicate_groups.sort_by(|a, b| {
        b.functions
            .len()
            .cmp(&a.functions.len())
            .then_with(|| a.name.cmp(&b.name))
    });
    duplicate_groups.truncate(20);
    let mut semantic_duplicate_groups: Vec<DuplicateFunctionGroup> = by_semantic_shape
        .into_iter()
        .filter(|(_, functions)| functions.len() > 1)
        .map(|(fingerprint, functions)| DuplicateFunctionGroup {
            fingerprint,
            name: shared_duplicate_name(&functions),
            functions,
        })
        .collect();
    semantic_duplicate_groups.sort_by(|a, b| {
        b.functions
            .len()
            .cmp(&a.functions.len())
            .then_with(|| a.name.cmp(&b.name))
    });
    semantic_duplicate_groups.truncate(20);

    let max_function_complexity = values.iter().copied().fold(0.0, f64::max) as usize;
    let max_cognitive_complexity = cognitive_values.iter().copied().fold(0.0, f64::max) as usize;
    let average_function_complexity = if values.is_empty() {
        0.0
    } else {
        round3(values.iter().sum::<f64>() / values.len() as f64)
    };
    let average_cognitive_complexity = if cognitive_values.is_empty() {
        0.0
    } else {
        round3(cognitive_values.iter().sum::<f64>() / cognitive_values.len() as f64)
    };
    let duplicate_count = duplicate_groups
        .iter()
        .map(|group| group.functions.len().saturating_sub(1))
        .sum::<usize>();
    let redundancy_ratio = ratio(
        dead_functions.len() + duplicate_count,
        report.functions.len(),
    );

    let (complexity_entropy, complexity_entropy_bits) =
        complexity_distribution_entropy(&all_functions);

    ComplexityMetrics {
        max_function_complexity,
        max_cognitive_complexity,
        average_function_complexity,
        average_cognitive_complexity,
        complexity_gini: gini(&values),
        complexity_entropy,
        complexity_entropy_bits,
        all_functions,
        complex_functions,
        dead_functions,
        duplicate_groups,
        semantic_duplicate_groups,
        redundancy_ratio,
        public_api_functions,
    }
}

fn root_causes(report: &ScanReport, metrics: &MetricsSummary) -> RootCauseScores {
    // Combined structural-distribution health: average of file-size and
    // function-complexity normalized entropy. Higher = more variety across
    // log-buckets / complexity values, lower = monoculture or pathological
    // concentration. Treated as 0..1 so it composes with the other dimensions
    // when its weight is set.
    let structural_uniformity = round3(
        ((metrics.size.file_size_entropy + metrics.complexity.complexity_entropy) / 2.0)
            .clamp(0.0, 1.0),
    );
    RootCauseScores {
        modularity: (1.0 - metrics.coupling.cross_unstable_ratio).clamp(0.0, 1.0),
        acyclicity: 1.0 / (1.0 + report.graph.cycle_count as f64),
        depth: 1.0 / (1.0 + metrics.architecture.module_depth.saturating_sub(4) as f64),
        equality: (1.0 - metrics.complexity.complexity_gini).clamp(0.0, 1.0),
        redundancy: (1.0 - metrics.complexity.redundancy_ratio).clamp(0.0, 1.0),
        structural_uniformity,
    }
}

fn quality_signal(scores: &RootCauseScores, weights: &ScoreConfig) -> u32 {
    let values = [
        (scores.modularity, weights.modularity_weight),
        (scores.acyclicity, weights.acyclicity_weight),
        (scores.depth, weights.depth_weight),
        (scores.equality, weights.equality_weight),
        (scores.redundancy, weights.redundancy_weight),
        (
            scores.structural_uniformity,
            weights.structural_uniformity_weight,
        ),
    ];
    let weight_sum = values
        .iter()
        .map(|(_, weight)| weight.max(0.0))
        .sum::<f64>()
        .max(0.0001);
    let weighted_log = values
        .iter()
        .map(|(value, weight)| value.max(0.0001).ln() * weight.max(0.0))
        .sum::<f64>();
    ((weighted_log / weight_sum).exp() * 10000.0).round() as u32
}

fn file_adjacency(report: &ScanReport) -> HashMap<usize, Vec<usize>> {
    let mut adjacency: HashMap<usize, Vec<usize>> = HashMap::new();
    for import in &report.imports {
        if let Some(to_file) = import.resolved_file {
            if to_file == import.from_file {
                continue;
            }
            adjacency.entry(import.from_file).or_default().push(to_file);
        }
    }
    adjacency
}

fn reverse_adjacency(adjacency: &HashMap<usize, Vec<usize>>) -> HashMap<usize, Vec<usize>> {
    let mut reverse: HashMap<usize, Vec<usize>> = HashMap::new();
    for (from, targets) in adjacency {
        for to in targets {
            reverse.entry(*to).or_default().push(*from);
        }
    }
    reverse
}

fn reachable_count(start: usize, adjacency: &HashMap<usize, Vec<usize>>) -> usize {
    let mut seen = HashSet::new();
    let mut queue: VecDeque<usize> = adjacency.get(&start).cloned().unwrap_or_default().into();
    while let Some(next) = queue.pop_front() {
        if seen.insert(next) {
            if let Some(children) = adjacency.get(&next) {
                queue.extend(children);
            }
        }
    }
    seen.remove(&start);
    seen.len()
}

fn attack_surface_metrics(
    report: &ScanReport,
    adjacency: &HashMap<usize, Vec<usize>>,
) -> (usize, usize) {
    let graph_files: HashSet<usize> = adjacency
        .iter()
        .flat_map(|(from, targets)| std::iter::once(*from).chain(targets.iter().copied()))
        .collect();
    if graph_files.is_empty() || report.entry_points.is_empty() {
        return (0, graph_files.len());
    }

    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    for entry in &report.entry_points {
        if graph_files.contains(&entry.file_id) && seen.insert(entry.file_id) {
            queue.push_back(entry.file_id);
        }
    }
    while let Some(file_id) = queue.pop_front() {
        let Some(targets) = adjacency.get(&file_id) else {
            continue;
        };
        for target in targets {
            if seen.insert(*target) {
                queue.push_back(*target);
            }
        }
    }

    (seen.len(), graph_files.len())
}

fn dependency_levels(
    report: &ScanReport,
    adjacency: &HashMap<usize, Vec<usize>>,
    reverse: &HashMap<usize, Vec<usize>>,
) -> BTreeMap<String, usize> {
    let mut indegree: HashMap<usize, usize> =
        report.files.iter().map(|file| (file.file_id, 0)).collect();
    for targets in adjacency.values() {
        for target in targets {
            *indegree.entry(*target).or_default() += 1;
        }
    }
    let mut queue: VecDeque<usize> = indegree
        .iter()
        .filter_map(|(file_id, degree)| (*degree == 0).then_some(*file_id))
        .collect();
    let mut levels: HashMap<usize, usize> = HashMap::new();
    while let Some(file_id) = queue.pop_front() {
        let parent_level = reverse
            .get(&file_id)
            .into_iter()
            .flatten()
            .filter_map(|parent| levels.get(parent).copied())
            .max()
            .unwrap_or(0);
        levels.entry(file_id).or_insert(parent_level);
        if let Some(children) = adjacency.get(&file_id) {
            for child in children {
                let next_level = levels.get(&file_id).copied().unwrap_or(0) + 1;
                levels
                    .entry(*child)
                    .and_modify(|level| *level = (*level).max(next_level))
                    .or_insert(next_level);
                if let Some(degree) = indegree.get_mut(child) {
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        queue.push_back(*child);
                    }
                }
            }
        }
    }
    report
        .files
        .iter()
        .map(|file| {
            (
                file.path.to_string_lossy().into_owned(),
                levels.get(&file.file_id).copied().unwrap_or(0),
            )
        })
        .collect()
}

fn upward_violations(
    report: &ScanReport,
    adjacency: &HashMap<usize, Vec<usize>>,
    levels: &BTreeMap<String, usize>,
) -> Vec<DependencyViolationMetric> {
    let mut violations = Vec::new();
    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file || import.resolution != ImportResolution::Local {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from_path = from_file.path.to_string_lossy().into_owned();
        let to_path = to_file.path.to_string_lossy().into_owned();
        let from_level = levels.get(&from_path).copied().unwrap_or(0);
        let to_level = levels.get(&to_path).copied().unwrap_or(0);
        let reason = if from_level < to_level {
            Some("upward_level".to_string())
        } else if reachable_from(to_file_id, import.from_file, adjacency) {
            Some("cycle_edge".to_string())
        } else {
            None
        };
        let Some(reason) = reason else {
            continue;
        };
        violations.push(DependencyViolationMetric {
            from_file_id: import.from_file,
            from_path,
            from_level,
            to_file_id,
            to_path,
            to_level,
            reason,
        });
    }

    violations.sort_by(|a, b| {
        let a_diff = a.to_level.abs_diff(a.from_level);
        let b_diff = b.to_level.abs_diff(b.from_level);
        b_diff
            .cmp(&a_diff)
            .then_with(|| a.from_path.cmp(&b.from_path))
            .then_with(|| a.to_path.cmp(&b.to_path))
    });
    violations.truncate(20);
    violations
}

fn reachable_from(start: usize, target: usize, adjacency: &HashMap<usize, Vec<usize>>) -> bool {
    let mut seen = HashSet::new();
    let mut queue: VecDeque<usize> = adjacency.get(&start).cloned().unwrap_or_default().into();
    while let Some(next) = queue.pop_front() {
        if next == target {
            return true;
        }
        if seen.insert(next) {
            if let Some(children) = adjacency.get(&next) {
                queue.extend(children);
            }
        }
    }
    false
}

fn module_stability(report: &ScanReport, config: &RaysenseConfig) -> Vec<ModuleStabilityMetric> {
    let stable = stable_foundation_modules(report, config);
    let mut metrics = module_stability_all(report, config);
    metrics.retain(|metric| !stable.contains(&metric.module));
    metrics.truncate(20);
    metrics
}

fn stable_foundation_metrics(
    report: &ScanReport,
    config: &RaysenseConfig,
) -> Vec<ModuleStabilityMetric> {
    let stable = stable_foundation_modules(report, config);
    let mut metrics: Vec<ModuleStabilityMetric> = module_stability_all(report, config)
        .into_iter()
        .filter(|metric| stable.contains(&metric.module))
        .collect();
    metrics.sort_by(|a, b| {
        b.fan_in
            .cmp(&a.fan_in)
            .then_with(|| a.module.cmp(&b.module))
    });
    metrics.truncate(20);
    metrics
}

fn stable_foundation_modules(report: &ScanReport, config: &RaysenseConfig) -> HashSet<String> {
    module_stability_all(report, config)
        .into_iter()
        .filter(|metric| metric.fan_in >= 2 && (metric.fan_out == 0 || metric.instability <= 0.15))
        .map(|metric| metric.module)
        .collect()
}

pub fn is_foundation_file(report: &ScanReport, config: &RaysenseConfig, file_id: usize) -> bool {
    foundation_file_ids(report, config).contains(&file_id)
}

fn foundation_file_ids(report: &ScanReport, config: &RaysenseConfig) -> HashSet<usize> {
    let stable_modules = stable_foundation_modules(report, config);
    let file_fan_in = file_fan_in(report);

    report
        .files
        .iter()
        .filter(|file| {
            stable_modules.contains(&module_group(file, config))
                || file_fan_in.get(&file.file_id).copied().unwrap_or(0) >= 5
                || is_package_index_path(&normalize_rule_path(&file.path))
        })
        .map(|file| file.file_id)
        .collect()
}

fn file_fan_in(report: &ScanReport) -> HashMap<usize, usize> {
    let mut fan_in: HashMap<usize, usize> = HashMap::new();
    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id != import.from_file && import.resolution == ImportResolution::Local {
            *fan_in.entry(to_file_id).or_default() += 1;
        }
    }
    fan_in
}

fn module_stability_all(
    report: &ScanReport,
    config: &RaysenseConfig,
) -> Vec<ModuleStabilityMetric> {
    let mut fan_in: HashMap<String, usize> = HashMap::new();
    let mut fan_out: HashMap<String, usize> = HashMap::new();
    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from = module_group(from_file, config);
        let to = module_group(to_file, config);
        if from != to {
            *fan_out.entry(from).or_default() += 1;
            *fan_in.entry(to).or_default() += 1;
        }
    }
    let mut modules: HashSet<String> = fan_in
        .keys()
        .cloned()
        .chain(fan_out.keys().cloned())
        .collect();
    modules.extend(report.files.iter().map(|file| module_group(file, config)));
    let mut metrics: Vec<ModuleStabilityMetric> = modules
        .into_iter()
        .map(|module| {
            let incoming = fan_in.get(&module).copied().unwrap_or(0);
            let outgoing = fan_out.get(&module).copied().unwrap_or(0);
            ModuleStabilityMetric {
                module,
                fan_in: incoming,
                fan_out: outgoing,
                instability: round3(ratio(outgoing, incoming + outgoing)),
            }
        })
        .collect();
    metrics.sort_by(|a, b| {
        b.fan_out
            .cmp(&a.fan_out)
            .then_with(|| a.module.cmp(&b.module))
    });
    metrics
}

fn module_distance_metrics(
    report: &ScanReport,
    config: &RaysenseConfig,
) -> Vec<ModuleDistanceMetric> {
    let mut abstract_by_module: HashMap<String, usize> = HashMap::new();
    let mut total_by_module: HashMap<String, usize> = HashMap::new();
    let sources = source_cache(report);

    for file in &report.files {
        let Some(source) = sources.get(&file.file_id) else {
            continue;
        };
        let (abstract_count, total_count) = type_counts(source, file, config);
        if total_count == 0 {
            continue;
        }
        let module = module_group(file, config);
        *abstract_by_module.entry(module.clone()).or_default() += abstract_count;
        *total_by_module.entry(module).or_default() += total_count;
    }

    let stability_by_module: HashMap<String, ModuleStabilityMetric> =
        module_stability_all(report, config)
            .into_iter()
            .map(|metric| (metric.module.clone(), metric))
            .collect();
    let stable_modules = stable_foundation_modules(report, config);

    let mut metrics: Vec<ModuleDistanceMetric> = total_by_module
        .into_iter()
        .map(|(module, total_types)| {
            let abstract_count = abstract_by_module.get(&module).copied().unwrap_or(0);
            let stability = stability_by_module.get(&module);
            let fan_in = stability.map(|metric| metric.fan_in).unwrap_or(0);
            let fan_out = stability.map(|metric| metric.fan_out).unwrap_or(0);
            let instability = if fan_in + fan_out == 0 {
                0.5
            } else {
                ratio(fan_out, fan_in + fan_out)
            };
            let abstractness = ratio(abstract_count, total_types);
            let distance = (abstractness + instability - 1.0).abs();
            ModuleDistanceMetric {
                module: module.clone(),
                abstractness: round3(abstractness),
                instability: round3(instability),
                distance: round3(distance),
                abstract_count,
                total_types,
                fan_in,
                fan_out,
                is_foundation: instability <= 0.30 || stable_modules.contains(&module),
            }
        })
        .collect();

    metrics.sort_by(|a, b| {
        b.distance
            .partial_cmp(&a.distance)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.module.cmp(&b.module))
    });
    metrics.truncate(20);
    metrics
}

fn type_counts(source: &str, file: &FileFact, config: &RaysenseConfig) -> (usize, usize) {
    let mut abstract_count = 0usize;
    let mut total_count = 0usize;
    let plugin = plugin_for_file(file, config);
    for line in source.lines() {
        let clean = line.split("//").next().unwrap_or(line).trim();
        if clean.is_empty()
            || clean.starts_with('#')
            || clean.starts_with('*')
            || clean.starts_with("/*")
        {
            continue;
        }
        let is_configured_abstract = plugin.is_some_and(|plugin| {
            plugin
                .abstract_type_prefixes
                .iter()
                .any(|prefix| clean.starts_with(prefix))
        });
        let is_configured_concrete = plugin.is_some_and(|plugin| {
            plugin
                .concrete_type_prefixes
                .iter()
                .any(|prefix| clean.starts_with(prefix))
        });
        let is_abstract =
            is_configured_abstract || is_abstract_type_line(clean, &file.language_name);
        let is_type = is_abstract
            || is_configured_concrete
            || is_concrete_type_line(clean, &file.language_name);
        if is_type {
            total_count += 1;
            if is_abstract {
                abstract_count += 1;
            }
        }
    }
    (abstract_count, total_count)
}

pub(crate) fn is_abstract_type_line(line: &str, language: &str) -> bool {
    match language {
        "rust" => line.starts_with("trait ") || line.starts_with("pub trait "),
        "typescript" | "tsx" | "javascript" => {
            line.starts_with("interface ")
                || line.starts_with("export interface ")
                || line.starts_with("abstract class ")
                || line.starts_with("export abstract class ")
        }
        "python" => {
            line.starts_with("class ") && (line.contains("Protocol") || line.contains("ABC"))
        }
        "c++" | "cpp" => line.starts_with("class ") && line.contains("= 0"),
        _ => false,
    }
}

pub(crate) fn is_concrete_type_line(line: &str, language: &str) -> bool {
    match language {
        "rust" => {
            line.starts_with("struct ")
                || line.starts_with("pub struct ")
                || line.starts_with("enum ")
                || line.starts_with("pub enum ")
                || line.starts_with("type ")
                || line.starts_with("pub type ")
        }
        "typescript" | "tsx" | "javascript" => {
            line.starts_with("class ")
                || line.starts_with("export class ")
                || line.starts_with("type ")
                || line.starts_with("export type ")
        }
        "python" => line.starts_with("class "),
        "c" | "c++" | "cpp" => {
            line.starts_with("struct ")
                || line.starts_with("typedef struct")
                || line.starts_with("enum ")
                || line.starts_with("typedef enum")
                || line.starts_with("class ")
        }
        _ => false,
    }
}

fn cycle_components(
    report: &ScanReport,
    adjacency: &HashMap<usize, Vec<usize>>,
) -> Vec<Vec<String>> {
    let mut cycles = Vec::new();
    for file in &report.files {
        let mut stack = adjacency.get(&file.file_id).cloned().unwrap_or_default();
        let mut seen = HashSet::new();
        while let Some(next) = stack.pop() {
            if next == file.file_id {
                cycles.push(vec![file.path.to_string_lossy().into_owned()]);
                break;
            }
            if seen.insert(next) {
                if let Some(children) = adjacency.get(&next) {
                    stack.extend(children);
                }
            }
        }
    }
    cycles.truncate(20);
    cycles
}

fn distribution_entropy(counts: &[usize]) -> (f64, f64) {
    let total: usize = counts.iter().sum();
    if total == 0 {
        return (0.0, 0.0);
    }
    let distinct = counts.iter().filter(|count| **count > 0).count();
    if distinct <= 1 {
        return (0.0, 0.0);
    }
    let total = total as f64;
    let entropy_bits: f64 = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum();
    let max_entropy = (distinct as f64).log2();
    let entropy = if max_entropy > 0.0 {
        entropy_bits / max_entropy
    } else {
        0.0
    };
    (round3(entropy), round3(entropy_bits))
}

// Log-scale buckets so wildly different file sizes spread across distinct bins
// (e.g. 1000-line and 1100-line files share a bucket; 100 and 1000 do not).
fn file_lines_bucket(lines: usize) -> usize {
    if lines == 0 {
        0
    } else {
        (usize::BITS - lines.leading_zeros()) as usize
    }
}

fn file_size_distribution_entropy(report: &ScanReport) -> (f64, f64) {
    let mut buckets: BTreeMap<usize, usize> = BTreeMap::new();
    for file in &report.files {
        *buckets.entry(file_lines_bucket(file.lines)).or_default() += 1;
    }
    let counts: Vec<usize> = buckets.into_values().collect();
    distribution_entropy(&counts)
}

fn complexity_distribution_entropy(functions: &[FunctionComplexityMetric]) -> (f64, f64) {
    let mut buckets: BTreeMap<usize, usize> = BTreeMap::new();
    for function in functions {
        *buckets.entry(function.value).or_default() += 1;
    }
    let counts: Vec<usize> = buckets.into_values().collect();
    distribution_entropy(&counts)
}

fn gini(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let sum = sorted.iter().sum::<f64>();
    if sum == 0.0 {
        return 0.0;
    }
    let n = sorted.len() as f64;
    let weighted = sorted
        .iter()
        .enumerate()
        .map(|(idx, value)| (idx as f64 + 1.0) * value)
        .sum::<f64>();
    round3((2.0 * weighted) / (n * sum) - (n + 1.0) / n)
}

fn is_entry_like_function(name: &str) -> bool {
    matches!(name, "main" | "init" | "start" | "run" | "new")
        || name.starts_with("test_")
        || name.ends_with("_test")
}

fn source_cache(report: &ScanReport) -> HashMap<usize, String> {
    report
        .files
        .iter()
        .filter_map(|file| {
            fs::read_to_string(report.snapshot.root.join(&file.path))
                .ok()
                .map(|source| (file.file_id, source))
        })
        .collect()
}

fn function_body(source: &str, function: &crate::facts::FunctionFact) -> String {
    source
        .lines()
        .skip(function.start_line.saturating_sub(1))
        .take(function.end_line.saturating_sub(function.start_line) + 1)
        .collect::<Vec<_>>()
        .join("\n")
}

fn lexical_complexity(body: &str, language: &str) -> usize {
    let mut value = 1usize;
    for token in normalized_tokens(body) {
        if matches!(
            token.as_str(),
            "if" | "else"
                | "elif"
                | "for"
                | "while"
                | "loop"
                | "match"
                | "case"
                | "catch"
                | "except"
                | "switch"
                | "guard"
                | "when"
        ) {
            value += 1;
        }
    }
    value += body.matches("&&").count();
    value += body.matches("||").count();
    value += body.matches('?').count();
    if matches!(language, "python" | "ruby" | "swift") {
        value += body.matches(" and ").count();
        value += body.matches(" or ").count();
    }
    value
}

fn cognitive_complexity(body: &str, language: &str) -> usize {
    let mut score = 0usize;
    let mut nesting = 0usize;
    for line in strip_strings_and_comments(body).lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('}') {
            nesting = nesting.saturating_sub(1);
        }
        let tokens = normalized_tokens(trimmed);
        if tokens.iter().any(|token| is_branch_token(token)) {
            score += 1 + nesting;
        }
        score += trimmed.matches("&&").count();
        score += trimmed.matches("||").count();
        if matches!(language, "python" | "ruby" | "swift") {
            score += trimmed.matches(" and ").count();
            score += trimmed.matches(" or ").count();
        }
        if trimmed.ends_with('{') || trimmed.ends_with(':') {
            nesting += 1;
        }
        nesting = nesting.saturating_sub(trimmed.matches('}').count());
    }
    score
}

fn is_branch_token(token: &str) -> bool {
    matches!(
        token,
        "if" | "elif"
            | "else"
            | "for"
            | "while"
            | "loop"
            | "match"
            | "case"
            | "catch"
            | "except"
            | "switch"
            | "guard"
            | "when"
    )
}

fn normalized_body_fingerprint(body: &str) -> Option<String> {
    let tokens = normalized_tokens(body);
    if tokens.len() < 12 {
        return None;
    }
    let normalized = tokens
        .iter()
        .map(|token| {
            if token.chars().all(|ch| ch.is_ascii_digit()) {
                "0"
            } else if is_keyword_token(token) {
                token.as_str()
            } else {
                "id"
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(short_hash(&normalized))
}

fn semantic_shape_fingerprint(body: &str) -> Option<String> {
    let tokens = normalized_tokens(body);
    if tokens.len() < 20 {
        return None;
    }
    let shape = tokens
        .iter()
        .filter(|token| {
            is_keyword_token(token) || matches!(token.as_str(), "{" | "}" | "(" | ")" | "?" | ":")
        })
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    if shape.split_whitespace().count() < 4 {
        return None;
    }
    Some(format!("shape:{}", short_hash(&shape)))
}

fn normalized_tokens(body: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in strip_strings_and_comments(body).chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch.to_ascii_lowercase());
        } else {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            if matches!(ch, '{' | '}' | '(' | ')' | '[' | ']' | '?' | ':') {
                tokens.push(ch.to_string());
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn strip_strings_and_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    let mut in_string = None;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                out.push('\n');
            } else {
                out.push(' ');
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
                out.push(' ');
            } else {
                out.push(if ch == '\n' { '\n' } else { ' ' });
            }
            continue;
        }
        if let Some(quote) = in_string {
            if ch == '\\' {
                chars.next();
                out.push(' ');
            } else if ch == quote {
                in_string = None;
                out.push(' ');
            } else {
                out.push(if ch == '\n' { '\n' } else { ' ' });
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line_comment = true;
            out.push(' ');
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block_comment = true;
            out.push(' ');
        } else if ch == '"' || ch == '\'' || ch == '`' {
            in_string = Some(ch);
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn is_keyword_token(token: &str) -> bool {
    matches!(
        token,
        "if" | "else"
            | "elif"
            | "for"
            | "while"
            | "loop"
            | "match"
            | "case"
            | "catch"
            | "except"
            | "switch"
            | "return"
            | "break"
            | "continue"
            | "async"
            | "await"
            | "yield"
            | "try"
            | "throw"
    )
}

fn is_public_api_like(
    file: &crate::facts::FileFact,
    function: &crate::facts::FunctionFact,
    body: &str,
    config: &RaysenseConfig,
) -> bool {
    let name = function.name.as_str();
    let path = normalize_rule_path(&file.path);
    is_test_path_configured(&path, config)
        || matches_configured_path(&path, &config.scan.public_api_paths)
        || matches!(name, "main" | "init" | "start" | "run" | "new")
        || name.starts_with("test_")
        || name.ends_with("_test")
        || body.lines().next().is_some_and(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("pub ")
                || trimmed.starts_with("pub(")
                || trimmed.starts_with("export ")
                || trimmed.starts_with("public ")
                || trimmed.starts_with("def __")
        })
        || path.ends_with("lib.rs")
        || is_package_index_path(&path)
}

fn is_package_index_path(path: &str) -> bool {
    path.ends_with("mod.rs")
        || path.ends_with("__init__.py")
        || path.ends_with("index.ts")
        || path.ends_with("index.tsx")
        || path.ends_with("index.js")
}

fn shared_duplicate_name(functions: &[FunctionComplexityMetric]) -> String {
    let Some(first) = functions.first() else {
        return String::new();
    };
    if functions.iter().all(|function| function.name == first.name) {
        first.name.clone()
    } else {
        "similar_body".to_string()
    }
}

fn short_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let hash = format!("{:x}", hasher.finalize());
    hash[..16].to_string()
}

fn size_metrics(report: &ScanReport) -> SizeMetrics {
    let max_file_lines = report
        .files
        .iter()
        .map(|file| file.lines)
        .max()
        .unwrap_or(0);
    let max_function_lines = report
        .functions
        .iter()
        .map(|function| function.end_line.saturating_sub(function.start_line) + 1)
        .max()
        .unwrap_or(0);

    let (file_size_entropy, file_size_entropy_bits) = file_size_distribution_entropy(report);

    let total_lines: usize = report.files.iter().map(|file| file.lines).sum();
    let total_comment_lines: usize = report.files.iter().map(|file| file.comment_lines).sum();
    let comment_ratio = if total_lines == 0 {
        0.0
    } else {
        round3(total_comment_lines as f64 / total_lines as f64)
    };

    SizeMetrics {
        max_file_lines,
        max_function_lines,
        large_files: report.files.iter().filter(|file| file.lines >= 500).count(),
        long_functions: report
            .functions
            .iter()
            .filter(|function| function.end_line.saturating_sub(function.start_line) + 1 >= 80)
            .count(),
        file_size_entropy,
        file_size_entropy_bits,
        total_lines,
        total_comment_lines,
        comment_ratio,
    }
}

fn entry_point_metrics(report: &ScanReport) -> EntryPointMetrics {
    let mut metrics = EntryPointMetrics::default();
    for entry in &report.entry_points {
        match entry.kind {
            EntryPointKind::Binary => metrics.binaries += 1,
            EntryPointKind::Example => metrics.examples += 1,
            EntryPointKind::Test => metrics.tests += 1,
        }
    }
    metrics
}

fn test_gap_metrics(report: &ScanReport, config: &RaysenseConfig) -> TestGapMetrics {
    let test_paths: HashSet<String> = report
        .files
        .iter()
        .filter(|file| is_test_path_configured(&normalize_rule_path(&file.path), config))
        .map(|file| file.path.to_string_lossy().replace('\\', "/"))
        .collect();

    let mut production_files = 0;
    let mut files_without_nearby_tests = 0;
    let mut candidates = Vec::new();

    for file in &report.files {
        let path = normalize_rule_path(&file.path);
        if is_test_path_configured(&path, config) {
            continue;
        }
        if !report
            .functions
            .iter()
            .any(|function| function.file_id == file.file_id)
        {
            continue;
        }
        production_files += 1;
        let framework = test_framework(file);
        let expected_tests = expected_test_paths(&path, &framework, config);
        let matched_tests = expected_tests
            .iter()
            .filter(|path| test_paths.contains(*path))
            .cloned()
            .collect::<Vec<_>>();
        if matched_tests.is_empty() {
            files_without_nearby_tests += 1;
            candidates.push(TestGapCandidate {
                file_id: file.file_id,
                path,
                framework,
                expected_tests,
                matched_tests,
            });
        }
    }
    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    candidates.truncate(100);

    TestGapMetrics {
        production_files,
        test_files: report
            .files
            .iter()
            .filter(|file| is_test_path_configured(&normalize_rule_path(&file.path), config))
            .count(),
        files_without_nearby_tests,
        candidates,
    }
}

fn expected_test_paths(path: &str, framework: &str, config: &RaysenseConfig) -> Vec<String> {
    let normalized = path.replace('\\', "/");
    let path = Path::new(&normalized);
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let parent = parent.to_string_lossy().replace('\\', "/");
    let mut out = Vec::new();
    if !stem.is_empty() && !ext.is_empty() {
        out.push(format!("tests/{stem}_test.{ext}"));
        out.push(format!("tests/test_{stem}.{ext}"));
        for root in configured_test_roots(config) {
            out.push(format!("{root}/{stem}_test.{ext}"));
            out.push(format!("{root}/test_{stem}.{ext}"));
        }
        out.push(
            format!("{parent}/{stem}_test.{ext}")
                .trim_start_matches('/')
                .to_string(),
        );
        out.push(
            format!("{parent}/{stem}.test.{ext}")
                .trim_start_matches('/')
                .to_string(),
        );
    }
    if normalized.starts_with("src/") {
        out.push(normalized.replacen("src/", "tests/", 1));
        for root in configured_test_roots(config) {
            out.push(normalized.replacen("src/", &format!("{root}/"), 1));
        }
    }
    match framework {
        "rust" => {
            out.push(format!("tests/{stem}.rs"));
            out.push(format!("src/{stem}/tests.rs"));
        }
        "python" => {
            out.push(format!("tests/test_{stem}.py"));
        }
        "typescript" | "javascript" => {
            out.push(
                format!("{parent}/{stem}.spec.{ext}")
                    .trim_start_matches('/')
                    .to_string(),
            );
            out.push(
                format!("{parent}/{stem}.test.{ext}")
                    .trim_start_matches('/')
                    .to_string(),
            );
        }
        _ => {}
    }
    out.sort();
    out.dedup();
    out
}

fn test_framework(file: &crate::facts::FileFact) -> String {
    match file.language_name.as_str() {
        "rust" => "rust",
        "python" => "python",
        "typescript" => "typescript",
        "go" => "go",
        "java" => "junit",
        "csharp" => "dotnet",
        other => other,
    }
    .to_string()
}

fn dsm_metrics(report: &ScanReport, config: &RaysenseConfig) -> DsmMetrics {
    let mut edges: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut modules = HashSet::new();

    for file in &report.files {
        modules.insert(module_group(file, config));
    }

    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from_module = module_group(from_file, config);
        let to_module = module_group(to_file, config);
        if from_module != to_module {
            *edges.entry((from_module, to_module)).or_default() += 1;
        }
    }

    let mut top_module_edges: Vec<ModuleEdgeMetric> = edges
        .iter()
        .map(|((from_module, to_module), edges)| ModuleEdgeMetric {
            from_module: from_module.clone(),
            to_module: to_module.clone(),
            edges: *edges,
        })
        .collect();
    top_module_edges.sort_by(|a, b| {
        b.edges
            .cmp(&a.edges)
            .then_with(|| a.from_module.cmp(&b.from_module))
            .then_with(|| a.to_module.cmp(&b.to_module))
    });
    top_module_edges.truncate(10);

    DsmMetrics {
        module_count: modules.len(),
        module_edges: edges.values().sum(),
        top_module_edges,
    }
}

fn evolution_metrics(report: &ScanReport, complexity: &ComplexityMetrics) -> EvolutionMetrics {
    let root = &report.snapshot.root;
    let prefix = match git_output(root, ["rev-parse", "--show-prefix"]) {
        Ok(output) => output.trim().replace('\\', "/"),
        Err(reason) => {
            return EvolutionMetrics {
                available: false,
                reason,
                ..EvolutionMetrics::default()
            };
        }
    };

    let log = match git_output(
        root,
        [
            "log",
            "-n",
            "500",
            "--format=commit:%H|%ae|%at|%s",
            "--name-only",
        ],
    ) {
        Ok(output) => output,
        Err(reason) => {
            return EvolutionMetrics {
                available: false,
                reason,
                ..EvolutionMetrics::default()
            };
        }
    };

    let scanned_files: HashSet<String> = report
        .files
        .iter()
        .map(|file| file.path.to_string_lossy().replace('\\', "/"))
        .collect();
    let mut commits_sampled = 0;
    let mut bug_fix_commits = 0usize;
    let mut file_commits: BTreeMap<String, usize> = BTreeMap::new();
    let mut file_bug_fix_commits: BTreeMap<String, usize> = BTreeMap::new();
    let mut author_commits: BTreeMap<String, usize> = BTreeMap::new();
    let mut file_author_commits: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut file_age_window: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut pair_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut current_author: Option<String> = None;
    let mut current_timestamp: Option<i64> = None;
    let mut current_is_bug_fix = false;
    let mut commit_files = HashSet::new();

    for line in log.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("commit:") {
            flush_commit_files_with_author(
                &mut file_commits,
                &mut file_bug_fix_commits,
                &mut file_author_commits,
                &mut file_age_window,
                &mut pair_counts,
                &mut commit_files,
                current_author.as_deref(),
                current_timestamp,
                current_is_bug_fix,
            );
            commits_sampled += 1;
            // The subject (`%s`) can contain '|' characters, so it must be
            // the last field. Use `splitn(4, '|')` so the fourth split takes
            // the rest of the line verbatim.
            let mut parts = rest.splitn(4, '|');
            let _hash = parts.next();
            let author = parts.next().map(|email| email.trim().to_string());
            let timestamp = parts.next().and_then(|raw| raw.trim().parse::<i64>().ok());
            let subject = parts.next().unwrap_or("").trim();
            let is_bug_fix = is_bug_fix_subject(subject);
            if is_bug_fix {
                bug_fix_commits += 1;
            }
            if let Some(author) = author.as_ref() {
                if !author.is_empty() {
                    *author_commits.entry(author.clone()).or_default() += 1;
                }
            }
            current_author = author;
            current_timestamp = timestamp;
            current_is_bug_fix = is_bug_fix;
            continue;
        }

        if let Some(path) = scan_relative_git_path(line, &prefix) {
            if scanned_files.contains(&path) {
                commit_files.insert(path);
            }
        }
    }
    flush_commit_files_with_author(
        &mut file_commits,
        &mut file_bug_fix_commits,
        &mut file_author_commits,
        &mut file_age_window,
        &mut pair_counts,
        &mut commit_files,
        current_author.as_deref(),
        current_timestamp,
        current_is_bug_fix,
    );

    let mut top_changed_files: Vec<EvolutionFileMetric> = file_commits
        .iter()
        .map(|(path, commits)| EvolutionFileMetric {
            path: path.clone(),
            commits: *commits,
        })
        .collect();
    top_changed_files.sort_by(|a, b| b.commits.cmp(&a.commits).then_with(|| a.path.cmp(&b.path)));
    top_changed_files.truncate(10);

    let author_count = author_commits.len();
    let mut top_authors: Vec<EvolutionAuthorMetric> = author_commits
        .iter()
        .map(|(author, commits)| EvolutionAuthorMetric {
            author: author.clone(),
            commits: *commits,
        })
        .collect();
    top_authors.sort_by(|a, b| {
        b.commits
            .cmp(&a.commits)
            .then_with(|| a.author.cmp(&b.author))
    });
    top_authors.truncate(10);

    let mut file_ownership: Vec<EvolutionFileOwnership> = file_author_commits
        .iter()
        .map(|(path, by_author)| {
            let total_commits: usize = by_author.values().sum();
            let mut sorted: Vec<(&String, &usize)> = by_author.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            let (top_author, top_commits) = sorted
                .first()
                .map(|(name, count)| ((*name).clone(), **count))
                .unwrap_or_default();
            let bus_factor = bus_factor_for(&sorted, total_commits);
            EvolutionFileOwnership {
                path: path.clone(),
                top_author,
                top_author_commits: top_commits,
                total_commits,
                author_count: by_author.len(),
                bus_factor,
            }
        })
        .collect();
    // Order by key-person risk: lowest bus_factor first, then by churn.
    file_ownership.sort_by(|a, b| {
        a.bus_factor
            .cmp(&b.bus_factor)
            .then_with(|| b.total_commits.cmp(&a.total_commits))
            .then_with(|| a.path.cmp(&b.path))
    });
    file_ownership.truncate(20);

    let temporal_hotspots = temporal_hotspots(&file_commits, complexity);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or(0);
    let file_ages = file_ages(&file_age_window, now_unix);
    let change_coupling = change_coupling(&pair_counts, &file_commits);
    let bug_prone_files = bug_prone_files(&file_bug_fix_commits, &file_commits);

    EvolutionMetrics {
        available: true,
        reason: String::new(),
        commits_sampled,
        changed_files: file_commits.len(),
        top_changed_files,
        author_count,
        top_authors,
        file_ownership,
        temporal_hotspots,
        file_ages,
        change_coupling,
        bug_fix_commits,
        bug_prone_files,
    }
}

/// Subject-line classifier for bug-fix commits. Recognises the
/// Conventional Commits `fix:` prefix plus the common `bugfix`,
/// `hotfix`, and `revert` variants. Matches case-insensitively against
/// the start of the trimmed subject; a recognised prefix must be
/// followed by `:`, `!`, `(`, or whitespace so that words like
/// `fixing` or `feature` do not produce false positives.
fn is_bug_fix_subject(subject: &str) -> bool {
    let lower = subject.trim_start().to_ascii_lowercase();
    for prefix in ["bugfix", "hotfix", "revert", "fix"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            let next = rest.chars().next().unwrap_or(' ');
            if next == ':' || next == '!' || next == '(' || next.is_whitespace() {
                return true;
            }
        }
    }
    false
}

/// Top files ranked by absolute bug-fix-commit count, then by
/// bug-fix ratio, then by path. Files with zero bug-fix commits are
/// dropped. Top 20 returned.
fn bug_prone_files(
    file_bug_fix_commits: &BTreeMap<String, usize>,
    file_commits: &BTreeMap<String, usize>,
) -> Vec<EvolutionBugProneFile> {
    let mut entries: Vec<EvolutionBugProneFile> = file_bug_fix_commits
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(path, bug_fix_commits)| {
            let total_commits = file_commits.get(path).copied().unwrap_or(*bug_fix_commits);
            let bug_fix_ratio = if total_commits == 0 {
                0.0
            } else {
                *bug_fix_commits as f64 / total_commits as f64
            };
            EvolutionBugProneFile {
                path: path.clone(),
                bug_fix_commits: *bug_fix_commits,
                total_commits,
                bug_fix_ratio,
            }
        })
        .collect();
    entries.sort_by(|a, b| {
        b.bug_fix_commits
            .cmp(&a.bug_fix_commits)
            .then_with(|| {
                b.bug_fix_ratio
                    .partial_cmp(&a.bug_fix_ratio)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.path.cmp(&b.path))
    });
    entries.truncate(20);
    entries
}

/// Files with at least 3 co-commits, ranked by Jaccard similarity. Pairs that
/// only ever appear together are at strength 1.0; pairs that share a few
/// commits but each change independently are much lower.
fn change_coupling(
    pair_counts: &BTreeMap<(String, String), usize>,
    file_commits: &BTreeMap<String, usize>,
) -> Vec<EvolutionChangeCoupling> {
    const MIN_CO_COMMITS: usize = 3;
    let mut pairs: Vec<EvolutionChangeCoupling> = pair_counts
        .iter()
        .filter_map(|((a, b), count)| {
            if *count < MIN_CO_COMMITS {
                return None;
            }
            let count_a = file_commits.get(a).copied().unwrap_or(0);
            let count_b = file_commits.get(b).copied().unwrap_or(0);
            let union = count_a + count_b - count;
            if union == 0 {
                return None;
            }
            let strength = (*count as f64) / (union as f64);
            Some(EvolutionChangeCoupling {
                left: a.clone(),
                right: b.clone(),
                co_commits: *count,
                coupling_strength: round3(strength),
            })
        })
        .collect();
    pairs.sort_by(|a, b| {
        b.coupling_strength
            .partial_cmp(&a.coupling_strength)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.co_commits.cmp(&a.co_commits))
            .then_with(|| a.left.cmp(&b.left))
            .then_with(|| a.right.cmp(&b.right))
    });
    pairs.truncate(20);
    pairs
}

/// Build the top-N oldest files within the git log window. Returns at most 20
/// entries sorted by `age_days` descending. Files with a zero or future
/// timestamp (clock skew, missing data) are skipped.
fn file_ages(window: &BTreeMap<String, (i64, i64)>, now_unix: i64) -> Vec<EvolutionFileAge> {
    if window.is_empty() || now_unix <= 0 {
        return Vec::new();
    }
    const SECONDS_PER_DAY: i64 = 86_400;
    let mut ages: Vec<EvolutionFileAge> = window
        .iter()
        .filter_map(|(path, (first, last))| {
            if *first <= 0 || *last <= 0 || *first > now_unix {
                return None;
            }
            let age_days = ((now_unix - *first).max(0) / SECONDS_PER_DAY) as u64;
            let last_changed_days = ((now_unix - *last).max(0) / SECONDS_PER_DAY) as u64;
            Some(EvolutionFileAge {
                path: path.clone(),
                first_commit_unix: *first,
                last_commit_unix: *last,
                age_days,
                last_changed_days,
            })
        })
        .collect();
    ages.sort_by(|a, b| {
        b.age_days
            .cmp(&a.age_days)
            .then_with(|| b.last_changed_days.cmp(&a.last_changed_days))
            .then_with(|| a.path.cmp(&b.path))
    });
    ages.truncate(20);
    ages
}

/// Cross-reference commit churn with cyclomatic complexity to surface files
/// that are both volatile and intricate. Risk = commits × max-cyclomatic;
/// files with risk == 0 (no commits or trivial complexity) are dropped.
fn temporal_hotspots(
    file_commits: &BTreeMap<String, usize>,
    complexity: &ComplexityMetrics,
) -> Vec<EvolutionTemporalHotspot> {
    if file_commits.is_empty() || complexity.all_functions.is_empty() {
        return Vec::new();
    }

    let mut max_complexity_per_file: HashMap<&str, usize> = HashMap::new();
    for func in &complexity.all_functions {
        let entry = max_complexity_per_file
            .entry(func.path.as_str())
            .or_default();
        if func.value > *entry {
            *entry = func.value;
        }
    }

    let mut hotspots: Vec<EvolutionTemporalHotspot> = file_commits
        .iter()
        .filter_map(|(path, commits)| {
            let max_cc = max_complexity_per_file.get(path.as_str()).copied()?;
            let risk = commits.saturating_mul(max_cc);
            if risk == 0 {
                return None;
            }
            Some(EvolutionTemporalHotspot {
                path: path.clone(),
                commits: *commits,
                max_complexity: max_cc,
                risk_score: risk,
            })
        })
        .collect();

    hotspots.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| b.commits.cmp(&a.commits))
            .then_with(|| a.path.cmp(&b.path))
    });
    hotspots.truncate(10);
    hotspots
}

fn bus_factor_for(sorted: &[(&String, &usize)], total: usize) -> usize {
    if total == 0 {
        return 0;
    }
    let target = (total as f64 * 0.8).ceil() as usize;
    let mut covered = 0usize;
    for (idx, (_, commits)) in sorted.iter().enumerate() {
        covered += **commits;
        if covered >= target {
            return idx + 1;
        }
    }
    sorted.len().max(1)
}

/// Cap on files-per-commit considered for pair counting. A merge or
/// repo-wide rename touches hundreds of files but expresses no real coupling
/// signal; capping keeps pair generation `O(N²)` bounded.
const MAX_FILES_PER_COMMIT_FOR_COUPLING: usize = 50;

#[allow(clippy::too_many_arguments)]
fn flush_commit_files_with_author(
    file_commits: &mut BTreeMap<String, usize>,
    file_bug_fix_commits: &mut BTreeMap<String, usize>,
    file_author_commits: &mut BTreeMap<String, BTreeMap<String, usize>>,
    file_age_window: &mut BTreeMap<String, (i64, i64)>,
    pair_counts: &mut BTreeMap<(String, String), usize>,
    commit_files: &mut HashSet<String>,
    author: Option<&str>,
    timestamp: Option<i64>,
    is_bug_fix: bool,
) {
    if commit_files.len() <= MAX_FILES_PER_COMMIT_FOR_COUPLING {
        let sorted: Vec<&String> = {
            let mut v: Vec<&String> = commit_files.iter().collect();
            v.sort();
            v
        };
        for i in 0..sorted.len() {
            for j in (i + 1)..sorted.len() {
                let key = (sorted[i].clone(), sorted[j].clone());
                *pair_counts.entry(key).or_default() += 1;
            }
        }
    }
    for path in commit_files.drain() {
        *file_commits.entry(path.clone()).or_default() += 1;
        if is_bug_fix {
            *file_bug_fix_commits.entry(path.clone()).or_default() += 1;
        }
        if let Some(author) = author {
            if !author.is_empty() {
                *file_author_commits
                    .entry(path.clone())
                    .or_default()
                    .entry(author.to_string())
                    .or_default() += 1;
            }
        }
        if let Some(ts) = timestamp {
            file_age_window
                .entry(path)
                .and_modify(|(first, last)| {
                    if ts < *first {
                        *first = ts;
                    }
                    if ts > *last {
                        *last = ts;
                    }
                })
                .or_insert((ts, ts));
        }
    }
}

fn trend_metrics(report: &ScanReport) -> TrendMetrics {
    let path = report.snapshot.root.join(".raysense/trends/history.json");
    let Ok(content) = fs::read_to_string(&path) else {
        return TrendMetrics::default();
    };
    let Ok(samples) = serde_json::from_str::<Vec<TrendSample>>(&content) else {
        return TrendMetrics::default();
    };
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else {
        return TrendMetrics::default();
    };
    TrendMetrics {
        available: true,
        samples: samples.len(),
        score_delta: last.score as i16 - first.score as i16,
        quality_signal_delta: last.quality_signal as i32 - first.quality_signal as i32,
        rule_delta: last.rules as isize - first.rules as isize,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrendSample {
    score: u8,
    quality_signal: u32,
    rules: usize,
}

fn scan_relative_git_path(path: &str, prefix: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    if prefix.is_empty() {
        return Some(path);
    }
    path.strip_prefix(prefix)
        .map(|path| path.trim_start_matches('/').to_string())
        .filter(|path| !path.is_empty())
}

fn git_output<const N: usize>(root: &Path, args: [&str; N]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run git: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            return Err(format!("git exited with status {}", output.status));
        }
        return Err(stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn rules(
    report: &ScanReport,
    hotspots: &[FileHotspot],
    metrics: &MetricsSummary,
    config: &RaysenseConfig,
) -> Vec<RuleFinding> {
    let mut findings = Vec::new();
    let rules = &config.rules;
    let root_causes = root_causes(report, metrics);
    let quality_signal = quality_signal(&root_causes, &config.score);

    if rules.min_quality_signal > 0 && quality_signal < rules.min_quality_signal {
        findings.push(RuleFinding {
            severity: RuleSeverity::Error,
            code: "min_quality_signal".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!(
                "quality signal {} below minimum {}",
                quality_signal, rules.min_quality_signal
            ),
        });
    }

    push_min_score_finding(
        &mut findings,
        report,
        "min_modularity",
        "modularity",
        root_causes.modularity,
        rules.min_modularity,
    );
    push_min_score_finding(
        &mut findings,
        report,
        "min_acyclicity",
        "acyclicity",
        root_causes.acyclicity,
        rules.min_acyclicity,
    );
    push_min_score_finding(
        &mut findings,
        report,
        "min_depth",
        "depth",
        root_causes.depth,
        rules.min_depth,
    );
    push_min_score_finding(
        &mut findings,
        report,
        "min_equality",
        "equality",
        root_causes.equality,
        rules.min_equality,
    );
    push_min_score_finding(
        &mut findings,
        report,
        "min_redundancy",
        "redundancy",
        root_causes.redundancy,
        rules.min_redundancy,
    );

    if report.graph.cycle_count > rules.max_cycles {
        findings.push(RuleFinding {
            severity: RuleSeverity::Error,
            code: "max_cycles".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!(
                "{} cycle participants exceeds max {}",
                report.graph.cycle_count, rules.max_cycles
            ),
        });
    }

    if metrics.coupling.cross_module_ratio > rules.max_coupling_ratio {
        findings.push(RuleFinding {
            severity: RuleSeverity::Warning,
            code: "max_coupling".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!(
                "cross-module ratio {:.3} exceeds max {:.3}",
                metrics.coupling.cross_module_ratio, rules.max_coupling_ratio
            ),
        });
    }

    for function in metrics
        .complexity
        .all_functions
        .iter()
        .filter(|function| {
            let threshold = report
                .files
                .get(function.file_id)
                .map(|file| function_complexity_limit(file, config))
                .unwrap_or(rules.max_function_complexity);
            function.value > threshold
        })
        .take(rules.max_call_hotspot_findings.max(1))
    {
        let threshold = report
            .files
            .get(function.file_id)
            .map(|file| function_complexity_limit(file, config))
            .unwrap_or(rules.max_function_complexity);
        findings.push(RuleFinding {
            severity: RuleSeverity::Warning,
            code: "max_function_complexity".to_string(),
            path: function.path.clone(),
            message: format!(
                "{} complexity {} exceeds max {}",
                function.name, function.value, threshold
            ),
        });
    }

    for function in metrics
        .complexity
        .all_functions
        .iter()
        .filter(|function| {
            let threshold = report
                .files
                .get(function.file_id)
                .map(|file| cognitive_complexity_limit(file, config))
                .unwrap_or(rules.max_cognitive_complexity);
            threshold > 0 && function.cognitive_value > threshold
        })
        .take(rules.max_call_hotspot_findings.max(1))
    {
        let threshold = report
            .files
            .get(function.file_id)
            .map(|file| cognitive_complexity_limit(file, config))
            .unwrap_or(rules.max_cognitive_complexity);
        findings.push(RuleFinding {
            severity: RuleSeverity::Warning,
            code: "max_cognitive_complexity".to_string(),
            path: function.path.clone(),
            message: format!(
                "{} cognitive complexity {} exceeds max {}",
                function.name, function.cognitive_value, threshold
            ),
        });
    }

    for (file, limit) in report
        .files
        .iter()
        .filter_map(|file| file_line_limit(file, config).map(|limit| (file, limit)))
        .filter(|(file, limit)| file.lines > *limit)
        .take(rules.max_large_file_findings.max(1))
    {
        findings.push(RuleFinding {
            severity: RuleSeverity::Error,
            code: "max_file_lines".to_string(),
            path: file.path.to_string_lossy().into_owned(),
            message: format!("{} lines exceeds max {}", file.lines, limit),
        });
    }

    for (function, limit) in report
        .functions
        .iter()
        .filter_map(|function| {
            let file = report.files.get(function.file_id)?;
            function_line_limit(file, config).map(|limit| (function, limit))
        })
        .filter(|(function, limit)| {
            function.end_line.saturating_sub(function.start_line) + 1 > *limit
        })
        .take(rules.max_call_hotspot_findings.max(1))
    {
        let path = report
            .files
            .get(function.file_id)
            .map(|file| file.path.to_string_lossy().into_owned())
            .unwrap_or_else(|| report.snapshot.root.to_string_lossy().into_owned());
        let lines = function.end_line.saturating_sub(function.start_line) + 1;
        findings.push(RuleFinding {
            severity: RuleSeverity::Error,
            code: "max_function_lines".to_string(),
            path,
            message: format!(
                "{} has {} lines exceeding max {}",
                function.name, lines, limit
            ),
        });
    }

    for hotspot in hotspots {
        let limit = report
            .files
            .get(hotspot.file_id)
            .map(|file| high_file_fan_in_limit(file, config))
            .unwrap_or(rules.high_file_fan_in);
        if hotspot.fan_in >= limit {
            findings.push(RuleFinding {
                severity: if rules.no_god_files {
                    RuleSeverity::Warning
                } else {
                    RuleSeverity::Info
                },
                code: "high_fan_in".to_string(),
                path: hotspot.path.clone(),
                message: format!("{} incoming dependency edges", hotspot.fan_in),
            });
        }
    }

    if rules.no_god_files {
        for file in &metrics.coupling.god_files {
            findings.push(RuleFinding {
                severity: RuleSeverity::Warning,
                code: "no_god_files".to_string(),
                path: file.path.clone(),
                message: format!("{} outgoing dependency edges", file.fan_out),
            });
        }
    }

    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };

        let from_path = from_file.path.to_string_lossy();
        let to_path = to_file.path.to_string_lossy();
        if !is_test_path(&from_path) && is_test_path(&to_path) {
            findings.push(RuleFinding {
                severity: RuleSeverity::Warning,
                code: "production_depends_on_test".to_string(),
                path: from_path.into_owned(),
                message: format!("depends on test path {to_path}"),
            });
        }
    }

    let mut large_files: Vec<_> = report
        .files
        .iter()
        .filter(|file| file.lines >= large_file_lines_limit(file, config))
        .collect();
    large_files.sort_by(|a, b| b.lines.cmp(&a.lines).then_with(|| a.path.cmp(&b.path)));

    for file in large_files.iter().take(rules.max_large_file_findings) {
        findings.push(RuleFinding {
            severity: RuleSeverity::Info,
            code: "large_file".to_string(),
            path: file.path.to_string_lossy().into_owned(),
            message: format!("{} lines", file.lines),
        });
    }
    if large_files.len() > rules.max_large_file_findings {
        findings.push(RuleFinding {
            severity: RuleSeverity::Info,
            code: "large_file_summary".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!(
                "{} additional large files",
                large_files.len() - rules.max_large_file_findings
            ),
        });
    }

    if rules.no_tests_detected
        && metrics.test_gap.production_files > 0
        && metrics.test_gap.test_files == 0
        && report.snapshot.function_count > 0
    {
        findings.push(RuleFinding {
            severity: RuleSeverity::Info,
            code: "no_tests_detected".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!(
                "{} production files and no test files detected",
                metrics.test_gap.production_files
            ),
        });
    }

    if metrics.calls.total_calls >= rules.low_call_resolution_min_calls
        && metrics.calls.resolution_ratio < rules.low_call_resolution_ratio
    {
        findings.push(RuleFinding {
            severity: RuleSeverity::Info,
            code: "low_call_resolution".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!(
                "{} of {} calls resolved ({:.3})",
                metrics.calls.resolved_edges,
                metrics.calls.total_calls,
                metrics.calls.resolution_ratio
            ),
        });
    }

    let function_threshold_in = |function: &FunctionCallMetric| -> usize {
        report
            .files
            .get(function.file_id)
            .map(|file| high_function_fan_in_limit(file, config))
            .unwrap_or(rules.high_function_fan_in)
    };
    let function_threshold_out = |function: &FunctionCallMetric| -> usize {
        report
            .files
            .get(function.file_id)
            .map(|file| high_function_fan_out_limit(file, config))
            .unwrap_or(rules.high_function_fan_out)
    };
    for function in metrics
        .calls
        .top_called_functions
        .iter()
        .filter(|function| function.calls >= function_threshold_in(function))
        .take(rules.max_call_hotspot_findings)
    {
        findings.push(RuleFinding {
            severity: RuleSeverity::Info,
            code: "high_function_fan_in".to_string(),
            path: function.path.clone(),
            message: format!(
                "{} has {} resolved incoming calls",
                function.name, function.calls
            ),
        });
    }

    for function in metrics
        .calls
        .top_calling_functions
        .iter()
        .filter(|function| function.calls >= function_threshold_out(function))
        .take(rules.max_call_hotspot_findings)
    {
        findings.push(RuleFinding {
            severity: RuleSeverity::Info,
            code: "high_function_fan_out".to_string(),
            path: function.path.clone(),
            message: format!(
                "{} has {} resolved outgoing calls",
                function.name, function.calls
            ),
        });
    }

    findings.extend(boundary_findings(report, &config.boundaries));
    let layer_findings = layer_findings(report, &config.boundaries);
    if rules.max_upward_layer_violations > 0
        && layer_findings.len() > rules.max_upward_layer_violations
    {
        findings.push(RuleFinding {
            severity: RuleSeverity::Error,
            code: "max_upward_layer_violations".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!(
                "{} upward layer violations exceeds max {}",
                layer_findings.len(),
                rules.max_upward_layer_violations
            ),
        });
    }
    findings.extend(layer_findings);

    findings
}

fn language_override_for<'a>(
    file: &FileFact,
    config: &'a RaysenseConfig,
) -> Option<&'a LanguageRuleOverride> {
    config
        .rules
        .language_overrides
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&file.language_name))
        .map(|(_, value)| value)
}

fn function_complexity_limit(file: &FileFact, config: &RaysenseConfig) -> usize {
    language_override_for(file, config)
        .and_then(|o| o.max_function_complexity)
        .or_else(|| plugin_for_file(file, config).and_then(|plugin| plugin.max_function_complexity))
        .unwrap_or(config.rules.max_function_complexity)
}

fn cognitive_complexity_limit(file: &FileFact, config: &RaysenseConfig) -> usize {
    language_override_for(file, config)
        .and_then(|o| o.max_cognitive_complexity)
        .or_else(|| {
            plugin_for_file(file, config).and_then(|plugin| plugin.max_cognitive_complexity)
        })
        .unwrap_or(config.rules.max_cognitive_complexity)
}

fn file_line_limit(file: &FileFact, config: &RaysenseConfig) -> Option<usize> {
    language_override_for(file, config)
        .and_then(|o| o.max_file_lines)
        .or_else(|| plugin_for_file(file, config).and_then(|plugin| plugin.max_file_lines))
        .or_else(|| (config.rules.max_file_lines > 0).then_some(config.rules.max_file_lines))
}

fn function_line_limit(file: &FileFact, config: &RaysenseConfig) -> Option<usize> {
    language_override_for(file, config)
        .and_then(|o| o.max_function_lines)
        .or_else(|| plugin_for_file(file, config).and_then(|plugin| plugin.max_function_lines))
        .or_else(|| {
            (config.rules.max_function_lines > 0).then_some(config.rules.max_function_lines)
        })
}

fn high_file_fan_in_limit(file: &FileFact, config: &RaysenseConfig) -> usize {
    language_override_for(file, config)
        .and_then(|o| o.high_file_fan_in)
        .unwrap_or(config.rules.high_file_fan_in)
}

fn high_file_fan_out_limit(file: &FileFact, config: &RaysenseConfig) -> usize {
    language_override_for(file, config)
        .and_then(|o| o.high_file_fan_out)
        .unwrap_or(config.rules.high_file_fan_out)
}

fn large_file_lines_limit(file: &FileFact, config: &RaysenseConfig) -> usize {
    language_override_for(file, config)
        .and_then(|o| o.large_file_lines)
        .unwrap_or(config.rules.large_file_lines)
}

fn high_function_fan_in_limit(file: &FileFact, config: &RaysenseConfig) -> usize {
    language_override_for(file, config)
        .and_then(|o| o.high_function_fan_in)
        .unwrap_or(config.rules.high_function_fan_in)
}

fn high_function_fan_out_limit(file: &FileFact, config: &RaysenseConfig) -> usize {
    language_override_for(file, config)
        .and_then(|o| o.high_function_fan_out)
        .unwrap_or(config.rules.high_function_fan_out)
}

fn plugin_for_file<'a>(
    file: &FileFact,
    config: &'a RaysenseConfig,
) -> Option<&'a LanguagePluginConfig> {
    config
        .scan
        .plugins
        .iter()
        .find(|plugin| plugin.name.eq_ignore_ascii_case(&file.language_name))
}

fn push_min_score_finding(
    findings: &mut Vec<RuleFinding>,
    report: &ScanReport,
    code: &str,
    label: &str,
    value: f64,
    min: f64,
) {
    if min > 0.0 && value < min {
        findings.push(RuleFinding {
            severity: RuleSeverity::Error,
            code: code.to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!("{label} score {value:.3} below minimum {min:.3}"),
        });
    }
}

fn remediations(rules: &[RuleFinding], metrics: &MetricsSummary) -> Vec<Remediation> {
    let mut out = Vec::new();
    for rule in rules {
        let action = match rule.code.as_str() {
            "min_quality_signal" => {
                "inspect the lowest root-cause score and fix the matching structural bottleneck"
            }
            "min_modularity" => "reduce cross-module edges or regroup files by cohesive module",
            "min_acyclicity" => "remove dependency cycles by introducing a lower-level interface",
            "min_depth" => "flatten long dependency chains or invert unnecessary layers",
            "min_equality" => {
                "split oversized files/functions and rebalance concentrated complexity"
            }
            "min_redundancy" => "remove dead functions or consolidate duplicated implementations",
            "max_file_lines" => "split the file into smaller cohesive modules",
            "max_function_lines" => "extract helpers or split the function into smaller steps",
            "max_function_complexity" => {
                "split the function, extract decision branches, or add a local policy override"
            }
            "max_cognitive_complexity" => {
                "flatten nesting, return early, or extract nested decision branches"
            }
            "high_fan_in" => "introduce a facade boundary or split shared responsibilities",
            "production_depends_on_test" => {
                "move shared fixtures into a production-safe support module"
            }
            "large_file" => "split file by cohesive type, operation, or module boundary",
            "no_tests_detected" => "add first tests at the expected test-gap paths",
            "low_call_resolution" => {
                "add language plugin patterns or enable a grammar-backed scanner"
            }
            "layer_order" => "invert the dependency or update ordered layer config",
            "max_upward_layer_violations" => {
                "remove upward layer dependencies or adjust layer ordering"
            }
            "max_cycles" => {
                "break one dependency edge in each cycle or configure an allowed boundary"
            }
            _ => "inspect the finding and tune policy or architecture",
        };
        out.push(Remediation {
            code: rule.code.clone(),
            path: rule.path.clone(),
            action: action.to_string(),
            command: format!("raysense check {} --json", shell_path(&rule.path)),
        });
    }
    for gap in metrics.test_gap.candidates.iter().take(10) {
        if let Some(path) = gap.expected_tests.first() {
            out.push(Remediation {
                code: "test_gap".to_string(),
                path: gap.path.clone(),
                action: format!("add a {} test for {}", gap.framework, gap.path),
                command: format!(
                    "mkdir -p {} && touch {}",
                    parent_path(path),
                    shell_path(path)
                ),
            });
        }
    }
    out.truncate(50);
    out
}

fn shell_path(path: &str) -> String {
    if path.contains(' ') {
        format!("'{}'", path.replace('\'', "'\\''"))
    } else {
        path.to_string()
    }
}

fn parent_path(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|path| shell_path(&path.to_string_lossy()))
        .unwrap_or_else(|| ".".to_string())
}

fn boundary_findings(report: &ScanReport, config: &BoundaryConfig) -> Vec<RuleFinding> {
    if config.forbidden_edges.is_empty() {
        return Vec::new();
    }

    let forbidden: HashSet<(&str, &str)> = config
        .forbidden_edges
        .iter()
        .map(|edge| (edge.from.as_str(), edge.to.as_str()))
        .collect();
    let reasons: BTreeMap<(&str, &str), &str> = config
        .forbidden_edges
        .iter()
        .map(|edge| ((edge.from.as_str(), edge.to.as_str()), edge.reason.as_str()))
        .collect();
    let mut edges: BTreeMap<(String, String), (usize, String)> = BTreeMap::new();

    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from_module = top_module(&from_file.module);
        let to_module = top_module(&to_file.module);
        if forbidden.contains(&(from_module, to_module)) {
            let reason = reasons
                .get(&(from_module, to_module))
                .copied()
                .unwrap_or_default()
                .to_string();
            edges
                .entry((from_module.to_string(), to_module.to_string()))
                .and_modify(|entry| entry.0 += 1)
                .or_insert((1, reason));
        }
    }

    edges
        .into_iter()
        .map(|((from_module, to_module), (count, reason))| {
            let reason = reason.trim();
            let message = if reason.is_empty() {
                format!("{from_module} -> {to_module} has {count} dependency edges")
            } else {
                format!("{from_module} -> {to_module} has {count} dependency edges: {reason}")
            };
            RuleFinding {
                severity: RuleSeverity::Warning,
                code: "forbidden_module_edge".to_string(),
                path: report.snapshot.root.to_string_lossy().into_owned(),
                message,
            }
        })
        .collect()
}

fn layer_findings(report: &ScanReport, config: &BoundaryConfig) -> Vec<RuleFinding> {
    if config.layers.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        if to_file_id == import.from_file {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from_path = normalize_rule_path(&from_file.path);
        let to_path = normalize_rule_path(&to_file.path);
        let Some(from_layer) = matching_layer(&from_path, &config.layers) else {
            continue;
        };
        let Some(to_layer) = matching_layer(&to_path, &config.layers) else {
            continue;
        };
        if from_layer.order < to_layer.order {
            findings.push(RuleFinding {
                severity: RuleSeverity::Warning,
                code: "layer_order".to_string(),
                path: from_path,
                message: format!(
                    "{} depends upward on {} through {}",
                    from_layer.name, to_layer.name, to_path
                ),
            });
        }
    }
    findings
}

fn matching_layer<'a>(path: &str, layers: &'a [LayerConfig]) -> Option<&'a LayerConfig> {
    layers
        .iter()
        .filter(|layer| path_matches_rule(path, &layer.path))
        .max_by_key(|layer| layer.path.len())
}

fn path_matches_rule(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    if let Some(prefix) = pattern.strip_suffix("/*") {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    } else {
        path == pattern || path.starts_with(&format!("{pattern}/"))
    }
}

fn normalize_rule_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn module_group(file: &crate::facts::FileFact, config: &RaysenseConfig) -> String {
    let path = normalize_rule_path(&file.path);
    if let Some(group) = ecosystem_module_group(&path, &file.language_name) {
        return group;
    }
    for root in &config.scan.module_roots {
        let root = root.trim_matches('/');
        if root.is_empty() {
            continue;
        }
        if path == root || path.starts_with(&format!("{root}/")) {
            let rest = path.trim_start_matches(root).trim_start_matches('/');
            let next = rest.split('/').next().unwrap_or("");
            return if next.is_empty() {
                root.to_string()
            } else {
                format!("{root}/{next}")
            };
        }
    }
    for layer in &config.boundaries.layers {
        if path_matches_rule(&path, &layer.path) {
            return layer.name.clone();
        }
    }
    top_module(&file.module).to_string()
}

fn ecosystem_module_group(path: &str, language: &str) -> Option<String> {
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() >= 3 && parts[0] == "crates" {
        return Some(format!("crates/{}", parts[1]));
    }
    if parts.len() >= 3 && parts[0] == "packages" {
        return Some(format!("packages/{}", parts[1]));
    }
    if parts.len() >= 3 && parts[0] == "apps" {
        return Some(format!("apps/{}", parts[1]));
    }
    match language {
        "go" if parts.len() >= 2 => Some(parts[..parts.len().saturating_sub(1)].join("/")),
        "python" if parts.len() >= 2 && parts[0] == "src" => {
            parts.get(1).map(|item| (*item).to_string())
        }
        "java" | "kotlin" if parts.iter().any(|part| *part == "src") => parts
            .iter()
            .position(|part| *part == "java" || *part == "kotlin")
            .and_then(|idx| parts.get(idx + 1))
            .map(|item| (*item).to_string()),
        _ => None,
    }
}

fn top_module(module: &str) -> &str {
    module.split(['.', '/']).next().unwrap_or(module)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    round3(numerator as f64 / denominator as f64)
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn is_test_path_configured(path: &str, config: &RaysenseConfig) -> bool {
    is_test_path(path) || matches_configured_path(path, &config.scan.test_roots)
}

fn matches_configured_path(path: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .map(|pattern| pattern.trim())
        .filter(|pattern| !pattern.is_empty())
        .any(|pattern| path_matches_rule(path, pattern))
}

fn configured_test_roots(config: &RaysenseConfig) -> Vec<String> {
    let mut roots = if config.scan.test_roots.is_empty() {
        vec!["tests".to_string()]
    } else {
        config
            .scan
            .test_roots
            .iter()
            .map(|root| root.trim().trim_matches('/').to_string())
            .filter(|root| !root.is_empty())
            .collect()
    };
    roots.sort();
    roots.dedup();
    roots
}

fn is_test_path(path: &str) -> bool {
    path.starts_with("test/")
        || path.starts_with("tests/")
        || path.contains("/test/")
        || path.contains("/tests/")
        || path.contains("_test.")
        || path.contains("_tests.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{
        CallEdgeFact, CallFact, EntryPointFact, EntryPointKind, FileFact, FunctionFact, ImportFact,
        Language, SnapshotFact,
    };
    use crate::graph::compute_graph_metrics;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn computes_resolution_breakdown_and_hotspots() {
        let files = vec![file(0, "a.rs"), file(1, "b.rs")];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 0, None, ImportResolution::External),
            import(2, 1, None, ImportResolution::Unresolved),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let health = compute_health(&report);

        assert_eq!(health.resolution.local, 1);
        assert_eq!(health.resolution.external, 1);
        assert_eq!(health.resolution.unresolved, 1);
        assert_eq!(health.hotspots[0].path, "b.rs");
        assert!(health.coverage_score < 100);
        assert_eq!(health.structural_score, 100);
        assert!(health.score < 100);
    }

    #[test]
    fn discounts_edges_to_stable_foundations() {
        let files = vec![
            file(0, "src/app/a.rs"),
            file(1, "src/app/b.rs"),
            file(2, "src/core/types.rs"),
            file(3, "src/feature/use_case.rs"),
            file(4, "src/infra/adapter.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(2), ImportResolution::Local),
            import(1, 1, Some(2), ImportResolution::Local),
            import(2, 3, Some(4), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let mut config = RaysenseConfig::default();
        config.scan.module_roots = vec!["src".to_string()];
        let health = compute_health_with_config(&report, &config);

        assert_eq!(health.metrics.coupling.cross_module_edges, 3);
        assert_eq!(health.metrics.coupling.cross_unstable_edges, 1);
        assert!(health
            .metrics
            .architecture
            .stable_foundations
            .iter()
            .any(|module| module.module == "src/core"));
        assert!(health.root_causes.modularity > 0.6);
    }

    #[test]
    fn reports_non_foundation_blast_radius() {
        let files = vec![
            file(0, "src/core/types.rs"),
            file(1, "src/app1/a.rs"),
            file(2, "src/app2/a.rs"),
            file(3, "src/app3/a.rs"),
            file(4, "src/app4/a.rs"),
            file(5, "src/app5/a.rs"),
            file(6, "src/app6/a.rs"),
        ];
        let imports = vec![
            import(0, 1, Some(0), ImportResolution::Local),
            import(1, 2, Some(0), ImportResolution::Local),
            import(2, 3, Some(0), ImportResolution::Local),
            import(3, 4, Some(0), ImportResolution::Local),
            import(4, 5, Some(0), ImportResolution::Local),
            import(5, 6, Some(0), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let mut config = RaysenseConfig::default();
        config.scan.module_roots = vec!["src".to_string()];
        let health = compute_health_with_config(&report, &config);

        assert_eq!(health.metrics.architecture.max_blast_radius, 6);
        assert_eq!(
            health.metrics.architecture.max_blast_radius_file,
            "src/core/types.rs"
        );
        assert_eq!(
            health.metrics.architecture.max_non_foundation_blast_radius,
            0
        );
        assert!(health
            .metrics
            .architecture
            .stable_foundations
            .iter()
            .any(|module| module.module == "src/core"));
    }

    #[test]
    fn computes_distance_from_main_sequence() {
        let root = temp_health_root("distance");
        fs::create_dir_all(root.join("src/api")).unwrap();
        fs::create_dir_all(root.join("src/impls")).unwrap();
        fs::write(root.join("src/api/mod.rs"), "pub trait Store {}\n").unwrap();
        fs::write(root.join("src/impls/store.rs"), "pub struct DiskStore;\n").unwrap();

        let files = vec![file(0, "src/api/mod.rs"), file(1, "src/impls/store.rs")];
        let imports = vec![import(0, 1, Some(0), ImportResolution::Local)];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root,
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let mut config = RaysenseConfig::default();
        config.scan.module_roots = vec!["src".to_string()];
        let health = compute_health_with_config(&report, &config);

        let api = health
            .metrics
            .architecture
            .distance_metrics
            .iter()
            .find(|metric| metric.module == "src/api")
            .unwrap();
        assert_eq!(api.abstract_count, 1);
        assert_eq!(api.total_types, 1);
        assert_eq!(api.abstractness, 1.0);
        assert_eq!(api.instability, 0.0);
        assert_eq!(api.distance, 0.0);
    }

    #[test]
    fn applies_plugin_type_prefixes_to_main_sequence_distance() {
        let root = temp_health_root("plugin_distance");
        fs::create_dir_all(root.join("src/api")).unwrap();
        fs::write(
            root.join("src/api/contract.foo"),
            "contract Store\nrecord Disk\n",
        )
        .unwrap();

        let mut files = vec![file(0, "src/api/contract.foo")];
        files[0].language = Language::Unknown;
        files[0].language_name = "foo".to_string();
        let graph = compute_graph_metrics(&files, &[]);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root,
                file_count: files.len(),
                function_count: 0,
                import_count: 0,
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };
        let mut config = RaysenseConfig::default();
        config.scan.plugins.push(LanguagePluginConfig {
            name: "foo".to_string(),
            abstract_type_prefixes: vec!["contract ".to_string()],
            concrete_type_prefixes: vec!["record ".to_string()],
            ..LanguagePluginConfig::default()
        });
        config.scan.module_roots = vec!["src".to_string()];
        let health = compute_health_with_config(&report, &config);
        let metric = &health.metrics.architecture.distance_metrics[0];

        assert_eq!(metric.abstract_count, 1);
        assert_eq!(metric.total_types, 2);
        assert_eq!(metric.abstractness, 0.5);
    }

    #[test]
    fn computes_attack_surface_from_entry_points() {
        let files = vec![
            file(0, "src/main.rs"),
            file(1, "src/service.rs"),
            file(2, "src/repo.rs"),
            file(3, "src/orphan.rs"),
            file(4, "src/util.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 1, Some(2), ImportResolution::Local),
            import(2, 3, Some(4), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: vec![EntryPointFact {
                entry_id: 0,
                file_id: 0,
                kind: EntryPointKind::Binary,
                symbol: "main".to_string(),
            }],
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let health = compute_health(&report);

        assert_eq!(health.metrics.architecture.attack_surface_files, 3);
        assert_eq!(health.metrics.architecture.total_graph_files, 5);
        assert_eq!(health.metrics.architecture.attack_surface_ratio, 0.6);
    }

    #[test]
    fn computes_coupling_entropy_for_unstable_cross_module_edges() {
        let files = vec![
            file(0, "src/a/mod.rs"),
            file(1, "src/b/mod.rs"),
            file(2, "src/c/mod.rs"),
            file(3, "src/d/mod.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 2, Some(3), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let mut config = RaysenseConfig::default();
        config.scan.module_roots = vec!["src".to_string()];
        let health = compute_health_with_config(&report, &config);

        assert_eq!(health.metrics.coupling.entropy_pairs, 2);
        assert_eq!(health.metrics.coupling.entropy_bits, 1.0);
        assert_eq!(health.metrics.coupling.entropy, 1.0);
    }

    #[test]
    fn distribution_entropy_handles_uniform_and_concentrated() {
        assert_eq!(distribution_entropy(&[]), (0.0, 0.0));
        assert_eq!(distribution_entropy(&[0, 0, 0]), (0.0, 0.0));
        assert_eq!(distribution_entropy(&[10]), (0.0, 0.0));
        assert_eq!(distribution_entropy(&[10, 0]), (0.0, 0.0));
        assert_eq!(distribution_entropy(&[5, 5]), (1.0, 1.0));
        assert_eq!(distribution_entropy(&[3, 3, 3, 3]), (1.0, 2.0));
    }

    #[test]
    fn file_lines_bucket_separates_orders_of_magnitude() {
        assert_eq!(file_lines_bucket(0), 0);
        assert_eq!(file_lines_bucket(1), 1);
        assert_eq!(file_lines_bucket(2), 2);
        assert_eq!(file_lines_bucket(3), 2);
        assert_eq!(file_lines_bucket(4), 3);
        assert_eq!(file_lines_bucket(7), 3);
        assert_eq!(file_lines_bucket(1000), file_lines_bucket(1023));
        assert_ne!(file_lines_bucket(100), file_lines_bucket(1000));
    }

    fn report_with_file_lines(lines: &[usize]) -> ScanReport {
        let files: Vec<FileFact> = lines
            .iter()
            .enumerate()
            .map(|(idx, count)| {
                let mut f = file(idx, &format!("src/m{idx}.rs"));
                f.lines = *count;
                f
            })
            .collect();
        let imports = Vec::new();
        let graph = compute_graph_metrics(&files, &imports);
        ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: 0,
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        }
    }

    #[test]
    fn file_size_entropy_zero_for_identical_sizes() {
        let report = report_with_file_lines(&[100, 100, 100, 100]);
        let metrics = size_metrics(&report);
        assert_eq!(metrics.file_size_entropy, 0.0);
        assert_eq!(metrics.file_size_entropy_bits, 0.0);
    }

    #[test]
    fn file_size_entropy_uniform_for_distinct_buckets() {
        // Two files at ~1 line, two files at ~1024 lines: two equally-populated
        // log2 buckets, so normalized entropy is 1.0 and absolute is log2(2) = 1.0 bits.
        let report = report_with_file_lines(&[1, 1, 1024, 1024]);
        let metrics = size_metrics(&report);
        assert_eq!(metrics.file_size_entropy, 1.0);
        assert_eq!(metrics.file_size_entropy_bits, 1.0);
    }

    #[test]
    fn quality_signal_preserved_when_file_size_distribution_varies() {
        // Same file count, same large_files/long_functions, but very different
        // size distributions. With the default ScoreConfig (structural_uniformity_weight = 0),
        // the two reports must produce byte-identical score / quality_signal.
        let uniform = report_with_file_lines(&[100, 100, 100, 100]);
        let spread = report_with_file_lines(&[1, 8, 64, 1024]);

        let config = RaysenseConfig::default();
        let h_uniform = compute_health_with_config(&uniform, &config);
        let h_spread = compute_health_with_config(&spread, &config);

        assert_ne!(
            h_uniform.metrics.size.file_size_entropy,
            h_spread.metrics.size.file_size_entropy
        );
        assert_eq!(h_uniform.score, h_spread.score);
        assert_eq!(h_uniform.quality_signal, h_spread.quality_signal);
        assert_eq!(
            h_uniform.root_causes.modularity,
            h_spread.root_causes.modularity
        );
        assert_eq!(
            h_uniform.root_causes.equality,
            h_spread.root_causes.equality
        );
        assert_eq!(
            h_uniform.root_causes.redundancy,
            h_spread.root_causes.redundancy
        );
    }

    #[test]
    fn grade_thresholds_map_scores_to_letter_grades() {
        let thresholds = GradeThresholds::default();
        assert_eq!(grade_for(0.95, &thresholds), "A");
        assert_eq!(grade_for(0.9, &thresholds), "A");
        assert_eq!(grade_for(0.85, &thresholds), "B");
        assert_eq!(grade_for(0.8, &thresholds), "B");
        assert_eq!(grade_for(0.75, &thresholds), "C");
        assert_eq!(grade_for(0.7, &thresholds), "C");
        assert_eq!(grade_for(0.6, &thresholds), "D");
        assert_eq!(grade_for(0.5, &thresholds), "D");
        assert_eq!(grade_for(0.4, &thresholds), "F");
    }

    #[test]
    fn custom_grade_thresholds_are_respected() {
        let thresholds = GradeThresholds {
            a: 0.95,
            b: 0.9,
            c: 0.85,
            d: 0.7,
        };
        // Score 0.92 would be A by default, but B under stricter thresholds.
        assert_eq!(grade_for(0.92, &thresholds), "B");
        // Score 0.74 would be C by default, but D under stricter thresholds.
        assert_eq!(grade_for(0.74, &thresholds), "D");
    }

    #[test]
    fn is_bug_fix_subject_recognises_conventional_and_common_prefixes() {
        // Conventional Commits "fix" forms.
        assert!(is_bug_fix_subject("fix: stop crash on empty input"));
        assert!(is_bug_fix_subject(
            "fix(parser): off-by-one in bracket match"
        ));
        assert!(is_bug_fix_subject("fix!: breaking signature change"));
        assert!(is_bug_fix_subject("fix typo in error message")); // whitespace after prefix

        // Common variants.
        assert!(is_bug_fix_subject("bugfix: ratelimit underflow"));
        assert!(is_bug_fix_subject("hotfix: production redeploy"));
        assert!(is_bug_fix_subject("revert: bring back prior behaviour"));
        assert!(is_bug_fix_subject("Revert \"feat: new thing\"")); // git's default revert subject

        // Indented / leading whitespace still counts.
        assert!(is_bug_fix_subject("  fix: leading spaces"));

        // Negatives - words that start with `fix*` but are not fix commits.
        assert!(!is_bug_fix_subject("feat: add validator"));
        assert!(!is_bug_fix_subject("fixing the parser is hard")); // "fixing", not "fix"
        assert!(!is_bug_fix_subject("fixtures: regenerate snapshots")); // "fixtures"
        assert!(!is_bug_fix_subject("docs: typo in README"));
        assert!(!is_bug_fix_subject(""));
    }

    #[test]
    fn bug_prone_files_ranks_by_count_then_ratio() {
        use std::collections::BTreeMap;

        let mut bug_fixes: BTreeMap<String, usize> = BTreeMap::new();
        let mut totals: BTreeMap<String, usize> = BTreeMap::new();

        bug_fixes.insert("src/parser.rs".to_string(), 8);
        totals.insert("src/parser.rs".to_string(), 12);

        bug_fixes.insert("src/cli.rs".to_string(), 5);
        totals.insert("src/cli.rs".to_string(), 20);

        bug_fixes.insert("src/lexer.rs".to_string(), 5);
        totals.insert("src/lexer.rs".to_string(), 8);

        bug_fixes.insert("src/quiet.rs".to_string(), 0);
        totals.insert("src/quiet.rs".to_string(), 30);

        let ranked = bug_prone_files(&bug_fixes, &totals);

        // Files with zero bug fixes are dropped.
        assert!(!ranked.iter().any(|e| e.path == "src/quiet.rs"));

        // First by absolute fix count, then by ratio. parser (8 fixes) leads;
        // among the two files with 5 fixes, lexer (5/8=0.625) outranks
        // cli (5/20=0.25).
        let paths: Vec<&str> = ranked.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["src/parser.rs", "src/lexer.rs", "src/cli.rs"]);

        // Ratio is computed against total_commits, not fix-only commits.
        let parser = ranked.iter().find(|e| e.path == "src/parser.rs").unwrap();
        assert!((parser.bug_fix_ratio - (8.0 / 12.0)).abs() < 1e-9);
    }

    #[test]
    fn bus_factor_returns_minimum_authors_for_eighty_percent_coverage() {
        // Single author owns all commits → bus factor 1.
        let one = "alice".to_string();
        let only_alice = vec![(&one, &10usize)];
        assert_eq!(bus_factor_for(&only_alice, 10), 1);

        // 5+5 split → top author owns 50%; need both for 80% coverage.
        let alice = "alice".to_string();
        let bob = "bob".to_string();
        let split = vec![(&alice, &5usize), (&bob, &5usize)];
        assert_eq!(bus_factor_for(&split, 10), 2);

        // 9+1 split → top author owns 90% (>= 80%) → bus factor 1.
        let dominant = vec![(&alice, &9usize), (&bob, &1usize)];
        assert_eq!(bus_factor_for(&dominant, 10), 1);

        // No commits → bus factor 0.
        assert_eq!(bus_factor_for(&[], 0), 0);
    }

    #[test]
    fn structural_uniformity_averages_size_and_complexity_entropy() {
        let report = report_with_file_lines(&[1, 1, 1024, 1024]);
        let health = compute_health_with_config(&report, &RaysenseConfig::default());
        // No functions in this synthetic report, so complexity_entropy is 0.
        // file_size_entropy is 1.0 (two equally-populated log buckets).
        assert_eq!(health.metrics.size.file_size_entropy, 1.0);
        assert_eq!(health.metrics.complexity.complexity_entropy, 0.0);
        assert_eq!(health.root_causes.structural_uniformity, 0.5);
    }

    #[test]
    fn plugin_config_round_trips_extended_semantic_fields() {
        let config: RaysenseConfig = toml::from_str(
            r#"
[[scan.plugins]]
name = "toy"
extensions = ["toy"]
resolver_alias_files = ["aliases.json"]
namespace_separator = "."
module_prefix_files = ["mod.toy", "init.toy"]
module_prefix_directives = ["package "]
entry_point_patterns = ["main", "init"]
test_module_patterns = ["tests/*"]
test_attribute_patterns = ["@Test"]
parameter_node_kinds = ["parameter"]
complexity_node_kinds = ["if_expression", "while_expression"]
logical_operator_kinds = ["&&", "||"]
abstract_base_classes = ["Base", "Abstract"]
"#,
        )
        .expect("plugin config with new fields parses");

        let plugin = config
            .scan
            .plugins
            .iter()
            .find(|plugin| plugin.name == "toy")
            .expect("toy plugin present");
        assert_eq!(plugin.resolver_alias_files, vec!["aliases.json"]);
        assert_eq!(plugin.namespace_separator.as_deref(), Some("."));
        assert_eq!(plugin.module_prefix_files, vec!["mod.toy", "init.toy"]);
        assert_eq!(plugin.module_prefix_directives, vec!["package "]);
        assert_eq!(plugin.entry_point_patterns, vec!["main", "init"]);
        assert_eq!(plugin.test_module_patterns, vec!["tests/*"]);
        assert_eq!(plugin.test_attribute_patterns, vec!["@Test"]);
        assert_eq!(plugin.parameter_node_kinds, vec!["parameter"]);
        assert_eq!(
            plugin.complexity_node_kinds,
            vec!["if_expression", "while_expression"]
        );
        assert_eq!(plugin.logical_operator_kinds, vec!["&&", "||"]);
        assert_eq!(plugin.abstract_base_classes, vec!["Base", "Abstract"]);
    }

    #[test]
    fn plugin_config_defaults_extended_fields_to_empty() {
        let config: RaysenseConfig = toml::from_str(
            r#"
[[scan.plugins]]
name = "minimal"
extensions = ["min"]
"#,
        )
        .expect("minimal plugin parses");
        let plugin = config
            .scan
            .plugins
            .iter()
            .find(|plugin| plugin.name == "minimal")
            .expect("minimal plugin present");
        assert!(plugin.resolver_alias_files.is_empty());
        assert!(plugin.namespace_separator.is_none());
        assert!(plugin.module_prefix_files.is_empty());
        assert!(plugin.module_prefix_directives.is_empty());
        assert!(plugin.entry_point_patterns.is_empty());
        assert!(plugin.test_module_patterns.is_empty());
        assert!(plugin.test_attribute_patterns.is_empty());
        assert!(plugin.parameter_node_kinds.is_empty());
        assert!(plugin.complexity_node_kinds.is_empty());
        assert!(plugin.logical_operator_kinds.is_empty());
        assert!(plugin.abstract_base_classes.is_empty());
    }

    #[test]
    fn quality_signal_shifts_when_structural_uniformity_weight_set() {
        // Two reports with different structural uniformity values. With the
        // default weight (0.0) their quality_signal must match. With a non-zero
        // weight the score must shift in the direction of the higher-uniformity
        // report - that is the explicit opt-in behavior change.
        let monoculture = report_with_file_lines(&[100, 100, 100, 100]);
        let diverse = report_with_file_lines(&[1, 1, 1024, 1024]);

        let mut config = RaysenseConfig::default();
        let baseline_mono = compute_health_with_config(&monoculture, &config).quality_signal;
        let baseline_div = compute_health_with_config(&diverse, &config).quality_signal;
        assert_eq!(baseline_mono, baseline_div);

        config.score.structural_uniformity_weight = 1.0;
        let weighted_mono = compute_health_with_config(&monoculture, &config).quality_signal;
        let weighted_div = compute_health_with_config(&diverse, &config).quality_signal;

        assert_ne!(weighted_mono, baseline_mono);
        assert_ne!(weighted_div, baseline_div);
        assert!(
            weighted_div > weighted_mono,
            "diverse distribution should outscore monoculture once weighted in"
        );
    }

    #[test]
    fn computes_module_cohesion_from_internal_edges() {
        let files = vec![
            file(0, "src/a/one.rs"),
            file(1, "src/a/two.rs"),
            file(2, "src/a/three.rs"),
        ];
        let imports = vec![import(0, 0, Some(1), ImportResolution::Local)];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let mut config = RaysenseConfig::default();
        config.scan.module_roots = vec!["src".to_string()];
        let health = compute_health_with_config(&report, &config);

        assert_eq!(health.metrics.coupling.cohesive_module_count, 1);
        assert_eq!(health.metrics.coupling.average_module_cohesion, Some(0.5));
    }

    #[test]
    fn reports_file_instability_and_god_files() {
        let files = vec![
            file(0, "src/app.rs"),
            file(1, "src/a.rs"),
            file(2, "src/b.rs"),
            file(3, "src/c.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 0, Some(2), ImportResolution::Local),
            import(2, 0, Some(3), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };
        let mut config = RaysenseConfig::default();
        config.rules.high_file_fan_out = 2;
        let health = compute_health_with_config(&report, &config);

        assert_eq!(health.metrics.coupling.god_files[0].path, "src/app.rs");
        assert_eq!(health.metrics.coupling.god_files[0].fan_out, 3);
        assert_eq!(
            health.metrics.coupling.most_unstable_files[0].path,
            "src/app.rs"
        );
        assert_eq!(
            health.metrics.coupling.most_unstable_files[0].instability,
            1.0
        );
        assert!(health.rules.iter().any(|rule| rule.code == "no_god_files"));
    }

    #[test]
    fn reports_cycle_edges_as_upward_violations() {
        let files = vec![file(0, "src/a.rs"), file(1, "src/b.rs")];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 1, Some(0), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let health = compute_health(&report);

        assert_eq!(health.metrics.architecture.upward_violations.len(), 2);
        assert!(health
            .metrics
            .architecture
            .upward_violations
            .iter()
            .all(|violation| violation.reason == "cycle_edge"));
    }

    #[test]
    fn flags_production_dependencies_on_test_paths() {
        let files = vec![file(0, "src/a.c"), file(1, "test/test.h")];
        let imports = vec![import(0, 0, Some(1), ImportResolution::Local)];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let health = compute_health(&report);

        assert_eq!(health.rules.len(), 1);
        assert_eq!(health.rules[0].code, "production_depends_on_test");
        assert!(health.structural_score < 100);
    }

    #[test]
    fn computes_metric_families() {
        let mut files = vec![file(0, "core/a.rs"), file(1, "io/b.rs")];
        files[0].lines = 600;
        let imports = vec![import(0, 0, Some(1), ImportResolution::Local)];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 1,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: vec![FunctionFact {
                function_id: 0,
                file_id: 0,
                name: "large".to_string(),
                start_line: 10,
                end_line: 95,
            }],
            entry_points: vec![EntryPointFact {
                entry_id: 0,
                file_id: 0,
                kind: EntryPointKind::Binary,
                symbol: "main".to_string(),
            }],
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };

        let health = compute_health(&report);

        assert_eq!(health.metrics.coupling.cross_module_edges, 1);
        assert_eq!(health.metrics.size.large_files, 1);
        assert_eq!(health.metrics.size.long_functions, 1);
        assert_eq!(health.metrics.entry_points.binaries, 1);
        assert_eq!(health.metrics.dsm.module_edges, 1);
    }

    #[test]
    fn computes_source_aware_complexity_duplicates_and_test_gaps() {
        let root = temp_health_root("source_metrics");
        fs::create_dir_all(root.join("src")).unwrap();
        let source = r#"
pub fn exported(value: i32) -> i32 {
    if value > 0 { value } else { 0 }
}

fn first(value: i32) -> i32 {
    if value > 10 && value < 20 {
        return value;
    }
    0
}

fn second(input: i32) -> i32 {
    if input > 10 && input < 20 {
        return input;
    }
    0
}
"#;
        fs::write(root.join("src/lib.rs"), source).unwrap();

        let files = vec![file(0, "src/lib.rs")];
        let functions = vec![
            FunctionFact {
                function_id: 0,
                file_id: 0,
                name: "exported".to_string(),
                start_line: 2,
                end_line: 4,
            },
            FunctionFact {
                function_id: 1,
                file_id: 0,
                name: "first".to_string(),
                start_line: 6,
                end_line: 11,
            },
            FunctionFact {
                function_id: 2,
                file_id: 0,
                name: "second".to_string(),
                start_line: 13,
                end_line: 18,
            },
        ];
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: root.clone(),
                file_count: files.len(),
                function_count: functions.len(),
                import_count: 0,
                call_count: 0,
            },
            files,
            functions,
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph: compute_graph_metrics(&[], &[]),
        };
        let health = compute_health(&report);
        fs::remove_dir_all(&root).unwrap();

        assert!(health.metrics.complexity.max_function_complexity >= 3);
        assert!(health
            .metrics
            .complexity
            .duplicate_groups
            .iter()
            .any(|group| group.functions.len() >= 2));
        assert!(health
            .metrics
            .complexity
            .dead_functions
            .iter()
            .all(|function| function.name != "exported"));
        assert_eq!(health.metrics.test_gap.files_without_nearby_tests, 1);
        assert!(health.metrics.test_gap.candidates[0]
            .expected_tests
            .iter()
            .any(|path| path == "tests/lib_test.rs"));
    }

    #[test]
    fn applies_configured_public_api_paths_and_test_roots() {
        let root = temp_health_root("configured_paths");
        fs::create_dir_all(root.join("app")).unwrap();
        fs::create_dir_all(root.join("spec")).unwrap();
        fs::write(
            root.join("app/service.rs"),
            r#"
fn exported_surface() -> i32 {
    1
}
"#,
        )
        .unwrap();
        fs::write(root.join("spec/service_test.rs"), "fn service_test() {}\n").unwrap();

        let files = vec![file(0, "app/service.rs"), file(1, "spec/service_test.rs")];
        let functions = vec![FunctionFact {
            function_id: 0,
            file_id: 0,
            name: "exported_surface".to_string(),
            start_line: 2,
            end_line: 4,
        }];
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: root.clone(),
                file_count: files.len(),
                function_count: functions.len(),
                import_count: 0,
                call_count: 0,
            },
            files,
            functions,
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph: compute_graph_metrics(&[], &[]),
        };
        let mut config = RaysenseConfig::default();
        config.scan.public_api_paths = vec!["app/*".to_string()];
        config.scan.test_roots = vec!["spec".to_string()];

        let health = compute_health_with_config(&report, &config);
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(health.metrics.complexity.public_api_functions, 1);
        assert!(health.metrics.complexity.dead_functions.is_empty());
        assert_eq!(health.metrics.test_gap.test_files, 1);
        assert_eq!(health.metrics.test_gap.files_without_nearby_tests, 0);
    }

    #[test]
    fn normalizes_git_paths_for_scanned_subdirectories() {
        assert_eq!(
            scan_relative_git_path("crates/core/src/lib.rs", "crates/core/"),
            Some("src/lib.rs".to_string())
        );
        assert_eq!(
            scan_relative_git_path("other/src/lib.rs", "crates/core/"),
            None
        );
        assert_eq!(
            scan_relative_git_path("src/lib.rs", ""),
            Some("src/lib.rs".to_string())
        );
    }

    #[test]
    fn computes_call_metrics() {
        let files = vec![file(0, "src/a.rs")];
        let functions = vec![
            function(0, 0, "run"),
            function(1, 0, "load"),
            function(2, 0, "save"),
        ];
        let calls = vec![
            call(0, 0, Some(0), "load"),
            call(1, 0, Some(0), "save"),
            call(2, 0, Some(2), "load"),
        ];
        let call_edges = vec![
            call_edge(0, 0, 0, 1),
            call_edge(1, 1, 0, 2),
            call_edge(2, 2, 2, 1),
        ];
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: functions.len(),
                import_count: 0,
                call_count: calls.len(),
            },
            files,
            functions,
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls,
            call_edges,
            types: Vec::new(),
            graph: compute_graph_metrics(&[], &[]),
        };

        let health = compute_health(&report);

        assert_eq!(health.metrics.calls.total_calls, 3);
        assert_eq!(health.metrics.calls.resolved_edges, 3);
        assert_eq!(health.metrics.calls.max_function_fan_in, 2);
        assert_eq!(health.metrics.calls.max_function_fan_out, 2);
        assert_eq!(health.metrics.calls.top_called_functions[0].name, "load");
        assert_eq!(health.metrics.calls.top_calling_functions[0].name, "run");
    }

    #[test]
    fn reports_call_metric_findings() {
        let files = vec![file(0, "src/a.rs")];
        let functions = vec![function(0, 0, "run"), function(1, 0, "load")];
        let mut calls = Vec::new();
        let mut call_edges = Vec::new();
        for id in 0..250 {
            calls.push(call(id, 0, Some(0), "load"));
            if id < 100 {
                call_edges.push(call_edge(id, id, 0, 1));
            }
        }
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: functions.len(),
                import_count: 0,
                call_count: calls.len(),
            },
            files,
            functions,
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls,
            call_edges,
            types: Vec::new(),
            graph: compute_graph_metrics(&[], &[]),
        };

        let health = compute_health(&report);
        let codes: Vec<&str> = health.rules.iter().map(|rule| rule.code.as_str()).collect();

        assert!(codes.contains(&"low_call_resolution"));
        assert!(codes.contains(&"high_function_fan_out"));
    }

    #[test]
    fn applies_rule_config_thresholds() {
        let files = vec![file(0, "src/a.rs")];
        let functions = vec![function(0, 0, "run"), function(1, 0, "load")];
        let mut calls = Vec::new();
        let mut call_edges = Vec::new();
        for id in 0..250 {
            calls.push(call(id, 0, Some(0), "load"));
            if id < 100 {
                call_edges.push(call_edge(id, id, 0, 1));
            }
        }
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: functions.len(),
                import_count: 0,
                call_count: calls.len(),
            },
            files,
            functions,
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls,
            call_edges,
            types: Vec::new(),
            graph: compute_graph_metrics(&[], &[]),
        };
        let config: RaysenseConfig = toml::from_str(
            r#"
[rules]
low_call_resolution_ratio = 0.3
high_function_fan_in = 500
high_function_fan_out = 500
no_tests_detected = false
"#,
        )
        .unwrap();

        let health = compute_health_with_config(&report, &config);
        let codes: Vec<&str> = health.rules.iter().map(|rule| rule.code.as_str()).collect();

        assert!(!codes.contains(&"low_call_resolution"));
        assert!(!codes.contains(&"high_function_fan_in"));
        assert!(!codes.contains(&"high_function_fan_out"));
        assert!(!codes.contains(&"no_tests_detected"));
    }

    #[test]
    fn applies_minimum_score_gates() {
        let files = vec![file(0, "src/a.rs"), file(1, "src/b.rs")];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 1, Some(0), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };
        let config: RaysenseConfig = toml::from_str(
            r#"
[rules]
min_quality_signal = 9999
min_acyclicity = 0.9
"#,
        )
        .unwrap();

        let health = compute_health_with_config(&report, &config);
        let codes: Vec<&str> = health.rules.iter().map(|rule| rule.code.as_str()).collect();

        assert!(codes.contains(&"min_quality_signal"));
        assert!(codes.contains(&"min_acyclicity"));
    }

    #[test]
    fn applies_hard_size_gates() {
        let mut source = file(0, "src/a.rs");
        source.lines = 120;
        let mut long_function = function(0, 0, "long");
        long_function.end_line = 80;
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: 1,
                function_count: 1,
                import_count: 0,
                call_count: 0,
            },
            files: vec![source],
            functions: vec![long_function],
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph: compute_graph_metrics(&[], &[]),
        };
        let config: RaysenseConfig = toml::from_str(
            r#"
[rules]
max_file_lines = 100
max_function_lines = 50
"#,
        )
        .unwrap();

        let health = compute_health_with_config(&report, &config);
        let codes: Vec<&str> = health.rules.iter().map(|rule| rule.code.as_str()).collect();

        assert!(codes.contains(&"max_file_lines"));
        assert!(codes.contains(&"max_function_lines"));
    }

    #[test]
    fn applies_plugin_threshold_overrides() {
        let mut source = file(0, "src/a.rs");
        source.lines = 120;
        let mut long_function = function(0, 0, "long");
        long_function.end_line = 80;
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: 1,
                function_count: 1,
                import_count: 0,
                call_count: 0,
            },
            files: vec![source],
            functions: vec![long_function],
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph: compute_graph_metrics(&[], &[]),
        };
        let config: RaysenseConfig = toml::from_str(
            r#"
[[scan.plugins]]
name = "rust"
extensions = ["rs"]
max_function_complexity = 0
max_file_lines = 100
max_function_lines = 50

[rules]
max_file_lines = 0
max_function_lines = 0
no_tests_detected = false
"#,
        )
        .unwrap();

        let health = compute_health_with_config(&report, &config);
        let codes: Vec<&str> = health.rules.iter().map(|rule| rule.code.as_str()).collect();

        assert!(codes.contains(&"max_function_complexity"));
        assert!(codes.contains(&"max_file_lines"));
        assert!(codes.contains(&"max_function_lines"));
    }

    #[test]
    fn reports_forbidden_module_edges() {
        let files = vec![file(0, "src/a.rs"), file(1, "test/b.rs")];
        let imports = vec![import(0, 0, Some(1), ImportResolution::Local)];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };
        let config: RaysenseConfig = toml::from_str(
            r#"
[[boundaries.forbidden_edges]]
from = "src"
to = "test"
reason = "runtime code must not depend on tests"
"#,
        )
        .unwrap();

        let health = compute_health_with_config(&report, &config);

        let finding = health
            .rules
            .iter()
            .find(|rule| rule.code == "forbidden_module_edge")
            .expect("forbidden edge rule should be reported");
        assert!(finding
            .message
            .contains("runtime code must not depend on tests"));
    }

    #[test]
    fn caps_upward_layer_violations() {
        let files = vec![
            file(0, "src/infra/db.rs"),
            file(1, "src/api/http.rs"),
            file(2, "src/api/rpc.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 0, Some(2), ImportResolution::Local),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports,
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            graph,
        };
        let config: RaysenseConfig = toml::from_str(
            r#"
[rules]
max_upward_layer_violations = 1

[[boundaries.layers]]
name = "infra"
path = "src/infra/*"
order = 0

[[boundaries.layers]]
name = "api"
path = "src/api/*"
order = 2
"#,
        )
        .unwrap();

        let health = compute_health_with_config(&report, &config);

        assert!(health
            .rules
            .iter()
            .any(|rule| rule.code == "max_upward_layer_violations"));
        assert_eq!(
            health
                .rules
                .iter()
                .filter(|rule| rule.code == "layer_order")
                .count(),
            2
        );
    }

    fn file(file_id: usize, path: &str) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language: Language::Rust,
            language_name: "rust".to_string(),
            module: path.trim_end_matches(".rs").to_string(),
            lines: 1,
            bytes: 1,
            content_hash: String::new(),
            comment_lines: 0,
        }
    }

    fn temp_health_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("raysense-health-{name}-{nanos}"))
    }

    fn import(
        import_id: usize,
        from_file: usize,
        resolved_file: Option<usize>,
        resolution: ImportResolution,
    ) -> ImportFact {
        ImportFact {
            import_id,
            from_file,
            target: String::new(),
            kind: "use".to_string(),
            resolution,
            resolved_file,
        }
    }

    fn function(function_id: usize, file_id: usize, name: &str) -> FunctionFact {
        FunctionFact {
            function_id,
            file_id,
            name: name.to_string(),
            start_line: 1,
            end_line: 1,
        }
    }

    fn call(
        call_id: usize,
        file_id: usize,
        caller_function: Option<usize>,
        target: &str,
    ) -> CallFact {
        CallFact {
            call_id,
            file_id,
            caller_function,
            target: target.to_string(),
            line: 1,
        }
    }

    fn call_edge(
        edge_id: usize,
        call_id: usize,
        caller_function: usize,
        callee_function: usize,
    ) -> CallEdgeFact {
        CallEdgeFact {
            edge_id,
            call_id,
            caller_function,
            callee_function,
        }
    }

    fn complexity_metric(file_id: usize, path: &str, value: usize) -> FunctionComplexityMetric {
        FunctionComplexityMetric {
            function_id: 0,
            file_id,
            path: path.to_string(),
            name: format!("fn_{file_id}"),
            value,
            cognitive_value: value,
        }
    }

    #[test]
    fn temporal_hotspots_rank_by_churn_times_complexity() {
        let mut file_commits: BTreeMap<String, usize> = BTreeMap::new();
        file_commits.insert("src/hot.rs".to_string(), 12);
        file_commits.insert("src/quiet.rs".to_string(), 1);
        file_commits.insert("src/simple.rs".to_string(), 50);
        file_commits.insert("src/orphan.rs".to_string(), 3);

        let complexity = ComplexityMetrics {
            all_functions: vec![
                complexity_metric(0, "src/hot.rs", 4),
                complexity_metric(0, "src/hot.rs", 9),
                complexity_metric(1, "src/quiet.rs", 20),
                complexity_metric(2, "src/simple.rs", 1),
            ],
            ..ComplexityMetrics::default()
        };

        let hotspots = temporal_hotspots(&file_commits, &complexity);

        assert_eq!(hotspots.len(), 3, "orphan.rs has no complexity → dropped");
        assert!(
            hotspots.iter().all(|h| h.path != "src/orphan.rs"),
            "files with no functions must not appear",
        );

        let top = &hotspots[0];
        assert_eq!(top.path, "src/hot.rs");
        assert_eq!(top.commits, 12);
        assert_eq!(
            top.max_complexity, 9,
            "uses max function complexity per file"
        );
        assert_eq!(top.risk_score, 12 * 9);

        let simple = hotspots.iter().find(|h| h.path == "src/simple.rs").unwrap();
        let quiet = hotspots.iter().find(|h| h.path == "src/quiet.rs").unwrap();
        assert_eq!(simple.risk_score, 50);
        assert_eq!(quiet.risk_score, 20);
        assert!(
            hotspots[1].risk_score >= hotspots[2].risk_score,
            "results are sorted by risk_score descending",
        );
    }

    #[test]
    fn file_ages_rank_oldest_first_and_drop_invalid() {
        const DAY: i64 = 86_400;
        let now: i64 = 100 * DAY;
        let mut window: BTreeMap<String, (i64, i64)> = BTreeMap::new();
        window.insert("ancient.rs".to_string(), (10 * DAY, 90 * DAY));
        window.insert("recent.rs".to_string(), (95 * DAY, 99 * DAY));
        window.insert("middle.rs".to_string(), (50 * DAY, 60 * DAY));
        // Future timestamp from clock skew is dropped.
        window.insert("future.rs".to_string(), (110 * DAY, 110 * DAY));
        // Zero timestamp (no data) is dropped.
        window.insert("zero.rs".to_string(), (0, 0));

        let ages = file_ages(&window, now);

        assert_eq!(ages.len(), 3, "future.rs and zero.rs must be skipped");
        assert_eq!(ages[0].path, "ancient.rs");
        assert_eq!(ages[0].age_days, 90);
        assert_eq!(ages[0].last_changed_days, 10);
        assert_eq!(ages[1].path, "middle.rs");
        assert_eq!(ages[2].path, "recent.rs");
        assert_eq!(ages[2].age_days, 5);
    }

    #[test]
    fn file_ages_returns_empty_when_now_is_unknown() {
        let mut window: BTreeMap<String, (i64, i64)> = BTreeMap::new();
        window.insert("a.rs".to_string(), (1, 2));
        assert!(file_ages(&window, 0).is_empty());
    }

    #[test]
    fn change_coupling_ranks_pairs_by_jaccard_above_min_threshold() {
        let mut pair_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
        pair_counts.insert(("a.rs".to_string(), "b.rs".to_string()), 5);
        pair_counts.insert(("a.rs".to_string(), "c.rs".to_string()), 4);
        pair_counts.insert(("b.rs".to_string(), "c.rs".to_string()), 2);
        pair_counts.insert(("d.rs".to_string(), "e.rs".to_string()), 3);

        let mut file_commits: BTreeMap<String, usize> = BTreeMap::new();
        file_commits.insert("a.rs".to_string(), 5);
        file_commits.insert("b.rs".to_string(), 5);
        file_commits.insert("c.rs".to_string(), 6);
        file_commits.insert("d.rs".to_string(), 3);
        file_commits.insert("e.rs".to_string(), 3);

        let pairs = change_coupling(&pair_counts, &file_commits);

        assert_eq!(
            pairs.len(),
            3,
            "the 2-co-commit pair is below MIN_CO_COMMITS"
        );
        assert_eq!(pairs[0].left, "a.rs");
        assert_eq!(pairs[0].right, "b.rs");
        assert!(
            (pairs[0].coupling_strength - 1.0).abs() < 1e-9,
            "always co-changed"
        );
        let de = pairs.iter().find(|p| p.left == "d.rs").unwrap();
        assert!((de.coupling_strength - 1.0).abs() < 1e-9);
        let ac = pairs
            .iter()
            .find(|p| p.left == "a.rs" && p.right == "c.rs")
            .unwrap();
        assert!(ac.coupling_strength < 1.0);
    }

    #[test]
    fn change_coupling_returns_empty_when_no_pair_meets_threshold() {
        let mut pair_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
        pair_counts.insert(("a.rs".to_string(), "b.rs".to_string()), 1);
        let mut file_commits: BTreeMap<String, usize> = BTreeMap::new();
        file_commits.insert("a.rs".to_string(), 1);
        file_commits.insert("b.rs".to_string(), 1);
        let pairs = change_coupling(&pair_counts, &file_commits);
        assert!(pairs.is_empty());
    }

    #[test]
    fn language_override_wins_over_global_for_complexity_limit() {
        let py_file = file(0, "src/util.py");
        let rs_file = file(1, "src/lib.rs");
        let mut config = RaysenseConfig::default();
        config.rules.max_function_complexity = 50; // global ceiling
        config.rules.language_overrides.insert(
            "python".to_string(),
            LanguageRuleOverride {
                max_function_complexity: Some(8),
                ..LanguageRuleOverride::default()
            },
        );
        // Need to set the language_name on the test files since `file()` factory
        // uses Language::Rust by default - make a Python-named one.
        let mut py = py_file;
        py.language_name = "python".to_string();

        assert_eq!(function_complexity_limit(&py, &config), 8);
        assert_eq!(function_complexity_limit(&rs_file, &config), 50);
    }

    #[test]
    fn language_override_falls_through_to_plugin_then_global() {
        let mut file_a = file(0, "src/a.go");
        file_a.language_name = "go".to_string();
        let mut file_b = file(1, "src/b.go");
        file_b.language_name = "go".to_string();
        let mut config = RaysenseConfig::default();
        config.rules.max_file_lines = 1000;
        // Plugin sets a Go-specific limit of 600.
        config.scan.plugins.push(LanguagePluginConfig {
            name: "go".to_string(),
            max_file_lines: Some(600),
            ..LanguagePluginConfig::default()
        });
        // No language_overrides entry → plugin should win.
        assert_eq!(file_line_limit(&file_a, &config), Some(600));
        // Add a language override of 200 → it wins over the plugin.
        config.rules.language_overrides.insert(
            "go".to_string(),
            LanguageRuleOverride {
                max_file_lines: Some(200),
                ..LanguageRuleOverride::default()
            },
        );
        assert_eq!(file_line_limit(&file_b, &config), Some(200));
    }

    #[test]
    fn temporal_hotspots_skip_zero_risk() {
        let mut file_commits: BTreeMap<String, usize> = BTreeMap::new();
        file_commits.insert("src/zero.rs".to_string(), 0);
        file_commits.insert("src/some.rs".to_string(), 4);

        let complexity = ComplexityMetrics {
            all_functions: vec![
                complexity_metric(0, "src/zero.rs", 5),
                complexity_metric(1, "src/some.rs", 0),
            ],
            ..ComplexityMetrics::default()
        };

        let hotspots = temporal_hotspots(&file_commits, &complexity);
        assert!(
            hotspots.is_empty(),
            "either factor being zero means no risk score",
        );
    }
}
