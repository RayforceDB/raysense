use crate::facts::{EntryPointKind, ImportResolution, ScanReport};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RaysenseConfig {
    pub rules: RuleConfig,
    pub boundaries: BoundaryConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    pub high_file_fan_in: usize,
    pub large_file_lines: usize,
    pub max_large_file_findings: usize,
    pub low_call_resolution_min_calls: usize,
    pub low_call_resolution_ratio: f64,
    pub high_function_fan_in: usize,
    pub high_function_fan_out: usize,
    pub max_call_hotspot_findings: usize,
    pub no_tests_detected: bool,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            high_file_fan_in: 50,
            large_file_lines: 500,
            max_large_file_findings: 20,
            low_call_resolution_min_calls: 100,
            low_call_resolution_ratio: 0.5,
            high_function_fan_in: 200,
            high_function_fan_out: 100,
            max_call_hotspot_findings: 5,
            no_tests_detected: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BoundaryConfig {
    pub forbidden_edges: Vec<ForbiddenEdgeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForbiddenEdgeConfig {
    pub from: String,
    pub to: String,
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
    pub coverage_score: u8,
    pub structural_score: u8,
    pub metrics: MetricsSummary,
    pub resolution: ResolutionBreakdown,
    pub hotspots: Vec<FileHotspot>,
    pub rules: Vec<RuleFinding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub coupling: CouplingMetrics,
    pub calls: CallMetrics,
    pub size: SizeMetrics,
    pub entry_points: EntryPointMetrics,
    pub test_gap: TestGapMetrics,
    pub dsm: DsmMetrics,
    pub evolution: EvolutionMetrics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CouplingMetrics {
    pub local_edges: usize,
    pub cross_module_edges: usize,
    pub cross_module_ratio: f64,
    pub max_fan_in: usize,
    pub max_fan_out: usize,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionFileMetric {
    pub path: String,
    pub commits: usize,
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
    let metrics = metrics(report, &hotspots);
    let rules = rules(report, &hotspots, &metrics, config);

    HealthSummary {
        score: health_score(report, &resolution, &rules),
        coverage_score: coverage_score(report, &resolution),
        structural_score: structural_score(report, &rules),
        metrics,
        resolution,
        hotspots,
        rules,
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

fn health_score(
    report: &ScanReport,
    resolution: &ResolutionBreakdown,
    rules: &[RuleFinding],
) -> u8 {
    coverage_score(report, resolution).saturating_add(structural_score(report, rules)) / 2
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

fn metrics(report: &ScanReport, hotspots: &[FileHotspot]) -> MetricsSummary {
    MetricsSummary {
        coupling: coupling_metrics(report, hotspots),
        calls: call_metrics(report),
        size: size_metrics(report),
        entry_points: entry_point_metrics(report),
        test_gap: test_gap_metrics(report),
        dsm: dsm_metrics(report),
        evolution: evolution_metrics(report),
    }
}

fn coupling_metrics(report: &ScanReport, hotspots: &[FileHotspot]) -> CouplingMetrics {
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
            let Some(from_file) = report.files.get(import.from_file) else {
                return false;
            };
            let Some(to_file) = report.files.get(to_file_id) else {
                return false;
            };
            top_module(&from_file.module) != top_module(&to_file.module)
        })
        .count();

    CouplingMetrics {
        local_edges,
        cross_module_edges,
        cross_module_ratio: ratio(cross_module_edges, local_edges),
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

    SizeMetrics {
        max_file_lines,
        max_function_lines,
        large_files: report.files.iter().filter(|file| file.lines >= 500).count(),
        long_functions: report
            .functions
            .iter()
            .filter(|function| function.end_line.saturating_sub(function.start_line) + 1 >= 80)
            .count(),
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

fn test_gap_metrics(report: &ScanReport) -> TestGapMetrics {
    let test_modules: HashSet<String> = report
        .files
        .iter()
        .filter(|file| is_test_path(&file.path.to_string_lossy()))
        .map(|file| normalized_test_subject(&file.module))
        .collect();

    let mut production_files = 0;
    let mut files_without_nearby_tests = 0;

    for file in &report.files {
        let path = file.path.to_string_lossy();
        if is_test_path(&path) {
            continue;
        }
        production_files += 1;
        if !test_modules.contains(&normalized_test_subject(&file.module)) {
            files_without_nearby_tests += 1;
        }
    }

    TestGapMetrics {
        production_files,
        test_files: report
            .files
            .iter()
            .filter(|file| is_test_path(&file.path.to_string_lossy()))
            .count(),
        files_without_nearby_tests,
    }
}

fn dsm_metrics(report: &ScanReport) -> DsmMetrics {
    let mut edges: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut modules = HashSet::new();

    for file in &report.files {
        modules.insert(top_module(&file.module).to_string());
    }

    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from_module = top_module(&from_file.module).to_string();
        let to_module = top_module(&to_file.module).to_string();
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

fn evolution_metrics(report: &ScanReport) -> EvolutionMetrics {
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
        ["log", "-n", "500", "--format=commit:%H", "--name-only"],
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
    let mut file_commits: BTreeMap<String, usize> = BTreeMap::new();
    let mut commit_files = HashSet::new();

    for line in log.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("commit:") {
            flush_commit_files(&mut file_commits, &mut commit_files);
            commits_sampled += 1;
            continue;
        }

        if let Some(path) = scan_relative_git_path(line, &prefix) {
            if scanned_files.contains(&path) {
                commit_files.insert(path);
            }
        }
    }
    flush_commit_files(&mut file_commits, &mut commit_files);

    let mut top_changed_files: Vec<EvolutionFileMetric> = file_commits
        .iter()
        .map(|(path, commits)| EvolutionFileMetric {
            path: path.clone(),
            commits: *commits,
        })
        .collect();
    top_changed_files.sort_by(|a, b| b.commits.cmp(&a.commits).then_with(|| a.path.cmp(&b.path)));
    top_changed_files.truncate(10);

    EvolutionMetrics {
        available: true,
        reason: String::new(),
        commits_sampled,
        changed_files: file_commits.len(),
        top_changed_files,
    }
}

fn flush_commit_files(
    file_commits: &mut BTreeMap<String, usize>,
    commit_files: &mut HashSet<String>,
) {
    for path in commit_files.drain() {
        *file_commits.entry(path).or_default() += 1;
    }
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

    for hotspot in hotspots {
        if hotspot.fan_in >= rules.high_file_fan_in {
            findings.push(RuleFinding {
                severity: RuleSeverity::Warning,
                code: "high_fan_in".to_string(),
                path: hotspot.path.clone(),
                message: format!("{} incoming dependency edges", hotspot.fan_in),
            });
        }
    }

    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
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
        .filter(|file| file.lines >= rules.large_file_lines)
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

    for function in metrics
        .calls
        .top_called_functions
        .iter()
        .filter(|function| function.calls >= rules.high_function_fan_in)
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
        .filter(|function| function.calls >= rules.high_function_fan_out)
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

    findings
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
    let mut edges: BTreeMap<(String, String), usize> = BTreeMap::new();

    for import in &report.imports {
        let Some(to_file_id) = import.resolved_file else {
            continue;
        };
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_file_id) else {
            continue;
        };
        let from_module = top_module(&from_file.module);
        let to_module = top_module(&to_file.module);
        if forbidden.contains(&(from_module, to_module)) {
            *edges
                .entry((from_module.to_string(), to_module.to_string()))
                .or_default() += 1;
        }
    }

    edges
        .into_iter()
        .map(|((from_module, to_module), count)| RuleFinding {
            severity: RuleSeverity::Warning,
            code: "forbidden_module_edge".to_string(),
            path: report.snapshot.root.to_string_lossy().into_owned(),
            message: format!("{from_module} -> {to_module} has {count} dependency edges"),
        })
        .collect()
}

fn top_module(module: &str) -> &str {
    module.split(['.', '/']).next().unwrap_or(module)
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    (numerator as f64 / denominator as f64 * 1000.0).round() / 1000.0
}

fn normalized_test_subject(module: &str) -> String {
    module
        .replace(".tests.", ".")
        .replace(".test.", ".")
        .replace("_tests", "")
        .replace("_test", "")
        .trim_start_matches("tests.")
        .trim_start_matches("test.")
        .to_string()
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
    use std::path::PathBuf;

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
            graph,
        };
        let config: RaysenseConfig = toml::from_str(
            r#"
[[boundaries.forbidden_edges]]
from = "src"
to = "test"
"#,
        )
        .unwrap();

        let health = compute_health_with_config(&report, &config);

        assert!(health
            .rules
            .iter()
            .any(|rule| rule.code == "forbidden_module_edge"));
    }

    fn file(file_id: usize, path: &str) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language: Language::Rust,
            module: path.trim_end_matches(".rs").to_string(),
            lines: 1,
            bytes: 1,
            content_hash: String::new(),
        }
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
}
