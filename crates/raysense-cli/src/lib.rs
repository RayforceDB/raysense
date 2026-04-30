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

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use raysense_core::{
    build_baseline, compute_health_with_config, diff_baselines, scan_path_with_config,
    BaselineDiff, ImportResolution, ProjectBaseline, RaysenseConfig,
};
use raysense_memory::{
    BaselineFilterMode, BaselineFilterOp, BaselineSortDirection, BaselineTableFilter,
    BaselineTableQuery, BaselineTableSort,
};
use serde_json::Value;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

mod mcp;

#[derive(Debug, Parser)]
#[command(name = "raysense")]
#[command(about = "Local architectural telemetry for AI coding agents")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Observe {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        memory: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Health {
        path: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Edges {
        path: PathBuf,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    RayforceVersion,
    Memory {
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Mcp,
}

#[derive(Debug, Subcommand)]
enum BaselineCommand {
    Save {
        path: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Diff {
        path: PathBuf,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Tables {
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Table {
        table: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        columns: Option<String>,
        #[arg(long = "filter")]
        filters: Vec<String>,
        #[arg(long, default_value = "all", value_parser = ["all", "any"])]
        filter_mode: String,
        #[arg(long)]
        sort: Vec<String>,
        #[arg(long)]
        desc: bool,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
}

pub fn run() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Observe {
            path,
            json,
            memory,
            config,
        } => {
            let config = config_for_root(&path, config.as_deref())?;
            let report = scan_path_with_config(path, &config)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if memory {
                let memory = raysense_memory::RayMemory::from_report_with_config(&report, &config)?;
                print_memory_summary(&memory.summary());
            } else {
                print_summary(&report, &config);
            }
        }
        Command::Health { path, json, config } => {
            let config = config_for_root(&path, config.as_deref())?;
            let report = scan_path_with_config(path, &config)?;
            let health = compute_health_with_config(&report, &config);
            if json {
                println!("{}", serde_json::to_string_pretty(&health)?);
            } else {
                print_health(&report, &health);
            }
        }
        Command::Edges { path, all, config } => {
            let config = config_for_root(&path, config.as_deref())?;
            let report = scan_path_with_config(path, &config)?;
            print_edges(&report, all)?;
        }
        Command::RayforceVersion => {
            println!("{}", rayforce_sys::version_string());
        }
        Command::Memory { path, config } => {
            let config = config_for_root(&path, config.as_deref())?;
            let report = scan_path_with_config(path, &config)?;
            let memory = raysense_memory::RayMemory::from_report_with_config(&report, &config)?;
            print_memory_summary(&memory.summary());
        }
        Command::Baseline { command } => match command {
            BaselineCommand::Save {
                path,
                output,
                config,
            } => {
                let output = output.unwrap_or_else(|| path.join(".raysense/baseline"));
                save_baseline(&path, &output, config.as_deref())?;
                println!("baseline {}", output.display());
            }
            BaselineCommand::Diff {
                path,
                baseline,
                config,
                json,
            } => {
                let baseline = baseline.unwrap_or_else(|| path.join(".raysense/baseline"));
                let diff = diff_baseline(&path, &baseline, config.as_deref())?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&diff)?);
                } else {
                    print_baseline_diff(&diff);
                }
            }
            BaselineCommand::Tables { baseline, json } => {
                let baseline = baseline.unwrap_or_else(default_baseline_dir);
                let tables_dir = baseline.join("tables");
                let tables =
                    raysense_memory::list_baseline_tables(&tables_dir).with_context(|| {
                        format!("failed to list baseline tables {}", tables_dir.display())
                    })?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&tables)?);
                } else {
                    print_baseline_tables(&tables);
                }
            }
            BaselineCommand::Table {
                table,
                baseline,
                columns,
                filters,
                filter_mode,
                sort,
                desc,
                offset,
                limit,
                json,
            } => {
                let baseline = baseline.unwrap_or_else(default_baseline_dir);
                let tables_dir = baseline.join("tables");
                let query = BaselineTableQuery {
                    offset,
                    limit,
                    columns: parse_columns(columns.as_deref())?,
                    filters: parse_filters(&filters)?,
                    filter_mode: parse_filter_mode(&filter_mode)?,
                    sort: parse_sort(&sort, desc)?,
                };
                let rows = raysense_memory::query_baseline_table(&tables_dir, &table, query)
                    .with_context(|| {
                        format!("failed to read baseline table {}", tables_dir.display())
                    })?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                } else {
                    print_baseline_rows(&rows);
                }
            }
        },
        Command::Mcp => {
            mcp::run()?;
        }
    }

    Ok(())
}

fn config_for_root(
    root: &std::path::Path,
    explicit: Option<&std::path::Path>,
) -> Result<RaysenseConfig> {
    if let Some(path) = explicit {
        return RaysenseConfig::from_path(path)
            .with_context(|| format!("failed to load config {}", path.display()));
    }

    let default_path = root.join(".raysense.toml");
    if default_path.exists() {
        return RaysenseConfig::from_path(&default_path)
            .with_context(|| format!("failed to load config {}", default_path.display()));
    }

    Ok(RaysenseConfig::default())
}

fn save_baseline(root: &Path, output: &Path, config_path: Option<&Path>) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let baseline = build_baseline(&report, &health);
    let memory = raysense_memory::RayMemory::from_report_with_config(&report, &config)?;
    let tables_dir = output.join("tables");

    fs::create_dir_all(output)
        .with_context(|| format!("failed to create baseline dir {}", output.display()))?;
    fs::write(
        output.join("manifest.json"),
        serde_json::to_string_pretty(&baseline)?,
    )
    .with_context(|| format!("failed to write baseline manifest {}", output.display()))?;
    if tables_dir.exists() {
        fs::remove_dir_all(&tables_dir)
            .with_context(|| format!("failed to clear baseline tables {}", tables_dir.display()))?;
    }
    memory
        .save_splayed(&tables_dir)
        .with_context(|| format!("failed to write baseline tables {}", tables_dir.display()))?;

    Ok(())
}

fn diff_baseline(
    root: &Path,
    baseline_dir: &Path,
    config_path: Option<&Path>,
) -> Result<BaselineDiff> {
    let before: ProjectBaseline = serde_json::from_str(
        &fs::read_to_string(baseline_dir.join("manifest.json")).with_context(|| {
            format!(
                "failed to read baseline manifest {}",
                baseline_dir.join("manifest.json").display()
            )
        })?,
    )?;
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let after = build_baseline(&report, &health);
    Ok(diff_baselines(&before, &after))
}

fn default_baseline_dir() -> PathBuf {
    PathBuf::from(".raysense/baseline")
}

fn parse_columns(columns: Option<&str>) -> Result<Option<Vec<String>>> {
    let Some(columns) = columns else {
        return Ok(None);
    };
    let parsed: Vec<String> = columns
        .split(',')
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .map(str::to_string)
        .collect();
    if parsed.is_empty() {
        Err(anyhow!("columns must include at least one column name"))
    } else {
        Ok(Some(parsed))
    }
}

fn parse_filters(filters: &[String]) -> Result<Vec<BaselineTableFilter>> {
    filters
        .iter()
        .map(|filter| {
            let mut parts = filter.splitn(3, ':');
            let column = parts
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("filter must use column:op:value"))?;
            let op = parts
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("filter must use column:op:value"))?;
            let value = parts
                .next()
                .ok_or_else(|| anyhow!("filter must use column:op:value"))?;
            Ok(BaselineTableFilter {
                column: column.to_string(),
                op: parse_filter_op(op)?,
                value: parse_filter_value(value),
            })
        })
        .collect()
}

fn parse_filter_op(op: &str) -> Result<BaselineFilterOp> {
    match op {
        "eq" => Ok(BaselineFilterOp::Eq),
        "ne" => Ok(BaselineFilterOp::Ne),
        "in" => Ok(BaselineFilterOp::In),
        "not_in" => Ok(BaselineFilterOp::NotIn),
        "contains" => Ok(BaselineFilterOp::Contains),
        "starts_with" => Ok(BaselineFilterOp::StartsWith),
        "ends_with" => Ok(BaselineFilterOp::EndsWith),
        "regex" => Ok(BaselineFilterOp::Regex),
        "not_regex" => Ok(BaselineFilterOp::NotRegex),
        "gt" => Ok(BaselineFilterOp::Gt),
        "gte" => Ok(BaselineFilterOp::Gte),
        "lt" => Ok(BaselineFilterOp::Lt),
        "lte" => Ok(BaselineFilterOp::Lte),
        _ => Err(anyhow!("unsupported filter op {op}")),
    }
}

fn parse_filter_mode(mode: &str) -> Result<BaselineFilterMode> {
    match mode {
        "all" => Ok(BaselineFilterMode::All),
        "any" => Ok(BaselineFilterMode::Any),
        _ => Err(anyhow!("unsupported filter mode {mode}")),
    }
}

fn parse_filter_value(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()))
}

fn parse_sort(sorts: &[String], desc: bool) -> Result<Vec<BaselineTableSort>> {
    sorts
        .iter()
        .map(|sort| {
            let (column, direction) = parse_sort_spec(sort, desc)?;
            Ok(BaselineTableSort { column, direction })
        })
        .collect()
}

fn parse_sort_spec(sort: &str, desc: bool) -> Result<(String, BaselineSortDirection)> {
    let (column, explicit_direction) = sort
        .split_once(':')
        .map_or((sort, None), |(column, direction)| {
            (column, Some(direction))
        });
    if column.is_empty() {
        return Err(anyhow!("sort column must not be empty"));
    }
    let direction = match explicit_direction {
        Some("asc") => BaselineSortDirection::Asc,
        Some("desc") => BaselineSortDirection::Desc,
        Some(direction) => return Err(anyhow!("unsupported sort direction {direction}")),
        None if desc => BaselineSortDirection::Desc,
        None => BaselineSortDirection::Asc,
    };
    Ok((column.to_string(), direction))
}

fn print_memory_summary(summary: &raysense_memory::MemorySummary) {
    println!(
        "files rows={} cols={}",
        summary.files.rows, summary.files.columns
    );
    println!(
        "functions rows={} cols={}",
        summary.functions.rows, summary.functions.columns
    );
    println!(
        "entry_points rows={} cols={}",
        summary.entry_points.rows, summary.entry_points.columns
    );
    println!(
        "imports rows={} cols={}",
        summary.imports.rows, summary.imports.columns
    );
    println!(
        "calls rows={} cols={}",
        summary.calls.rows, summary.calls.columns
    );
    println!(
        "call_edges rows={} cols={}",
        summary.call_edges.rows, summary.call_edges.columns
    );
    println!(
        "health rows={} cols={}",
        summary.health.rows, summary.health.columns
    );
    println!(
        "hotspots rows={} cols={}",
        summary.hotspots.rows, summary.hotspots.columns
    );
    println!(
        "rules rows={} cols={}",
        summary.rules.rows, summary.rules.columns
    );
    println!(
        "module_edges rows={} cols={}",
        summary.module_edges.rows, summary.module_edges.columns
    );
    println!(
        "changed_files rows={} cols={}",
        summary.changed_files.rows, summary.changed_files.columns
    );
}

fn print_baseline_tables(tables: &[raysense_memory::BaselineTableInfo]) {
    println!("name\trows\tcolumns");
    for table in tables {
        println!("{}\t{}\t{}", table.name, table.rows, table.columns);
    }
}

fn print_baseline_rows(rows: &raysense_memory::BaselineTableRows) {
    println!(
        "table {} rows={} matched={} offset={} limit={}",
        rows.name, rows.total_rows, rows.matched_rows, rows.offset, rows.limit
    );
    println!("{}", rows.columns.join("\t"));
    for row in &rows.rows {
        let values = rows
            .columns
            .iter()
            .map(|column| display_cell(row.get(column).unwrap_or(&Value::Null)))
            .collect::<Vec<_>>();
        println!("{}", values.join("\t"));
    }
}

fn display_cell(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn print_baseline_diff(diff: &BaselineDiff) {
    println!("score_delta {}", diff.score_delta);
    println!("coverage_score_delta {}", diff.coverage_score_delta);
    println!("structural_score_delta {}", diff.structural_score_delta);
    println!(
        "facts_delta files={} functions={} imports={} calls={} call_edges={}",
        diff.file_count_delta,
        diff.function_count_delta,
        diff.import_count_delta,
        diff.call_count_delta,
        diff.call_edge_count_delta
    );
    println!(
        "rules added={} removed={}",
        diff.added_rules.len(),
        diff.removed_rules.len()
    );
    println!(
        "hotspots added={} removed={}",
        diff.added_hotspots.len(),
        diff.removed_hotspots.len()
    );
    println!(
        "module_edges added={} removed={} changed={}",
        diff.added_module_edges.len(),
        diff.removed_module_edges.len(),
        diff.changed_module_edges.len()
    );

    if !diff.added_rules.is_empty() {
        println!("added_rules");
        for rule in &diff.added_rules {
            println!(
                "  {:?} {} {} - {}",
                rule.severity, rule.code, rule.path, rule.message
            );
        }
    }

    if !diff.changed_module_edges.is_empty() {
        println!("changed_module_edges");
        for edge in &diff.changed_module_edges {
            println!(
                "  {} -> {} before={} after={} delta={}",
                edge.from_module, edge.to_module, edge.before, edge.after, edge.delta
            );
        }
    }
}

fn print_summary(report: &raysense_core::ScanReport, config: &RaysenseConfig) {
    let health = compute_health_with_config(report, config);
    println!("snapshot {}", report.snapshot.snapshot_id);
    println!("root {}", report.snapshot.root.display());
    println!("score {}", health.score);
    println!("coverage_score {}", health.coverage_score);
    println!("structural_score {}", health.structural_score);
    println!("files {}", report.snapshot.file_count);
    println!("functions {}", report.snapshot.function_count);
    println!("calls {}", report.snapshot.call_count);
    println!("call_edges {}", report.call_edges.len());
    println!(
        "entry_points total={} binaries={} examples={} tests={}",
        report.entry_points.len(),
        health.metrics.entry_points.binaries,
        health.metrics.entry_points.examples,
        health.metrics.entry_points.tests
    );
    println!("imports {}", report.snapshot.import_count);
    println!("local_imports {}", health.resolution.local);
    println!("external_imports {}", health.resolution.external);
    println!("system_imports {}", health.resolution.system);
    println!("unresolved_imports {}", health.resolution.unresolved);
    println!("resolved_edges {}", report.graph.resolved_edge_count);
    println!("cycles {}", report.graph.cycle_count);
    println!("max_fan_in {}", report.graph.max_fan_in);
    println!("max_fan_out {}", report.graph.max_fan_out);
}

fn print_health(report: &raysense_core::ScanReport, health: &raysense_core::HealthSummary) {
    println!("score {}", health.score);
    println!("coverage_score {}", health.coverage_score);
    println!("structural_score {}", health.structural_score);
    println!("root {}", report.snapshot.root.display());
    println!(
        "facts files={} functions={} calls={} call_edges={} imports={}",
        report.snapshot.file_count,
        report.snapshot.function_count,
        report.snapshot.call_count,
        report.call_edges.len(),
        report.snapshot.import_count
    );
    println!(
        "entry_points total={} binaries={} examples={} tests={}",
        report.entry_points.len(),
        health.metrics.entry_points.binaries,
        health.metrics.entry_points.examples,
        health.metrics.entry_points.tests
    );
    println!(
        "imports local={} external={} system={} unresolved={}",
        health.resolution.local,
        health.resolution.external,
        health.resolution.system,
        health.resolution.unresolved
    );
    println!(
        "graph resolved_edges={} cycles={} max_fan_in={} max_fan_out={}",
        report.graph.resolved_edge_count,
        report.graph.cycle_count,
        report.graph.max_fan_in,
        report.graph.max_fan_out
    );
    println!(
        "coupling local_edges={} cross_module_edges={} cross_module_ratio={:.3}",
        health.metrics.coupling.local_edges,
        health.metrics.coupling.cross_module_edges,
        health.metrics.coupling.cross_module_ratio
    );
    println!(
        "calls total={} resolved_edges={} resolution_ratio={:.3} max_function_fan_in={} max_function_fan_out={}",
        health.metrics.calls.total_calls,
        health.metrics.calls.resolved_edges,
        health.metrics.calls.resolution_ratio,
        health.metrics.calls.max_function_fan_in,
        health.metrics.calls.max_function_fan_out
    );
    println!(
        "size max_file_lines={} max_function_lines={} large_files={} long_functions={}",
        health.metrics.size.max_file_lines,
        health.metrics.size.max_function_lines,
        health.metrics.size.large_files,
        health.metrics.size.long_functions
    );
    println!(
        "test_gap production_files={} test_files={} files_without_nearby_tests={}",
        health.metrics.test_gap.production_files,
        health.metrics.test_gap.test_files,
        health.metrics.test_gap.files_without_nearby_tests
    );
    println!(
        "dsm modules={} module_edges={}",
        health.metrics.dsm.module_count, health.metrics.dsm.module_edges
    );
    if health.metrics.evolution.available {
        println!(
            "evolution available=true commits_sampled={} changed_files={}",
            health.metrics.evolution.commits_sampled, health.metrics.evolution.changed_files
        );
    } else {
        println!(
            "evolution available=false reason={}",
            health.metrics.evolution.reason
        );
    }

    if !health.metrics.evolution.top_changed_files.is_empty() {
        println!("changed_files");
        for file in &health.metrics.evolution.top_changed_files {
            println!("  commits={} {}", file.commits, file.path);
        }
    }

    if !health.metrics.calls.top_called_functions.is_empty() {
        println!("top_called_functions");
        for function in &health.metrics.calls.top_called_functions {
            println!(
                "  calls={} {}:{}",
                function.calls, function.path, function.name
            );
        }
    }

    if !health.metrics.calls.top_calling_functions.is_empty() {
        println!("top_calling_functions");
        for function in &health.metrics.calls.top_calling_functions {
            println!(
                "  calls={} {}:{}",
                function.calls, function.path, function.name
            );
        }
    }

    if !health.metrics.dsm.top_module_edges.is_empty() {
        println!("module_edges");
        for edge in &health.metrics.dsm.top_module_edges {
            println!(
                "  {} -> {} edges={}",
                edge.from_module, edge.to_module, edge.edges
            );
        }
    }

    if !health.hotspots.is_empty() {
        println!("hotspots");
        for hotspot in &health.hotspots {
            println!(
                "  fan_in={} fan_out={} {}",
                hotspot.fan_in, hotspot.fan_out, hotspot.path
            );
        }
    }

    if !health.rules.is_empty() {
        println!("rules");
        for rule in &health.rules {
            println!(
                "  {:?} {} {} - {}",
                rule.severity, rule.code, rule.path, rule.message
            );
        }
    }
}

fn print_edges(report: &raysense_core::ScanReport, all: bool) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    for import in &report.imports {
        if !all && import.resolution != ImportResolution::Local {
            continue;
        }

        let from = report
            .files
            .get(import.from_file)
            .map(|file| file.path.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("#{}", import.from_file));
        let to = import
            .resolved_file
            .and_then(|file_id| report.files.get(file_id))
            .map(|file| file.path.to_string_lossy().into_owned())
            .unwrap_or_else(|| import.target.clone());

        if let Err(err) = writeln!(
            stdout,
            "{:?} {} -> {} ({})",
            import.resolution, from, to, import.kind
        ) {
            if err.kind() == io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(err);
        }
    }

    Ok(())
}
