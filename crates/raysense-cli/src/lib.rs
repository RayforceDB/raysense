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

#![recursion_limit = "256"]

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
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    Check {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        sarif: Option<PathBuf>,
    },
    Gate {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        save: bool,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Watch {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = 2)]
        interval: u64,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Visualize {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        watch: bool,
        #[arg(long, default_value_t = 2)]
        interval: u64,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Trend {
        #[command(subcommand)]
        command: TrendCommand,
    },
    Remediate {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    WhatIf {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long = "ignore")]
        ignore_paths: Vec<String>,
        #[arg(long = "generated")]
        generated_paths: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Mcp,
}

#[derive(Debug, Subcommand)]
enum PluginCommand {
    List {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Add {
        name: String,
        extensions: Vec<String>,
        #[arg(long = "file-name")]
        file_names: Vec<String>,
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    AddStandard {
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Remove {
        name: String,
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Validate {
        dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Scaffold {
        name: String,
        extension: String,
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
    Init {
        name: String,
        extension: String,
        #[arg(long, default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    List,
    Init {
        preset: String,
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum TrendCommand {
    Record {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Show {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
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
        Command::Check {
            path,
            config,
            json,
            sarif,
        } => {
            let exit = check_project(&path, config.as_deref(), json, sarif.as_deref())?;
            process::exit(exit);
        }
        Command::Gate {
            path,
            save,
            baseline,
            config,
            json,
        } => {
            let exit = gate_project(&path, baseline, config.as_deref(), save, json)?;
            process::exit(exit);
        }
        Command::Watch {
            path,
            interval,
            config,
        } => watch_project(&path, config.as_deref(), interval)?,
        Command::Visualize {
            path,
            output,
            watch,
            interval,
            config,
        } => visualize_project(&path, output, config.as_deref(), watch, interval)?,
        Command::Plugin { command } => match command {
            PluginCommand::List { path, config } => list_plugins(&path, config.as_deref())?,
            PluginCommand::Add {
                name,
                extensions,
                file_names,
                path,
                config,
            } => add_plugin(&path, config.as_deref(), &name, extensions, file_names)?,
            PluginCommand::AddStandard { path, config } => {
                add_standard_plugins(&path, config.as_deref())?
            }
            PluginCommand::Remove { name, path, config } => {
                remove_plugin(&path, config.as_deref(), &name)?
            }
            PluginCommand::Validate { dir, json } => {
                let validation = validate_plugin_dir(&dir)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&validation)?);
                } else {
                    print_plugin_validation(&validation);
                }
                if !validation["valid"].as_bool().unwrap_or(false) {
                    return Err(anyhow!("plugin validation failed"));
                }
            }
            PluginCommand::Scaffold {
                name,
                extension,
                path,
            } => {
                let output = scaffold_plugin(&path, &name, &extension)?;
                println!("plugin_scaffold {} {}", name, output.display());
            }
            PluginCommand::Init {
                name,
                extension,
                path,
                config,
            } => add_plugin(&path, config.as_deref(), &name, vec![extension], Vec::new())?,
        },
        Command::Policy { command } => match command {
            PolicyCommand::List => list_policies(),
            PolicyCommand::Init {
                preset,
                path,
                config,
            } => init_policy(&path, config.as_deref(), &preset)?,
        },
        Command::Trend { command } => match command {
            TrendCommand::Record { path, config } => record_trend(&path, config.as_deref())?,
            TrendCommand::Show { path, config, json } => {
                show_trend(&path, config.as_deref(), json)?
            }
        },
        Command::Remediate { path, config, json } => {
            print_remediations(&path, config.as_deref(), json)?
        }
        Command::WhatIf {
            path,
            config,
            ignore_paths,
            generated_paths,
            json,
        } => print_what_if(
            &path,
            config.as_deref(),
            &ignore_paths,
            &generated_paths,
            json,
        )?,
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

fn check_project(
    root: &Path,
    config_path: Option<&Path>,
    json: bool,
    sarif: Option<&Path>,
) -> Result<i32> {
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    if let Some(path) = sarif {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(
            path,
            serde_json::to_string_pretty(&sarif_report(&report, &health))?,
        )
        .with_context(|| format!("failed to write {}", path.display()))?;
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&health)?);
    } else {
        print_health(&report, &health);
    }
    let has_errors = health
        .rules
        .iter()
        .any(|rule| matches!(rule.severity, raysense_core::RuleSeverity::Error));
    Ok(if has_errors { 1 } else { 0 })
}

fn sarif_report(
    report: &raysense_core::ScanReport,
    health: &raysense_core::HealthSummary,
) -> Value {
    let mut seen_rules = BTreeSet::new();
    let rules = health
        .rules
        .iter()
        .filter(|rule| seen_rules.insert(rule.code.clone()))
        .map(|rule| {
            json!({
                "id": rule.code,
                "name": rule.code,
                "shortDescription": {
                    "text": rule.code
                },
                "fullDescription": {
                    "text": rule.message
                },
                "defaultConfiguration": {
                    "level": sarif_level(rule.severity)
                }
            })
        })
        .collect::<Vec<_>>();
    let results = health
        .rules
        .iter()
        .map(|rule| {
            json!({
                "ruleId": rule.code,
                "level": sarif_level(rule.severity),
                "message": {
                    "text": rule.message
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": sarif_uri(&report.snapshot.root, &rule.path)
                            },
                            "region": {
                                "startLine": 1
                            }
                        }
                    }
                ]
            })
        })
        .collect::<Vec<_>>();

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "raysense",
                        "informationUri": "https://github.com/RayforceDB/raysense",
                        "rules": rules
                    }
                },
                "properties": {
                    "snapshot_id": report.snapshot.snapshot_id,
                    "quality_signal": health.quality_signal,
                    "score": health.score
                },
                "results": results
            }
        ]
    })
}

fn sarif_level(severity: raysense_core::RuleSeverity) -> &'static str {
    match severity {
        raysense_core::RuleSeverity::Error => "error",
        raysense_core::RuleSeverity::Warning => "warning",
        raysense_core::RuleSeverity::Info => "note",
    }
}

fn sarif_uri(root: &Path, path: &str) -> String {
    let path = Path::new(path);
    let relative = path.strip_prefix(root).unwrap_or(path);
    if relative.as_os_str().is_empty() {
        ".".to_string()
    } else {
        relative.to_string_lossy().replace('\\', "/")
    }
}

fn gate_project(
    root: &Path,
    baseline: Option<PathBuf>,
    config_path: Option<&Path>,
    save: bool,
    json: bool,
) -> Result<i32> {
    let baseline = baseline.unwrap_or_else(|| root.join(".raysense/baseline"));
    if save {
        save_baseline(root, &baseline, config_path)?;
        println!("baseline {}", baseline.display());
        return Ok(0);
    }
    let diff = diff_baseline(root, &baseline, config_path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&diff)?);
    } else {
        print_baseline_diff(&diff);
    }
    Ok(if diff.score_delta < 0 || !diff.added_rules.is_empty() {
        1
    } else {
        0
    })
}

fn watch_project(root: &Path, config_path: Option<&Path>, interval: u64) -> Result<()> {
    let mut last_snapshot = String::new();
    loop {
        let config = config_for_root(root, config_path)?;
        let report = scan_path_with_config(root, &config)?;
        let health = compute_health_with_config(&report, &config);
        if report.snapshot.snapshot_id != last_snapshot {
            println!(
                "snapshot {} quality_signal={} score={} files={} rules={}",
                report.snapshot.snapshot_id,
                health.quality_signal,
                health.score,
                report.snapshot.file_count,
                health.rules.len()
            );
            last_snapshot = report.snapshot.snapshot_id;
        }
        thread::sleep(Duration::from_secs(interval.max(1)));
    }
}

fn visualize_project(
    root: &Path,
    output: Option<PathBuf>,
    config_path: Option<&Path>,
    watch: bool,
    interval: u64,
) -> Result<()> {
    let output = output.unwrap_or_else(|| root.join(".raysense/visualization.html"));
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    loop {
        let config = config_for_root(root, config_path)?;
        let report = scan_path_with_config(root, &config)?;
        let health = compute_health_with_config(&report, &config);
        fs::write(&output, visualization_html(&report, &health))
            .with_context(|| format!("failed to write {}", output.display()))?;
        println!(
            "visualization {} snapshot={} quality_signal={}",
            output.display(),
            report.snapshot.snapshot_id,
            health.quality_signal
        );
        if !watch {
            break;
        }
        thread::sleep(Duration::from_secs(interval.max(1)));
    }
    Ok(())
}

fn visualization_html(
    report: &raysense_core::ScanReport,
    health: &raysense_core::HealthSummary,
) -> String {
    let max_lines = report
        .files
        .iter()
        .map(|file| file.lines)
        .max()
        .unwrap_or(1)
        .max(1);
    let cells = report
        .files
        .iter()
        .map(|file| {
            let width = ((file.lines as f64 / max_lines as f64) * 100.0).max(8.0);
            format!(
                "<div class=\"file\" style=\"flex-basis:{width:.1}%\"><b>{}</b><span>{} lines</span><small>{}</small></div>",
                html_escape(&file.path.to_string_lossy()),
                file.lines,
                html_escape(&file.language_name)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let modules = health
        .metrics
        .dsm
        .top_module_edges
        .iter()
        .map(|edge| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&edge.from_module),
                html_escape(&edge.to_module),
                edge.edges
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let complex = health
        .metrics
        .complexity
        .complex_functions
        .iter()
        .take(12)
        .map(|function| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&function.path),
                html_escape(&function.name),
                function.value
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let gaps = health
        .metrics
        .test_gap
        .candidates
        .iter()
        .take(12)
        .map(|gap| {
            format!(
                "<tr><td>{}</td><td>{}</td></tr>",
                html_escape(&gap.path),
                html_escape(&gap.expected_tests.join(", "))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let hotspots = health
        .hotspots
        .iter()
        .map(|hotspot| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&hotspot.path),
                html_escape(&hotspot.module),
                hotspot.fan_in,
                hotspot.fan_out
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let rules = health
        .rules
        .iter()
        .take(12)
        .map(|rule| {
            format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                rule.severity,
                html_escape(&rule.code),
                html_escape(&rule.path),
                html_escape(&rule.message)
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let mut module_names = BTreeSet::new();
    for module in &health.metrics.architecture.unstable_modules {
        if !module.module.is_empty() {
            module_names.insert(module.module.clone());
        }
    }
    for edge in &health.metrics.dsm.top_module_edges {
        if !edge.from_module.is_empty() {
            module_names.insert(edge.from_module.clone());
        }
        if !edge.to_module.is_empty() {
            module_names.insert(edge.to_module.clone());
        }
    }
    let module_names = module_names.into_iter().take(16).collect::<Vec<_>>();
    let stability_by_module = health
        .metrics
        .architecture
        .unstable_modules
        .iter()
        .map(|module| (module.module.clone(), module.instability))
        .collect::<BTreeMap<_, _>>();
    let module_positions = module_names
        .iter()
        .enumerate()
        .map(|(idx, module)| {
            let x = 80 + (idx % 4) * 190;
            let y = 70 + (idx / 4) * 70;
            (module.clone(), (x, y))
        })
        .collect::<BTreeMap<_, _>>();
    let module_edges = health
        .metrics
        .dsm
        .top_module_edges
        .iter()
        .filter_map(|edge| {
            let (x1, y1) = module_positions.get(&edge.from_module)?;
            let (x2, y2) = module_positions.get(&edge.to_module)?;
            let width = edge.edges.min(8).max(1);
            Some(format!(
                "<line x1=\"{x1}\" y1=\"{y1}\" x2=\"{x2}\" y2=\"{y2}\" stroke-width=\"{width}\"/>"
            ))
        })
        .collect::<Vec<_>>()
        .join("");
    let module_nodes = module_names
        .iter()
        .map(|module| {
            let (x, y) = module_positions[module];
            let instability = stability_by_module.get(module).copied().unwrap_or(0.0);
            let radius = 22 + (instability * 18.0).round() as usize;
            let label = compact_label(module, 24);
            format!(
                "<g><circle cx=\"{x}\" cy=\"{y}\" r=\"{radius}\"/><text x=\"{x}\" y=\"{text_y}\" text-anchor=\"middle\">{}</text><title>{} instability {:.3}</title></g>",
                html_escape(&label),
                html_escape(module),
                instability,
                text_y = y + radius + 16
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let telemetry = serde_json::to_string(&serde_json::json!({
        "snapshot_id": report.snapshot.snapshot_id,
        "files": report.files.len(),
        "functions": report.functions.len(),
        "rules": health.rules.len(),
        "score": health.score,
        "quality_signal": health.quality_signal,
        "coverage_score": health.coverage_score,
        "structural_score": health.structural_score,
        "root_causes": health.root_causes,
        "resolution": health.resolution,
        "top_module_edges": health.metrics.dsm.top_module_edges,
        "hotspots": health.hotspots,
    }))
    .unwrap_or_else(|_| "{}".to_string());
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="10"><title>Raysense</title>
<style>
body{{font-family:system-ui,sans-serif;margin:24px;background:#111;color:#eee;line-height:1.4}}
.top{{display:flex;gap:24px;align-items:flex-end;flex-wrap:wrap}}
.metric{{font-size:14px;color:#aaa}}.metric b{{display:block;color:#fff;font-size:28px}}
.grid{{display:flex;flex-wrap:wrap;gap:8px;margin:24px 0}}
.file{{min-width:120px;min-height:72px;background:#1d2838;border:1px solid #31445d;padding:8px;box-sizing:border-box}}
.file b,.file span,.file small{{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.file span{{color:#9db5d6}}.file small{{color:#7d8999}}
.panels{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:24px}}
.bar{{height:8px;background:#263b57;margin-top:6px}}.bar span{{display:block;height:8px;background:#78a6d8}}
svg{{width:100%;max-width:820px;height:330px;background:#151b24;border:1px solid #333}}
svg line{{stroke:#78a6d8;opacity:.42}}svg circle{{fill:#263b57;stroke:#9cc7ef;stroke-width:2}}
svg text{{fill:#eee;font-size:11px}}
table{{border-collapse:collapse;width:100%;margin-top:16px}}td,th{{border-bottom:1px solid #333;padding:6px;text-align:left}}
</style></head><body>
<div class="top">
<div class="metric"><b>{}</b>quality signal</div>
<div class="metric"><b>{}</b>score</div>
<div class="metric"><b>{}</b>coverage</div>
<div class="metric"><b>{}</b>structure</div>
<div class="metric"><b>{}</b>files</div>
<div class="metric"><b>{}</b>functions</div>
<div class="metric"><b>{}</b>rules</div>
<div class="metric"><b>{:.3}</b>modularity<div class="bar"><span style="width:{:.1}%"></span></div></div>
<div class="metric"><b>{:.3}</b>redundancy<div class="bar"><span style="width:{:.1}%"></span></div></div>
</div>
<h2>Files</h2>
<div class="grid">{}</div>
<div class="panels">
<section><h2>Modules</h2><svg viewBox="0 0 820 330">{}{}</svg></section>
<section><h2>Module Edges</h2><table><tr><th>from</th><th>to</th><th>edges</th></tr>{}</table></section>
<section><h2>Hotspots</h2><table><tr><th>file</th><th>module</th><th>fan in</th><th>fan out</th></tr>{}</table></section>
<section><h2>Rules</h2><table><tr><th>severity</th><th>code</th><th>path</th><th>message</th></tr>{}</table></section>
<section><h2>Complexity</h2><table><tr><th>file</th><th>function</th><th>value</th></tr>{}</table></section>
<section><h2>Test Gaps</h2><table><tr><th>source</th><th>expected tests</th></tr>{}</table></section>
</div>
<script type="application/json" id="raysense-telemetry">{}</script>
</body></html>"#,
        health.quality_signal,
        health.score,
        health.coverage_score,
        health.structural_score,
        report.files.len(),
        report.functions.len(),
        health.rules.len(),
        health.root_causes.modularity,
        health.root_causes.modularity * 100.0,
        health.root_causes.redundancy,
        health.root_causes.redundancy * 100.0,
        cells,
        module_edges,
        module_nodes,
        modules,
        hotspots,
        rules,
        complex,
        gaps,
        json_script_escape(&telemetry)
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn json_script_escape(value: &str) -> String {
    value
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn compact_label(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let tail = value
        .rsplit(['/', '.'])
        .find(|part| !part.is_empty())
        .unwrap_or(value);
    if tail.chars().count() <= max_chars {
        tail.to_string()
    } else {
        let prefix = tail
            .chars()
            .take(max_chars.saturating_sub(3))
            .collect::<String>();
        format!("{prefix}...")
    }
}

fn list_plugins(root: &Path, config_path: Option<&Path>) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    if config.scan.plugins.is_empty() {
        println!("no plugins configured");
        return Ok(());
    }
    for plugin in config.scan.plugins {
        println!(
            "{}\texts={}\tfiles={}",
            plugin.name,
            plugin.extensions.join(","),
            plugin.file_names.join(",")
        );
    }
    Ok(())
}

fn add_plugin(
    root: &Path,
    config_path: Option<&Path>,
    name: &str,
    extensions: Vec<String>,
    file_names: Vec<String>,
) -> Result<()> {
    if extensions.is_empty() && file_names.is_empty() {
        return Err(anyhow!("extensions or file names must not be empty"));
    }
    let path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = if path.exists() {
        RaysenseConfig::from_path(&path)
            .with_context(|| format!("failed to load config {}", path.display()))?
    } else {
        RaysenseConfig::default()
    };
    config.scan.plugins.retain(|plugin| plugin.name != name);
    config
        .scan
        .plugins
        .push(raysense_core::LanguagePluginConfig {
            name: name.to_string(),
            extensions,
            file_names,
            ..raysense_core::LanguagePluginConfig::default()
        });
    let toml = toml::to_string_pretty(&config).context("failed to encode config")?;
    fs::write(&path, toml).with_context(|| format!("failed to write {}", path.display()))?;
    println!("plugin {} {}", name, path.display());
    Ok(())
}

fn add_standard_plugins(root: &Path, config_path: Option<&Path>) -> Result<()> {
    let path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = if path.exists() {
        RaysenseConfig::from_path(&path)
            .with_context(|| format!("failed to load config {}", path.display()))?
    } else {
        RaysenseConfig::default()
    };
    let standard = raysense_core::standard_language_plugins();
    for plugin in &standard {
        config
            .scan
            .plugins
            .retain(|existing| existing.name != plugin.name);
    }
    config.scan.plugins.extend(standard);
    config
        .scan
        .plugins
        .sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    let count = config.scan.plugins.len();
    let toml = toml::to_string_pretty(&config).context("failed to encode config")?;
    fs::write(&path, toml).with_context(|| format!("failed to write {}", path.display()))?;
    println!("plugins {} {}", count, path.display());
    Ok(())
}

fn remove_plugin(root: &Path, config_path: Option<&Path>, name: &str) -> Result<()> {
    let path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = if path.exists() {
        RaysenseConfig::from_path(&path)
            .with_context(|| format!("failed to load config {}", path.display()))?
    } else {
        RaysenseConfig::default()
    };
    let before = config.scan.plugins.len();
    config
        .scan
        .plugins
        .retain(|plugin| !plugin.name.eq_ignore_ascii_case(name));
    let removed = before - config.scan.plugins.len();
    let toml = toml::to_string_pretty(&config).context("failed to encode config")?;
    fs::write(&path, toml).with_context(|| format!("failed to write {}", path.display()))?;
    println!("plugin_removed {} {} {}", name, removed, path.display());
    Ok(())
}

pub(crate) fn validate_plugin_dir(dir: &Path) -> Result<Value> {
    let manifest_path = dir.join("plugin.toml");
    let content = fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read {}", manifest_path.display()))?;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let plugin: raysense_core::LanguagePluginConfig =
        match toml::from_str(&content).context("failed to parse plugin manifest") {
            Ok(plugin) => plugin,
            Err(error) => {
                return Ok(json!({
                    "dir": dir,
                    "valid": false,
                    "errors": [error.to_string()],
                    "warnings": warnings
                }));
            }
        };

    if plugin.name.trim().is_empty() {
        errors.push("plugin name must not be empty".to_string());
    }
    if plugin.extensions.is_empty() && plugin.file_names.is_empty() {
        errors.push("extensions or file_names must not be empty".to_string());
    }
    if plugin.function_prefixes.is_empty() && plugin.tags_query.is_none() {
        warnings.push("no function_prefixes or inline tags_query configured".to_string());
    }

    let query_path = dir.join("queries/tags.scm");
    let query = if let Some(query) = plugin.tags_query.as_ref() {
        Some(query.clone())
    } else if query_path.exists() {
        Some(
            fs::read_to_string(&query_path)
                .with_context(|| format!("failed to read {}", query_path.display()))?,
        )
    } else {
        None
    };
    if let Some(query) = query.as_ref() {
        if !has_supported_query_capture(query) {
            warnings.push(
                "tags query has no recognized function, name, or import captures".to_string(),
            );
        }
        if !plugin_has_query_language(&plugin) {
            warnings
                .push("tags query requires a supported grammar or grammar_path to run".to_string());
        }
    }

    let grammar_path = plugin.grammar_path.as_ref().map(|path| {
        let path = PathBuf::from(path);
        if path.is_relative() {
            dir.join(path)
        } else {
            path
        }
    });
    if let Some(path) = grammar_path.as_ref() {
        if !path.exists() {
            errors.push(format!("grammar_path does not exist: {}", path.display()));
        }
    }

    Ok(json!({
        "dir": dir,
        "valid": errors.is_empty(),
        "plugin": plugin,
        "has_query_file": query_path.exists(),
        "has_query": query.is_some(),
        "grammar_path": grammar_path,
        "errors": errors,
        "warnings": warnings
    }))
}

fn has_supported_query_capture(query: &str) -> bool {
    [
        "@definition.function",
        "@definition.method",
        "@function",
        "@method",
        "@name",
        "@import",
        "@reference.import",
        "@module",
        "@source",
    ]
    .iter()
    .any(|capture| query.contains(capture))
}

fn plugin_has_query_language(plugin: &raysense_core::LanguagePluginConfig) -> bool {
    plugin.grammar_path.is_some()
        || matches!(
            plugin.grammar.as_deref().unwrap_or(plugin.name.as_str()),
            "c" | "cpp" | "c++" | "python" | "rust" | "typescript" | "javascript" | "tsx" | "jsx"
        )
}

fn print_plugin_validation(validation: &Value) {
    println!("valid {}", validation["valid"].as_bool().unwrap_or(false));
    if let Some(plugin) = validation["plugin"].as_object() {
        println!(
            "name {}",
            plugin.get("name").and_then(Value::as_str).unwrap_or("")
        );
    }
    for error in validation["errors"].as_array().into_iter().flatten() {
        println!("error {}", error.as_str().unwrap_or(""));
    }
    for warning in validation["warnings"].as_array().into_iter().flatten() {
        println!("warning {}", warning.as_str().unwrap_or(""));
    }
}

pub(crate) fn scaffold_plugin(root: &Path, name: &str, extension: &str) -> Result<PathBuf> {
    if name.trim().is_empty() {
        return Err(anyhow!("plugin name must not be empty"));
    }
    if extension.trim().is_empty() {
        return Err(anyhow!("plugin extension must not be empty"));
    }
    let plugin_dir = root.join(".raysense/plugins").join(name);
    if plugin_dir.exists() {
        return Err(anyhow!(
            "plugin directory already exists: {}",
            plugin_dir.display()
        ));
    }
    let query_dir = plugin_dir.join("queries");
    fs::create_dir_all(&query_dir)
        .with_context(|| format!("failed to create {}", query_dir.display()))?;
    let extension = extension.trim().trim_start_matches('.');
    let manifest = format!(
        r#"name = "{name}"
extensions = ["{extension}"]
function_prefixes = ["function ", "def ", "fn "]
import_prefixes = ["import ", "use ", "require "]
call_suffixes = ["("]
test_path_patterns = ["tests/*", "test/*"]
local_import_prefixes = ["."]
max_function_complexity = 15
max_cognitive_complexity = 20
"#
    );
    fs::write(plugin_dir.join("plugin.toml"), manifest).with_context(|| {
        format!(
            "failed to write {}",
            plugin_dir.join("plugin.toml").display()
        )
    })?;
    let query = r#"; Optional tree-sitter tags query.
; Recognized captures include:
;   @definition.function with @name
;   @definition.method with @name
;   @reference.import, @import, @module, or @source
"#;
    fs::write(query_dir.join("tags.scm"), query)
        .with_context(|| format!("failed to write {}", query_dir.join("tags.scm").display()))?;
    Ok(plugin_dir)
}

fn list_policies() {
    for name in ["rust-crate", "monorepo", "service-backend", "library"] {
        println!("{name}");
    }
}

fn init_policy(root: &Path, config_path: Option<&Path>, preset: &str) -> Result<()> {
    let path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = if path.exists() {
        RaysenseConfig::from_path(&path)
            .with_context(|| format!("failed to load config {}", path.display()))?
    } else {
        RaysenseConfig::default()
    };
    apply_policy_preset(&mut config, preset)?;
    let toml = toml::to_string_pretty(&config).context("failed to encode config")?;
    fs::write(&path, toml).with_context(|| format!("failed to write {}", path.display()))?;
    println!("policy {} {}", preset, path.display());
    Ok(())
}

fn apply_policy_preset(config: &mut RaysenseConfig, preset: &str) -> Result<()> {
    match preset {
        "rust-crate" => {
            config.scan.ignored_paths = vec!["target".to_string()];
            config.scan.generated_paths = vec!["**/generated/*".to_string()];
            config.scan.enabled_languages = vec!["rust".to_string(), "toml".to_string()];
            config.scan.module_roots = vec!["crates".to_string(), "src".to_string()];
            config.scan.test_roots = vec!["tests".to_string(), "benches".to_string()];
            config.scan.public_api_paths =
                vec!["src/lib.rs".to_string(), "*/src/lib.rs".to_string()];
            config.rules.max_function_complexity = 20;
        }
        "monorepo" => {
            config.scan.module_roots = vec![
                "apps".to_string(),
                "packages".to_string(),
                "crates".to_string(),
                "services".to_string(),
            ];
            config.rules.max_coupling_ratio = 0.4;
            config.rules.high_file_fan_in = 75;
        }
        "service-backend" => {
            config.scan.module_roots =
                vec!["src".to_string(), "internal".to_string(), "pkg".to_string()];
            config.rules.max_function_complexity = 18;
            config.boundaries.layers = vec![
                raysense_core::LayerConfig {
                    name: "api".to_string(),
                    path: "src/api/*".to_string(),
                    order: 2,
                },
                raysense_core::LayerConfig {
                    name: "domain".to_string(),
                    path: "src/domain/*".to_string(),
                    order: 1,
                },
                raysense_core::LayerConfig {
                    name: "infra".to_string(),
                    path: "src/infra/*".to_string(),
                    order: 0,
                },
            ];
        }
        "library" => {
            config.scan.public_api_paths = vec![
                "src/lib.*".to_string(),
                "include/*".to_string(),
                "*/src/lib.*".to_string(),
            ];
            config.rules.max_function_complexity = 15;
            config.score.redundancy_weight = 1.5;
        }
        _ => return Err(anyhow!("unknown policy preset {preset}")),
    }
    Ok(())
}

fn record_trend(root: &Path, config_path: Option<&Path>) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let dir = report.snapshot.root.join(".raysense/trends");
    let path = dir.join("history.json");
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let mut samples: Vec<Value> = if path.exists() {
        serde_json::from_str(&fs::read_to_string(&path)?).unwrap_or_default()
    } else {
        Vec::new()
    };
    samples.push(serde_json::json!({
        "timestamp": unix_time(),
        "snapshot_id": report.snapshot.snapshot_id,
        "score": health.score,
        "quality_signal": health.quality_signal,
        "rules": health.rules.len(),
        "files": report.files.len(),
        "functions": report.functions.len()
    }));
    fs::write(&path, serde_json::to_string_pretty(&samples)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("trend {}", path.display());
    Ok(())
}

fn show_trend(root: &Path, config_path: Option<&Path>, json: bool) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    if json {
        println!("{}", serde_json::to_string_pretty(&health.metrics.trend)?);
    } else if health.metrics.trend.available {
        println!(
            "trend samples={} score_delta={} quality_signal_delta={} rule_delta={}",
            health.metrics.trend.samples,
            health.metrics.trend.score_delta,
            health.metrics.trend.quality_signal_delta,
            health.metrics.trend.rule_delta
        );
    } else {
        println!("trend unavailable");
    }
    Ok(())
}

fn print_remediations(root: &Path, config_path: Option<&Path>, json: bool) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    if json {
        println!("{}", serde_json::to_string_pretty(&health.remediations)?);
    } else {
        for item in health.remediations {
            println!("{} {} - {}", item.code, item.path, item.action);
            println!("  {}", item.command);
        }
    }
    Ok(())
}

fn print_what_if(
    root: &Path,
    config_path: Option<&Path>,
    ignore_paths: &[String],
    generated_paths: &[String],
    json: bool,
) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    let before_report = scan_path_with_config(root, &config)?;
    let before_health = compute_health_with_config(&before_report, &config);
    let before = build_baseline(&before_report, &before_health);
    let mut simulated_config = config.clone();
    simulated_config
        .scan
        .ignored_paths
        .extend(ignore_paths.iter().cloned());
    simulated_config
        .scan
        .generated_paths
        .extend(generated_paths.iter().cloned());
    let after_report = scan_path_with_config(root, &simulated_config)?;
    let after_health = compute_health_with_config(&after_report, &simulated_config);
    let after = build_baseline(&after_report, &after_health);
    let diff = diff_baselines(&before, &after);
    let output = serde_json::json!({
        "ignored_paths": ignore_paths,
        "generated_paths": generated_paths,
        "before": {
            "score": before_health.score,
            "quality_signal": before_health.quality_signal,
            "files": before_report.snapshot.file_count,
            "rules": before_health.rules.len()
        },
        "after": {
            "score": after_health.score,
            "quality_signal": after_health.quality_signal,
            "files": after_report.snapshot.file_count,
            "rules": after_health.rules.len()
        },
        "diff": diff.clone()
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "what_if score {} -> {} quality_signal {} -> {} files {} -> {} rules {} -> {}",
            before_health.score,
            after_health.score,
            before_health.quality_signal,
            after_health.quality_signal,
            before_report.snapshot.file_count,
            after_report.snapshot.file_count,
            before_health.rules.len(),
            after_health.rules.len()
        );
        print_baseline_diff(&diff);
    }
    Ok(())
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
    println!("quality_signal {}", health.quality_signal);
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
    println!("quality_signal {}", health.quality_signal);
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
        "coupling local_edges={} cross_module_edges={} cross_module_ratio={:.3} cross_unstable_edges={} cross_unstable_ratio={:.3} entropy={:.3} entropy_bits={:.3} entropy_pairs={} average_module_cohesion={} cohesive_module_count={}",
        health.metrics.coupling.local_edges,
        health.metrics.coupling.cross_module_edges,
        health.metrics.coupling.cross_module_ratio,
        health.metrics.coupling.cross_unstable_edges,
        health.metrics.coupling.cross_unstable_ratio,
        health.metrics.coupling.entropy,
        health.metrics.coupling.entropy_bits,
        health.metrics.coupling.entropy_pairs,
        health
            .metrics
            .coupling
            .average_module_cohesion
            .map(|value| format!("{value:.3}"))
            .unwrap_or_else(|| "none".to_string()),
        health.metrics.coupling.cohesive_module_count
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
    println!(
        "root_causes modularity={:.3} acyclicity={:.3} depth={:.3} equality={:.3} redundancy={:.3}",
        health.root_causes.modularity,
        health.root_causes.acyclicity,
        health.root_causes.depth,
        health.root_causes.equality,
        health.root_causes.redundancy
    );
    println!(
        "architecture depth={} max_blast_radius={} max_blast_radius_file={} max_non_foundation_blast_radius={} max_non_foundation_blast_radius_file={} attack_surface_files={} attack_surface_ratio={:.3} average_distance_from_main_sequence={:.3}",
        health.metrics.architecture.module_depth,
        health.metrics.architecture.max_blast_radius,
        health.metrics.architecture.max_blast_radius_file,
        health.metrics.architecture.max_non_foundation_blast_radius,
        health
            .metrics
            .architecture
            .max_non_foundation_blast_radius_file,
        health.metrics.architecture.attack_surface_files,
        health.metrics.architecture.attack_surface_ratio,
        health
            .metrics
            .architecture
            .average_distance_from_main_sequence
    );
    println!(
        "complexity max={} avg={:.3} cognitive_max={} cognitive_avg={:.3} gini={:.3} dead_functions={} duplicate_groups={} redundancy_ratio={:.3}",
        health.metrics.complexity.max_function_complexity,
        health.metrics.complexity.average_function_complexity,
        health.metrics.complexity.max_cognitive_complexity,
        health.metrics.complexity.average_cognitive_complexity,
        health.metrics.complexity.complexity_gini,
        health.metrics.complexity.dead_functions.len(),
        health.metrics.complexity.duplicate_groups.len(),
        health.metrics.complexity.redundancy_ratio
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
