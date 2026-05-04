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

use crate::memory::{
    BaselineFilterMode, BaselineFilterOp, BaselineSortDirection, BaselineTableFilter,
    BaselineTableQuery, BaselineTableSort,
};
use crate::{
    build_baseline, compute_health_with_config, diff_baselines, scan_path_with_config,
    BaselineDiff, HealthSummary, ProjectBaseline, RaysenseConfig, ScanReport,
};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use crate::mcp;

/// One-tool CLI: `raysense [path]` runs a health report by default.
/// Top-level flags pick a different mode (json, ui, watch, check, mcp).
/// Advanced operations (baseline / plugin / policy / trend / whatif) live as
/// subcommands so their multi-arg shapes don't pollute the simple path.
#[derive(Debug, Parser)]
#[command(name = "raysense")]
#[command(version)]
#[command(about = "Architectural X-ray for your codebase. Live, local, agent-ready.")]
struct Args {
    /// Path to scan. Default: current directory.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Run the rule gate. Exits non-zero if any rule fails.
    #[arg(long)]
    check: bool,

    /// With `--check`: also write a SARIF code-scanning report here.
    #[arg(long, value_name = "PATH")]
    sarif: Option<PathBuf>,

    /// Watch mode: rescan and reprint when files change. Filesystem-driven
    /// (no polling); ignores changes inside target / .git / node_modules / .raysense.
    #[arg(long)]
    watch: bool,

    /// Start the live UI HTTP server. Optional port (default 7000).
    #[arg(long, value_name = "PORT", num_args = 0..=1, default_missing_value = "7000")]
    ui: Option<u16>,

    /// Run as a stdio MCP server. Path is ignored.
    #[arg(long)]
    mcp: bool,

    /// Print the linked C library version and exit.
    #[arg(long)]
    rayforce_version: bool,

    /// Optional explicit `.raysense.toml` path.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    advanced: Option<Command>,
}

/// Advanced subcommands. Most users never need these - the top-level flags
/// cover the common 90 %.
#[derive(Debug, Subcommand)]
enum Command {
    /// Save / diff / query a baseline of the current scan.
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    /// Manage language plugins (list / add / sync / validate / scaffold).
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// Apply or list rule policy presets.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Record / show health-score trend snapshots.
    Trend {
        #[command(subcommand)]
        command: TrendCommand,
    },
    /// What-if simulation: rescan with extra ignored / generated paths.
    Whatif {
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
    /// Register raysense across every local Claude host.
    /// No flags = auto-detect Claude Desktop, Claude Code, and Cowork (the
    /// Desktop research-preview agent mode) and install to whichever are
    /// present. Pass `--desktop` / `--code` / `--cowork` to force a subset.
    Install {
        /// Force-install for Claude Desktop (edits claude_desktop_config.json).
        #[arg(long)]
        desktop: bool,
        /// Force-install the raysense plugin for Claude Code (edits
        /// `~/.claude/settings.json`).
        #[arg(long)]
        code: bool,
        /// Force-install for Cowork (Claude Desktop's research-preview agent
        /// mode); registers the raysense marketplace in every local cowork
        /// session's `known_marketplaces.json`.
        #[arg(long)]
        cowork: bool,
    },
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
    Sync {
        /// Optional list of standard plugin names to sync. When omitted,
        /// every standard plugin is materialized.
        names: Vec<String>,
        #[arg(long, default_value = ".")]
        path: PathBuf,
        /// Overwrite existing plugin.toml files.
        #[arg(long)]
        force: bool,
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
    /// Evaluate every .rfl policy file in a directory against the saved
    /// baseline. Each policy is a Rayfall expression that returns a
    /// table of (severity, code, path, message) findings.
    Check {
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        policies: Option<PathBuf>,
        #[arg(long)]
        json: bool,
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
    Query {
        table: String,
        rayfall: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Import an external CSV as a baseline table.  The new table joins the
    /// built-in ones (files, functions, ...) and becomes queryable through
    /// `baseline query`, `policy check`, and the MCP tools.
    ImportCsv {
        /// Name to register the imported table under (a-z0-9_, no dots).
        name: String,
        /// Path to the CSV file.  First row is treated as headers.
        csv: PathBuf,
        #[arg(long)]
        baseline: Option<PathBuf>,
    },
}

pub fn run() -> Result<()> {
    let args = Args::parse();

    if let Some(command) = args.advanced {
        return run_advanced(command);
    }

    if args.rayforce_version {
        println!("{}", crate::sys::version_string());
        return Ok(());
    }
    if args.mcp {
        return mcp::run();
    }
    if let Some(port) = args.ui {
        return serve_visualization(&args.path, args.config.as_deref(), port);
    }
    if args.watch {
        return watch_project(&args.path, args.config.as_deref());
    }
    if args.check {
        let exit = check_project(
            &args.path,
            args.config.as_deref(),
            args.json,
            args.sarif.as_deref(),
        )?;
        process::exit(exit);
    }

    // Default mode: health report.
    let config = config_for_root(&args.path, args.config.as_deref())?;
    let report = scan_path_with_config(&args.path, &config)?;
    let health = compute_health_with_config(&report, &config);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&health)?);
    } else {
        print_health(&report, &health);
    }
    Ok(())
}

fn run_advanced(command: Command) -> Result<()> {
    match command {
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
            PluginCommand::Sync { names, path, force } => {
                let summary = sync_standard_plugins(&path, &names, force)?;
                for entry in &summary.written {
                    println!("plugin_sync wrote {}", entry.display());
                }
                for entry in &summary.skipped {
                    println!("plugin_sync skipped {}", entry.display());
                }
                println!(
                    "plugin_sync wrote={} skipped={}",
                    summary.written.len(),
                    summary.skipped.len()
                );
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
            PolicyCommand::Check {
                baseline,
                policies,
                json,
            } => {
                let exit = run_policy_check(baseline, policies, json)?;
                if exit != 0 {
                    process::exit(exit);
                }
            }
        },
        Command::Trend { command } => match command {
            TrendCommand::Record { path, config } => record_trend(&path, config.as_deref())?,
            TrendCommand::Show { path, config, json } => {
                show_trend(&path, config.as_deref(), json)?
            }
        },
        Command::Whatif {
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
        Command::Install {
            desktop,
            code,
            cowork,
        } => {
            crate::install::run(crate::install::InstallSelection {
                desktop,
                code,
                cowork,
            })?
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
                    crate::memory::list_baseline_tables(&tables_dir).with_context(|| {
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
                let rows = crate::memory::query_baseline_table(&tables_dir, &table, query)
                    .with_context(|| {
                        format!("failed to read baseline table {}", tables_dir.display())
                    })?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                } else {
                    print_baseline_rows(&rows);
                }
            }
            BaselineCommand::Query {
                table,
                rayfall,
                baseline,
                json,
            } => {
                // Stderr-only progress lines so JSON callers and pipes
                // see clean stdout.  Hidden under 200ms of eval time.
                if !json {
                    crate::memory::enable_cli_progress();
                }
                let baseline = baseline.unwrap_or_else(default_baseline_dir);
                let tables_dir = baseline.join("tables");
                let rows = crate::memory::query_with_rayfall(&tables_dir, &table, &rayfall)
                    .with_context(|| {
                        format!(
                            "failed to evaluate Rayfall against {}",
                            tables_dir.display()
                        )
                    })?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                } else {
                    print_baseline_rows(&rows);
                }
            }
            BaselineCommand::ImportCsv {
                name,
                csv,
                baseline,
            } => {
                let baseline = baseline.unwrap_or_else(default_baseline_dir);
                let tables_dir = baseline.join("tables");
                crate::memory::import_csv_table(&tables_dir, &name, &csv).with_context(|| {
                    format!(
                        "failed to import {} as baseline table {}",
                        csv.display(),
                        name
                    )
                })?;
                println!(
                    "imported {} -> {}",
                    csv.display(),
                    tables_dir.join(&name).display()
                );
            }
        },
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
        .any(|rule| matches!(rule.severity, crate::RuleSeverity::Error));
    Ok(if has_errors { 1 } else { 0 })
}

pub(crate) fn sarif_report(report: &crate::ScanReport, health: &crate::HealthSummary) -> Value {
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

fn sarif_level(severity: crate::RuleSeverity) -> &'static str {
    match severity {
        crate::RuleSeverity::Error => "error",
        crate::RuleSeverity::Warning => "warning",
        crate::RuleSeverity::Info => "note",
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

fn watch_project(root: &Path, config_path: Option<&Path>) -> Result<()> {
    let mut last_snapshot = String::new();
    let mut emit = || -> Result<()> {
        let config = config_for_root(root, config_path)?;
        let report = scan_path_with_config(root, &config)?;
        let health = compute_health_with_config(&report, &config);
        if report.snapshot.snapshot_id != last_snapshot {
            println!(
                "snapshot {} score={} files={} rules={}",
                report.snapshot.snapshot_id,
                health.score,
                report.snapshot.file_count,
                health.rules.len()
            );
            last_snapshot = report.snapshot.snapshot_id;
        }
        Ok(())
    };
    emit()?;
    watch_paths_blocking(root, emit)
}

/// Watch a project root with `notify`, debounce events that fall in
/// always-ignored directories (target, .git, node_modules, .raysense),
/// and call `on_change` once per debounced burst (~150 ms window).
fn watch_paths_blocking<F>(root: &Path, mut on_change: F) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    use notify::{RecursiveMode, Watcher};
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            if relevant_event(&event) {
                let _ = tx.send(());
            }
        }
    })
    .context("failed to start filesystem watcher")?;
    watcher
        .watch(root, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch {}", root.display()))?;
    loop {
        // wait for at least one event
        if rx.recv().is_err() {
            break;
        }
        // drain rapid bursts
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(150);
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                break;
            }
            match rx.recv_timeout(deadline - now) {
                Ok(()) => continue,
                Err(_) => break,
            }
        }
        on_change()?;
    }
    Ok(())
}

fn relevant_event(event: &notify::Event) -> bool {
    use notify::EventKind;
    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
        return false;
    }
    event.paths.iter().any(|p| !is_ignored_event_path(p))
}

fn is_ignored_event_path(path: &Path) -> bool {
    path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("target" | ".git" | "node_modules" | ".raysense")
        )
    })
}

/// Run a tokio HTTP server that hosts the live visualization. The server
/// re-scans on a fixed interval, only emits an SSE `data-changed` event when
/// the new snapshot's content hash differs from the previous one, and serves
/// the HTML page without any meta-refresh. Browsers connected to `/events`
/// reload the page on each change; other state (filter selections, scroll,
/// expanded panels) survives whenever data didn't actually change.
fn serve_visualization(root: &Path, config_path: Option<&Path>, port: u16) -> Result<()> {
    let root = root.to_path_buf();
    let config_path = config_path.map(Path::to_path_buf);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start tokio runtime")?;

    runtime.block_on(async move {
        use axum::{
            response::sse::{Event, KeepAlive, Sse},
            response::{Html, IntoResponse},
            routing::get,
            Json, Router,
        };
        use std::sync::Arc;
        use tokio::sync::{broadcast, RwLock};
        use tokio_stream::wrappers::BroadcastStream;
        use tokio_stream::StreamExt;

        let initial = scan_now(&root, config_path.as_deref())?;
        let state = Arc::new(LiveState {
            inner: RwLock::new(initial),
            tx: broadcast::channel::<()>(16).0,
        });

        // Bridge filesystem events into a tokio mpsc; the watcher's callback
        // runs on a private notify thread (sync), and we drain into the
        // async runtime for debouncing + rescan.
        let (fs_tx, mut fs_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        // `stop_rx` blocks the spawn_blocking task instead of `thread::park()`.
        // After Ctrl+C, dropping `stop_tx` (below, after axum exits) returns
        // Err from recv, the watcher object goes out of scope, notify's
        // background thread shuts down, and the spawn_blocking task ends.
        // Without this signalling path, tokio's runtime drop would block
        // forever waiting for a parked task to terminate, and Ctrl+C would
        // appear to do nothing.
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let watcher_root = root.clone();
        let _watcher_keepalive = tokio::task::spawn_blocking(move || {
            use notify::{RecursiveMode, Watcher};
            let mut watcher =
                match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                    if let Ok(event) = res {
                        if relevant_event(&event) {
                            let _ = fs_tx.send(());
                        }
                    }
                }) {
                    Ok(w) => w,
                    Err(err) => {
                        eprintln!("filesystem watcher init failed: {err}");
                        return;
                    }
                };
            if let Err(err) = watcher.watch(&watcher_root, RecursiveMode::Recursive) {
                eprintln!("filesystem watcher attach failed: {err}");
                return;
            }
            // Block here until shutdown signal. Dropping `stop_tx` from the
            // async block above causes recv to return Err, then `watcher`
            // drops cleanly on scope exit.
            let _ = stop_rx.recv();
        });

        let scanner_state = state.clone();
        let scanner_root = root.clone();
        let scanner_config = config_path.clone();
        tokio::spawn(async move {
            let debounce = std::time::Duration::from_millis(150);
            while let Some(()) = fs_rx.recv().await {
                // drain rapid bursts
                loop {
                    match tokio::time::timeout(debounce, fs_rx.recv()).await {
                        Ok(Some(())) => continue,
                        _ => break,
                    }
                }
                let scan = match tokio::task::spawn_blocking({
                    let root = scanner_root.clone();
                    let cfg = scanner_config.clone();
                    move || scan_now(&root, cfg.as_deref())
                })
                .await
                {
                    Ok(Ok(snap)) => snap,
                    Ok(Err(err)) => {
                        eprintln!("rescan failed: {err}");
                        continue;
                    }
                    Err(err) => {
                        eprintln!("rescan task panicked: {err}");
                        continue;
                    }
                };
                let mut current = scanner_state.inner.write().await;
                if current.hash != scan.hash {
                    *current = scan;
                    let _ = scanner_state.tx.send(());
                }
            }
        });

        let html_state = state.clone();
        let data_state = state.clone();
        let events_state = state.clone();

        let app = Router::new()
            .route(
                "/",
                get(move || async move {
                    let snap = html_state.inner.read().await;
                    Html(snap.html.clone()).into_response()
                }),
            )
            .route(
                "/data",
                get(move || async move {
                    let snap = data_state.inner.read().await;
                    Json(snap.payload.clone()).into_response()
                }),
            )
            .route(
                "/events",
                get(move || async move {
                    let rx = events_state.tx.subscribe();
                    let stream = BroadcastStream::new(rx).map(|item| match item {
                        Ok(()) => Ok(Event::default().event("data-changed")),
                        Err(_) => Ok::<_, std::convert::Infallible>(
                            Event::default().event("data-changed"),
                        ),
                    });
                    Sse::new(stream).keep_alive(KeepAlive::default())
                }),
            );

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind {addr}"))?;
        println!("visualization http://{addr} (filesystem watcher; Ctrl+C to stop)");

        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
            .context("server error")?;

        // Wake the filesystem watcher's spawn_blocking task so the runtime
        // can shut down. See the channel construction above for the why.
        drop(stop_tx);

        Ok::<(), anyhow::Error>(())
    })
}

struct LiveState {
    inner: tokio::sync::RwLock<LiveSnapshot>,
    tx: tokio::sync::broadcast::Sender<()>,
}

struct LiveSnapshot {
    hash: String,
    html: String,
    payload: serde_json::Value,
}

fn scan_now(root: &Path, config_path: Option<&Path>) -> Result<LiveSnapshot> {
    use sha2::{Digest, Sha256};
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let html = visualization_html(&report, &health);
    let payload = serde_json::json!({
        "snapshot_id": report.snapshot.snapshot_id,
        "score": health.score,
        "quality_signal": health.quality_signal,
        "files": report.files.len(),
        "functions": report.functions.len(),
        "rules": health.rules.len(),
    });
    let mut hasher = Sha256::new();
    hasher.update(report.snapshot.snapshot_id.as_bytes());
    hasher.update(serde_json::to_vec(&payload).unwrap_or_default());
    let hash = format!("{:x}", hasher.finalize());
    Ok(LiveSnapshot {
        hash,
        html,
        payload,
    })
}

pub(crate) fn visualization_html(
    report: &crate::ScanReport,
    health: &crate::HealthSummary,
) -> String {
    let max_lines = report
        .files
        .iter()
        .map(|file| file.lines)
        .max()
        .unwrap_or(1)
        .max(1);
    let churn_by_path: std::collections::HashMap<String, usize> = health
        .metrics
        .evolution
        .top_changed_files
        .iter()
        .map(|file| (file.path.clone(), file.commits))
        .collect();
    let age_by_path: std::collections::HashMap<String, u64> = health
        .metrics
        .evolution
        .file_ages
        .iter()
        .map(|file| (file.path.clone(), file.age_days))
        .collect();
    let risk_by_path: std::collections::HashMap<String, usize> = health
        .metrics
        .evolution
        .temporal_hotspots
        .iter()
        .map(|file| (file.path.clone(), file.risk_score))
        .collect();
    let instability_by_module: std::collections::HashMap<String, f64> = health
        .metrics
        .architecture
        .unstable_modules
        .iter()
        .map(|module| (module.module.clone(), module.instability))
        .collect();
    let directory_for = |path: &str| -> String {
        path.rsplit_once('/')
            .map(|(dir, _)| dir.to_string())
            .unwrap_or_default()
    };

    let path_for_file: Vec<String> = report
        .files
        .iter()
        .map(|file| file.path.to_string_lossy().into_owned())
        .collect();
    let function_to_file: Vec<usize> = report
        .functions
        .iter()
        .map(|function| function.file_id)
        .collect();
    let entry_point_files: std::collections::HashSet<usize> = report
        .entry_points
        .iter()
        .map(|entry| entry.file_id)
        .collect();
    let type_name_to_file: std::collections::HashMap<String, usize> = report
        .types
        .iter()
        .map(|type_fact| (type_fact.name.clone(), type_fact.file_id))
        .collect();

    let mut imports_out: Vec<std::collections::BTreeSet<usize>> =
        vec![std::collections::BTreeSet::new(); report.files.len()];
    let mut imports_in: Vec<std::collections::BTreeSet<usize>> =
        vec![std::collections::BTreeSet::new(); report.files.len()];
    for import in &report.imports {
        if let Some(to) = import.resolved_file {
            if to == import.from_file {
                continue;
            }
            imports_out[import.from_file].insert(to);
            imports_in[to].insert(import.from_file);
        }
    }
    let mut calls_out: Vec<std::collections::BTreeSet<usize>> =
        vec![std::collections::BTreeSet::new(); report.files.len()];
    let mut calls_in: Vec<std::collections::BTreeSet<usize>> =
        vec![std::collections::BTreeSet::new(); report.files.len()];
    for edge in &report.call_edges {
        let (Some(&from_file), Some(&to_file)) = (
            function_to_file.get(edge.caller_function),
            function_to_file.get(edge.callee_function),
        ) else {
            continue;
        };
        if from_file == to_file {
            continue;
        }
        calls_out[from_file].insert(to_file);
        calls_in[to_file].insert(from_file);
    }
    let mut inherits_out: Vec<std::collections::BTreeSet<usize>> =
        vec![std::collections::BTreeSet::new(); report.files.len()];
    let mut inherits_in: Vec<std::collections::BTreeSet<usize>> =
        vec![std::collections::BTreeSet::new(); report.files.len()];
    for type_fact in &report.types {
        for base in &type_fact.bases {
            let Some(&base_file) = type_name_to_file.get(base) else {
                continue;
            };
            if base_file == type_fact.file_id {
                continue;
            }
            inherits_out[type_fact.file_id].insert(base_file);
            inherits_in[base_file].insert(type_fact.file_id);
        }
    }
    let render_paths = |ids: &std::collections::BTreeSet<usize>| -> Vec<String> {
        ids.iter()
            .filter_map(|id| path_for_file.get(*id).cloned())
            .collect()
    };
    let adjacency_json = serde_json::to_string(
        &report
            .files
            .iter()
            .map(|file| {
                let id = file.file_id;
                serde_json::json!({
                    "path": path_for_file[id],
                    "imports_out": render_paths(&imports_out[id]),
                    "imports_in": render_paths(&imports_in[id]),
                    "calls_out": render_paths(&calls_out[id]),
                    "calls_in": render_paths(&calls_in[id]),
                    "inherits_out": render_paths(&inherits_out[id]),
                    "inherits_in": render_paths(&inherits_in[id])
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string());

    let _ = max_lines;
    let author_by_path: std::collections::HashMap<&str, &str> = health
        .metrics
        .evolution
        .file_ownership
        .iter()
        .map(|o| (o.path.as_str(), o.top_author.as_str()))
        .collect();
    let bus_by_path: std::collections::HashMap<&str, usize> = health
        .metrics
        .evolution
        .file_ownership
        .iter()
        .map(|o| (o.path.as_str(), o.bus_factor))
        .collect();
    let test_gap_paths: std::collections::HashSet<&str> = health
        .metrics
        .test_gap
        .candidates
        .iter()
        .map(|c| c.path.as_str())
        .collect();
    let cycle_index_by_path: std::collections::HashMap<String, usize> = health
        .metrics
        .architecture
        .cycles
        .iter()
        .enumerate()
        .flat_map(|(idx, files)| files.iter().map(move |f| (f.clone(), idx)))
        .collect();
    let files_json = serde_json::to_string(
        &report
            .files
            .iter()
            .map(|file| {
                let path = file.path.to_string_lossy().into_owned();
                let churn = churn_by_path.get(path.as_str()).copied().unwrap_or(0);
                let age = age_by_path.get(path.as_str()).copied().unwrap_or(0);
                let risk = risk_by_path.get(path.as_str()).copied().unwrap_or(0);
                let instability = instability_by_module
                    .get(file.module.as_str())
                    .copied()
                    .unwrap_or(0.0);
                let directory = directory_for(path.as_str());
                let is_entry = entry_point_files.contains(&file.file_id);
                let author = author_by_path
                    .get(path.as_str())
                    .copied()
                    .unwrap_or("")
                    .to_string();
                let bus = bus_by_path.get(path.as_str()).copied().unwrap_or(0);
                let in_test_gap = test_gap_paths.contains(path.as_str());
                let cycle = cycle_index_by_path.get(path.as_str()).copied();
                serde_json::json!({
                    "path": path,
                    "lines": file.lines,
                    "language": file.language_name,
                    "churn": churn,
                    "age": age,
                    "risk": risk,
                    "instability": instability,
                    "directory": directory,
                    "entry": is_entry,
                    "author": author,
                    "bus": bus,
                    "test_gap": in_test_gap,
                    "cycle": cycle,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string());

    let cycles_json = serde_json::to_string(&health.metrics.architecture.cycles)
        .unwrap_or_else(|_| "[]".to_string());
    let change_coupling_json = serde_json::to_string(&health.metrics.evolution.change_coupling)
        .unwrap_or_else(|_| "[]".to_string());
    let distance_metrics_json = serde_json::to_string(
        &health
            .metrics
            .architecture
            .distance_metrics
            .iter()
            .map(|m| {
                serde_json::json!({
                    "module": m.module,
                    "instability": m.instability,
                    "abstractness": m.abstractness,
                    "distance": m.distance,
                    "is_foundation": m.is_foundation,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| "[]".to_string());
    let dsm_json = serde_json::to_string(&health.metrics.dsm.top_module_edges)
        .unwrap_or_else(|_| "[]".to_string());
    let trend_json = read_trend_samples(&report.snapshot.root)
        .map(|s| serde_json::to_string(&s).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string());
    let functions_json = {
        use std::collections::HashMap;
        // group functions by file with their cyclomatic complexity from the
        // health complexity table; each entry is { path, functions: [...] }
        let mut complexity_by_function: HashMap<usize, &crate::FunctionComplexityMetric> =
            HashMap::new();
        for fc in &health.metrics.complexity.all_functions {
            complexity_by_function.insert(fc.function_id, fc);
        }
        let mut grouped: HashMap<usize, Vec<serde_json::Value>> = HashMap::new();
        for func in &report.functions {
            let lines = func.end_line.saturating_sub(func.start_line) + 1;
            let value = complexity_by_function
                .get(&func.function_id)
                .map(|fc| fc.value)
                .unwrap_or(0);
            grouped
                .entry(func.file_id)
                .or_default()
                .push(serde_json::json!({
                    "name": func.name,
                    "lines": lines,
                    "value": value,
                }));
        }
        let entries: Vec<serde_json::Value> = report
            .files
            .iter()
            .filter_map(|file| {
                grouped.get(&file.file_id).map(|fns| {
                    serde_json::json!({
                        "path": file.path.to_string_lossy(),
                        "functions": fns,
                    })
                })
            })
            .collect();
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
    };
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

    // Module edges and instability are now surfaced in the left panel as
    // text rows; the central viz is a treemap, not a node-link diagram.
    let unstable_modules = health
        .metrics
        .architecture
        .unstable_modules
        .iter()
        .take(8)
        .map(|m| {
            format!(
                "<tr><td>{}</td><td>{:.3}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&m.module),
                m.instability,
                m.fan_in,
                m.fan_out,
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let module_edges_rows = health
        .metrics
        .dsm
        .top_module_edges
        .iter()
        .take(8)
        .map(|edge| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&edge.from_module),
                html_escape(&edge.to_module),
                edge.edges,
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
    let project_name = report
        .snapshot
        .root
        .canonicalize()
        .ok()
        .as_deref()
        .and_then(|p| p.file_name())
        .or_else(|| report.snapshot.root.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| report.snapshot.root.to_string_lossy().into_owned());
    let arch = &health.metrics.architecture;
    let evo = &health.metrics.evolution;
    let cycles = arch.cycles.len();
    let upward = arch.upward_violations.len();
    let max_blast = arch.max_blast_radius;
    let attack_pct = arch.attack_surface_ratio * 100.0;
    let commits = evo.commits_sampled;
    let authors = evo.author_count;
    let changed = evo.changed_files;
    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Raysense</title>
<style>
/* Viridis-derived palette. Perceptually uniform, colorblind-safe.
 * Bright end clamped to ~0.78 so white labels remain readable on
 * the warmest tiles. */
:root{{
  --bg:#070b14;       /* deep graphite */
  --surface:#0f1320;
  --surface2:#161b2c;
  --line:#252a3d;
  --text:#e6e9ee;
  --muted:#7a8294;
  --accent:#21918c;   /* viridis mid teal */
  --good:#5ec962;     /* viridis ~0.75 green */
  --warn:#a5db36;     /* viridis ~0.85 yellow-green */
  --bad:#f85149;      /* semantic emergency, outside viridis */
}}
*{{box-sizing:border-box;}}
html,body{{margin:0;padding:0;height:100%;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;font-size:13px;line-height:1.4;}}
*{{scrollbar-color:#2a3340 #0c1014;scrollbar-width:thin;}}
*::-webkit-scrollbar{{width:10px;height:10px;}}
*::-webkit-scrollbar-track{{background:var(--bg);}}
*::-webkit-scrollbar-thumb{{background:var(--surface2);border-radius:5px;border:2px solid var(--bg);}}
*::-webkit-scrollbar-thumb:hover{{background:var(--line);}}
*::-webkit-scrollbar-corner{{background:var(--bg);}}
.app{{display:grid;grid-template-rows:auto 1fr auto;height:100vh;}}
header{{display:flex;align-items:center;gap:16px;padding:8px 16px;background:var(--surface);border-bottom:1px solid var(--line);}}
header h1{{margin:0;font-size:14px;color:var(--accent);letter-spacing:.04em;text-transform:uppercase;display:flex;gap:10px;align-items:baseline;}}
header h1 .project{{color:var(--text);font-weight:600;letter-spacing:0;text-transform:none;font-size:14px;}}
header .toolbar{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}}
header label{{color:var(--muted);font-size:12px;}}
header select,header input[type=checkbox]{{background:var(--surface2);color:var(--text);border:1px solid var(--line);padding:3px 6px;font-size:12px;}}
.body{{display:grid;grid-template-columns:300px 1fr;min-height:0;}}
aside.left{{overflow-y:auto;border-right:1px solid var(--line);padding:14px 14px;background:var(--surface);}}
aside.left h3{{margin:14px 0 6px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;}}
aside.left h3:first-child{{margin-top:0;}}
.bar{{height:6px;background:var(--surface2);margin:6px 0 10px;}}
.bar > span{{display:block;height:100%;background:var(--accent);}}
.kv{{display:grid;grid-template-columns:1fr auto auto;gap:4px 12px;align-items:baseline;font-size:12px;}}
.kv .k{{color:var(--muted);}}
.kv .v{{color:var(--text);white-space:nowrap;font-variant-numeric:tabular-nums;}}
.kv .g{{color:var(--good);font-weight:600;}}
.q-num{{font-size:32px;color:var(--text);font-weight:600;line-height:1;}}
.q-sub{{color:var(--muted);font-size:13px;font-weight:normal;}}
table.compact{{border-collapse:collapse;width:100%;font-size:11px;margin-top:4px;}}
table.compact th,table.compact td{{padding:3px 4px;border-bottom:1px solid var(--line);text-align:left;}}
table.compact th{{color:var(--muted);font-weight:normal;}}
ul.cycles{{list-style:none;margin:0;padding:0;font-size:11px;}}
ul.cycles li{{cursor:pointer;padding:3px 0;color:var(--text);border-bottom:1px solid var(--line);}}
ul.cycles li:hover{{color:var(--bad);}}
ul.cycles li.selected{{color:var(--bad);font-weight:600;}}
ul.cycles li small{{color:var(--muted);margin-left:4px;}}
#main-seq{{margin-top:6px;background:var(--bg);}}
#main-seq circle{{fill:var(--accent);}}
#main-seq circle.foundation{{fill:var(--good);}}
#main-seq circle.off{{fill:var(--bad);}}
#main-seq line.guide{{stroke:var(--line);stroke-dasharray:2 3;}}
#main-seq text{{fill:var(--muted);font-size:9px;}}
#trend-spark{{margin-top:8px;}}
#trend-spark path{{fill:none;stroke:var(--accent);stroke-width:1.5;}}
#trend-spark .last{{fill:var(--accent);}}
.dsm-grid{{display:grid;gap:1px;background:var(--line);}}
.dsm-cell{{background:var(--surface2);padding:2px 4px;font-size:10px;color:var(--text);text-align:right;font-variant-numeric:tabular-nums;}}
.dsm-row-label{{padding:2px 6px;background:var(--surface);color:var(--muted);font-size:10px;text-align:right;}}
.dsm-col-label{{padding:2px 4px;background:var(--surface);color:var(--muted);font-size:10px;text-align:left;writing-mode:vertical-rl;}}
main.canvas{{position:relative;overflow:hidden;background:var(--bg);}}
#treemap{{width:100%;height:100%;display:block;background:var(--bg);}}
.tile{{stroke:var(--bg);stroke-width:0.5;cursor:pointer;}}
.tile:hover{{stroke:var(--accent);stroke-width:2;}}
.tile.selected{{stroke:#ffd86b;stroke-width:3;}}
.tile.dim{{opacity:.18;}}
.tile.upstream{{stroke:var(--warn);stroke-width:2;}}
.tile.downstream{{stroke:var(--good);stroke-width:2;}}
.tile.cycle{{stroke:var(--bad);stroke-width:2;}}
.tile.gap{{filter:url(#stripe);}}
.tile-label{{pointer-events:none;fill:var(--text);font-size:10px;}}
.tile-lang{{pointer-events:none;fill:var(--text);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9px;font-weight:600;letter-spacing:.06em;opacity:.75;}}
.edge{{pointer-events:none;opacity:.5;fill:none;stroke-linecap:round;stroke-width:1;}}
.edge.imports{{stroke:#21918c;}}     /* viridis mid teal */
.edge.calls{{stroke:#5ec962;}}        /* viridis ~0.75 green */
.edge.inherits{{stroke:#a5db36;}}     /* viridis ~0.85 yellow-green */
.edge.dim{{opacity:.06;}}
.ribbon{{pointer-events:none;fill:none;}}
.zoom-overlay{{position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(12,16,20,0.92);z-index:4;cursor:zoom-out;}}
.zoom-overlay[hidden]{{display:none;}}
.zoom-overlay rect.fn{{fill:var(--surface2);stroke:var(--bg);}}
.zoom-overlay rect.fn:hover{{stroke:var(--accent);stroke-width:2;}}
.zoom-overlay text.fn-label{{pointer-events:none;fill:var(--text);font-size:10px;}}
.zoom-overlay text.zoom-title{{fill:var(--accent);font-size:14px;}}
.zoom-overlay text.zoom-hint{{fill:var(--muted);font-size:11px;}}
.detail{{position:absolute;top:12px;right:12px;width:280px;background:var(--surface2);border:1px solid var(--line);padding:12px;z-index:5;box-shadow:0 6px 20px rgba(0,0,0,.5);}}
.detail h3{{margin:0 0 8px;font-size:13px;word-break:break-all;color:var(--text);}}
.detail dl{{margin:0;}}
.detail dt{{color:var(--muted);font-size:11px;margin-top:6px;}}
.detail dd{{margin:0;color:var(--text);}}
.detail button{{float:right;background:var(--surface);color:var(--text);border:1px solid var(--line);padding:0 8px;cursor:pointer;font-size:14px;line-height:18px;}}
footer{{background:var(--surface);border-top:1px solid var(--line);max-height:35vh;overflow-y:auto;}}
footer details{{padding:8px 16px;}}
footer summary{{cursor:pointer;color:var(--muted);font-size:12px;}}
footer details[open] summary{{margin-bottom:8px;}}
footer .panels{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;}}
footer table{{border-collapse:collapse;width:100%;font-size:11px;}}
footer th,footer td{{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;}}
footer th{{color:var(--muted);font-weight:normal;}}
footer h4{{margin:0 0 4px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;}}
</style></head><body>
<div class="app">
<header>
<h1>raysense <span class="project">{}</span></h1>
<div class="toolbar">
<label>color <select id="color-mode"><option value="language">language</option><option value="mono">mono</option><option value="lines">lines</option><option value="churn">churn</option><option value="age">age</option><option value="risk">risk</option><option value="instability">instability</option><option value="author">author</option><option value="bus">bus factor</option><option value="test_gap">test gap</option></select></label>
<label>focus <select id="focus-mode"><option value="all">all</option><option value="language">language</option><option value="directory">directory</option><option value="entry">entry points</option><option value="impact">impact radius</option></select></label>
<select id="focus-value" hidden></select>
<label>edges <select id="edge-filter"><option value="all">all</option><option value="imports">imports</option><option value="calls">calls</option><option value="inherits">inherits</option></select></label>
<label><input type="checkbox" id="show-edges"> show edges</label>
<label><input type="checkbox" id="show-ribbons"> coupling ribbons</label>
</div>
</header>
<div class="body">
<aside class="left">
<h3>Quality</h3>
<div class="q-num" style="color:hsl({},70%,60%)">{}<span class="q-sub"> / 100</span></div>
<div class="bar"><span style="width:{}%;background:hsl({},65%,45%)"></span></div>
<svg id="trend-spark" width="100%" height="36" preserveAspectRatio="none"></svg>
<div class="kv">
<span class="k">coverage</span><span class="v">{} / 100</span><span></span>
<span class="k">structure</span><span class="v">{} / 100</span><span></span>
<span class="k">files</span><span class="v">{}</span><span></span>
<span class="k">functions</span><span class="v">{}</span><span></span>
<span class="k">rules</span><span class="v">{}</span><span></span>
</div>
<h3>Dimensions</h3>
<div class="kv">
<span class="k">modularity</span><span class="v">{} / 100</span><span class="g">{}</span>
<span class="k">acyclicity</span><span class="v">{} / 100</span><span class="g">{}</span>
<span class="k">depth</span><span class="v">{} / 100</span><span class="g">{}</span>
<span class="k">equality</span><span class="v">{} / 100</span><span class="g">{}</span>
<span class="k">redundancy</span><span class="v">{} / 100</span><span class="g">{}</span>
<span class="k">uniformity</span><span class="v">{} / 100</span><span class="g">{}</span>
</div>
<h3>Architecture</h3>
<div class="kv">
<span class="k">cycles</span><span class="v">{}</span><span></span>
<span class="k">max blast</span><span class="v">{}</span><span></span>
<span class="k">attack surface</span><span class="v">{:.0}%</span><span></span>
<span class="k">upward violations</span><span class="v">{}</span><span></span>
</div>
<svg id="main-seq" width="100%" height="160" viewBox="0 0 220 160" preserveAspectRatio="xMidYMid meet"></svg>
<h3>Evolution</h3>
<div class="kv">
<span class="k">commits sampled</span><span class="v">{}</span><span></span>
<span class="k">authors</span><span class="v">{}</span><span></span>
<span class="k">changed files</span><span class="v">{}</span><span></span>
</div>
<h3>Unstable Modules</h3>
<table class="compact"><tr><th>module</th><th>I</th><th>in</th><th>out</th></tr>{}</table>
<h3>Cycles</h3>
<ul id="cycles-list" class="cycles"></ul>
</aside>
<main class="canvas">
<svg id="treemap"></svg>
<svg id="zoom" class="zoom-overlay" hidden></svg>
<aside class="detail" id="detail" hidden>
<button id="detail-close" type="button">×</button>
<h3 id="detail-title"></h3>
<dl id="detail-body"></dl>
</aside>
</main>
</div>
<footer>
<details>
<summary>Tables</summary>
<div class="panels">
<section><h4>Module DSM</h4><div id="dsm-grid" class="dsm-grid"></div></section>
<section><h4>Module Edges</h4><table><tr><th>from</th><th>to</th><th>edges</th></tr>{}</table></section>
<section><h4>Hotspots</h4><table><tr><th>file</th><th>module</th><th>fan in</th><th>fan out</th></tr>{}</table></section>
<section><h4>Rules</h4><table><tr><th>severity</th><th>code</th><th>path</th><th>message</th></tr>{}</table></section>
<section><h4>Complexity</h4><table><tr><th>file</th><th>function</th><th>value</th></tr>{}</table></section>
<section><h4>Test Gaps</h4><table><tr><th>source</th><th>expected tests</th></tr>{}</table></section>
</div>
</details>
</footer>
</div>
<script type="application/json" id="raysense-files">{}</script>
<script type="application/json" id="raysense-adjacency">{}</script>
<script type="application/json" id="raysense-telemetry">{}</script>
<script type="application/json" id="raysense-cycles">{}</script>
<script type="application/json" id="raysense-coupling">{}</script>
<script type="application/json" id="raysense-distance">{}</script>
<script type="application/json" id="raysense-dsm">{}</script>
<script type="application/json" id="raysense-trend">{}</script>
<script type="application/json" id="raysense-functions">{}</script>
<script>
(function() {{
  var files = JSON.parse(document.getElementById('raysense-files').textContent || '[]');
  var adjacency = JSON.parse(document.getElementById('raysense-adjacency').textContent || '[]');
  var adjByPath = {{}}; adjacency.forEach(function(e){{ adjByPath[e.path] = e; }});
  var svg = document.getElementById('treemap');
  var detail = document.getElementById('detail');
  var detailTitle = document.getElementById('detail-title');
  var detailBody = document.getElementById('detail-body');
  var closeBtn = document.getElementById('detail-close');
  var colorSelect = document.getElementById('color-mode');
  var focusModeSelect = document.getElementById('focus-mode');
  var focusValueSelect = document.getElementById('focus-value');
  var edgeSelect = document.getElementById('edge-filter');
  var showEdges = document.getElementById('show-edges');
  if (!svg) return;
  var selectedPath = null;
  var ATTR = {{lines:'lines', churn:'churn', age:'age', risk:'risk', instability:'instability'}};
  var HUE = {{lines:210, churn:12, age:280, risk:350, instability:50}};
  // Viridis colormap stops (matplotlib default). 11 anchor points,
  // linearly interpolated. Input t is clamped to [0, 0.78] so the
  // brightest tiles never reach full yellow - white labels stay readable.
  var VIRIDIS = [
    [68, 1, 84],     // 0.0
    [72, 35, 116],
    [64, 67, 135],
    [52, 94, 141],
    [41, 120, 142],
    [32, 144, 140],
    [34, 167, 132],
    [68, 190, 112],
    [121, 209, 81],
    [189, 222, 38],
    [253, 231, 36]   // 1.0
  ];
  var V_MAX = 0.78;
  function viridis(t) {{
    if (!isFinite(t)) t = 0;
    t = Math.max(0, Math.min(V_MAX, t));
    var n = VIRIDIS.length - 1;
    var idx = t * n;
    var lo = Math.floor(idx);
    var hi = Math.min(lo + 1, n);
    var f = idx - lo;
    var a = VIRIDIS[lo], b = VIRIDIS[hi];
    return 'rgb(' + Math.round(a[0] + (b[0]-a[0])*f) + ',' +
                    Math.round(a[1] + (b[1]-a[1])*f) + ',' +
                    Math.round(a[2] + (b[2]-a[2])*f) + ')';
  }}
  // Pick a label colour with enough contrast against the tile fill.
  // Returns dark text on bright fills (viridis yellows/greens), and
  // null otherwise so CSS's default light text wins.
  function readableTextOn(c) {{
    var r, g, b;
    if (c[0] === '#') {{
      var hex = c.slice(1);
      if (hex.length === 3) hex = hex.split('').map(function(x){{return x+x;}}).join('');
      r = parseInt(hex.slice(0,2),16)/255;
      g = parseInt(hex.slice(2,4),16)/255;
      b = parseInt(hex.slice(4,6),16)/255;
    }} else {{
      var m = c.match(/\d+/g);
      if (!m || m.length < 3) return null;
      r = +m[0]/255; g = +m[1]/255; b = +m[2]/255;
    }}
    var lum = 0.2126*r + 0.7152*g + 0.0722*b;
    return lum > 0.55 ? '#08111c' : null;
  }}
  // Brand glyphs from Devicon (MIT) and Simple Icons (CC0).
  // Each entry carries its own viewBox so multi-source paths render correctly.
  var LANG_ICON = {{
      rust: {{d:'M62.96.242c-.232.135-1.203 1.528-2.16 3.097-2.4 3.94-2.426 3.942-5.65.55-2.098-2.208-2.605-2.612-3.28-2.607-.44.002-.995.152-1.235.332-.24.18-.916 1.612-1.504 3.183-1.346 3.6-1.41 3.715-2.156 3.86-.46.086-1.343-.407-3.463-1.929-1.565-1.125-3.1-2.045-3.411-2.045-1.291 0-1.655.706-2.27 4.4-.78 4.697-.754 4.681-4.988 2.758-1.71-.776-3.33-1.41-3.603-1.41-.274 0-.792.293-1.15.652-.652.652-.653.655-.475 4.246l.178 3.595-.68.364c-.602.322-1.017.283-3.684-.348-3.48-.822-4.216-.8-4.92.15l-.516.693.692 2.964c.38 1.63.745 3.2.814 3.487.067.287-.05.746-.26 1.02-.348.448-.717.49-3.94.44-5.452-.086-5.761.382-3.51 5.3.718 1.56 1.305 2.98 1.305 3.15 0 .898-.717 1.224-3.794 1.727-1.722.28-3.218.51-3.326.51-.107 0-.43.235-.717.522-.937.936-.671 1.816 1.453 4.814 2.646 3.735 2.642 3.75-1.73 5.421-4.971 1.902-5.072 2.37-1.287 5.96 3.525 3.344 3.53 3.295-.461 5.804C.208 62.8.162 62.846.085 63.876c-.093 1.253-.071 1.275 3.538 3.48 3.57 2.18 3.57 2.246.067 5.56C-.078 76.48.038 77 5.013 78.877c4.347 1.64 4.353 1.66 1.702 5.394-1.502 2.117-1.981 3-1.981 3.653 0 1.223.637 1.535 4.44 2.174 3.206.54 3.92.857 3.92 1.741 0 .182-.588 1.612-1.307 3.177-2.236 4.87-1.981 5.275 3.31 5.275 4.93 0 4.799-.15 3.737 4.294-.8 3.35-.813 3.992-.088 4.715.554.556 1.6.494 4.87-.289 2.499-.596 2.937-.637 3.516-.328l.66.354-.177 3.594c-.178 3.593-.177 3.595.475 4.248.358.36.884.652 1.165.652.282 0 1.903-.63 3.604-1.404 4.22-1.916 4.194-1.932 4.973 2.75.617 3.711.977 4.4 2.294 4.4.327 0 1.83-.88 3.34-1.958 2.654-1.893 3.342-2.19 4.049-1.74.182.115.89 1.67 1.572 3.455 1.003 2.625 1.37 3.31 1.929 3.576 1.062.51 1.72.1 4.218-2.62 3.016-3.286 3.14-3.27 5.602.72 2.72 4.406 3.424 4.396 6.212-.089 2.402-3.864 2.374-3.862 5.621-.47 2.157 2.25 2.616 2.61 3.343 2.61.464 0 1.019-.175 1.23-.388.214-.213.92-1.786 1.568-3.496.649-1.71 1.321-3.2 1.495-3.31.687-.436 1.398-.13 4.048 1.752 1.56 1.108 3.028 1.96 3.377 1.96 1.296 0 1.764-.92 2.302-4.535.46-3.082.554-3.378 1.16-3.685.596-.302.954-.2 3.75 1.07 1.701.77 3.323 1.402 3.604 1.402.282 0 .816-.302 1.184-.672l.672-.67-.184-3.448c-.177-3.29-.16-3.468.364-3.943.54-.488.596-.486 3.615.204 3.656.835 4.338.857 5.025.17.671-.67.664-.818-.254-4.69-1.03-4.346-1.168-4.19 3.78-4.19 3.374 0 3.75-.049 4.18-.523.718-.793.547-1.702-.896-4.779-.729-1.55-1.32-2.96-1.315-3.135.024-.914.743-1.227 4.065-1.767 2.033-.329 3.553-.71 3.829-.96.923-.833.584-1.918-1.523-4.873-2.642-3.703-2.63-3.738 1.599-5.297 5.064-1.866 5.209-2.488 1.419-6.09-3.51-3.335-3.512-3.317.333-5.677 4.648-2.853 4.655-3.496.082-6.335-3.933-2.44-3.93-2.406-.405-5.753 3.78-3.593 3.678-4.063-1.295-5.965-4.388-1.679-4.402-1.72-1.735-5.38 1.588-2.18 1.982-2.903 1.982-3.65 0-1.306-.586-1.598-4.436-2.22-3.216-.52-3.924-.835-3.924-1.75 0-.174.588-1.574 1.307-3.113 1.406-3.013 1.604-4.22.808-4.94-.428-.387-1-.443-4.067-.392-3.208.054-3.618.008-4.063-.439-.486-.488-.48-.557.278-3.725.931-3.88.935-3.975.17-4.694-.777-.73-1.262-.718-4.826.121-2.597.612-3.027.653-3.617.337l-.67-.36.185-3.582.186-3.58-.67-.67c-.369-.37-.891-.67-1.163-.67-.27 0-1.884.64-3.583 1.421-2.838 1.306-3.143 1.393-3.757 1.072-.612-.32-.714-.637-1.237-3.829-.603-3.693-.977-4.412-2.288-4.412-.311 0-1.853.925-3.426 2.055-2.584 1.856-2.93 2.032-3.574 1.807-.533-.186-.843-.59-1.221-1.599-.28-.742-.817-2.172-1.194-3.177-.762-2.028-1.187-2.482-2.328-2.482-.637 0-1.213.458-3.28 2.604-3.25 3.375-3.261 3.374-5.65-.545C66.073 1.78 65.075.382 64.81.24c-.597-.32-1.3-.32-1.85.002m2.96 11.798c2.83 2.014 1.326 6.75-2.144 6.75-3.368 0-5.064-4.057-2.66-6.36 1.358-1.3 3.304-1.459 4.805-.39m-3.558 12.507c1.855.705 2.616.282 6.852-3.8l3.182-3.07 1.347.18c4.225.56 12.627 4.25 17.455 7.666 4.436 3.14 10.332 9.534 12.845 13.93l.537.942-2.38 5.364c-1.31 2.95-2.382 5.673-2.382 6.053 0 .878.576 2.267 1.13 2.726.234.195 2.457 1.265 4.939 2.378l4.51 2.025.178 1.148c.23 1.495.26 5.167.052 6.21l-.163.816h-2.575c-2.987 0-2.756-.267-2.918 3.396-.118 2.656-.76 4.124-2.22 5.075-2.377 1.551-6.304 1.27-7.97-.57-.255-.284-.752-1.705-1.105-3.16-1.03-4.254-2.413-6.64-5.193-8.965-.878-.733-1.595-1.418-1.595-1.522 0-.102.965-.915 2.145-1.803 4.298-3.24 6.77-7.012 7.04-10.747.519-7.126-5.158-13.767-13.602-15.92-2.002-.51-2.857-.526-27.624-.526-14.057 0-25.56-.092-25.56-.204 0-.263 3.125-3.295 4.965-4.816 5.054-4.178 11.618-7.465 18.417-9.22l2.35-.61 3.34 3.387c1.839 1.863 3.64 3.5 4.003 3.637M20.3 46.34c1.539 1.008 2.17 3.54 1.26 5.062-1.405 2.356-4.966 2.455-6.373.178-2.046-3.309 1.895-7.349 5.113-5.24m90.672.13c4.026 2.454.906 8.493-3.404 6.586-2.877-1.273-2.97-5.206-.155-6.64 1.174-.6 2.523-.579 3.56.053M32.163 61.5v15.02h-13.28l-.526-2.285c-1.036-4.5-1.472-9.156-1.211-12.969l.182-2.679 4.565-2.047c2.864-1.283 4.706-2.262 4.943-2.625 1.038-1.584.94-2.715-.518-5.933l-.68-1.502h6.523V61.5M70.39 47.132c2.843.74 4.345 2.245 4.349 4.355.002 1.55-.765 2.52-2.67 3.38-1.348.61-1.562.625-10.063.708l-8.686.084v-8.92h7.782c6.078 0 8.112.086 9.288.393m-2.934 21.554c1.41.392 3.076 1.616 3.93 2.888.898 1.337 1.423 3.076 2.667 8.836 1.05 4.87 1.727 6.46 3.62 8.532 2.345 2.566 1.8 2.466 13.514 2.466 5.61 0 10.198.09 10.198.2 0 .197-3.863 4.764-4.03 4.764-.048 0-2.066-.422-4.484-.939-6.829-1.458-7.075-1.287-8.642 6.032l-1.008 4.702-.91.448c-1.518.75-6.453 2.292-9.01 2.82-4.228.87-8.828 1.162-12.871.821-6.893-.585-16.02-3.259-16.377-4.8-.075-.327-.535-2.443-1.018-4.704-.485-2.26-1.074-4.404-1.31-4.764-1.13-1.724-2.318-1.83-7.547-.674-1.98.44-3.708.796-3.84.796-.248 0-3.923-4.249-3.923-4.535 0-.09 8.728-.194 19.396-.23l19.395-.066.07-6.89c.05-4.865-.018-6.997-.23-7.25-.234-.284-1.485-.358-6.011-.358H53.32v-8.36l6.597.001c3.626.002 7.02.12 7.539.264M37.57 100.02c3.084 1.88 1.605 6.804-2.043 6.8-3.74 0-5.127-4.88-1.94-6.826 1.055-.643 2.908-.63 3.983.026m56.48.206c1.512 1.108 2.015 3.413 1.079 4.95-2.46 4.034-8.612.827-6.557-3.419 1.01-2.085 3.695-2.837 5.478-1.53', vb:128}},
      c: {{d:'M125 50c-4-32-24-50-62-50C29 0 3 24 3 64c0 39 24 64 64 64 32 0 55-19 58-50H87c-2 11-8 20-20 20-21 0-24-16-24-33 0-23 8-35 22-35 13 0 20 7 22 20z', vb:128}},
      cpp: {{d:'M63.443 0c-1.782 0-3.564.39-4.916 1.172L11.594 28.27C8.89 29.828 6.68 33.66 6.68 36.78v54.197c0 1.562.55 3.298 1.441 4.841l-.002.002c.89 1.543 2.123 2.89 3.475 3.672l46.931 27.094c2.703 1.562 7.13 1.562 9.832 0h.002l46.934-27.094c1.352-.78 2.582-2.129 3.473-3.672.89-1.543 1.441-3.28 1.441-4.843V36.779c0-1.557-.55-3.295-1.441-4.838v-.002c-.891-1.545-2.121-2.893-3.473-3.67L68.359 1.173C67.008.39 65.226 0 63.443 0zm.002 26.033c13.465 0 26.02 7.246 32.77 18.91l-16.38 9.479c-3.372-5.836-9.66-9.467-16.39-9.467-10.432 0-18.922 8.49-18.922 18.924S53.013 82.8 63.445 82.8c6.735 0 13.015-3.625 16.395-9.465l16.375 9.477c-6.746 11.662-19.305 18.91-32.77 18.91-20.867 0-37.843-16.977-37.843-37.844s16.976-37.844 37.843-37.844v-.002zM92.881 57.57h4.201v4.207h4.203v4.203h-4.203v4.207h-4.201V65.98h-4.207v-4.203h4.207V57.57zm15.765 0h4.208v4.207h4.203v4.203h-4.203v4.207h-4.208V65.98h-4.205v-4.203h4.205V57.57z', vb:128}},
      python: {{d:'M49.33 62h29.159C86.606 62 93 55.132 93 46.981V19.183c0-7.912-6.632-13.856-14.555-15.176-5.014-.835-10.195-1.215-15.187-1.191-4.99.023-9.612.448-13.805 1.191C37.098 6.188 35 10.758 35 19.183V30h29v4H23.776c-8.484 0-15.914 5.108-18.237 14.811-2.681 11.12-2.8 17.919 0 29.53C7.614 86.983 12.569 93 21.054 93H31V79.952C31 70.315 39.428 62 49.33 62zm-1.838-39.11c-3.026 0-5.478-2.479-5.478-5.545 0-3.079 2.451-5.581 5.478-5.581 3.015 0 5.479 2.502 5.479 5.581-.001 3.066-2.465 5.545-5.479 5.545zm74.789 25.921C120.183 40.363 116.178 34 107.682 34H97v12.981C97 57.031 88.206 65 78.489 65H49.33C41.342 65 35 72.326 35 80.326v27.8c0 7.91 6.745 12.564 14.462 14.834 9.242 2.717 17.994 3.208 29.051 0C85.862 120.831 93 116.549 93 108.126V97H64v-4h43.682c8.484 0 11.647-5.776 14.599-14.66 3.047-9.145 2.916-17.799 0-29.529zm-41.955 55.606c3.027 0 5.479 2.479 5.479 5.547 0 3.076-2.451 5.579-5.479 5.579-3.015 0-5.478-2.502-5.478-5.579 0-3.068 2.463-5.547 5.478-5.547z', vb:128}},
      typescript: {{d:'M2 63.91v62.5h125v-125H2zm100.73-5a15.56 15.56 0 017.82 4.5 20.58 20.58 0 013 4c0 .16-5.4 3.81-8.69 5.85-.12.08-.6-.44-1.13-1.23a7.09 7.09 0 00-5.87-3.53c-3.79-.26-6.23 1.73-6.21 5a4.58 4.58 0 00.54 2.34c.83 1.73 2.38 2.76 7.24 4.86 8.95 3.85 12.78 6.39 15.16 10 2.66 4 3.25 10.46 1.45 15.24-2 5.2-6.9 8.73-13.83 9.9a38.32 38.32 0 01-9.52-.1A23 23 0 0180 109.19c-1.15-1.27-3.39-4.58-3.25-4.82a9.34 9.34 0 011.15-.73l4.6-2.64 3.59-2.08.75 1.11a16.78 16.78 0 004.74 4.54c4 2.1 9.46 1.81 12.16-.62a5.43 5.43 0 00.69-6.92c-1-1.39-3-2.56-8.59-5-6.45-2.78-9.23-4.5-11.77-7.24a16.48 16.48 0 01-3.43-6.25 25 25 0 01-.22-8c1.33-6.23 6-10.58 12.82-11.87a31.66 31.66 0 019.49.26zm-29.34 5.24v5.12H57.16v46.23H45.65V69.26H29.38v-5a49.19 49.19 0 01.14-5.16c.06-.08 10-.12 22-.1h21.81z', vb:128}},
      javascript: {{d:'M2 1v125h125V1H2zm66.119 106.513c-1.845 3.749-5.367 6.212-9.448 7.401-6.271 1.44-12.269.619-16.731-2.059-2.986-1.832-5.318-4.652-6.901-7.901l9.52-5.83c.083.035.333.487.667 1.071 1.214 2.034 2.261 3.474 4.319 4.485 2.022.69 6.461 1.131 8.175-2.427 1.047-1.81.714-7.628.714-14.065C58.433 78.073 58.48 68 58.48 58h11.709c0 11 .06 21.418 0 32.152.025 6.58.596 12.446-2.07 17.361zm48.574-3.308c-4.07 13.922-26.762 14.374-35.83 5.176-1.916-2.165-3.117-3.296-4.26-5.795 4.819-2.772 4.819-2.772 9.508-5.485 2.547 3.915 4.902 6.068 9.139 6.949 5.748.702 11.531-1.273 10.234-7.378-1.333-4.986-11.77-6.199-18.873-11.531-7.211-4.843-8.901-16.611-2.975-23.335 1.975-2.487 5.343-4.343 8.877-5.235l3.688-.477c7.081-.143 11.507 1.727 14.756 5.355.904.916 1.642 1.904 3.022 4.045-3.772 2.404-3.76 2.381-9.163 5.879-1.154-2.486-3.069-4.046-5.093-4.724-3.142-.952-7.104.083-7.926 3.403-.285 1.023-.226 1.975.227 3.665 1.273 2.903 5.545 4.165 9.377 5.926 11.031 4.474 14.756 9.271 15.672 14.981.882 4.916-.213 8.105-.38 8.581z', vb:128}},
      go: {{d:'M108.2 64.8c-.1-.1-.2-.2-.4-.2l-.1-.1c-.1-.1-.2-.1-.2-.2l-.1-.1c-.1 0-.2-.1-.2-.1l-.2-.1c-.1 0-.2-.1-.2-.1l-.2-.1c-.1 0-.2-.1-.2-.1-.1 0-.1 0-.2-.1l-.3-.1c-.1 0-.1 0-.2-.1l-.3-.1h-.1l-.4-.1h-.2c-.1 0-.2 0-.3-.1h-2.3c-.6-13.3.6-26.8-2.8-39.6 12.9-4.6 2.8-22.3-8.4-14.4-7.4-6.4-17.6-7.8-28.3-7.8-10.5.7-20.4 2.9-27.4 8.4-2.8-1.4-5.5-1.8-7.9-1.1v.1c-.1 0-.3.1-.4.2-.1 0-.3.1-.4.2h-.1c-.1 0-.2.1-.4.2h-.1l-.3.2h-.1l-.3.2h-.1l-.3.2s-.1 0-.1.1l-.3.2s-.1 0-.1.1l-.3.2s-.1 0-.1.1l-.3.2-.1.1c-.1.1-.2.1-.2.2l-.1.1-.2.2-.1.1c-.1.1-.1.2-.2.2l-.1.1c-.1.1-.1.2-.2.2l-.1.1c-.1.1-.1.2-.2.2l-.1.1c-.1.1-.1.2-.2.2l-.1.1c-.1.1-.1.2-.2.2l-.1.1-.1.3s0 .1-.1.1l-.1.3s0 .1-.1.1l-.1.3s0 .1-.1.1l-.1.3s0 .1-.1.1c.4.3.4.4.4.4v.1l-.1.3v.1c0 .1 0 .2-.1.3v3.1c0 .1 0 .2.1.3v.1l.1.3v.1l.1.3s0 .1.1.1l.1.3s0 .1.1.1l.1.3s0 .1.1.1l.2.3s0 .1.1.1l.2.3s0 .1.1.1l.2.3.1.1.3.3.3.3h.1c1 .9 2 1.6 4 2.2v-.2C23 37.3 26.5 50 26.7 63c-.6 0-.7.4-1.7.5h-.5c-.1 0-.3 0-.5.1-.1 0-.3 0-.4.1l-.4.1h-.1l-.4.1h-.1l-.3.1h-.1l-.3.1s-.1 0-.1.1l-.3.1-.2.1c-.1 0-.2.1-.2.1l-.2.1-.2.1c-.1 0-.2.1-.2.1l-.2.1-.4.3c-.1.1-.2.2-.3.2l-.4.4-.1.1c-.1.2-.3.4-.4.5l-.2.3-.3.6-.1.3v.3c0 .5.2.9.9 1.2.2 3.7 3.9 2 5.6.8l.1-.1c.2-.2.5-.3.6-.3h.1l.2-.1c.1 0 .1 0 .2-.1.2-.1.4-.1.5-.2.1 0 .1-.1.1-.2l.1-.1c.1-.2.2-.6.2-1.2l.1-1.3v1.8c-.5 13.1-4 30.7 3.3 42.5 1.3 2.1 2.9 3.9 4.7 5.4h-.5c-.2.2-.5.4-.8.6l-.9.6-.3.2-.6.4-.9.7-1.1 1c-.2.2-.3.4-.4.5l-.4.6-.2.3c-.1.2-.2.4-.2.6l-.1.3c-.2.8 0 1.7.6 2.7l.4.4h.2c.1 0 .2 0 .4.1.2.4 1.2 2.5 3.9.9 2.8-1.5 4.7-4.6 8.1-5.1l-.5-.6c5.9 2.8 12.8 4 19 4.2 8.7.3 18.6-.9 26.5-5.2 2.2.7 3.9 3.9 5.8 5.4l.1.1.1.1.1.1.1.1s.1 0 .1.1c0 0 .1 0 .1.1 0 0 .1 0 .1.1h2.1s.1 0 .1-.1h.1s.1 0 .1-.1h.1s.1 0 .1-.1c0 0 .1 0 .1-.1l.1-.1s.1 0 .1-.1l.1-.1h.1l.2-.2.2-.1h.1l.1-.1h.1l.1-.1.1-.1.1-.1.1-.1.1-.1.1-.1.1-.1v-.1s0-.1.1-.1v-.1s0-.1.1-.1v-.1s0-.1.1-.1v-1.4s-.3 0-.3-.1l-.3-.1v-.1l.3-.1s.2 0 .2-.1l.1-.1v-2.1s0-.1-.1-.1v-.1s0-.1-.1-.1v-.1s0-.1-.1-.1c0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1 0 0 0-.1-.1-.1l-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1v-.1l-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1-.1c2-1.9 3.8-4.2 5.1-6.9 5.9-11.8 4.9-26.2 4.1-39.2h.1c.1 0 .2.1.2.1h.3s.1 0 .1.1h.1s.1 0 .1.1l.2.1c1.7 1.2 5.4 2.9 5.6-.8 1.6.6-.3-1.8-1.3-2.5zM36 23C32.8 7 58.4 4 59.3 19.6c.8 13-20 16.3-23.3 3.4zm36.1 15c-1.3 1.4-2.7 1.2-4.1.7 0 1.9.4 3.9.1 5.9-.5.9-1.5 1-2.3 1.4-1.2-.2-2.1-.9-2.6-2l-.2-.1c-3.9 5.2-6.3-1.1-5.2-5-1.2.1-2.2-.2-3-1.5-1.4-2.6.7-5.8 3.4-6.3.7 3 8.7 2.6 10.1-.2 3.1 1.5 6.5 4.3 3.8 7.1zm-7-17.5c-.9-13.8 20.3-17.5 23.4-4 3.5 15-20.8 18.9-23.4 4zM41.7 17c-1.9 0-3.5 1.7-3.5 3.8 0 2.1 1.6 3.8 3.5 3.8s3.5-1.7 3.5-3.8c0-2.1-1.5-3.8-3.5-3.8zm1.6 5.7c-.5 0-.8-.4-.8-1 0-.5.4-1 .8-1 .5 0 .8.4.8 1 0 .5-.3 1-.8 1zm27.8-6.6c-1.9 0-3.4 1.7-3.4 3.8 0 2.1 1.5 3.8 3.4 3.8s3.4-1.7 3.4-3.8c0-2.1-1.5-3.8-3.4-3.8zm1.6 5.6c-.4 0-.8-.4-.8-1 0-.5.4-1 .8-1s.8.4.8 1-.4 1-.8 1z', vb:128}},
      java: {{d:'M47.617 98.12c-19.192 5.362 11.677 16.439 36.115 5.969-4.003-1.556-6.874-3.351-6.874-3.351-10.897 2.06-15.952 2.222-25.844 1.092-8.164-.935-3.397-3.71-3.397-3.71zm33.189-10.46c-14.444 2.779-22.787 2.69-33.354 1.6-8.171-.845-2.822-4.805-2.822-4.805-21.137 7.016 11.767 14.977 41.309 6.336-3.14-1.106-5.133-3.131-5.133-3.131zm11.319-60.575c.001 0-42.731 10.669-22.323 34.187 6.024 6.935-1.58 13.17-1.58 13.17s15.289-7.891 8.269-17.777c-6.559-9.215-11.587-13.793 15.634-29.58zm9.998 81.144s3.529 2.91-3.888 5.159c-14.102 4.272-58.706 5.56-71.095.171-4.45-1.938 3.899-4.625 6.526-5.192 2.739-.593 4.303-.485 4.303-.485-4.952-3.487-32.013 6.85-13.742 9.815 49.821 8.076 90.817-3.637 77.896-9.468zM85 77.896c2.395-1.634 5.703-3.053 5.703-3.053s-9.424 1.685-18.813 2.474c-11.494.964-23.823 1.154-30.012.326-14.652-1.959 8.033-7.348 8.033-7.348s-8.812-.596-19.644 4.644C17.455 81.134 61.958 83.958 85 77.896zm5.609 15.145c-.108.29-.468.616-.468.616 31.273-8.221 19.775-28.979 4.822-23.725-1.312.464-2 1.543-2 1.543s.829-.334 2.678-.72c7.559-1.575 18.389 10.119-5.032 22.286zM64.181 70.069c-4.614-10.429-20.26-19.553.007-35.559C89.459 14.563 76.492 1.587 76.492 1.587c5.23 20.608-18.451 26.833-26.999 39.667-5.821 8.745 2.857 18.142 14.688 28.815zm27.274 51.748c-19.187 3.612-42.854 3.191-56.887.874 0 0 2.874 2.38 17.646 3.331 22.476 1.437 57-.8 57.816-11.436.001 0-1.57 4.032-18.575 7.231z', vb:128}},
      ruby: {{d:'m35.971 111.33 81.958 11.188c-9.374-15.606-18.507-30.813-27.713-46.144Zm89.71-86.383L93.513 73.339c-.462.696-1.061 1.248-.41 2.321 8.016 13.237 15.969 26.513 23.942 39.777 1.258 2.095 2.53 4.182 4.157 6.192l4.834-96.58zM16.252 66.22c.375.355 1.311.562 1.747.347 7.689-3.779 15.427-7.474 22.948-11.564 2.453-1.333 4.339-3.723 6.452-5.661 6.997-6.417 13.983-12.847 20.966-19.278.427-.395.933-.777 1.188-1.275 2.508-4.902 4.973-9.829 7.525-14.898-3.043-1.144-5.928-2.263-8.849-3.281-.396-.138-1.02.136-1.449.375-6.761 3.777-13.649 7.353-20.195 11.472-3.275 2.061-5.943 5.098-8.843 7.743-4.674 4.266-9.342 8.542-13.948 12.882a24.011 24.011 0 0 0-3.288 3.854c-3.15 4.587-6.206 9.24-9.402 14.025 1.786 1.847 3.41 3.613 5.148 5.259zm28.102-6.271-11.556 48.823 54.3-34.987zm76.631-34.846-46.15 7.71 15.662 38.096zM44.996 56.644l41.892 13.6c-5.25-12.79-10.32-25.133-15.495-37.737ZM16.831 75.643 2.169 110.691l27.925-.825Zm13.593 26.096.346-.076c3.353-13.941 6.754-27.786 10.177-42.272L18.544 71.035c3.819 9.926 7.891 20.397 11.88 30.704zm84.927-78.897c-4.459-1.181-8.918-2.366-13.379-3.539-6.412-1.686-12.829-3.351-19.237-5.052-.801-.213-1.38-.352-1.851.613-2.265 4.64-4.6 9.245-6.901 13.868-.071.143-.056.328-.111.687l41.47-6.285zM89.482 12.288l36.343 10.054-6.005-17.11-30.285 6.715ZM33.505 114.007c-4.501-.519-9.122-.042-13.687.037-3.75.063-7.5.206-11.25.323-.386.012-.771.09-1.156.506 31.003 2.866 62.005 5.732 93.007 8.6l.063-.414-29.815-4.07c-12.384-1.691-24.747-3.551-37.162-4.982ZM2.782 99.994c3.995-9.27 7.973-18.546 11.984-27.809.401-.929.37-1.56-.415-2.308-1.678-1.597-3.237-3.318-5.071-5.226-2.479 12.24-4.897 24.177-7.317 36.113l.271.127c.185-.297.411-.578.548-.897zm78.74-90.153c6.737-1.738 13.572-3.097 20.367-4.613.44-.099.87-.244 1.303-.368l-.067-.332-29.194 3.928c2.741 1.197 4.853 2.091 7.591 1.385z', vb:128}},
      markdown: {{d:'M11.95 24.348c-5.836 0-10.618 4.867-10.618 10.681v57.942c0 5.814 4.782 10.681 10.617 10.681h104.102c5.835 0 10.617-4.867 10.617-10.681V35.03c0-5.814-4.783-10.681-10.617-10.681H14.898l-.002-.002H11.95zm-.007 9.543h104.108c.625 0 1.076.423 1.076 1.14v57.94c0 .717-.453 1.14-1.076 1.14H11.949c-.623 0-1.076-.423-1.076-1.14V35.029c0-.715.451-1.135 1.07-1.138z', vb:128}},
      html: {{d:'M9.032 2l10.005 112.093 44.896 12.401 45.02-12.387L118.968 2H9.032zm89.126 26.539l-.627 7.172L97.255 39H44.59l1.257 14h50.156l-.336 3.471-3.233 36.119-.238 2.27L64 102.609v.002l-.034.018-28.177-7.423L33.876 74h13.815l.979 10.919L63.957 89H64v-.546l15.355-3.875L80.959 67H33.261l-3.383-38.117L29.549 25h68.939l-.33 3.539z', vb:128}},
      css: {{d:'M8.76 1l10.055 112.883 45.118 12.58 45.244-12.626L119.24 1H8.76zm89.591 25.862l-3.347 37.605.01.203-.014.467v-.004l-2.378 26.294-.262 2.336L64 101.607v.001l-.022.019-28.311-7.888L33.75 72h13.883l.985 11.054 15.386 4.17-.004.008v-.002l15.443-4.229L81.075 65H48.792l-.277-3.043-.631-7.129L47.553 51h34.749l1.264-14H30.64l-.277-3.041-.63-7.131L29.401 23h69.281l-.331 3.862z', vb:128}},
      shell: {{d:'M112.205 26.129 71.8 2.142A15.326 15.326 0 0 0 64.005 0c-2.688 0-5.386.717-7.796 2.152L15.795 26.14C10.976 28.999 8 34.289 8 40.018v47.975c0 5.729 2.967 11.019 7.796 13.878L56.2 125.858A15.193 15.193 0 0 0 63.995 128a15.32 15.32 0 0 0 7.796-2.142l40.414-23.987c4.819-2.86 7.796-8.16 7.796-13.878V40.007c0-5.718-2.967-11.019-7.796-13.878zm-31.29 74.907.063 3.448c0 .418-.267.889-.588 1.06l-2.046 1.178c-.321.16-.6-.032-.6-.45l-.032-3.394c-1.745.728-3.523.9-4.647.45-.214-.086-.31-.397-.225-.761l.739-3.116c.064-.246.193-.493.364-.643a.725.725 0 0 1 .193-.139c.117-.064.235-.075.332-.032 1.22.407 2.773.214 4.272-.535 1.907-.964 3.18-2.913 3.16-4.84-.022-1.757-.964-2.474-3.267-2.496-2.934.01-5.675-.567-5.718-4.894-.032-3.555 1.81-7.26 4.744-9.595l-.032-3.48c0-.428.257-.9.589-1.07l1.98-1.264c.322-.161.6.043.6.46l.033 3.48c1.456-.578 2.72-.738 3.865-.47.247.064.364.406.257.802l-.77 3.084a1.372 1.372 0 0 1-.354.622.825.825 0 0 1-.203.15c-.108.053-.204.064-.3.053-.525-.118-1.767-.385-3.727.6-2.056 1.038-2.773 2.827-2.763 4.155.022 1.585.825 2.066 3.63 2.11 3.738.064 5.344 1.691 5.387 5.45.053 3.684-1.917 7.657-4.937 10.077zm21.18-5.794c0 .322-.042.621-.31.771l-10.216 6.211c-.267.161-.482.022-.482-.3V99.29c0-.321.193-.492.46-.653l10.067-6.018c.268-.16.482-.022.482.3zm7.026-58.993L70.89 59.86c-4.765 2.784-8.278 5.911-8.288 11.662v47.107c0 3.437 1.392 5.665 3.523 6.318a12.81 12.81 0 0 1-2.12.204c-2.239 0-4.445-.61-6.383-1.757L17.219 99.408c-3.951-2.345-6.403-6.725-6.403-11.426V40.007c0-4.7 2.452-9.08 6.403-11.426L57.634 4.594a12.555 12.555 0 0 1 6.382-1.756c2.238 0 4.444.61 6.382 1.756l40.415 23.987c3.33 1.981 5.579 5.397 6.21 9.242-1.36-2.86-4.38-3.63-7.902-1.574z', vb:128}},
      csharp: {{d:'M117.5 33.5l.3-.2c-.6-1.1-1.5-2.1-2.4-2.6L67.1 2.9c-.8-.5-1.9-.7-3.1-.7-1.2 0-2.3.3-3.1.7l-48 27.9c-1.7 1-2.9 3.5-2.9 5.4v55.7c0 1.1.2 2.3.9 3.4l-.2.1c.5.8 1.2 1.5 1.9 1.9l48.2 27.9c.8.5 1.9.7 3.1.7 1.2 0 2.3-.3 3.1-.7l48-27.9c1.7-1 2.9-3.5 2.9-5.4V36.1c.1-.8 0-1.7-.4-2.6zm-53.5 70c-21.8 0-39.5-17.7-39.5-39.5S42.2 24.5 64 24.5c14.7 0 27.5 8.1 34.3 20l-13 7.5C81.1 44.5 73.1 39.5 64 39.5c-13.5 0-24.5 11-24.5 24.5s11 24.5 24.5 24.5c9.1 0 17.1-5 21.3-12.4l12.9 7.6c-6.8 11.8-19.6 19.8-34.2 19.8zM115 62h-3.2l-.9 4h4.1v5h-5l-1.2 6h-4.9l1.2-6h-3.8l-1.2 6h-4.8l1.2-6H94v-5h3.5l.9-4H94v-5h5.3l1.2-6h4.9l-1.2 6h3.8l1.2-6h4.8l-1.2 6h2.2v5zm-12.7 4h3.8l.9-4h-3.8z', vb:128}},
      crystal: {{d:'m127.806 81.328-46.325 45.987c-.185.185-.464.276-.65.185l-63.283-16.863c-.279-.095-.464-.28-.464-.464L.035 47.317c-.09-.275 0-.46.186-.645L46.55.685c.184-.185.463-.276.649-.185l63.28 16.863c.278.095.463.28.463.464L127.9 80.682c.185.275.09.46-.094.645zM65.726 31.28 3.557 47.778c-.095 0-.185.185-.095.28l45.495 45.156c.09.095.28.095.28-.09l16.675-61.748c.095 0-.09-.185-.184-.094zm0 0', vb:128}},
      dart: {{d:'M106.9 34.3c-2.6-2.6-7-5.1-11.3-6.5L118.4 93l-6.9 15.7 15.8-5.2V54.8l-20.4-20.5zm-13.5 83.8l-65-22.9c1.4 4.3 3.8 8.7 6.5 11.4l21.3 21.2 47.6.1 5.3-16.7-15.7 6.9zm-67.9-29l-.1-2.7V28.9L1.7 65.1C-.4 67.3.7 72 4 75.5l14.7 14.8 7.3 2.6c-.3-1.3-.5-2.5-.5-3.8z', vb:128}},
      docker: {{d:'M124.8 52.1c-4.3-2.5-10-2.8-14.8-1.4-.6-5.2-4-9.7-8-12.9l-1.6-1.3-1.4 1.6c-2.7 3.1-3.5 8.3-3.1 12.3.3 2.9 1.2 5.9 3 8.3-1.4.8-2.9 1.9-4.3 2.4-2.8 1-5.9 2-8.9 2H79V49H66V24H51v12H26v13H13v14H1.8l-.2 1.5c-.5 6.4.3 12.6 3 18.5l1.1 2.2.1.2c7.9 13.4 21.7 19 36.8 19 29.2 0 53.3-13.1 64.3-40.6 7.4.4 15-1.8 18.6-8.9l.9-1.8-1.6-1zM28 39h10v11H28V39zm13.1 44.2c0 1.7-1.4 3.1-3.1 3.1-1.7 0-3.1-1.4-3.1-3.1 0-1.7 1.4-3.1 3.1-3.1 1.7.1 3.1 1.4 3.1 3.1zM28 52h10v11H28V52zm-13 0h11v11H15V52zm27.7 50.2c-15.8-.1-24.3-5.4-31.3-12.4 2.1.1 4.1.2 5.9.2 1.6 0 3.2 0 4.7-.1 3.9-.2 7.3-.7 10.1-1.5 2.3 5.3 6.5 10.2 14 13.8h-3.4zM51 63H40V52h11v11zm0-13H40V39h11v11zm13 13H53V52h11v11zm0-13H53V39h11v11zm0-13H53V26h11v11zm13 26H66V52h11v11zM38.8 81.2c-.2-.1-.5-.2-.8-.2-1.2 0-2.2 1-2.2 2.2 0 1.2 1 2.2 2.2 2.2s2.2-1 2.2-2.2c0-.3-.1-.6-.2-.8-.2.3-.4.5-.8.5-.5 0-.9-.4-.9-.9.1-.4.3-.7.5-.8z', vb:128}},
      elixir: {{d:'M33.9 114c3.5 4.4 7.5 7.6 11.9 9.9-5.6-4.6-10-11.5-12-21.4-3.8-1.4-6.8-3.3-9.1-5.7 1.6 6.4 4.6 12.3 9.2 17.2zm-.6-47c-1.8-5.9-2.4-12.7-1.8-20.4-1.1 2.3-2.1 4.8-3.2 7.3-4.5 13.1-6.5 26.7-4.6 38.7 2.1 3.2 5.2 5.8 9.6 7.6-1.4-7.7-1.5-19.9 0-33.2zm2.2 33.8c0 .1 0 .1 0 0 3.2 1.2 6.8 2 11.1 2.5 3.5.6 7.3 1 11.3 1.3-8.3-9.1-15.6-19.8-20.3-28.6-1.1-1.6-2-3.3-2.8-5-1.1 12.2-.8 23.1.7 29.8zm51.4-28.7c-1.1-7.5-2.3-15.1-2.3-22.3C71.9 38 59.6 25.4 60.1 5.1c-.4.3-.8.6-1.1.9-2.2 1.9-4.4 4-6.5 6.3-4.5 6.4-8.1 14.6-10.9 23.5-1.6 11.6 9.6 34.3 24.5 51.7 7.2-.3 14.8-2.5 22.1-6.5-.4-2.9-.8-5.9-1.3-8.9zm10 39.7c-2.6-.5-5.2-1.4-7.8-2.6-1.3 4.1-3.4 7.9-6.4 11.4 1.1.3 2.1.6 3.1.7 4.2-2.5 8-5.8 11.1-9.5z', vb:128}},
      elm: {{d:'M64 60.74l25.65-25.65h-51.3L64 60.74zM7.91 4.65l25.83 25.84h56.17L64.07 4.65H7.91zM67.263 63.993l28.08-28.08 27.951 27.953-28.08 28.079zM123.35 57.42V4.65H70.58l52.77 52.77zM60.74 64L4.65 7.91V120.1L60.74 64zM98.47 95.21l24.88 24.89V70.33L98.47 95.21zM64 67.26L7.91 123.35h112.18L64 67.26z', vb:128}},
      erlang: {{d:'M18.2 24.1L1 24v80h19.7v-.1C11 93.6 5.2 79.2 5.3 62.1 5.2 47 10 33.9 18.2 24.1zm92.9 79.8zM127 24h-16.4c6.2 9 9.6 19.3 9.1 32.1.1 1.2.1 1.9 0 4.9H46.3c0 22 7.7 38.3 27.3 38.4 13.5-.1 23.2-10.1 29.9-20.9l19 9.5c-3.4 6.1-7.2 11-11.4 16H127V24zm-16.5.1zm-45.4 1.5c-9 0-16.8 7.4-17.6 16.4H81c-.3-9-6.8-16.4-15.9-16.4z', vb:128}},
      fsharp: {{d:'M0 64.5L60.7 3.8v30.4L30.4 64.5l30.4 30.4v30.4L0 64.5zm39.1 0l21.7-21.7v43.4L39.1 64.5zm88.9 0L65.1 3.8v30.4l30.4 30.4-30.4 30.3v30.4L128 64.5z', vb:128}},
      fortran: {{d:'M18.969 0C13.25 0 0 11 0 18.66v90.453c0 5.692 11.21 18.903 18.781 18.903l90.551-.032c6.738-.004 18.688-9.683 18.688-18.601V18.84c0-6.078-10.61-18.832-18.43-18.832L18.969 0zm-1.395 13.66h93.367v41.711l-10.992-.164c-.101-.098-.402-3.047-.605-5.758C98.19 36.7 95.328 29.363 89.809 26.5c-2.914-1.504-7.457-1.95-22.02-1.953l-13.57.004v31.273h2.41c4.066-.05 9.234-1.004 10.941-2.058 2.211-1.356 4.067-5.27 4.72-9.989.491-3.445.87-6.023.87-6.023h10.676v49.691H72.793v-1.957c0-3.21-1.508-10.691-2.563-12.949-1.656-3.465-4.464-4.668-12.449-5.422l-3.664-.351.203 16.113c.149 15.308.25 16.164 1.203 17.469 1.207 1.605 2.512 1.906 10.493 2.507l5.355.258-.035 10.938H17.574v-10.942l4.922-.304c9.988-.653 9.887-.602 10.39-8.43.45-7.43-.116-65.598-.452-66.762-.551-1.922-2.618-3.027-8.786-3.023l-6.074-.04V13.66z', vb:128}},
      godot: {{d:'M52.203 9.61c-5.3 1.18-10.543 2.816-15.457 5.292.113 4.34.395 8.496.961 12.72-1.906 1.222-3.914 2.273-5.695 3.702-1.813 1.395-3.66 2.727-5.301 4.36a101.543 101.543 0 00-10.316-6.004C12.543 33.824 8.94 38.297 6 43.305c2.313 3.629 4.793 7.273 7.086 10.117v30.723c.059 0 .113.003.168.007L32.09 85.97a2.027 2.027 0 011.828 1.875l.582 8.316 16.426 1.172 1.133-7.672a2.03 2.03 0 012.007-1.734h19.868a2.03 2.03 0 012.007 1.734l1.133 7.672 16.43-1.172.578-8.316a2.027 2.027 0 011.828-1.875l18.828-1.817c.055-.004.11-.007.168-.007V81.69h.008V53.42c2.652-3.335 5.16-7.019 7.086-10.116-2.941-5.008-6.543-9.48-10.395-13.625a101.543 101.543 0 00-10.316 6.004c-1.64-1.633-3.488-2.965-5.3-4.36-1.782-1.43-3.79-2.48-5.696-3.703.566-4.223.848-8.379.96-12.719-4.913-2.476-10.155-4.113-15.456-5.293-2.117 3.559-4.055 7.41-5.738 11.176-2-.332-4.008-.457-6.02-.48V20.3c-.016 0-.027.004-.039.004s-.023-.004-.04-.004v.004c-2.01.023-4.019.148-6.019.48-1.683-3.765-3.62-7.617-5.738-11.176zM37.301 54.55c6.27 0 11.351 5.079 11.351 11.345 0 6.27-5.082 11.351-11.351 11.351-6.266 0-11.348-5.082-11.348-11.351 0-6.266 5.082-11.344 11.348-11.344zm53.398 0c6.266 0 11.348 5.079 11.348 11.345 0 6.27-5.082 11.351-11.348 11.351-6.27 0-11.351-5.082-11.351-11.351 0-6.266 5.082-11.344 11.351-11.344zM64 61.189c2.016 0 3.656 1.488 3.656 3.32v10.449c0 1.832-1.64 3.32-3.656 3.32-2.02 0-3.652-1.488-3.652-3.32v-10.45c0-1.831 1.632-3.32 3.652-3.32zm0 0', vb:128}},
      graphql: {{d:'M118.238 95.328c-3.07 5.344-9.918 7.168-15.261 4.098-5.344-3.074-7.168-9.922-4.098-15.266 3.074-5.344 9.922-7.168 15.266-4.097 5.375 3.105 7.199 9.921 4.093 15.265M29.09 43.84c-3.074 5.344-9.922 7.168-15.266 4.097-5.344-3.074-7.168-9.921-4.097-15.265 3.074-5.344 9.921-7.168 15.265-4.098 5.344 3.106 7.168 9.922 4.098 15.266M9.762 95.328c-3.075-5.344-1.25-12.16 4.093-15.266 5.344-3.07 12.16-1.246 15.266 4.098 3.07 5.344 1.246 12.16-4.098 15.266-5.375 3.07-12.191 1.246-15.261-4.098M98.91 43.84c-3.07-5.344-1.246-12.16 4.098-15.266 5.344-3.07 12.16-1.246 15.265 4.098 3.07 5.344 1.247 12.16-4.097 15.266-5.344 3.07-12.192 1.246-15.266-4.098M64 126.656a11.158 11.158 0 01-11.168-11.168A11.158 11.158 0 0164 104.32a11.158 11.158 0 0111.168 11.168c0 6.145-4.992 11.168-11.168 11.168M64 23.68a11.158 11.158 0 01-11.168-11.168A11.158 11.158 0 0164 1.344a11.158 11.158 0 0111.168 11.168A11.158 11.158 0 0164 23.68', vb:128}},
      groovy: {{d:'M57.27 43.147c-6.273 10.408-6.633 10.955-7.504 11.382-.78.383-.97.407-1.287.164-1.296-.996-3.031-.705-4.248.712l-.676.787-.143-.843c-.223-1.318-.299-1.505-.842-2.092-.506-.545-.508-.564-.214-2.21.364-2.04.385-3.53.071-5.01-.613-2.894-2.139-4.224-4.845-4.224-2.341 0-5.13 1.864-8.696 5.81-2.148 2.378-5.401 6.847-6.1 8.382l-.272.597-11.193-.141c-6.967-.088-11.117-.066-10.99.059.111.11 4.892 1.949 10.624 4.087l10.423 3.887.389.909c.463 1.081 1.665 2.462 2.696 3.099l.742.459-.866.388c-.644.288-.984.63-1.325 1.331-.673 1.385-.451 2.176 1.102 3.925.698.787 1.662 2.185 2.141 3.107.58 1.114 1.099 1.815 1.548 2.088.724.442 2.059.544 2.691.206.713-.382 4.905-1.438 4.762-1.201-.077.129-2.522 3.971-5.433 8.537-2.911 4.566-5.247 8.347-5.192 8.403.056.055 8.933-3.328 19.727-7.52l19.626-7.62L83.553 88.2c10.762 4.178 19.648 7.569 19.747 7.536.098-.033-1.301-2.376-3.109-5.207l-3.288-5.147 1.135-.228c2.552-.512 5.431-2.527 6.98-4.884 2.26-3.438 2.587-7.399 1.084-13.136-.302-1.151-.499-2.142-.438-2.202.06-.06 4.99-1.933 10.956-4.161 5.966-2.229 10.931-4.135 11.034-4.236.104-.102-5.137-.129-11.888-.059-10.269.106-12.088.08-12.169-.176a12.474 12.474 0 01-.215-.853c-.141-.65-1.085-1.654-1.816-1.933-.282-.108-1.21-.21-2.062-.227-1.377-.029-1.631.031-2.298.54-.413.315-.811.765-.886 1-.181.571-.402.537-.751-.114-.812-1.518-3.259-1.842-4.504-.596l-.629.628-1.245-.617c-1.536-.761-3.42-.983-4.504-.53-.53.221-.906.255-1.279.114-.888-.337-2.307-.065-2.969.569l-.595.57-.976-.659c-.537-.362-1.246-.753-1.576-.869-.496-.174-1.676-2.002-6.881-10.66-3.455-5.747-6.342-10.45-6.416-10.45-.074 0-3.1 4.92-6.725 10.934m-18.682 1.788c1.109.776 1.382 2.983.769 6.212-.671 3.539-1.702 5.813-3.553 7.838-1.213 1.327-2.574 2.061-3.858 2.081-2.946.044-3.694-2.859-1.755-6.813.706-1.438 2.499-3.906 2.839-3.906.167 0 .677 2.003.677 2.66 0 .224-.403 1.073-.895 1.888-.717 1.187-.894 1.681-.894 2.494 0 3.113 2.902 2.729 4.473-.593 1.586-3.353 2.474-9.821 1.496-10.905-.522-.579-.832-.566-2.253.096-2.246 1.045-6.923 6.488-8.534 9.931-1.583 3.384-1.245 6.914.844 8.801 2.073 1.872 5.366 1.519 7.788-.835 1.85-1.799 3.249-4.447 3.827-7.244.348-1.68.86-1.854 1.037-.352.069.58.605 2.529 1.192 4.33 1.451 4.455 1.732 5.652 1.73 7.359-.003 1.889-.619 3.24-2.111 4.629-1.427 1.328-3.429 2.232-7.167 3.237-1.643.441-3.359.933-3.813 1.093-1.106.389-1.178.376-1.416-.248-.352-.926-1.71-2.943-2.608-3.872l-.86-.891.867-.233c2.86-.77 7.084-2.305 9.12-3.315 2.446-1.212 4.011-2.464 4.718-3.773.561-1.039.526-3.601-.067-4.871l-.447-.96-.249.64c-1.385 3.563-4.003 6.201-7.143 7.198-1.894.602-4.369.435-5.898-.396-2.676-1.457-3.167-4.382-1.37-8.167 2.085-4.395 8.022-11.31 10.979-12.787 1.541-.77 1.846-.81 2.535-.326M76.54 56.23c2.405 1.199 3.94 3.79 3.97 6.703.023 2.183-.502 3.639-1.768 4.905-1.196 1.196-2.454 1.619-4.202 1.414-2.996-.352-4.711-2.078-4.944-4.974-.24-2.992 1.276-7.128 2.998-8.178.997-.608 2.57-.556 3.946.13m-10.644.499c.364.259.951 1.082 1.348 1.887.66 1.341.703 1.564.703 3.676 0 2.11-.044 2.337-.7 3.671-1.305 2.652-3.664 4.17-6.158 3.963-1.429-.118-2.156-.616-2.814-1.929-.925-1.843-.586-5.413.797-8.384.669-1.438 2.511-3.436 3.269-3.545 1.007-.146 2.921.21 3.555.661m34.495-.459c.127.086.641 2.029 1.142 4.317.501 2.288 1.255 5.456 1.677 7.04.663 2.49.768 3.212.776 5.333.012 3.058-.363 4.391-1.75 6.233-2.407 3.196-5.96 4.412-11.737 4.015-1.324-.091-2.474-.231-2.554-.312-.08-.08.164-.387.542-.683 1.093-.856 1.787-2.241 1.914-3.821.061-.758.152-1.379.203-1.379.051 0 1.069.25 2.264.554 4.753 1.213 7.851.145 9.344-3.22.605-1.362.733-3.696.329-5.974l-.302-1.706-.03 1.28c-.016.704-.165 1.917-.33 2.697-.566 2.669-1.612 4.023-3.109 4.023-1.706 0-2.664-1.871-3.303-6.451-1.025-7.345-1.366-8.804-2.365-10.122-.598-.788-.617-.913-.22-1.456.275-.376.33-.332.825.653.292.581.938 2.303 1.435 3.828 1.344 4.122 1.929 5.129 3.276 5.641.736.28 1.854-.172 2.367-.954 1.145-1.748.933-4.101-.659-7.306a257.362 257.362 0 01-1.102-2.233c-.094-.206 1.063-.203 1.367.003m-28.051.662c-.669.94-.895 1.708-.902 3.063-.016 3.327 3.216 5.348 6.296 3.937 2.416-1.105 2.693-2.965.811-5.44-1.151-1.514-3.444-2.585-4.197-1.96-.55.456-.358 1.016.631 1.842 1.139.953 1.313 1.319.811 1.7-1.219.925-3.257-.351-3.257-2.04 0-.489.1-1.074.221-1.301.33-.617.082-.498-.414.199m15.435-.311c2.714 1.134 4.77 5.84 4.535 10.381-.124 2.407-.676 3.92-1.784 4.893-1.496 1.313-3.662.444-4.89-1.962-.569-1.116-1.076-2.882-1.915-6.678-.634-2.868-1.195-4.517-1.799-5.285-.37-.469-.378-.561-.086-.977.177-.253.404-.46.504-.46.327 0 1.038 1.771 1.587 3.957.622 2.477.971 3.384 1.619 4.208 1.021 1.297 3.093 1.66 4.109.718 1.286-1.192 1.601-2.947.905-5.042-.621-1.87-2.84-3.752-3.567-3.025-.164.163-.129.383.122.766.193.295.352.728.352.961 0 .597-.448 1.511-.741 1.511-.302 0-1.067-.698-1.514-1.379-.402-.614-.456-2.13-.091-2.569.336-.405 1.705-.414 2.654-.018m-24.628.552c-.616.616-.543.892.559 2.118.975 1.084.982 1.102.587 1.541-.22.244-.612.525-.872.624-.597.229-1.706-.142-1.986-.664-.307-.576-.253-2.245.101-3.092.447-1.07.002-.909-.746.27-1.182 1.863-1.369 4.031-.494 5.717 1.345 2.592 4.606 2.303 6.705-.594.983-1.357.782-3.022-.579-4.806-1.096-1.437-2.481-1.908-3.275-1.114M47.202 58.78c.263.803.591 1.496.73 1.539.329.104 1.765-1.2 2.519-2.289.326-.471.674-.857.773-.857.098 0 .329.292.514.649.185.358.592.747.905.866.515.196.65.129 1.429-.703l.861-.918.066.679c.125 1.288-1.479 3.458-2.902 3.928-.653.216-.862.172-2.008-.419-.966-.498-1.374-.609-1.667-.453-.572.307-.684 1.227-.319 2.622.412 1.574.843 2.425 1.669 3.296.813.857 1.703.909 3.244.191l1.07-.498.011 2.413.01 2.413-.818.327c-1.031.413-2.359.419-3.139.016-.894-.462-1.441-1.869-2.055-5.284-.711-3.954-1.229-5.526-2.137-6.489-.398-.422-.661-.876-.583-1.008.339-.578 1.198-1.632 1.27-1.56.044.043.295.736.557 1.539M93.653 73.6c0 .117-.149.213-.332.213-.183 0-.274-.096-.201-.213.073-.117.222-.213.333-.213.11 0 .2.096.2.213', vb:128}},
      haskell: {{d:'M30.1 110.2L60.2 65 30.1 19.9h22.6l60.2 90.3H90.4L71.5 81.9l-18.8 28.2H30.1zM102.9 83.8l-10-15.1H128v15.1h-25.1zM87.8 61.3l-10-15.1H128v15.1H87.8z', vb:128}},
      kotlin: {{d:'M112.484 112.484H15.516V15.516h96.968L64 64Zm0 0', vb:128}},
      lua: {{d:'M61.7 0c-1.9 0-3.8.2-5.6.4l.2 1.5c1.8-.2 3.6-.4 5.5-.4L61.7 0zm5.6 0-.1 1.5c1.8.1 3.6.3 5.4.5l.3-1.5C71 .3 69.2.1 67.3 0zm45.7.8c-7.9 0-14.4 6.3-14.4 14.3S105 29.4 113 29.4s14.3-6.4 14.3-14.3S120.9.8 113 .8zm-62.4.6c-1.8.4-3.6.9-5.4 1.4l.4 1.4c1.7-.5 3.5-1 5.3-1.4l-.3-1.4zm27.6.3-.3 1.4c1.8.4 3.6.8 5.3 1.4l.4-1.3c-1.8-.6-3.6-1.1-5.4-1.5zm-38.3 3c-1.7.7-3.4 1.5-5.1 2.3l.7 1.3c1.6-.8 3.3-1.6 5-2.3l-.6-1.3zm49 .3-.5 1.4c1.6.7 3.3 1.5 4.9 2.3l.6-1.3c-1.6-.9-3.3-1.7-5-2.4zM30 9.7c-1.6 1-3.1 2.1-4.6 3.2l.9 1.2c1.4-1.1 2.9-2.1 4.5-3.2L30 9.7zm34 5.4c-27 0-49 21.9-49 49s21.9 49 49 49 49-21.9 49-49-22-49-49-49zm-42.9 1.4c-1.4 1.2-2.7 2.5-4 3.9l1.1 1c1.2-1.3 2.5-2.6 3.9-3.8l-1-1.1zm-7.6 8.2c-1.1 1.4-2.2 2.9-3.2 4.5l1.2.8c1-1.5 2-3 3.2-4.4l-1.2-.9zm70.8 4.7c7.9 0 14.3 6.4 14.3 14.3S92.2 58 84.3 58 70 51.6 70 43.7s6.4-14.3 14.3-14.3zM7.4 34.1c-.9 1.6-1.7 3.3-2.4 5l1.4.5c.7-1.6 1.5-3.3 2.3-4.8l-1.3-.7zm113.6.8-1.3.7c.9 1.6 1.6 3.3 2.3 5l1.3-.6c-.7-1.7-1.5-3.4-2.3-5.1zM3.1 44.3c-.6 1.8-1.1 3.6-1.5 5.4L3 50c.4-1.8.9-3.5 1.5-5.2l-1.4-.5zm122.1 1-1.4.4c.6 1.7 1 3.5 1.4 5.3l1.4-.3c-.4-1.8-.9-3.6-1.4-5.4zM.5 55.1C.3 57 .1 58.8 0 60.7l1.5.1c.1-1.8.3-3.6.5-5.4l-1.5-.3zm127.1 1.1-1.5.2c.2 1.8.3 3.6.4 5.4h1.5c0-1.9-.2-3.8-.4-5.6zm-96.9.2h4.1v28.5h15.9v3.6h-20V56.4zm57.7 8.3c5.7 0 8.7 2.2 8.7 6.3v13.6c0 1.1.7 1.8 2 1.8.2 0 .4 0 .8-.1l-.1 2.8c-1.2.3-1.8.4-2.5.4-2.4 0-3.5-1.1-3.8-3.4-2.6 2.4-4.9 3.4-7.8 3.4-4.7 0-7.6-2.6-7.6-6.8 0-3 1.4-5.1 4.1-6.2 1.4-.6 2.2-.7 7.4-1.4 2.9-.4 3.8-1 3.8-2.6v-1c0-2.2-1.9-3.4-5.2-3.4-3.4 0-5.1 1.3-5.4 4.1h-3.7c.1-2.3.5-3.6 1.6-4.8 1.5-1.7 4.3-2.7 7.7-2.7zm-33.8.7h3.7v16.3c0 2.8 1.9 4.5 4.8 4.5 3.8 0 6.3-3.1 6.3-7.8v-13H73v23.1h-3.3v-3.2c-2.2 3-4.3 4.2-7.7 4.2-4.5 0-7.4-2.5-7.4-6.3V65.4zm-53.1.8-1.5.1c.1 1.9.2 3.7.5 5.6l1.4-.3c-.2-1.8-.3-3.6-.4-5.4zm124.9 1.1c-.1 1.8-.3 3.6-.5 5.4l1.5.2c.3-1.8.5-3.7.5-5.5l-1.5-.1zM2.8 77.1l-1.4.3c.4 1.8.9 3.6 1.4 5.4l1.4-.4c-.6-1.8-1-3.5-1.4-5.3zm90.6 0c-1.2.6-2 .7-5.9 1.3-3.9.5-5.6 1.8-5.6 4.2 0 2.3 1.7 3.7 4.5 3.7 2.2 0 4-.7 5.5-2.1 1.1-1 1.5-1.8 1.5-3v-4.1zm31.6.9c-.5 1.8-.9 3.6-1.5 5.3l1.4.5c.6-1.8 1.1-3.6 1.5-5.5L125 78zM6 87.5l-1.3.5c.7 1.7 1.5 3.4 2.3 5.1l1.3-.6c-.9-1.7-1.6-3.3-2.3-5zm115.7 1c-.8 1.6-1.5 3.3-2.4 4.9l1.3.7L123 89l-1.3-.5zM10.9 97.2l-1.2.8c1 1.6 2.1 3.1 3.2 4.6l1.1-.9c-1.1-1.5-2.1-3-3.1-4.5zm105.6.9c-1 1.5-2.1 3-3.2 4.4l1.2.9c1.1-1.4 2.2-3 3.2-4.5l-1.2-.8zm-98.9 7.8-1.1 1c1.2 1.4 2.5 2.7 3.9 4l1-1.1c-1.3-1.2-2.6-2.6-3.8-3.9zm92.2.8c-1.2 1.3-2.6 2.6-3.9 3.8l1 1.1c1.3-1.3 2.7-2.6 4-3.9l-1.1-1zm-84.2 6.6-.9 1.2c1.4 1.1 2.9 2.2 4.5 3.2l.8-1.2c-1.5-1-3-2.1-4.4-3.2zm76.1.7c-1.5 1.1-3 2.1-4.5 3.1l.8 1.2c1.5-1 3.1-2 4.6-3.1l-.9-1.2zm-67 5.3-.7 1.3c1.6.9 3.3 1.7 5 2.4l.6-1.3c-1.6-.8-3.3-1.5-4.9-2.4zm57.7.4c-1.7.9-3.3 1.6-5 2.3l.6 1.4c1.7-.7 3.4-1.5 5.1-2.4l-.7-1.3zm-47.7 3.8-.5 1.4c1.8.6 3.6 1.1 5.4 1.5l.4-1.4c-1.8-.5-3.6-.9-5.3-1.5zm37.6.3c-1.8.6-3.5 1-5.3 1.4l.3 1.4c1.9-.3 3.7-.8 5.4-1.4l-.4-1.4zm-27 2.2-.2 1.5c1.9.2 3.7.4 5.6.5v-1.5c-1.8-.1-3.6-.3-5.4-.5zm16.3.1c-1.8.2-3.6.3-5.4.4l.1 1.5c1.8-.1 3.7-.2 5.5-.4l-.2-1.5z', vb:128}},
      matlab: {{d:'M123.965 91.902c-7.246-18.297-13.262-37.058-20.184-55.476-3.054-7.84-6.047-15.746-10.215-23.082-1.656-2.633-3.238-5.528-5.953-7.215a4.013 4.013 0 00-2.222-.606c-1.27.028-2.536.594-3.504 1.415-3.645 2.886-5.805 7.082-8.227 10.949-4.277 7.172-8.789 14.687-15.941 19.347-3.36 2.371-7.762 2.63-11 5.172-4.43 3.34-7.442 8.078-11.074 12.184-.829.988-2.11 1.383-3.227 1.918C21.578 60.93 10.738 65.336 0 69.98c9.09 7.032 18.777 13.29 28.05 20.079 2.544-.504 5.098-1.547 7.72-1.082 4.16 1.3 6.597 5.285 8.503 8.93 3.875 7.94 6.676 16.323 9.813 24.57 5.246-.375 9.969-3.079 14.027-6.258 7.809-6.324 13.758-14.5 20.305-22.047 3.14-3.3 6.34-7.23 11.05-8.149 4.762-1.152 9.864.555 13.395 3.836 4.957 4.43 9.344 9.551 15.137 12.942-.777-3.836-2.645-7.278-4.035-10.899zM42.96 79.012c-4.57 2.703-9.426 4.93-14.176 7.289-7.457-4.996-14.723-10.29-22.05-15.465 9.878-4.328 19.91-8.348 29.917-12.387 4.746 3.703 9.637 7.223 14.383 10.926-2.23 3.563-4.914 6.871-8.074 9.637zm10.168-12.414C48.414 63.058 43.64 59.609 39 55.977c2.977-4.055 6.238-7.977 10.14-11.172 2.587-1.657 5.743-2.117 8.426-3.61 6.368-3.18 10.711-9.011 14.86-14.582-5.317 13.805-10.992 27.664-19.297 39.985zm0 0', vb:128}},
      nim: {{d:'M64.508 20.135v.004s-4.905 3.873-9.906 7.726a70.222 70.222 0 0 0-20.696 2.975c-5.028-3.2-9.463-6.715-9.463-6.715s-3.78 6.505-6.158 10.322a52.032 52.032 0 0 0-10.22 6.776C4.393 39.773.136 37.989 0 37.943c4.86 9.806 8.129 19.622 17.016 25.524 14.171-22.35 79.908-20.294 94.35-.13 9.32-4.881 12.977-15.335 16.634-25.026-.402.132-5.398 1.804-8.635 3.039a52.521 52.521 0 0 0-9.08-6.903c-2.455-4.498-6.03-10.574-6.03-10.574s-4.237 3.151-9.142 6.584a97.211 97.211 0 0 0-21.398-2.342c-4.572-3.776-9.207-7.98-9.207-7.98zm59.373 38.468a61.161 61.161 0 0 1-21.028 17.686 55.85 55.85 0 0 1-13.636 3.625L64.232 66.97 39.09 79.654a71.675 71.675 0 0 1-13.637-3.492 64.347 64.347 0 0 1-20.424-17.4l11.674 28.275c20.274 26.743 72.042 28.603 94.63.516 5.338-12.037 12.548-28.95 12.548-28.95z', vb:128}},
      ocaml: {{d:'M65.004 115.355c-.461-.894-1.004-2.796-1.356-3.601-.378-.711-1.46-2.692-1.984-3.332-1.164-1.332-1.437-1.438-1.809-3.23-.628-3.067-2.148-8.462-4.042-12.227-1.004-2-2.626-3.606-4.067-5.07-1.246-1.247-4.121-3.31-4.668-3.227-4.766.894-6.226 5.586-8.457 9.27-1.27 2.062-2.516 3.769-3.52 5.937-.898 1.98-.812 4.23-2.331 5.938a15.44 15.44 0 00-3.333 5.855c-.195.453-.546 4.957-1.003 6.016l7.02-.438c6.585.461 4.687 2.961 14.858 2.438l16.098-.54a24.864 24.864 0 00-1.433-3.792zM111.793 8.254H16.207C7.312 8.23.086 15.457.086 24.352v35.105c2.352-.812 5.578-5.75 6.668-6.934 1.789-2.062 2.16-4.77 3.059-6.378 2.062-3.793 2.433-6.477 7.101-6.477 2.164 0 3.063.516 4.5 2.516.996 1.332 2.79 3.957 3.602 5.668 1.004 1.98 2.523 4.582 3.254 5.125.515.351.972.722 1.433.894.707.27 1.356-.27 1.902-.629.622-.539.895-1.52 1.52-2.953.895-2.086 1.813-4.418 2.332-5.312.914-1.461 1.273-3.254 2.25-4.067 1.461-1.246 3.441-1.355 3.957-1.437 2.98-.625 4.336 1.437 5.777 2.707.973.894 2.243 2.605 3.246 4.851.708 1.793 1.606 3.52 2.067 4.5.351.98 1.266 2.606 1.789 4.582.543 1.711 1.809 3.067 2.352 3.961 0 0 .812 2.164 5.476 4.145a34.992 34.992 0 004.336 1.52c2.066.734 4.047.644 6.563.374 1.789 0 2.793-2.625 3.601-4.683.438-1.254.98-4.774 1.25-5.758.27-.996-.437-1.707.192-2.625.722-.977 1.164-1.082 1.519-2.332.914-2.793 5.957-2.875 8.832-2.875 2.414 0 2.063 2.332 6.125 1.52 2.336-.434 4.586.273 7.023.995 2.063.543 4.043 1.168 5.204 2.524.73.898 2.629 5.312.73 5.476.164.188.36.645.625.817-.46 1.707-2.25.46-3.332.27-1.355-.27-2.332 0-3.684.624-2.335.996-5.668.918-7.726 2.625-1.715 1.438-1.715 4.582-2.543 6.371 0 0-2.254 5.696-6.996 9.192-1.278.914-3.715 3.058-8.918 3.871-2.356.355-4.586.355-7.024.27-1.164-.079-2.332-.079-3.52-.079-.706 0-3.062-.109-2.96.164l-.27.645c.024.29.063.602.164.895.102.515.102.976.192 1.437 0 .98-.086 2.063 0 3.066.082 2.063.894 3.957 1.004 6.102.078 2.355 1.246 4.875 2.414 6.77.46.707 1.086.789 1.355 1.71.352.98 0 2.141.188 3.227.625 4.227 1.875 8.73 3.773 12.61v.078c2.332-.352 4.77-1.247 7.836-1.684 5.664-.832 13.5-.461 18.54-.914 12.796-1.168 19.706 5.226 31.148 2.601V24.336c-.063-8.895-7.293-16.102-16.207-16.102zM64.086 83.855c0-.187 0-.187 0 0zm-34.457 14.75c.894-1.98 1.433-4.125 2.144-6.101.73-1.899 1.813-4.61 3.684-5.582-.246-.274-3.957-.375-4.934-.461-1.082-.086-2.171-.273-3.25-.438a135.241 135.241 0 01-6.125-1.265c-1.168-.274-5.21-1.715-6.02-2.067-2.085-.894-3.421-3.52-4.96-3.246-.977.188-1.98.54-2.605 1.54-.543.812-.731 2.242-1.083 3.226-.437 1.086-1.168 2.164-1.707 3.25-1.277 1.875-3.332 3.582-4.23 5.484-.191.457-.27.895-.457 1.356v21.683c1.082.188 2.16.371 3.328.73 8.996 2.438 11.164 2.606 19.98 1.63l.813-.11c.625-1.437 1.188-6.207 1.629-7.644.352-1.164.812-2.063.996-3.14.164-1.09 0-2.173-.102-3.15-.171-2.628 1.895-3.519 2.899-5.69zm0 0', vb:128}},
      perl: {{d:'M53.343 127.515c-13.912-2.458-25.845-8.812-35.707-19.004C9.252 99.845 3.48 88.926.851 76.764-.284 71.51-.284 56.477.85 51.222c1.776-8.219 5.228-16.388 9.927-23.509 3.112-4.71 12.227-13.825 16.938-16.937 7.121-4.698 15.292-8.15 23.511-9.925 5.256-1.135 20.29-1.135 25.546 0 12.809 2.769 23.454 8.553 32.638 17.736 9.188 9.187 14.969 19.827 17.738 32.635 1.135 5.255 1.135 20.287 0 25.542-2.769 12.808-8.55 23.452-17.738 32.635-9.043 9.042-19.55 14.81-32.146 17.652-4.469 1.005-19.24 1.295-23.922.464zm11.565-12.772c0-4.194-.06-4.496-.908-4.496-.84 0-.904.29-.868 3.899.04 4.262.34 5.574 1.207 5.284.404-.134.57-1.494.57-4.687zm-6.758 1.445c1.196-1.194 1.543-1.917 1.543-3.209 0-1.315-.162-1.634-.763-1.517-.416.08-.92.759-1.114 1.505-.198.751-1.002 1.906-1.785 2.572-1.417 1.194-1.47 2.191-.121 2.191.384 0 1.393-.694 2.24-1.542zm14.945 1.05c.166-.271-.339-1.037-1.126-1.699-.783-.666-1.587-1.821-1.784-2.572-.194-.746-.699-1.425-1.115-1.505-.601-.117-.763.202-.763 1.517 0 2.608 3.747 5.942 4.788 4.259zm-20.66-8.146c0-.262-.635-.823-1.41-1.247-5.058-2.769-10.984-7.177-14.282-10.612-6.435-6.704-9.33-13.385-9.402-21.676-.044-5.542.67-8.432 3.367-13.607 2.608-5 5.631-8.779 13.947-17.42 9.29-9.648 11.429-12.195 13.043-15.53 1.147-2.369 1.296-3.232 1.458-8.238.197-6.216-.182-10.506-.929-10.506-.339 0-.403 1.614-.21 5.235.622 11.593-1.53 15.19-14.892 24.88-9.2 6.677-13.422 10.302-16.612 14.261-4.517 5.615-6.52 10.471-7.02 17.054-1.207 15.868 8.85 29.628 26.591 36.385 3.916 1.49 6.35 1.881 6.35 1.021zm30.696-1.287c6.1-2.539 10.738-5.611 15.11-10.007 6.665-6.7 9.442-12.965 9.858-22.24.363-8.134-1.405-13.515-6.439-19.61-3.447-4.173-7.161-7.16-17.173-13.812-13.47-8.95-16.632-12.513-16.632-18.746 0-1.659.299-4.004.662-5.219.622-2.066.606-3.491-.02-1.857-.593 1.546-1.946.836-2.676-1.408l-.703-2.156.267 2.043c.94 7.241 1.061 10.272.641 16.614-.56 8.565-1.614 14.426-4.505 25.074-2.87 10.572-3.387 14.402-3.031 22.475.298 6.826 1.255 11.932 3.475 18.592 2.06 6.188 2.443 6.656 6.23 7.625 2.086.533 4.06 1.433 5.63 2.567 1.474 1.066 2.952 1.76 3.78 1.776.75.012 3.237-.759 5.526-1.711zm-1.369-3.076c-.565-.565-.302-1.046 1.91-3.492 6.972-7.697 10.096-15.645 10.185-25.906.06-6.995-1.482-11.625-6.197-18.592-2.135-3.152-9.636-11.011-13.265-13.893-2.664-2.115-5.397-5.72-5.886-7.762-.496-2.067.888-1.522 2.495.985.787 1.227 2.495 3.027 3.79 4 1.297.977 5.132 3.834 8.523 6.357 11.666 8.67 16.858 16.065 18.024 25.668.679 5.558-.395 11.302-3.108 16.634-2.81 5.526-7.937 11.545-12.325 14.479-2.7 1.8-3.552 2.115-4.146 1.522zm-22.836.585c.133-.343-1.034-2.535-2.592-4.872-4.13-6.192-5.926-9.61-7.602-14.454-1.413-4.09-1.49-4.646-1.501-10.887-.016-9.433 1.005-12.424 8.49-24.848 7.056-11.722 8.013-16.259 7.217-34.286-.286-6.462-.61-11.839-.718-11.948-.747-.746-.904 1.167-.63 7.665.549 12.941-.287 20.15-3.016 26.064-1.857 4.024-3.936 7.076-9.53 14.002-7.788 9.64-9.984 14.75-9.944 23.125.029 5.744.808 9.276 3.129 14.188 2.51 5.316 7.133 10.685 12.926 15.012 2.669 1.99 3.391 2.228 3.77 1.239z', vb:128}},
      php: {{d:'M64 30.332C28.654 30.332 0 45.407 0 64s28.654 33.668 64 33.668c35.345 0 64-15.075 64-33.668S99.346 30.332 64 30.332zm-5.982 9.81h7.293v.003l-1.745 8.968h6.496c4.087 0 6.908.714 8.458 2.139 1.553 1.427 2.017 3.737 1.398 6.93l-3.053 15.7h-7.408l2.902-14.929c.33-1.698.208-2.855-.365-3.473-.573-.617-1.793-.925-3.658-.925h-5.828L58.752 73.88h-7.291l6.557-33.738zM26.73 49.114h14.133c4.252 0 7.355 1.116 9.305 3.348 1.95 2.232 2.536 5.346 1.758 9.346-.32 1.649-.863 3.154-1.625 4.52-.763 1.364-1.76 2.613-2.99 3.745-1.468 1.373-3.098 2.353-4.891 2.936-1.794.585-4.08.875-6.858.875h-6.294l-1.745 8.97h-7.35l6.557-33.74zm57.366 0h14.13c4.252 0 7.353 1.116 9.303 3.348h.002c1.95 2.232 2.538 5.346 1.76 9.346-.32 1.649-.861 3.154-1.623 4.52-.763 1.364-1.76 2.613-2.992 3.745-1.467 1.373-3.098 2.353-4.893 2.936-1.794.585-4.077.875-6.855.875h-6.295l-1.744 8.97h-7.35l6.557-33.74zm-51.051 5.325-2.742 14.12h4.468c2.963 0 5.172-.556 6.622-1.673 1.45-1.116 2.428-2.981 2.937-5.592.485-2.507.264-4.279-.666-5.309-.93-1.032-2.79-1.547-5.584-1.547h-5.035zm57.363 0-2.744 14.12h4.47c2.965 0 5.17-.556 6.622-1.673 1.449-1.116 2.427-2.981 2.935-5.592.487-2.507.266-4.279-.664-5.309-.93-1.032-2.792-1.547-5.584-1.547h-5.035z', vb:128}},
      powershell: {{d:'M124.912 19.358c-.962-1.199-2.422-1.858-4.111-1.858h-92.61c-3.397 0-6.665 2.642-7.444 6.015L2.162 104.022c-.396 1.711-.058 3.394.926 4.619.963 1.199 2.423 1.858 4.111 1.858v.001H99.81c3.396 0 6.665-2.643 7.443-6.016l18.586-80.508c.395-1.711.057-3.395-.927-4.618zm-98.589 77.17c-1.743-2.397-1.323-5.673.94-7.318l37.379-27.067v-.556L41.157 36.603c-1.916-2.038-1.716-5.333.445-7.361 2.162-2.027 5.466-2.019 7.382.019l28.18 29.979c1.6 1.702 1.718 4.279.457 6.264-.384.774-1.182 1.628-2.593 2.618l-41.45 29.769c-2.263 1.644-5.512 1.034-7.255-1.363zm59.543.538H63.532c-2.597 0-4.702-2.082-4.702-4.65s2.105-4.65 4.702-4.65h22.333c2.597 0 4.702 2.082 4.702 4.65s-2.104 4.65-4.701 4.65z', vb:128}},
      r: {{d:'M64 14.6465v.002c-35.346 0-64 19.1902-64 42.8632 0 20.764 22.0464 38.0766 51.3164 42.0176v-12.83c-15.55-4.89-26.166-14.6943-26.166-25.9923 0-16.183 21.7795-29.3027 48.6465-29.3027 26.866 0 46.6914 8.9748 46.6914 29.3027 0 10.486-5.2715 17.9507-14.0645 22.7207 1.204.908 2.2184 2.073 2.9024 3.42l.3886.6543C121.0248 79.772 128 69.1888 128 57.5098c0-23.672-28.654-42.8633-64-42.8633zM52.7363 41.2637v72.084l21.834-.0098-.0039-28.2188h5.8613c1.199 0 1.7167.3481 2.9297 1.3301 1.454 1.177 3.8164 5.2383 3.8164 5.2383l11.5371 21.666 24.6739-.0097-15.2657-25.7403a8.388 8.388 0 0 0-1.4199-2.041c-.974-1.036-2.3255-1.8227-3.1055-2.2188-2.249-1.1375-6.12-2.3076-6.123-2.3085 0 0 19.08-1.4151 19.08-20.4141 0-18.999-19.9706-19.3574-19.9706-19.3574H52.7363zm22.0176 15.627 13.2188.0077s6.123-.3302 6.123 6.0098c0 6.216-6.123 6.2344-6.123 6.2344l-13.2247.0039.006-12.2559zm9.3457 32.6366c-2.612.257-5.3213.411-8.1133.463l.002 9.6288a88.362 88.362 0 0 0 12.4746-2.4902l-.502-.9414c-.68-1.268-1.3472-2.5426-2.0332-3.8066a41.01 41.01 0 0 0-1.828-2.8516v-.002z', vb:128}},
      scala: {{d:'M25.411 110.572V95.077l11.842-.474c12.315-.473 21.45-1.488 34.847-3.789 15.225-2.639 30.246-7.375 31.803-10.082.406-.677.676 4.534.676 14.616v15.698l-1.76 1.353c-1.894 1.489-9.202 3.993-17.524 6.09C72.303 121.737 40.568 126 29.742 126h-4.33zM25.411 71.327V55.83l11.842-.406c13.127-.541 23.344-1.691 36.877-4.195 15.157-2.842 28.96-7.443 29.976-9.947.203-.473.406 6.09.406 14.616.067 13.533-.068 15.698-1.083 16.78-2.368 2.64-20.638 7.376-39.449 10.286-11.435 1.76-30.381 3.79-35.66 3.79h-2.909zM25.411 32.352V17.195l2.098-.406c1.15-.203 3.992-.406 6.293-.406 11.367 0 38.366-3.722 51.628-7.105 9.27-2.436 15.698-4.872 17.931-6.902 1.15-1.015 1.218-.406 1.218 14.48 0 14.548-.067 15.63-1.285 16.714-1.827 1.691-14.345 5.548-24.09 7.51-15.765 3.113-41.951 6.429-50.883 6.429h-2.91z', vb:128}},
      solidity: {{d:'M43.322 0L22.756 36.576l20.566 36.561 20.564-36.561h41.143L84.465 0H43.322zm41.342 54.863L64.1 91.424H22.955L43.519 128h41.145l20.58-36.576-20.58-36.561z', vb:128}},
      svelte: {{d:'M110.293 16.914C98.586-.086 75.668-5 58.02 5.707l-29.856 18.98a33.94 33.94 0 00-15.418 22.938 35.543 35.543 0 003.566 23.102 33.01 33.01 0 00-5.066 12.793 36.517 36.517 0 006.191 27.52c11.727 16.96 34.583 21.897 52.27 11.312l29.879-19a34.025 34.025 0 0015.355-22.938 35.44 35.44 0 00-3.586-23.02c7.938-12.456 7.52-28.48-1.062-40.48zm-55.254 95.773a23.645 23.645 0 01-25.394-9.433c-3.461-4.793-4.73-10.711-3.73-16.586l.585-2.832.54-1.75 1.605 1.062c3.52 2.668 7.46 4.582 11.668 5.875l1.082.375-.122 1.067c-.105 1.48.332 3.144 1.188 4.414 1.75 2.52 4.793 3.73 7.727 2.937.644-.207 1.273-.418 1.812-.754l29.754-18.976c1.5-.961 2.457-2.398 2.832-4.106.328-1.773-.106-3.585-1.066-5.02-1.774-2.46-4.793-3.565-7.727-2.831-.645.226-1.332.48-1.879.812l-11.25 7.145c-10.644 6.328-24.394 3.355-31.46-6.832a21.854 21.854 0 01-3.75-16.586 20.643 20.643 0 019.456-13.875l29.692-18.98c1.875-1.168 3.894-2.02 6.082-2.668 9.605-2.5 19.726 1.27 25.394 9.394a22.027 22.027 0 013.043 19.398l-.543 1.77-1.539-1.062a39.399 39.399 0 00-11.727-5.875l-1.066-.313.106-1.066c.105-1.563-.332-3.207-1.188-4.48-1.754-2.52-4.793-3.583-7.727-2.833-.644.211-1.273.418-1.812.754L45.812 49.977c-1.5 1-2.46 2.394-2.773 4.144-.312 1.707.106 3.582 1.066 4.957 1.708 2.524 4.81 3.586 7.688 2.832.687-.207 1.332-.414 1.855-.75l11.375-7.254c1.856-1.226 3.938-2.12 6.067-2.707 9.668-2.52 19.75 1.274 25.394 9.438 3.461 4.793 4.793 10.707 3.832 16.52a20.487 20.487 0 01-9.332 13.874L61.23 109.97a25.82 25.82 0 01-6.187 2.707zm0 0', vb:128}},
      swift: {{d:'M125.54 26.23a28.78 28.78 0 00-2.65-7.58 28.84 28.84 0 00-4.76-6.32 23.42 23.42 0 00-6.62-4.55 27.27 27.27 0 00-7.68-2.53c-2.65-.51-5.56-.51-8.21-.76H30.25a45.46 45.46 0 00-6.09.51 21.81 21.81 0 00-5.82 1.52c-.53.25-1.32.51-1.85.76a33.82 33.82 0 00-5 3.28c-.53.51-1.06.76-1.59 1.26a22.41 22.41 0 00-4.76 6.32 23.61 23.61 0 00-2.65 7.58 78.47 78.47 0 00-.79 7.83v60.39a39.32 39.32 0 00.79 7.83 28.78 28.78 0 002.65 7.58 28.84 28.84 0 004.76 6.32 23.42 23.42 0 006.62 4.55 27.27 27.27 0 007.68 2.53c2.65.51 5.56.51 8.21.76h63.22a45.08 45.08 0 008.21-.76 27.27 27.27 0 007.68-2.53 30.13 30.13 0 006.62-4.55 22.41 22.41 0 004.76-6.32 23.61 23.61 0 002.65-7.58 78.47 78.47 0 00.79-7.83V34.06a39.32 39.32 0 00-.8-7.83zm-18.79 75.54C101 91 90.37 94.33 85 96.5c-11.11 6.13-26.38 6.76-41.75.47A64.53 64.53 0 0113.84 73a50 50 0 0010.85 6.32c15.87 7.1 31.73 6.61 42.9 0-15.9-11.66-29.4-26.82-39.46-39.2a43.47 43.47 0 01-5.29-6.82c12.16 10.61 31.5 24 38.38 27.79a271.77 271.77 0 01-27-32.34 266.8 266.8 0 0044.47 34.87c.71.38 1.26.7 1.7 1a32.71 32.71 0 001.21-3.51c3.71-12.89-.53-27.54-9.79-39.67C93.25 33.81 106 57.05 100.66 76.51c-.14.53-.29 1-.45 1.55l.19.22c10.6 12.63 7.67 26.02 6.35 23.49z', vb:128}},
      terraform: {{d:'M46.324 26.082L77.941 44.5v36.836L46.324 62.918zm0 0M81.41 44.5v36.836l31.633-18.418V26.082zm0 0M11.242 5.523V42.36L42.86 60.777V23.941zm0 0M77.941 85.375L46.324 66.957v36.824L77.941 122.2zm0 0', vb:128}},
      vue: {{d:'M0 8.934l49.854.158 14.3 24.415 14.3-24.415 49.548-.158-63.835 110.134zm126.987.637l-24.37.021-38.473 66.053L25.692 9.592l-24.75-.02 63.212 107.89z', vb:128}},
      zig: {{d:'M125.49 5.438L43.503 103.32 2.51 122.562l81.987-98.719zM117.96 23.843l-.836 15.06-15.059 4.182z', vb:128}},
      toml: {{d:'M.014 0h5.34v2.652H2.888v18.681h2.468V24H.015V0Zm17.622 5.049v2.78h-4.274v12.935h-3.008V7.83H6.059V5.05h11.577ZM23.986 24h-5.34v-2.652h2.467V2.667h-2.468V0h5.34v24Z', vb:24}},
      yaml: {{d:'m0 .97 4.111 6.453v4.09h2.638v-4.09L11.053.969H8.214L5.58 5.125 2.965.969Zm12.093.024-4.47 10.544h2.114l.97-2.345h4.775l.804 2.345h2.26L14.255.994Zm1.133 2.225 1.463 3.87h-3.096zm3.06 9.475v10.29H24v-2.199h-5.454v-8.091zm-12.175.002v10.335h2.217v-7.129l2.32 4.792h1.746l2.4-4.96v7.295h2.127V12.696h-2.904L9.44 17.37l-2.455-4.674Z', vb:24}},
      json: {{d:'M12.043 23.968c.479-.004.953-.029 1.426-.094a11.805 11.805 0 003.146-.863 12.404 12.404 0 003.793-2.542 11.977 11.977 0 002.44-3.427 11.794 11.794 0 001.02-3.476c.149-1.16.135-2.346-.045-3.499a11.96 11.96 0 00-.793-2.788 11.197 11.197 0 00-.854-1.617c-1.168-1.837-2.861-3.314-4.81-4.3a12.835 12.835 0 00-2.172-.87h-.005c.119.063.24.132.345.201.12.074.239.146.351.225a8.93 8.93 0 011.559 1.33c1.063 1.145 1.797 2.548 2.218 4.041.284.982.434 1.998.495 3.017.044.743.044 1.491-.047 2.229-.149 1.27-.554 2.51-1.228 3.596a7.475 7.475 0 01-1.903 2.084c-1.244.928-2.877 1.482-4.436 1.114a3.916 3.916 0 01-.748-.258 4.692 4.692 0 01-.779-.45 6.08 6.08 0 01-1.244-1.105 6.507 6.507 0 01-1.049-1.747 7.366 7.366 0 01-.494-2.54c-.03-1.273.225-2.553.854-3.67a6.43 6.43 0 011.663-1.918c.225-.178.464-.333.704-.479l.016-.007a5.121 5.121 0 00-1.441-.12 4.963 4.963 0 00-1.228.24c-.359.12-.704.27-1.019.45a6.146 6.146 0 00-.733.494c-.211.18-.42.36-.615.555-1.123 1.153-1.768 2.682-2.022 4.256-.15.973-.15 1.96-.091 2.95.105 1.395.391 2.787.945 4.062a8.518 8.518 0 001.348 2.173 8.14 8.14 0 003.132 2.23 7.934 7.934 0 002.113.54c.074.015.149.015.209.015zm-2.934-.398a4.102 4.102 0 01-.45-.228 8.5 8.5 0 01-2.038-1.534c-1.094-1.137-1.827-2.566-2.247-4.08a15.184 15.184 0 01-.495-3.172 12.14 12.14 0 01.046-2.082c.135-1.257.495-2.501 1.124-3.58a6.889 6.889 0 011.783-2.053 6.23 6.23 0 011.633-.9 5.363 5.363 0 013.522-.045c.029 0 .029 0 .045.03.015.015.045.015.06.03.045.016.104.045.165.074.239.12.479.271.704.42a6.294 6.294 0 012.097 2.502c.42.914.615 1.934.631 2.938.014 1.079-.18 2.157-.645 3.146a6.42 6.42 0 01-2.638 2.832c.09.03.18.045.271.075.225.044.449.074.688.074 1.468.045 2.892-.66 3.94-1.647.195-.18.375-.375.54-.585.225-.27.435-.54.614-.823.239-.375.435-.75.614-1.154a8.112 8.112 0 00.509-1.664c.196-1.004.211-2.022.149-3.026-.135-2.022-.673-4.045-1.842-5.724a9.054 9.054 0 00-.555-.719 9.868 9.868 0 00-1.063-1.034 8.477 8.477 0 00-1.363-.915 9.927 9.927 0 00-1.692-.598l-.3-.06c-.209-.03-.42-.044-.634-.06a8.453 8.453 0 00-1.015.016c-.704.045-1.412.16-2.112.337C5.799 1.227 2.863 3.566 1.3 6.67A11.834 11.834 0 00.238 9.801a11.81 11.81 0 00-.104 3.775c.12 1.02.374 2.023.778 2.977.227.57.511 1.124.825 1.648 1.094 1.783 2.683 3.236 4.51 4.24.688.39 1.408.69 2.157.944.226.074.45.15.689.21z', vb:24}},
  }};
  // Languages sampled from viridis. All values stay below V_MAX so
  // even the warmest tiles remain dark enough for white labels.
  var LANG = {{
    rust:       viridis(0.78), // warmest in our clamped range
    c:          viridis(0.45),
    cpp:        viridis(0.55),
    python:     viridis(0.62),
    typescript: viridis(0.30),
    javascript: viridis(0.72),
    go:         viridis(0.50),
    java:       viridis(0.78),
    ruby:       viridis(0.78),
    markdown:   viridis(0.18),
    toml:       viridis(0.18),
    yaml:       viridis(0.18),
    json:       viridis(0.18),
    html:       viridis(0.74),
    css:        viridis(0.35),
    shell:      viridis(0.58)
  }};
  var pathToRect = {{}};

  function squarify(items, x, y, w, h, total) {{
    var out = [];
    if (!items.length || w <= 0 || h <= 0 || total <= 0) return out;
    var idx = 0;
    while (idx < items.length) {{
      var row = []; var bestAR = Infinity; var k = idx;
      while (k < items.length) {{
        var attempt = row.concat([items[k]]);
        var sumW = attempt.reduce(function(s,it){{return s+it.weight;}}, 0);
        var ar = worstAR(attempt, sumW, total, w, h);
        if (row.length > 0 && ar > bestAR) break;
        row = attempt; bestAR = ar; k++;
      }}
      var rowSum = row.reduce(function(s,it){{return s+it.weight;}}, 0);
      if (rowSum <= 0) break;
      var ratio = rowSum / total;
      if (w >= h) {{
        var stripW = w * ratio; var yo = y;
        row.forEach(function(it){{
          var itH = h * (it.weight / rowSum);
          out.push({{path:it.path, x:x, y:yo, w:stripW, h:itH, item:it.item}});
          yo += itH;
        }});
        x += stripW; w -= stripW;
      }} else {{
        var stripH = h * ratio; var xo = x;
        row.forEach(function(it){{
          var itW = w * (it.weight / rowSum);
          out.push({{path:it.path, x:xo, y:y, w:itW, h:stripH, item:it.item}});
          xo += itW;
        }});
        y += stripH; h -= stripH;
      }}
      total -= rowSum; idx = k;
    }}
    return out;
  }}
  function worstAR(row, sumW, total, w, h) {{
    if (sumW <= 0 || total <= 0) return Infinity;
    var ratio = sumW / total;
    var stripLong, stripShort;
    if (w >= h) {{ stripLong = h; stripShort = w * ratio; }}
    else        {{ stripLong = w; stripShort = h * ratio; }}
    if (stripLong <= 0 || stripShort <= 0) return Infinity;
    var max = 0;
    row.forEach(function(it){{
      var f = it.weight / sumW;
      var l = stripLong * f;
      if (l <= 0) {{ max = Infinity; return; }}
      max = Math.max(max, Math.max(l/stripShort, stripShort/l));
    }});
    return max;
  }}
  function authorHue(name) {{
    if (!name) return 210;
    var h = 0;
    for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    return h % 360;
  }}
  function colorFor(item, mode) {{
    var FB = '#30363d'; // primer line - neutral chrome
    if (mode === 'mono') return FB;
    if (mode === 'language') return LANG[item.language] || FB;
    if (mode === 'author') {{
      if (!item.author) return FB;
      // Sample only Nord aurora + frost hues so it stays in-theme.
      var hues = [193, 213, 220, 14, 25, 38, 92, 311];
      return 'hsl(' + hues[authorHue(item.author) % hues.length] + ',32%,55%)';
    }}
    if (mode === 'bus') {{
      var bf = +item.bus || 0;
      if (bf === 0) return FB;
      if (bf === 1) return '#f85149'; // status red
      if (bf === 2) return '#d29922'; // status amber
      return '#3fb950';                // status green
    }}
    if (mode === 'test_gap') {{
      return item.test_gap ? '#d29922' : FB; // amber = warning
    }}
    var attr = ATTR[mode]; if (!attr) return FB;
    var v = +item[attr] || 0;
    var max = files.reduce(function(m,it){{ return Math.max(m, +it[attr]||0); }}, 1) || 1;
    var ratio = v / max;
    return viridis(ratio);
  }}
  // Auxiliary data
  var cycles = JSON.parse(document.getElementById('raysense-cycles').textContent || '[]');
  var distance = JSON.parse(document.getElementById('raysense-distance').textContent || '[]');
  var dsm = JSON.parse(document.getElementById('raysense-dsm').textContent || '[]');
  var trend = JSON.parse(document.getElementById('raysense-trend').textContent || '[]');
  var coupling = JSON.parse(document.getElementById('raysense-coupling').textContent || '[]');
  var fnsRaw = JSON.parse(document.getElementById('raysense-functions').textContent || '[]');
  var fnsByFile = {{}}; fnsRaw.forEach(function(e){{ fnsByFile[e.path] = e.functions || []; }});
  var selectedCycle = null;
  function renderCyclesList() {{
    var list = document.getElementById('cycles-list');
    if (!list) return;
    if (!cycles.length) {{ list.innerHTML = '<li><small>no cycles</small></li>'; return; }}
    list.innerHTML = cycles.map(function(cyc, i){{
      return '<li data-cycle="'+i+'">cycle '+(i+1)+' <small>'+cyc.length+' files</small></li>';
    }}).join('');
    list.querySelectorAll('li[data-cycle]').forEach(function(li){{
      li.addEventListener('click', function(){{
        var idx = +li.getAttribute('data-cycle');
        selectedCycle = (selectedCycle === idx) ? null : idx;
        list.querySelectorAll('li').forEach(function(x){{ x.classList.toggle('selected', +x.getAttribute('data-cycle') === selectedCycle); }});
        drawHighlight();
        drawEdges();
      }});
    }});
  }}
  function renderTrend() {{
    var spark = document.getElementById('trend-spark');
    if (!spark) return;
    spark.innerHTML = '';
    if (trend.length < 2) return;
    var box = spark.getBoundingClientRect();
    var W = box.width, H = 36;
    var max = trend.reduce(function(m,p){{ return Math.max(m, p.score); }}, 1);
    var min = trend.reduce(function(m,p){{ return Math.min(m, p.score); }}, max);
    var span = Math.max(max - min, 1);
    var n = trend.length;
    var pts = trend.map(function(p, i){{
      var x = (i / (n - 1)) * W;
      var y = H - ((p.score - min) / span) * (H - 4) - 2;
      return x.toFixed(1) + ',' + y.toFixed(1);
    }});
    spark.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    path.setAttribute('points', pts.join(' '));
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', 'var(--accent)');
    path.setAttribute('stroke-width', '1.5');
    spark.appendChild(path);
    var lastDot = document.createElementNS('http://www.w3.org/2000/svg','circle');
    var last = pts[pts.length - 1].split(',');
    lastDot.setAttribute('cx', last[0]); lastDot.setAttribute('cy', last[1]);
    lastDot.setAttribute('r', '2.5');
    lastDot.setAttribute('fill', 'var(--accent)');
    spark.appendChild(lastDot);
  }}
  function renderMainSequence() {{
    var s = document.getElementById('main-seq');
    if (!s) return;
    s.innerHTML = '';
    if (!distance.length) return;
    var pad = 22, W = 220, H = 160;
    var iw = W - pad * 2, ih = H - pad * 2;
    // axes + the main-sequence diagonal (A + I = 1)
    var bg = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    bg.innerHTML =
      '<line class="guide" x1="'+pad+'" y1="'+(H-pad)+'" x2="'+(W-pad)+'" y2="'+(H-pad)+'"/>'+
      '<line class="guide" x1="'+pad+'" y1="'+pad+'" x2="'+pad+'" y2="'+(H-pad)+'"/>'+
      '<line class="guide" x1="'+pad+'" y1="'+pad+'" x2="'+(W-pad)+'" y2="'+(H-pad)+'"/>'+
      '<text x="'+pad+'" y="'+(H-6)+'">stable</text>'+
      '<text x="'+(W-pad-26)+'" y="'+(H-6)+'">unstable</text>'+
      '<text x="3" y="'+pad+'">abstract</text>'+
      '<text x="3" y="'+(H-pad)+'">concrete</text>'+
      '<text x="'+(W/2 - 38)+'" y="12">main-sequence (A+I=1)</text>';
    s.appendChild(bg);
    distance.forEach(function(m){{
      var cx = pad + m.instability * iw;
      var cy = (H - pad) - m.abstractness * ih;
      var c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('cx', cx.toFixed(1));
      c.setAttribute('cy', cy.toFixed(1));
      c.setAttribute('r', '3');
      var cls = m.is_foundation ? 'foundation' : (m.distance > 0.5 ? 'off' : '');
      if (cls) c.setAttribute('class', cls);
      var t = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      t.textContent = m.module + ' I=' + m.instability.toFixed(2) + ' A=' + m.abstractness.toFixed(2) + ' D=' + m.distance.toFixed(2);
      c.appendChild(t);
      s.appendChild(c);
    }});
  }}
  function drawRibbons() {{
    var existing = svg.querySelectorAll('path.ribbon');
    existing.forEach(function(e){{ e.remove(); }});
    var toggle = document.getElementById('show-ribbons');
    if (!toggle || !toggle.checked) return;
    if (!coupling || !coupling.length) return;
    coupling.forEach(function(p){{
      var a = pathToRect[p.left]; if (!a) return;
      var b = pathToRect[p.right]; if (!b) return;
      var ax = a.x + a.w/2, ay = a.y + a.h/2;
      var bx = b.x + b.w/2, by = b.y + b.h/2;
      var dx = bx - ax, dy = by - ay;
      var dist = Math.sqrt(dx*dx + dy*dy) || 1;
      var pull = Math.min(dist * 0.35, 90);
      var midX = (ax + bx) / 2 + (-dy / dist) * pull;
      var midY = (ay + by) / 2 + (dx / dist) * pull;
      var d = 'M' + ax.toFixed(1) + ',' + ay.toFixed(1) +
        ' Q' + midX.toFixed(1) + ',' + midY.toFixed(1) +
        ' ' + bx.toFixed(1) + ',' + by.toFixed(1);
      var alpha = 0.18 + p.coupling_strength * 0.55;
      var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('class', 'ribbon');
      path.setAttribute('d', d);
      path.setAttribute('stroke', 'hsla(310, 70%, 60%, ' + alpha.toFixed(2) + ')');
      path.setAttribute('stroke-width', String(0.6 + p.coupling_strength * 2.5));
      svg.appendChild(path);
    }});
  }}
  function showFunctions(filePath) {{
    var fns = fnsByFile[filePath] || [];
    if (!fns.length) return;
    var zoom = document.getElementById('zoom');
    zoom.innerHTML = '';
    zoom.removeAttribute('hidden');
    var rect = svg.getBoundingClientRect();
    var W = rect.width, H = rect.height;
    zoom.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    var title = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    title.setAttribute('class', 'zoom-title');
    title.setAttribute('x', '12'); title.setAttribute('y', '20');
    title.textContent = filePath;
    zoom.appendChild(title);
    var hint = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    hint.setAttribute('class', 'zoom-hint');
    hint.setAttribute('x', '12'); hint.setAttribute('y', '36');
    hint.textContent = fns.length + ' functions - click anywhere or press Esc to close';
    zoom.appendChild(hint);
    var items = fns.map(function(f){{
      return {{ path: f.name, weight: Math.max(+f.value || 1, 1), item: f }};
    }});
    items.sort(function(a, b){{ return b.weight - a.weight; }});
    var total = items.reduce(function(s, it){{ return s + it.weight; }}, 0);
    var laid = squarify(items, 12, 46, W - 24, H - 58, total);
    var maxValue = items.reduce(function(m, it){{ return Math.max(m, it.weight); }}, 1);
    laid.forEach(function(r){{
      var fillRatio = (r.item.value || 0) / maxValue;
      var lightness = 18 + Math.round(fillRatio * 30);
      var rectEl = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rectEl.setAttribute('class', 'fn');
      rectEl.setAttribute('x', r.x); rectEl.setAttribute('y', r.y);
      rectEl.setAttribute('width', Math.max(r.w-1, 0));
      rectEl.setAttribute('height', Math.max(r.h-1, 0));
      rectEl.setAttribute('fill', 'hsl(350, 55%, ' + lightness + '%)');
      var ttip = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      ttip.textContent = r.item.name + ' - cyclomatic ' + r.item.value + ', ' + r.item.lines + ' lines';
      rectEl.appendChild(ttip);
      zoom.appendChild(rectEl);
      if (r.w > 60 && r.h > 18) {{
        var label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('class', 'fn-label');
        label.setAttribute('x', r.x + 4);
        label.setAttribute('y', r.y + 12);
        label.textContent = r.item.name;
        zoom.appendChild(label);
      }}
    }});
  }}
  function hideFunctions() {{
    var zoom = document.getElementById('zoom');
    if (zoom) {{ zoom.setAttribute('hidden', ''); zoom.innerHTML = ''; }}
  }}
  function renderDsm() {{
    var host = document.getElementById('dsm-grid');
    if (!host) return;
    host.innerHTML = '';
    if (!dsm.length) {{ host.textContent = 'no module edges'; return; }}
    var modules = {{}};
    dsm.forEach(function(e){{ modules[e.from_module] = true; modules[e.to_module] = true; }});
    var keys = Object.keys(modules).sort().slice(0, 12);
    var by = {{}};
    dsm.forEach(function(e){{ by[e.from_module + '|' + e.to_module] = e.edges; }});
    var max = dsm.reduce(function(m,e){{ return Math.max(m, e.edges); }}, 1);
    host.style.gridTemplateColumns = '160px repeat(' + keys.length + ', 36px)';
    // header row
    host.appendChild(empty('dsm-row-label', ''));
    keys.forEach(function(k){{ host.appendChild(empty('dsm-col-label', shortName(k))); }});
    keys.forEach(function(row){{
      host.appendChild(empty('dsm-row-label', shortName(row)));
      keys.forEach(function(col){{
        var v = by[row + '|' + col] || 0;
        var cell = empty('dsm-cell', v ? String(v) : '');
        if (v) {{
          var t = Math.min(v / max, 1);
          cell.style.background = 'hsl(210,55%,' + Math.round(15 + t * 30) + '%)';
        }}
        host.appendChild(cell);
      }});
    }});
    function empty(cls, text) {{ var d = document.createElement('div'); d.className = cls; d.textContent = text; return d; }}
    function shortName(s) {{ return s.length > 14 ? s.slice(0, 13) + '…' : s; }}
  }}
  function reachable(path, dir) {{
    var seen = {{}}; var queue = [path];
    while (queue.length) {{
      var p = queue.shift();
      if (seen[p]) continue; seen[p] = true;
      var entry = adjByPath[p]; if (!entry) continue;
      var f = edgeSelect ? edgeSelect.value : 'all';
      var keys = (f === 'all') ? ['imports_'+dir,'calls_'+dir,'inherits_'+dir] : [f+'_'+dir];
      keys.forEach(function(k){{ (entry[k]||[]).forEach(function(n){{ if (!seen[n]) queue.push(n); }}); }});
    }}
    return seen;
  }}
  function focusFilter(file) {{
    var mode = focusModeSelect ? focusModeSelect.value : 'all';
    var val = focusValueSelect ? focusValueSelect.value : '';
    if (mode === 'language') return file.language === val;
    if (mode === 'directory') return file.directory === val;
    if (mode === 'entry') return !!file.entry;
    if (mode === 'impact') {{
      if (!selectedPath) return true;
      var down = reachable(selectedPath, 'out');
      var up = reachable(selectedPath, 'in');
      return file.path === selectedPath || down[file.path] || up[file.path];
    }}
    return true;
  }}
  function rebuildFocusValues() {{
    if (!focusModeSelect || !focusValueSelect) return;
    var mode = focusModeSelect.value;
    if (mode !== 'language' && mode !== 'directory') {{
      focusValueSelect.innerHTML = ''; focusValueSelect.hidden = true; return;
    }}
    var seen = {{}};
    files.forEach(function(f){{ var v = f[mode]||''; if (v) seen[v] = true; }});
    var keys = Object.keys(seen).sort();
    focusValueSelect.innerHTML = keys.map(function(k){{
      return '<option value="'+escapeAttr(k)+'">'+escapeAttr(k)+'</option>';
    }}).join('');
    focusValueSelect.hidden = !keys.length;
  }}
  function escapeAttr(v) {{ return String(v).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;'); }}
  function render() {{
    var rect = svg.getBoundingClientRect();
    var W = rect.width, H = rect.height;
    if (W <= 0 || H <= 0) return;
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.innerHTML = '';
    pathToRect = {{}};
    var mode = colorSelect ? colorSelect.value : 'language';
    var visible = files.filter(focusFilter);
    if (!visible.length) return;
    var items = visible.map(function(f){{ return {{path:f.path, weight:Math.max(+f.lines||0, 1), item:f}}; }});
    items.sort(function(a,b){{ return b.weight - a.weight; }});
    var total = items.reduce(function(s,it){{ return s+it.weight; }}, 0);
    var laid = squarify(items, 0, 0, W, H, total);
    laid.forEach(function(r){{
      pathToRect[r.path] = r;
      var rectEl = document.createElementNS('http://www.w3.org/2000/svg','rect');
      rectEl.setAttribute('class','tile');
      rectEl.setAttribute('data-path', r.path);
      rectEl.setAttribute('x', r.x); rectEl.setAttribute('y', r.y);
      rectEl.setAttribute('width', Math.max(r.w-1, 0));
      rectEl.setAttribute('height', Math.max(r.h-1, 0));
      rectEl.setAttribute('fill', colorFor(r.item, mode));
      svg.appendChild(rectEl);
      var dark = readableTextOn(rectEl.getAttribute('fill'));
      if (r.w > 60 && r.h > 18) {{
        var label = document.createElementNS('http://www.w3.org/2000/svg','text');
        label.setAttribute('class','tile-label');
        label.setAttribute('x', r.x + 4);
        label.setAttribute('y', r.y + 12);
        if (dark) label.setAttribute('fill', dark);
        label.textContent = (r.path.split('/').pop() || '');
        svg.appendChild(label);
      }}
      if (r.w > 60 && r.h > 28) {{
        var icon = LANG_ICON[r.item.language];
        if (icon) {{
          var iconEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
          iconEl.setAttribute('d', icon.d);
          var size = 14;
          var scale = size / icon.vb;
          var ix = r.x + r.w - size - 4;
          var iy = r.y + 4;
          iconEl.setAttribute('transform', 'translate(' + ix + ' ' + iy + ') scale(' + scale + ')');
          iconEl.setAttribute('fill', dark || '#e6e9ee');
          iconEl.setAttribute('opacity', '0.8');
          iconEl.setAttribute('pointer-events', 'none');
          svg.appendChild(iconEl);
        }}
      }}
    }});
    drawHighlight();
    drawEdges();
    drawRibbons();
  }}
  function drawHighlight() {{
    var rects = svg.querySelectorAll('rect.tile');
    rects.forEach(function(el){{ el.classList.remove('selected','upstream','downstream','dim','cycle'); }});
    if (selectedCycle !== null && cycles[selectedCycle]) {{
      var members = {{}};
      cycles[selectedCycle].forEach(function(p){{ members[p] = true; }});
      rects.forEach(function(el){{
        var p = el.getAttribute('data-path');
        if (members[p]) el.classList.add('cycle');
        else el.classList.add('dim');
      }});
      return;
    }}
    if (!selectedPath) return;
    var down = reachable(selectedPath, 'out');
    var up = reachable(selectedPath, 'in');
    rects.forEach(function(el){{
      var p = el.getAttribute('data-path');
      if (p === selectedPath) el.classList.add('selected');
      else if (down[p]) el.classList.add('downstream');
      else if (up[p]) el.classList.add('upstream');
      else el.classList.add('dim');
    }});
  }}
  function sideAnchor(rect, ox, oy) {{
    var cx = rect.x + rect.w/2, cy = rect.y + rect.h/2;
    var dx = ox - cx, dy = oy - cy;
    // Pick the border the line cx,cy → ox,oy crosses first.
    if (Math.abs(dx) * rect.h > Math.abs(dy) * rect.w) {{
      return dx > 0
        ? {{ x: rect.x + rect.w, y: cy, side: 'r' }}
        : {{ x: rect.x, y: cy, side: 'l' }};
    }}
    return dy > 0
      ? {{ x: cx, y: rect.y + rect.h, side: 'b' }}
      : {{ x: cx, y: rect.y, side: 't' }};
  }}
  function pullOut(anchor, len) {{
    switch (anchor.side) {{
      case 'r': return {{ x: anchor.x + len, y: anchor.y }};
      case 'l': return {{ x: anchor.x - len, y: anchor.y }};
      case 't': return {{ x: anchor.x, y: anchor.y - len }};
      case 'b': return {{ x: anchor.x, y: anchor.y + len }};
    }}
    return {{ x: anchor.x, y: anchor.y }};
  }}
  function curvePath(a, b, lane) {{
    var dx = b.x - a.x, dy = b.y - a.y;
    var dist = Math.sqrt(dx*dx + dy*dy) || 1;
    var pull = Math.min(dist * 0.4, 80);
    var ac = pullOut(a, pull);
    var bc = pullOut(b, pull);
    // Lane offset perpendicular to overall edge direction (separates edge types)
    var nx = -dy / dist * lane, ny = dx / dist * lane;
    return 'M' + a.x.toFixed(1) + ',' + a.y.toFixed(1) +
      ' C' + (ac.x + nx).toFixed(1) + ',' + (ac.y + ny).toFixed(1) +
      ' ' + (bc.x + nx).toFixed(1) + ',' + (bc.y + ny).toFixed(1) +
      ' ' + b.x.toFixed(1) + ',' + b.y.toFixed(1);
  }}
  function drawEdges() {{
    var existing = svg.querySelectorAll('path.edge');
    existing.forEach(function(e){{ e.remove(); }});
    if (!showEdges || !showEdges.checked) return;
    var f = edgeSelect ? edgeSelect.value : 'all';
    var types = (f === 'all') ? ['imports','calls','inherits'] : [f];
    var laneOf = {{ imports: -2, calls: 0, inherits: 2 }};
    var down = selectedPath ? reachable(selectedPath, 'out') : null;
    var up = selectedPath ? reachable(selectedPath, 'in') : null;
    // Aggregate: count multiplicity per (from, to, type) - for raysense
    // each edge type is already deduplicated in adjacency, so multiplicity
    // is 1 today; we keep the structure so future per-edge counts plug in.
    var edges = [];
    adjacency.forEach(function(entry){{
      var a = pathToRect[entry.path]; if (!a) return;
      types.forEach(function(t){{
        (entry[t+'_out']||[]).forEach(function(toPath){{
          var b = pathToRect[toPath]; if (!b) return;
          edges.push({{ from: entry.path, to: toPath, type: t, a: a, b: b, count: 1 }});
        }});
      }});
    }});
    edges.forEach(function(e){{
      var bcx = e.b.x + e.b.w/2, bcy = e.b.y + e.b.h/2;
      var acx = e.a.x + e.a.w/2, acy = e.a.y + e.a.h/2;
      var aA = sideAnchor(e.a, bcx, bcy);
      var bA = sideAnchor(e.b, acx, acy);
      var lane = laneOf[e.type] || 0;
      var d = curvePath(aA, bA, lane);
      var pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      pathEl.setAttribute('class', 'edge ' + e.type);
      pathEl.setAttribute('d', d);
      pathEl.setAttribute('stroke-width', String(0.8 + Math.min(e.count - 1, 4) * 0.4));
      if (selectedPath) {{
        var inRoute = e.from === selectedPath || e.to === selectedPath ||
          (down && (down[e.from] || down[e.to])) ||
          (up && (up[e.from] || up[e.to]));
        if (!inRoute) pathEl.classList.add('dim');
      }}
      svg.appendChild(pathEl);
    }});
  }}
  function showDetail(file) {{
    detailTitle.textContent = file.path;
    var lines = [
      ['language', file.language],
      ['lines', file.lines],
      ['churn (commits)', file.churn],
      ['age (days)', file.age],
      ['risk score', file.risk],
      ['instability', (+file.instability).toFixed(3)],
      ['entry point', file.entry ? 'yes' : 'no']
    ];
    var entry = adjByPath[file.path];
    if (entry) {{
      lines.push(['imports out / in', entry.imports_out.length + ' / ' + entry.imports_in.length]);
      lines.push(['calls out / in', entry.calls_out.length + ' / ' + entry.calls_in.length]);
      lines.push(['inherits out / in', entry.inherits_out.length + ' / ' + entry.inherits_in.length]);
    }}
    detailBody.innerHTML = lines.map(function(p){{
      return '<dt>'+escapeAttr(p[0])+'</dt><dd>'+escapeAttr(p[1])+'</dd>';
    }}).join('');
    detail.hidden = false;
  }}
  svg.addEventListener('click', function(e){{
    var target = e.target.closest && e.target.closest('rect.tile');
    if (!target) return;
    var p = target.getAttribute('data-path');
    selectedPath = p;
    selectedCycle = null;
    var list = document.getElementById('cycles-list');
    if (list) list.querySelectorAll('li').forEach(function(x){{ x.classList.remove('selected'); }});
    var file = files.find(function(f){{ return f.path === p; }});
    if (file) showDetail(file);
    drawHighlight(); drawEdges();
    if (focusModeSelect && focusModeSelect.value === 'impact') render();
  }});
  if (closeBtn) closeBtn.addEventListener('click', function(){{
    detail.hidden = true; selectedPath = null;
    drawHighlight(); drawEdges();
    if (focusModeSelect && focusModeSelect.value === 'impact') render();
  }});
  if (colorSelect) colorSelect.addEventListener('change', render);
  if (focusModeSelect) focusModeSelect.addEventListener('change', function(){{ rebuildFocusValues(); render(); }});
  if (focusValueSelect) focusValueSelect.addEventListener('change', render);
  if (edgeSelect) edgeSelect.addEventListener('change', function(){{ drawEdges(); if (focusModeSelect && focusModeSelect.value === 'impact') render(); }});
  if (showEdges) showEdges.addEventListener('change', drawEdges);
  var ribbonsToggle = document.getElementById('show-ribbons');
  if (ribbonsToggle) ribbonsToggle.addEventListener('change', drawRibbons);
  svg.addEventListener('dblclick', function(e){{
    var target = e.target.closest && e.target.closest('rect.tile');
    if (!target) return;
    showFunctions(target.getAttribute('data-path'));
  }});
  var zoomEl = document.getElementById('zoom');
  if (zoomEl) zoomEl.addEventListener('click', hideFunctions);
  document.addEventListener('keydown', function(e){{
    if (e.key === 'Escape') hideFunctions();
  }});
  window.addEventListener('resize', function(){{ render(); renderTrend(); }});
  rebuildFocusValues();
  renderCyclesList();
  renderTrend();
  renderMainSequence();
  renderDsm();
  render();
}})();
</script>
<script>
(function() {{
  if (typeof EventSource !== 'function') return;
  try {{
    var es = new EventSource('/events');
    es.addEventListener('data-changed', function() {{ location.reload(); }});
  }} catch (_) {{}}
}})();
</script>
</body></html>"#,
        html_escape(&project_name),
        (health.score as f64 * 1.3).round() as u32,
        health.score,
        health.score,
        (health.score as f64 * 1.3).round() as u32,
        health.coverage_score,
        health.structural_score,
        report.files.len(),
        report.functions.len(),
        health.rules.len(),
        (health.root_causes.modularity * 100.0).round() as u32,
        html_escape(&health.grades.modularity),
        (health.root_causes.acyclicity * 100.0).round() as u32,
        html_escape(&health.grades.acyclicity),
        (health.root_causes.depth * 100.0).round() as u32,
        html_escape(&health.grades.depth),
        (health.root_causes.equality * 100.0).round() as u32,
        html_escape(&health.grades.equality),
        (health.root_causes.redundancy * 100.0).round() as u32,
        html_escape(&health.grades.redundancy),
        (health.root_causes.structural_uniformity * 100.0).round() as u32,
        html_escape(&health.grades.structural_uniformity),
        cycles,
        max_blast,
        attack_pct,
        upward,
        commits,
        authors,
        changed,
        unstable_modules,
        module_edges_rows,
        hotspots,
        rules,
        complex,
        gaps,
        json_script_escape(&files_json),
        json_script_escape(&adjacency_json),
        json_script_escape(&telemetry),
        json_script_escape(&cycles_json),
        json_script_escape(&change_coupling_json),
        json_script_escape(&distance_metrics_json),
        json_script_escape(&dsm_json),
        json_script_escape(&trend_json),
        json_script_escape(&functions_json),
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

#[derive(serde::Deserialize, serde::Serialize)]
struct TrendPoint {
    score: u8,
}

/// Read trend samples for the live HTML dashboard sparkline. v0.8
/// pulls them straight from the splayed `trend_health` table; there
/// is no JSON sidecar. Returns `None` when no trend history has been
/// recorded yet.
fn read_trend_samples(root: &Path) -> Option<Vec<TrendPoint>> {
    let samples = crate::memory::read_trend_history_from_splay(root)?;
    if samples.is_empty() {
        return None;
    }
    Some(
        samples
            .into_iter()
            .map(|s| TrendPoint { score: s.score })
            .collect(),
    )
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
    config.scan.plugins.push(crate::LanguagePluginConfig {
        name: name.to_string(),
        extensions,
        file_names,
        ..crate::LanguagePluginConfig::default()
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
    let standard = crate::standard_language_plugins();
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
    let plugin: crate::LanguagePluginConfig =
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

fn plugin_has_query_language(plugin: &crate::LanguagePluginConfig) -> bool {
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

#[derive(Debug, Clone, Default)]
pub(crate) struct PluginSyncSummary {
    pub written: Vec<PathBuf>,
    pub skipped: Vec<PathBuf>,
}

pub(crate) fn sync_standard_plugins(
    root: &Path,
    names: &[String],
    force: bool,
) -> Result<PluginSyncSummary> {
    let plugins = crate::standard_language_plugins();
    let filter: std::collections::HashSet<&str> = names.iter().map(String::as_str).collect();
    let mut summary = PluginSyncSummary::default();
    for plugin in plugins {
        if !filter.is_empty() && !filter.contains(plugin.name.as_str()) {
            continue;
        }
        let plugin_dir = root.join(".raysense/plugins").join(&plugin.name);
        let manifest_path = plugin_dir.join("plugin.toml");
        if manifest_path.exists() && !force {
            summary.skipped.push(manifest_path);
            continue;
        }
        fs::create_dir_all(&plugin_dir)
            .with_context(|| format!("failed to create {}", plugin_dir.display()))?;
        let toml = toml::to_string_pretty(&plugin)
            .with_context(|| format!("failed to encode plugin manifest for {}", plugin.name))?;
        fs::write(&manifest_path, toml)
            .with_context(|| format!("failed to write {}", manifest_path.display()))?;
        summary.written.push(manifest_path);
    }
    Ok(summary)
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
abstract_type_prefixes = ["interface "]
concrete_type_prefixes = ["class ", "type "]
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

pub(crate) fn apply_policy_preset(config: &mut RaysenseConfig, preset: &str) -> Result<()> {
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
                crate::LayerConfig {
                    name: "api".to_string(),
                    path: "src/api/*".to_string(),
                    order: 2,
                },
                crate::LayerConfig {
                    name: "domain".to_string(),
                    path: "src/domain/*".to_string(),
                    order: 1,
                },
                crate::LayerConfig {
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
    let path = append_trend_sample(&report, &health)?;
    println!("trend {}", path.display());
    Ok(())
}

/// Append a sample to the splayed trend log. v0.8 routes through
/// `memory::append_trend_sample_splay`, which mutates the splayed
/// `trend_*` tables under `<root>/.raysense/baseline/tables/` in
/// place via Rayfall `concat`. There is no JSON sidecar.
///
/// Returns the canonical trend tables directory so callers can show
/// the user where the sample landed.
pub(crate) fn append_trend_sample(report: &ScanReport, health: &HealthSummary) -> Result<PathBuf> {
    crate::memory::append_trend_sample_splay(report, health, &report.snapshot.root)
        .context("failed to append trend sample")?;
    Ok(crate::memory::trend_tables_dir(&report.snapshot.root))
}

fn show_trend(root: &Path, config_path: Option<&Path>, json: bool) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    if json {
        println!("{}", serde_json::to_string_pretty(&health.metrics.trend)?);
        return Ok(());
    }
    if !health.metrics.trend.available {
        println!("trend unavailable");
        return Ok(());
    }
    println!(
        "trend samples={} score_delta={} quality_signal_delta={} rule_delta={}",
        health.metrics.trend.samples,
        health.metrics.trend.score_delta,
        health.metrics.trend.quality_signal_delta,
        health.metrics.trend.rule_delta,
    );
    if !health.metrics.trend.dimension_deltas.is_empty() {
        println!("dimension_drift");
        for (name, delta) in &health.metrics.trend.dimension_deltas {
            println!("  {}={:+.3}", name, delta);
        }
    }
    if health.metrics.trend.series.len() >= 2 {
        println!("recent_samples");
        for sample in health.metrics.trend.series.iter().rev().take(5).rev() {
            println!(
                "  ts={} score={} quality_signal={} rules={} {}",
                sample.timestamp,
                sample.score,
                sample.quality_signal,
                sample.rules,
                sample.snapshot_id,
            );
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
            "what_if score {} -> {} / 100 files {} -> {} rules {} -> {}",
            before_health.score,
            after_health.score,
            before_report.snapshot.file_count,
            after_report.snapshot.file_count,
            before_health.rules.len(),
            after_health.rules.len()
        );
        print_baseline_diff(&diff);
    }
    Ok(())
}

fn save_baseline(root: &Path, output: &Path, config_path: Option<&Path>) -> Result<()> {
    let config = config_for_root(root, config_path)?;
    let report = scan_path_with_config(root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let baseline = build_baseline(&report, &health);

    // Record the trend sample first so this snapshot is part of the
    // history that the splayed `trend_*` tables read from. Failures
    // here are non-fatal: the trend log is best-effort, the baseline
    // itself is what the user asked for.
    if let Err(reason) = append_trend_sample(&report, &health) {
        eprintln!("warning: failed to record trend sample: {reason:#}");
    }

    let memory = crate::memory::RayMemory::from_report_with_config(&report, &config)?;
    let tables_dir = output.join("tables");

    fs::create_dir_all(output)
        .with_context(|| format!("failed to create baseline dir {}", output.display()))?;
    fs::write(
        output.join("manifest.json"),
        serde_json::to_string_pretty(&baseline)?,
    )
    .with_context(|| format!("failed to write baseline manifest {}", output.display()))?;
    // v0.8: do NOT remove tables_dir wholesale. Two reasons:
    // 1. The shared `.sym` file lives at tables_dir/.sym. ray_sym_save
    //    short-circuits when persisted_count == str_count (sym.c:901),
    //    so a delete + save sequence can leave the new baseline without
    //    a `.sym` file when no new symbols were interned since the last
    //    save. Subsequent reads then fail with "corrupt".
    // 2. Trend tables are loaded into memory in `from_report_with_config`
    //    via `load_or_empty_trend_tables`. Removing the directory would
    //    discard the on-disk trend log between load and rewrite.
    // splay_save uses `mkdir -p` and per-table column overwrites, so it
    //  is safe to call against an existing directory.
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

fn default_policies_dir() -> PathBuf {
    PathBuf::from(".raysense/policies")
}

/// Returns 0 on success, 1 if any policy fails to evaluate (parse / type
/// error, schema mismatch, missing columns), or 2 if any policy reports an
/// error-severity finding. Eval errors take precedence over findings:
/// "I cannot tell whether the rule passed" is worse than "the rule
/// definitively failed."
fn run_policy_check(
    baseline: Option<PathBuf>,
    policies: Option<PathBuf>,
    json: bool,
) -> Result<i32> {
    let baseline = baseline.unwrap_or_else(default_baseline_dir);
    let tables_dir = baseline.join("tables");
    let policies_dir = policies.unwrap_or_else(default_policies_dir);

    if !json {
        crate::memory::enable_cli_progress();
    }
    let results =
        crate::memory::eval_all_policies(&tables_dir, &policies_dir).with_context(|| {
            format!(
                "failed to walk policies directory {}",
                policies_dir.display()
            )
        })?;

    let exit = crate::memory::policy_exit_code(&results);

    if json {
        let payload: Vec<serde_json::Value> = results
            .iter()
            .map(|r| match &r.findings {
                Ok(findings) => serde_json::json!({
                    "policy": r.path.display().to_string(),
                    "ok": true,
                    "findings": findings,
                }),
                Err(err) => serde_json::json!({
                    "policy": r.path.display().to_string(),
                    "ok": false,
                    "error": err.to_string(),
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "exit": exit,
                "policies": payload,
            }))?
        );
        return Ok(exit);
    }

    if results.is_empty() {
        println!(
            "no policies found at {} (looking for *.rfl files)",
            policies_dir.display(),
        );
        return Ok(exit);
    }
    let mut total = 0usize;
    let mut errors = 0usize;
    for result in &results {
        match &result.findings {
            Ok(findings) => {
                println!("{}: {} finding(s)", result.path.display(), findings.len());
                for finding in findings {
                    println!(
                        "  [{:?}] {} {} - {}",
                        finding.severity, finding.code, finding.path, finding.message,
                    );
                    total += 1;
                }
            }
            Err(err) => {
                errors += 1;
                println!("{}: ERROR {}", result.path.display(), err);
            }
        }
    }
    println!(
        "{} policy file(s) evaluated, {} finding(s), {} eval error(s); exit {}",
        results.len(),
        total,
        errors,
        exit,
    );
    Ok(exit)
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

fn print_baseline_tables(tables: &[crate::memory::BaselineTableInfo]) {
    println!("name\trows\tcolumns");
    for table in tables {
        println!("{}\t{}\t{}", table.name, table.rows, table.columns);
    }
}

fn print_baseline_rows(rows: &crate::memory::BaselineTableRows) {
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

fn print_health(report: &crate::ScanReport, health: &crate::HealthSummary) {
    println!("score {} / 100", health.score);
    println!("coverage {} / 100", health.coverage_score);
    println!("structure {} / 100", health.structural_score);
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
        "coupling local_edges={} cross_module_edges={} cross_module_ratio={:.3} cross_unstable_edges={} cross_unstable_ratio={:.3} entropy={:.3} entropy_bits={:.3} entropy_pairs={} average_module_cohesion={} cohesive_module_count={} god_files={} unstable_hotspots={}",
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
        health.metrics.coupling.cohesive_module_count,
        health.metrics.coupling.god_files.len(),
        health.metrics.coupling.unstable_hotspots.len()
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
        "size max_file_lines={} max_function_lines={} large_files={} long_functions={} file_size_entropy={:.3} file_size_entropy_bits={:.3} total_lines={} total_comment_lines={} comment_ratio={:.3}",
        health.metrics.size.max_file_lines,
        health.metrics.size.max_function_lines,
        health.metrics.size.large_files,
        health.metrics.size.long_functions,
        health.metrics.size.file_size_entropy,
        health.metrics.size.file_size_entropy_bits,
        health.metrics.size.total_lines,
        health.metrics.size.total_comment_lines,
        health.metrics.size.comment_ratio
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
    let pct = |v: f64| (v * 100.0).round() as u32;
    println!(
        "dimensions modularity={}/100 ({}) acyclicity={}/100 ({}) depth={}/100 ({}) equality={}/100 ({}) redundancy={}/100 ({}) structural_uniformity={}/100 ({})",
        pct(health.root_causes.modularity),
        health.grades.modularity,
        pct(health.root_causes.acyclicity),
        health.grades.acyclicity,
        pct(health.root_causes.depth),
        health.grades.depth,
        pct(health.root_causes.equality),
        health.grades.equality,
        pct(health.root_causes.redundancy),
        health.grades.redundancy,
        pct(health.root_causes.structural_uniformity),
        health.grades.structural_uniformity,
    );
    println!("overall_grade {}", health.grades.overall);
    println!(
        "architecture depth={} max_blast_radius={} max_blast_radius_file={} max_non_foundation_blast_radius={} max_non_foundation_blast_radius_file={} attack_surface_files={} attack_surface_ratio={:.3} upward_violations={} upward_violation_ratio={:.3} average_distance_from_main_sequence={:.3}",
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
        health.metrics.architecture.upward_violations.len(),
        health.metrics.architecture.upward_violation_ratio,
        health
            .metrics
            .architecture
            .average_distance_from_main_sequence
    );
    println!(
        "complexity max={} avg={:.3} cognitive_max={} cognitive_avg={:.3} gini={:.3} dead_functions={} duplicate_groups={} redundancy_ratio={:.3} entropy={:.3} entropy_bits={:.3}",
        health.metrics.complexity.max_function_complexity,
        health.metrics.complexity.average_function_complexity,
        health.metrics.complexity.max_cognitive_complexity,
        health.metrics.complexity.average_cognitive_complexity,
        health.metrics.complexity.complexity_gini,
        health.metrics.complexity.dead_functions.len(),
        health.metrics.complexity.duplicate_groups.len(),
        health.metrics.complexity.redundancy_ratio,
        health.metrics.complexity.complexity_entropy,
        health.metrics.complexity.complexity_entropy_bits
    );
    if health.metrics.evolution.available {
        println!(
            "evolution available=true commits_sampled={} changed_files={} authors={} bug_fix_commits={}",
            health.metrics.evolution.commits_sampled,
            health.metrics.evolution.changed_files,
            health.metrics.evolution.author_count,
            health.metrics.evolution.bug_fix_commits,
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

    if !health.metrics.evolution.temporal_hotspots.is_empty() {
        println!("temporal_hotspots");
        for hotspot in &health.metrics.evolution.temporal_hotspots {
            println!(
                "  risk={} commits={} max_complexity={} {}",
                hotspot.risk_score, hotspot.commits, hotspot.max_complexity, hotspot.path,
            );
        }
    }

    if !health.metrics.evolution.file_ages.is_empty() {
        println!("oldest_files");
        for age in &health.metrics.evolution.file_ages {
            println!(
                "  age_days={} last_changed_days={} {}",
                age.age_days, age.last_changed_days, age.path,
            );
        }
    }

    if !health.metrics.evolution.change_coupling.is_empty() {
        println!("change_coupling");
        for pair in &health.metrics.evolution.change_coupling {
            println!(
                "  strength={:.3} co_commits={} {} <-> {}",
                pair.coupling_strength, pair.co_commits, pair.left, pair.right,
            );
        }
    }

    if !health.metrics.evolution.bug_prone_files.is_empty() {
        println!("bug_prone_files");
        for entry in &health.metrics.evolution.bug_prone_files {
            println!(
                "  fix_commits={} total={} ratio={:.3} {}",
                entry.bug_fix_commits, entry.total_commits, entry.bug_fix_ratio, entry.path,
            );
        }
    }

    if !health.metrics.evolution.edit_risk_files.is_empty() {
        println!("edit_risk_files");
        for entry in &health.metrics.evolution.edit_risk_files {
            println!(
                "  risk={:.1} commits={} max_complexity={} bus_factor={} tests={} {}",
                entry.risk_score,
                entry.commits,
                entry.max_complexity,
                entry.bus_factor,
                if entry.has_nearby_tests { "yes" } else { "no" },
                entry.path,
            );
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

    print_baseline_save_hint(&report.snapshot.root);
}

/// Print a single-line nudge pointing the user at `baseline save` when no
/// baseline exists yet.  Skipped when stdout is not a TTY (so JSON / pipe /
/// MCP consumers stay byte-clean) and when a baseline already lives at the
/// default location (the user has clearly already discovered the command).
fn print_baseline_save_hint(root: &Path) {
    use std::io::IsTerminal;

    if !std::io::stdout().is_terminal() {
        return;
    }
    let baseline = root.join(".raysense").join("baseline").join("tables");
    if baseline.is_dir() {
        return;
    }
    println!();
    println!("[hint] run `raysense baseline save .` to materialize 24 queryable tables");
    println!("       (call graph, hotspots, ownership, arch_cycles, ...) for follow-up");
    println!("       Rayfall queries.  Agents pick this up automatically via the");
    println!("       bootstrap skill (`/raysense:bootstrap`).");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("raysense-cli-{name}-{nanos}"))
    }

    #[test]
    fn sync_standard_plugins_writes_then_skips_without_force() {
        let root = temp_root("sync");
        fs::create_dir_all(&root).unwrap();
        let summary = sync_standard_plugins(&root, &["go".to_string()], false).unwrap();
        assert_eq!(summary.written.len(), 1);
        assert!(summary.skipped.is_empty());
        let manifest = root.join(".raysense/plugins/go/plugin.toml");
        assert!(manifest.exists());

        let again = sync_standard_plugins(&root, &["go".to_string()], false).unwrap();
        assert!(again.written.is_empty());
        assert_eq!(again.skipped.len(), 1);

        let forced = sync_standard_plugins(&root, &["go".to_string()], true).unwrap();
        assert_eq!(forced.written.len(), 1);
        assert!(forced.skipped.is_empty());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn visualization_html_includes_treemap_and_panels() {
        let report = crate::scan_path(env!("CARGO_MANIFEST_DIR")).unwrap();
        let health = crate::compute_health(&report);
        let html = visualization_html(&report, &health);
        assert!(html.contains("id=\"color-mode\""));
        assert!(html.contains("id=\"treemap\""));
        assert!(html.contains("id=\"raysense-files\""));
        assert!(html.contains("id=\"raysense-adjacency\""));
        assert!(html.contains("id=\"raysense-telemetry\""));
        assert!(html.contains("\"churn\""), "files JSON should carry churn");
        assert!(html.contains("class=\"app\""));
    }

    #[test]
    fn sync_standard_plugins_filters_unknown_names_to_empty() {
        let root = temp_root("sync-unknown");
        fs::create_dir_all(&root).unwrap();
        let summary =
            sync_standard_plugins(&root, &["definitely-not-a-language".to_string()], false)
                .unwrap();
        assert!(summary.written.is_empty());
        assert!(summary.skipped.is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    /// v0.8 trend log is splay-native. After two `append_trend_sample`
    /// calls, the splayed `trend_health` table must hold two rows and
    /// `read_trend_history_from_splay` must round-trip them back into
    /// typed `TrendSample` form. No JSON file is created.
    #[test]
    fn append_trend_sample_grows_splayed_trend_health() {
        let _guard = crate::memory::rayforce_test_guard();
        let root = temp_root("trend-splay");
        fs::create_dir_all(&root).unwrap();
        let mut report = crate::scan_path(env!("CARGO_MANIFEST_DIR")).unwrap();
        report.snapshot.root = root.clone();
        let health = crate::compute_health(&report);

        let dir = append_trend_sample(&report, &health).unwrap();
        // First call: creates trend_* tables under
        // <root>/.raysense/baseline/tables/.
        assert!(dir.join("trend_health").is_dir());
        assert!(dir.join("trend_hotspots").is_dir());
        assert!(dir.join("trend_violations").is_dir());

        // Second call: must concat onto the existing splay, not replace it.
        // Different snapshot id so both rows are distinguishable.
        report.snapshot.snapshot_id = "second".to_string();
        let _ = append_trend_sample(&report, &health).unwrap();

        let samples = crate::memory::read_trend_history_from_splay(&root)
            .expect("trend tables must be readable");
        assert_eq!(
            samples.len(),
            2,
            "expected two trend samples after two appends"
        );
        // No JSON file is written.
        assert!(
            !root.join(".raysense/trends/history.json").exists(),
            "v0.8 must not write JSON",
        );

        fs::remove_dir_all(&root).unwrap();
    }
}
