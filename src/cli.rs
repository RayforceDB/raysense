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
use std::time::{SystemTime, UNIX_EPOCH};

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
            // Park here forever; dropping the watcher would stop events.
            std::thread::park();
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
  // Brand glyphs from Simple Icons (CC0, public domain). 24x24 viewBox.
  // https://simpleicons.org - well-designed, recognizable language marks.
  var LANG_ICON = {{
      rust: 'M23.8346 11.7033l-1.0073-.6236a13.7268 13.7268 0 00-.0283-.2936l.8656-.8069a.3483.3483 0 00-.1154-.578l-1.1066-.414a8.4958 8.4958 0 00-.087-.2856l.6904-.9587a.3462.3462 0 00-.2257-.5446l-1.1663-.1894a9.3574 9.3574 0 00-.1407-.2622l.49-1.0761a.3437.3437 0 00-.0274-.3361.3486.3486 0 00-.3006-.154l-1.1845.0416a6.7444 6.7444 0 00-.1873-.2268l.2723-1.153a.3472.3472 0 00-.417-.4172l-1.1532.2724a14.0183 14.0183 0 00-.2278-.1873l.0415-1.1845a.3442.3442 0 00-.49-.328l-1.076.491c-.0872-.0476-.1742-.0952-.2623-.1407l-.1903-1.1673A.3483.3483 0 0016.256.955l-.9597.6905a8.4867 8.4867 0 00-.2855-.086l-.414-1.1066a.3483.3483 0 00-.5781-.1154l-.8069.8666a9.2936 9.2936 0 00-.2936-.0284L12.2946.1683a.3462.3462 0 00-.5892 0l-.6236 1.0073a13.7383 13.7383 0 00-.2936.0284L9.9803.3374a.3462.3462 0 00-.578.1154l-.4141 1.1065c-.0962.0274-.1903.0567-.2855.086L7.744.955a.3483.3483 0 00-.5447.2258L7.009 2.348a9.3574 9.3574 0 00-.2622.1407l-1.0762-.491a.3462.3462 0 00-.49.328l.0416 1.1845a7.9826 7.9826 0 00-.2278.1873L3.8413 3.425a.3472.3472 0 00-.4171.4171l.2713 1.1531c-.0628.075-.1255.1509-.1863.2268l-1.1845-.0415a.3462.3462 0 00-.328.49l.491 1.0761a9.167 9.167 0 00-.1407.2622l-1.1662.1894a.3483.3483 0 00-.2258.5446l.6904.9587a13.303 13.303 0 00-.087.2855l-1.1065.414a.3483.3483 0 00-.1155.5781l.8656.807a9.2936 9.2936 0 00-.0283.2935l-1.0073.6236a.3442.3442 0 000 .5892l1.0073.6236c.008.0982.0182.1964.0283.2936l-.8656.8079a.3462.3462 0 00.1155.578l1.1065.4141c.0273.0962.0567.1914.087.2855l-.6904.9587a.3452.3452 0 00.2268.5447l1.1662.1893c.0456.088.0922.1751.1408.2622l-.491 1.0762a.3462.3462 0 00.328.49l1.1834-.0415c.0618.0769.1235.1528.1873.2277l-.2713 1.1541a.3462.3462 0 00.4171.4161l1.153-.2713c.075.0638.151.1255.2279.1863l-.0415 1.1845a.3442.3442 0 00.49.327l1.0761-.49c.087.0486.1741.0951.2622.1407l.1903 1.1662a.3483.3483 0 00.5447.2268l.9587-.6904a9.299 9.299 0 00.2855.087l.414 1.1066a.3452.3452 0 00.5781.1154l.8079-.8656c.0972.0111.1954.0203.2936.0294l.6236 1.0073a.3472.3472 0 00.5892 0l.6236-1.0073c.0982-.0091.1964-.0183.2936-.0294l.8069.8656a.3483.3483 0 00.578-.1154l.4141-1.1066a8.4626 8.4626 0 00.2855-.087l.9587.6904a.3452.3452 0 00.5447-.2268l.1903-1.1662c.088-.0456.1751-.0931.2622-.1407l1.0762.49a.3472.3472 0 00.49-.327l-.0415-1.1845a6.7267 6.7267 0 00.2267-.1863l1.1531.2713a.3472.3472 0 00.4171-.416l-.2713-1.1542c.0628-.0749.1255-.1508.1863-.2278l1.1845.0415a.3442.3442 0 00.328-.49l-.49-1.076c.0475-.0872.0951-.1742.1407-.2623l1.1662-.1893a.3483.3483 0 00.2258-.5447l-.6904-.9587.087-.2855 1.1066-.414a.3462.3462 0 00.1154-.5781l-.8656-.8079c.0101-.0972.0202-.1954.0283-.2936l1.0073-.6236a.3442.3442 0 000-.5892zm-6.7413 8.3551a.7138.7138 0 01.2986-1.396.714.714 0 11-.2997 1.396zm-.3422-2.3142a.649.649 0 00-.7715.5l-.3573 1.6685c-1.1035.501-2.3285.7795-3.6193.7795a8.7368 8.7368 0 01-3.6951-.814l-.3574-1.6684a.648.648 0 00-.7714-.499l-1.473.3158a8.7216 8.7216 0 01-.7613-.898h7.1676c.081 0 .1356-.0141.1356-.088v-2.536c0-.074-.0536-.0881-.1356-.0881h-2.0966v-1.6077h2.2677c.2065 0 1.1065.0587 1.394 1.2088.0901.3533.2875 1.5044.4232 1.8729.1346.413.6833 1.2381 1.2685 1.2381h3.5716a.7492.7492 0 00.1296-.0131 8.7874 8.7874 0 01-.8119.9526zM6.8369 20.024a.714.714 0 11-.2997-1.396.714.714 0 01.2997 1.396zM4.1177 8.9972a.7137.7137 0 11-1.304.5791.7137.7137 0 011.304-.579zm-.8352 1.9813l1.5347-.6824a.65.65 0 00.33-.8585l-.3158-.7147h1.2432v5.6025H3.5669a8.7753 8.7753 0 01-.2834-3.348zm6.7343-.5437V8.7836h2.9601c.153 0 1.0792.1772 1.0792.8697 0 .575-.7107.7815-1.2948.7815zm10.7574 1.4862c0 .2187-.008.4363-.0243.651h-.9c-.09 0-.1265.0586-.1265.1477v.413c0 .973-.5487 1.1846-1.0296 1.2382-.4576.0517-.9648-.1913-1.0275-.4717-.2704-1.5186-.7198-1.8436-1.4305-2.4034.8817-.5599 1.799-1.386 1.799-2.4915 0-1.1936-.819-1.9458-1.3769-2.3153-.7825-.5163-1.6491-.6195-1.883-.6195H5.4682a8.7651 8.7651 0 014.907-2.7699l1.0974 1.151a.648.648 0 00.9182.0213l1.227-1.1743a8.7753 8.7753 0 016.0044 4.2762l-.8403 1.8982a.652.652 0 00.33.8585l1.6178.7188c.0283.2875.0425.577.0425.8717zm-9.3006-9.5993a.7128.7128 0 11.984 1.0316.7137.7137 0 01-.984-1.0316zm8.3389 6.71a.7107.7107 0 01.9395-.3625.7137.7137 0 11-.9405.3635z',
      c: 'M16.5921 9.1962s-.354-3.298-3.627-3.39c-3.2741-.09-4.9552 2.474-4.9552 6.14 0 3.6651 1.858 6.5972 5.0451 6.5972 3.184 0 3.5381-3.665 3.5381-3.665l6.1041.365s.36 3.31-2.196 5.836c-2.552 2.5241-5.6901 2.9371-7.8762 2.9201-2.19-.017-5.2261.034-8.1602-2.97-2.938-3.0101-3.436-5.9302-3.436-8.8002 0-2.8701.556-6.6702 4.047-9.5502C7.444.72 9.849 0 12.254 0c10.0422 0 10.7172 9.2602 10.7172 9.2602z',
      cpp: 'M22.394 6c-.167-.29-.398-.543-.652-.69L12.926.22c-.509-.294-1.34-.294-1.848 0L2.26 5.31c-.508.293-.923 1.013-.923 1.6v10.18c0 .294.104.62.271.91.167.29.398.543.652.69l8.816 5.09c.508.293 1.34.293 1.848 0l8.816-5.09c.254-.147.485-.4.652-.69.167-.29.27-.616.27-.91V6.91c.003-.294-.1-.62-.268-.91zM12 19.11c-3.92 0-7.109-3.19-7.109-7.11 0-3.92 3.19-7.11 7.11-7.11a7.133 7.133 0 016.156 3.553l-3.076 1.78a3.567 3.567 0 00-3.08-1.78A3.56 3.56 0 008.444 12 3.56 3.56 0 0012 15.555a3.57 3.57 0 003.08-1.778l3.078 1.78A7.135 7.135 0 0112 19.11zm7.11-6.715h-.79v.79h-.79v-.79h-.79v-.79h.79v-.79h.79v.79h.79zm2.962 0h-.79v.79h-.79v-.79h-.79v-.79h.79v-.79h.79v.79h.79z',
      python: 'M14.25.18l.9.2.73.26.59.3.45.32.34.34.25.34.16.33.1.3.04.26.02.2-.01.13V8.5l-.05.63-.13.55-.21.46-.26.38-.3.31-.33.25-.35.19-.35.14-.33.1-.3.07-.26.04-.21.02H8.77l-.69.05-.59.14-.5.22-.41.27-.33.32-.27.35-.2.36-.15.37-.1.35-.07.32-.04.27-.02.21v3.06H3.17l-.21-.03-.28-.07-.32-.12-.35-.18-.36-.26-.36-.36-.35-.46-.32-.59-.28-.73-.21-.88-.14-1.05-.05-1.23.06-1.22.16-1.04.24-.87.32-.71.36-.57.4-.44.42-.33.42-.24.4-.16.36-.1.32-.05.24-.01h.16l.06.01h8.16v-.83H6.18l-.01-2.75-.02-.37.05-.34.11-.31.17-.28.25-.26.31-.23.38-.2.44-.18.51-.15.58-.12.64-.1.71-.06.77-.04.84-.02 1.27.05zm-6.3 1.98l-.23.33-.08.41.08.41.23.34.33.22.41.09.41-.09.33-.22.23-.34.08-.41-.08-.41-.23-.33-.33-.22-.41-.09-.41.09zm13.09 3.95l.28.06.32.12.35.18.36.27.36.35.35.47.32.59.28.73.21.88.14 1.04.05 1.23-.06 1.23-.16 1.04-.24.86-.32.71-.36.57-.4.45-.42.33-.42.24-.4.16-.36.09-.32.05-.24.02-.16-.01h-8.22v.82h5.84l.01 2.76.02.36-.05.34-.11.31-.17.29-.25.25-.31.24-.38.2-.44.17-.51.15-.58.13-.64.09-.71.07-.77.04-.84.01-1.27-.04-1.07-.14-.9-.2-.73-.25-.59-.3-.45-.33-.34-.34-.25-.34-.16-.33-.1-.3-.04-.25-.02-.2.01-.13v-5.34l.05-.64.13-.54.21-.46.26-.38.3-.32.33-.24.35-.2.35-.14.33-.1.3-.06.26-.04.21-.02.13-.01h5.84l.69-.05.59-.14.5-.21.41-.28.33-.32.27-.35.2-.36.15-.36.1-.35.07-.32.04-.28.02-.21V6.07h2.09l.14.01zm-6.47 14.25l-.23.33-.08.41.08.41.23.33.33.23.41.08.41-.08.33-.23.23-.33.08-.41-.08-.41-.23-.33-.33-.23-.41-.08-.41.08z',
      typescript: 'M1.125 0C.502 0 0 .502 0 1.125v21.75C0 23.498.502 24 1.125 24h21.75c.623 0 1.125-.502 1.125-1.125V1.125C24 .502 23.498 0 22.875 0zm17.363 9.75c.612 0 1.154.037 1.627.111a6.38 6.38 0 0 1 1.306.34v2.458a3.95 3.95 0 0 0-.643-.361 5.093 5.093 0 0 0-.717-.26 5.453 5.453 0 0 0-1.426-.2c-.3 0-.573.028-.819.086a2.1 2.1 0 0 0-.623.242c-.17.104-.3.229-.393.374a.888.888 0 0 0-.14.49c0 .196.053.373.156.529.104.156.252.304.443.444s.423.276.696.41c.273.135.582.274.926.416.47.197.892.407 1.266.628.374.222.695.473.963.753.268.279.472.598.614.957.142.359.214.776.214 1.253 0 .657-.125 1.21-.373 1.656a3.033 3.033 0 0 1-1.012 1.085 4.38 4.38 0 0 1-1.487.596c-.566.12-1.163.18-1.79.18a9.916 9.916 0 0 1-1.84-.164 5.544 5.544 0 0 1-1.512-.493v-2.63a5.033 5.033 0 0 0 3.237 1.2c.333 0 .624-.03.872-.09.249-.06.456-.144.623-.25.166-.108.29-.234.373-.38a1.023 1.023 0 0 0-.074-1.089 2.12 2.12 0 0 0-.537-.5 5.597 5.597 0 0 0-.807-.444 27.72 27.72 0 0 0-1.007-.436c-.918-.383-1.602-.852-2.053-1.405-.45-.553-.676-1.222-.676-2.005 0-.614.123-1.141.369-1.582.246-.441.58-.804 1.004-1.089a4.494 4.494 0 0 1 1.47-.629 7.536 7.536 0 0 1 1.77-.201zm-15.113.188h9.563v2.166H9.506v9.646H6.789v-9.646H3.375z',
      javascript: 'M0 0h24v24H0V0zm22.034 18.276c-.175-1.095-.888-2.015-3.003-2.873-.736-.345-1.554-.585-1.797-1.14-.091-.33-.105-.51-.046-.705.15-.646.915-.84 1.515-.66.39.12.75.42.976.9 1.034-.676 1.034-.676 1.755-1.125-.27-.42-.404-.601-.586-.78-.63-.705-1.469-1.065-2.834-1.034l-.705.089c-.676.165-1.32.525-1.71 1.005-1.14 1.291-.811 3.541.569 4.471 1.365 1.02 3.361 1.244 3.616 2.205.24 1.17-.87 1.545-1.966 1.41-.811-.18-1.26-.586-1.755-1.336l-1.83 1.051c.21.48.45.689.81 1.109 1.74 1.756 6.09 1.666 6.871-1.004.029-.09.24-.705.074-1.65l.046.067zm-8.983-7.245h-2.248c0 1.938-.009 3.864-.009 5.805 0 1.232.063 2.363-.138 2.711-.33.689-1.18.601-1.566.48-.396-.196-.597-.466-.83-.855-.063-.105-.11-.196-.127-.196l-1.825 1.125c.305.63.75 1.172 1.324 1.517.855.51 2.004.675 3.207.405.783-.226 1.458-.691 1.811-1.411.51-.93.402-2.07.397-3.346.012-2.054 0-4.109 0-6.179l.004-.056z',
      go: 'M1.811 10.231c-.047 0-.058-.023-.035-.059l.246-.315c.023-.035.081-.058.128-.058h4.172c.046 0 .058.035.035.07l-.199.303c-.023.036-.082.07-.117.07zM.047 11.306c-.047 0-.059-.023-.035-.058l.245-.316c.023-.035.082-.058.129-.058h5.328c.047 0 .07.035.058.07l-.093.28c-.012.047-.058.07-.105.07zm2.828 1.075c-.047 0-.059-.035-.035-.07l.163-.292c.023-.035.07-.07.117-.07h2.337c.047 0 .07.035.07.082l-.023.28c0 .047-.047.082-.082.082zm12.129-2.36c-.736.187-1.239.327-1.963.514-.176.046-.187.058-.34-.117-.174-.199-.303-.327-.548-.444-.737-.362-1.45-.257-2.115.175-.795.514-1.204 1.274-1.192 2.22.011.935.654 1.706 1.577 1.835.795.105 1.46-.175 1.987-.77.105-.13.198-.27.315-.434H10.47c-.245 0-.304-.152-.222-.35.152-.362.432-.97.596-1.274a.315.315 0 01.292-.187h4.253c-.023.316-.023.631-.07.947a4.983 4.983 0 01-.958 2.29c-.841 1.11-1.94 1.8-3.33 1.986-1.145.152-2.209-.07-3.143-.77-.865-.655-1.356-1.52-1.484-2.595-.152-1.274.222-2.419.993-3.424.83-1.086 1.928-1.776 3.272-2.02 1.098-.2 2.15-.07 3.096.571.62.41 1.063.97 1.356 1.648.07.105.023.164-.117.2m3.868 6.461c-1.064-.024-2.034-.328-2.852-1.029a3.665 3.665 0 01-1.262-2.255c-.21-1.32.152-2.489.947-3.529.853-1.122 1.881-1.706 3.272-1.95 1.192-.21 2.314-.095 3.33.595.923.63 1.496 1.484 1.648 2.605.198 1.578-.257 2.863-1.344 3.962-.771.783-1.718 1.273-2.805 1.495-.315.06-.63.07-.934.106zm2.78-4.72c-.011-.153-.011-.27-.034-.387-.21-1.157-1.274-1.81-2.384-1.554-1.087.245-1.788.935-2.045 2.033-.21.912.234 1.835 1.075 2.21.643.28 1.285.244 1.905-.07.923-.48 1.425-1.228 1.484-2.233z',
      java: 'M11.915 0 11.7.215C9.515 2.4 7.47 6.39 6.046 10.483c-1.064 1.024-3.633 2.81-3.711 3.551-.093.87 1.746 2.611 1.55 3.235-.198.625-1.304 1.408-1.014 1.939.1.188.823.011 1.277-.491a13.389 13.389 0 0 0-.017 2.14c.076.906.27 1.668.643 2.232.372.563.956.911 1.667.911.397 0 .727-.114 1.024-.264.298-.149.571-.33.91-.5.68-.34 1.634-.666 3.53-.604 1.903.062 2.872.39 3.559.704.687.314 1.15.664 1.925.664.767 0 1.395-.336 1.807-.9.412-.563.631-1.33.72-2.24.06-.623.055-1.32 0-2.066.454.45 1.117.604 1.213.424.29-.53-.816-1.314-1.013-1.937-.198-.624 1.642-2.366 1.549-3.236-.08-.748-2.707-2.568-3.748-3.586C16.428 6.374 14.308 2.394 12.13.215zm.175 6.038a2.95 2.95 0 0 1 2.943 2.942 2.95 2.95 0 0 1-2.943 2.943A2.95 2.95 0 0 1 9.148 8.98a2.95 2.95 0 0 1 2.942-2.942zM8.685 7.983a3.515 3.515 0 0 0-.145.997c0 1.951 1.6 3.55 3.55 3.55 1.95 0 3.55-1.598 3.55-3.55 0-.329-.046-.648-.132-.951.334.095.64.208.915.336a42.699 42.699 0 0 1 2.042 5.829c.678 2.545 1.01 4.92.846 6.607-.082.844-.29 1.51-.606 1.94-.315.431-.713.651-1.315.651-.593 0-.932-.27-1.673-.61-.741-.338-1.825-.694-3.792-.758-1.974-.064-3.073.293-3.821.669-.375.188-.659.373-.911.5s-.466.2-.752.2c-.53 0-.876-.209-1.16-.64-.285-.43-.474-1.101-.545-1.948-.141-1.693.176-4.069.823-6.614a43.155 43.155 0 0 1 1.934-5.783c.348-.167.749-.31 1.192-.425zm-3.382 4.362a.216.216 0 0 1 .13.031c-.166.56-.323 1.116-.463 1.665a33.849 33.849 0 0 0-.547 2.555 3.9 3.9 0 0 0-.2-.39c-.58-1.012-.914-1.642-1.16-2.08.315-.24 1.679-1.755 2.24-1.781zm13.394.01c.562.027 1.926 1.543 2.24 1.783-.246.438-.58 1.068-1.16 2.08a4.428 4.428 0 0 0-.163.309 32.354 32.354 0 0 0-.562-2.49 40.579 40.579 0 0 0-.482-1.652.216.216 0 0 1 .127-.03z',
      ruby: 'M20.156.083c3.033.525 3.893 2.598 3.829 4.77L24 4.822 22.635 22.71 4.89 23.926h.016C3.433 23.864.15 23.729 0 19.139l1.645-3 2.819 6.586.503 1.172 2.805-9.144-.03.007.016-.03 9.255 2.956-1.396-5.431-.99-3.9 8.82-.569-.615-.51L16.5 2.114 20.159.073l-.003.01zM0 19.089zM5.13 5.073c3.561-3.533 8.157-5.621 9.922-3.84 1.762 1.777-.105 6.105-3.673 9.636-3.563 3.532-8.103 5.734-9.864 3.957-1.766-1.777.045-6.217 3.612-9.75l.003-.003z',
      markdown: 'M22.27 19.385H1.73A1.73 1.73 0 010 17.655V6.345a1.73 1.73 0 011.73-1.73h20.54A1.73 1.73 0 0124 6.345v11.308a1.73 1.73 0 01-1.73 1.731zM5.769 15.923v-4.5l2.308 2.885 2.307-2.885v4.5h2.308V8.078h-2.308l-2.307 2.885-2.308-2.885H3.46v7.847zM21.232 12h-2.309V8.077h-2.307V12h-2.308l3.461 4.039z',
      toml: 'M.014 0h5.34v2.652H2.888v18.681h2.468V24H.015V0Zm17.622 5.049v2.78h-4.274v12.935h-3.008V7.83H6.059V5.05h11.577ZM23.986 24h-5.34v-2.652h2.467V2.667h-2.468V0h5.34v24Z',
      yaml: 'm0 .97 4.111 6.453v4.09h2.638v-4.09L11.053.969H8.214L5.58 5.125 2.965.969Zm12.093.024-4.47 10.544h2.114l.97-2.345h4.775l.804 2.345h2.26L14.255.994Zm1.133 2.225 1.463 3.87h-3.096zm3.06 9.475v10.29H24v-2.199h-5.454v-8.091zm-12.175.002v10.335h2.217v-7.129l2.32 4.792h1.746l2.4-4.96v7.295h2.127V12.696h-2.904L9.44 17.37l-2.455-4.674Z',
      json: 'M12.043 23.968c.479-.004.953-.029 1.426-.094a11.805 11.805 0 003.146-.863 12.404 12.404 0 003.793-2.542 11.977 11.977 0 002.44-3.427 11.794 11.794 0 001.02-3.476c.149-1.16.135-2.346-.045-3.499a11.96 11.96 0 00-.793-2.788 11.197 11.197 0 00-.854-1.617c-1.168-1.837-2.861-3.314-4.81-4.3a12.835 12.835 0 00-2.172-.87h-.005c.119.063.24.132.345.201.12.074.239.146.351.225a8.93 8.93 0 011.559 1.33c1.063 1.145 1.797 2.548 2.218 4.041.284.982.434 1.998.495 3.017.044.743.044 1.491-.047 2.229-.149 1.27-.554 2.51-1.228 3.596a7.475 7.475 0 01-1.903 2.084c-1.244.928-2.877 1.482-4.436 1.114a3.916 3.916 0 01-.748-.258 4.692 4.692 0 01-.779-.45 6.08 6.08 0 01-1.244-1.105 6.507 6.507 0 01-1.049-1.747 7.366 7.366 0 01-.494-2.54c-.03-1.273.225-2.553.854-3.67a6.43 6.43 0 011.663-1.918c.225-.178.464-.333.704-.479l.016-.007a5.121 5.121 0 00-1.441-.12 4.963 4.963 0 00-1.228.24c-.359.12-.704.27-1.019.45a6.146 6.146 0 00-.733.494c-.211.18-.42.36-.615.555-1.123 1.153-1.768 2.682-2.022 4.256-.15.973-.15 1.96-.091 2.95.105 1.395.391 2.787.945 4.062a8.518 8.518 0 001.348 2.173 8.14 8.14 0 003.132 2.23 7.934 7.934 0 002.113.54c.074.015.149.015.209.015zm-2.934-.398a4.102 4.102 0 01-.45-.228 8.5 8.5 0 01-2.038-1.534c-1.094-1.137-1.827-2.566-2.247-4.08a15.184 15.184 0 01-.495-3.172 12.14 12.14 0 01.046-2.082c.135-1.257.495-2.501 1.124-3.58a6.889 6.889 0 011.783-2.053 6.23 6.23 0 011.633-.9 5.363 5.363 0 013.522-.045c.029 0 .029 0 .045.03.015.015.045.015.06.03.045.016.104.045.165.074.239.12.479.271.704.42a6.294 6.294 0 012.097 2.502c.42.914.615 1.934.631 2.938.014 1.079-.18 2.157-.645 3.146a6.42 6.42 0 01-2.638 2.832c.09.03.18.045.271.075.225.044.449.074.688.074 1.468.045 2.892-.66 3.94-1.647.195-.18.375-.375.54-.585.225-.27.435-.54.614-.823.239-.375.435-.75.614-1.154a8.112 8.112 0 00.509-1.664c.196-1.004.211-2.022.149-3.026-.135-2.022-.673-4.045-1.842-5.724a9.054 9.054 0 00-.555-.719 9.868 9.868 0 00-1.063-1.034 8.477 8.477 0 00-1.363-.915 9.927 9.927 0 00-1.692-.598l-.3-.06c-.209-.03-.42-.044-.634-.06a8.453 8.453 0 00-1.015.016c-.704.045-1.412.16-2.112.337C5.799 1.227 2.863 3.566 1.3 6.67A11.834 11.834 0 00.238 9.801a11.81 11.81 0 00-.104 3.775c.12 1.02.374 2.023.778 2.977.227.57.511 1.124.825 1.648 1.094 1.783 2.683 3.236 4.51 4.24.688.39 1.408.69 2.157.944.226.074.45.15.689.21z',
      html: 'M1.5 0h21l-1.91 21.563L11.977 24l-8.564-2.438L1.5 0zm7.031 9.75l-.232-2.718 10.059.003.23-2.622L5.412 4.41l.698 8.01h9.126l-.326 3.426-2.91.804-2.955-.81-.188-2.11H6.248l.33 4.171L12 19.351l5.379-1.443.744-8.157H8.531z',
      css: 'M0 0v20.16A3.84 3.84 0 0 0 3.84 24h16.32A3.84 3.84 0 0 0 24 20.16V3.84A3.84 3.84 0 0 0 20.16 0Zm14.256 13.08c1.56 0 2.28 1.08 2.304 2.64h-1.608c.024-.288-.048-.6-.144-.84-.096-.192-.288-.264-.552-.264-.456 0-.696.264-.696.84-.024.576.288.888.768 1.08.72.288 1.608.744 1.92 1.296q.432.648.432 1.656c0 1.608-.912 2.592-2.496 2.592-1.656 0-2.4-1.032-2.424-2.688h1.68c0 .792.264 1.176.792 1.176.264 0 .456-.072.552-.24.192-.312.24-1.176-.048-1.512-.312-.408-.912-.6-1.32-.816q-.828-.396-1.224-.936c-.24-.36-.36-.888-.36-1.536 0-1.44.936-2.472 2.424-2.448m5.4 0c1.584 0 2.304 1.08 2.328 2.64h-1.608c0-.288-.048-.6-.168-.84-.096-.192-.264-.264-.528-.264-.48 0-.72.264-.72.84s.288.888.792 1.08c.696.288 1.608.744 1.92 1.296.264.432.408.984.408 1.656.024 1.608-.888 2.592-2.472 2.592-1.68 0-2.424-1.056-2.448-2.688h1.68c0 .744.264 1.176.792 1.176.264 0 .456-.072.552-.24.216-.312.264-1.176-.048-1.512-.288-.408-.888-.6-1.32-.816-.552-.264-.96-.576-1.2-.936s-.36-.888-.36-1.536c-.024-1.44.912-2.472 2.4-2.448m-11.031.018c.711-.006 1.419.198 1.839.63.432.432.672 1.128.648 1.992H9.336c.024-.456-.096-.792-.432-.96-.312-.144-.768-.048-.888.24-.12.264-.192.576-.168.864v3.504c0 .744.264 1.128.768 1.128a.65.65 0 0 0 .552-.264c.168-.24.192-.552.168-.84h1.776c.096 1.632-.984 2.712-2.568 2.688-1.536 0-2.496-.864-2.472-2.472v-4.032c0-.816.24-1.44.696-1.848.432-.408 1.146-.624 1.857-.63',
      shell: 'M21.038,4.9l-7.577-4.498C13.009,0.134,12.505,0,12,0c-0.505,0-1.009,0.134-1.462,0.403L2.961,4.9 C2.057,5.437,1.5,6.429,1.5,7.503v8.995c0,1.073,0.557,2.066,1.462,2.603l7.577,4.497C10.991,23.866,11.495,24,12,24 c0.505,0,1.009-0.134,1.461-0.402l7.577-4.497c0.904-0.537,1.462-1.529,1.462-2.603V7.503C22.5,6.429,21.943,5.437,21.038,4.9z M15.17,18.946l0.013,0.646c0.001,0.078-0.05,0.167-0.111,0.198l-0.383,0.22c-0.061,0.031-0.111-0.007-0.112-0.085L14.57,19.29 c-0.328,0.136-0.66,0.169-0.872,0.084c-0.04-0.016-0.057-0.075-0.041-0.142l0.139-0.584c0.011-0.046,0.036-0.092,0.069-0.121 c0.012-0.011,0.024-0.02,0.036-0.026c0.022-0.011,0.043-0.014,0.062-0.006c0.229,0.077,0.521,0.041,0.802-0.101 c0.357-0.181,0.596-0.545,0.592-0.907c-0.003-0.328-0.181-0.465-0.613-0.468c-0.55,0.001-1.064-0.107-1.072-0.917 c-0.007-0.667,0.34-1.361,0.889-1.8l-0.007-0.652c-0.001-0.08,0.048-0.168,0.111-0.2l0.37-0.236 c0.061-0.031,0.111,0.007,0.112,0.087l0.006,0.653c0.273-0.109,0.511-0.138,0.726-0.088c0.047,0.012,0.067,0.076,0.048,0.151 l-0.144,0.578c-0.011,0.044-0.036,0.088-0.065,0.116c-0.012,0.012-0.025,0.021-0.038,0.028c-0.019,0.01-0.038,0.013-0.057,0.009 c-0.098-0.022-0.332-0.073-0.699,0.113c-0.385,0.195-0.52,0.53-0.517,0.778c0.003,0.297,0.155,0.387,0.681,0.396 c0.7,0.012,1.003,0.318,1.01,1.023C16.105,17.747,15.736,18.491,15.17,18.946z M19.143,17.859c0,0.06-0.008,0.116-0.058,0.145 l-1.916,1.164c-0.05,0.029-0.09,0.004-0.09-0.056v-0.494c0-0.06,0.037-0.093,0.087-0.122l1.887-1.129 c0.05-0.029,0.09-0.004,0.09,0.056V17.859z M20.459,6.797l-7.168,4.427c-0.894,0.523-1.553,1.109-1.553,2.187v8.833 c0,0.645,0.26,1.063,0.66,1.184c-0.131,0.023-0.264,0.039-0.398,0.039c-0.42,0-0.833-0.114-1.197-0.33L3.226,18.64 c-0.741-0.44-1.201-1.261-1.201-2.142V7.503c0-0.881,0.46-1.702,1.201-2.142l7.577-4.498c0.363-0.216,0.777-0.33,1.197-0.33 c0.419,0,0.833,0.114,1.197,0.33l7.577,4.498c0.624,0.371,1.046,1.013,1.164,1.732C21.686,6.557,21.12,6.411,20.459,6.797z',
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
          iconEl.setAttribute('d', icon);
          var size = 14;
          var scale = size / 24;
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

/// Read `.raysense/trends/history.json` if it exists. The file is only
/// written by `--trend record`; absence is normal and silent.
fn read_trend_samples(root: &Path) -> Option<Vec<TrendPoint>> {
    let path = root.join(".raysense/trends/history.json");
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str::<Vec<TrendPoint>>(&content).ok()
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

/// Append one row to `<root>/.raysense/trends/history.json` describing
/// the score, quality signal, rule count, and per-dimension scores at
/// `now`. Used both by `raysense trend record` and by `raysense
/// baseline save`. Returns the path the row was written to.
fn append_trend_sample(report: &ScanReport, health: &HealthSummary) -> Result<PathBuf> {
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
        "functions": report.functions.len(),
        "root_causes": health.root_causes,
        "overall_grade": health.grades.overall,
    }));
    fs::write(&path, serde_json::to_string_pretty(&samples)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
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
    let memory = crate::memory::RayMemory::from_report_with_config(&report, &config)?;
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

    // Record a trend sample so the score-drift series captures every
    // baseline save automatically. Failures here are non-fatal: the
    // baseline itself succeeded, the trend log is best-effort.
    if let Err(reason) = append_trend_sample(&report, &health) {
        eprintln!("warning: failed to record trend sample: {reason}");
    }

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
}
