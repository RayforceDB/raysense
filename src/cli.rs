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
    BaselineDiff, ProjectBaseline, RaysenseConfig,
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

/// Advanced subcommands. Most users never need these — the top-level flags
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
/* Nord palette (https://www.nordtheme.com) — low-fatigue, eye-friendly. */
:root{{
  --bg:#2e3440;       /* nord0  polar night */
  --surface:#3b4252;  /* nord1 */
  --surface2:#434c5e; /* nord2 */
  --line:#4c566a;     /* nord3 */
  --text:#eceff4;     /* nord6  snow storm */
  --muted:#9aa6b6;    /* between nord3 and nord4 */
  --accent:#88c0d0;   /* nord8  frost */
  --good:#a3be8c;     /* nord14 aurora green */
  --warn:#ebcb8b;     /* nord13 aurora yellow */
  --bad:#bf616a;      /* nord11 aurora red */
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
.edge{{pointer-events:none;opacity:.7;fill:none;stroke-linecap:round;stroke-width:1.4;}}
.edge.imports{{stroke:var(--accent);}}
.edge.calls{{stroke:var(--good);}}
.edge.inherits{{stroke:var(--warn);}}
.edge.dim{{opacity:.08;}}
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
  // Nord palette — every color drawn from frost (cool blues/teals) and
  // aurora (warm accents). Languages share the same saturation and
  // lightness, so the treemap reads as one theme.
  var LANG = {{
    rust:       '#d08770', // nord12 aurora orange
    c:          '#81a1c1', // nord9  frost slate-blue
    cpp:        '#b48ead', // nord15 aurora purple
    python:     '#a3be8c', // nord14 aurora green
    typescript: '#5e81ac', // nord10 frost dark blue
    javascript: '#ebcb8b', // nord13 aurora yellow
    go:         '#8fbcbb', // nord7  frost teal
    java:       '#bf616a', // nord11 aurora red
    ruby:       '#bf616a', // nord11
    markdown:   '#4c566a', // nord3  polar night lightest
    toml:       '#4c566a',
    yaml:       '#4c566a',
    json:       '#4c566a',
    html:       '#d08770',
    css:        '#88c0d0', // nord8  frost
    shell:      '#a3be8c'  // share with python (script colour)
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
    var FB = '#434c5e'; // nord2 — neutral mid-tone
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
      if (bf === 1) return '#bf616a'; // nord11 red
      if (bf === 2) return '#ebcb8b'; // nord13 yellow
      return '#a3be8c';                // nord14 green
    }}
    if (mode === 'test_gap') {{
      return item.test_gap ? '#d08770' : FB; // nord12 orange
    }}
    var attr = ATTR[mode]; if (!attr) return FB;
    var v = +item[attr] || 0;
    var max = files.reduce(function(m,it){{ return Math.max(m, +it[attr]||0); }}, 1) || 1;
    var ratio = v / max;
    var hue = HUE[mode] || 210;
    var lightness = 38 + Math.round(ratio * 22);
    return 'hsl(' + hue + ',32%,' + lightness + '%)';
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
    hint.textContent = fns.length + ' functions — click anywhere or press Esc to close';
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
      ttip.textContent = r.item.name + ' — cyclomatic ' + r.item.value + ', ' + r.item.lines + ' lines';
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
      if (r.w > 60 && r.h > 18) {{
        var label = document.createElementNS('http://www.w3.org/2000/svg','text');
        label.setAttribute('class','tile-label');
        label.setAttribute('x', r.x + 4);
        label.setAttribute('y', r.y + 12);
        label.textContent = (r.path.split('/').pop() || '');
        svg.appendChild(label);
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
    // Aggregate: count multiplicity per (from, to, type) — for raysense
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
            "trend samples={} score_delta={} rule_delta={}",
            health.metrics.trend.samples,
            health.metrics.trend.score_delta,
            health.metrics.trend.rule_delta
        );
    } else {
        println!("trend unavailable");
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
            "evolution available=true commits_sampled={} changed_files={} authors={}",
            health.metrics.evolution.commits_sampled,
            health.metrics.evolution.changed_files,
            health.metrics.evolution.author_count
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
