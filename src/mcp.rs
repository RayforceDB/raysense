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
    build_baseline, compute_health_with_config, diff_baselines, is_foundation_file,
    scan_path_with_config, ImportResolution, ProjectBaseline, RaysenseConfig,
};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

const PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Default)]
struct McpState {
    last_path: Option<PathBuf>,
    last_config: Option<RaysenseConfig>,
    baseline: Option<ProjectBaseline>,
    cached_health: Option<HealthCache>,
}

struct HealthCache {
    root: PathBuf,
    signature: String,
    report_root: PathBuf,
    health: crate::HealthSummary,
}

/// Tools that mutate scan inputs (config, baselines, plugins, sessions) or
/// the on-disk repo state must clear the cached health before they run, so
/// the next read tool re-scans.
const HEALTH_INVALIDATING_TOOLS: &[&str] = &[
    "raysense_session_start",
    "raysense_session_end",
    "raysense_rescan",
    "raysense_what_if",
    "raysense_baseline_save",
    "raysense_config_write",
    "raysense_plugin_add",
    "raysense_plugin_add_standard",
    "raysense_plugin_sync",
    "raysense_plugin_remove",
];

pub fn run() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut state = McpState::default();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match handle_message(&line, &mut state) {
            Ok(Some(response)) => response,
            Ok(None) => continue,
            Err(err) => jsonrpc_error(Value::Null, -32700, &err.to_string()),
        };
        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}

fn handle_message(line: &str, state: &mut McpState) -> Result<Option<Value>> {
    let message: Value = serde_json::from_str(line).context("invalid JSON-RPC message")?;
    let id = message.get("id").cloned();
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return Ok(id.map(|id| jsonrpc_error(id, -32600, "missing method")));
    };

    match method {
        "initialize" => Ok(id.map(|id| jsonrpc_result(id, initialize_result()))),
        "notifications/initialized" => Ok(None),
        "ping" => Ok(id.map(|id| jsonrpc_result(id, json!({})))),
        "tools/list" => Ok(id.map(|id| jsonrpc_result(id, tools_list()))),
        "tools/call" => {
            let Some(id) = id else {
                return Ok(None);
            };
            let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
            let result = match call_tool(&params, state) {
                Ok(result) => jsonrpc_result(id, tool_success(result)),
                Err(err) => jsonrpc_result(id, tool_error(err.to_string())),
            };
            Ok(Some(result))
        }
        _ => Ok(id.map(|id| jsonrpc_error(id, -32601, "method not found"))),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "serverInfo": {
            "name": "raysense",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "raysense_config_read",
                "description": "Read Raysense defaults or the effective config for a project root/config path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
                        "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."}
                    }
                }
            },
            {
                "name": "raysense_config_write",
                "description": "Write Raysense config as TOML so future scans use the same policy.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
                        "config_path": {"type": "string", "description": "Destination config file. Defaults to <path>/.raysense.toml."},
                        "config": config_schema()
                    },
                    "required": ["config"]
                }
            },
            {
                "name": "raysense_health",
                "description": "Scan a project and return health using either file config or an inline config override.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
                        "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
                        "config": config_schema()
                    }
                }
            },
            {
                "name": "raysense_scan",
                "description": "Scan a project and return raw scan facts: files, functions, entry points, imports, calls, call edges, and graph metrics.",
                "inputSchema": path_limit_schema("Maximum rows per fact collection. Defaults to 1000.")
            },
            {
                "name": "raysense_edges",
                "description": "Return resolved dependency edges from a project scan.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
                        "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
                        "config": config_schema(),
                        "all": {"type": "boolean", "description": "Include unresolved, external, and system imports. Defaults to false."},
                        "limit": {"type": "integer", "minimum": 1, "description": "Maximum edges to return. Defaults to 1000."}
                    }
                }
            },
            {
                "name": "raysense_hotspots",
                "description": "Return file dependency hotspots from project health.",
                "inputSchema": health_limit_schema("Maximum hotspots to return. Defaults to 100.")
            },
            {
                "name": "raysense_rules",
                "description": "Return health rule findings from project health.",
                "inputSchema": health_limit_schema("Maximum findings to return. Defaults to 100.")
            },
            {
                "name": "raysense_module_edges",
                "description": "Return DSM top-level module dependency edges from project health.",
                "inputSchema": health_limit_schema("Maximum module edges to return. Defaults to 100.")
            },
            {
                "name": "raysense_architecture",
                "description": "Return architecture metrics, root cause scores, cycles, levels, and unstable modules.",
                "inputSchema": health_limit_schema("Maximum repeated architecture rows to return. Defaults to 100.")
            },
            {
                "name": "raysense_coupling",
                "description": "Return coupling metrics, dependency hotspots, and top module edges.",
                "inputSchema": health_limit_schema("Maximum hotspot and module-edge rows to return. Defaults to 100.")
            },
            {
                "name": "raysense_cycles",
                "description": "Return detected dependency cycles.",
                "inputSchema": health_limit_schema("Maximum cycles to return. Defaults to 100.")
            },
            {
                "name": "raysense_hottest",
                "description": "Return the hottest files and functions by dependency and call traffic.",
                "inputSchema": health_limit_schema("Maximum hot items per list to return. Defaults to 100.")
            },
            {
                "name": "raysense_blast_radius",
                "description": "Return reachable local dependency impact for a file, or the current max blast-radius file when omitted.",
                "inputSchema": blast_radius_schema()
            },
            {
                "name": "raysense_level",
                "description": "Return dependency level information for all modules or one requested module.",
                "inputSchema": level_schema()
            },
            {
                "name": "raysense_session_start",
                "description": "Save an in-memory and persisted baseline for an agent session.",
                "inputSchema": baseline_schema("Optional persisted baseline directory.")
            },
            {
                "name": "raysense_session_end",
                "description": "Compare current health to the in-memory session baseline.",
                "inputSchema": baseline_schema("Persisted session baseline directory.")
            },
            {
                "name": "raysense_rescan",
                "description": "Rescan the last session path or the provided path.",
                "inputSchema": path_limit_schema("Maximum rows per fact collection. Defaults to 1000.")
            },
            {
                "name": "raysense_check_rules",
                "description": "Scan and return pass/fail rule status.",
                "inputSchema": health_limit_schema("Maximum findings to return. Defaults to 100.")
            },
            {
                "name": "raysense_policy_check",
                "description": "Evaluate every .rfl policy file in <project>/.raysense/policies (or a caller-supplied directory) against the saved baseline. Each policy is a Rayfall expression that must return a RAY_TABLE with columns severity, code, path, message; severities are case-insensitive info / warning / error. Use this when teams want to ship architectural rules as code-reviewable files instead of asking raysense for a built-in flag. Pairs with raysense_baseline_save (run that first to materialize tables).",
                "inputSchema": policy_check_schema()
            },
            {
                "name": "raysense_evolution",
                "description": "Return changed-file evolution metrics.",
                "inputSchema": health_limit_schema("Maximum changed files to return. Defaults to 100.")
            },
            {
                "name": "raysense_dsm",
                "description": "Return DSM, module level, and stability metrics.",
                "inputSchema": health_limit_schema("Maximum module edges to return. Defaults to 100.")
            },
            {
                "name": "raysense_test_gaps",
                "description": "Return test-gap metrics and files without nearby tests.",
                "inputSchema": health_limit_schema("Maximum files to return. Defaults to 100.")
            },
            {
                "name": "raysense_visualize",
                "description": "Write a self-refreshing HTML architecture dashboard and optionally return the HTML.",
                "inputSchema": visualize_schema()
            },
            {
                "name": "raysense_sarif",
                "description": "Write a SARIF code-scanning report for rule findings and optionally return the SARIF JSON.",
                "inputSchema": sarif_schema()
            },
            {
                "name": "raysense_plugins",
                "description": "List configured generic language plugins.",
                "inputSchema": path_limit_schema("Unused.")
            },
            {
                "name": "raysense_standard_plugins",
                "description": "Return built-in standard language plugin profiles that can be written into config.",
                "inputSchema": path_limit_schema("Maximum plugins to return. Defaults to all.")
            },
            {
                "name": "raysense_plugin_add",
                "description": "Add or replace a generic language plugin in project config.",
                "inputSchema": plugin_add_schema()
            },
            {
                "name": "raysense_plugin_add_standard",
                "description": "Add standard language plugin profiles to project config.",
                "inputSchema": plugin_add_standard_schema()
            },
            {
                "name": "raysense_plugin_remove",
                "description": "Remove a generic language plugin from project config.",
                "inputSchema": plugin_remove_schema()
            },
            {
                "name": "raysense_plugin_validate",
                "description": "Validate a local generic language plugin directory.",
                "inputSchema": plugin_validate_schema()
            },
            {
                "name": "raysense_plugin_scaffold",
                "description": "Create a project-local generic language plugin template.",
                "inputSchema": plugin_scaffold_schema()
            },
            {
                "name": "raysense_plugin_sync",
                "description": "Materialize bundled standard plugin profiles into project-local .raysense/plugins/<name>/plugin.toml files. Skips existing manifests unless force is true.",
                "inputSchema": plugin_sync_schema()
            },
            {
                "name": "raysense_remediations",
                "description": "Return suggested remediation actions for current findings and test gaps.",
                "inputSchema": health_limit_schema("Maximum remediation actions to return. Defaults to 100.")
            },
            {
                "name": "raysense_what_if",
                "description": "Simulate scan config changes or local dependency edge removal and return health deltas without writing files.",
                "inputSchema": what_if_schema()
            },
            {
                "name": "raysense_break_cycle_recommendations",
                "description": "Rank candidate local edges whose removal would reduce the report's cycle count.",
                "inputSchema": break_cycle_recommendations_schema()
            },
            {
                "name": "raysense_trend",
                "description": "Query the persisted trend history (.raysense/trends/history.json). Filter by window and dimension; choose summary/table/json output.",
                "inputSchema": trend_schema()
            },
            {
                "name": "raysense_drift",
                "description": "Compute regressions across the trend history window: dimensions that worsened, files new to or risen on the hotspot list, rules newly tripped or with increased counts.",
                "inputSchema": drift_schema()
            },
            {
                "name": "raysense_policy_presets",
                "description": "List built-in policy preset names.",
                "inputSchema": path_limit_schema("Unused.")
            },
            {
                "name": "raysense_policy_init",
                "description": "Apply a built-in policy preset and write the resulting config.",
                "inputSchema": policy_init_schema()
            },
            {
                "name": "raysense_memory_summary",
                "description": "Materialize Rayforce-backed memory tables and return their row/column counts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
                        "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
                        "config": config_schema()
                    }
                }
            },
            {
                "name": "raysense_baseline_save",
                "description": "Save a project baseline manifest plus Rayforce splayed baseline tables.",
                "inputSchema": baseline_schema("Destination baseline directory. Defaults to <path>/.raysense/baseline.")
            },
            {
                "name": "raysense_baseline_diff",
                "description": "Diff the current project health against a saved baseline.",
                "inputSchema": baseline_schema("Baseline directory. Defaults to <path>/.raysense/baseline.")
            },
            {
                "name": "raysense_baseline_tables",
                "description": "List Rayforce splayed tables saved in a Raysense baseline.",
                "inputSchema": baseline_table_schema(false)
            },
            {
                "name": "raysense_baseline_table_read",
                "description": "Read rows from a Rayforce splayed table saved in a Raysense baseline.",
                "inputSchema": baseline_table_schema(true)
            },
            {
                "name": "raysense_baseline_query",
                "description": "Evaluate a Rayfall expression against a saved baseline table. The named table is bound to the symbol `t`; the expression must return a RAY_TABLE. Canonical form: (select {from: t where: <pred>}). Operators are prefix and arity-strict, e.g. (> lines 500), (and p q), (== language \"rust\"). For schema and worked examples, load the `query` skill bundled with this plugin (`/raysense:query`).",
                "inputSchema": baseline_query_schema()
            },
            {
                "name": "raysense_baseline_import_csv",
                "description": "Import an external CSV as a new baseline table.  First row is treated as headers; column types are inferred.  The new table sits alongside files / functions / call_edges / ... and is reachable from raysense_baseline_query, raysense_baseline_table_read, and policy packs.  Use this to bring coverage data, lint counts, runtime traces, or embeddings into the same query substrate as the structural baseline.",
                "inputSchema": baseline_import_csv_schema()
            }
        ]
    })
}

fn call_tool(params: &Value, state: &mut McpState) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing tool name"))?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    if HEALTH_INVALIDATING_TOOLS.contains(&name) {
        state.cached_health = None;
    }

    match name {
        "raysense_config_read" => read_config_tool(&args),
        "raysense_config_write" => write_config_tool(&args),
        "raysense_health" => health_tool(&args, state),
        "raysense_scan" => scan_tool(&args),
        "raysense_edges" => edges_tool(&args),
        "raysense_hotspots" => hotspots_tool(&args, state),
        "raysense_rules" => rules_tool(&args),
        "raysense_module_edges" => module_edges_tool(&args),
        "raysense_architecture" => architecture_tool(&args, state),
        "raysense_coupling" => coupling_tool(&args),
        "raysense_cycles" => cycles_tool(&args),
        "raysense_hottest" => hottest_tool(&args),
        "raysense_blast_radius" => blast_radius_tool(&args),
        "raysense_level" => level_tool(&args),
        "raysense_session_start" => session_start_tool(&args, state),
        "raysense_session_end" => session_end_tool(&args, state),
        "raysense_rescan" => rescan_tool(&args, state),
        "raysense_check_rules" => check_rules_tool(&args),
        "raysense_policy_check" => policy_check_tool(&args),
        "raysense_evolution" => evolution_tool(&args, state),
        "raysense_dsm" => dsm_tool(&args, state),
        "raysense_test_gaps" => test_gaps_tool(&args),
        "raysense_visualize" => visualize_tool(&args),
        "raysense_sarif" => sarif_tool(&args),
        "raysense_plugins" => plugins_tool(&args),
        "raysense_standard_plugins" => standard_plugins_tool(&args),
        "raysense_plugin_add" => plugin_add_tool(&args),
        "raysense_plugin_add_standard" => plugin_add_standard_tool(&args),
        "raysense_plugin_sync" => plugin_sync_tool(&args),
        "raysense_plugin_remove" => plugin_remove_tool(&args),
        "raysense_plugin_validate" => plugin_validate_tool(&args),
        "raysense_plugin_scaffold" => plugin_scaffold_tool(&args),
        "raysense_remediations" => remediations_tool(&args),
        "raysense_what_if" => what_if_tool(&args),
        "raysense_break_cycle_recommendations" => break_cycle_recommendations_tool(&args),
        "raysense_trend" => trend_tool(&args),
        "raysense_drift" => drift_tool(&args),
        "raysense_policy_presets" => policy_presets_tool(&args),
        "raysense_policy_init" => policy_init_tool(&args),
        "raysense_memory_summary" => memory_summary_tool(&args),
        "raysense_baseline_save" => baseline_save_tool(&args),
        "raysense_baseline_diff" => baseline_diff_tool(&args),
        "raysense_baseline_tables" => baseline_tables_tool(&args),
        "raysense_baseline_table_read" => baseline_table_read_tool(&args),
        "raysense_baseline_query" => baseline_query_tool(&args),
        "raysense_baseline_import_csv" => baseline_import_csv_tool(&args),
        _ => Err(anyhow!("unknown tool {name}")),
    }
}

fn read_config_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let (config, source) = load_config(&root, config_path_arg(args)?)?;
    Ok(json!({
        "source": source,
        "config": config
    }))
}

fn write_config_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let path = config_path_arg(args)?.unwrap_or_else(|| root.join(".raysense.toml"));
    let config = config_arg(args)?;
    let toml = toml::to_string_pretty(&config).context("failed to encode config as TOML")?;
    fs::write(&path, toml).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(json!({
        "path": path,
        "config": config
    }))
}

fn health_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let (root, health) = health_from_args_cached(args, state)?;

    Ok(json!({
        "root": root,
        "health": health
    }))
}

fn scan_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let limit = limit_arg(args, 1000)?;
    let report = scan_path_with_config(&root, &config)?;

    Ok(json!({
        "root": report.snapshot.root,
        "snapshot": report.snapshot,
        "files": limited(&report.files, limit),
        "functions": limited(&report.functions, limit),
        "entry_points": limited(&report.entry_points, limit),
        "imports": limited(&report.imports, limit),
        "calls": limited(&report.calls, limit),
        "call_edges": limited(&report.call_edges, limit),
        "graph": report.graph,
        "limits": {
            "limit": limit,
            "files_total": report.files.len(),
            "functions_total": report.functions.len(),
            "entry_points_total": report.entry_points.len(),
            "imports_total": report.imports.len(),
            "calls_total": report.calls.len(),
            "call_edges_total": report.call_edges.len()
        }
    }))
}

fn edges_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let all = bool_arg(args, "all", false)?;
    let limit = limit_arg(args, 1000)?;
    let report = scan_path_with_config(&root, &config)?;
    let mut total = 0usize;
    let mut edges = Vec::new();

    for import in &report.imports {
        if !all && import.resolution != ImportResolution::Local {
            continue;
        }
        total += 1;
        if edges.len() >= limit {
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

        edges.push(json!({
            "import_id": import.import_id,
            "from": from,
            "to": to,
            "kind": import.kind,
            "resolution": import.resolution
        }));
    }

    Ok(json!({
        "root": report.snapshot.root,
        "edges": edges,
        "limit": limit,
        "total": total
    }))
}

fn hotspots_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let (root, health) = health_from_args_cached(args, state)?;
    let limit = limit_arg(args, 100)?;

    Ok(json!({
        "root": root,
        "hotspots": limited(&health.hotspots, limit),
        "limit": limit,
        "total": health.hotspots.len()
    }))
}

fn rules_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;

    Ok(json!({
        "root": root,
        "rules": limited(&health.rules, limit),
        "limit": limit,
        "total": health.rules.len()
    }))
}

fn module_edges_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;

    Ok(json!({
        "root": root,
        "module_edges": limited(&health.metrics.dsm.top_module_edges, limit),
        "limit": limit,
        "total": health.metrics.dsm.top_module_edges.len()
    }))
}

fn architecture_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let (root, health) = health_from_args_cached(args, state)?;
    // Default flipped: summary by default, full only when detail=true.
    // The full surface is what every architecture analysis returns
    // through baseline tables anyway -- agents that want to keep
    // working context small can stop here, agents that want everything
    // pass detail=true.  The legacy `summary: true` keyword still works.
    let detail = detail_arg(args);
    let summary = !detail || summary_arg(args);
    let limit = if summary {
        SUMMARY_TOP_N
    } else {
        limit_arg(args, 100)?
    };

    if summary {
        return Ok(json!({
            "root": root,
            "score": health.score,
            "quality_signal": health.quality_signal,
            "root_causes": health.root_causes,
            "summary": {
                "module_depth": health.metrics.architecture.module_depth,
                "max_blast_radius": health.metrics.architecture.max_blast_radius,
                "max_blast_radius_file": health.metrics.architecture.max_blast_radius_file,
                "attack_surface_files": health.metrics.architecture.attack_surface_files,
                "attack_surface_ratio": health.metrics.architecture.attack_surface_ratio,
                "total_graph_files": health.metrics.architecture.total_graph_files,
                "average_distance_from_main_sequence": health.metrics.architecture.average_distance_from_main_sequence,
                "cycle_total": health.metrics.architecture.cycles.len(),
                "upward_violation_total": health.metrics.architecture.upward_violations.len(),
                "unstable_module_total": health.metrics.architecture.unstable_modules.len(),
                "stable_foundation_total": health.metrics.architecture.stable_foundations.len(),
                "level_total": health.metrics.architecture.levels.len(),
                "top_cycles": limited(&health.metrics.architecture.cycles, limit),
                "top_unstable_modules": limited(&health.metrics.architecture.unstable_modules, limit),
                "top_upward_violations": limited(&health.metrics.architecture.upward_violations, limit),
            },
            "explore": EXPLORE_HINT_ARCHITECTURE.clone(),
        }));
    }

    Ok(json!({
        "root": root,
        "score": health.score,
        "quality_signal": health.quality_signal,
        "root_causes": health.root_causes,
        "architecture": {
            "module_depth": health.metrics.architecture.module_depth,
            "max_blast_radius": health.metrics.architecture.max_blast_radius,
            "max_blast_radius_file": health.metrics.architecture.max_blast_radius_file,
            "max_non_foundation_blast_radius": health.metrics.architecture.max_non_foundation_blast_radius,
            "max_non_foundation_blast_radius_file": health.metrics.architecture.max_non_foundation_blast_radius_file,
            "attack_surface_files": health.metrics.architecture.attack_surface_files,
            "attack_surface_ratio": health.metrics.architecture.attack_surface_ratio,
            "total_graph_files": health.metrics.architecture.total_graph_files,
            "average_distance_from_main_sequence": health.metrics.architecture.average_distance_from_main_sequence,
            "levels": health.metrics.architecture.levels,
            "cycles": limited(&health.metrics.architecture.cycles, limit),
            "upward_violations": limited(&health.metrics.architecture.upward_violations, limit),
            "upward_violation_ratio": health.metrics.architecture.upward_violation_ratio,
            "unstable_modules": limited(&health.metrics.architecture.unstable_modules, limit),
            "stable_foundations": limited(&health.metrics.architecture.stable_foundations, limit),
            "distance_metrics": limited(&health.metrics.architecture.distance_metrics, limit),
            "cycle_total": health.metrics.architecture.cycles.len(),
            "upward_violation_total": health.metrics.architecture.upward_violations.len(),
            "unstable_module_total": health.metrics.architecture.unstable_modules.len(),
            "stable_foundation_total": health.metrics.architecture.stable_foundations.len(),
            "distance_metric_total": health.metrics.architecture.distance_metrics.len()
        },
        "dsm": {
            "module_count": health.metrics.dsm.module_count,
            "module_edges": health.metrics.dsm.module_edges,
            "top_module_edges": limited(&health.metrics.dsm.top_module_edges, limit)
        }
    }))
}

fn coupling_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;

    Ok(json!({
        "root": root,
        "coupling": health.metrics.coupling,
        "hotspots": limited(&health.hotspots, limit),
        "module_edges": limited(&health.metrics.dsm.top_module_edges, limit),
        "limits": {
            "limit": limit,
            "hotspots_total": health.hotspots.len(),
            "module_edges_total": health.metrics.dsm.top_module_edges.len()
        }
    }))
}

fn cycles_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;

    Ok(json!({
        "root": root,
        "cycles": limited(&health.metrics.architecture.cycles, limit),
        "limit": limit,
        "total": health.metrics.architecture.cycles.len()
    }))
}

fn hottest_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;

    Ok(json!({
        "root": root,
        "files": limited(&health.hotspots, limit),
        "top_called_functions": limited(&health.metrics.calls.top_called_functions, limit),
        "top_calling_functions": limited(&health.metrics.calls.top_calling_functions, limit),
        "complex_functions": limited(&health.metrics.complexity.complex_functions, limit),
        "limits": {
            "limit": limit,
            "file_total": health.hotspots.len(),
            "top_called_total": health.metrics.calls.top_called_functions.len(),
            "top_calling_total": health.metrics.calls.top_calling_functions.len(),
            "complex_function_total": health.metrics.complexity.complex_functions.len()
        }
    }))
}

fn blast_radius_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let limit = limit_arg(args, 100)?;
    let requested_file = args.get("file").and_then(Value::as_str);
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let file_id = match requested_file {
        Some(file) => {
            find_file_id(&report, file).ok_or_else(|| anyhow!("file not found in scan: {file}"))?
        }
        None => find_file_id(&report, &health.metrics.architecture.max_blast_radius_file)
            .ok_or_else(|| anyhow!("no max blast-radius file found"))?,
    };
    let Some(file) = report.files.get(file_id) else {
        return Err(anyhow!("file id {file_id} is out of range"));
    };
    let reachable = reachable_files(&report, file_id, limit);
    let reachable_total = reachable_count(&report, file_id);

    Ok(json!({
        "root": report.snapshot.root,
        "file_id": file_id,
        "file": file.path,
        "blast_radius": reachable_total,
        "is_foundation": is_foundation_file(&report, &config, file_id),
        "reachable_files": reachable,
        "limit": limit
    }))
}

fn level_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let module = args.get("module").and_then(Value::as_str);
    let levels = &health.metrics.architecture.levels;

    if let Some(module) = module {
        return Ok(json!({
            "root": root,
            "module": module,
            "level": levels.get(module),
            "found": levels.contains_key(module)
        }));
    }

    Ok(json!({
        "root": root,
        "levels": levels,
        "total": levels.len()
    }))
}

fn session_start_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let root = root_arg(args)?;
    let baseline_path = baseline_dir_arg(args, &root).ok();
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let baseline = build_baseline(&report, &health);
    if let Some(path) = baseline_path.as_ref() {
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create session baseline {}", path.display()))?;
        fs::write(
            path.join("session.json"),
            serde_json::to_string_pretty(&baseline)?,
        )
        .with_context(|| format!("failed to write session baseline {}", path.display()))?;
    }
    state.last_path = Some(root.clone());
    state.last_config = Some(config);
    state.baseline = Some(baseline.clone());
    Ok(json!({
        "root": report.snapshot.root,
        "quality_signal": health.quality_signal,
        "score": health.score,
        "baseline_path": baseline_path,
        "baseline": baseline
    }))
}

fn session_end_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let root = args
        .get("path")
        .map(|_| root_arg(args))
        .transpose()?
        .or_else(|| state.last_path.clone())
        .ok_or_else(|| anyhow!("no session path; call raysense_session_start first"))?;
    let config = if args.get("config").is_some() || args.get("config_path").is_some() {
        effective_config(args, &root)?
    } else {
        state.last_config.clone().unwrap_or_default()
    };
    let before =
        if let Some(baseline) = state.baseline.clone() {
            baseline
        } else {
            let baseline_dir = baseline_dir_arg(args, &root)?;
            let manifest = baseline_dir.join("session.json");
            serde_json::from_str(&fs::read_to_string(&manifest).with_context(|| {
                format!("failed to read session baseline {}", manifest.display())
            })?)?
        };
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let after = build_baseline(&report, &health);
    let diff = diff_baselines(&before, &after);
    Ok(json!({
        "root": report.snapshot.root,
        "pass": diff.score_delta >= 0 && diff.added_rules.is_empty(),
        "quality_signal": health.quality_signal,
        "score": health.score,
        "diff": diff
    }))
}

fn rescan_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let root = args
        .get("path")
        .map(|_| root_arg(args))
        .transpose()?
        .or_else(|| state.last_path.clone())
        .unwrap_or(std::env::current_dir().context("failed to read current directory")?);
    let config = if args.get("config").is_some() || args.get("config_path").is_some() {
        effective_config(args, &root)?
    } else {
        state.last_config.clone().unwrap_or_default()
    };
    state.last_path = Some(root.clone());
    state.last_config = Some(config.clone());
    let limit = limit_arg(args, 1000)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    Ok(json!({
        "root": report.snapshot.root,
        "snapshot": report.snapshot,
        "quality_signal": health.quality_signal,
        "health": health,
        "files": limited(&report.files, limit),
        "functions": limited(&report.functions, limit),
        "imports": limited(&report.imports, limit),
        "calls": limited(&report.calls, limit),
        "call_edges": limited(&report.call_edges, limit)
    }))
}

fn check_rules_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;
    let pass = !health
        .rules
        .iter()
        .any(|rule| matches!(rule.severity, crate::RuleSeverity::Error));
    Ok(json!({
        "root": root,
        "pass": pass,
        "quality_signal": health.quality_signal,
        "rules": limited(&health.rules, limit),
        "total": health.rules.len()
    }))
}

fn policy_check_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let baseline_dir = baseline_dir_arg(args, &root)?;
    let tables_dir = baseline_dir.join("tables");
    let policies_dir = args
        .get("policies_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".raysense/policies"));

    let results =
        crate::memory::eval_all_policies(&tables_dir, &policies_dir).with_context(|| {
            format!(
                "failed to walk policies directory {}",
                policies_dir.display()
            )
        })?;

    let payload: Vec<Value> = results
        .iter()
        .map(|r| match &r.findings {
            Ok(findings) => json!({
                "policy": r.path.display().to_string(),
                "ok": true,
                "findings": findings,
            }),
            Err(err) => json!({
                "policy": r.path.display().to_string(),
                "ok": false,
                "error": err.to_string(),
            }),
        })
        .collect();
    let exit = crate::memory::policy_exit_code(&results);
    Ok(json!({
        "root": root,
        "policies_path": policies_dir,
        "pass": exit == 0,
        "exit": exit,
        "policies": payload,
        "total": results.len(),
    }))
}

fn evolution_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let (root, health) = health_from_args_cached(args, state)?;
    let limit = limit_arg(args, 100)?;
    Ok(json!({
        "root": root,
        "evolution": {
            "available": health.metrics.evolution.available,
            "reason": health.metrics.evolution.reason,
            "commits_sampled": health.metrics.evolution.commits_sampled,
            "changed_files": health.metrics.evolution.changed_files,
            "top_changed_files": limited(&health.metrics.evolution.top_changed_files, limit),
            "author_count": health.metrics.evolution.author_count,
            "top_authors": limited(&health.metrics.evolution.top_authors, limit),
            "file_ownership": limited(&health.metrics.evolution.file_ownership, limit),
            "temporal_hotspots": limited(&health.metrics.evolution.temporal_hotspots, limit),
            "file_ages": limited(&health.metrics.evolution.file_ages, limit),
            "change_coupling": limited(&health.metrics.evolution.change_coupling, limit)
        }
    }))
}

fn dsm_tool(args: &Value, state: &mut McpState) -> Result<Value> {
    let (root, health) = health_from_args_cached(args, state)?;
    let detail = detail_arg(args);
    let summary = !detail || summary_arg(args);
    let limit = if summary {
        SUMMARY_TOP_N
    } else {
        limit_arg(args, 100)?
    };

    if summary {
        return Ok(json!({
            "root": root,
            "summary": {
                "module_count": health.metrics.dsm.module_count,
                "level_count": health.metrics.architecture.levels.len(),
                "upward_violation_total": health.metrics.architecture.upward_violations.len(),
                "upward_violation_ratio": health.metrics.architecture.upward_violation_ratio,
                "unstable_module_total": health.metrics.architecture.unstable_modules.len(),
                "stable_foundation_total": health.metrics.architecture.stable_foundations.len(),
                "top_module_edges": limited(&health.metrics.dsm.top_module_edges, limit),
                "top_unstable_modules": limited(&health.metrics.architecture.unstable_modules, limit),
                "top_upward_violations": limited(&health.metrics.architecture.upward_violations, limit),
            },
            "explore": EXPLORE_HINT_DSM.clone(),
        }));
    }

    Ok(json!({
        "root": root,
        "dsm": health.metrics.dsm,
        "levels": health.metrics.architecture.levels,
        "upward_violations": limited(&health.metrics.architecture.upward_violations, limit),
        "upward_violation_ratio": health.metrics.architecture.upward_violation_ratio,
        "unstable_modules": limited(&health.metrics.architecture.unstable_modules, limit),
        "stable_foundations": limited(&health.metrics.architecture.stable_foundations, limit),
        "distance_metrics": limited(&health.metrics.architecture.distance_metrics, limit),
        "module_edges": limited(&health.metrics.dsm.top_module_edges, limit)
    }))
}

fn test_gaps_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let limit = limit_arg(args, 100)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    Ok(json!({
        "root": report.snapshot.root,
        "test_gap": health.metrics.test_gap,
        "candidate_files": limited(&health.metrics.test_gap.candidates, limit)
    }))
}

fn visualize_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let output = args
        .get("output_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".raysense/visualization.html"));
    let include_html = bool_arg(args, "include_html", false)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let html = crate::cli::visualization_html(&report, &health);
    fs::write(&output, &html).with_context(|| format!("failed to write {}", output.display()))?;

    Ok(json!({
        "root": report.snapshot.root,
        "output_path": output,
        "snapshot_id": report.snapshot.snapshot_id,
        "quality_signal": health.quality_signal,
        "score": health.score,
        "html": if include_html { Value::String(html) } else { Value::Null }
    }))
}

fn sarif_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let output = args
        .get("output_path")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let include_sarif = bool_arg(args, "include_sarif", false)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let sarif = crate::cli::sarif_report(&report, &health);

    if let Some(path) = output.as_ref() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(path, serde_json::to_string_pretty(&sarif)?)
            .with_context(|| format!("failed to write {}", path.display()))?;
    }

    Ok(json!({
        "root": report.snapshot.root,
        "output_path": output,
        "snapshot_id": report.snapshot.snapshot_id,
        "quality_signal": health.quality_signal,
        "score": health.score,
        "rules": health.rules.len(),
        "sarif": if include_sarif { sarif } else { Value::Null }
    }))
}

fn plugins_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let (config, source) = load_config(&root, config_path_arg(args)?)?;
    Ok(json!({
        "root": root,
        "source": source,
        "plugins": config.scan.plugins
    }))
}

fn standard_plugins_tool(args: &Value) -> Result<Value> {
    let limit = args
        .get("limit")
        .map(|_| limit_arg(args, usize::MAX))
        .transpose()?
        .unwrap_or(usize::MAX);
    let plugins = crate::standard_language_plugins();
    Ok(json!({
        "plugins": limited(&plugins, limit),
        "total": plugins.len()
    }))
}

fn plugin_add_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing plugin name"))?;
    let extensions = string_array_arg(args, "extensions")?;
    let file_names = string_array_arg(args, "file_names")?;
    if extensions.is_empty() && file_names.is_empty() {
        return Err(anyhow!("extensions or file_names must not be empty"));
    }
    let path = config_path_arg(args)?.unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = load_or_default_config(&path)?;
    config.scan.plugins.retain(|plugin| plugin.name != name);
    config.scan.plugins.push(crate::LanguagePluginConfig {
        name: name.to_string(),
        extensions,
        file_names,
        ..crate::LanguagePluginConfig::default()
    });
    write_config_path(&path, &config)?;

    Ok(json!({
        "root": root,
        "path": path,
        "config": config
    }))
}

fn plugin_sync_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let names = string_array_arg(args, "names")?;
    let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
    let summary = crate::cli::sync_standard_plugins(&root, &names, force)?;
    Ok(json!({
        "root": root,
        "wrote": summary.written.len(),
        "skipped": summary.skipped.len(),
        "written_paths": summary.written.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "skipped_paths": summary.skipped.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
    }))
}

fn plugin_add_standard_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let path = config_path_arg(args)?.unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = load_or_default_config(&path)?;
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
    write_config_path(&path, &config)?;

    Ok(json!({
        "root": root,
        "path": path,
        "plugins": config.scan.plugins,
        "total": config.scan.plugins.len()
    }))
}

fn plugin_remove_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing plugin name"))?;
    let path = config_path_arg(args)?.unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = load_or_default_config(&path)?;
    let before = config.scan.plugins.len();
    config
        .scan
        .plugins
        .retain(|plugin| !plugin.name.eq_ignore_ascii_case(name));
    let removed = before - config.scan.plugins.len();
    write_config_path(&path, &config)?;

    Ok(json!({
        "root": root,
        "path": path,
        "removed": removed,
        "config": config
    }))
}

fn plugin_validate_tool(args: &Value) -> Result<Value> {
    let dir = args
        .get("dir")
        .or_else(|| args.get("plugin_dir"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing plugin dir"))?;
    crate::cli::validate_plugin_dir(Path::new(dir))
}

fn plugin_scaffold_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let name = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing plugin name"))?;
    let extension = args
        .get("extension")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing plugin extension"))?;
    let dir = crate::cli::scaffold_plugin(&root, name, extension)?;
    let validation = crate::cli::validate_plugin_dir(&dir)?;
    Ok(json!({
        "root": root,
        "dir": dir,
        "validation": validation
    }))
}

fn remediations_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;
    Ok(json!({
        "root": root,
        "remediations": limited(&health.remediations, limit),
        "total": health.remediations.len()
    }))
}

fn what_if_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    if let Some(actions) = args.get("actions").and_then(Value::as_array) {
        if !actions.is_empty() {
            return what_if_sequence_tool(actions, &root, &config);
        }
    }
    match args.get("action").and_then(Value::as_str) {
        Some("remove_edge") => return what_if_edge_tool(args, &root, &config, "remove_edge"),
        Some("add_edge") => return what_if_edge_tool(args, &root, &config, "add_edge"),
        Some("remove_file") => return what_if_remove_file_tool(args, &root, &config),
        Some("move_file") => return what_if_move_file_tool(args, &root, &config),
        Some("break_cycle") => return what_if_break_cycle_tool(args, &root, &config),
        Some(action) => return Err(anyhow!("unsupported what-if action: {action}")),
        None => {}
    }

    let ignore_paths = string_array_arg(args, "ignore_paths")?;
    let generated_paths = string_array_arg(args, "generated_paths")?;
    let before_report = scan_path_with_config(&root, &config)?;
    let before_health = compute_health_with_config(&before_report, &config);
    let before = build_baseline(&before_report, &before_health);
    let mut simulated_config = config.clone();
    simulated_config
        .scan
        .ignored_paths
        .extend(ignore_paths.clone());
    simulated_config
        .scan
        .generated_paths
        .extend(generated_paths.clone());
    let after_report = scan_path_with_config(&root, &simulated_config)?;
    let after_health = compute_health_with_config(&after_report, &simulated_config);
    let after = build_baseline(&after_report, &after_health);

    Ok(json!({
        "root": before_report.snapshot.root,
        "ignore_paths": ignore_paths,
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
        "diff": diff_baselines(&before, &after)
    }))
}

fn what_if_edge_tool(
    args: &Value,
    root: &Path,
    config: &RaysenseConfig,
    action: &str,
) -> Result<Value> {
    let from = args
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing from"))?;
    let to = args
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing to"))?;
    let before_report = scan_path_with_config(root, config)?;
    let before_health = compute_health_with_config(&before_report, config);
    let before = build_baseline(&before_report, &before_health);

    let after_report = match action {
        "remove_edge" => crate::simulate::remove_edge(&before_report, from, to),
        "add_edge" => crate::simulate::add_edge(&before_report, from, to),
        _ => unreachable!("validated what-if action"),
    }
    .map_err(|err| anyhow!(err.to_string()))?;

    let changed_edges = match action {
        "remove_edge" => before_report
            .imports
            .len()
            .saturating_sub(after_report.imports.len()),
        "add_edge" => after_report
            .imports
            .len()
            .saturating_sub(before_report.imports.len()),
        _ => unreachable!("validated what-if action"),
    };

    let after_health = compute_health_with_config(&after_report, config);
    let after = build_baseline(&after_report, &after_health);

    Ok(json!({
        "root": before_report.snapshot.root,
        "action": action,
        "from": from,
        "to": to,
        "changed_edges": changed_edges,
        "before": what_if_health_summary(&before_health),
        "after": what_if_health_summary(&after_health),
        "diff": diff_baselines(&before, &after)
    }))
}

fn what_if_remove_file_tool(args: &Value, root: &Path, config: &RaysenseConfig) -> Result<Value> {
    let file = args
        .get("file")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing file"))?;
    let before_report = scan_path_with_config(root, config)?;
    let before_health = compute_health_with_config(&before_report, config);
    let before = build_baseline(&before_report, &before_health);
    let after_report = crate::simulate_remove_file(&before_report, file)
        .map_err(|err| anyhow!(err.to_string()))?;
    let after_health = compute_health_with_config(&after_report, config);
    let after = build_baseline(&after_report, &after_health);

    Ok(json!({
        "root": before_report.snapshot.root,
        "action": "remove_file",
        "file": file,
        "before": what_if_health_summary(&before_health),
        "after": what_if_health_summary(&after_health),
        "diff": diff_baselines(&before, &after)
    }))
}

fn what_if_move_file_tool(args: &Value, root: &Path, config: &RaysenseConfig) -> Result<Value> {
    let from = args
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing from"))?;
    let to = args
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing to"))?;
    let before_report = scan_path_with_config(root, config)?;
    let before_health = compute_health_with_config(&before_report, config);
    let before = build_baseline(&before_report, &before_health);
    let after_report = crate::simulate_move_file(&before_report, config, from, to)
        .map_err(|err| anyhow!(err.to_string()))?;
    let after_health = compute_health_with_config(&after_report, config);
    let after = build_baseline(&after_report, &after_health);

    Ok(json!({
        "root": before_report.snapshot.root,
        "action": "move_file",
        "from": from,
        "to": to,
        "before": what_if_health_summary(&before_health),
        "after": what_if_health_summary(&after_health),
        "diff": diff_baselines(&before, &after)
    }))
}

fn what_if_break_cycle_tool(args: &Value, root: &Path, config: &RaysenseConfig) -> Result<Value> {
    let from = args
        .get("from")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing from"))?;
    let to = args
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing to"))?;
    let before_report = scan_path_with_config(root, config)?;
    let before_health = compute_health_with_config(&before_report, config);
    let before = build_baseline(&before_report, &before_health);
    let after_report = crate::simulate_break_cycle(&before_report, from, to)
        .map_err(|err| anyhow!(err.to_string()))?;
    let after_health = compute_health_with_config(&after_report, config);
    let after = build_baseline(&after_report, &after_health);

    Ok(json!({
        "root": before_report.snapshot.root,
        "action": "break_cycle",
        "from": from,
        "to": to,
        "before": what_if_health_summary(&before_health),
        "after": what_if_health_summary(&after_health),
        "diff": diff_baselines(&before, &after)
    }))
}

fn break_cycle_recommendations_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(20);
    let max_candidates = args
        .get("max_candidates")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(500);
    let report = scan_path_with_config(&root, &config)?;
    let recommendations = crate::break_cycle_recommendations(&report, limit, max_candidates);
    Ok(json!({
        "root": report.snapshot.root,
        "cycle_count_before": report.graph.cycle_count,
        "considered_edges_cap": max_candidates,
        "recommendations": recommendations,
    }))
}

fn what_if_sequence_tool(actions: &[Value], root: &Path, config: &RaysenseConfig) -> Result<Value> {
    let parsed_actions: Vec<crate::simulate::Action> = actions
        .iter()
        .enumerate()
        .map(|(idx, step)| {
            serde_json::from_value(step.clone()).map_err(|err| anyhow!("step {idx}: {err}"))
        })
        .collect::<Result<_>>()?;

    let before_report = scan_path_with_config(root, config)?;
    let before_health = compute_health_with_config(&before_report, config);
    let before = build_baseline(&before_report, &before_health);

    let after_report = crate::simulate::simulate_sequence(&before_report, config, &parsed_actions)
        .map_err(|err| anyhow!(err.to_string()))?;

    let after_health = compute_health_with_config(&after_report, config);
    let after = build_baseline(&after_report, &after_health);
    Ok(json!({
        "root": before_report.snapshot.root,
        "actions": actions,
        "before": what_if_health_summary(&before_health),
        "after": what_if_health_summary(&after_health),
        "diff": diff_baselines(&before, &after)
    }))
}

fn what_if_health_summary(health: &crate::HealthSummary) -> Value {
    json!({
        "score": health.score,
        "quality_signal": health.quality_signal,
        "rules": health.rules.len(),
        "max_blast_radius": health.metrics.architecture.max_blast_radius,
        "max_non_foundation_blast_radius": health.metrics.architecture.max_non_foundation_blast_radius,
        "cycles": health.metrics.architecture.cycles.len(),
        "upward_violations": health.metrics.architecture.upward_violations.len(),
        "cross_unstable_edges": health.metrics.coupling.cross_unstable_edges,
        "cross_unstable_ratio": health.metrics.coupling.cross_unstable_ratio
    })
}

fn trend_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let (window_label, window_secs) = window_arg(args)?;
    let dimension = dimension_arg(args)?;
    let format = trend_format_arg(args)?;
    let limit = limit_arg(args, 20)?;

    let samples = crate::health::read_trend_history(&root);
    let now = unix_time_secs();
    let cutoff = window_secs.map(|w| now - w);
    let filtered: Vec<&crate::health::TrendSample> = samples
        .iter()
        .filter(|s| match cutoff {
            Some(c) => s.timestamp >= c,
            None => true,
        })
        .collect();

    let data = match format.as_str() {
        "summary" => trend_summary(&filtered, &dimension),
        "table" => trend_table(&filtered, &dimension, limit),
        "json" => trend_json(&filtered, &dimension, limit),
        // Validated upstream by trend_format_arg.
        _ => json!({}),
    };

    Ok(json!({
        "root": root,
        "window": window_label,
        "dimension": dimension,
        "format": format,
        "samples": filtered.len(),
        "data": data,
    }))
}

/// Cap on history.json window choices. Adding a new entry here
/// auto-extends the validation in `window_arg` and the schema enum.
const TREND_WINDOWS: &[(&str, i64)] = &[
    ("7d", 7 * 86_400),
    ("30d", 30 * 86_400),
    ("90d", 90 * 86_400),
];

fn unix_time_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn window_arg(args: &Value) -> Result<(String, Option<i64>)> {
    let label = args
        .get("window")
        .and_then(Value::as_str)
        .unwrap_or("30d")
        .to_string();
    if label == "all" {
        return Ok((label, None));
    }
    if let Some((_, seconds)) = TREND_WINDOWS
        .iter()
        .find(|(name, _)| *name == label.as_str())
    {
        return Ok((label, Some(*seconds)));
    }
    Err(anyhow!(
        "window must be one of 7d, 30d, 90d, all (got {label})"
    ))
}

fn dimension_arg(args: &Value) -> Result<String> {
    let value = args
        .get("dimension")
        .and_then(Value::as_str)
        .unwrap_or("all");
    match value {
        "health" | "hotspots" | "violations" | "all" => Ok(value.to_string()),
        other => Err(anyhow!(
            "dimension must be one of health, hotspots, violations, all (got {other})"
        )),
    }
}

fn trend_format_arg(args: &Value) -> Result<String> {
    let value = args
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("summary");
    match value {
        "summary" | "table" | "json" => Ok(value.to_string()),
        other => Err(anyhow!(
            "format must be one of summary, table, json (got {other})"
        )),
    }
}

fn trend_summary(samples: &[&crate::health::TrendSample], dimension: &str) -> Value {
    let first = samples.first().copied();
    let last = samples.last().copied();
    let mut out = serde_json::Map::new();

    if dimension == "health" || dimension == "all" {
        let block = match (first, last) {
            (Some(a), Some(b)) => json!({
                "first_timestamp": a.timestamp,
                "last_timestamp": b.timestamp,
                "score_first": a.score,
                "score_last": b.score,
                "score_delta": b.score as i32 - a.score as i32,
                "quality_signal_first": a.quality_signal,
                "quality_signal_last": b.quality_signal,
                "quality_signal_delta": b.quality_signal as i64 - a.quality_signal as i64,
                "rules_first": a.rules,
                "rules_last": b.rules,
                "rules_delta": b.rules as isize - a.rules as isize,
                "modularity_delta": round3(b.root_causes.modularity - a.root_causes.modularity),
                "acyclicity_delta": round3(b.root_causes.acyclicity - a.root_causes.acyclicity),
                "depth_delta": round3(b.root_causes.depth - a.root_causes.depth),
                "equality_delta": round3(b.root_causes.equality - a.root_causes.equality),
                "redundancy_delta": round3(b.root_causes.redundancy - a.root_causes.redundancy),
                "structural_uniformity_delta": round3(
                    b.root_causes.structural_uniformity - a.root_causes.structural_uniformity
                ),
            }),
            _ => json!({"available": false}),
        };
        out.insert("health".to_string(), block);
    }

    if dimension == "hotspots" || dimension == "all" {
        let mut top = std::collections::BTreeMap::<&str, &crate::health::TrendHotspotSample>::new();
        for sample in samples {
            for h in &sample.top_hotspots {
                top.entry(h.path.as_str())
                    .and_modify(|existing| {
                        if h.risk_score > existing.risk_score {
                            *existing = h;
                        }
                    })
                    .or_insert(h);
            }
        }
        let mut top: Vec<_> = top.into_iter().collect();
        top.sort_by_key(|(_, h)| std::cmp::Reverse(h.risk_score));
        let rows: Vec<Value> = top
            .into_iter()
            .take(SUMMARY_TOP_N)
            .map(|(_, h)| {
                json!({
                    "path": h.path,
                    "commits": h.commits,
                    "max_complexity": h.max_complexity,
                    "risk_score": h.risk_score,
                })
            })
            .collect();
        out.insert("hotspots".to_string(), Value::Array(rows));
    }

    if dimension == "violations" || dimension == "all" {
        let mut totals: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for sample in samples {
            for (rule, count) in &sample.rule_breakdown {
                *totals.entry(rule.as_str()).or_default() += count;
            }
        }
        let mut totals: Vec<_> = totals.into_iter().collect();
        totals.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        let rows: Vec<Value> = totals
            .into_iter()
            .take(SUMMARY_TOP_N)
            .map(|(rule, count)| json!({"rule_id": rule, "total_count": count}))
            .collect();
        out.insert("violations".to_string(), Value::Array(rows));
    }

    Value::Object(out)
}

fn trend_table(samples: &[&crate::health::TrendSample], dimension: &str, limit: usize) -> Value {
    let mut out = serde_json::Map::new();

    if dimension == "health" || dimension == "all" {
        let rows: Vec<Value> = samples
            .iter()
            .rev()
            .take(limit)
            .map(|s| {
                json!({
                    "timestamp": s.timestamp,
                    "snapshot_id": s.snapshot_id,
                    "score": s.score,
                    "quality_signal": s.quality_signal,
                    "rules": s.rules,
                    "modularity": s.root_causes.modularity,
                    "acyclicity": s.root_causes.acyclicity,
                    "depth": s.root_causes.depth,
                    "equality": s.root_causes.equality,
                    "redundancy": s.root_causes.redundancy,
                    "structural_uniformity": s.root_causes.structural_uniformity,
                    "overall_grade": s.overall_grade,
                })
            })
            .collect();
        out.insert("health".to_string(), Value::Array(rows));
    }

    if dimension == "hotspots" || dimension == "all" {
        let mut rows = Vec::new();
        for s in samples {
            for h in &s.top_hotspots {
                rows.push(json!({
                    "timestamp": s.timestamp,
                    "snapshot_id": s.snapshot_id,
                    "path": h.path,
                    "commits": h.commits,
                    "max_complexity": h.max_complexity,
                    "risk_score": h.risk_score,
                }));
            }
        }
        rows.truncate(limit);
        out.insert("hotspots".to_string(), Value::Array(rows));
    }

    if dimension == "violations" || dimension == "all" {
        let mut rows = Vec::new();
        for s in samples {
            for (rule, count) in &s.rule_breakdown {
                rows.push(json!({
                    "timestamp": s.timestamp,
                    "snapshot_id": s.snapshot_id,
                    "rule_id": rule,
                    "count": count,
                }));
            }
        }
        rows.truncate(limit);
        out.insert("violations".to_string(), Value::Array(rows));
    }

    Value::Object(out)
}

fn trend_json(samples: &[&crate::health::TrendSample], _dimension: &str, limit: usize) -> Value {
    let raw: Vec<&crate::health::TrendSample> = samples.iter().rev().take(limit).copied().collect();
    json!(raw)
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn drift_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let (window_label, window_secs) = window_arg(args)?;
    let limit = limit_arg(args, 5)?;

    let samples = crate::health::read_trend_history(&root);
    let now = unix_time_secs();
    let cutoff = window_secs.map(|w| now - w);
    let in_window: Vec<&crate::health::TrendSample> = samples
        .iter()
        .filter(|s| match cutoff {
            Some(c) => s.timestamp >= c,
            None => true,
        })
        .collect();

    if in_window.len() < 2 {
        return Ok(json!({
            "root": root,
            "window": window_label,
            "available": false,
            "samples": in_window.len(),
            "reason": "need at least 2 samples in the window to compute drift",
        }));
    }

    let first = in_window.first().unwrap();
    let last = in_window.last().unwrap();

    let worsened = worsened_dimensions(first, last);
    let hotspots = drift_hotspots(first, last, limit);
    let rules = drift_rule_violations(first, last, limit);

    Ok(json!({
        "root": root,
        "window": window_label,
        "available": true,
        "samples": in_window.len(),
        "first_timestamp": first.timestamp,
        "last_timestamp": last.timestamp,
        "first_snapshot_id": first.snapshot_id,
        "last_snapshot_id": last.snapshot_id,
        "worsened_dimensions": worsened,
        "hotspots_new_or_risen": hotspots,
        "rules_new_or_increased": rules,
    }))
}

/// Surface dimensions that got worse from `first` to `last`. For score
/// and root-cause floats, "worse" means lower; for rule count, "worse"
/// means higher. Equal or improved dimensions are dropped so the agent
/// only sees the regression list.
fn worsened_dimensions(
    first: &crate::health::TrendSample,
    last: &crate::health::TrendSample,
) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();

    let score_delta = last.score as i32 - first.score as i32;
    if score_delta < 0 {
        out.push(json!({
            "dimension": "score",
            "before": first.score,
            "after": last.score,
            "delta": score_delta,
            "direction": "down",
        }));
    }
    let rules_delta = last.rules as isize - first.rules as isize;
    if rules_delta > 0 {
        out.push(json!({
            "dimension": "rules",
            "before": first.rules,
            "after": last.rules,
            "delta": rules_delta,
            "direction": "up",
        }));
    }
    let dims: [(&str, f64, f64); 6] = [
        (
            "modularity",
            first.root_causes.modularity,
            last.root_causes.modularity,
        ),
        (
            "acyclicity",
            first.root_causes.acyclicity,
            last.root_causes.acyclicity,
        ),
        ("depth", first.root_causes.depth, last.root_causes.depth),
        (
            "equality",
            first.root_causes.equality,
            last.root_causes.equality,
        ),
        (
            "redundancy",
            first.root_causes.redundancy,
            last.root_causes.redundancy,
        ),
        (
            "structural_uniformity",
            first.root_causes.structural_uniformity,
            last.root_causes.structural_uniformity,
        ),
    ];
    for (name, before, after) in dims {
        // Skip endpoints that look unset (older v1 samples) so we don't
        // synthesize a misleading drop from 0.0 to a real value.
        if before == 0.0 && after == 0.0 {
            continue;
        }
        let delta = round3(after - before);
        if delta < 0.0 {
            out.push(json!({
                "dimension": name,
                "before": round3(before),
                "after": round3(after),
                "delta": delta,
                "direction": "down",
            }));
        }
    }
    out
}

/// Files that were not in `first.top_hotspots` but appear in
/// `last.top_hotspots`, plus files whose `risk_score` increased. Sorted
/// by descending delta.
fn drift_hotspots(
    first: &crate::health::TrendSample,
    last: &crate::health::TrendSample,
    limit: usize,
) -> Vec<Value> {
    let first_by_path: std::collections::BTreeMap<&str, &crate::health::TrendHotspotSample> = first
        .top_hotspots
        .iter()
        .map(|h| (h.path.as_str(), h))
        .collect();
    let mut out: Vec<(i64, Value)> = Vec::new();
    for current in &last.top_hotspots {
        let before = first_by_path.get(current.path.as_str());
        let before_score = before.map(|h| h.risk_score as i64).unwrap_or(0);
        let delta = current.risk_score as i64 - before_score;
        if delta <= 0 {
            continue;
        }
        out.push((
            delta,
            json!({
                "path": current.path,
                "before_risk_score": before_score,
                "after_risk_score": current.risk_score,
                "delta": delta,
                "is_new": before.is_none(),
                "commits": current.commits,
                "max_complexity": current.max_complexity,
            }),
        ));
    }
    out.sort_by_key(|(d, _)| std::cmp::Reverse(*d));
    out.into_iter().take(limit).map(|(_, v)| v).collect()
}

/// Rule codes that gained violations, plus rules that newly tripped
/// (absent in `first.rule_breakdown`). Sorted by descending delta.
fn drift_rule_violations(
    first: &crate::health::TrendSample,
    last: &crate::health::TrendSample,
    limit: usize,
) -> Vec<Value> {
    let mut out: Vec<(isize, Value)> = Vec::new();
    for (rule, count) in &last.rule_breakdown {
        let before = first.rule_breakdown.get(rule).copied().unwrap_or(0);
        let delta = *count as isize - before as isize;
        if delta <= 0 {
            continue;
        }
        out.push((
            delta,
            json!({
                "rule_id": rule,
                "before_count": before,
                "after_count": count,
                "delta": delta,
                "is_new": before == 0,
            }),
        ));
    }
    out.sort_by_key(|(d, _)| std::cmp::Reverse(*d));
    out.into_iter().take(limit).map(|(_, v)| v).collect()
}

fn drift_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "window": {
                "type": "string",
                "enum": ["7d", "30d", "90d", "all"],
                "description": "Time window for drift detection. Defaults to 30d. Drift compares the oldest in-window sample to the newest."
            },
            "limit": {"type": "integer", "minimum": 1, "description": "Max rows surfaced per category (hotspots and rule increases). Defaults to 5."}
        }
    })
}

fn trend_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "window": {
                "type": "string",
                "enum": ["7d", "30d", "90d", "all"],
                "description": "Time window of trend samples to consider. Defaults to 30d."
            },
            "dimension": {
                "type": "string",
                "enum": ["health", "hotspots", "violations", "all"],
                "description": "Which trend dimension to surface. Defaults to all."
            },
            "format": {
                "type": "string",
                "enum": ["summary", "table", "json"],
                "description": "Output verbosity. summary: deltas + top-5; table: per-row entries; json: raw samples. Defaults to summary."
            },
            "limit": {"type": "integer", "minimum": 1, "description": "Cap on rows in non-summary modes. Defaults to 20."}
        }
    })
}

fn policy_presets_tool(_args: &Value) -> Result<Value> {
    Ok(json!({
        "presets": ["rust-crate", "monorepo", "service-backend", "library"]
    }))
}

fn policy_init_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let preset = args
        .get("preset")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing preset"))?;
    let path = config_path_arg(args)?.unwrap_or_else(|| root.join(".raysense.toml"));
    let mut config = load_or_default_config(&path)?;
    crate::cli::apply_policy_preset(&mut config, preset)?;
    write_config_path(&path, &config)?;

    Ok(json!({
        "root": root,
        "path": path,
        "preset": preset,
        "config": config
    }))
}

fn memory_summary_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let memory = crate::memory::RayMemory::from_report_with_config(&report, &config)?;

    Ok(json!({
        "root": report.snapshot.root,
        "summary": memory.summary()
    }))
}

fn baseline_save_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let output = baseline_dir_arg(args, &root)?;
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let baseline = build_baseline(&report, &health);

    // Record the trend sample first so this snapshot is part of the
    // history that the splayed `trend_*` tables read from. Failures
    // here are silent (best-effort) - the baseline itself is what
    // matters and stdout/stderr are reserved for JSON-RPC traffic.
    let _ = crate::cli::append_trend_sample(&report, &health);

    let memory = crate::memory::RayMemory::from_report_with_config(&report, &config)?;
    let tables_dir = output.join("tables");

    fs::create_dir_all(&output)
        .with_context(|| format!("failed to create baseline dir {}", output.display()))?;
    fs::write(
        output.join("manifest.json"),
        serde_json::to_string_pretty(&baseline)?,
    )
    .with_context(|| format!("failed to write baseline manifest {}", output.display()))?;
    // v0.8: see cli::save_baseline for why tables_dir is preserved
    // across save (sym short-circuit + trend log preservation).
    memory
        .save_splayed(&tables_dir)
        .with_context(|| format!("failed to write baseline tables {}", tables_dir.display()))?;

    Ok(json!({
        "path": output,
        "tables_path": tables_dir,
        "baseline": baseline
    }))
}

fn baseline_diff_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let baseline_dir = baseline_dir_arg(args, &root)?;
    let manifest = baseline_dir.join("manifest.json");
    let before: ProjectBaseline =
        serde_json::from_str(&fs::read_to_string(&manifest).with_context(|| {
            format!("failed to read baseline manifest {}", manifest.display())
        })?)?;
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let after = build_baseline(&report, &health);

    Ok(json!({
        "baseline_path": baseline_dir,
        "diff": diff_baselines(&before, &after)
    }))
}

fn baseline_tables_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let baseline_dir = baseline_dir_arg(args, &root)?;
    let tables_dir = baseline_dir.join("tables");
    let tables = crate::memory::list_baseline_tables(&tables_dir)
        .with_context(|| format!("failed to list baseline tables {}", tables_dir.display()))?;

    Ok(json!({
        "baseline_path": baseline_dir,
        "tables_path": tables_dir,
        "tables": tables
    }))
}

fn baseline_table_read_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let baseline_dir = baseline_dir_arg(args, &root)?;
    let tables_dir = baseline_dir.join("tables");
    let table = args
        .get("table")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("table must be a string"))?;
    let offset = args
        .get("offset")
        .map(|value| {
            value
                .as_u64()
                .map(|value| value as usize)
                .ok_or_else(|| anyhow!("offset must be a non-negative integer"))
        })
        .transpose()?
        .unwrap_or(0);
    let limit = limit_arg(args, 100)?;
    let query = BaselineTableQuery {
        offset,
        limit,
        columns: columns_arg(args)?,
        filters: filters_arg(args)?,
        filter_mode: filter_mode_arg(args)?,
        sort: sort_arg(args)?,
    };
    let table_rows = crate::memory::query_baseline_table(&tables_dir, table, query)
        .with_context(|| format!("failed to read baseline table {}", tables_dir.display()))?;

    Ok(json!({
        "baseline_path": baseline_dir,
        "tables_path": tables_dir,
        "table": table_rows
    }))
}

fn baseline_query_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let baseline_dir = baseline_dir_arg(args, &root)?;
    let tables_dir = baseline_dir.join("tables");
    let table = args
        .get("table")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("table must be a string"))?;
    let rayfall = args
        .get("rayfall")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("rayfall must be a string"))?;

    let table_rows =
        crate::memory::query_with_rayfall(&tables_dir, table, rayfall).with_context(|| {
            format!(
                "failed to evaluate Rayfall against {}",
                tables_dir.display()
            )
        })?;

    Ok(json!({
        "baseline_path": baseline_dir,
        "tables_path": tables_dir,
        "bind": "t",
        "rayfall": rayfall,
        "table": table_rows
    }))
}

fn baseline_import_csv_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let baseline_dir = baseline_dir_arg(args, &root)?;
    let tables_dir = baseline_dir.join("tables");
    let table = args
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("name must be a string"))?;
    let csv_path = args
        .get("csv_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("csv_path must be a string"))?;

    crate::memory::import_csv_table(&tables_dir, table, &csv_path).with_context(|| {
        format!(
            "failed to import {} as baseline table {}",
            csv_path.display(),
            table
        )
    })?;

    Ok(json!({
        "baseline_path": baseline_dir,
        "tables_path": tables_dir,
        "table": table,
        "csv_path": csv_path,
        "imported_into": tables_dir.join(table),
    }))
}

fn health_from_args(args: &Value) -> Result<(PathBuf, crate::HealthSummary)> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    Ok((report.snapshot.root, health))
}

/// Cached variant of `health_from_args` — stores the most-recent
/// `(root, config)` health on the state and returns it on subsequent calls
/// without re-scanning, until a tool in `HEALTH_INVALIDATING_TOOLS` runs.
fn health_from_args_cached(
    args: &Value,
    state: &mut McpState,
) -> Result<(PathBuf, crate::HealthSummary)> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let signature = config_signature(&root, &config);
    if let Some(cached) = &state.cached_health {
        if cached.root == root && cached.signature == signature {
            return Ok((cached.report_root.clone(), cached.health.clone()));
        }
    }
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    let report_root = report.snapshot.root;
    state.cached_health = Some(HealthCache {
        root: root.clone(),
        signature,
        report_root: report_root.clone(),
        health: health.clone(),
    });
    Ok((report_root, health))
}

/// Stable signature of the effective config for cache-key purposes. Falls
/// back to the empty string if serialization fails — a cache miss is always
/// safe.
fn config_signature(root: &Path, config: &RaysenseConfig) -> String {
    let payload = serde_json::to_string(config).unwrap_or_default();
    format!("{}::{}", root.display(), payload)
}

fn effective_config(args: &Value, root: &Path) -> Result<RaysenseConfig> {
    if args.get("config").is_some() {
        config_arg(args)
    } else {
        Ok(load_config(root, config_path_arg(args)?)?.0)
    }
}

fn baseline_dir_arg(args: &Value, root: &Path) -> Result<PathBuf> {
    args.get("baseline_path")
        .map(|value| {
            value
                .as_str()
                .map(PathBuf::from)
                .ok_or_else(|| anyhow!("baseline_path must be a string"))
        })
        .transpose()
        .map(|path| path.unwrap_or_else(|| root.join(".raysense/baseline")))
}

fn find_file_id(report: &crate::ScanReport, requested: &str) -> Option<usize> {
    let requested = requested.replace('\\', "/");
    report
        .files
        .iter()
        .find(|file| normalize_path(&file.path) == requested)
        .or_else(|| {
            report
                .files
                .iter()
                .find(|file| normalize_path(&file.path).ends_with(&requested))
        })
        .map(|file| file.file_id)
}

fn reachable_files(report: &crate::ScanReport, start: usize, limit: usize) -> Vec<Value> {
    let adjacency = local_adjacency(report);
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut out = Vec::new();
    seen.insert(start);
    queue.push_back(start);

    while let Some(file_id) = queue.pop_front() {
        let Some(next_files) = adjacency.get(&file_id) else {
            continue;
        };
        for next in next_files {
            if !seen.insert(*next) {
                continue;
            }
            queue.push_back(*next);
            if out.len() < limit {
                if let Some(file) = report.files.get(*next) {
                    out.push(json!({
                        "file_id": file.file_id,
                        "path": file.path,
                        "module": file.module,
                        "language": file.language_name
                    }));
                }
            }
        }
    }

    out
}

fn reachable_count(report: &crate::ScanReport, start: usize) -> usize {
    let adjacency = local_adjacency(report);
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    seen.insert(start);
    queue.push_back(start);

    while let Some(file_id) = queue.pop_front() {
        let Some(next_files) = adjacency.get(&file_id) else {
            continue;
        };
        for next in next_files {
            if seen.insert(*next) {
                queue.push_back(*next);
            }
        }
    }

    seen.len().saturating_sub(1)
}

fn local_adjacency(report: &crate::ScanReport) -> HashMap<usize, Vec<usize>> {
    let mut adjacency: HashMap<usize, Vec<usize>> = HashMap::new();
    for import in &report.imports {
        let Some(to_file) = import.resolved_file else {
            continue;
        };
        if import.resolution == ImportResolution::Local && import.from_file != to_file {
            adjacency.entry(to_file).or_default().push(import.from_file);
        }
    }
    adjacency
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn root_arg(args: &Value) -> Result<PathBuf> {
    Ok(match args.get("path").and_then(Value::as_str) {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir().context("failed to read current directory")?,
    })
}

fn config_path_arg(args: &Value) -> Result<Option<PathBuf>> {
    args.get("config_path")
        .map(|value| {
            value
                .as_str()
                .map(PathBuf::from)
                .ok_or_else(|| anyhow!("config_path must be a string"))
        })
        .transpose()
}

fn bool_arg(args: &Value, name: &str, default: bool) -> Result<bool> {
    args.get(name)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| anyhow!("{name} must be a boolean"))
        })
        .unwrap_or(Ok(default))
}

fn limit_arg(args: &Value, default: usize) -> Result<usize> {
    match args.get("limit") {
        Some(value) => {
            let limit = value
                .as_u64()
                .ok_or_else(|| anyhow!("limit must be a positive integer"))?;
            if limit == 0 {
                return Err(anyhow!("limit must be a positive integer"));
            }
            Ok(limit as usize)
        }
        None => Ok(default),
    }
}

fn columns_arg(args: &Value) -> Result<Option<Vec<String>>> {
    args.get("columns")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| anyhow!("columns must be an array of strings"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| anyhow!("columns must be an array of strings"))
                })
                .collect()
        })
        .transpose()
}

fn string_array_arg(args: &Value, name: &str) -> Result<Vec<String>> {
    let Some(value) = args.get(name) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| anyhow!("{name} must be an array of strings"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| anyhow!("{name} must be an array of strings"))
        })
        .collect()
}

fn filters_arg(args: &Value) -> Result<Vec<BaselineTableFilter>> {
    let Some(filters) = args.get("filters") else {
        return Ok(Vec::new());
    };
    filters
        .as_array()
        .ok_or_else(|| anyhow!("filters must be an array"))?
        .iter()
        .map(|filter| {
            let column = filter
                .get("column")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("filter column must be a string"))?
                .to_string();
            let op = filter
                .get("op")
                .and_then(Value::as_str)
                .map(parse_filter_op)
                .transpose()?
                .unwrap_or(BaselineFilterOp::Eq);
            let value = filter
                .get("value")
                .cloned()
                .ok_or_else(|| anyhow!("filter value is required"))?;
            Ok(BaselineTableFilter { column, op, value })
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

fn filter_mode_arg(args: &Value) -> Result<BaselineFilterMode> {
    match args
        .get("filter_mode")
        .and_then(Value::as_str)
        .unwrap_or("all")
    {
        "all" => Ok(BaselineFilterMode::All),
        "any" => Ok(BaselineFilterMode::Any),
        mode => Err(anyhow!("unsupported filter mode {mode}")),
    }
}

fn sort_arg(args: &Value) -> Result<Vec<BaselineTableSort>> {
    let Some(sort) = args.get("sort") else {
        return Ok(Vec::new());
    };
    match sort.as_array() {
        Some(sort) => sort.iter().map(parse_sort_item).collect(),
        None => Ok(vec![parse_sort_item(sort)?]),
    }
}

fn parse_sort_item(value: &Value) -> Result<BaselineTableSort> {
    let column = value
        .get("column")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sort column must be a string"))?
        .to_string();
    let direction = match value
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("asc")
    {
        "asc" => BaselineSortDirection::Asc,
        "desc" => BaselineSortDirection::Desc,
        direction => return Err(anyhow!("unsupported sort direction {direction}")),
    };
    Ok(BaselineTableSort { column, direction })
}

fn config_arg(args: &Value) -> Result<RaysenseConfig> {
    let config = args
        .get("config")
        .cloned()
        .ok_or_else(|| anyhow!("missing config"))?;
    serde_json::from_value(config).context("invalid Raysense config")
}

fn load_config(root: &Path, explicit: Option<PathBuf>) -> Result<(RaysenseConfig, String)> {
    if let Some(path) = explicit {
        let config = RaysenseConfig::from_path(&path)
            .with_context(|| format!("failed to load config {}", path.display()))?;
        return Ok((config, path.to_string_lossy().into_owned()));
    }

    let default_path = root.join(".raysense.toml");
    if default_path.exists() {
        let config = RaysenseConfig::from_path(&default_path)
            .with_context(|| format!("failed to load config {}", default_path.display()))?;
        return Ok((config, default_path.to_string_lossy().into_owned()));
    }

    Ok((RaysenseConfig::default(), "default".to_string()))
}

fn load_or_default_config(path: &Path) -> Result<RaysenseConfig> {
    if path.exists() {
        RaysenseConfig::from_path(path)
            .with_context(|| format!("failed to load config {}", path.display()))
    } else {
        Ok(RaysenseConfig::default())
    }
}

fn write_config_path(path: &Path, config: &RaysenseConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let toml = toml::to_string_pretty(config).context("failed to encode config as TOML")?;
    fs::write(path, toml).with_context(|| format!("failed to write {}", path.display()))
}

fn tool_success(structured: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string_pretty(&structured).unwrap_or_else(|_| "{}".to_string())
            }
        ],
        "structuredContent": structured,
        "isError": false
    })
}

fn tool_error(message: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true
    })
}

fn jsonrpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn config_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "scan": {
                "type": "object",
                "properties": {
                    "ignored_paths": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "generated_paths": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "enabled_languages": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "disabled_languages": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "module_roots": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "test_roots": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "public_api_paths": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "plugins": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "grammar": {"type": ["string", "null"]},
                                "grammar_path": {"type": ["string", "null"]},
                                "grammar_symbol": {"type": ["string", "null"]},
                                "extensions": {"type": "array", "items": {"type": "string"}},
                                "file_names": {"type": "array", "items": {"type": "string"}},
                                "function_prefixes": {"type": "array", "items": {"type": "string"}},
                                "import_prefixes": {"type": "array", "items": {"type": "string"}},
                                "call_suffixes": {"type": "array", "items": {"type": "string"}},
                                "abstract_type_prefixes": {"type": "array", "items": {"type": "string"}},
                                "concrete_type_prefixes": {"type": "array", "items": {"type": "string"}},
                                "tags_query": {"type": ["string", "null"]},
                                "package_index_files": {"type": "array", "items": {"type": "string"}},
                                "test_path_patterns": {"type": "array", "items": {"type": "string"}},
                                "source_roots": {"type": "array", "items": {"type": "string"}},
                                "ignored_paths": {"type": "array", "items": {"type": "string"}},
                                "local_import_prefixes": {"type": "array", "items": {"type": "string"}},
                                "max_function_complexity": {"type": ["integer", "null"], "minimum": 0},
                                "max_cognitive_complexity": {"type": ["integer", "null"], "minimum": 0},
                                "max_file_lines": {"type": ["integer", "null"], "minimum": 0},
                                "max_function_lines": {"type": ["integer", "null"], "minimum": 0},
                                "resolver_alias_files": {"type": "array", "items": {"type": "string"}},
                                "namespace_separator": {"type": ["string", "null"]},
                                "module_prefix_files": {"type": "array", "items": {"type": "string"}},
                                "module_prefix_directives": {"type": "array", "items": {"type": "string"}},
                                "entry_point_patterns": {"type": "array", "items": {"type": "string"}},
                                "test_module_patterns": {"type": "array", "items": {"type": "string"}},
                                "test_attribute_patterns": {"type": "array", "items": {"type": "string"}},
                                "parameter_node_kinds": {"type": "array", "items": {"type": "string"}},
                                "complexity_node_kinds": {"type": "array", "items": {"type": "string"}},
                                "logical_operator_kinds": {"type": "array", "items": {"type": "string"}},
                                "abstract_base_classes": {"type": "array", "items": {"type": "string"}}
                            },
                            "required": ["name"]
                        }
                    }
                }
            },
            "rules": {
                "type": "object",
                "properties": {
                    "min_quality_signal": {"type": "integer", "minimum": 0, "maximum": 10000},
                    "min_modularity": {"type": "number", "minimum": 0, "maximum": 1},
                    "min_acyclicity": {"type": "number", "minimum": 0, "maximum": 1},
                    "min_depth": {"type": "number", "minimum": 0, "maximum": 1},
                    "min_equality": {"type": "number", "minimum": 0, "maximum": 1},
                    "min_redundancy": {"type": "number", "minimum": 0, "maximum": 1},
                    "max_cycles": {"type": "integer", "minimum": 0},
                    "max_coupling_ratio": {"type": "number", "minimum": 0, "maximum": 1},
                    "max_function_complexity": {"type": "integer", "minimum": 0},
                    "max_cognitive_complexity": {"type": "integer", "minimum": 0},
                    "max_file_lines": {"type": "integer", "minimum": 0},
                    "max_function_lines": {"type": "integer", "minimum": 0},
                    "no_god_files": {"type": "boolean"},
                    "high_file_fan_in": {"type": "integer", "minimum": 0},
                    "high_file_fan_out": {"type": "integer", "minimum": 0},
                    "large_file_lines": {"type": "integer", "minimum": 0},
                    "max_large_file_findings": {"type": "integer", "minimum": 0},
                    "low_call_resolution_ratio": {"type": "number", "minimum": 0, "maximum": 1},
                    "low_call_resolution_min_calls": {"type": "integer", "minimum": 0},
                    "high_function_fan_in": {"type": "integer", "minimum": 0},
                    "high_function_fan_out": {"type": "integer", "minimum": 0},
                    "max_call_hotspot_findings": {"type": "integer", "minimum": 0},
                    "max_upward_layer_violations": {"type": "integer", "minimum": 0},
                    "no_tests_detected": {"type": "boolean"}
                }
            },
            "boundaries": {
                "type": "object",
                "properties": {
                    "forbidden_edges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from": {"type": "string"},
                                "to": {"type": "string"},
                                "reason": {"type": "string"}
                            },
                            "required": ["from", "to"]
                        }
                    },
                    "layers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "path": {"type": "string"},
                                "order": {"type": "integer"}
                            },
                            "required": ["name", "path", "order"]
                        }
                    }
                }
            },
            "score": {
                "type": "object",
                "properties": {
                    "modularity_weight": {"type": "number", "minimum": 0},
                    "acyclicity_weight": {"type": "number", "minimum": 0},
                    "depth_weight": {"type": "number", "minimum": 0},
                    "equality_weight": {"type": "number", "minimum": 0},
                    "redundancy_weight": {"type": "number", "minimum": 0}
                }
            }
        }
    })
}

fn path_limit_schema(limit_description: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "limit": {"type": "integer", "minimum": 1, "description": limit_description}
        }
    })
}

fn health_limit_schema(limit_description: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "limit": {"type": "integer", "minimum": 1, "description": limit_description},
            "summary": {"type": "boolean", "description": "Legacy alias for the default summary mode.  Default is summary; pass detail=true to opt into the full surface."},
            "detail": {"type": "boolean", "description": "When true, return the full surface (module-level distance vectors, every cycle, every unstable module).  Defaults to false: typed tools answer 'is this OK?' with headlines, the substrate (raysense_baseline_query) answers 'tell me about it' with arbitrary Rayfall queries."}
        }
    })
}

fn summary_arg(args: &Value) -> bool {
    args.get("summary")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn detail_arg(args: &Value) -> bool {
    args.get("detail").and_then(Value::as_bool).unwrap_or(false)
}

/// Cap used for top-N previews in summary mode -- small enough for an
/// agent to keep in working memory, large enough to spot the worst offenders.
const SUMMARY_TOP_N: usize = 5;

fn explore_hint_architecture() -> Value {
    json!({
        "hint": "Architecture analysis is materialized as queryable tables in v0.6.0+ baselines.  Reach for raysense_baseline_query (or pass detail: true) instead of jq-piping a JSON dump.",
        "tables": [
            "arch_cycles",
            "arch_unstable",
            "arch_foundations",
            "arch_levels",
            "arch_distance",
            "arch_violations",
            "module_edges",
            "hotspots",
            "rules"
        ],
        "examples": [
            "(select {from: t where: (> scc_size 1)})            ;; multi-module cycles, against arch_cycles",
            "(select {from: t desc: instability take: 10})       ;; against arch_unstable",
            "(select {from: t where: (> distance 0.7)})          ;; modules off the main sequence, against arch_distance"
        ]
    })
}

fn explore_hint_dsm() -> Value {
    json!({
        "hint": "DSM detail (per-module instability, distance, level assignments, every upward violation) is queryable as proper tables in v0.6.0+ baselines.  Reach for raysense_baseline_query for arbitrary slices.",
        "tables": [
            "arch_levels",
            "arch_distance",
            "arch_violations",
            "arch_unstable",
            "arch_foundations",
            "module_edges"
        ],
        "examples": [
            "(select {from: t desc: level})                       ;; deepest layers first, against arch_levels",
            "(select {from: t where: (== reason \"forbidden\")})  ;; against arch_violations",
            "(select {from: t desc: edges take: 20})              ;; strongest module-to-module edges"
        ]
    })
}

// Static-construction trick: the `EXPLORE_HINT_*` slots are referenced by
// callers as `EXPLORE_HINT_*.clone()` so they read like constants.  serde_json
// values are not const-constructible, so we proxy through helper fns above.
struct ExploreHint(fn() -> Value);
impl ExploreHint {
    fn clone(&self) -> Value {
        (self.0)()
    }
}
const EXPLORE_HINT_ARCHITECTURE: ExploreHint = ExploreHint(explore_hint_architecture);
const EXPLORE_HINT_DSM: ExploreHint = ExploreHint(explore_hint_dsm);

fn blast_radius_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "file": {"type": "string", "description": "Optional scanned file path. Defaults to the current max blast-radius file."},
            "limit": {"type": "integer", "minimum": 1, "description": "Maximum reachable files to return. Defaults to 100."}
        }
    })
}

fn level_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "module": {"type": "string", "description": "Optional module name. When omitted, all module levels are returned."}
        }
    })
}

fn break_cycle_recommendations_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "limit": {"type": "integer", "description": "Maximum recommendations to return. Defaults to 20."},
            "max_candidates": {"type": "integer", "description": "Maximum local edges to consider. Defaults to 500."}
        }
    })
}

fn what_if_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "action": {"type": "string", "enum": ["remove_edge", "add_edge", "remove_file", "move_file", "break_cycle"], "description": "Optional graph action to simulate. When omitted, simulates config-only changes."},
            "from": {"type": "string", "description": "Source file path for edge, move_file, or break_cycle actions."},
            "to": {"type": "string", "description": "Target file path for edge, move_file, or break_cycle actions."},
            "file": {"type": "string", "description": "Target file path for remove_file."},
            "actions": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Optional ordered list of action objects (each with the same shape as a single action) to apply in sequence. Overrides the singular action when present."
            },
            "ignore_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra ignored path patterns to simulate."
            },
            "generated_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Extra generated path patterns to simulate."
            }
        }
    })
}

fn visualize_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "output_path": {"type": "string", "description": "HTML output path. Defaults to <path>/.raysense/visualization.html."},
            "include_html": {"type": "boolean", "description": "Return generated HTML inline. Defaults to false."}
        }
    })
}

fn sarif_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
            "output_path": {"type": "string", "description": "Optional SARIF output path."},
            "include_sarif": {"type": "boolean", "description": "Return generated SARIF inline. Defaults to false."}
        }
    })
}

fn policy_init_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Destination config file. Defaults to <path>/.raysense.toml."},
            "preset": {"type": "string", "enum": ["rust-crate", "monorepo", "service-backend", "library"]}
        },
        "required": ["preset"]
    })
}

fn plugin_add_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Destination config file. Defaults to <path>/.raysense.toml."},
            "name": {"type": "string", "description": "Plugin name."},
            "extensions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "File extensions handled by the plugin."
            },
            "file_names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Exact extensionless or special file names handled by the plugin."
            }
        },
        "required": ["name"]
    })
}

fn plugin_sync_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional plugin names to sync. When omitted, all standard plugins are materialized."
            },
            "force": {"type": "boolean", "description": "Overwrite existing project-local plugin.toml files. Defaults to false."}
        }
    })
}

fn plugin_add_standard_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Destination config file. Defaults to <path>/.raysense.toml."}
        }
    })
}

fn plugin_remove_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Destination config file. Defaults to <path>/.raysense.toml."},
            "name": {"type": "string", "description": "Plugin name to remove."}
        },
        "required": ["name"]
    })
}

fn plugin_validate_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "dir": {"type": "string", "description": "Plugin directory containing plugin.toml and optional queries/tags.scm."}
        },
        "required": ["dir"]
    })
}

fn plugin_scaffold_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "name": {"type": "string", "description": "Plugin name."},
            "extension": {"type": "string", "description": "File extension handled by the plugin."}
        },
        "required": ["name", "extension"]
    })
}

fn baseline_schema(path_description: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "baseline_path": {"type": "string", "description": path_description},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema()
        }
    })
}

fn baseline_table_schema(require_table: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "baseline_path": {"type": "string", "description": "Baseline directory. Defaults to <path>/.raysense/baseline."},
            "table": {"type": "string", "description": "Baseline table name, such as files, functions, imports, calls, call_edges, health, hotspots, rules, module_edges, or changed_files."},
            "offset": {"type": "integer", "minimum": 0, "description": "First row offset. Defaults to 0."},
            "limit": {"type": "integer", "minimum": 1, "description": "Maximum rows to return. Defaults to 100."},
            "columns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of columns to include in returned rows."
            },
            "filters": {
                "type": "array",
                "description": "Optional AND filters applied before offset and limit.",
                "items": {
                    "type": "object",
                    "properties": {
                        "column": {"type": "string"},
                        "op": {"type": "string", "enum": ["eq", "ne", "in", "not_in", "contains", "starts_with", "ends_with", "regex", "not_regex", "gt", "gte", "lt", "lte"]},
                        "value": {}
                    },
                    "required": ["column", "value"]
                }
            },
            "filter_mode": {"type": "string", "enum": ["all", "any"], "description": "How filters combine. all is AND and any is OR. Defaults to all."},
            "sort": {
                "description": "Optional sort object or ordered array of sort objects applied after filters.",
                "oneOf": [
                    {
                        "type": "object",
                        "properties": {
                            "column": {"type": "string"},
                            "direction": {"type": "string", "enum": ["asc", "desc"]}
                        },
                        "required": ["column"]
                    },
                    {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "column": {"type": "string"},
                                "direction": {"type": "string", "enum": ["asc", "desc"]}
                            },
                            "required": ["column"]
                        }
                    }
                ]
            }
        }
    });
    if require_table {
        schema["required"] = json!(["table"]);
    }
    schema
}

fn baseline_import_csv_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "baseline_path": {"type": "string", "description": "Baseline directory. Defaults to <path>/.raysense/baseline."},
            "name": {"type": "string", "description": "Name to register the imported table under (a-z0-9_, no dots)."},
            "csv_path": {"type": "string", "description": "Absolute or working-directory-relative path to the CSV file. First row is treated as headers; column types are inferred."}
        },
        "required": ["name", "csv_path"]
    })
}

fn baseline_query_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "baseline_path": {"type": "string", "description": "Baseline directory. Defaults to <path>/.raysense/baseline."},
            "table": {"type": "string", "description": "Baseline table to bind as the symbol `t` before evaluation."},
            "rayfall": {"type": "string", "description": "Rayfall expression to evaluate. The named table is bound as `t`. The expression must return a RAY_TABLE; wrap with select to project columns when querying scalars."}
        },
        "required": ["table", "rayfall"]
    })
}

fn policy_check_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "baseline_path": {"type": "string", "description": "Baseline directory. Defaults to <path>/.raysense/baseline."},
            "policies_path": {"type": "string", "description": "Directory of .rfl policy files. Defaults to <path>/.raysense/policies."}
        }
    })
}

fn limited<T: serde::Serialize>(items: &[T], limit: usize) -> Vec<Value> {
    items
        .iter()
        .take(limit)
        .map(|item| serde_json::to_value(item).unwrap_or(Value::Null))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_config_tools() {
        let mut state = McpState::default();
        let response = handle_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            &mut state,
        )
        .unwrap()
        .unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();

        assert!(names.contains(&"raysense_config_read"));
        assert!(names.contains(&"raysense_config_write"));
        assert!(names.contains(&"raysense_health"));
        assert!(names.contains(&"raysense_scan"));
        assert!(names.contains(&"raysense_edges"));
        assert!(names.contains(&"raysense_hotspots"));
        assert!(names.contains(&"raysense_rules"));
        assert!(names.contains(&"raysense_module_edges"));
        assert!(names.contains(&"raysense_architecture"));
        assert!(names.contains(&"raysense_coupling"));
        assert!(names.contains(&"raysense_cycles"));
        assert!(names.contains(&"raysense_hottest"));
        assert!(names.contains(&"raysense_blast_radius"));
        assert!(names.contains(&"raysense_level"));
        assert!(names.contains(&"raysense_session_start"));
        assert!(names.contains(&"raysense_session_end"));
        assert!(names.contains(&"raysense_rescan"));
        assert!(names.contains(&"raysense_check_rules"));
        assert!(names.contains(&"raysense_evolution"));
        assert!(names.contains(&"raysense_dsm"));
        assert!(names.contains(&"raysense_test_gaps"));
        assert!(names.contains(&"raysense_visualize"));
        assert!(names.contains(&"raysense_sarif"));
        assert!(names.contains(&"raysense_plugins"));
        assert!(names.contains(&"raysense_standard_plugins"));
        assert!(names.contains(&"raysense_plugin_add"));
        assert!(names.contains(&"raysense_plugin_add_standard"));
        assert!(names.contains(&"raysense_plugin_sync"));
        assert!(names.contains(&"raysense_plugin_remove"));
        assert!(names.contains(&"raysense_plugin_validate"));
        assert!(names.contains(&"raysense_plugin_scaffold"));
        assert!(names.contains(&"raysense_remediations"));
        assert!(names.contains(&"raysense_what_if"));
        assert!(names.contains(&"raysense_break_cycle_recommendations"));
        assert!(names.contains(&"raysense_trend"));
        assert!(names.contains(&"raysense_drift"));
        assert!(names.contains(&"raysense_policy_presets"));
        assert!(names.contains(&"raysense_policy_init"));
        assert!(names.contains(&"raysense_memory_summary"));
        assert!(names.contains(&"raysense_baseline_save"));
        assert!(names.contains(&"raysense_baseline_diff"));
        assert!(names.contains(&"raysense_baseline_tables"));
        assert!(names.contains(&"raysense_baseline_table_read"));
    }

    #[test]
    fn reads_default_config() {
        // Point the test at a known-empty directory so it doesn't pick up
        // raysense's own .raysense.toml when running inside the source
        // tree.  /tmp/raysense-test-empty-* is created on demand and
        // guaranteed not to carry a config.
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("raysense-empty-config-{suffix}"));
        std::fs::create_dir_all(&dir).unwrap();
        let dir_str = dir.to_string_lossy();
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"raysense_config_read","arguments":{{"path":"{dir_str}"}}}}}}"#,
        );

        let mut state = McpState::default();
        let response = handle_message(&request, &mut state).unwrap().unwrap();
        let content = &response["result"]["structuredContent"];

        assert_eq!(content["source"], "default");
        assert_eq!(content["config"]["rules"]["high_file_fan_in"], 50);
        assert_eq!(content["config"]["rules"]["high_file_fan_out"], 15);
        assert_eq!(
            content["config"]["boundaries"]["forbidden_edges"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn health_cache_populates_and_invalidates() {
        let mut state = McpState::default();
        assert!(state.cached_health.is_none(), "fresh state has no cache");

        let args = json!({"root": env!("CARGO_MANIFEST_DIR")});
        let _ = health_from_args_cached(&args, &mut state).unwrap();
        assert!(state.cached_health.is_some(), "cache populated after read");

        let signature_before = state
            .cached_health
            .as_ref()
            .map(|c| c.signature.clone())
            .unwrap();
        let _ = health_from_args_cached(&args, &mut state).unwrap();
        let signature_after = state
            .cached_health
            .as_ref()
            .map(|c| c.signature.clone())
            .unwrap();
        assert_eq!(
            signature_before, signature_after,
            "second call must reuse the cached signature, not invalidate it",
        );

        // Simulate a mutating tool by clearing the cache the way call_tool would.
        if HEALTH_INVALIDATING_TOOLS.contains(&"raysense_rescan") {
            state.cached_health = None;
        }
        assert!(
            state.cached_health.is_none(),
            "invalidating tool must drop the cache",
        );
    }

    /// Build a synthetic TrendSample for the test helpers below.
    fn synth_sample(
        timestamp: i64,
        snapshot_id: &str,
        score: u8,
        quality_signal: u32,
        rules: usize,
        modularity: f64,
        equality: f64,
        overall_grade: &str,
        hotspots: Vec<(&str, usize, usize, usize)>,
        rule_breakdown: Vec<(&str, usize)>,
    ) -> crate::health::TrendSample {
        crate::health::TrendSample {
            timestamp,
            snapshot_id: snapshot_id.to_string(),
            score,
            quality_signal,
            rules,
            root_causes: crate::health::RootCauseScores {
                modularity,
                acyclicity: 0.9,
                depth: 1.0,
                equality,
                redundancy: 0.8,
                structural_uniformity: 0.7,
            },
            overall_grade: overall_grade.to_string(),
            schema: 2,
            top_hotspots: hotspots
                .into_iter()
                .map(|(p, c, m, r)| crate::health::TrendHotspotSample {
                    path: p.to_string(),
                    commits: c,
                    max_complexity: m,
                    risk_score: r,
                })
                .collect(),
            rule_breakdown: rule_breakdown
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }
    }

    /// Seed a temp project root's splayed trend tables with synthetic
    /// samples, then run the new trend_tool. v0.8 reads from splay
    /// only; there is no JSON sidecar.
    #[test]
    fn trend_tool_filters_window_and_formats_output() {
        let _guard = crate::memory::rayforce_test_guard();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("raysense-trend-tool-{suffix}"));
        std::fs::create_dir_all(&root).unwrap();

        let now = unix_time_secs();
        let recent = now - 3 * 86_400; // in-window for 7d
        let old = now - 100 * 86_400; // out-of-window for 90d
        let samples = vec![
            synth_sample(
                old,
                "snap-old",
                60,
                6000,
                5,
                0.5,
                0.5,
                "D",
                vec![("src/old.rs", 5, 10, 50)],
                vec![("old_rule", 5)],
            ),
            synth_sample(
                recent,
                "snap-recent",
                80,
                8000,
                2,
                0.9,
                0.7,
                "B",
                vec![("src/big.rs", 12, 18, 216)],
                vec![("max_function_complexity", 2)],
            ),
        ];
        crate::memory::write_trend_history_splay_for_tests(&root, &samples).unwrap();

        // 7d window drops the old sample.
        let args = json!({
            "path": root.to_string_lossy().to_string(),
            "window": "7d",
            "format": "summary",
        });
        let result = trend_tool(&args).unwrap();
        assert_eq!(result["window"], json!("7d"));
        assert_eq!(result["samples"], json!(1));

        // all window keeps both.
        let args = json!({
            "path": root.to_string_lossy().to_string(),
            "window": "all",
            "format": "summary",
        });
        let result = trend_tool(&args).unwrap();
        assert_eq!(result["samples"], json!(2));
        assert_eq!(result["data"]["health"]["score_first"], json!(60));
        assert_eq!(result["data"]["health"]["score_last"], json!(80));
        assert_eq!(result["data"]["health"]["score_delta"], json!(20));

        // table format with limit honors the cap.
        let args = json!({
            "path": root.to_string_lossy().to_string(),
            "window": "all",
            "dimension": "violations",
            "format": "table",
            "limit": 1,
        });
        let result = trend_tool(&args).unwrap();
        assert_eq!(
            result["data"]["violations"].as_array().map(Vec::len),
            Some(1),
            "limit=1 must cap rows"
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn trend_tool_rejects_unknown_window() {
        let args = json!({"window": "1y"});
        let err = trend_tool(&args).unwrap_err();
        assert!(err.to_string().contains("window must be one of"));
    }

    /// drift_tool needs at least 2 samples in the window to compute
    /// deltas. A two-sample synthetic history with one rule going from
    /// 0 to 1 should surface as `is_new: true`, modularity dropping
    /// 0.9 -> 0.5 should appear in worsened_dimensions, and a hotspot
    /// risk_score climbing 50 -> 200 should top the hotspots list.
    #[test]
    fn drift_tool_surfaces_regressions() {
        let _guard = crate::memory::rayforce_test_guard();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("raysense-drift-tool-{suffix}"));
        std::fs::create_dir_all(&root).unwrap();

        let now = unix_time_secs();
        let first_ts = now - 5 * 86_400;
        let last_ts = now - 86_400;
        let samples = vec![
            synth_sample(
                first_ts,
                "before",
                80,
                8000,
                0,
                0.9,
                0.7,
                "B",
                vec![("src/big.rs", 5, 10, 50)],
                vec![],
            ),
            synth_sample(
                last_ts,
                "after",
                70,
                7000,
                1,
                0.5,
                0.7,
                "C",
                vec![("src/big.rs", 12, 18, 200), ("src/new.rs", 3, 8, 24)],
                vec![("max_function_complexity", 1)],
            ),
        ];
        crate::memory::write_trend_history_splay_for_tests(&root, &samples).unwrap();

        let args = json!({
            "path": root.to_string_lossy().to_string(),
            "window": "30d",
        });
        let result = drift_tool(&args).unwrap();
        assert_eq!(result["available"], json!(true));
        assert_eq!(result["samples"], json!(2));

        // Score and modularity both regressed.
        let worsened = result["worsened_dimensions"].as_array().unwrap();
        let dims: Vec<&str> = worsened
            .iter()
            .filter_map(|d| d["dimension"].as_str())
            .collect();
        assert!(
            dims.contains(&"score"),
            "expected score in worsened: {dims:?}"
        );
        assert!(
            dims.contains(&"modularity"),
            "expected modularity in worsened: {dims:?}"
        );
        assert!(
            dims.contains(&"rules"),
            "expected rules count in worsened: {dims:?}"
        );

        // src/big.rs went 50 -> 200 (delta 150); src/new.rs is brand new.
        let hotspots = result["hotspots_new_or_risen"].as_array().unwrap();
        assert!(!hotspots.is_empty(), "expected at least one risen hotspot");
        let top = &hotspots[0];
        assert_eq!(top["path"], json!("src/big.rs"));
        assert_eq!(top["delta"], json!(150));
        assert_eq!(top["is_new"], json!(false));

        // max_function_complexity newly tripped.
        let rules = result["rules_new_or_increased"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["rule_id"], json!("max_function_complexity"));
        assert_eq!(rules[0]["is_new"], json!(true));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn drift_tool_reports_unavailable_with_one_sample() {
        let _guard = crate::memory::rayforce_test_guard();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("raysense-drift-empty-{suffix}"));
        std::fs::create_dir_all(&root).unwrap();

        let samples = vec![synth_sample(
            1,
            "only",
            80,
            8000,
            0,
            0.9,
            0.7,
            "B",
            vec![],
            vec![],
        )];
        crate::memory::write_trend_history_splay_for_tests(&root, &samples).unwrap();

        let args = json!({
            "path": root.to_string_lossy().to_string(),
            "window": "all",
        });
        let result = drift_tool(&args).unwrap();
        assert_eq!(result["available"], json!(false));
        assert_eq!(result["samples"], json!(1));

        std::fs::remove_dir_all(&root).unwrap();
    }
}
