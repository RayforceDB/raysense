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
use raysense_core::{
    build_baseline, compute_health_with_config, diff_baselines, scan_path_with_config,
    ImportResolution, ProjectBaseline, RaysenseConfig,
};
use raysense_memory::{
    BaselineFilterMode, BaselineFilterOp, BaselineSortDirection, BaselineTableFilter,
    BaselineTableQuery, BaselineTableSort,
};
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
}

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
                "name": "raysense_remediations",
                "description": "Return suggested remediation actions for current findings and test gaps.",
                "inputSchema": health_limit_schema("Maximum remediation actions to return. Defaults to 100.")
            },
            {
                "name": "raysense_what_if",
                "description": "Simulate scan config changes and return score, rule, and baseline deltas without writing files.",
                "inputSchema": what_if_schema()
            },
            {
                "name": "raysense_trend",
                "description": "Return persisted trend metrics when .raysense/trends/history.json exists.",
                "inputSchema": health_limit_schema("Unused.")
            },
            {
                "name": "raysense_policy_presets",
                "description": "List built-in policy preset names.",
                "inputSchema": path_limit_schema("Unused.")
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

    match name {
        "raysense_config_read" => read_config_tool(&args),
        "raysense_config_write" => write_config_tool(&args),
        "raysense_health" => health_tool(&args),
        "raysense_scan" => scan_tool(&args),
        "raysense_edges" => edges_tool(&args),
        "raysense_hotspots" => hotspots_tool(&args),
        "raysense_rules" => rules_tool(&args),
        "raysense_module_edges" => module_edges_tool(&args),
        "raysense_architecture" => architecture_tool(&args),
        "raysense_coupling" => coupling_tool(&args),
        "raysense_cycles" => cycles_tool(&args),
        "raysense_hottest" => hottest_tool(&args),
        "raysense_blast_radius" => blast_radius_tool(&args),
        "raysense_level" => level_tool(&args),
        "raysense_session_start" => session_start_tool(&args, state),
        "raysense_session_end" => session_end_tool(&args, state),
        "raysense_rescan" => rescan_tool(&args, state),
        "raysense_check_rules" => check_rules_tool(&args),
        "raysense_evolution" => evolution_tool(&args),
        "raysense_dsm" => dsm_tool(&args),
        "raysense_test_gaps" => test_gaps_tool(&args),
        "raysense_plugins" => plugins_tool(&args),
        "raysense_standard_plugins" => standard_plugins_tool(&args),
        "raysense_remediations" => remediations_tool(&args),
        "raysense_what_if" => what_if_tool(&args),
        "raysense_trend" => trend_tool(&args),
        "raysense_policy_presets" => policy_presets_tool(&args),
        "raysense_memory_summary" => memory_summary_tool(&args),
        "raysense_baseline_save" => baseline_save_tool(&args),
        "raysense_baseline_diff" => baseline_diff_tool(&args),
        "raysense_baseline_tables" => baseline_tables_tool(&args),
        "raysense_baseline_table_read" => baseline_table_read_tool(&args),
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

fn health_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);

    Ok(json!({
        "root": report.snapshot.root,
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

fn hotspots_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
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

fn architecture_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;

    Ok(json!({
        "root": root,
        "score": health.score,
        "quality_signal": health.quality_signal,
        "root_causes": health.root_causes,
        "architecture": {
            "module_depth": health.metrics.architecture.module_depth,
            "max_blast_radius": health.metrics.architecture.max_blast_radius,
            "max_blast_radius_file": health.metrics.architecture.max_blast_radius_file,
            "levels": health.metrics.architecture.levels,
            "cycles": limited(&health.metrics.architecture.cycles, limit),
            "unstable_modules": limited(&health.metrics.architecture.unstable_modules, limit),
            "cycle_total": health.metrics.architecture.cycles.len(),
            "unstable_module_total": health.metrics.architecture.unstable_modules.len()
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
        .any(|rule| matches!(rule.severity, raysense_core::RuleSeverity::Error));
    Ok(json!({
        "root": root,
        "pass": pass,
        "quality_signal": health.quality_signal,
        "rules": limited(&health.rules, limit),
        "total": health.rules.len()
    }))
}

fn evolution_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;
    Ok(json!({
        "root": root,
        "evolution": {
            "available": health.metrics.evolution.available,
            "reason": health.metrics.evolution.reason,
            "commits_sampled": health.metrics.evolution.commits_sampled,
            "changed_files": health.metrics.evolution.changed_files,
            "top_changed_files": limited(&health.metrics.evolution.top_changed_files, limit)
        }
    }))
}

fn dsm_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    let limit = limit_arg(args, 100)?;
    Ok(json!({
        "root": root,
        "dsm": health.metrics.dsm,
        "levels": health.metrics.architecture.levels,
        "unstable_modules": limited(&health.metrics.architecture.unstable_modules, limit),
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
    let plugins = raysense_core::standard_language_plugins();
    Ok(json!({
        "plugins": limited(&plugins, limit),
        "total": plugins.len()
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

fn trend_tool(args: &Value) -> Result<Value> {
    let (root, health) = health_from_args(args)?;
    Ok(json!({
        "root": root,
        "trend": health.metrics.trend
    }))
}

fn policy_presets_tool(_args: &Value) -> Result<Value> {
    Ok(json!({
        "presets": ["rust-crate", "monorepo", "service-backend", "library"]
    }))
}

fn memory_summary_tool(args: &Value) -> Result<Value> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let memory = raysense_memory::RayMemory::from_report_with_config(&report, &config)?;

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
    let memory = raysense_memory::RayMemory::from_report_with_config(&report, &config)?;
    let tables_dir = output.join("tables");

    fs::create_dir_all(&output)
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
    let tables = raysense_memory::list_baseline_tables(&tables_dir)
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
    let table_rows = raysense_memory::query_baseline_table(&tables_dir, table, query)
        .with_context(|| format!("failed to read baseline table {}", tables_dir.display()))?;

    Ok(json!({
        "baseline_path": baseline_dir,
        "tables_path": tables_dir,
        "table": table_rows
    }))
}

fn health_from_args(args: &Value) -> Result<(PathBuf, raysense_core::HealthSummary)> {
    let root = root_arg(args)?;
    let config = effective_config(args, &root)?;
    let report = scan_path_with_config(&root, &config)?;
    let health = compute_health_with_config(&report, &config);
    Ok((report.snapshot.root, health))
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

fn find_file_id(report: &raysense_core::ScanReport, requested: &str) -> Option<usize> {
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

fn reachable_files(report: &raysense_core::ScanReport, start: usize, limit: usize) -> Vec<Value> {
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

fn reachable_count(report: &raysense_core::ScanReport, start: usize) -> usize {
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

fn local_adjacency(report: &raysense_core::ScanReport) -> HashMap<usize, Vec<usize>> {
    let mut adjacency: HashMap<usize, Vec<usize>> = HashMap::new();
    for import in &report.imports {
        let Some(to_file) = import.resolved_file else {
            continue;
        };
        if import.resolution == ImportResolution::Local && import.from_file != to_file {
            adjacency.entry(import.from_file).or_default().push(to_file);
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
                                "extensions": {"type": "array", "items": {"type": "string"}},
                                "function_prefixes": {"type": "array", "items": {"type": "string"}},
                                "import_prefixes": {"type": "array", "items": {"type": "string"}},
                                "call_suffixes": {"type": "array", "items": {"type": "string"}},
                                "package_index_files": {"type": "array", "items": {"type": "string"}},
                                "test_path_patterns": {"type": "array", "items": {"type": "string"}},
                                "source_roots": {"type": "array", "items": {"type": "string"}},
                                "ignored_paths": {"type": "array", "items": {"type": "string"}},
                                "local_import_prefixes": {"type": "array", "items": {"type": "string"}}
                            },
                            "required": ["name", "extensions"]
                        }
                    }
                }
            },
            "rules": {
                "type": "object",
                "properties": {
                    "max_cycles": {"type": "integer", "minimum": 0},
                    "max_coupling_ratio": {"type": "number", "minimum": 0, "maximum": 1},
                    "max_function_complexity": {"type": "integer", "minimum": 0},
                    "no_god_files": {"type": "boolean"},
                    "high_file_fan_in": {"type": "integer", "minimum": 0},
                    "large_file_lines": {"type": "integer", "minimum": 0},
                    "max_large_file_findings": {"type": "integer", "minimum": 0},
                    "low_call_resolution_ratio": {"type": "number", "minimum": 0, "maximum": 1},
                    "low_call_resolution_min_calls": {"type": "integer", "minimum": 0},
                    "high_function_fan_in": {"type": "integer", "minimum": 0},
                    "high_function_fan_out": {"type": "integer", "minimum": 0},
                    "max_call_hotspot_findings": {"type": "integer", "minimum": 0},
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
                                "to": {"type": "string"}
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
            "limit": {"type": "integer", "minimum": 1, "description": limit_description}
        }
    })
}

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

fn what_if_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Project root. Defaults to the current directory."},
            "config_path": {"type": "string", "description": "Explicit config file. Defaults to <path>/.raysense.toml when present."},
            "config": config_schema(),
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
        assert!(names.contains(&"raysense_plugins"));
        assert!(names.contains(&"raysense_standard_plugins"));
        assert!(names.contains(&"raysense_remediations"));
        assert!(names.contains(&"raysense_what_if"));
        assert!(names.contains(&"raysense_trend"));
        assert!(names.contains(&"raysense_policy_presets"));
        assert!(names.contains(&"raysense_memory_summary"));
        assert!(names.contains(&"raysense_baseline_save"));
        assert!(names.contains(&"raysense_baseline_diff"));
        assert!(names.contains(&"raysense_baseline_tables"));
        assert!(names.contains(&"raysense_baseline_table_read"));
    }

    #[test]
    fn reads_default_config() {
        let mut state = McpState::default();
        let response = handle_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"raysense_config_read","arguments":{}}}"#,
            &mut state,
        )
        .unwrap()
        .unwrap();
        let content = &response["result"]["structuredContent"];

        assert_eq!(content["source"], "default");
        assert_eq!(content["config"]["rules"]["high_file_fan_in"], 50);
        assert_eq!(
            content["config"]["boundaries"]["forbidden_edges"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
}
