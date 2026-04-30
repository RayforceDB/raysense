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
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

const PROTOCOL_VERSION: &str = "2025-06-18";

pub fn run() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match handle_message(&line) {
            Ok(Some(response)) => response,
            Ok(None) => continue,
            Err(err) => jsonrpc_error(Value::Null, -32700, &err.to_string()),
        };
        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}

fn handle_message(line: &str) -> Result<Option<Value>> {
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
            let result = match call_tool(&params) {
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

fn call_tool(params: &Value) -> Result<Value> {
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
                    "enabled_languages": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["c", "cpp", "python", "rust", "typescript"]}
                    },
                    "disabled_languages": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["c", "cpp", "python", "rust", "typescript"]}
                    }
                }
            },
            "rules": {
                "type": "object",
                "properties": {
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
                    }
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
                        "op": {"type": "string", "enum": ["eq", "ne", "in", "not_in", "contains", "starts_with", "ends_with", "gt", "gte", "lt", "lte"]},
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
        let response =
            handle_message(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
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
        assert!(names.contains(&"raysense_memory_summary"));
        assert!(names.contains(&"raysense_baseline_save"));
        assert!(names.contains(&"raysense_baseline_diff"));
        assert!(names.contains(&"raysense_baseline_tables"));
        assert!(names.contains(&"raysense_baseline_table_read"));
    }

    #[test]
    fn reads_default_config() {
        let response = handle_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"raysense_config_read","arguments":{}}}"#,
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
