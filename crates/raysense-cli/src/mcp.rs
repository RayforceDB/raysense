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
use raysense_core::{compute_health_with_config, scan_path, RaysenseConfig};
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
    let report = scan_path(&root)?;
    let config = if args.get("config").is_some() {
        config_arg(args)?
    } else {
        load_config(&report.snapshot.root, config_path_arg(args)?)?.0
    };
    let health = compute_health_with_config(&report, &config);

    Ok(json!({
        "root": report.snapshot.root,
        "health": health
    }))
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
