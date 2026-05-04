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

//! `raysense install` - one-shot registration of the stdio MCP server with
//! local Claude hosts (Claude Desktop and the `claude` CLI / Claude Code).
//!
//! The whole point is to spare users hand-editing `claude_desktop_config.json`.
//! Default behavior: detect which hosts the machine has, register raysense
//! with each one, skip the rest with a friendly note. Existing `raysense`
//! entries are overwritten silently (matching `npm install` / `gh extension
//! install` semantics) so re-running after a `cargo install` upgrade just
//! works.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Which MCP host to register raysense with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// Edits `claude_desktop_config.json` directly.
    ClaudeDesktop,
    /// Shells out to the `claude` CLI's `mcp add`.
    ClaudeCode,
}

impl Host {
    fn label(self) -> &'static str {
        match self {
            Host::ClaudeDesktop => "claude-desktop",
            Host::ClaudeCode => "claude-code",
        }
    }
}

/// User selection from the CLI flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstallSelection {
    pub desktop: bool,
    pub code: bool,
}

impl InstallSelection {
    fn explicit(self) -> bool {
        self.desktop || self.code
    }
}

/// Entry point for the `raysense install` subcommand.
pub fn run(selection: InstallSelection) -> Result<()> {
    let bin = current_binary()?;
    let targets = resolve_targets(selection);

    if targets.is_empty() {
        eprintln!(
            "install: no Claude hosts detected on this machine.\n  \
             - Claude Desktop config dir not found ({}).\n  \
             - `claude` CLI not found on PATH.\n  \
             Pass `--desktop` or `--code` to force a specific host.",
            describe_desktop_dir()
        );
        return Err(anyhow!("no install targets"));
    }

    println!("install: using {}", bin.display());
    let mut any_failed = false;
    for host in targets {
        match install_one(host, &bin) {
            Ok(note) => println!("install {} ok: {}", host.label(), note),
            Err(err) => {
                any_failed = true;
                eprintln!("install {} failed: {:#}", host.label(), err);
            }
        }
    }

    if any_failed {
        Err(anyhow!("one or more install targets failed"))
    } else {
        println!(
            "install: done. Restart Claude Desktop / reload Claude Code to pick up the change."
        );
        Ok(())
    }
}

/// Pick the host list to act on:
/// - if user passed any `--desktop` / `--code` flag, honor it exactly;
/// - otherwise, install to every host we can detect on this machine.
fn resolve_targets(selection: InstallSelection) -> Vec<Host> {
    if selection.explicit() {
        let mut out = Vec::new();
        if selection.desktop {
            out.push(Host::ClaudeDesktop);
        }
        if selection.code {
            out.push(Host::ClaudeCode);
        }
        return out;
    }

    let mut out = Vec::new();
    if claude_desktop_config_dir()
        .map(|d| d.exists())
        .unwrap_or(false)
    {
        out.push(Host::ClaudeDesktop);
    }
    if find_in_path("claude").is_some() {
        out.push(Host::ClaudeCode);
    }
    out
}

fn install_one(host: Host, bin: &Path) -> Result<String> {
    match host {
        Host::ClaudeDesktop => install_claude_desktop(bin),
        Host::ClaudeCode => install_claude_code(bin),
    }
}

fn install_claude_desktop(bin: &Path) -> Result<String> {
    let path = claude_desktop_config_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent: {}", path.display()))?;
    if !parent.exists() {
        bail!(
            "Claude Desktop config dir not found: {}. Is Claude Desktop installed?",
            parent.display()
        );
    }

    let entry = json!({
        "command": bin.to_string_lossy(),
        "args": ["mcp"],
    });

    let existing = if path.exists() {
        fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let (text, action) = upsert_mcp_server(&existing, "raysense", entry)?;
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(format!("{} {}", action, path.display()))
}

fn install_claude_code(bin: &Path) -> Result<String> {
    let claude = find_in_path("claude").ok_or_else(|| anyhow!("`claude` CLI not on PATH"))?;
    // `claude mcp add <name> --scope user -- <command> [args...]`
    // The `--` separates raysense's argv from claude's flags.
    let bin_str = bin.to_string_lossy().into_owned();
    let output = Command::new(&claude)
        .args([
            "mcp",
            "add",
            "raysense",
            "--scope",
            "user",
            "--",
            bin_str.as_str(),
            "mcp",
        ])
        .output()
        .with_context(|| format!("run {} mcp add", claude.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "`claude mcp add raysense` exited {}: {}{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(format!("registered via `{}`", claude.display()))
}

/// Pure JSON-merge helper - the only piece with real bugs to catch.
/// Reads existing config text (may be empty), inserts/replaces the named MCP
/// server, returns the new pretty-printed text plus a one-word action label.
fn upsert_mcp_server(existing: &str, name: &str, entry: Value) -> Result<(String, &'static str)> {
    let mut root: Value = if existing.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(existing).context("parse existing config as JSON")?
    };

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("config root is not a JSON object"))?;
    let servers = obj
        .entry("mcpServers".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let servers = servers
        .as_object_mut()
        .ok_or_else(|| anyhow!("`mcpServers` is not a JSON object"))?;

    let action = if servers.contains_key(name) {
        "updated"
    } else {
        "added"
    };
    servers.insert(name.to_string(), entry);

    let mut text = serde_json::to_string_pretty(&root)?;
    text.push('\n');
    Ok((text, action))
}

fn current_binary() -> Result<PathBuf> {
    let exe = env::current_exe().context("read current executable path")?;
    Ok(exe.canonicalize().unwrap_or(exe))
}

fn claude_desktop_config_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        home_dir().map(|h| h.join("Library/Application Support/Claude"))
    } else if cfg!(target_os = "windows") {
        env::var_os("APPDATA").map(|a| PathBuf::from(a).join("Claude"))
    } else {
        // Linux / other unix: follow XDG.
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|h| h.join(".config")))
            .map(|c| c.join("Claude"))
    }
}

fn claude_desktop_config_path() -> Result<PathBuf> {
    Ok(claude_desktop_config_dir()
        .ok_or_else(|| anyhow!("could not resolve Claude Desktop config directory for this OS"))?
        .join("claude_desktop_config.json"))
}

fn describe_desktop_dir() -> String {
    claude_desktop_config_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        if cfg!(target_os = "windows") {
            for ext in ["exe", "cmd", "bat"] {
                let with_ext = candidate.with_extension(ext);
                if with_ext.is_file() {
                    return Some(with_ext);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raysense_entry() -> Value {
        json!({
            "command": "/usr/local/bin/raysense",
            "args": ["mcp"],
        })
    }

    #[test]
    fn upsert_into_empty_string_creates_object() {
        let (text, action) = upsert_mcp_server("", "raysense", raysense_entry()).unwrap();
        assert_eq!(action, "added");
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed["mcpServers"]["raysense"]["command"],
            "/usr/local/bin/raysense"
        );
        assert_eq!(parsed["mcpServers"]["raysense"]["args"][0], "mcp");
    }

    #[test]
    fn upsert_into_existing_config_preserves_siblings() {
        let existing = r#"{
            "mcpServers": {
                "other-tool": { "command": "other", "args": [] }
            },
            "theme": "dark"
        }"#;
        let (text, action) = upsert_mcp_server(existing, "raysense", raysense_entry()).unwrap();
        assert_eq!(action, "added");
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["theme"], "dark");
        assert_eq!(parsed["mcpServers"]["other-tool"]["command"], "other");
        assert!(parsed["mcpServers"]["raysense"].is_object());
    }

    #[test]
    fn upsert_updates_existing_raysense_entry() {
        let existing = r#"{
            "mcpServers": {
                "raysense": { "command": "/old/raysense", "args": ["mcp"] }
            }
        }"#;
        let (text, action) = upsert_mcp_server(existing, "raysense", raysense_entry()).unwrap();
        assert_eq!(action, "updated");
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed["mcpServers"]["raysense"]["command"],
            "/usr/local/bin/raysense"
        );
    }

    #[test]
    fn upsert_creates_mcp_servers_when_missing() {
        let existing = r#"{ "theme": "dark" }"#;
        let (text, _) = upsert_mcp_server(existing, "raysense", raysense_entry()).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert!(parsed["mcpServers"]["raysense"].is_object());
        assert_eq!(parsed["theme"], "dark");
    }

    #[test]
    fn upsert_rejects_non_object_root() {
        let err = upsert_mcp_server("[]", "raysense", raysense_entry()).unwrap_err();
        assert!(err.to_string().contains("not a JSON object"));
    }

    #[test]
    fn upsert_rejects_non_object_mcp_servers() {
        let existing = r#"{ "mcpServers": [] }"#;
        let err = upsert_mcp_server(existing, "raysense", raysense_entry()).unwrap_err();
        assert!(err.to_string().contains("`mcpServers`"));
    }

    #[test]
    fn upsert_output_ends_with_newline() {
        let (text, _) = upsert_mcp_server("", "raysense", raysense_entry()).unwrap();
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn resolve_targets_honors_explicit_flags() {
        let only_desktop = resolve_targets(InstallSelection {
            desktop: true,
            code: false,
        });
        assert_eq!(only_desktop, vec![Host::ClaudeDesktop]);

        let only_code = resolve_targets(InstallSelection {
            desktop: false,
            code: true,
        });
        assert_eq!(only_code, vec![Host::ClaudeCode]);

        let both = resolve_targets(InstallSelection {
            desktop: true,
            code: true,
        });
        assert_eq!(both, vec![Host::ClaudeDesktop, Host::ClaudeCode]);
    }
}
