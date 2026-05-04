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

//! `raysense install` - one-shot registration of raysense with every local
//! Claude host on the machine.
//!
//! Three surfaces, each with its own native install path:
//!
//! - **Claude Desktop** — edits `claude_desktop_config.json` to register the
//!   stdio MCP server. Desktop has no plugin system, so this is the only
//!   surface we can reach.
//! - **Claude Code** — edits `~/.claude/settings.json` to register the
//!   `raysense-marketplace` GitHub source under `extraKnownMarketplaces` and
//!   flips on `enabledPlugins["raysense@raysense-marketplace"]`. The plugin
//!   bundles its own `.mcp.json`, so this single edit lights up tools,
//!   prompts, slash commands, and skills in one shot. Best-effort cleanup of
//!   any legacy `claude mcp add raysense` entry from older installs.
//! - **Cowork** (Claude Desktop's research-preview agent mode) — registers
//!   the marketplace in `cowork_plugins/known_marketplaces.json` for every
//!   account/device pair on disk. The actual plugin install happens when the
//!   user's next Cowork session runs `/plugin install raysense@raysense-marketplace`,
//!   because Cowork's `installed_plugins.json` carries fields (gitCommitSha,
//!   installedAt) that the harness owns.
//!
//! Default behavior: detect every host present on this machine and install
//! to all of them. Pass `--desktop` / `--code` / `--cowork` to force a
//! specific subset. Existing `raysense` entries are overwritten silently
//! (matching `npm install` / `gh extension install` semantics) so re-running
//! after a `cargo install` upgrade just works.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Map, Value};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MARKETPLACE_NAME: &str = "raysense-marketplace";
const PLUGIN_HANDLE: &str = "raysense@raysense-marketplace";
const MARKETPLACE_REPO: &str = "RayforceDB/raysense";

/// Which Claude host to register raysense with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// Edits `claude_desktop_config.json` directly.
    ClaudeDesktop,
    /// Edits `~/.claude/settings.json` to install the raysense plugin.
    ClaudeCode,
    /// Edits `cowork_plugins/known_marketplaces.json` under
    /// `local-agent-mode-sessions/<account>/<device>/` for every pair.
    Cowork,
}

impl Host {
    fn label(self) -> &'static str {
        match self {
            Host::ClaudeDesktop => "claude-desktop",
            Host::ClaudeCode => "claude-code",
            Host::Cowork => "cowork",
        }
    }
}

/// User selection from the CLI flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstallSelection {
    pub desktop: bool,
    pub code: bool,
    pub cowork: bool,
}

impl InstallSelection {
    fn explicit(self) -> bool {
        self.desktop || self.code || self.cowork
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
             - Claude Code home dir (~/.claude) not found.\n  \
             - Cowork plugin registry not found ({}).\n  \
             Pass --desktop, --code, or --cowork to force a specific host.",
            describe_desktop_dir(),
            describe_cowork_root(),
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
/// - if any `--desktop` / `--code` / `--cowork` flag was passed, honor it exactly;
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
        if selection.cowork {
            out.push(Host::Cowork);
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
    if claude_code_dir().map(|d| d.exists()).unwrap_or(false) {
        out.push(Host::ClaudeCode);
    }
    if !cowork_known_marketplaces_paths().is_empty() {
        out.push(Host::Cowork);
    }
    out
}

fn install_one(host: Host, bin: &Path) -> Result<String> {
    match host {
        Host::ClaudeDesktop => install_claude_desktop(bin),
        Host::ClaudeCode => install_claude_code(),
        Host::Cowork => install_cowork(),
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
        "args": ["--mcp"],
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

fn install_claude_code() -> Result<String> {
    let path = claude_code_settings_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("settings path has no parent: {}", path.display()))?;
    if !parent.exists() {
        bail!(
            "Claude Code home dir not found: {}. Is Claude Code installed?",
            parent.display()
        );
    }

    // Best-effort cleanup: drop a legacy `claude mcp add raysense` registration
    // from earlier raysense versions, since the plugin now provides its own
    // bundled MCP server via .mcp.json. Two raysense MCP servers under the
    // same name would collide.
    if let Some(claude) = find_in_path("claude") {
        let _ = Command::new(&claude)
            .args(["mcp", "remove", "raysense", "--scope", "user"])
            .output();
    }

    let existing = if path.exists() {
        fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let (text, action) = upsert_plugin_install(&existing)?;
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))?;
    Ok(format!("{} {}", action, path.display()))
}

fn install_cowork() -> Result<String> {
    let paths = cowork_known_marketplaces_paths();
    if paths.is_empty() {
        bail!(
            "no cowork plugin registry found under {}. Is Cowork mode enabled in Claude Desktop?",
            describe_cowork_root()
        );
    }

    let mut wrote = 0;
    for path in &paths {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("cowork path has no parent: {}", path.display()))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("create cowork plugin dir {}", parent.display()))?;
        let existing = if path.exists() {
            fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
        } else {
            String::new()
        };
        let (text, _action) = upsert_cowork_marketplace(&existing)?;
        fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
        wrote += 1;
    }

    Ok(format!(
        "registered marketplace in {} cowork registr{}; finish in your next Cowork session with `/plugin install {}`",
        wrote,
        if wrote == 1 { "y" } else { "ies" },
        PLUGIN_HANDLE
    ))
}

/// Upsert raysense into Claude Code's `~/.claude/settings.json`:
///
/// - registers the marketplace under `extraKnownMarketplaces.<MARKETPLACE_NAME>`
///   pointing at the GitHub repo;
/// - sets `enabledPlugins["raysense@raysense-marketplace"] = true`.
///
/// All other keys (existing marketplaces, other enabled plugins, env vars,
/// statusLine config, etc.) are preserved.
fn upsert_plugin_install(existing: &str) -> Result<(String, &'static str)> {
    let mut root: Value = if existing.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(existing).context("parse Claude Code settings.json as JSON")?
    };

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("settings.json root is not a JSON object"))?;

    let markets = obj
        .entry("extraKnownMarketplaces".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let markets = markets
        .as_object_mut()
        .ok_or_else(|| anyhow!("`extraKnownMarketplaces` is not a JSON object"))?;
    let was_market = markets.contains_key(MARKETPLACE_NAME);
    markets.insert(
        MARKETPLACE_NAME.to_string(),
        json!({
            "source": { "source": "github", "repo": MARKETPLACE_REPO }
        }),
    );

    let plugins = obj
        .entry("enabledPlugins".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let plugins = plugins
        .as_object_mut()
        .ok_or_else(|| anyhow!("`enabledPlugins` is not a JSON object"))?;
    let was_enabled = plugins.contains_key(PLUGIN_HANDLE);
    plugins.insert(PLUGIN_HANDLE.to_string(), Value::Bool(true));

    let action = if was_market && was_enabled {
        "updated"
    } else {
        "added"
    };
    let mut text = serde_json::to_string_pretty(&root)?;
    text.push('\n');
    Ok((text, action))
}

/// Upsert raysense-marketplace into Cowork's `known_marketplaces.json`.
/// Cowork itself fills in `installLocation` / `lastUpdated` on the next
/// `/plugin install`, so we only seed the source.
fn upsert_cowork_marketplace(existing: &str) -> Result<(String, &'static str)> {
    let mut root: Value = if existing.trim().is_empty() {
        Value::Object(Map::new())
    } else {
        serde_json::from_str(existing).context("parse cowork known_marketplaces.json as JSON")?
    };

    let obj = root
        .as_object_mut()
        .ok_or_else(|| anyhow!("known_marketplaces.json root is not a JSON object"))?;

    let was_present = obj.contains_key(MARKETPLACE_NAME);
    obj.insert(
        MARKETPLACE_NAME.to_string(),
        json!({
            "source": { "source": "github", "repo": MARKETPLACE_REPO }
        }),
    );

    let action = if was_present { "updated" } else { "added" };
    let mut text = serde_json::to_string_pretty(&root)?;
    text.push('\n');
    Ok((text, action))
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

fn claude_code_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".claude"))
}

fn claude_code_settings_path() -> Result<PathBuf> {
    Ok(claude_code_dir()
        .ok_or_else(|| anyhow!("could not resolve Claude Code home directory"))?
        .join("settings.json"))
}

fn cowork_sessions_root() -> Option<PathBuf> {
    claude_desktop_config_dir().map(|d| d.join("local-agent-mode-sessions"))
}

/// Walk `local-agent-mode-sessions/<account>/<device>/cowork_plugins/` for
/// every account+device pair on disk and return the path to that pair's
/// `known_marketplaces.json`. Includes paths whose file does not yet exist
/// (we'll create it on write) as long as the parent `cowork_plugins` dir
/// is present, since that's what proves Cowork has run for this pair.
fn cowork_known_marketplaces_paths() -> Vec<PathBuf> {
    let Some(root) = cowork_sessions_root() else {
        return Vec::new();
    };
    if !root.exists() {
        return Vec::new();
    }
    let Ok(account_iter) = fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for account in account_iter.flatten() {
        let account_path = account.path();
        if !account_path.is_dir() {
            continue;
        }
        let Ok(device_iter) = fs::read_dir(&account_path) else {
            continue;
        };
        for device in device_iter.flatten() {
            let device_path = device.path();
            if !device_path.is_dir() {
                continue;
            }
            let cowork_dir = device_path.join("cowork_plugins");
            if cowork_dir.exists() {
                out.push(cowork_dir.join("known_marketplaces.json"));
            }
        }
    }
    out
}

fn describe_cowork_root() -> String {
    cowork_sessions_root()
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
            "args": ["--mcp"],
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
        assert_eq!(parsed["mcpServers"]["raysense"]["args"][0], "--mcp");
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
            cowork: false,
        });
        assert_eq!(only_desktop, vec![Host::ClaudeDesktop]);

        let only_code = resolve_targets(InstallSelection {
            desktop: false,
            code: true,
            cowork: false,
        });
        assert_eq!(only_code, vec![Host::ClaudeCode]);

        let only_cowork = resolve_targets(InstallSelection {
            desktop: false,
            code: false,
            cowork: true,
        });
        assert_eq!(only_cowork, vec![Host::Cowork]);

        let all_three = resolve_targets(InstallSelection {
            desktop: true,
            code: true,
            cowork: true,
        });
        assert_eq!(
            all_three,
            vec![Host::ClaudeDesktop, Host::ClaudeCode, Host::Cowork]
        );
    }

    #[test]
    fn upsert_plugin_install_into_empty_settings_creates_keys() {
        let (text, action) = upsert_plugin_install("").unwrap();
        assert_eq!(action, "added");
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed["extraKnownMarketplaces"][MARKETPLACE_NAME]["source"]["source"],
            "github"
        );
        assert_eq!(
            parsed["extraKnownMarketplaces"][MARKETPLACE_NAME]["source"]["repo"],
            MARKETPLACE_REPO
        );
        assert_eq!(parsed["enabledPlugins"][PLUGIN_HANDLE], true);
    }

    #[test]
    fn upsert_plugin_install_preserves_existing_plugins_and_marketplaces() {
        let existing = r#"{
            "env": { "FOO": "bar" },
            "extraKnownMarketplaces": {
                "other-market": { "source": { "source": "github", "repo": "x/y" } }
            },
            "enabledPlugins": {
                "other@other-market": true
            }
        }"#;
        let (text, action) = upsert_plugin_install(existing).unwrap();
        assert_eq!(action, "added");
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["env"]["FOO"], "bar");
        assert_eq!(
            parsed["extraKnownMarketplaces"]["other-market"]["source"]["repo"],
            "x/y"
        );
        assert_eq!(parsed["enabledPlugins"]["other@other-market"], true);
        assert!(parsed["extraKnownMarketplaces"][MARKETPLACE_NAME].is_object());
        assert_eq!(parsed["enabledPlugins"][PLUGIN_HANDLE], true);
    }

    #[test]
    fn upsert_plugin_install_is_idempotent() {
        let existing = r#"{
            "extraKnownMarketplaces": {
                "raysense-marketplace": { "source": { "source": "github", "repo": "RayforceDB/raysense" } }
            },
            "enabledPlugins": { "raysense@raysense-marketplace": true }
        }"#;
        let (_text, action) = upsert_plugin_install(existing).unwrap();
        assert_eq!(action, "updated");
    }

    #[test]
    fn upsert_plugin_install_rejects_non_object_root() {
        let err = upsert_plugin_install("[]").unwrap_err();
        assert!(err.to_string().contains("not a JSON object"));
    }

    #[test]
    fn upsert_cowork_marketplace_into_empty_creates_entry() {
        let (text, action) = upsert_cowork_marketplace("").unwrap();
        assert_eq!(action, "added");
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed[MARKETPLACE_NAME]["source"]["repo"], MARKETPLACE_REPO);
    }

    #[test]
    fn upsert_cowork_marketplace_preserves_other_marketplaces() {
        let existing = r#"{
            "knowledge-work-plugins": {
                "source": { "source": "github", "repo": "anthropics/knowledge-work-plugins" },
                "installLocation": "/somewhere",
                "lastUpdated": "2026-03-03T11:55:58.389Z"
            }
        }"#;
        let (text, _) = upsert_cowork_marketplace(existing).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed["knowledge-work-plugins"]["installLocation"],
            "/somewhere"
        );
        assert!(parsed[MARKETPLACE_NAME].is_object());
    }
}
