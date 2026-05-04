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

//! Package-manager workspace discovery. Reads the manifest files declared
//! by each language plugin (`Cargo.toml` for Rust today; npm `package.json`,
//! Go `go.work`, uv `pyproject.toml` later) and produces a `WorkspaceMap`
//! that lets the scanner classify cross-crate imports as `Local` and
//! resolve `crate::` against the importing member's `src/` root.
//!
//! This module is data-only: it doesn't change resolution. Slice 5 wires
//! the discovery into the scan loop without consuming the map; slices 6
//! and 7 follow up with the resolution and classification changes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::health::RaysenseConfig;

/// Map from a workspace member's *crate name* (the one used in `use
/// my_crate::Foo`) to its on-disk layout. Empty when the project has no
/// manifest the configured plugins recognize, or when none of the
/// plugins declare a `workspace_manifest_files` entry.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceMap {
    pub members_by_crate: HashMap<String, MemberCrate>,
    pub member_src_dirs: Vec<PathBuf>,
}

/// One workspace member crate. `manifest_dir` is relative to the scan
/// root; `src_dir` is the `src/` directory that holds its sources.
#[derive(Debug, Clone)]
pub struct MemberCrate {
    pub crate_name: String,
    pub manifest_dir: PathBuf,
    pub src_dir: PathBuf,
}

/// Discover the workspace layout under `root` by consulting each
/// configured plugin's `workspace_manifest_files`. Currently only the
/// Cargo manifest format is parsed; other manifests added later become
/// new arms in the dispatcher below without changing call sites.
pub fn discover(root: &Path, config: &RaysenseConfig) -> WorkspaceMap {
    let mut map = WorkspaceMap::default();
    for plugin in &config.scan.plugins {
        for file_name in &plugin.workspace_manifest_files {
            if file_name.eq_ignore_ascii_case("Cargo.toml") {
                discover_cargo_workspace(root, &mut map);
            }
        }
    }
    // Synthesize the rust default for projects without a configured
    // plugin (the most common case for built-in language support).
    let cargo_manifest = root.join("Cargo.toml");
    if cargo_manifest.is_file() && map.members_by_crate.is_empty() {
        discover_cargo_workspace(root, &mut map);
    }
    map
}

fn discover_cargo_workspace(root: &Path, map: &mut WorkspaceMap) {
    let manifest_path = root.join("Cargo.toml");
    let Ok(text) = std::fs::read_to_string(&manifest_path) else {
        return;
    };
    let Ok(parsed) = text.parse::<toml::Table>() else {
        return;
    };

    let mut member_paths: Vec<PathBuf> = Vec::new();
    if let Some(workspace) = parsed.get("workspace").and_then(|v| v.as_table()) {
        if let Some(members) = workspace.get("members").and_then(|v| v.as_array()) {
            for entry in members {
                let Some(member) = entry.as_str() else {
                    continue;
                };
                if member.contains('*') {
                    // v1: literal paths only. Glob patterns are common in
                    // real workspaces; deferring expansion to a follow-up
                    // slice keeps this one small and predictable.
                    continue;
                }
                member_paths.push(PathBuf::from(member));
            }
        }
    }

    // A root manifest with `[package]` is itself a member, even when it
    // also declares a `[workspace]` (the common "virtual + package"
    // shape). Push the root path so it gets the same treatment below.
    if parsed.get("package").is_some() {
        member_paths.push(PathBuf::from("."));
    }

    for relative in member_paths {
        let manifest_dir = root.join(&relative);
        let member_manifest = manifest_dir.join("Cargo.toml");
        let Ok(member_text) = std::fs::read_to_string(&member_manifest) else {
            continue;
        };
        let Ok(member_parsed) = member_text.parse::<toml::Table>() else {
            continue;
        };
        let Some(crate_name) = member_parsed
            .get("package")
            .and_then(|v| v.as_table())
            .and_then(|t| t.get("name"))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        let src_dir = manifest_dir.join("src");
        if !src_dir.is_dir() {
            continue;
        }
        let member = MemberCrate {
            crate_name: crate_name.to_string(),
            manifest_dir: relative.clone(),
            src_dir: src_dir.clone(),
        };
        map.members_by_crate.insert(crate_name.to_string(), member);
        map.member_src_dirs.push(src_dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::RaysenseConfig;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_workspace_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("raysense_workspace_{name}_{nanos}"));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn discovers_cargo_workspace_members() {
        let root = temp_workspace_root("cargo_members");
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/alpha\", \"crates/beta\"]\n",
        )
        .unwrap();
        for (member, name) in [("crates/alpha", "alpha"), ("crates/beta", "beta")] {
            let manifest_dir = root.join(member);
            fs::create_dir_all(manifest_dir.join("src")).unwrap();
            fs::write(
                manifest_dir.join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n"),
            )
            .unwrap();
            fs::write(manifest_dir.join("src/lib.rs"), "").unwrap();
        }

        let map = discover(&root, &RaysenseConfig::default());
        let alpha = map
            .members_by_crate
            .get("alpha")
            .expect("alpha member is discovered");
        assert_eq!(alpha.crate_name, "alpha");
        assert!(alpha.src_dir.ends_with("crates/alpha/src"));
        assert!(map.members_by_crate.contains_key("beta"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn discovers_single_crate_root_package() {
        let root = temp_workspace_root("cargo_single");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"solo\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "").unwrap();

        let map = discover(&root, &RaysenseConfig::default());
        let solo = map
            .members_by_crate
            .get("solo")
            .expect("root [package] is treated as a workspace member");
        assert_eq!(solo.manifest_dir, PathBuf::from("."));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn skips_glob_workspace_members_for_now() {
        let root = temp_workspace_root("cargo_glob");
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("crates/alpha/src")).unwrap();
        fs::write(
            root.join("crates/alpha/Cargo.toml"),
            "[package]\nname = \"alpha\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();

        let map = discover(&root, &RaysenseConfig::default());
        assert!(
            map.members_by_crate.is_empty(),
            "glob expansion is intentionally deferred to a follow-up slice"
        );

        fs::remove_dir_all(&root).unwrap();
    }
}
