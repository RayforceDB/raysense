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

use crate::facts::{
    CallEdgeFact, CallFact, EntryPointFact, EntryPointKind, FileFact, FunctionFact, ImportFact,
    ImportResolution, Language, ScanReport, SnapshotFact, TraitImplFact, TypeFact, Visibility,
};
use crate::graph::compute_graph_metrics;
use crate::health::{LanguagePluginConfig, RaysenseConfig};
use crate::profile::ProjectProfile;
use ignore::WalkBuilder;
use libloading::Library;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use tree_sitter::{Language as TsLanguage, Node, Parser, Query, QueryCursor, StreamingIterator};
use tree_sitter_language::LanguageFn;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("failed to scan {path}: {source}")]
    Walk {
        path: PathBuf,
        #[source]
        source: ignore::Error,
    },
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse plugin config {path}: {source}")]
    PluginConfig {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to load grammar library {path}: {message}")]
    GrammarLibrary { path: PathBuf, message: String },
}

pub fn scan_path(root: impl AsRef<Path>) -> Result<ScanReport, ScanError> {
    scan_path_with_config(root, &RaysenseConfig::default())
}

pub fn scan_path_with_config(
    root: impl AsRef<Path>,
    config: &RaysenseConfig,
) -> Result<ScanReport, ScanError> {
    let root = root
        .as_ref()
        .canonicalize()
        .map_err(|source| ScanError::Read {
            path: root.as_ref().to_path_buf(),
            source,
        })?;
    let config = load_project_plugins(&root, config)?;
    // Workspace discovery runs once per scan. The map is built eagerly
    // so future slices can wire it into `crate::` resolution and
    // cross-crate import classification without changing this seam.
    let _workspace = crate::workspace::discover(&root, &config);

    let mut files = Vec::new();
    let mut functions = Vec::new();
    let mut entry_points = Vec::new();
    let mut imports = Vec::new();
    let mut calls = Vec::new();
    let mut types: Vec<TypeFact> = Vec::new();
    let mut trait_impls: Vec<TraitImplFact> = Vec::new();

    for entry in WalkBuilder::new(&root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .parents(true)
        .build()
    {
        let entry = entry.map_err(|source| ScanError::Walk {
            path: root.clone(),
            source,
        })?;

        if !entry.file_type().map(|ty| ty.is_file()).unwrap_or(false) {
            continue;
        }

        let path = entry.path();
        let relative_path = path.strip_prefix(&root).unwrap_or(path).to_path_buf();
        if is_internal_path(&relative_path) || is_default_ignored(&relative_path) {
            continue;
        }
        if is_ignored_path(&relative_path, &config.scan.ignored_paths)
            || is_ignored_path(&relative_path, &config.scan.generated_paths)
        {
            continue;
        }

        let language = Language::from_path(path);
        let plugin = matching_plugin(&relative_path, &config);
        if plugin
            .as_ref()
            .is_some_and(|plugin| is_ignored_path(&relative_path, &plugin.ignored_paths))
        {
            continue;
        }
        if !language.is_supported() && plugin.is_none() {
            continue;
        }
        let language_label = plugin
            .as_ref()
            .map(|plugin| plugin.name.clone())
            .unwrap_or_else(|| language_name(language).to_string());
        if !is_enabled_language_name(&language_label, &config) {
            continue;
        }

        let content = fs::read_to_string(path).map_err(|source| ScanError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        let file_id = files.len();
        let file_fact = FileFact {
            file_id,
            module: module_name(&relative_path, language, plugin.as_ref()),
            path: relative_path.clone(),
            language,
            language_name: language_label,
            lines: content.lines().count(),
            bytes: content.len(),
            content_hash: hash_content(&content),
            comment_lines: count_comment_lines(&content),
        };

        let mut file_functions = if let Some(plugin) = plugin.as_ref() {
            extract_plugin_functions(file_id, &content, plugin)
        } else {
            extract_functions(file_id, language, &content)
        };
        let visibility_patterns_owned;
        let visibility_patterns = match plugin.as_ref() {
            Some(plugin) => &plugin.visibility_patterns,
            None => match synthesize_language_plugin_defaults(language) {
                Some(synth) => {
                    visibility_patterns_owned = synth.visibility_patterns;
                    &visibility_patterns_owned
                }
                None => {
                    visibility_patterns_owned = std::collections::BTreeMap::new();
                    &visibility_patterns_owned
                }
            },
        };
        for function in &mut file_functions {
            let line = line_at(&content, function.start_line);
            function.visibility = classify_visibility(line, visibility_patterns);
        }
        for function in &mut file_functions {
            function.function_id = functions.len();
            functions.push(function.clone());
        }

        let mut file_entry_points = extract_entry_points(
            file_id,
            language,
            &relative_path,
            &content,
            &file_functions,
            plugin.as_ref(),
        );
        for entry_point in &mut file_entry_points {
            entry_point.entry_id = entry_points.len();
            entry_points.push(entry_point.clone());
        }

        let mut file_imports = if let Some(plugin) = plugin.as_ref() {
            extract_plugin_imports(file_id, &content, plugin)
        } else {
            extract_imports(file_id, language, &content)
        };
        let alias_capture_enabled = match plugin.as_ref() {
            Some(plugin) => plugin.capture_import_aliases,
            None => synthesize_language_plugin_defaults(language)
                .map(|plugin| plugin.capture_import_aliases)
                .unwrap_or(false),
        };
        if !alias_capture_enabled {
            for import in &mut file_imports {
                import.alias = None;
            }
        }
        for import in &mut file_imports {
            import.import_id = imports.len();
            imports.push(import.clone());
        }

        let mut file_calls = if let Some(plugin) = plugin.as_ref() {
            extract_plugin_calls(file_id, &content, &file_functions, plugin)
        } else {
            extract_calls(file_id, language, &content, &file_functions)
        };
        for call in &mut file_calls {
            call.call_id = calls.len();
            calls.push(call.clone());
        }

        let line_types = if matches!(language, Language::Rayfall) {
            extract_rayfall_types(file_id, &content)
        } else {
            extract_types(file_id, &file_fact, &content, plugin.as_ref())
        };
        let mut merged_types = merge_tree_sitter_types_with_line_types(
            extract_tree_sitter_types(file_id, &content, language),
            line_types,
            plugin.as_ref(),
        );
        for type_fact in &mut merged_types {
            let line = line_at(&content, type_fact.line);
            type_fact.visibility = classify_visibility(line, visibility_patterns);
        }
        for mut type_fact in merged_types {
            type_fact.type_id = types.len();
            types.push(type_fact);
        }

        for mut impl_fact in extract_trait_impls(file_id, &content, language) {
            impl_fact.impl_id = trait_impls.len();
            trait_impls.push(impl_fact);
        }

        files.push(file_fact);
    }

    let alias_map = build_alias_map(&root, &config);
    apply_alias_rewrites(&mut imports, &files, &alias_map);
    resolve_imports(&files, &mut imports, &config);
    let call_edges = resolve_call_edges(&files, &functions, &calls);

    let snapshot_id = snapshot_id(&files);
    let graph = compute_graph_metrics(&files, &imports);
    let snapshot = SnapshotFact {
        snapshot_id,
        root,
        file_count: files.len(),
        function_count: functions.len(),
        import_count: imports.len(),
        call_count: calls.len(),
    };

    Ok(ScanReport {
        snapshot,
        files,
        functions,
        entry_points,
        imports,
        calls,
        call_edges,
        types,
        trait_impls,
        graph,
    })
}

fn load_project_plugins(root: &Path, config: &RaysenseConfig) -> Result<RaysenseConfig, ScanError> {
    let mut config = config.clone();
    let plugins_dir = root.join(".raysense/plugins");
    if !plugins_dir.exists() {
        return Ok(config);
    }
    let entries = fs::read_dir(&plugins_dir).map_err(|source| ScanError::Read {
        path: plugins_dir.clone(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ScanError::Read {
            path: plugins_dir.clone(),
            source,
        })?;
        let plugin_path = entry.path().join("plugin.toml");
        if !plugin_path.exists() {
            continue;
        }
        let content = fs::read_to_string(&plugin_path).map_err(|source| ScanError::Read {
            path: plugin_path.clone(),
            source,
        })?;
        let mut plugin: LanguagePluginConfig =
            toml::from_str(&content).map_err(|source| ScanError::PluginConfig {
                path: plugin_path,
                source,
            })?;
        let tags_path = entry.path().join("queries/tags.scm");
        if tags_path.exists() {
            plugin.tags_query =
                Some(
                    fs::read_to_string(&tags_path).map_err(|source| ScanError::Read {
                        path: tags_path,
                        source,
                    })?,
                );
        }
        if let Some(grammar_path) = plugin.grammar_path.as_ref() {
            let path = PathBuf::from(grammar_path);
            if path.is_relative() {
                plugin.grammar_path =
                    Some(entry.path().join(path).to_string_lossy().replace('\\', "/"));
            }
        }
        if plugin.name.trim().is_empty()
            || (plugin.extensions.is_empty() && plugin.file_names.is_empty())
        {
            continue;
        }
        config
            .scan
            .plugins
            .retain(|existing| existing.name != plugin.name);
        config.scan.plugins.push(plugin);
    }
    Ok(config)
}

fn is_ignored_path(path: &Path, ignored_paths: &[String]) -> bool {
    let path = normalize_relative_path(path);
    ignored_paths
        .iter()
        .map(|pattern| pattern.trim())
        .filter(|pattern| !pattern.is_empty())
        .any(|pattern| matches_path_pattern(&path, &normalize_pattern(pattern)))
}

fn is_internal_path(path: &Path) -> bool {
    normalize_relative_path(path).starts_with(".raysense/")
}

/// Build / vendor / cache directories that are almost never project source.
/// Skipped in addition to whatever the project's `.gitignore` already
/// excludes, so trees without a project `.gitignore` (extracted `.crate`
/// tarballs, downloaded archives, fresh checkouts that haven't been opened
/// in their build tool yet) don't blow up raysense's analysis with
/// thousands of vendored or generated files.
///
/// `vendor/` is intentionally NOT in the list -- some projects (Go modules
/// with `vendor/`, PHP/Composer, raysense's own published `.crate`) treat
/// it as committed source.  Those that don't can add it via the project's
/// `.raysense.toml` `[scan] ignored_paths` list.
const DEFAULT_IGNORED_DIRS: &[&str] = &[
    "target",
    "node_modules",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".cache",
    ".venv",
    "venv",
    "__pycache__",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".gradle",
    ".idea",
    ".vscode",
];

fn is_default_ignored(path: &Path) -> bool {
    let path = normalize_relative_path(path);
    DEFAULT_IGNORED_DIRS
        .iter()
        .any(|dir| path == *dir || path.starts_with(&format!("{dir}/")))
}

fn matches_path_pattern(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    if pattern.is_empty() {
        return false;
    }
    if pattern.contains('*') {
        return wildcard_match(path, pattern);
    }
    path == pattern || path.starts_with(&format!("{pattern}/"))
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    let mut remaining = value;
    let mut parts = pattern.split('*').peekable();
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');

    if let Some(first) = parts.next() {
        if !first.is_empty() {
            if !remaining.starts_with(first) {
                return false;
            }
            remaining = &remaining[first.len()..];
        } else if !starts_with_wildcard {
            return false;
        }
    }

    while let Some(part) = parts.next() {
        if part.is_empty() {
            continue;
        }
        let Some(index) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[index + part.len()..];
        if parts.peek().is_none() && !ends_with_wildcard && !remaining.is_empty() {
            return false;
        }
    }

    true
}

fn normalize_relative_path(path: &Path) -> String {
    path.components()
        .filter_map(component_to_string)
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_pattern(pattern: &str) -> String {
    pattern.replace('\\', "/").trim_matches('/').to_string()
}

fn is_enabled_language_name(language: &str, config: &RaysenseConfig) -> bool {
    if config
        .scan
        .disabled_languages
        .iter()
        .any(|item| item.eq_ignore_ascii_case(language))
    {
        return false;
    }
    config.scan.enabled_languages.is_empty()
        || config
            .scan
            .enabled_languages
            .iter()
            .any(|item| item.eq_ignore_ascii_case(language))
}

pub(crate) fn matching_plugin(
    path: &Path,
    config: &RaysenseConfig,
) -> Option<LanguagePluginConfig> {
    config
        .scan
        .plugins
        .iter()
        .find(|plugin| plugin_matches_path(plugin, path))
        .cloned()
        .or_else(|| builtin_language_plugin(path))
}

fn plugin_by_language_name(name: &str, config: &RaysenseConfig) -> Option<LanguagePluginConfig> {
    config
        .scan
        .plugins
        .iter()
        .find(|plugin| plugin.name.eq_ignore_ascii_case(name))
        .cloned()
        .or_else(|| {
            standard_language_plugins()
                .into_iter()
                .find(|plugin| plugin.name.eq_ignore_ascii_case(name))
        })
}

fn plugin_matches_extension(plugin: &LanguagePluginConfig, ext: &str) -> bool {
    !plugin.name.trim().is_empty()
        && plugin
            .extensions
            .iter()
            .any(|candidate| candidate.trim_start_matches('.').eq_ignore_ascii_case(ext))
}

fn plugin_matches_path(plugin: &LanguagePluginConfig, path: &Path) -> bool {
    if plugin.name.trim().is_empty() {
        return false;
    }
    if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| plugin_matches_extension(plugin, ext))
    {
        return true;
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    plugin
        .file_names
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(file_name))
}

fn builtin_language_plugin(path: &Path) -> Option<LanguagePluginConfig> {
    standard_language_plugins()
        .into_iter()
        .find(|plugin| plugin_matches_path(plugin, path))
}

pub fn standard_language_plugins() -> Vec<LanguagePluginConfig> {
    let catalog = [
        ("go", &["go"][..], &["func "][..], &["import "][..]),
        (
            "java",
            &["java"],
            &["public ", "private ", "protected ", "static "],
            &["import "],
        ),
        ("kotlin", &["kt", "kts"], &["fun "], &["import "]),
        ("scala", &["scala"], &["def "], &["import "]),
        (
            "csharp",
            &["cs"],
            &["public ", "private ", "protected ", "static "],
            &["using "],
        ),
        (
            "php",
            &["php"],
            &["function "],
            &["use ", "require ", "include "],
        ),
        ("ruby", &["rb"], &["def "], &["require ", "load "]),
        ("swift", &["swift"], &["func "], &["import "]),
        (
            "objective-c",
            &["m", "mm"],
            &["- ", "+ "],
            &["#import ", "#include "],
        ),
        ("zig", &["zig"], &["fn "], &["@import("]),
        (
            "nim",
            &["nim"],
            &["proc ", "func ", "method "],
            &["import ", "include "],
        ),
        ("lua", &["lua"], &["function "], &["require "]),
        ("r", &["r", "R"], &[""], &["library(", "require("]),
        ("julia", &["jl"], &["function "], &["using ", "import "]),
        (
            "dart",
            &["dart"],
            &["void ", "Future<", "String ", "int "],
            &["import "],
        ),
        (
            "elixir",
            &["ex", "exs"],
            &["def ", "defp "],
            &["alias ", "import ", "require "],
        ),
        ("erlang", &["erl", "hrl"], &[""], &["-include", "-import"]),
        ("haskell", &["hs", "lhs"], &[""], &["import "]),
        ("ocaml", &["ml", "mli"], &["let "], &["open "]),
        ("fsharp", &["fs", "fsi", "fsx"], &["let "], &["open "]),
        (
            "clojure",
            &["clj", "cljs", "cljc"],
            &["(defn "],
            &["(:require ", "(require "],
        ),
        ("lisp", &["lisp", "lsp", "el"], &["(defun "], &["(require "]),
        ("scheme", &["scm", "ss"], &["(define "], &["(import "]),
        ("perl", &["pl", "pm"], &["sub "], &["use ", "require "]),
        (
            "powershell",
            &["ps1", "psm1"],
            &["function "],
            &["Import-Module "],
        ),
        (
            "shell",
            &["sh", "bash", "zsh", "fish"],
            &["function "],
            &["source ", ". "],
        ),
        (
            "sql",
            &["sql"],
            &["create function ", "create procedure "],
            &["include "],
        ),
        ("html", &["html", "htm"], &["function "], &["<script"]),
        (
            "css",
            &["css", "scss", "sass", "less"],
            &[""],
            &["@import "],
        ),
        ("vue", &["vue"], &["function ", "const "], &["import "]),
        (
            "svelte",
            &["svelte"],
            &["function ", "const "],
            &["import "],
        ),
        (
            "jsonnet",
            &["jsonnet", "libsonnet"],
            &["local "],
            &["import "],
        ),
        (
            "terraform",
            &["tf", "tfvars"],
            &["resource ", "module "],
            &["module "],
        ),
        (
            "hcl",
            &["hcl"],
            &["resource ", "module ", "variable "],
            &["module "],
        ),
        (
            "gdscript",
            &["gd"],
            &["func "],
            &["extends ", "class_name "],
        ),
        (
            "glsl",
            &["glsl", "vert", "frag", "geom", "tesc", "tese", "comp"],
            &["void "],
            &["#include "],
        ),
        ("yaml", &["yaml", "yml"], &[""], &[]),
        ("toml", &["toml"], &[], &[]),
        ("json", &["json"], &[""], &[]),
        ("xml", &["xml"], &[""], &[]),
        ("markdown", &["md", "mdx"], &[], &[]),
        (
            "dockerfile",
            &["dockerfile"],
            &["FROM "],
            &["COPY ", "ADD "],
        ),
        ("make", &["mk", "make"], &[""], &["include "]),
        (
            "cmake",
            &["cmake"],
            &["function(", "macro("],
            &["include(", "add_subdirectory("],
        ),
        ("gradle", &["gradle"], &["task "], &["apply "]),
        ("groovy", &["groovy"], &["def "], &["import "]),
        ("cobol", &["cob", "cbl", "cpy"], &["       "], &["COPY "]),
        ("vb", &["vb"], &["Sub ", "Function "], &["Imports "]),
        (
            "pascal",
            &["pas", "pp", "inc"],
            &["function ", "procedure "],
            &["uses "],
        ),
        (
            "fortran",
            &["f", "f90", "f95", "for"],
            &["function ", "subroutine "],
            &["use "],
        ),
        ("matlab", &["m"], &["function "], &["import "]),
        ("solidity", &["sol"], &["function "], &["import "]),
        ("vyper", &["vy"], &["def "], &["import "]),
        ("proto", &["proto"], &["service ", "rpc "], &["import "]),
        ("thrift", &["thrift"], &["service "], &["include "]),
        ("vlang", &["v"], &["fn "], &["import "]),
        (
            "graphql",
            &["graphql", "gql"],
            &["type ", "query ", "mutation "],
            &["import "],
        ),
        ("assembly", &["s", "asm"], &[""], &["include "]),
        ("coffeescript", &["coffee"], &[""], &["require "]),
        ("elm", &["elm"], &[""], &["import "]),
        ("rescript", &["res", "resi"], &["let "], &["open "]),
        ("crystal", &["cr"], &["def "], &["require "]),
        ("d", &["d"], &["void ", "int ", "auto "], &["import "]),
    ];
    catalog
        .iter()
        .map(|(name, extensions, function_prefixes, import_prefixes)| {
            let mut plugin = LanguagePluginConfig {
                name: (*name).to_string(),
                grammar: None,
                grammar_path: None,
                grammar_symbol: None,
                extensions: extensions.iter().map(|item| (*item).to_string()).collect(),
                function_prefixes: function_prefixes
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                import_prefixes: import_prefixes
                    .iter()
                    .map(|item| (*item).to_string())
                    .collect(),
                call_suffixes: vec!["(".to_string()],
                tags_query: None,
                ..LanguagePluginConfig::default()
            };
            apply_builtin_profile_defaults(&mut plugin);
            plugin
        })
        .collect()
}

fn apply_builtin_profile_defaults(plugin: &mut LanguagePluginConfig) {
    plugin.file_names = match plugin.name.as_str() {
        "dockerfile" => vec!["Dockerfile".to_string(), "Containerfile".to_string()],
        "make" => vec!["Makefile".to_string(), "GNUmakefile".to_string()],
        "cmake" => vec!["CMakeLists.txt".to_string()],
        _ => Vec::new(),
    };
    plugin.package_index_files = match plugin.name.as_str() {
        "python" => vec!["__init__.py".to_string()],
        "typescript" | "javascript" | "vue" | "svelte" => {
            vec![
                "index.ts".to_string(),
                "index.tsx".to_string(),
                "index.js".to_string(),
            ]
        }
        "rust" => vec!["mod.rs".to_string()],
        _ => Vec::new(),
    };
    plugin.test_path_patterns = match plugin.name.as_str() {
        "rust" => vec![
            "tests/*".to_string(),
            "*_test.rs".to_string(),
            "*/tests.rs".to_string(),
        ],
        "python" => vec![
            "tests/*".to_string(),
            "test_*.py".to_string(),
            "*_test.py".to_string(),
        ],
        "typescript" | "javascript" => {
            vec![
                "*.test.*".to_string(),
                "*.spec.*".to_string(),
                "tests/*".to_string(),
            ]
        }
        _ => vec!["tests/*".to_string(), "test/*".to_string()],
    };
    plugin.source_roots = match plugin.name.as_str() {
        "rust" | "typescript" | "javascript" | "python" => vec!["src".to_string()],
        "java" | "kotlin" | "scala" => {
            vec!["src/main/java".to_string(), "src/main/kotlin".to_string()]
        }
        "go" => vec!["cmd".to_string(), "pkg".to_string(), "internal".to_string()],
        _ => Vec::new(),
    };
    plugin.ignored_paths = match plugin.name.as_str() {
        "typescript" | "javascript" => vec!["node_modules/*".to_string(), "dist/*".to_string()],
        "rust" => vec!["target/*".to_string()],
        "python" => vec!["__pycache__/*".to_string(), ".venv/*".to_string()],
        _ => Vec::new(),
    };
    plugin.local_import_prefixes = match plugin.name.as_str() {
        "rust" => vec![
            "crate::".to_string(),
            "self::".to_string(),
            "super::".to_string(),
        ],
        "typescript" | "javascript" | "python" => vec![".".to_string()],
        _ => vec![".".to_string()],
    };
    plugin.test_attribute_patterns = match plugin.name.as_str() {
        "rust" => vec!["#[test]".to_string()],
        "java" | "kotlin" => vec!["@Test".to_string()],
        _ => Vec::new(),
    };
    plugin.conditional_test_attributes = match plugin.name.as_str() {
        "rust" => vec!["#[cfg(test)]".to_string()],
        _ => Vec::new(),
    };
    plugin.capture_import_aliases = matches!(plugin.name.as_str(), "rust");
    plugin.visibility_patterns = builtin_visibility_patterns(plugin.name.as_str());
    plugin.workspace_manifest_files = match plugin.name.as_str() {
        "rust" => vec!["Cargo.toml".to_string()],
        _ => Vec::new(),
    };
}

/// Built-in `visibility_patterns` table for the languages whose modifiers
/// raysense recognizes out of the box. Other languages get an empty map
/// (and therefore `Visibility::Unknown` on every fact) until a project
/// plugin spells the patterns out.
fn builtin_visibility_patterns(name: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    match name {
        "rust" => {
            map.insert("public".to_string(), vec!["pub ".to_string()]);
            map.insert("internal".to_string(), vec!["pub(crate)".to_string()]);
            map.insert(
                "restricted".to_string(),
                vec!["pub(super)".to_string(), "pub(in ".to_string()],
            );
        }
        "java" | "kotlin" | "scala" => {
            map.insert("public".to_string(), vec!["public ".to_string()]);
            map.insert("protected".to_string(), vec!["protected ".to_string()]);
            map.insert("private".to_string(), vec!["private ".to_string()]);
        }
        "csharp" => {
            map.insert("public".to_string(), vec!["public ".to_string()]);
            map.insert("protected".to_string(), vec!["protected ".to_string()]);
            map.insert("private".to_string(), vec!["private ".to_string()]);
            map.insert("internal".to_string(), vec!["internal ".to_string()]);
        }
        _ => {}
    }
    map
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::CSharp => "csharp",
        Language::Java => "java",
        Language::Kotlin => "kotlin",
        Language::Python => "python",
        Language::Rayfall => "rayfall",
        Language::Ruby => "ruby",
        Language::Rust => "rust",
        Language::Scala => "scala",
        Language::Swift => "swift",
        Language::TypeScript => "typescript",
        Language::Unknown => "unknown",
    }
}

fn hash_content(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn snapshot_id(files: &[FileFact]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.path.to_string_lossy().as_bytes());
        hasher.update(file.content_hash.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn module_name(
    path: &Path,
    language: Language,
    plugin: Option<&LanguagePluginConfig>,
) -> String {
    let mut components: Vec<String> = path.components().filter_map(component_to_string).collect();
    if let Some(plugin) = plugin {
        for root in &plugin.source_roots {
            let root_parts: Vec<&str> = root.split('/').filter(|part| !part.is_empty()).collect();
            if !root_parts.is_empty()
                && components
                    .iter()
                    .map(String::as_str)
                    .take(root_parts.len())
                    .eq(root_parts.iter().copied())
            {
                components.drain(..root_parts.len());
                break;
            }
        }
    }

    if let Some(last) = components.last_mut() {
        if let Some(stem) = Path::new(last).file_stem().and_then(|stem| stem.to_str()) {
            *last = stem.to_string();
        }
    }

    match language {
        Language::Rust if components.last().is_some_and(|name| name == "mod") => {
            components.pop();
        }
        Language::TypeScript | Language::Python
            if components
                .last()
                .is_some_and(|name| name == "index" || name == "__init__") =>
        {
            components.pop();
        }
        _ => {}
    }
    if let Some(plugin) = plugin {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if plugin
            .package_index_files
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(file_name))
        {
            components.pop();
        }
    }

    components.join(".")
}

fn extract_functions(file_id: usize, language: Language, content: &str) -> Vec<FunctionFact> {
    match language {
        Language::Rust => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_rust::LANGUAGE.into(),
            &["function_item"],
        )
        .unwrap_or_else(|| extract_token_functions(file_id, content, "fn ")),
        Language::Python => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_python::LANGUAGE.into(),
            &["function_definition"],
        )
        .unwrap_or_else(|| extract_prefixed_functions(file_id, content, "def ")),
        Language::TypeScript => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_typescript::LANGUAGE_TSX.into(),
            &[
                "function_declaration",
                "generator_function_declaration",
                "method_definition",
                "lexical_declaration",
            ],
        )
        .unwrap_or_else(|| extract_typescript_functions(file_id, content)),
        Language::C => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_c::LANGUAGE.into(),
            &["function_definition"],
        )
        .unwrap_or_else(|| extract_c_like_functions(file_id, content)),
        Language::Cpp => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_cpp::LANGUAGE.into(),
            &["function_definition"],
        )
        .unwrap_or_else(|| extract_c_like_functions(file_id, content)),
        Language::Java => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_java::LANGUAGE.into(),
            &["method_declaration", "constructor_declaration"],
        )
        .unwrap_or_else(|| extract_c_like_functions(file_id, content)),
        Language::CSharp => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_c_sharp::LANGUAGE.into(),
            &[
                "method_declaration",
                "constructor_declaration",
                "local_function_statement",
            ],
        )
        .unwrap_or_else(|| extract_c_like_functions(file_id, content)),
        Language::Kotlin => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_kotlin_ng::LANGUAGE.into(),
            &["function_declaration"],
        )
        .unwrap_or_else(|| extract_prefixed_functions(file_id, content, "fun ")),
        Language::Scala => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_scala::LANGUAGE.into(),
            &["function_definition", "function_declaration"],
        )
        .unwrap_or_else(|| extract_prefixed_functions(file_id, content, "def ")),
        Language::Swift => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_swift::LANGUAGE.into(),
            &["function_declaration", "init_declaration"],
        )
        .unwrap_or_else(|| extract_prefixed_functions(file_id, content, "func ")),
        Language::Ruby => extract_tree_sitter_functions(
            file_id,
            content,
            tree_sitter_ruby::LANGUAGE.into(),
            &["method", "singleton_method"],
        )
        .unwrap_or_else(|| extract_prefixed_functions(file_id, content, "def ")),
        Language::Rayfall => extract_rayfall_functions(file_id, content),
        Language::Unknown => Vec::new(),
    }
}

fn extract_tree_sitter_functions(
    file_id: usize,
    content: &str,
    language: tree_sitter::Language,
    function_kinds: &[&str],
) -> Option<Vec<FunctionFact>> {
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut functions = Vec::new();
    collect_tree_sitter_functions(file_id, content, root, function_kinds, &mut functions);
    Some(functions)
}

fn collect_tree_sitter_functions(
    file_id: usize,
    content: &str,
    node: Node<'_>,
    function_kinds: &[&str],
    functions: &mut Vec<FunctionFact>,
) {
    if function_kinds.contains(&node.kind()) {
        if is_function_node(node) {
            if let Some(name) = function_name(content, node) {
                functions.push(FunctionFact {
                    function_id: 0,
                    file_id,
                    name,
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    visibility: Visibility::default(),
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_tree_sitter_functions(file_id, content, child, function_kinds, functions);
    }
}

fn is_function_node(node: Node<'_>) -> bool {
    node.kind() != "lexical_declaration"
        || has_descendant_kind(node, &["arrow_function", "function"])
}

fn has_descendant_kind(node: Node<'_>, kinds: &[&str]) -> bool {
    if kinds.contains(&node.kind()) {
        return true;
    }
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .any(|child| has_descendant_kind(child, kinds));
    found
}

fn function_name(content: &str, node: Node<'_>) -> Option<String> {
    if let Some(name) = node.child_by_field_name("name") {
        return node_text(content, name);
    }
    if let Some(declarator) = node.child_by_field_name("declarator") {
        return first_identifier(content, declarator);
    }
    first_identifier(content, node)
}

fn first_identifier(content: &str, node: Node<'_>) -> Option<String> {
    if node.kind() == "identifier" || node.kind() == "field_identifier" {
        return node_text(content, node);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(identifier) = first_identifier(content, child) {
            return Some(identifier);
        }
    }
    None
}

fn last_identifier(content: &str, node: Node<'_>) -> Option<String> {
    let mut out = if node.kind() == "identifier" || node.kind() == "field_identifier" {
        node_text(content, node)
    } else {
        None
    };

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(identifier) = last_identifier(content, child) {
            out = Some(identifier);
        }
    }
    out
}

fn node_text(content: &str, node: Node<'_>) -> Option<String> {
    node.utf8_text(content.as_bytes())
        .ok()
        .filter(|text| !text.is_empty())
        .map(ToString::to_string)
}

fn extract_entry_points(
    file_id: usize,
    language: Language,
    path: &Path,
    content: &str,
    functions: &[FunctionFact],
    plugin: Option<&LanguagePluginConfig>,
) -> Vec<EntryPointFact> {
    let mut entries = Vec::new();

    for function in functions {
        if function.name == "main"
            && matches!(language, Language::Rust | Language::C | Language::Cpp)
        {
            entries.push(new_entry(file_id, EntryPointKind::Binary, "main"));
        }
    }

    let normalized = normalize_path(path);
    if normalized.starts_with("examples/") {
        entries.push(new_entry(
            file_id,
            EntryPointKind::Example,
            path_symbol(path),
        ));
    }
    if is_test_path_profile(&normalized, plugin) {
        entries.push(new_entry(file_id, EntryPointKind::Test, path_symbol(path)));
    }

    let synthesized;
    let effective_plugin = match plugin {
        Some(plugin) => Some(plugin),
        None => match synthesize_language_plugin_defaults(language) {
            Some(plugin) => {
                synthesized = plugin;
                Some(&synthesized)
            }
            None => None,
        },
    };
    if let Some(plugin) = effective_plugin {
        let mut already_test: std::collections::HashSet<usize> = std::collections::HashSet::new();
        if !plugin.test_attribute_patterns.is_empty() {
            let lines: Vec<&str> = content.lines().collect();
            for (idx, function) in functions.iter().enumerate() {
                if function_has_preceding_test_attribute(
                    &lines,
                    function.start_line,
                    &plugin.test_attribute_patterns,
                ) {
                    entries.push(new_entry(
                        file_id,
                        EntryPointKind::Test,
                        function.name.clone(),
                    ));
                    already_test.insert(idx);
                }
            }
        }
        if !plugin.conditional_test_attributes.is_empty() {
            let ranges =
                collect_cfg_test_ranges(content, language, &plugin.conditional_test_attributes);
            if !ranges.is_empty() {
                for (idx, function) in functions.iter().enumerate() {
                    if already_test.contains(&idx) {
                        continue;
                    }
                    if ranges.iter().any(|(start, end)| {
                        function.start_line >= *start && function.start_line <= *end
                    }) {
                        entries.push(new_entry(
                            file_id,
                            EntryPointKind::Test,
                            function.name.clone(),
                        ));
                        already_test.insert(idx);
                    }
                }
            }
        }
    }

    entries
}

/// Synthesize the built-in plugin defaults for a known language so that
/// scans without a project-configured plugin still see language-aware
/// behaviour (test attributes, etc.). Returns `None` for languages that
/// have no built-in profile entry.
fn synthesize_language_plugin_defaults(language: Language) -> Option<LanguagePluginConfig> {
    if matches!(language, Language::Unknown) {
        return None;
    }
    let mut plugin = LanguagePluginConfig {
        name: language_name(language).to_string(),
        ..LanguagePluginConfig::default()
    };
    apply_builtin_profile_defaults(&mut plugin);
    Some(plugin)
}

/// Classify a single trimmed source line against a plugin's
/// `visibility_patterns` map. Returns the matching `Visibility` variant,
/// or `Visibility::Unknown` when no pattern matches. Patterns are walked
/// longest-prefix-first so longer specific tokens (e.g. `pub(crate)`)
/// win over their shorter shared prefix (`pub `).
fn classify_visibility(
    line: &str,
    patterns: &std::collections::BTreeMap<String, Vec<String>>,
) -> Visibility {
    if patterns.is_empty() {
        return Visibility::Unknown;
    }
    let trimmed = line.trim_start();
    let mut best: Option<(usize, Visibility)> = None;
    for (variant_name, prefixes) in patterns {
        let variant = match variant_name.as_str() {
            "public" => Visibility::Public,
            "protected" => Visibility::Protected,
            "internal" => Visibility::Internal,
            "restricted" => Visibility::Restricted,
            "private" => Visibility::Private,
            _ => continue,
        };
        for prefix in prefixes {
            if prefix.is_empty() {
                continue;
            }
            if trimmed.starts_with(prefix.as_str())
                && best.map(|(len, _)| prefix.len() > len).unwrap_or(true)
            {
                best = Some((prefix.len(), variant));
            }
        }
    }
    best.map(|(_, variant)| variant)
        .unwrap_or(Visibility::Unknown)
}

/// Read line `line_no` (1-indexed) from `content`, returning an empty
/// string if out of range. Used by the visibility classifier to peek at
/// the declaration line without re-collecting `content.lines()`.
fn line_at(content: &str, line_no: usize) -> &str {
    if line_no == 0 {
        return "";
    }
    content.lines().nth(line_no - 1).unwrap_or("")
}

/// True when the (trimmed) line above `function_start_line` -- skipping
/// blank and comment lines -- begins with any pattern in `patterns`.
/// Implements `test_attribute_patterns` semantics for languages whose
/// per-function test marker is a single source line (e.g. Rust `#[test]`,
/// Java `@Test`).
fn function_has_preceding_test_attribute(
    lines: &[&str],
    function_start_line: usize,
    patterns: &[String],
) -> bool {
    if function_start_line < 2 || function_start_line - 1 > lines.len() {
        return false;
    }
    let mut idx = function_start_line - 2;
    loop {
        let line = lines[idx].trim();
        let is_skippable = line.is_empty()
            || line.starts_with("//")
            || line.starts_with("///")
            || line.starts_with("/*")
            || line.starts_with("*");
        if is_skippable {
            if idx == 0 {
                return false;
            }
            idx -= 1;
            continue;
        }
        return patterns
            .iter()
            .any(|pattern| line.starts_with(pattern.trim()));
    }
}

/// Walk the source tree for `attribute_item`-like nodes whose leading
/// text matches any pattern in `patterns`, returning the inclusive
/// 1-indexed line range of the *next* annotated item (mod, function,
/// nested item). Used to cascade test classification: any function whose
/// definition falls in one of the returned ranges is part of a test
/// scope. Currently dispatches via tree-sitter for Rust; other languages
/// return an empty vector until their grammar dispatch is added.
fn collect_cfg_test_ranges(
    content: &str,
    language: Language,
    patterns: &[String],
) -> Vec<(usize, usize)> {
    if patterns.is_empty() {
        return Vec::new();
    }
    let ts_language: tree_sitter::Language = match language {
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        _ => return Vec::new(),
    };
    let mut parser = Parser::new();
    if parser.set_language(&ts_language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(content, None) else {
        return Vec::new();
    };
    let normalized: Vec<String> = patterns
        .iter()
        .map(|pattern| pattern.split_whitespace().collect::<String>())
        .filter(|pattern| !pattern.is_empty())
        .collect();
    if normalized.is_empty() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    walk_cfg_test_attributes(content, tree.root_node(), &normalized, &mut ranges);
    ranges
}

fn walk_cfg_test_attributes(
    content: &str,
    node: Node<'_>,
    normalized_patterns: &[String],
    ranges: &mut Vec<(usize, usize)>,
) {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    for (idx, child) in children.iter().enumerate() {
        if child.kind() != "attribute_item" {
            continue;
        }
        let Some(text) = node_text(content, *child) else {
            continue;
        };
        let collapsed: String = text.split_whitespace().collect();
        if !normalized_patterns
            .iter()
            .any(|pattern| collapsed.starts_with(pattern))
        {
            continue;
        }
        let mut next = idx + 1;
        while let Some(sibling) = children.get(next) {
            match sibling.kind() {
                "attribute_item" | "line_comment" | "block_comment" => next += 1,
                _ => break,
            }
        }
        if let Some(target) = children.get(next) {
            ranges.push((
                target.start_position().row + 1,
                target.end_position().row + 1,
            ));
        }
    }
    for child in &children {
        walk_cfg_test_attributes(content, *child, normalized_patterns, ranges);
    }
}

fn new_entry(file_id: usize, kind: EntryPointKind, symbol: impl Into<String>) -> EntryPointFact {
    EntryPointFact {
        entry_id: 0,
        file_id,
        kind,
        symbol: symbol.into(),
    }
}

fn path_symbol(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("")
        .to_string()
}

fn extract_token_functions(file_id: usize, content: &str, token: &str) -> Vec<FunctionFact> {
    let lines: Vec<&str> = content.lines().collect();
    content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let rest = line.split_once(token)?.1;
            let name = rest
                .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                .next()
                .filter(|name| !name.is_empty())?;
            Some(FunctionFact {
                function_id: 0,
                file_id,
                name: name.to_string(),
                start_line: idx + 1,
                end_line: block_end_line(&lines, idx),
                visibility: Visibility::default(),
            })
        })
        .collect()
}

fn extract_prefixed_functions(file_id: usize, content: &str, prefix: &str) -> Vec<FunctionFact> {
    let lines: Vec<&str> = content.lines().collect();
    content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let trimmed = line.trim_start();
            let rest = trimmed.strip_prefix(prefix)?;
            let name = rest
                .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                .next()
                .filter(|name| !name.is_empty())?;
            Some(FunctionFact {
                function_id: 0,
                file_id,
                name: name.to_string(),
                start_line: idx + 1,
                end_line: indented_block_end_line(&lines, idx),
                visibility: Visibility::default(),
            })
        })
        .collect()
}

fn extract_typescript_functions(file_id: usize, content: &str) -> Vec<FunctionFact> {
    let mut functions = extract_token_functions(file_id, content, "function ");
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if let Some((name, _)) = trimmed.split_once("=>") {
            let name = name.trim().trim_start_matches("export const").trim();
            if let Some(name) = name.split(':').next().filter(|name| !name.is_empty()) {
                functions.push(FunctionFact {
                    function_id: 0,
                    file_id,
                    name: name.to_string(),
                    start_line: idx + 1,
                    end_line: block_end_line(&lines, idx),
                    visibility: Visibility::default(),
                });
            }
        }
    }
    functions
}

fn extract_c_like_functions(file_id: usize, content: &str) -> Vec<FunctionFact> {
    let searchable = strip_c_like_comments(content);
    let lines: Vec<&str> = content.lines().collect();
    let depths = brace_depths_before_lines(&searchable);
    searchable
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            if depths.get(idx).copied().unwrap_or_default() > 0 {
                return None;
            }
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.ends_with(';') || !trimmed.contains('(') {
                return None;
            }
            if !opens_function_body(&lines, idx) {
                return None;
            }
            let before_paren = trimmed.split('(').next()?.trim();
            let name = before_paren.split_whitespace().last()?;
            if before_paren.contains("typedef")
                || before_paren.contains("struct")
                || name.is_empty()
                || matches!(name, "if" | "for" | "while" | "switch")
            {
                return None;
            }
            Some(FunctionFact {
                function_id: 0,
                file_id,
                name: name.to_string(),
                start_line: idx + 1,
                end_line: block_end_line(&lines, idx),
                visibility: Visibility::default(),
            })
        })
        .collect()
}

fn extract_plugin_functions(
    file_id: usize,
    content: &str,
    plugin: &LanguagePluginConfig,
) -> Vec<FunctionFact> {
    if let Some(functions) = extract_query_functions(file_id, content, plugin) {
        return functions;
    }
    let lines: Vec<&str> = content.lines().collect();
    let prefixes = plugin.function_prefixes.clone();

    let mut functions = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        for prefix in &prefixes {
            if prefix.is_empty() {
                continue;
            }
            let Some(rest) = trimmed.strip_prefix(prefix) else {
                continue;
            };
            let name = rest
                .split(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '-'))
                .next()
                .filter(|name| !name.is_empty());
            if let Some(name) = name {
                functions.push(FunctionFact {
                    function_id: 0,
                    file_id,
                    name: name.to_string(),
                    start_line: idx + 1,
                    end_line: generic_block_end_line(&lines, idx),
                    visibility: Visibility::default(),
                });
            }
            break;
        }
    }
    functions
}

fn extract_plugin_imports(
    file_id: usize,
    content: &str,
    plugin: &LanguagePluginConfig,
) -> Vec<ImportFact> {
    if let Some(imports) = extract_query_imports(file_id, content, plugin) {
        return imports;
    }
    let prefixes = plugin.import_prefixes.clone();

    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            for prefix in &prefixes {
                if prefix.is_empty() {
                    continue;
                }
                if let Some(rest) = trimmed.strip_prefix(prefix) {
                    let target = rest
                        .trim()
                        .trim_matches(['"', '\'', ';'])
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_matches(['"', '\'', ';']);
                    if !target.is_empty() {
                        return Some(new_import(file_id, target, "plugin_import"));
                    }
                }
            }
            None
        })
        .collect()
}

fn extract_query_functions(
    file_id: usize,
    content: &str,
    plugin: &LanguagePluginConfig,
) -> Option<Vec<FunctionFact>> {
    let loaded = query_language(plugin)?;
    let language = loaded.language();
    let query_source = plugin.tags_query.as_deref()?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let query = Query::new(&language, query_source).ok()?;
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, content.as_bytes());
    let mut functions = Vec::new();

    while let Some(matched) = matches.next() {
        let mut name = None;
        let mut definition = None;
        for capture in matched.captures {
            let capture_name = capture_names
                .get(capture.index as usize)
                .copied()
                .unwrap_or("");
            if query_capture_is_name(capture_name) {
                name = node_text(content, capture.node);
            }
            if query_capture_is_function(capture_name) {
                definition = Some(capture.node);
            }
        }
        let Some(node) = definition.or_else(|| {
            matched
                .captures
                .iter()
                .find(|capture| {
                    capture_names
                        .get(capture.index as usize)
                        .is_some_and(|name| query_capture_is_name(name))
                })
                .map(|capture| capture.node)
        }) else {
            continue;
        };
        let Some(name) = name else {
            continue;
        };
        functions.push(FunctionFact {
            function_id: 0,
            file_id,
            name,
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
            visibility: Visibility::default(),
        });
    }
    functions.sort_by(|a, b| {
        a.start_line
            .cmp(&b.start_line)
            .then_with(|| a.name.cmp(&b.name))
    });
    functions.dedup_by(|a, b| a.name == b.name && a.start_line == b.start_line);
    Some(functions)
}

fn extract_query_imports(
    file_id: usize,
    content: &str,
    plugin: &LanguagePluginConfig,
) -> Option<Vec<ImportFact>> {
    let loaded = query_language(plugin)?;
    let language = loaded.language();
    let query_source = plugin.tags_query.as_deref()?;
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let query = Query::new(&language, query_source).ok()?;
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&query, root, content.as_bytes());
    let mut imports = Vec::new();

    while let Some(matched) = matches.next() {
        for capture in matched.captures {
            let capture_name = capture_names
                .get(capture.index as usize)
                .copied()
                .unwrap_or("");
            if !query_capture_is_import(capture_name) {
                continue;
            }
            if let Some(target) = node_text(content, capture.node)
                .and_then(|text| quoted_module_specifier(&text).or(Some(text)))
                .map(|target| target.trim_matches(['"', '\'', ';']).to_string())
                .filter(|target| !target.is_empty())
            {
                imports.push(new_import(file_id, &target, "query_import"));
            }
        }
    }
    imports.dedup_by(|a, b| a.target == b.target);
    Some(imports)
}

enum QueryLanguage {
    Builtin(TsLanguage),
    Dynamic {
        language: TsLanguage,
        _library: Library,
    },
}

impl QueryLanguage {
    fn language(&self) -> TsLanguage {
        match self {
            Self::Builtin(language) => language.clone(),
            Self::Dynamic { language, .. } => language.clone(),
        }
    }
}

fn query_language(plugin: &LanguagePluginConfig) -> Option<QueryLanguage> {
    if let Some(path) = plugin.grammar_path.as_ref() {
        return load_dynamic_query_language(plugin, path)
            .map(|(language, library)| QueryLanguage::Dynamic {
                language,
                _library: library,
            })
            .ok();
    }
    match plugin.grammar.as_deref().unwrap_or(plugin.name.as_str()) {
        "c" => Some(QueryLanguage::Builtin(tree_sitter_c::LANGUAGE.into())),
        "cpp" | "c++" => Some(QueryLanguage::Builtin(tree_sitter_cpp::LANGUAGE.into())),
        "python" => Some(QueryLanguage::Builtin(tree_sitter_python::LANGUAGE.into())),
        "rust" => Some(QueryLanguage::Builtin(tree_sitter_rust::LANGUAGE.into())),
        "typescript" | "javascript" | "tsx" | "jsx" => Some(QueryLanguage::Builtin(
            tree_sitter_typescript::LANGUAGE_TSX.into(),
        )),
        _ => None,
    }
}

fn load_dynamic_query_language(
    plugin: &LanguagePluginConfig,
    path: &str,
) -> Result<(TsLanguage, Library), ScanError> {
    let path = PathBuf::from(path);
    let symbol = plugin
        .grammar_symbol
        .clone()
        .unwrap_or_else(|| format!("tree_sitter_{}", plugin.name.replace('-', "_")));
    let library = unsafe { Library::new(&path) }.map_err(|error| ScanError::GrammarLibrary {
        path: path.clone(),
        message: error.to_string(),
    })?;
    let language = unsafe {
        let function: libloading::Symbol<'_, unsafe extern "C" fn() -> *const ()> = library
            .get(symbol.as_bytes())
            .map_err(|error| ScanError::GrammarLibrary {
                path: path.clone(),
                message: error.to_string(),
            })?;
        TsLanguage::new(LanguageFn::from_raw(*function))
    };
    Ok((language, library))
}

fn query_capture_is_function(name: &str) -> bool {
    name.contains("definition.function")
        || name.contains("definition.method")
        || name == "function"
        || name == "method"
}

fn query_capture_is_name(name: &str) -> bool {
    name == "name" || name.ends_with(".name")
}

fn query_capture_is_import(name: &str) -> bool {
    name.contains("reference.import")
        || name.contains("import")
        || name.contains("module")
        || name.contains("source")
}

fn extract_plugin_calls(
    file_id: usize,
    content: &str,
    functions: &[FunctionFact],
    plugin: &LanguagePluginConfig,
) -> Vec<CallFact> {
    let suffixes = plugin.call_suffixes.clone();
    if suffixes.is_empty() {
        return Vec::new();
    }
    let mut calls = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        for token in line.split(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '-')) {
            if token.is_empty() || functions.iter().any(|function| function.name == token) {
                continue;
            }
            if suffixes
                .iter()
                .any(|suffix| line.contains(&format!("{token}{suffix}")))
            {
                calls.push(CallFact {
                    call_id: 0,
                    file_id,
                    caller_function: enclosing_function(functions, idx + 1),
                    target: token.to_string(),
                    line: idx + 1,
                });
            }
        }
    }
    calls
}

fn generic_block_end_line(lines: &[&str], start_idx: usize) -> usize {
    let brace_end = block_end_line(lines, start_idx);
    if brace_end > start_idx + 1 {
        brace_end
    } else {
        indented_block_end_line(lines, start_idx)
    }
}

fn brace_depths_before_lines(content: &str) -> Vec<usize> {
    let mut depth = 0usize;
    let mut depths = Vec::new();

    for line in content.lines() {
        depths.push(depth);
        for ch in line.chars() {
            match ch {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }

    depths
}

fn opens_function_body(lines: &[&str], start_idx: usize) -> bool {
    for line in lines.iter().skip(start_idx) {
        for ch in line.chars() {
            match ch {
                '{' => return true,
                ';' => return false,
                _ => {}
            }
        }
    }
    false
}

fn strip_c_like_comments(content: &str) -> String {
    let mut stripped = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    let mut in_block = false;
    let mut in_line = false;

    while let Some(ch) = chars.next() {
        if in_line {
            if ch == '\n' {
                in_line = false;
                stripped.push('\n');
            } else {
                stripped.push(' ');
            }
            continue;
        }

        if in_block {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
                stripped.push(' ');
                stripped.push(' ');
            } else if ch == '\n' {
                stripped.push('\n');
            } else {
                stripped.push(' ');
            }
            continue;
        }

        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block = true;
            stripped.push(' ');
            stripped.push(' ');
        } else if ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            in_line = true;
            stripped.push(' ');
            stripped.push(' ');
        } else {
            stripped.push(ch);
        }
    }

    stripped
}

fn block_end_line(lines: &[&str], start_idx: usize) -> usize {
    let mut depth = 0isize;
    let mut saw_open = false;

    for (idx, line) in lines.iter().enumerate().skip(start_idx) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    saw_open = true;
                }
                '}' if saw_open => {
                    depth -= 1;
                    if depth <= 0 {
                        return idx + 1;
                    }
                }
                _ => {}
            }
        }
    }

    start_idx + 1
}

fn indented_block_end_line(lines: &[&str], start_idx: usize) -> usize {
    let base_indent = leading_spaces(lines[start_idx]);
    let mut end_idx = start_idx;

    for (idx, line) in lines.iter().enumerate().skip(start_idx + 1) {
        if line.trim().is_empty() {
            end_idx = idx;
            continue;
        }
        if leading_spaces(line) <= base_indent {
            break;
        }
        end_idx = idx;
    }

    end_idx + 1
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|ch| ch.is_whitespace()).count()
}

fn extract_imports(file_id: usize, language: Language, content: &str) -> Vec<ImportFact> {
    match language {
        Language::Rust => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_rust::LANGUAGE.into())
                .unwrap_or_else(|| extract_rust_imports(file_id, content))
        }
        Language::Python => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_python::LANGUAGE.into())
                .unwrap_or_else(|| extract_python_imports(file_id, content))
        }
        Language::TypeScript => extract_tree_sitter_imports(
            file_id,
            content,
            tree_sitter_typescript::LANGUAGE_TSX.into(),
        )
        .unwrap_or_else(|| extract_typescript_imports(file_id, content)),
        Language::C => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_c::LANGUAGE.into())
                .unwrap_or_else(|| extract_c_imports(file_id, content))
        }
        Language::Cpp => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_cpp::LANGUAGE.into())
                .unwrap_or_else(|| extract_c_imports(file_id, content))
        }
        Language::Java => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_java::LANGUAGE.into())
                .unwrap_or_else(|| extract_jvm_style_imports(file_id, content, "import"))
        }
        Language::CSharp => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_c_sharp::LANGUAGE.into())
                .unwrap_or_else(|| extract_jvm_style_imports(file_id, content, "using"))
        }
        Language::Kotlin => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_kotlin_ng::LANGUAGE.into())
                .unwrap_or_else(|| extract_jvm_style_imports(file_id, content, "import"))
        }
        Language::Scala => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_scala::LANGUAGE.into())
                .unwrap_or_else(|| extract_jvm_style_imports(file_id, content, "import"))
        }
        Language::Swift => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_swift::LANGUAGE.into())
                .unwrap_or_else(|| extract_jvm_style_imports(file_id, content, "import"))
        }
        Language::Ruby => {
            extract_tree_sitter_imports(file_id, content, tree_sitter_ruby::LANGUAGE.into())
                .unwrap_or_else(|| extract_ruby_imports(file_id, content))
        }
        Language::Rayfall => extract_rayfall_imports(file_id, content),
        Language::Unknown => Vec::new(),
    }
}

fn extract_tree_sitter_imports(
    file_id: usize,
    content: &str,
    language: tree_sitter::Language,
) -> Option<Vec<ImportFact>> {
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut imports = Vec::new();
    collect_tree_sitter_imports(file_id, content, root, &mut imports);
    Some(imports)
}

fn collect_tree_sitter_imports(
    file_id: usize,
    content: &str,
    node: Node<'_>,
    imports: &mut Vec<ImportFact>,
) {
    match node.kind() {
        "use_declaration" => {
            if let Some(target) = rust_use_target(content, node) {
                for (expanded, alias) in expand_brace_targets_with_aliases(&target) {
                    imports.push(new_import_with_alias(file_id, &expanded, "use", alias));
                }
            }
        }
        "mod_item" => {
            if let Some(target) = rust_mod_target(content, node) {
                imports.push(new_import(file_id, &target, "mod"));
            }
        }
        "preproc_include" => {
            if let Some((target, kind)) = c_include_target(content, node) {
                imports.push(new_import(file_id, &target, kind));
            }
        }
        "import_statement" => {
            for target in python_import_targets(content, node) {
                imports.push(new_import(file_id, &target, "import"));
            }
            if let Some(target) = typescript_import_target(content, node) {
                imports.push(new_import(file_id, &target, "import"));
            }
        }
        "import_from_statement" | "future_import_statement" => {
            if let Some(target) = python_from_import_target(content, node) {
                imports.push(new_import(file_id, &target, "from"));
            }
        }
        "import_declaration" => {
            // Java / Scala / Swift: `import com.foo.Bar;` or `import Foundation`.
            // C# uses `using_directive`, handled below. Python `import_statement`
            // is matched above and never reaches this arm.
            if let Some(target) = jvm_style_import_target(content, node, "import") {
                imports.push(new_import(file_id, &target, "import"));
            }
        }
        "using_directive" => {
            // C#: `using System.Linq;` or `using static System.Math;`.
            if let Some(target) = jvm_style_import_target(content, node, "using") {
                imports.push(new_import(file_id, &target, "using"));
            }
        }
        "import_header" => {
            // Kotlin: `import com.foo.Bar` (no semicolon).
            if let Some(target) = jvm_style_import_target(content, node, "import") {
                imports.push(new_import(file_id, &target, "import"));
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_tree_sitter_imports(file_id, content, child, imports);
    }
}

fn rust_use_target(content: &str, node: Node<'_>) -> Option<String> {
    Some(
        node_text(content, node)?
            .strip_prefix("use ")?
            .trim()
            .trim_end_matches(';')
            .trim()
            .to_string(),
    )
}

/// Heuristic count of comment lines. A line is treated as a comment if its
/// first non-whitespace token is one of `//`, `#`, `--`, `;` (lisp/asm),
/// `*` (continuation of a `/*` block), or if the line falls between `/* */`
/// markers. Cross-language and conservative — the goal is a comparable ratio,
/// not exact counts.
fn count_comment_lines(content: &str) -> usize {
    let mut count = 0;
    let mut in_block = false;
    for raw_line in content.lines() {
        let line = raw_line.trim_start();
        if in_block {
            count += 1;
            if line.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if line.starts_with("/*") {
            count += 1;
            if !line.contains("*/") {
                in_block = true;
            }
            continue;
        }
        if line.starts_with("//")
            || line.starts_with('#')
            || line.starts_with("--")
            || line.starts_with(';')
            || line.starts_with('*')
        {
            count += 1;
        }
    }
    count
}

/// Fan a single `prefix::{a, b, c}` style target out into `["prefix::a",
/// "prefix::b", "prefix::c"]`. Inputs without braces pass through unchanged
/// so callers can use this unconditionally. Nested braces are not supported —
/// only the first brace group is expanded. Test-only helper kept around so
/// the existing brace-shape tests continue to read the way they did before
/// alias capture landed; production code calls `expand_brace_targets_with_aliases`.
#[cfg(test)]
fn expand_brace_targets(target: &str) -> Vec<String> {
    expand_brace_targets_with_aliases(target)
        .into_iter()
        .map(|(target, _)| target)
        .collect()
}

/// Same as `expand_brace_targets` but also recognizes per-item `as alias`
/// renames. `use crate::{a, b as c, d}` -> `[(crate::a, None),
/// (crate::b, Some("c")), (crate::d, None)]`. Top-level `use a::B as C`
/// is also handled. The brace expansion preserves existing semantics; the
/// alias is attached only to the matching item.
fn expand_brace_targets_with_aliases(target: &str) -> Vec<(String, Option<String>)> {
    let Some(open) = target.find('{') else {
        let (path, alias) = split_use_alias(target);
        return vec![(path.to_string(), alias)];
    };
    let Some(close_rel) = target[open..].find('}') else {
        let (path, alias) = split_use_alias(target);
        return vec![(path.to_string(), alias)];
    };
    let close = open + close_rel;
    let prefix = &target[..open];
    let suffix = &target[close + 1..];
    let items: Vec<(String, Option<String>)> = target[open + 1..close]
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|item| {
            let (path, alias) = split_use_alias(item);
            let full = format!("{prefix}{path}{suffix}");
            (full, alias)
        })
        .collect();
    if items.is_empty() {
        let (path, alias) = split_use_alias(target);
        return vec![(path.to_string(), alias)];
    }
    items
}

/// Split a `path as alias` segment into `(path, Some(alias))`. The
/// separator is the literal token ` as ` so identifiers ending in
/// "as" don't false-match. Inputs without `as` return `(input, None)`.
fn split_use_alias(item: &str) -> (&str, Option<String>) {
    let trimmed = item.trim();
    if let Some((path, alias)) = trimmed.rsplit_once(" as ") {
        let alias = alias.trim().trim_end_matches(';').trim();
        if !alias.is_empty() {
            return (path.trim(), Some(alias.to_string()));
        }
    }
    (trimmed, None)
}

fn rust_mod_target(content: &str, node: Node<'_>) -> Option<String> {
    let text = node_text(content, node)?;
    if text.contains('{') {
        return None;
    }
    node.child_by_field_name("name")
        .and_then(|name| node_text(content, name))
}

fn c_include_target(content: &str, node: Node<'_>) -> Option<(String, &'static str)> {
    let text = node_text(content, node)?;
    let target = text.trim().strip_prefix("#include")?.trim();
    let kind = if target.starts_with('<') {
        "include_system"
    } else {
        "include"
    };
    Some((clean_c_include_target(target).to_string(), kind))
}

fn python_import_targets(content: &str, node: Node<'_>) -> Vec<String> {
    let Some(text) = node_text(content, node) else {
        return Vec::new();
    };
    let Some(rest) = text.trim().strip_prefix("import ") else {
        return Vec::new();
    };
    if rest.starts_with(['"', '\'']) || rest.contains(" from ") {
        return Vec::new();
    }
    rest.split(',')
        .filter_map(|part| {
            part.trim()
                .split_whitespace()
                .next()
                .filter(|target| !target.is_empty())
                .map(ToString::to_string)
        })
        .collect()
}

fn python_from_import_target(content: &str, node: Node<'_>) -> Option<String> {
    let text = node_text(content, node)?;
    text.trim()
        .strip_prefix("from ")?
        .split_whitespace()
        .next()
        .filter(|target| !target.is_empty())
        .map(ToString::to_string)
}

fn typescript_import_target(content: &str, node: Node<'_>) -> Option<String> {
    quoted_module_specifier(&node_text(content, node)?)
}

fn quoted_module_specifier(text: &str) -> Option<String> {
    let mut quote = None;
    let mut start = 0usize;
    for (idx, ch) in text.char_indices() {
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            start = idx + ch.len_utf8();
            break;
        }
    }
    let quote = quote?;
    let end = text[start..].find(quote)? + start;
    Some(text[start..end].to_string())
}

fn extract_calls(
    file_id: usize,
    language: Language,
    content: &str,
    functions: &[FunctionFact],
) -> Vec<CallFact> {
    let (language, call_kinds) = match language {
        Language::Rust => (tree_sitter_rust::LANGUAGE.into(), &["call_expression"][..]),
        Language::C => (tree_sitter_c::LANGUAGE.into(), &["call_expression"][..]),
        Language::Cpp => (tree_sitter_cpp::LANGUAGE.into(), &["call_expression"][..]),
        Language::Python => (tree_sitter_python::LANGUAGE.into(), &["call"][..]),
        Language::TypeScript => (
            tree_sitter_typescript::LANGUAGE_TSX.into(),
            &["call_expression"][..],
        ),
        Language::Java => (
            tree_sitter_java::LANGUAGE.into(),
            &["method_invocation", "object_creation_expression"][..],
        ),
        Language::CSharp => (
            tree_sitter_c_sharp::LANGUAGE.into(),
            &["invocation_expression", "object_creation_expression"][..],
        ),
        Language::Kotlin => (
            tree_sitter_kotlin_ng::LANGUAGE.into(),
            &["call_expression"][..],
        ),
        Language::Scala => (tree_sitter_scala::LANGUAGE.into(), &["call_expression"][..]),
        Language::Swift => (tree_sitter_swift::LANGUAGE.into(), &["call_expression"][..]),
        Language::Ruby => (tree_sitter_ruby::LANGUAGE.into(), &["call"][..]),
        Language::Rayfall => return extract_rayfall_calls(file_id, content, functions),
        Language::Unknown => return Vec::new(),
    };

    extract_tree_sitter_calls(file_id, content, functions, language, call_kinds).unwrap_or_default()
}

fn extract_tree_sitter_calls(
    file_id: usize,
    content: &str,
    functions: &[FunctionFact],
    language: tree_sitter::Language,
    call_kinds: &[&str],
) -> Option<Vec<CallFact>> {
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }

    let mut calls = Vec::new();
    collect_tree_sitter_calls(file_id, content, root, functions, call_kinds, &mut calls);
    Some(calls)
}

fn collect_tree_sitter_calls(
    file_id: usize,
    content: &str,
    node: Node<'_>,
    functions: &[FunctionFact],
    call_kinds: &[&str],
    calls: &mut Vec<CallFact>,
) {
    if call_kinds.contains(&node.kind()) {
        if let Some(target) = call_target(content, node) {
            let line = node.start_position().row + 1;
            calls.push(CallFact {
                call_id: 0,
                file_id,
                caller_function: enclosing_function(functions, line),
                target,
                line,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_tree_sitter_calls(file_id, content, child, functions, call_kinds, calls);
    }
}

fn call_target(content: &str, node: Node<'_>) -> Option<String> {
    let function = node.child_by_field_name("function")?;
    match function.kind() {
        "identifier" | "field_identifier" | "scoped_identifier" | "qualified_identifier" => {
            node_text(content, function)
        }
        _ => last_identifier(content, function),
    }
}

fn enclosing_function(functions: &[FunctionFact], line: usize) -> Option<usize> {
    functions
        .iter()
        .filter(|function| function.start_line <= line && line <= function.end_line)
        .min_by_key(|function| function.end_line.saturating_sub(function.start_line))
        .map(|function| function.function_id)
}

fn extract_rust_imports(file_id: usize, content: &str) -> Vec<ImportFact> {
    let mut imports = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        if let Some(target) = trimmed.strip_prefix("use ") {
            let stripped = target.trim_end_matches(';').trim();
            for (expanded, alias) in expand_brace_targets_with_aliases(stripped) {
                imports.push(new_import_with_alias(file_id, &expanded, "use", alias));
            }
        }
        if let Some(rest) = trimmed.strip_prefix("mod ") {
            if rest.contains('{') {
                continue;
            }
            if let Some(target) = rest
                .trim_end_matches(';')
                .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                .next()
                .filter(|target| !target.is_empty())
            {
                imports.push(new_import(file_id, target, "mod"));
            }
        }
    }
    imports
}

fn extract_python_imports(file_id: usize, content: &str) -> Vec<ImportFact> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if let Some(target) = trimmed.strip_prefix("import ") {
                return Some(new_import(file_id, target.trim(), "import"));
            }
            if let Some(target) = trimmed.strip_prefix("from ") {
                return target
                    .split_whitespace()
                    .next()
                    .map(|target| new_import(file_id, target, "from"));
            }
            None
        })
        .collect()
}

fn extract_typescript_imports(file_id: usize, content: &str) -> Vec<ImportFact> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("import ") {
                return None;
            }
            let target = trimmed
                .split(" from ")
                .nth(1)
                .unwrap_or(trimmed.trim_start_matches("import "))
                .trim()
                .trim_end_matches(';')
                .trim_matches(['"', '\'']);
            Some(new_import(file_id, target, "import"))
        })
        .collect()
}

/// Generic line-based fallback for languages whose import syntax is
/// `<keyword> some.qualified.name[;]` — Java, Kotlin, Scala, Swift,
/// and (with `using`) C#. Used when the tree-sitter parse fails.
fn extract_jvm_style_imports(file_id: usize, content: &str, keyword: &str) -> Vec<ImportFact> {
    let prefix = format!("{keyword} ");
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let target = trimmed.strip_prefix(&prefix)?;
            // Strip trailing `;`, comments, or whitespace.
            let target = target
                .split(&['/', ';'][..])
                .next()
                .unwrap_or(target)
                .trim()
                .trim_start_matches("static ")
                .trim();
            if target.is_empty() {
                return None;
            }
            Some(new_import(file_id, target, keyword))
        })
        .collect()
}

/// Pull the qualified name out of a JVM-style import node by stripping
/// the leading keyword and trailing punctuation. Tree-sitter grammars
/// disagree on whether the keyword is a separate child or part of the
/// node text, so we work from the raw node text and do a single split.
fn jvm_style_import_target(content: &str, node: Node<'_>, keyword: &str) -> Option<String> {
    let text = node_text(content, node)?;
    let stripped = text.trim_start().strip_prefix(keyword)?.trim();
    let stripped = stripped.strip_prefix("static ").unwrap_or(stripped);
    let target = stripped
        .split(&['/', ';', '\n'][..])
        .next()
        .unwrap_or(stripped)
        .trim();
    if target.is_empty() {
        None
    } else {
        Some(target.to_string())
    }
}

fn extract_ruby_imports(file_id: usize, content: &str) -> Vec<ImportFact> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            for (prefix, kind) in [
                ("require_relative ", "require_relative"),
                ("require ", "require"),
                ("load ", "load"),
            ] {
                if let Some(target) = trimmed.strip_prefix(prefix) {
                    let target = target.trim().trim_matches(['"', '\'']).split('#').next()?;
                    if !target.is_empty() {
                        return Some(new_import(file_id, target.trim(), kind));
                    }
                }
            }
            None
        })
        .collect()
}

fn extract_c_imports(file_id: usize, content: &str) -> Vec<ImportFact> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let target = trimmed.strip_prefix("#include ")?.trim();
            let kind = if target.starts_with('<') {
                "include_system"
            } else {
                "include"
            };
            Some(new_import(file_id, clean_c_include_target(target), kind))
        })
        .collect()
}

fn clean_c_include_target(target: &str) -> &str {
    target
        .trim()
        .trim_matches(['<', '>', '"'])
        .split('"')
        .next()
        .unwrap_or(target)
        .split('>')
        .next()
        .unwrap_or(target)
        .trim()
}

fn new_import(file_id: usize, target: &str, kind: &str) -> ImportFact {
    new_import_with_alias(file_id, target, kind, None)
}

fn new_import_with_alias(
    file_id: usize,
    target: &str,
    kind: &str,
    alias: Option<String>,
) -> ImportFact {
    ImportFact {
        import_id: 0,
        from_file: file_id,
        target: target.to_string(),
        kind: kind.to_string(),
        resolution: ImportResolution::Unresolved,
        resolved_file: None,
        alias,
    }
}

/// Emit `TypeFact`s for type/class/interface declarations. Uses the plugin's
/// `abstract_type_prefixes` and `concrete_type_prefixes` for line matching, and
/// falls back to built-in heuristics for Rust/TS/Python/C-like languages.
fn extract_types(
    file_id: usize,
    file: &FileFact,
    content: &str,
    plugin: Option<&LanguagePluginConfig>,
) -> Vec<TypeFact> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let clean = line.split("//").next().unwrap_or(line).trim();
        if clean.is_empty()
            || clean.starts_with('#')
            || clean.starts_with('*')
            || clean.starts_with("/*")
        {
            continue;
        }
        let configured_abstract = plugin.is_some_and(|plugin| {
            plugin
                .abstract_type_prefixes
                .iter()
                .any(|prefix| !prefix.is_empty() && clean.starts_with(prefix))
        });
        let configured_concrete = plugin.is_some_and(|plugin| {
            plugin
                .concrete_type_prefixes
                .iter()
                .any(|prefix| !prefix.is_empty() && clean.starts_with(prefix))
        });
        let builtin_abstract =
            crate::health::is_abstract_type_line(clean, file.language_name.as_str());
        let builtin_concrete =
            crate::health::is_concrete_type_line(clean, file.language_name.as_str());
        let is_abstract = configured_abstract || builtin_abstract;
        let is_type = is_abstract || configured_concrete || builtin_concrete;
        if !is_type {
            continue;
        }
        let name = type_name_from_line(clean).unwrap_or_default();
        let bases = extract_base_class_names(clean);
        let abstract_by_base = plugin.is_some_and(|plugin| {
            !plugin.abstract_base_classes.is_empty()
                && bases.iter().any(|base| {
                    plugin
                        .abstract_base_classes
                        .iter()
                        .any(|known| known == base)
                })
        });
        out.push(TypeFact {
            type_id: 0,
            file_id,
            name,
            is_abstract: is_abstract || abstract_by_base,
            line: idx + 1,
            bases,
            visibility: Visibility::default(),
        });
    }
    out
}

/// Generic base-class parser. Handles four common shapes that put
/// inheritance on the same line as the type name:
///   `class Foo extends Bar implements Baz, Qux` (Java/Kotlin/TS/JS)
///   `class Foo with Bar with Baz` (Scala — also extends/with)
///   `class Foo : public Bar, virtual Baz` (C++/C#)
///   `class Foo(Bar, Baz):` (Python)
/// Returns identifiers stripped of access keywords (`public`, `virtual`,
/// `protected`, `private`).
/// Tree-sitter-driven type extraction for languages where the grammar
/// carries inheritance directly on the class node. When tree-sitter rejects
/// the file (parse error, unknown grammar) the caller falls back to the
/// line-based parser. Returns `None` to mean "no tree available — use the
/// line parser instead."
fn extract_tree_sitter_types(
    file_id: usize,
    content: &str,
    language: Language,
) -> Option<Vec<TypeFact>> {
    let ts_language = match language {
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::Kotlin => tree_sitter_kotlin_ng::LANGUAGE.into(),
        Language::Scala => tree_sitter_scala::LANGUAGE.into(),
        Language::Swift => tree_sitter_swift::LANGUAGE.into(),
        Language::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        _ => return None,
    };
    let mut parser = Parser::new();
    parser.set_language(&ts_language).ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let mut out = Vec::new();
    collect_tree_sitter_types(file_id, content, root, &mut out);
    Some(out)
}

/// Extract `impl Trait for Type` style relationships from a source file.
/// Currently dispatches via tree-sitter for Rust; other languages return
/// an empty vector until their grammar dispatch is added (Swift
/// `extension Foo: Bar` is the obvious next candidate).
fn extract_trait_impls(file_id: usize, content: &str, language: Language) -> Vec<TraitImplFact> {
    match language {
        Language::Rust => extract_rust_trait_impls(file_id, content).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn extract_rust_trait_impls(file_id: usize, content: &str) -> Option<Vec<TraitImplFact>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(content, None)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let mut out = Vec::new();
    collect_rust_trait_impls(file_id, content, root, &mut out);
    Some(out)
}

fn collect_rust_trait_impls(
    file_id: usize,
    content: &str,
    node: Node<'_>,
    out: &mut Vec<TraitImplFact>,
) {
    if node.kind() == "impl_item" {
        if let Some(trait_node) = node.child_by_field_name("trait") {
            if let Some(type_node) = node.child_by_field_name("type") {
                let trait_name = rust_impl_target_name(content, trait_node);
                let type_name = rust_impl_target_name(content, type_node);
                if let (Some(trait_name), Some(type_name)) = (trait_name, type_name) {
                    let generic_params = rust_impl_generic_param_names(content, node);
                    if !generic_params.contains(&type_name) {
                        out.push(TraitImplFact {
                            impl_id: 0,
                            file_id,
                            type_name,
                            trait_name,
                            line: node.start_position().row + 1,
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_trait_impls(file_id, content, child, out);
    }
}

/// Resolve the head identifier name of an `impl_item`'s `trait` or
/// `type` field. Walks `generic_type` / `scoped_type_identifier` /
/// `reference_type` wrappers; returns `None` for primitives or shapes
/// the grammar didn't tag with a name we can recover.
fn rust_impl_target_name(content: &str, node: Node<'_>) -> Option<String> {
    match node.kind() {
        "type_identifier" => node_text(content, node),
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(|inner| rust_impl_target_name(content, inner)),
        "scoped_type_identifier" => node
            .child_by_field_name("name")
            .and_then(|inner| node_text(content, inner)),
        "reference_type" => node
            .child_by_field_name("type")
            .and_then(|inner| rust_impl_target_name(content, inner)),
        // Primitive targets (`&str`, `[u8]`) and tuples: skip -- no
        // matching `TypeFact` exists for them anywhere in the report.
        _ => None,
    }
}

/// Names of generic type parameters declared on an `impl_item`, used to
/// filter out blanket impls (`impl<T> Foo for T`) where the implementer
/// position is just a parameter and would otherwise pollute the
/// inheritance graph with phantom relationships.
fn rust_impl_generic_param_names(content: &str, impl_node: Node<'_>) -> Vec<String> {
    let Some(params) = impl_node.child_by_field_name("type_parameters") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = params.walk();
    for child in params.children(&mut cursor) {
        if child.kind() == "type_parameter" {
            if let Some(name) = child
                .child_by_field_name("name")
                .or_else(|| child.named_child(0))
            {
                if let Some(text) = node_text(content, name) {
                    names.push(text);
                }
            }
        }
    }
    names
}

fn collect_tree_sitter_types(
    file_id: usize,
    content: &str,
    node: Node<'_>,
    out: &mut Vec<TypeFact>,
) {
    let kind = node.kind();
    let is_class = matches!(
        kind,
        // Python, Scala
        "class_definition"
            // TypeScript, Java, C#, Kotlin, Swift
            | "class_declaration"
            // C++
            | "class_specifier"
            | "struct_specifier"
            // Java, C#
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            // C#
            | "struct_declaration"
            // Kotlin, Scala
            | "object_declaration"
            | "object_definition"
            | "trait_definition"
            // Swift
            | "protocol_declaration"
            // Ruby
            | "class"
            | "module"
    );
    if is_class {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| node_text(content, n))
            .unwrap_or_default();
        if !name.is_empty() {
            let bases = base_classes_from_class_node(content, node);
            out.push(TypeFact {
                type_id: 0,
                file_id,
                name,
                is_abstract: false,
                line: node.start_position().row + 1,
                bases,
                visibility: Visibility::default(),
            });
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_tree_sitter_types(file_id, content, child, out);
    }
}

fn base_classes_from_class_node(content: &str, node: Node<'_>) -> Vec<String> {
    let mut bases = Vec::new();
    if let Some(superclasses) = node.child_by_field_name("superclasses") {
        // Python: `class Foo(Bar, Baz):` — `superclasses` is the argument_list.
        let mut cursor = superclasses.walk();
        for child in superclasses.children(&mut cursor) {
            if matches!(child.kind(), "identifier" | "attribute") {
                if let Some(text) = node_text(content, child) {
                    bases.push(text);
                }
            }
        }
    }
    if let Some(superclass) = node.child_by_field_name("superclass") {
        // Java: `class Foo extends Bar` — `superclass` field holds a single
        // type. Ruby: `class Foo < Bar` — same shape.
        collect_type_identifiers(content, superclass, &mut bases);
    }
    if let Some(supers) = node.child_by_field_name("interfaces") {
        // Java: `class Foo implements Baz, Qux` — `interfaces` field
        // (the rule named `super_interfaces` is bound to field `interfaces`).
        collect_type_identifiers(content, supers, &mut bases);
    }
    if let Some(bases_node) = node.child_by_field_name("bases") {
        // C#: `class Foo : Bar, IBaz` — `bases` field is a `base_list`.
        collect_type_identifiers(content, bases_node, &mut bases);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_heritage" => {
                // TypeScript: `class Foo extends Bar implements Baz, Qux {}`.
                let mut hcursor = child.walk();
                for clause in child.children(&mut hcursor) {
                    let mut ccursor = clause.walk();
                    for sub in clause.children(&mut ccursor) {
                        if matches!(sub.kind(), "identifier" | "type_identifier") {
                            if let Some(text) = node_text(content, sub) {
                                bases.push(text);
                            }
                        }
                    }
                }
            }
            "base_class_clause" => {
                // C++: `class Derived : public Base, protected IFace { ... }`.
                let mut ccursor = child.walk();
                for sub in child.children(&mut ccursor) {
                    if matches!(sub.kind(), "type_identifier" | "qualified_identifier") {
                        if let Some(text) = node_text(content, sub) {
                            bases.push(text);
                        }
                    }
                }
            }
            "base_list" => {
                // C# fallback when `bases` field is absent on some nodes.
                collect_type_identifiers(content, child, &mut bases);
            }
            "delegation_specifiers" | "delegation_specifier" => {
                // Kotlin: `class Foo : Bar(), Baz` — delegation_specifiers
                // holds delegation_specifier children that may wrap
                // user_type → type_identifier.
                collect_type_identifiers(content, child, &mut bases);
            }
            "extends_clause" | "with_clause" => {
                // Scala: `class Foo extends Bar with Baz with Qux` —
                // each clause carries the type identifiers.
                collect_type_identifiers(content, child, &mut bases);
            }
            "type_inheritance_clause" | "inheritance_clause" | "inheritance_specifier" => {
                // Swift: `class Foo: Bar, BazProtocol` — each inheritance
                // entry is a direct `inheritance_specifier` child of the
                // class_declaration.
                collect_type_identifiers(content, child, &mut bases);
            }
            _ => {}
        }
    }
    bases.sort();
    bases.dedup();
    bases
}

/// Recursively pull type identifiers out of a heritage subtree. Tree-sitter
/// grammars wrap the actual identifier in language-specific nodes (e.g.
/// Kotlin's `user_type` → `type_identifier`, Swift's `inheritance_specifier`
/// → `user_type` → `type_identifier`), so a flat scan is the most portable.
fn collect_type_identifiers(content: &str, node: Node<'_>, out: &mut Vec<String>) {
    if matches!(
        node.kind(),
        "type_identifier"
            | "identifier"
            | "qualified_identifier"
            | "scoped_identifier"
            // Ruby uses `constant` for capitalized class names.
            | "constant"
            | "scope_resolution"
    ) {
        if let Some(text) = node_text(content, node) {
            out.push(text);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_type_identifiers(content, child, out);
    }
}

/// When tree-sitter produces type facts, prefer them over the line-based
/// ones for matching `(name, line)` and merge their bases. Carry over
/// `is_abstract` from the line parser since it knows about plugin-configured
/// abstract markers and bases.
fn merge_tree_sitter_types_with_line_types(
    ts_types: Option<Vec<TypeFact>>,
    line_types: Vec<TypeFact>,
    plugin: Option<&LanguagePluginConfig>,
) -> Vec<TypeFact> {
    let Some(ts_types) = ts_types else {
        return line_types;
    };
    let mut out = ts_types;
    for ts_type in &mut out {
        let abstract_by_base = plugin.is_some_and(|plugin| {
            !plugin.abstract_base_classes.is_empty()
                && ts_type.bases.iter().any(|base| {
                    plugin
                        .abstract_base_classes
                        .iter()
                        .any(|known| known == base)
                })
        });
        if abstract_by_base {
            ts_type.is_abstract = true;
        }
        if let Some(line_match) = line_types
            .iter()
            .find(|t| t.name == ts_type.name && t.line == ts_type.line)
        {
            ts_type.is_abstract = ts_type.is_abstract || line_match.is_abstract;
            for base in &line_match.bases {
                if !ts_type.bases.contains(base) {
                    ts_type.bases.push(base.clone());
                }
            }
        }
    }
    out
}

fn extract_base_class_names(line: &str) -> Vec<String> {
    const TERMINATORS: &[char] = &['{', ';', '\n'];
    const STOP_KEYWORDS: &[&str] = &[" extends ", " implements ", " with "];

    let mut bases: Vec<String> = Vec::new();

    if let Some(start) = line.find('(') {
        if let Some(end_rel) = line[start..].find(')') {
            for token in split_base_tokens(&line[start + 1..start + end_rel]) {
                bases.push(token);
            }
        }
    }

    for keyword in STOP_KEYWORDS {
        let mut cursor = 0;
        while let Some(idx) = line[cursor..].find(keyword) {
            let after = &line[cursor + idx + keyword.len()..];
            let mut segment_end = after.find(TERMINATORS).unwrap_or(after.len());
            for other in STOP_KEYWORDS {
                if let Some(other_idx) = after.find(other) {
                    if other_idx < segment_end {
                        segment_end = other_idx;
                    }
                }
            }
            for token in split_base_tokens(&after[..segment_end]) {
                bases.push(token);
            }
            cursor += idx + keyword.len() + segment_end;
        }
    }

    if let Some(colon) = line.find(':') {
        let leading = &line[..colon];
        let looks_like_class = leading.contains("class ") || leading.contains("struct ");
        if looks_like_class && !leading.contains('(') {
            let after = &line[colon + 1..];
            let segment_end = after.find(TERMINATORS).unwrap_or(after.len());
            for token in split_base_tokens(&after[..segment_end]) {
                bases.push(token);
            }
        }
    }

    bases.retain(|name| !name.is_empty());
    bases.sort();
    bases.dedup();
    bases
}

fn split_base_tokens(segment: &str) -> Vec<String> {
    segment
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| {
            let mut words: Vec<&str> = item
                .split_whitespace()
                .filter(|word| {
                    !matches!(
                        *word,
                        "public" | "protected" | "private" | "virtual" | "static" | "final"
                    )
                })
                .collect();
            if words.is_empty() {
                String::new()
            } else {
                let last = words.pop().unwrap();
                last.trim_end_matches([',', ';', '{']).to_string()
            }
        })
        .filter(|name| !name.is_empty())
        .collect()
}

fn type_name_from_line(line: &str) -> Option<String> {
    let mut iter = line.split_whitespace();
    let mut leading = iter.next()?;
    while matches!(
        leading,
        "pub" | "public" | "abstract" | "static" | "export" | "default"
    ) {
        leading = iter.next()?;
    }
    let _kind = leading;
    let name = iter.next()?;
    let name = name
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or(name);
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Build per-language alias rewrite rules by reading each plugin's
/// `resolver_alias_files`. Supports JSON files with either a top-level
/// `paths` object, a `compilerOptions.paths` object (tsconfig style), or a
/// flat string-to-string map. Files that fail to read or parse are silently
/// skipped — alias support is best-effort and never aborts a scan.
fn build_alias_map(root: &Path, config: &RaysenseConfig) -> HashMap<String, Vec<(String, String)>> {
    let mut map: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for plugin in &config.scan.plugins {
        if plugin.resolver_alias_files.is_empty() {
            continue;
        }
        let mut rules = Vec::new();
        for alias_file in &plugin.resolver_alias_files {
            rules.extend(read_alias_file(&root.join(alias_file)));
        }
        if !rules.is_empty() {
            map.entry(plugin.name.clone()).or_default().extend(rules);
        }
    }
    map
}

fn read_alias_file(path: &Path) -> Vec<(String, String)> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    if let Some(paths) = value.get("compilerOptions").and_then(|v| v.get("paths")) {
        return extract_alias_paths(paths);
    }
    if let Some(paths) = value.get("paths") {
        return extract_alias_paths(paths);
    }
    if let Some(obj) = value.as_object() {
        return obj
            .iter()
            .filter_map(|(key, value)| value.as_str().map(|s| (key.clone(), s.to_string())))
            .collect();
    }
    Vec::new()
}

fn extract_alias_paths(value: &serde_json::Value) -> Vec<(String, String)> {
    let Some(obj) = value.as_object() else {
        return Vec::new();
    };
    obj.iter()
        .filter_map(|(key, value)| {
            let target = if let Some(arr) = value.as_array() {
                arr.iter().find_map(|item| item.as_str())?.to_string()
            } else if let Some(s) = value.as_str() {
                s.to_string()
            } else {
                return None;
            };
            Some((key.clone(), target))
        })
        .collect()
}

fn apply_alias_rewrites(
    imports: &mut [ImportFact],
    files: &[FileFact],
    aliases: &HashMap<String, Vec<(String, String)>>,
) {
    if aliases.is_empty() {
        return;
    }
    let lang_by_file: HashMap<usize, &str> = files
        .iter()
        .map(|file| (file.file_id, file.language_name.as_str()))
        .collect();
    for import in imports {
        let Some(language) = lang_by_file.get(&import.from_file) else {
            continue;
        };
        let Some(rules) = aliases.get(*language) else {
            continue;
        };
        if let Some(rewritten) = rewrite_alias(&import.target, rules) {
            import.target = rewritten;
        }
    }
}

fn rewrite_alias(target: &str, rules: &[(String, String)]) -> Option<String> {
    for (pattern, replacement) in rules {
        if let Some(rest) = match_alias(target, pattern) {
            return Some(apply_alias_replacement(replacement, &rest));
        }
    }
    None
}

fn match_alias(target: &str, pattern: &str) -> Option<String> {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        if let Some(rest) = target.strip_prefix(prefix) {
            return Some(rest.trim_start_matches('/').to_string());
        }
        return None;
    }
    if pattern == target {
        return Some(String::new());
    }
    None
}

fn apply_alias_replacement(replacement: &str, suffix: &str) -> String {
    if let Some(prefix) = replacement.strip_suffix("/*") {
        if suffix.is_empty() {
            prefix.to_string()
        } else {
            format!("{}/{}", prefix.trim_end_matches('/'), suffix)
        }
    } else {
        replacement.to_string()
    }
}

fn resolve_imports(files: &[FileFact], imports: &mut [ImportFact], config: &RaysenseConfig) {
    let mut by_path = HashMap::new();
    let mut by_module = HashMap::new();
    let profile = ProjectProfile::infer(files);

    for file in files {
        by_path.insert(normalize_path(&file.path), file.file_id);
        by_module.entry(file.module.clone()).or_insert(file.file_id);
    }

    let file_by_id: HashMap<usize, &FileFact> =
        files.iter().map(|file| (file.file_id, file)).collect();

    for import in imports {
        let Some(from_file) = file_by_id.get(&import.from_file).copied() else {
            continue;
        };
        import.resolved_file = resolve_import(
            from_file,
            import,
            &by_path,
            &by_module,
            &profile.include_roots,
            config,
        );
        import.resolution = classify_import(from_file, import, config);
    }
}

fn resolve_call_edges(
    files: &[FileFact],
    functions: &[FunctionFact],
    calls: &[CallFact],
) -> Vec<CallEdgeFact> {
    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for function in functions {
        by_name
            .entry(function.name.as_str())
            .or_default()
            .push(function.function_id);
    }

    let mut edges = Vec::new();
    for call in calls {
        let Some(caller_function) = call.caller_function else {
            continue;
        };
        let Some(callees) = by_name.get(call.target.as_str()) else {
            continue;
        };
        let Some(callee_function) = resolve_call_target(files, functions, caller_function, callees)
        else {
            continue;
        };
        edges.push(CallEdgeFact {
            edge_id: edges.len(),
            call_id: call.call_id,
            caller_function,
            callee_function,
        });
    }
    edges
}

fn resolve_call_target(
    files: &[FileFact],
    functions: &[FunctionFact],
    caller_function: usize,
    candidates: &[usize],
) -> Option<usize> {
    if candidates.is_empty() {
        return None;
    }

    let caller = functions.get(caller_function)?;
    unique_candidate(candidates.iter().copied().filter(|candidate| {
        functions
            .get(*candidate)
            .is_some_and(|function| function.file_id == caller.file_id)
    }))
    .or_else(|| {
        let caller_file = files.get(caller.file_id)?;
        unique_candidate(candidates.iter().copied().filter(|candidate| {
            let Some(function) = functions.get(*candidate) else {
                return false;
            };
            let Some(file) = files.get(function.file_id) else {
                return false;
            };
            top_path_component(&file.path) == top_path_component(&caller_file.path)
        }))
    })
    .or_else(|| unique_candidate(candidates.iter().copied()))
}

fn unique_candidate(candidates: impl IntoIterator<Item = usize>) -> Option<usize> {
    let mut iter = candidates.into_iter();
    let first = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    Some(first)
}

fn top_path_component(path: &Path) -> String {
    path.components()
        .find_map(component_to_string)
        .unwrap_or_default()
}

fn classify_import(
    from_file: &FileFact,
    import: &ImportFact,
    config: &RaysenseConfig,
) -> ImportResolution {
    if import.resolved_file.is_some() {
        return ImportResolution::Local;
    }
    if plugin_by_language_name(&from_file.language_name, config).is_some_and(|plugin| {
        plugin
            .local_import_prefixes
            .iter()
            .any(|prefix| !prefix.is_empty() && import.target.starts_with(prefix))
    }) {
        return ImportResolution::Unresolved;
    }

    match from_file.language {
        Language::C | Language::Cpp if import.kind == "include_system" => ImportResolution::System,
        Language::Rust
            if import.target.starts_with("super::") || import.target.starts_with("self::") =>
        {
            ImportResolution::Local
        }
        Language::Rust if rust_target_is_local(&import.target) => ImportResolution::Unresolved,
        Language::TypeScript if import.target.starts_with('.') => ImportResolution::Unresolved,
        Language::Python if import.target.starts_with('.') => ImportResolution::Unresolved,
        Language::C | Language::Cpp if import.kind == "include" => ImportResolution::Unresolved,
        _ => ImportResolution::External,
    }
}

fn resolve_import(
    from_file: &FileFact,
    import: &ImportFact,
    by_path: &HashMap<String, usize>,
    by_module: &HashMap<String, usize>,
    include_roots: &[PathBuf],
    config: &RaysenseConfig,
) -> Option<usize> {
    let candidates = import_candidates(from_file, import, include_roots, config);
    candidates
        .iter()
        .find_map(|candidate| by_path.get(candidate).copied())
        .or_else(|| {
            module_candidate(&import.target).and_then(|module| by_module.get(&module).copied())
        })
}

fn import_candidates(
    from_file: &FileFact,
    import: &ImportFact,
    include_roots: &[PathBuf],
    config: &RaysenseConfig,
) -> Vec<String> {
    match from_file.language {
        Language::Rust => rust_import_candidates(&from_file.path, &import.target),
        Language::Python => python_import_candidates(&import.target),
        Language::TypeScript => typescript_import_candidates(&from_file.path, &import.target),
        Language::C | Language::Cpp => {
            c_import_candidates(&from_file.path, &import.target, include_roots)
        }
        Language::Rayfall => rayfall_import_candidates(&from_file.path, &import.target),
        Language::Java
        | Language::CSharp
        | Language::Kotlin
        | Language::Scala
        | Language::Swift
        | Language::Ruby
        | Language::Unknown => plugin_import_candidates(from_file, import, config),
    }
}

/// Rayfall imports are bare filesystem path strings (e.g. `"./helper.rfl"`,
/// `"/tmp/data.csv"`, `"/var/db/trades/"`). Resolve `./` and `../` against
/// the importing file's directory; pass everything else through. Trailing
/// slashes (splayed/parted directory mounts) survive so the resolver can
/// match a directory entry.
fn rayfall_import_candidates(from_path: &Path, target: &str) -> Vec<String> {
    let raw = target.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    if raw.starts_with("./") || raw.starts_with("../") {
        if let Some(base) = relative_base(from_path, raw) {
            candidates.push(normalize_path(base));
        }
    }
    candidates.push(raw.trim_start_matches('/').to_string());
    candidates
}

fn plugin_import_candidates(
    from_file: &FileFact,
    import: &ImportFact,
    config: &RaysenseConfig,
) -> Vec<String> {
    let Some(plugin) = plugin_by_language_name(&from_file.language_name, config) else {
        return Vec::new();
    };
    let separator = plugin.namespace_separator.as_deref().unwrap_or(".");
    let raw = import.target.trim().trim_matches(['"', '\'', ';']);
    let target: String = if separator.is_empty() {
        raw.to_string()
    } else {
        raw.split(separator).collect::<Vec<_>>().join("/")
    };
    if target.is_empty() {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    let base_paths = if import.target.starts_with('.') {
        relative_base(&from_file.path, &import.target)
            .map(|path| vec![normalize_path(path)])
            .unwrap_or_default()
    } else {
        let mut paths = vec![target.clone()];
        paths.extend(
            plugin
                .source_roots
                .iter()
                .map(|root| format!("{}/{}", root.trim_matches('/'), target)),
        );
        paths
    };
    for base in base_paths {
        if has_known_extension_vec(&base, &plugin.extensions) {
            candidates.push(base.clone());
        } else {
            candidates.extend(
                plugin
                    .extensions
                    .iter()
                    .map(|ext| format!("{base}.{}", ext.trim_start_matches('.'))),
            );
        }
        candidates.extend(
            plugin
                .package_index_files
                .iter()
                .map(|index| format!("{base}/{index}")),
        );
        candidates.extend(
            plugin
                .module_prefix_files
                .iter()
                .map(|prefix| format!("{base}/{prefix}")),
        );
    }
    candidates
}

fn rust_import_candidates(from_path: &Path, target: &str) -> Vec<String> {
    if !rust_target_is_local(target) {
        return Vec::new();
    }

    let target = normalize_rust_target(target);
    let mut candidates = Vec::new();

    for prefix in rust_module_prefixes(&target) {
        candidates.push(format!("{prefix}.rs"));
        candidates.push(format!("{prefix}/mod.rs"));
        candidates.push(format!("src/{prefix}.rs"));
        candidates.push(format!("src/{prefix}/mod.rs"));

        if let Some(crate_src) = rust_crate_src_dir(from_path) {
            candidates.push(normalize_path(crate_src.join(format!("{prefix}.rs"))));
            candidates.push(normalize_path(crate_src.join(format!("{prefix}/mod.rs"))));
        }
    }

    candidates
}

fn rust_target_is_local(target: &str) -> bool {
    let target = target.trim();
    target.starts_with("crate::")
        || target.starts_with("self::")
        || target.starts_with("super::")
        || target == "super"
        || target == "self"
        || !target.contains("::")
}

fn normalize_rust_target(target: &str) -> String {
    strip_rust_prefix(target)
        .split("::")
        .filter(|segment| {
            !segment.is_empty()
                && *segment != "self"
                && *segment != "super"
                && *segment != "*"
                && !segment.starts_with('{')
        })
        .map(|segment| segment.split('{').next().unwrap_or(segment))
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn strip_rust_prefix(target: &str) -> &str {
    target
        .trim()
        .trim_end_matches(';')
        .trim_start_matches("crate::")
        .trim_start_matches("self::")
        .trim_start_matches("super::")
}

fn rust_module_prefixes(target: &str) -> Vec<String> {
    let parts: Vec<&str> = target.split('/').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return Vec::new();
    }

    (1..=parts.len())
        .rev()
        .map(|n| parts[..n].join("/"))
        .collect()
}

fn rust_crate_src_dir(from_path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in from_path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        out.push(part);
        if part == "src" {
            return Some(out);
        }
    }
    None
}

fn python_import_candidates(target: &str) -> Vec<String> {
    let target = target.replace('.', "/");
    vec![format!("{target}.py"), format!("{target}/__init__.py")]
}

fn typescript_import_candidates(from_path: &Path, target: &str) -> Vec<String> {
    let Some(base) = relative_base(from_path, target) else {
        return Vec::new();
    };
    let base = normalize_path(&base);
    let extensions = ["ts", "tsx", "js", "jsx"];
    let mut candidates = Vec::new();

    if has_known_extension(&base, &extensions) {
        candidates.push(base.clone());
    } else {
        candidates.extend(extensions.iter().map(|ext| format!("{base}.{ext}")));
    }
    candidates.extend(extensions.iter().map(|ext| format!("{base}/index.{ext}")));
    candidates
}

fn c_import_candidates(from_path: &Path, target: &str, include_roots: &[PathBuf]) -> Vec<String> {
    if target.starts_with('<') {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let parent = from_path.parent().unwrap_or_else(|| Path::new(""));
    candidates.push(normalize_path(normalize_components(parent.join(target))));
    candidates.push(target.replace('\\', "/"));
    candidates.extend(
        include_roots
            .iter()
            .map(|root| normalize_path(normalize_components(root.join(target)))),
    );
    candidates
}

fn module_candidate(target: &str) -> Option<String> {
    let target = target
        .trim()
        .trim_start_matches("crate::")
        .trim_start_matches("self::")
        .trim_start_matches("super::")
        .trim_start_matches("./")
        .trim_matches(['"', '\'']);
    if target.starts_with("../") || target.starts_with('/') || target.starts_with('@') {
        return None;
    }
    Some(
        target
            .replace("::", ".")
            .replace('/', ".")
            .split('{')
            .next()
            .unwrap_or(target)
            .trim_matches('.')
            .to_string(),
    )
    .filter(|target| !target.is_empty())
}

fn relative_base(from_path: &Path, target: &str) -> Option<PathBuf> {
    let target_path = Path::new(target);
    if !target.starts_with('.') {
        return Some(target_path.to_path_buf());
    }

    let parent = from_path.parent().unwrap_or_else(|| Path::new(""));
    Some(normalize_components(parent.join(target_path)))
}

fn normalize_components(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(part) => out.push(part),
            Component::RootDir | Component::Prefix(_) => {}
        }
    }
    out
}

fn normalize_path(path: impl AsRef<Path>) -> String {
    path.as_ref().to_string_lossy().replace('\\', "/")
}

fn has_known_extension(path: &str, extensions: &[&str]) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| extensions.contains(&ext))
}

fn has_known_extension_vec(path: &str, extensions: &[String]) -> bool {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            extensions
                .iter()
                .any(|candidate| candidate.trim_start_matches('.').eq_ignore_ascii_case(ext))
        })
}

fn component_to_string(component: Component<'_>) -> Option<String> {
    match component {
        Component::Normal(value) => value.to_str().map(ToOwned::to_owned),
        _ => None,
    }
}

fn is_test_path_profile(path: &str, plugin: Option<&LanguagePluginConfig>) -> bool {
    is_test_path(path)
        || plugin.is_some_and(|plugin| {
            plugin
                .test_path_patterns
                .iter()
                .any(|pattern| path_matches_pattern(path, pattern))
        })
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let pattern = pattern.trim().trim_matches('/');
    if pattern.is_empty() {
        return false;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }
    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
        return path.contains(pattern.trim_matches('*'));
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return path.ends_with(suffix) || path.contains(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix) || path.contains(prefix);
    }
    path == pattern || path.ends_with(&format!("/{pattern}"))
}

fn is_test_path(path: &str) -> bool {
    path.starts_with("test/")
        || path.starts_with("tests/")
        || path.contains("/test/")
        || path.contains("/tests/")
        || path.contains("_test.")
        || path.contains("_tests.")
}

const RAYFALL_IMPORT_PREFIXES: &[&str] = &[
    "(read ",
    "(load ",
    "(.csv.read ",
    "(.csv.write ",
    "(.db.splayed.get ",
    "(.db.splayed.mount ",
    "(.db.splayed.set ",
    "(.db.parted.get ",
    "(.db.parted.mount ",
    "(hnsw-load ",
    "(hnsw-save ",
];

fn is_rayfall_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '_' | '-' | '?' | '!' | '*' | '+' | '/' | '<' | '>' | '=' | '%' | '.'
        )
}

fn rayfall_ws(s: &str) -> &str {
    s.trim_start_matches(|c: char| c == ' ' || c == '\t')
}

/// If `line[pos..]` looks like `(set IDENT (HEAD …` where HEAD is one of
/// `forms`, return the identifier and the absolute column where `(HEAD`
/// begins. Whitespace between tokens is permitted; the form's body need
/// not be on the same line beyond `(HEAD`.
fn parse_rayfall_set_form<'a>(
    line: &str,
    pos: usize,
    forms: &'a [&str],
) -> Option<(String, &'a str, usize)> {
    let after_set = line.get(pos..)?.strip_prefix("(set")?;
    if !after_set
        .chars()
        .next()
        .is_some_and(|c| c == ' ' || c == '\t')
    {
        return None;
    }
    let after_ws1 = rayfall_ws(after_set);
    let id_end = after_ws1
        .find(|c: char| !is_rayfall_ident_char(c))
        .unwrap_or(after_ws1.len());
    if id_end == 0 {
        return None;
    }
    let name = &after_ws1[..id_end];
    let after_id = &after_ws1[id_end..];
    if !after_id
        .chars()
        .next()
        .is_some_and(|c| c == ' ' || c == '\t')
    {
        return None;
    }
    let after_ws2 = rayfall_ws(after_id);
    let head_pos = pos + (line.len() - pos - after_ws2.len());
    for form in forms {
        let opener = format!("({form}");
        if let Some(after_form) = after_ws2.strip_prefix(opener.as_str()) {
            let next = after_form.chars().next();
            if matches!(
                next,
                Some(' ') | Some('\t') | Some('[') | Some('(') | Some('\n')
            ) || next.is_none()
            {
                return Some((name.to_string(), form, head_pos));
            }
        }
    }
    None
}

/// Walk the source from `(start, col)` and return the 1-indexed line where
/// the opening paren at that position is closed. Honors `;` line comments
/// and `"` string literals so embedded parens don't confuse the counter.
fn rayfall_form_end_line(lines: &[&str], start: usize, col: usize) -> usize {
    let mut depth: i32 = 0;
    let mut started = false;
    let mut in_string = false;
    for (i, line) in lines.iter().enumerate().skip(start) {
        let from = if i == start { col } else { 0 };
        let mut chars = line[from..].chars();
        while let Some(ch) = chars.next() {
            if in_string {
                if ch == '\\' {
                    chars.next();
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            match ch {
                '"' => in_string = true,
                ';' => break,
                '(' => {
                    depth += 1;
                    started = true;
                }
                ')' => {
                    depth -= 1;
                    if started && depth <= 0 {
                        return i + 1;
                    }
                }
                _ => {}
            }
        }
    }
    lines.len().max(start + 1)
}

fn extract_rayfall_functions(file_id: usize, content: &str) -> Vec<FunctionFact> {
    let lines: Vec<&str> = content.lines().collect();
    let mut functions = Vec::new();
    let mut named_lambda_positions: std::collections::HashSet<(usize, usize)> =
        std::collections::HashSet::new();

    for (idx, line) in lines.iter().enumerate() {
        let mut from = 0;
        while let Some(rel) = line[from..].find("(set ") {
            let pos = from + rel;
            if let Some((name, _form, fn_pos)) = parse_rayfall_set_form(line, pos, &["fn"]) {
                let end_line = rayfall_form_end_line(&lines, idx, pos);
                functions.push(FunctionFact {
                    function_id: 0,
                    file_id,
                    name,
                    start_line: idx + 1,
                    end_line,
                    visibility: Visibility::default(),
                });
                named_lambda_positions.insert((idx, fn_pos));
                from = fn_pos.max(pos + 1);
            } else {
                from = pos + 1;
            }
        }
    }

    for (idx, line) in lines.iter().enumerate() {
        let mut from = 0;
        while let Some(rel) = line[from..].find("(fn") {
            let pos = from + rel;
            let after = &line[pos + 3..];
            let valid_terminator = after
                .chars()
                .next()
                .map(|c| c == ' ' || c == '\t' || c == '[' || c == '(')
                .unwrap_or(false);
            if !valid_terminator {
                from = pos + 1;
                continue;
            }
            if !named_lambda_positions.contains(&(idx, pos)) {
                let end_line = rayfall_form_end_line(&lines, idx, pos);
                functions.push(FunctionFact {
                    function_id: 0,
                    file_id,
                    name: format!("lambda@{}", idx + 1),
                    start_line: idx + 1,
                    end_line,
                    visibility: Visibility::default(),
                });
            }
            from = pos + 3;
        }
    }

    functions.sort_by_key(|f| (f.start_line, f.name.clone()));
    functions
}

fn rayfall_first_string_literal(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let mut out = String::new();
    let mut chars = s[start + 1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            '"' => return Some(out),
            _ => out.push(c),
        }
    }
    None
}

fn extract_rayfall_imports(file_id: usize, content: &str) -> Vec<ImportFact> {
    let mut imports = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim_start();
        for prefix in RAYFALL_IMPORT_PREFIXES {
            let Some(rest) = trimmed.strip_prefix(prefix) else {
                continue;
            };
            let Some(target) = rayfall_first_string_literal(rest) else {
                break;
            };
            let kind = prefix.trim_start_matches('(').trim().to_string();
            imports.push(ImportFact {
                import_id: 0,
                from_file: file_id,
                target,
                kind,
                resolution: ImportResolution::Unresolved,
                resolved_file: None,
                alias: None,
            });
            break;
        }
    }
    imports
}

fn extract_rayfall_calls(
    _file_id: usize,
    _content: &str,
    _functions: &[FunctionFact],
) -> Vec<CallFact> {
    Vec::new()
}

fn extract_rayfall_types(file_id: usize, content: &str) -> Vec<TypeFact> {
    let lines: Vec<&str> = content.lines().collect();
    let mut types = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let mut from = 0;
        while let Some(rel) = line[from..].find("(set ") {
            let pos = from + rel;
            if let Some((name, _form, _head_pos)) =
                parse_rayfall_set_form(line, pos, &["table", "dict"])
            {
                types.push(TypeFact {
                    type_id: 0,
                    file_id,
                    name,
                    is_abstract: false,
                    line: idx + 1,
                    bases: Vec::new(),
                    visibility: Visibility::default(),
                });
                from = pos + 5;
            } else {
                from = pos + 1;
            }
        }
    }
    types
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn default_ignored_skips_build_artifact_dirs_at_any_depth() {
        // Top-level matches.
        assert!(is_default_ignored(Path::new("target")));
        assert!(is_default_ignored(Path::new("node_modules")));
        assert!(is_default_ignored(Path::new("dist")));
        assert!(is_default_ignored(Path::new("__pycache__")));
        // Subpaths under an ignored dir.
        assert!(is_default_ignored(Path::new("target/release/build/foo.rs")));
        assert!(is_default_ignored(Path::new("node_modules/react/index.js")));
        assert!(is_default_ignored(Path::new(
            ".venv/lib/python3.12/site.py"
        )));

        // vendor is intentionally NOT in the default list -- some projects
        // commit vendored sources.  Users opt in via .raysense.toml.
        assert!(!is_default_ignored(Path::new("vendor")));
        assert!(!is_default_ignored(Path::new(
            "vendor/rayforce/include/rayforce.h"
        )));

        // Real source paths must not match.
        assert!(!is_default_ignored(Path::new("src/scanner.rs")));
        assert!(!is_default_ignored(Path::new(
            "examples/policies/no-huge-files.rfl"
        )));
    }

    #[test]
    fn extracts_rust_facts() {
        let content = r#"
use crate::graph;

pub fn scan_path() {}
fn helper() {}
"#;

        let functions = extract_functions(7, Language::Rust, content);
        let imports = extract_imports(7, Language::Rust, content);

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "scan_path");
        assert_eq!(functions[1].name, "helper");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].target, "crate::graph");
    }

    #[test]
    fn count_comment_lines_handles_common_languages() {
        let rust = "// header\nfn main() {}\n/// doc\n/* block\n  inside\n*/\nlet x = 1;\n";
        assert_eq!(
            count_comment_lines(rust),
            5,
            "// + /// + /* + inside + */ all count",
        );
        let python = "# top\n\"\"\"hi\"\"\"\nx = 1  # trailing\n# another\n";
        assert_eq!(
            count_comment_lines(python),
            2,
            "Only line-prefix # is counted, not trailing or docstrings",
        );
        let none = "fn main() { let x = 1; }\n";
        assert_eq!(count_comment_lines(none), 0);
    }

    #[test]
    fn expand_brace_targets_handles_common_shapes() {
        assert_eq!(expand_brace_targets("foo::bar"), vec!["foo::bar"]);
        assert_eq!(
            expand_brace_targets("foo::{a, b, c}"),
            vec!["foo::a", "foo::b", "foo::c"],
        );
        assert_eq!(
            expand_brace_targets("foo::{ a , b }"),
            vec!["foo::a", "foo::b"],
            "trims whitespace per item",
        );
        assert_eq!(
            expand_brace_targets("foo::{a}"),
            vec!["foo::a"],
            "single-item brace expansion",
        );
        assert_eq!(
            expand_brace_targets("foo::{}"),
            vec!["foo::{}"],
            "empty brace falls back to original target",
        );
        assert_eq!(
            expand_brace_targets("foo::{a"),
            vec!["foo::{a"],
            "missing close brace falls back to original target",
        );
    }

    #[test]
    fn fans_rust_brace_imports_into_separate_targets() {
        let content = "use crate::{graph, scanner};";
        let imports = extract_imports(11, Language::Rust, content);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].target, "crate::graph");
        assert_eq!(imports[1].target, "crate::scanner");
    }

    #[test]
    fn extracts_rust_use_alias() {
        let content = "use foo::Bar as Baz;\n";
        let imports = extract_imports(0, Language::Rust, content);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].target, "foo::Bar");
        assert_eq!(imports[0].alias.as_deref(), Some("Baz"));
    }

    #[test]
    fn extracts_rust_brace_use_with_per_item_aliases() {
        let content = "use crate::{a, b as c, d};\n";
        let imports = extract_imports(0, Language::Rust, content);
        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].target, "crate::a");
        assert_eq!(imports[0].alias, None);
        assert_eq!(imports[1].target, "crate::b");
        assert_eq!(imports[1].alias.as_deref(), Some("c"));
        assert_eq!(imports[2].target, "crate::d");
        assert_eq!(imports[2].alias, None);
    }

    #[test]
    fn rust_line_based_fallback_captures_alias() {
        let content = "use foo::Bar as Baz;\n";
        let imports = extract_rust_imports(0, content);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].target, "foo::Bar");
        assert_eq!(imports[0].alias.as_deref(), Some("Baz"));
    }

    #[test]
    fn extracts_rust_trait_impl_single() {
        let content = "trait Greet {}\nstruct Dog;\nimpl Greet for Dog {}\n";
        let impls = extract_trait_impls(0, content, Language::Rust);
        assert_eq!(impls.len(), 1);
        assert_eq!(impls[0].trait_name, "Greet");
        assert_eq!(impls[0].type_name, "Dog");
    }

    #[test]
    fn extracts_rust_multiple_impls_of_one_trait() {
        let content = "trait Greet {}\nstruct Dog;\nstruct Cat;\nimpl Greet for Dog {}\nimpl Greet for Cat {}\n";
        let impls = extract_trait_impls(0, content, Language::Rust);
        assert_eq!(impls.len(), 2);
        let pairs: std::collections::BTreeSet<(String, String)> = impls
            .iter()
            .map(|i| (i.type_name.clone(), i.trait_name.clone()))
            .collect();
        assert!(pairs.contains(&("Dog".to_string(), "Greet".to_string())));
        assert!(pairs.contains(&("Cat".to_string(), "Greet".to_string())));
    }

    #[test]
    fn extracts_rust_generic_impl_uses_head_name() {
        let content = "trait Greet {}\nimpl<T> Greet for Vec<T> {}\n";
        let impls = extract_trait_impls(0, content, Language::Rust);
        assert_eq!(impls.len(), 1);
        assert_eq!(impls[0].type_name, "Vec");
        assert_eq!(impls[0].trait_name, "Greet");
    }

    #[test]
    fn skips_rust_blanket_impls_over_type_parameter() {
        let content = "trait Foo {}\ntrait Bar {}\nimpl<T: Bar> Foo for T {}\n";
        let impls = extract_trait_impls(0, content, Language::Rust);
        assert!(
            impls.is_empty(),
            "blanket impl whose implementer is just a type parameter must not pollute the graph"
        );
    }

    #[test]
    fn inherent_impl_block_emits_no_trait_relation() {
        let content = "struct Foo;\nimpl Foo { fn bar(&self) {} }\n";
        let impls = extract_trait_impls(0, content, Language::Rust);
        assert!(
            impls.is_empty(),
            "an inherent impl Foo {{}} block has no trait field, so no trait/impl edge"
        );
    }

    #[test]
    fn scan_populates_trait_impls_in_report() {
        let root = temp_scan_root("trait_impls");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "pub trait Greet {}\npub struct Dog;\nimpl Greet for Dog {}\n",
        )
        .unwrap();
        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();
        assert!(
            report
                .trait_impls
                .iter()
                .any(|i| i.trait_name == "Greet" && i.type_name == "Dog"),
            "scan_path_with_config carries trait_impls through the public API"
        );
    }

    #[test]
    fn classifies_rust_pub_crate_as_internal() {
        let patterns = builtin_visibility_patterns("rust");
        assert_eq!(
            classify_visibility("pub(crate) fn foo() {}", &patterns),
            Visibility::Internal
        );
    }

    #[test]
    fn classifies_rust_pub_super_as_restricted() {
        let patterns = builtin_visibility_patterns("rust");
        assert_eq!(
            classify_visibility("pub(super) fn foo() {}", &patterns),
            Visibility::Restricted
        );
    }

    #[test]
    fn classifies_rust_pub_in_path_as_restricted() {
        let patterns = builtin_visibility_patterns("rust");
        assert_eq!(
            classify_visibility("pub(in crate::a::b) fn foo() {}", &patterns),
            Visibility::Restricted
        );
    }

    #[test]
    fn classifies_rust_bare_pub_as_public() {
        let patterns = builtin_visibility_patterns("rust");
        assert_eq!(
            classify_visibility("pub fn foo() {}", &patterns),
            Visibility::Public
        );
    }

    #[test]
    fn classifies_rust_no_modifier_as_unknown() {
        let patterns = builtin_visibility_patterns("rust");
        assert_eq!(
            classify_visibility("fn foo() {}", &patterns),
            Visibility::Unknown,
            "no modifier matches no pattern -- consumers may treat Unknown as private per language convention"
        );
    }

    #[test]
    fn classifies_java_protected_as_protected() {
        let patterns = builtin_visibility_patterns("java");
        assert_eq!(
            classify_visibility("protected void run() {}", &patterns),
            Visibility::Protected
        );
    }

    #[test]
    fn classify_visibility_walks_longest_prefix_first() {
        let patterns = builtin_visibility_patterns("rust");
        // `pub(crate)` is longer than `pub `; the longer must win even
        // though both prefixes start with `pub`.
        assert_eq!(
            classify_visibility("pub(crate) struct S;", &patterns),
            Visibility::Internal
        );
    }

    #[test]
    fn scan_populates_visibility_on_rust_functions_and_types() {
        let root = temp_scan_root("visibility");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "pub fn open() {}\npub(crate) fn internal() {}\nfn private_one() {}\npub struct Open;\npub(crate) struct Internal;\nstruct Private;\n",
        )
        .unwrap();
        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();

        let by_name: std::collections::HashMap<&str, &FunctionFact> = report
            .functions
            .iter()
            .map(|function| (function.name.as_str(), function))
            .collect();
        assert_eq!(by_name["open"].visibility, Visibility::Public);
        assert_eq!(by_name["internal"].visibility, Visibility::Internal);
        assert_eq!(by_name["private_one"].visibility, Visibility::Unknown);

        let types_by_name: std::collections::HashMap<&str, &TypeFact> = report
            .types
            .iter()
            .map(|type_fact| (type_fact.name.as_str(), type_fact))
            .collect();
        if let Some(open) = types_by_name.get("Open") {
            assert_eq!(open.visibility, Visibility::Public);
        }
        if let Some(internal) = types_by_name.get("Internal") {
            assert_eq!(internal.visibility, Visibility::Internal);
        }
    }

    #[test]
    fn split_use_alias_handles_common_shapes() {
        assert_eq!(split_use_alias("foo::Bar"), ("foo::Bar", None));
        assert_eq!(
            split_use_alias("foo::Bar as Baz"),
            ("foo::Bar", Some("Baz".to_string()))
        );
        assert_eq!(
            split_use_alias("  foo::Bar as Baz  "),
            ("foo::Bar", Some("Baz".to_string())),
            "leading/trailing whitespace is trimmed"
        );
        assert_eq!(
            split_use_alias("classname"),
            ("classname", None),
            "names that merely contain `as` substrings do not false-match"
        );
    }

    #[test]
    fn alias_capture_disabled_by_config_drops_alias() {
        let root = temp_scan_root("alias_disabled");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "use foo::Bar as Baz;\npub fn ok() {}\n",
        )
        .unwrap();
        let config: RaysenseConfig = toml::from_str(
            r#"
[[scan.plugins]]
name = "rust"
extensions = ["rs"]
import_prefixes = ["use "]
function_prefixes = ["fn "]
capture_import_aliases = false
"#,
        )
        .unwrap();
        let report = scan_path_with_config(&root, &config).unwrap();
        fs::remove_dir_all(&root).unwrap();

        let alias_present = report.imports.iter().any(|import| import.alias.is_some());
        assert!(
            !alias_present,
            "with capture_import_aliases = false the alias must be cleared"
        );
    }

    #[test]
    fn extracts_python_facts() {
        let content = r#"
import os
import sys, json as json_lib
from pathlib import Path

def run():
    Path.cwd()

class Worker:
    def start(self):
        run()
"#;

        let mut functions = extract_functions(3, Language::Python, content);
        for (idx, function) in functions.iter_mut().enumerate() {
            function.function_id = idx;
        }
        let imports = extract_imports(3, Language::Python, content);
        let calls = extract_calls(3, Language::Python, content, &functions);

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "run");
        assert_eq!(functions[1].name, "start");
        assert_eq!(imports.len(), 4);
        assert_eq!(imports[0].target, "os");
        assert_eq!(imports[1].target, "sys");
        assert_eq!(imports[2].target, "json");
        assert_eq!(imports[3].target, "pathlib");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].target, "cwd");
        assert_eq!(calls[0].caller_function, Some(0));
        assert_eq!(calls[1].target, "run");
        assert_eq!(calls[1].caller_function, Some(1));
    }

    #[test]
    fn extracts_tree_sitter_typescript_facts() {
        let content = r#"
import { load } from "./loader";
import "./setup";

export function run(): void {
    load();
}

const start = async () => {
    run();
};

class Service {
    boot() {
        start();
    }
}
"#;

        let functions = extract_functions(4, Language::TypeScript, content);
        let imports = extract_imports(4, Language::TypeScript, content);
        let calls = extract_calls(4, Language::TypeScript, content, &functions);

        assert_eq!(
            functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            vec!["run", "start", "boot"]
        );
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].target, "./loader");
        assert_eq!(imports[1].target, "./setup");
        assert_eq!(
            calls
                .iter()
                .map(|call| call.target.as_str())
                .collect::<Vec<_>>(),
            vec!["load", "run", "start"]
        );
    }

    #[test]
    fn scan_config_ignores_paths() {
        let root = temp_scan_root("ignored_paths");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("ignored")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn kept() {}\n").unwrap();
        fs::write(root.join("ignored/lib.rs"), "pub fn skipped() {}\n").unwrap();

        let config: RaysenseConfig = toml::from_str(
            r#"
[scan]
ignored_paths = ["ignored"]
"#,
        )
        .unwrap();
        let report = scan_path_with_config(&root, &config).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, PathBuf::from("src/lib.rs"));
        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].name, "kept");
    }

    #[test]
    fn scan_config_filters_languages() {
        let root = temp_scan_root("languages");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn kept() {}\n").unwrap();
        fs::write(root.join("src/tool.py"), "def skipped():\n    pass\n").unwrap();

        let config: RaysenseConfig = toml::from_str(
            r#"
[scan]
enabled_languages = ["rust"]
"#,
        )
        .unwrap();
        let report = scan_path_with_config(&root, &config).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].language, Language::Rust);
    }

    #[test]
    fn scan_config_adds_generic_language_plugins() {
        let root = temp_scan_root("plugins");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/tool.foo"),
            "load core\nfunction run\n  start()\n",
        )
        .unwrap();

        let config: RaysenseConfig = toml::from_str(
            r#"
[scan]

[[scan.plugins]]
name = "foo"
extensions = ["foo"]
function_prefixes = ["function "]
import_prefixes = ["load "]
call_suffixes = ["("]
"#,
        )
        .unwrap();
        let report = scan_path_with_config(&root, &config).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].language_name, "foo");
        assert_eq!(report.functions[0].name, "run");
        assert_eq!(report.imports[0].target, "core");
        assert_eq!(report.calls[0].target, "start");
    }

    #[test]
    fn plugin_profiles_drive_module_tests_ignores_and_resolution() {
        let root = temp_scan_root("plugin_profile");
        fs::create_dir_all(root.join("lib/pkg")).unwrap();
        fs::create_dir_all(root.join("spec")).unwrap();
        fs::create_dir_all(root.join("build")).unwrap();
        fs::write(root.join("lib/pkg/index.toy"), "import ../util\nfn run\n").unwrap();
        fs::write(root.join("lib/util.toy"), "fn helper\n").unwrap();
        fs::write(root.join("spec/pkg_test.toy"), "fn test_pkg\n").unwrap();
        fs::write(root.join("build/generated.toy"), "fn generated\n").unwrap();

        let config: RaysenseConfig = toml::from_str(
            r#"
[[scan.plugins]]
name = "toy"
extensions = ["toy"]
function_prefixes = ["fn "]
import_prefixes = ["import "]
call_suffixes = ["("]
package_index_files = ["index.toy"]
test_path_patterns = ["spec/*"]
source_roots = ["lib"]
ignored_paths = ["build/*"]
local_import_prefixes = ["."]
"#,
        )
        .unwrap();
        let report = scan_path_with_config(&root, &config).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 3);
        assert!(report
            .files
            .iter()
            .any(|file| file.path == PathBuf::from("spec/pkg_test.toy")));
        assert!(!report
            .files
            .iter()
            .any(|file| file.path == PathBuf::from("build/generated.toy")));
        assert!(report
            .files
            .iter()
            .any(|file| file.path == PathBuf::from("lib/pkg/index.toy") && file.module == "pkg"));
        assert!(report
            .entry_points
            .iter()
            .any(|entry| entry.kind == EntryPointKind::Test));
        assert_eq!(report.imports[0].resolution, ImportResolution::Local);
    }

    #[test]
    fn loads_project_local_plugin_manifests() {
        let root = temp_scan_root("local_plugins");
        fs::create_dir_all(root.join(".raysense/plugins/toy")).unwrap();
        fs::write(
            root.join(".raysense/plugins/toy/plugin.toml"),
            r#"
name = "toy"
extensions = ["toy"]
function_prefixes = ["fn "]
import_prefixes = ["load "]
call_suffixes = ["("]
"#,
        )
        .unwrap();
        fs::write(root.join("main.toy"), "load core\nfn run\n").unwrap();

        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].language_name, "toy");
        assert_eq!(report.functions[0].name, "run");
        assert_eq!(report.imports[0].target, "core");
    }

    #[test]
    fn project_local_plugins_can_use_tree_sitter_queries() {
        let root = temp_scan_root("local_plugin_queries");
        fs::create_dir_all(root.join(".raysense/plugins/rustish/queries")).unwrap();
        fs::write(
            root.join(".raysense/plugins/rustish/plugin.toml"),
            r#"
name = "rustish"
grammar = "rust"
extensions = ["rsh"]
function_prefixes = ["unused "]
import_prefixes = ["unused "]
call_suffixes = ["("]
"#,
        )
        .unwrap();
        fs::write(
            root.join(".raysense/plugins/rustish/queries/tags.scm"),
            r#"
(function_item
  name: (identifier) @name) @definition.function

(use_declaration
  argument: (_) @reference.import)
"#,
        )
        .unwrap();
        fs::write(root.join("main.rsh"), "use crate::core;\nfn run() {}\n").unwrap();

        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.functions[0].name, "run");
        assert_eq!(report.imports[0].target, "crate::core");
        assert_eq!(report.imports[0].kind, "query_import");
    }

    #[test]
    fn scans_builtin_language_catalog_extensions() {
        let root = temp_scan_root("builtin_catalog");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/main.go"),
            "package main\nimport \"fmt\"\nfunc run() {\n    fmt.Println(\"ok\")\n}\n",
        )
        .unwrap();

        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].language_name, "go");
        assert_eq!(report.functions[0].name, "run");
        assert_eq!(report.imports[0].target, "fmt");
    }

    #[test]
    fn scans_builtin_language_catalog_file_names() {
        let root = temp_scan_root("builtin_catalog_files");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("Dockerfile"),
            "FROM alpine\nCOPY . /app\nRUN echo ok\n",
        )
        .unwrap();

        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].language_name, "dockerfile");
        assert_eq!(report.imports[0].target, ".");
    }

    #[test]
    fn scans_expanded_builtin_language_catalog_extensions() {
        let root = temp_scan_root("expanded_builtin_catalog");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("main.gd"),
            "extends Node\nfunc _ready():\n    pass\n",
        )
        .unwrap();
        fs::write(root.join("shader.frag"), "void main() {}\n").unwrap();
        fs::write(
            root.join("main.hcl"),
            "module \"app\" { source = \"./app\" }\n",
        )
        .unwrap();

        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();
        let languages: std::collections::BTreeSet<_> = report
            .files
            .iter()
            .map(|file| file.language_name.as_str())
            .collect();

        assert!(languages.contains("gdscript"));
        assert!(languages.contains("glsl"));
        assert!(languages.contains("hcl"));
    }

    #[test]
    fn captures_function_extents() {
        let content = r#"
int add(int a, int b) {
    int sum = a + b;
    return sum;
}
"#;

        let functions = extract_functions(0, Language::C, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].start_line, 2);
        assert_eq!(functions[0].end_line, 5);
    }

    #[test]
    fn ignores_c_like_functions_in_comments() {
        let content = r#"
/*
 * Permission is hereby granted to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 */
int add(int a, int b) {
    return a + b;
}
"#;

        let functions = extract_functions(0, Language::C, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].start_line, 6);
    }

    #[test]
    fn ignores_c_like_static_asserts_and_typedefs() {
        let content = r#"
_Static_assert(sizeof(int) <= 16,
               "int must fit");

typedef struct RAY_ALIGN(32) {
    int value;
} aligned_t;

static inline int add(int a, int b) {
    return a + b;
}
"#;

        let functions = extract_functions(0, Language::C, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].start_line, 9);
    }

    #[test]
    fn ignores_c_like_calls_inside_function_bodies() {
        let content = r#"
int run(void) {
    if (check()) {
        return call_inside();
    }
    return 0;
}
"#;

        let functions = extract_functions(0, Language::C, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "run");
    }

    #[test]
    fn extracts_tree_sitter_rust_methods() {
        let content = r#"
pub struct Store;

impl Store {
    pub fn open() -> Self {
        Store
    }
}
"#;

        let functions = extract_functions(0, Language::Rust, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "open");
        assert_eq!(functions[0].start_line, 5);
        assert_eq!(functions[0].end_line, 7);
    }

    #[test]
    fn extracts_tree_sitter_c_multiline_declarators() {
        let content = r#"
static int
add(
    int a,
    int b
) {
    return a + b;
}
"#;

        let functions = extract_functions(0, Language::C, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions[0].start_line, 2);
        assert_eq!(functions[0].end_line, 8);
    }

    #[test]
    fn extracts_tree_sitter_cpp_methods() {
        let content = r#"
class Store {
    int open() {
        return 1;
    }
};
"#;

        let functions = extract_functions(0, Language::Cpp, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "open");
        assert_eq!(functions[0].start_line, 3);
        assert_eq!(functions[0].end_line, 5);
    }

    #[test]
    fn extracts_tree_sitter_calls_with_callers() {
        let content = r#"
fn run() {
    load();
    service.start();
}
"#;

        let mut functions = extract_functions(0, Language::Rust, content);
        functions[0].function_id = 42;
        let calls = extract_calls(0, Language::Rust, content, &functions);

        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].target, "load");
        assert_eq!(calls[0].caller_function, Some(42));
        assert_eq!(calls[1].target, "start");
        assert_eq!(calls[1].line, 4);
    }

    #[test]
    fn extracts_tree_sitter_c_calls() {
        let content = r#"
int run(void) {
    return add(1, 2);
}
"#;

        let functions = extract_functions(0, Language::C, content);
        let calls = extract_calls(0, Language::C, content, &functions);

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, "add");
        assert_eq!(calls[0].line, 3);
    }

    #[test]
    fn resolves_unambiguous_call_edges() {
        let files = vec![file(0, "src/a.rs", Language::Rust)];
        let functions = vec![function(0, 0, "run", 1, 3), function(1, 0, "load", 5, 7)];
        let calls = vec![CallFact {
            call_id: 9,
            file_id: 0,
            caller_function: Some(0),
            target: "load".to_string(),
            line: 2,
        }];

        let edges = resolve_call_edges(&files, &functions, &calls);

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].call_id, 9);
        assert_eq!(edges[0].caller_function, 0);
        assert_eq!(edges[0].callee_function, 1);
    }

    #[test]
    fn skips_ambiguous_call_edges() {
        let files = vec![
            file(0, "src/a.rs", Language::Rust),
            file(1, "src/b.rs", Language::Rust),
        ];
        let functions = vec![
            function(0, 0, "run", 1, 3),
            function(1, 1, "load", 5, 7),
            function(2, 1, "load", 5, 7),
        ];
        let calls = vec![CallFact {
            call_id: 9,
            file_id: 0,
            caller_function: Some(0),
            target: "load".to_string(),
            line: 2,
        }];

        let edges = resolve_call_edges(&files, &functions, &calls);

        assert!(edges.is_empty());
    }

    #[test]
    fn prefers_same_file_call_edges() {
        let files = vec![
            file(0, "src/a.rs", Language::Rust),
            file(1, "lib/b.rs", Language::Rust),
        ];
        let functions = vec![
            function(0, 0, "run", 1, 3),
            function(1, 0, "load", 5, 7),
            function(2, 1, "load", 5, 7),
        ];
        let calls = vec![CallFact {
            call_id: 9,
            file_id: 0,
            caller_function: Some(0),
            target: "load".to_string(),
            line: 2,
        }];

        let edges = resolve_call_edges(&files, &functions, &calls);

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].callee_function, 1);
    }

    #[test]
    fn prefers_same_top_module_call_edges() {
        let files = vec![
            file(0, "src/a.rs", Language::Rust),
            file(1, "src/b.rs", Language::Rust),
            file(2, "test/b.rs", Language::Rust),
        ];
        let functions = vec![
            function(0, 0, "run", 1, 3),
            function(1, 1, "load", 5, 7),
            function(2, 2, "load", 5, 7),
        ];
        let calls = vec![CallFact {
            call_id: 9,
            file_id: 0,
            caller_function: Some(0),
            target: "load".to_string(),
            line: 2,
        }];

        let edges = resolve_call_edges(&files, &functions, &calls);

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].callee_function, 1);
    }

    #[test]
    fn resolves_imports_by_stem() {
        let files = vec![
            file(0, "src/main.rs", Language::Rust),
            file(1, "src/graph.rs", Language::Rust),
        ];
        let mut imports = vec![new_import(0, "crate::graph", "use")];

        resolve_imports(&files, &mut imports, &RaysenseConfig::default());

        assert_eq!(imports[0].resolved_file, Some(1));
        assert_eq!(imports[0].resolution, ImportResolution::Local);
    }

    #[test]
    fn resolves_typescript_relative_imports() {
        let files = vec![
            file(0, "src/ui/form.ts", Language::TypeScript),
            file(1, "src/db/client.ts", Language::TypeScript),
            file(2, "src/widgets/index.ts", Language::TypeScript),
        ];
        let mut imports = vec![
            new_import(0, "../db/client", "import"),
            new_import(0, "../widgets", "import"),
        ];

        resolve_imports(&files, &mut imports, &RaysenseConfig::default());

        assert_eq!(imports[0].resolved_file, Some(1));
        assert_eq!(imports[1].resolved_file, Some(2));
        assert_eq!(imports[0].resolution, ImportResolution::Local);
        assert_eq!(imports[1].resolution, ImportResolution::Local);
    }

    #[test]
    fn resolves_rust_mod_files() {
        let files = vec![
            file(0, "src/main.rs", Language::Rust),
            file(1, "src/memory/mod.rs", Language::Rust),
        ];
        let mut imports = vec![new_import(0, "crate::memory", "use")];

        resolve_imports(&files, &mut imports, &RaysenseConfig::default());

        assert_eq!(imports[0].resolved_file, Some(1));
        assert_eq!(imports[0].resolution, ImportResolution::Local);
    }

    #[test]
    fn classifies_external_rust_crates() {
        let files = vec![file(0, "src/main.rs", Language::Rust)];
        let mut imports = vec![new_import(0, "serde::Serialize", "use")];

        resolve_imports(&files, &mut imports, &RaysenseConfig::default());

        assert_eq!(imports[0].resolved_file, None);
        assert_eq!(imports[0].resolution, ImportResolution::External);
    }

    #[test]
    fn classifies_c_system_and_local_includes() {
        let files = vec![
            file(0, "src/runtime.c", Language::C),
            file(1, "src/runtime.h", Language::C),
            file(2, "src/core/platform.h", Language::C),
        ];
        let mut imports = vec![
            new_import(0, "stdio.h", "include_system"),
            new_import(0, "runtime.h", "include"),
            new_import(0, "core/platform.h", "include"),
            new_import(0, "missing.h", "include"),
        ];

        resolve_imports(&files, &mut imports, &RaysenseConfig::default());

        assert_eq!(imports[0].resolution, ImportResolution::System);
        assert_eq!(imports[1].resolved_file, Some(1));
        assert_eq!(imports[1].resolution, ImportResolution::Local);
        assert_eq!(imports[2].resolved_file, Some(2));
        assert_eq!(imports[2].resolution, ImportResolution::Local);
        assert_eq!(imports[3].resolution, ImportResolution::Unresolved);
    }

    #[test]
    fn cleans_c_include_targets() {
        assert_eq!(
            clean_c_include_target("\"ops/ops.h\"    /* comment */"),
            "ops/ops.h"
        );
        assert_eq!(clean_c_include_target("<stdio.h>"), "stdio.h");
    }

    #[test]
    fn extracts_rust_mod_declarations() {
        let imports = extract_imports(
            0,
            Language::Rust,
            "mod scanner;\nmod tests {\n}\nuse crate::facts;\n",
        );

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].target, "scanner");
        assert_eq!(imports[0].kind, "mod");
    }

    #[test]
    fn extracts_tree_sitter_rust_imports() {
        let imports = extract_imports(
            0,
            Language::Rust,
            "use crate::facts::{FileFact, ImportFact};\nmod graph;\nmod tests {\n}\n",
        );

        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].target, "crate::facts::FileFact");
        assert_eq!(imports[0].kind, "use");
        assert_eq!(imports[1].target, "crate::facts::ImportFact");
        assert_eq!(imports[1].kind, "use");
        assert_eq!(imports[2].target, "graph");
        assert_eq!(imports[2].kind, "mod");
    }

    #[test]
    fn extracts_tree_sitter_c_includes() {
        let imports = extract_imports(
            0,
            Language::C,
            "#include <stdio.h>\n#include \"core/runtime.h\"\n",
        );

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].target, "stdio.h");
        assert_eq!(imports[0].kind, "include_system");
        assert_eq!(imports[1].target, "core/runtime.h");
        assert_eq!(imports[1].kind, "include");
    }

    #[test]
    fn extracts_entry_points() {
        let functions = vec![FunctionFact {
            function_id: 0,
            file_id: 0,
            name: "main".to_string(),
            start_line: 1,
            end_line: 1,
            visibility: Visibility::default(),
        }];

        let entries = extract_entry_points(
            0,
            Language::Rust,
            Path::new("examples/demo.rs"),
            "fn main() {}\n",
            &functions,
            None,
        );

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, EntryPointKind::Binary);
        assert_eq!(entries[1].kind, EntryPointKind::Example);
    }

    #[test]
    fn attribute_test_marks_rust_function_as_test_entry() {
        let content = "#[test]\nfn ok() {}\nfn helper() {}\n";
        let functions = extract_functions(0, Language::Rust, content);
        let entries = extract_entry_points(
            0,
            Language::Rust,
            Path::new("src/lib.rs"),
            content,
            &functions,
            None,
        );
        let test_symbols: Vec<&str> = entries
            .iter()
            .filter(|entry| entry.kind == EntryPointKind::Test)
            .map(|entry| entry.symbol.as_str())
            .collect();
        assert_eq!(
            test_symbols,
            vec!["ok"],
            "only the #[test]-annotated function is a test entry"
        );
    }

    #[test]
    fn cfg_test_module_marker_marks_contained_functions_as_test() {
        let content =
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn alpha() {}\n    fn helper() {}\n}\n";
        let functions = extract_functions(0, Language::Rust, content);
        let entries = extract_entry_points(
            0,
            Language::Rust,
            Path::new("src/lib.rs"),
            content,
            &functions,
            None,
        );
        let test_symbols: std::collections::BTreeSet<String> = entries
            .iter()
            .filter(|entry| entry.kind == EntryPointKind::Test)
            .map(|entry| entry.symbol.clone())
            .collect();
        assert!(test_symbols.contains("alpha"));
        assert!(
            test_symbols.contains("helper"),
            "#[cfg(test)] cascades to functions that lack their own #[test] marker"
        );
        assert_eq!(
            test_symbols.len(),
            2,
            "alpha is counted exactly once even though it matches both rules"
        );
    }

    #[test]
    fn extended_test_attribute_pattern_is_honored() {
        let content = "#[runtime_test]\nasync fn flow() {}\n";
        let functions = extract_functions(0, Language::Rust, content);
        let mut plugin = LanguagePluginConfig {
            name: "rust".to_string(),
            ..LanguagePluginConfig::default()
        };
        apply_builtin_profile_defaults(&mut plugin);
        plugin
            .test_attribute_patterns
            .push("#[runtime_test]".to_string());
        let entries = extract_entry_points(
            0,
            Language::Rust,
            Path::new("src/lib.rs"),
            content,
            &functions,
            Some(&plugin),
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == EntryPointKind::Test && entry.symbol == "flow"),
            "profile-extended test attribute is honored"
        );
    }

    #[test]
    fn helper_function_without_attribute_is_not_test_entry() {
        let content = "fn helper() {}\n";
        let functions = extract_functions(0, Language::Rust, content);
        let entries = extract_entry_points(
            0,
            Language::Rust,
            Path::new("src/lib.rs"),
            content,
            &functions,
            None,
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.kind != EntryPointKind::Test),
            "no test entries when the source has no test markers"
        );
    }

    #[test]
    fn cfg_test_detection_is_plugin_driven() {
        let content = "#[cfg(test)]\nmod tests {\n    fn helper() {}\n}\n";
        let functions = extract_functions(0, Language::Rust, content);
        let mut plugin = LanguagePluginConfig {
            name: "rust".to_string(),
            ..LanguagePluginConfig::default()
        };
        apply_builtin_profile_defaults(&mut plugin);
        plugin.test_attribute_patterns.clear();
        plugin.conditional_test_attributes.clear();
        let entries = extract_entry_points(
            0,
            Language::Rust,
            Path::new("src/lib.rs"),
            content,
            &functions,
            Some(&plugin),
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.kind != EntryPointKind::Test),
            "clearing the patterns disables test detection -- proves the knob is consulted"
        );
    }

    #[test]
    fn scan_classifies_inline_cfg_test_module_as_test_entry() {
        let root = temp_scan_root("inline_cfg_test");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "pub fn run() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn alpha() {}\n    fn helper() {}\n}\n",
        )
        .unwrap();
        let report = scan_path_with_config(&root, &RaysenseConfig::default()).unwrap();
        fs::remove_dir_all(&root).unwrap();

        let lib_id = report
            .files
            .iter()
            .find(|file| file.path == PathBuf::from("src/lib.rs"))
            .map(|file| file.file_id)
            .expect("scan produces a fact for src/lib.rs");
        let test_symbols: std::collections::BTreeSet<String> = report
            .entry_points
            .iter()
            .filter(|entry| entry.file_id == lib_id && entry.kind == EntryPointKind::Test)
            .map(|entry| entry.symbol.clone())
            .collect();
        assert!(
            test_symbols.contains("alpha"),
            "the #[test]-annotated function is detected"
        );
        assert!(
            test_symbols.contains("helper"),
            "the un-annotated function inside the #[cfg(test)] mod cascades"
        );
    }

    #[test]
    fn java_test_attribute_marks_function_as_test_entry() {
        let content = "@Test\nvoid run() {}\n";
        let functions = extract_token_functions(0, content, "void ");
        let entries = extract_entry_points(
            0,
            Language::Java,
            Path::new("src/main/java/Sample.java"),
            content,
            &functions,
            None,
        );
        assert!(
            entries
                .iter()
                .any(|entry| entry.kind == EntryPointKind::Test && entry.symbol == "run"),
            "@Test attribute proves the mechanism is generic across languages"
        );
    }

    #[test]
    fn derives_module_names() {
        assert_eq!(
            module_name(Path::new("src/memory/mod.rs"), Language::Rust, None),
            "src.memory"
        );
        assert_eq!(
            module_name(
                Path::new("src/widgets/index.ts"),
                Language::TypeScript,
                None
            ),
            "src.widgets"
        );
        assert_eq!(
            module_name(Path::new("pkg/__init__.py"), Language::Python, None),
            "pkg"
        );
    }

    #[test]
    fn extract_base_class_names_handles_common_languages() {
        assert_eq!(
            extract_base_class_names("class Foo extends Bar implements Baz, Qux {"),
            vec!["Bar".to_string(), "Baz".to_string(), "Qux".to_string()],
        );
        assert_eq!(
            extract_base_class_names("class Foo(Bar, Baz):"),
            vec!["Bar".to_string(), "Baz".to_string()],
        );
        assert_eq!(
            extract_base_class_names("class Foo : public Bar, virtual Baz {"),
            vec!["Bar".to_string(), "Baz".to_string()],
        );
        assert_eq!(
            extract_base_class_names("class Foo extends Bar with Baz with Qux {"),
            vec!["Bar".to_string(), "Baz".to_string(), "Qux".to_string()],
        );
        assert!(
            extract_base_class_names("struct Plain;").is_empty(),
            "Rust structs declared without inheritance produce no bases",
        );
    }

    #[test]
    fn tree_sitter_extracts_python_class_bases() {
        let content = "class Dog(Animal, Mammal):\n    pass\n";
        let types = extract_tree_sitter_types(0, content, Language::Python).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert_eq!(dog.bases, vec!["Animal".to_string(), "Mammal".to_string()]);
        assert_eq!(dog.line, 1);
    }

    #[test]
    fn tree_sitter_extracts_typescript_class_extends_and_implements() {
        let content = "class Foo extends Bar implements Baz, Qux {}\n";
        let types = extract_tree_sitter_types(0, content, Language::TypeScript).unwrap();
        let foo = types.iter().find(|t| t.name == "Foo").unwrap();
        assert!(foo.bases.contains(&"Bar".to_string()));
        assert!(foo.bases.contains(&"Baz".to_string()));
        assert!(foo.bases.contains(&"Qux".to_string()));
    }

    #[test]
    fn tree_sitter_extracts_cpp_class_inheritance() {
        let content =
            "class Animal {};\nclass Dog : public Animal, protected IBarker {\npublic:\n};\n";
        let types = extract_tree_sitter_types(0, content, Language::Cpp).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert_eq!(dog.bases, vec!["Animal".to_string(), "IBarker".to_string()]);
        let animal = types.iter().find(|t| t.name == "Animal").unwrap();
        assert!(animal.bases.is_empty());
    }

    #[test]
    fn tree_sitter_extracts_cpp_struct_inheritance() {
        let content = "struct Base {};\nstruct Derived : Base { int x; };\n";
        let types = extract_tree_sitter_types(0, content, Language::Cpp).unwrap();
        let derived = types.iter().find(|t| t.name == "Derived").unwrap();
        assert_eq!(derived.bases, vec!["Base".to_string()]);
    }

    #[test]
    fn tree_sitter_extracts_java_extends_and_implements() {
        let content =
            "class Dog extends Animal implements IBarker, ITracked {\n  void bark() {}\n}\n";
        let types = extract_tree_sitter_types(0, content, Language::Java).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
        assert!(dog.bases.contains(&"IBarker".to_string()));
        assert!(dog.bases.contains(&"ITracked".to_string()));
    }

    #[test]
    fn tree_sitter_extracts_csharp_base_list() {
        let content =
            "class Dog : Animal, IBarker, ITracked { public void Bark() {} }\ninterface IBarker {}\n";
        let types = extract_tree_sitter_types(0, content, Language::CSharp).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
        assert!(dog.bases.contains(&"IBarker".to_string()));
    }

    #[test]
    fn tree_sitter_extracts_kotlin_delegation_specifiers() {
        let content = "open class Animal\nclass Dog : Animal(), IBarker {\n  fun bark() {}\n}\ninterface IBarker\n";
        let types = extract_tree_sitter_types(0, content, Language::Kotlin).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
        assert!(dog.bases.contains(&"IBarker".to_string()));
    }

    #[test]
    fn tree_sitter_extracts_scala_extends_with() {
        let content =
            "class Dog extends Animal with IBarker with ITracked {\n  def bark(): Unit = ()\n}\n";
        let types = extract_tree_sitter_types(0, content, Language::Scala).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
        assert!(dog.bases.contains(&"IBarker".to_string()));
        assert!(dog.bases.contains(&"ITracked".to_string()));
    }

    #[test]
    fn tree_sitter_extracts_swift_inheritance_clause() {
        let content =
            "class Dog: Animal, IBarker, ITracked {\n  func bark() {}\n}\nprotocol IBarker {}\n";
        let types = extract_tree_sitter_types(0, content, Language::Swift).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert!(dog.bases.contains(&"Animal".to_string()));
        assert!(dog.bases.contains(&"IBarker".to_string()));
    }

    #[test]
    fn tree_sitter_extracts_ruby_superclass() {
        let content = "class Dog < Animal\n  def bark\n  end\nend\n";
        let types = extract_tree_sitter_types(0, content, Language::Ruby).unwrap();
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert_eq!(dog.bases, vec!["Animal".to_string()]);
    }

    #[test]
    fn tree_sitter_returns_none_for_languages_without_grammar_support() {
        // C is supported by tree-sitter but not by the type-extraction
        // dispatch — falls through and returns None.
        let content = "struct S { int x; };\n";
        assert!(extract_tree_sitter_types(0, content, Language::C).is_none());
    }

    #[test]
    fn extract_types_marks_abstract_when_base_matches_plugin_config() {
        let file = FileFact {
            file_id: 0,
            path: PathBuf::from("src/Animal.py"),
            language: Language::Python,
            language_name: "python".to_string(),
            module: "src.Animal".to_string(),
            lines: 1,
            bytes: 30,
            content_hash: String::new(),
            comment_lines: 0,
        };
        let content = "class Dog(AbstractAnimal):\n";
        let plugin = LanguagePluginConfig {
            name: "python".to_string(),
            abstract_base_classes: vec!["AbstractAnimal".to_string()],
            concrete_type_prefixes: vec!["class ".to_string()],
            ..LanguagePluginConfig::default()
        };
        let types = extract_types(0, &file, content, Some(&plugin));
        assert_eq!(types.len(), 1);
        assert_eq!(types[0].name, "Dog");
        assert_eq!(types[0].bases, vec!["AbstractAnimal".to_string()]);
        assert!(
            types[0].is_abstract,
            "config-listed abstract base should flip is_abstract on the subclass",
        );
    }

    #[test]
    fn extract_types_finds_rust_traits_and_structs() {
        let file = FileFact {
            file_id: 0,
            path: PathBuf::from("src/lib.rs"),
            language: Language::Rust,
            language_name: "rust".to_string(),
            module: "lib".to_string(),
            lines: 4,
            bytes: 80,
            content_hash: String::new(),
            comment_lines: 0,
        };
        let content = "trait Animal {}\npub struct Dog;\nstruct Cat;\nfn meow() {}\n";
        let types = extract_types(0, &file, content, None);
        assert_eq!(types.len(), 3);
        let names: Vec<&str> = types
            .iter()
            .map(|type_fact| type_fact.name.as_str())
            .collect();
        assert!(names.contains(&"Animal"));
        assert!(names.contains(&"Dog"));
        assert!(names.contains(&"Cat"));
        let animal = types.iter().find(|t| t.name == "Animal").unwrap();
        assert!(animal.is_abstract);
        let dog = types.iter().find(|t| t.name == "Dog").unwrap();
        assert!(!dog.is_abstract);
    }

    #[test]
    fn alias_rewrites_replace_prefix_pattern() {
        let rules = vec![("@app/*".to_string(), "src/app/*".to_string())];
        assert_eq!(
            rewrite_alias("@app/widgets/button", &rules).as_deref(),
            Some("src/app/widgets/button")
        );
        assert_eq!(rewrite_alias("@other/x", &rules), None);
    }

    #[test]
    fn alias_rewrites_handle_exact_match() {
        let rules = vec![("@root".to_string(), "src/index".to_string())];
        assert_eq!(rewrite_alias("@root", &rules).as_deref(), Some("src/index"));
    }

    #[test]
    fn read_alias_file_supports_tsconfig_and_flat_layouts() {
        let dir = std::env::temp_dir().join(format!(
            "raysense-alias-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let tsconfig = dir.join("tsconfig.json");
        fs::write(
            &tsconfig,
            r#"{"compilerOptions":{"paths":{"@app/*":["src/app/*"]}}}"#,
        )
        .unwrap();
        let parsed = read_alias_file(&tsconfig);
        assert!(parsed
            .iter()
            .any(|(k, v)| k == "@app/*" && v == "src/app/*"));

        let flat = dir.join("flat.json");
        fs::write(&flat, r#"{"@root":"src/index"}"#).unwrap();
        let parsed = read_alias_file(&flat);
        assert!(parsed.iter().any(|(k, v)| k == "@root" && v == "src/index"));
        fs::remove_dir_all(&dir).unwrap();
    }

    fn file(file_id: usize, path: &str, language: Language) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language,
            language_name: language_name(language).to_string(),
            module: module_name(Path::new(path), language, None),
            lines: 1,
            bytes: 1,
            content_hash: String::new(),
            comment_lines: 0,
        }
    }

    fn function(
        function_id: usize,
        file_id: usize,
        name: &str,
        start_line: usize,
        end_line: usize,
    ) -> FunctionFact {
        FunctionFact {
            function_id,
            file_id,
            name: name.to_string(),
            start_line,
            end_line,
            visibility: Visibility::default(),
        }
    }

    fn temp_scan_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("raysense-{name}-{nanos}"))
    }

    #[test]
    fn extracts_rayfall_named_functions() {
        let content = "(set fib (fn [x] (if (< x 2) 1 (+ (self (- x 1)) (self (- x 2))))))\n";
        let functions = extract_functions(0, Language::Rayfall, content);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "fib");
        assert_eq!(functions[0].start_line, 1);
    }

    #[test]
    fn extracts_rayfall_anonymous_lambdas() {
        let content = "(timer 500 1000000000 (fn [x] (insert 'q (list x))))\n";
        let functions = extract_functions(0, Language::Rayfall, content);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "lambda@1");
    }

    #[test]
    fn extracts_rayfall_named_and_anonymous_together() {
        let content = "(set f (fn [x] (* x x)))\n(timer 700 1000 (fn [x] (insert 'a x)))\n";
        let functions = extract_functions(0, Language::Rayfall, content);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "f");
        assert_eq!(functions[0].start_line, 1);
        assert_eq!(functions[1].name, "lambda@2");
        assert_eq!(functions[1].start_line, 2);
    }

    #[test]
    fn extracts_rayfall_table_types() {
        let content = "(set trades (table [Sym Ts Price] (list [] [] [])))\n";
        let report = scan_for_rayfall(content);
        assert_eq!(report.types.len(), 1);
        assert_eq!(report.types[0].name, "trades");
        assert!(!report.types[0].is_abstract);
        assert!(report.types[0].bases.is_empty());
    }

    #[test]
    fn extracts_rayfall_dict_types() {
        let content = "(set D (dict [a b c] [1 2 3]))\n";
        let report = scan_for_rayfall(content);
        assert_eq!(report.types.len(), 1);
        assert_eq!(report.types[0].name, "D");
    }

    #[test]
    fn extracts_rayfall_imports() {
        let content = "(load \"lib.rfl\")\n\
                       (.csv.read 'I64 \"data.csv\")\n\
                       (.db.splayed.get \"/db/trades/\")\n";
        let imports = extract_imports(0, Language::Rayfall, content);
        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].target, "lib.rfl");
        assert_eq!(imports[0].kind, "load");
        assert_eq!(imports[1].target, "data.csv");
        assert_eq!(imports[1].kind, ".csv.read");
        assert_eq!(imports[2].target, "/db/trades/");
        assert_eq!(imports[2].kind, ".db.splayed.get");
    }

    #[test]
    fn rayfall_kebab_case_function_names_are_preserved() {
        let content = "(set my-func (fn [x] x))\n(set T-Small (table [a b] (list [1 2] [3 4])))\n";
        let functions = extract_functions(0, Language::Rayfall, content);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "my-func");
        let report = scan_for_rayfall(content);
        let table = report
            .types
            .iter()
            .find(|t| t.line == 2)
            .expect("table type on line 2");
        assert_eq!(table.name, "T-Small");
    }

    /// Run a full scan against a single in-memory `.rfl` file so the test
    /// covers the dispatch in `scan_path_with_config` (which is what wires
    /// `extract_rayfall_types` into the report).
    fn scan_for_rayfall(content: &str) -> crate::facts::ScanReport {
        let dir = temp_scan_root("rayfall");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sample.rfl"), content).unwrap();
        let report = scan_path(&dir).expect("scan succeeds");
        let _ = std::fs::remove_dir_all(&dir);
        report
    }
}
