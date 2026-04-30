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
    ImportResolution, Language, ScanReport, SnapshotFact,
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

    let mut files = Vec::new();
    let mut functions = Vec::new();
    let mut entry_points = Vec::new();
    let mut imports = Vec::new();
    let mut calls = Vec::new();

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
        if is_internal_path(&relative_path) {
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
        };

        let mut file_functions = if let Some(plugin) = plugin.as_ref() {
            extract_plugin_functions(file_id, &content, plugin)
        } else {
            extract_functions(file_id, language, &content)
        };
        for function in &mut file_functions {
            function.function_id = functions.len();
            functions.push(function.clone());
        }

        let mut file_entry_points = extract_entry_points(
            file_id,
            language,
            &relative_path,
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

        files.push(file_fact);
    }

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

fn matching_plugin(path: &Path, config: &RaysenseConfig) -> Option<LanguagePluginConfig> {
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
        ("vb", &["vb"], &["Sub ", "Function "], &["Imports "]),
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
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::C => "c",
        Language::Cpp => "cpp",
        Language::Python => "python",
        Language::Rust => "rust",
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

fn module_name(path: &Path, language: Language, plugin: Option<&LanguagePluginConfig>) -> String {
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

    entries
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
                imports.push(new_import(file_id, &target, "use"));
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
            imports.push(new_import(
                file_id,
                target.trim_end_matches(';').trim(),
                "use",
            ));
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
    ImportFact {
        import_id: 0,
        from_file: file_id,
        target: target.to_string(),
        kind: kind.to_string(),
        resolution: ImportResolution::Unresolved,
        resolved_file: None,
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
        Language::Unknown => plugin_import_candidates(from_file, import, config),
    }
}

fn plugin_import_candidates(
    from_file: &FileFact,
    import: &ImportFact,
    config: &RaysenseConfig,
) -> Vec<String> {
    let Some(plugin) = plugin_by_language_name(&from_file.language_name, config) else {
        return Vec::new();
    };
    let target = import
        .target
        .trim()
        .trim_matches(['"', '\'', ';'])
        .replace('.', "/");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].target, "crate::facts::{FileFact, ImportFact}");
        assert_eq!(imports[0].kind, "use");
        assert_eq!(imports[1].target, "graph");
        assert_eq!(imports[1].kind, "mod");
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
        }];

        let entries = extract_entry_points(
            0,
            Language::Rust,
            Path::new("examples/demo.rs"),
            &functions,
            None,
        );

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, EntryPointKind::Binary);
        assert_eq!(entries[1].kind, EntryPointKind::Example);
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
        }
    }

    fn temp_scan_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("raysense-{name}-{nanos}"))
    }
}
