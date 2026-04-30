use crate::facts::{FileFact, FunctionFact, ImportFact, Language, ScanReport, SnapshotFact};
use crate::graph::compute_graph_metrics;
use ignore::WalkBuilder;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

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
}

pub fn scan_path(root: impl AsRef<Path>) -> Result<ScanReport, ScanError> {
    let root = root
        .as_ref()
        .canonicalize()
        .map_err(|source| ScanError::Read {
            path: root.as_ref().to_path_buf(),
            source,
        })?;

    let mut files = Vec::new();
    let mut functions = Vec::new();
    let mut imports = Vec::new();

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
        let language = Language::from_path(path);
        if !language.is_supported() {
            continue;
        }

        let content = fs::read_to_string(path).map_err(|source| ScanError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        let file_id = files.len();
        let relative_path = path.strip_prefix(&root).unwrap_or(path).to_path_buf();
        let file_fact = FileFact {
            file_id,
            path: relative_path,
            language,
            lines: content.lines().count(),
            bytes: content.len(),
            content_hash: hash_content(&content),
        };

        let mut file_functions = extract_functions(file_id, language, &content);
        for function in &mut file_functions {
            function.function_id = functions.len();
            functions.push(function.clone());
        }

        let mut file_imports = extract_imports(file_id, language, &content);
        for import in &mut file_imports {
            import.import_id = imports.len();
            imports.push(import.clone());
        }

        files.push(file_fact);
    }

    resolve_imports(&files, &mut imports);

    let snapshot_id = snapshot_id(&files);
    let graph = compute_graph_metrics(&files, &imports);
    let snapshot = SnapshotFact {
        snapshot_id,
        root,
        file_count: files.len(),
        function_count: functions.len(),
        import_count: imports.len(),
    };

    Ok(ScanReport {
        snapshot,
        files,
        functions,
        imports,
        graph,
    })
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

fn extract_functions(file_id: usize, language: Language, content: &str) -> Vec<FunctionFact> {
    match language {
        Language::Rust => extract_token_functions(file_id, content, "fn "),
        Language::Python => extract_prefixed_functions(file_id, content, "def "),
        Language::TypeScript => extract_typescript_functions(file_id, content),
        Language::C | Language::Cpp => extract_c_like_functions(file_id, content),
        Language::Unknown => Vec::new(),
    }
}

fn extract_token_functions(file_id: usize, content: &str, token: &str) -> Vec<FunctionFact> {
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
                end_line: idx + 1,
            })
        })
        .collect()
}

fn extract_prefixed_functions(file_id: usize, content: &str, prefix: &str) -> Vec<FunctionFact> {
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
                end_line: idx + 1,
            })
        })
        .collect()
}

fn extract_typescript_functions(file_id: usize, content: &str) -> Vec<FunctionFact> {
    let mut functions = extract_prefixed_functions(file_id, content, "function ");
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
                    end_line: idx + 1,
                });
            }
        }
    }
    functions
}

fn extract_c_like_functions(file_id: usize, content: &str) -> Vec<FunctionFact> {
    content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.ends_with(';') || !trimmed.contains('(') {
                return None;
            }
            let before_paren = trimmed.split('(').next()?.trim();
            let name = before_paren.split_whitespace().last()?;
            if name.is_empty() || matches!(name, "if" | "for" | "while" | "switch") {
                return None;
            }
            Some(FunctionFact {
                function_id: 0,
                file_id,
                name: name.to_string(),
                start_line: idx + 1,
                end_line: idx + 1,
            })
        })
        .collect()
}

fn extract_imports(file_id: usize, language: Language, content: &str) -> Vec<ImportFact> {
    match language {
        Language::Rust => extract_rust_imports(file_id, content),
        Language::Python => extract_python_imports(file_id, content),
        Language::TypeScript => extract_typescript_imports(file_id, content),
        Language::C | Language::Cpp => extract_c_imports(file_id, content),
        Language::Unknown => Vec::new(),
    }
}

fn extract_rust_imports(file_id: usize, content: &str) -> Vec<ImportFact> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let target = trimmed.strip_prefix("use ")?.trim_end_matches(';').trim();
            Some(new_import(file_id, target, "use"))
        })
        .collect()
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
            Some(new_import(
                file_id,
                target.trim_matches(['<', '>', '"']),
                "include",
            ))
        })
        .collect()
}

fn new_import(file_id: usize, target: &str, kind: &str) -> ImportFact {
    ImportFact {
        import_id: 0,
        from_file: file_id,
        target: target.to_string(),
        kind: kind.to_string(),
        resolved_file: None,
    }
}

fn resolve_imports(files: &[FileFact], imports: &mut [ImportFact]) {
    let mut by_stem = HashMap::new();
    let mut by_path = HashMap::new();

    for file in files {
        if let Some(stem) = file.path.file_stem().and_then(|stem| stem.to_str()) {
            by_stem.entry(stem.to_string()).or_insert(file.file_id);
        }
        by_path.insert(file.path.to_string_lossy().replace('\\', "/"), file.file_id);
    }

    for import in imports {
        let target = import.target.replace("::", "/").replace('.', "/");
        let target = target.trim_start_matches("./").trim_start_matches("../");
        import.resolved_file = by_path.get(target).copied().or_else(|| {
            by_stem
                .get(target.rsplit('/').next().unwrap_or(target))
                .copied()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
from pathlib import Path

def run():
    pass
"#;

        let functions = extract_functions(3, Language::Python, content);
        let imports = extract_imports(3, Language::Python, content);

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "run");
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[1].target, "pathlib");
    }

    #[test]
    fn resolves_imports_by_stem() {
        let files = vec![
            FileFact {
                file_id: 0,
                path: PathBuf::from("src/main.rs"),
                language: Language::Rust,
                lines: 1,
                bytes: 1,
                content_hash: String::new(),
            },
            FileFact {
                file_id: 1,
                path: PathBuf::from("src/graph.rs"),
                language: Language::Rust,
                lines: 1,
                bytes: 1,
                content_hash: String::new(),
            },
        ];
        let mut imports = vec![new_import(0, "crate::graph", "use")];

        resolve_imports(&files, &mut imports);

        assert_eq!(imports[0].resolved_file, Some(1));
    }
}
