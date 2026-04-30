use crate::facts::{FileFact, FunctionFact, ImportFact, Language, ScanReport, SnapshotFact};
use crate::graph::compute_graph_metrics;
use ignore::WalkBuilder;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
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
            module: module_name(&relative_path, language),
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

fn module_name(path: &Path, language: Language) -> String {
    let mut components: Vec<String> = path.components().filter_map(component_to_string).collect();

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

    components.join(".")
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
    let mut by_path = HashMap::new();
    let mut by_module = HashMap::new();

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
        import.resolved_file = resolve_import(from_file, import, &by_path, &by_module);
    }
}

fn resolve_import(
    from_file: &FileFact,
    import: &ImportFact,
    by_path: &HashMap<String, usize>,
    by_module: &HashMap<String, usize>,
) -> Option<usize> {
    let candidates = import_candidates(from_file, import);
    candidates
        .iter()
        .find_map(|candidate| by_path.get(candidate).copied())
        .or_else(|| {
            module_candidate(&import.target).and_then(|module| by_module.get(&module).copied())
        })
}

fn import_candidates(from_file: &FileFact, import: &ImportFact) -> Vec<String> {
    match from_file.language {
        Language::Rust => rust_import_candidates(&import.target),
        Language::Python => python_import_candidates(&import.target),
        Language::TypeScript => typescript_import_candidates(&from_file.path, &import.target),
        Language::C | Language::Cpp => c_import_candidates(&from_file.path, &import.target),
        Language::Unknown => Vec::new(),
    }
}

fn rust_import_candidates(target: &str) -> Vec<String> {
    let target = target
        .trim_start_matches("crate::")
        .trim_start_matches("self::")
        .replace("::", "/");
    vec![
        format!("{target}.rs"),
        format!("{target}/mod.rs"),
        format!("src/{target}.rs"),
        format!("src/{target}/mod.rs"),
    ]
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

fn c_import_candidates(from_path: &Path, target: &str) -> Vec<String> {
    if target.starts_with('<') {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    if let Some(base) = relative_base(from_path, target) {
        candidates.push(normalize_path(base));
    }
    candidates.push(target.replace('\\', "/"));
    candidates
}

fn module_candidate(target: &str) -> Option<String> {
    let target = target
        .trim()
        .trim_start_matches("crate::")
        .trim_start_matches("self::")
        .trim_start_matches("./")
        .trim_matches(['"', '\'']);
    if target.starts_with("../") || target.starts_with('/') || target.starts_with('@') {
        return None;
    }
    Some(
        target
            .replace("::", ".")
            .replace('/', ".")
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

fn component_to_string(component: Component<'_>) -> Option<String> {
    match component {
        Component::Normal(value) => value.to_str().map(ToOwned::to_owned),
        _ => None,
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
                module: "src.main".to_string(),
                lines: 1,
                bytes: 1,
                content_hash: String::new(),
            },
            FileFact {
                file_id: 1,
                path: PathBuf::from("src/graph.rs"),
                language: Language::Rust,
                module: "src.graph".to_string(),
                lines: 1,
                bytes: 1,
                content_hash: String::new(),
            },
        ];
        let mut imports = vec![new_import(0, "crate::graph", "use")];

        resolve_imports(&files, &mut imports);

        assert_eq!(imports[0].resolved_file, Some(1));
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

        resolve_imports(&files, &mut imports);

        assert_eq!(imports[0].resolved_file, Some(1));
        assert_eq!(imports[1].resolved_file, Some(2));
    }

    #[test]
    fn resolves_rust_mod_files() {
        let files = vec![
            file(0, "src/main.rs", Language::Rust),
            file(1, "src/memory/mod.rs", Language::Rust),
        ];
        let mut imports = vec![new_import(0, "crate::memory", "use")];

        resolve_imports(&files, &mut imports);

        assert_eq!(imports[0].resolved_file, Some(1));
    }

    #[test]
    fn derives_module_names() {
        assert_eq!(
            module_name(Path::new("src/memory/mod.rs"), Language::Rust),
            "src.memory"
        );
        assert_eq!(
            module_name(Path::new("src/widgets/index.ts"), Language::TypeScript),
            "src.widgets"
        );
        assert_eq!(
            module_name(Path::new("pkg/__init__.py"), Language::Python),
            "pkg"
        );
    }

    fn file(file_id: usize, path: &str, language: Language) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language,
            module: module_name(Path::new(path), language),
            lines: 1,
            bytes: 1,
            content_hash: String::new(),
        }
    }
}
