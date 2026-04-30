use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    C,
    Cpp,
    Python,
    Rust,
    TypeScript,
    Unknown,
}

impl Language {
    pub fn from_path(path: &std::path::Path) -> Self {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("c") | Some("h") => Self::C,
            Some("cc") | Some("cpp") | Some("cxx") | Some("hh") | Some("hpp") | Some("hxx") => {
                Self::Cpp
            }
            Some("py") => Self::Python,
            Some("rs") => Self::Rust,
            Some("ts") | Some("tsx") | Some("js") | Some("jsx") => Self::TypeScript,
            _ => Self::Unknown,
        }
    }

    pub fn is_supported(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFact {
    pub snapshot_id: String,
    pub root: PathBuf,
    pub file_count: usize,
    pub function_count: usize,
    pub import_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFact {
    pub file_id: usize,
    pub path: PathBuf,
    pub language: Language,
    pub module: String,
    pub lines: usize,
    pub bytes: usize,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionFact {
    pub function_id: usize,
    pub file_id: usize,
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointFact {
    pub entry_id: usize,
    pub file_id: usize,
    pub kind: EntryPointKind,
    pub symbol: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryPointKind {
    Binary,
    Example,
    Test,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportFact {
    pub import_id: usize,
    pub from_file: usize,
    pub target: String,
    pub kind: String,
    pub resolution: ImportResolution,
    pub resolved_file: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportResolution {
    External,
    Local,
    System,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub snapshot: SnapshotFact,
    pub files: Vec<FileFact>,
    pub functions: Vec<FunctionFact>,
    pub entry_points: Vec<EntryPointFact>,
    pub imports: Vec<ImportFact>,
    pub graph: crate::graph::GraphMetrics,
}
