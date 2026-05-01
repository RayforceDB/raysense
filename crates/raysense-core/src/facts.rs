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
    pub call_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFact {
    pub file_id: usize,
    pub path: PathBuf,
    pub language: Language,
    pub language_name: String,
    pub module: String,
    pub lines: usize,
    pub bytes: usize,
    pub content_hash: String,
    /// Number of lines that look like comments (line-prefix or block-body).
    /// Heuristic — correctness is best-effort across languages.
    #[serde(default)]
    pub comment_lines: usize,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFact {
    pub call_id: usize,
    pub file_id: usize,
    pub caller_function: Option<usize>,
    pub target: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdgeFact {
    pub edge_id: usize,
    pub call_id: usize,
    pub caller_function: usize,
    pub callee_function: usize,
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
    pub calls: Vec<CallFact>,
    pub call_edges: Vec<CallEdgeFact>,
    #[serde(default)]
    pub types: Vec<TypeFact>,
    pub graph: crate::graph::GraphMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeFact {
    pub type_id: usize,
    pub file_id: usize,
    pub name: String,
    pub is_abstract: bool,
    pub line: usize,
    /// Base classes / interfaces named on the type's defining line.
    /// Empty when the language declares inheritance separately
    /// (e.g. Rust `impl Trait for Type`).
    #[serde(default)]
    pub bases: Vec<String>,
}
