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

use thiserror::Error;

use crate::facts::{CallEdgeFact, CallFact, EntryPointFact, ImportFact, ScanReport, SnapshotFact};
use crate::graph::compute_graph_metrics;

#[derive(Debug, Error)]
pub enum SimulateError {
    #[error("file not found in scan: {0}")]
    FileNotFound(String),
}

/// Produce a `ScanReport` representing the codebase as if `file_path` did not
/// exist. All facts referencing the file (and any functions defined in it) are
/// dropped, and remaining file/function/call ids are renumbered so downstream
/// consumers that index by id continue to work.
pub fn remove_file(report: &ScanReport, file_path: &str) -> Result<ScanReport, SimulateError> {
    let target_id = report
        .files
        .iter()
        .position(|file| file.path.to_string_lossy() == file_path)
        .ok_or_else(|| SimulateError::FileNotFound(file_path.to_string()))?;

    let mut file_remap: Vec<Option<usize>> = vec![None; report.files.len()];
    let mut new_files = Vec::with_capacity(report.files.len().saturating_sub(1));
    for (old_id, file) in report.files.iter().enumerate() {
        if old_id == target_id {
            continue;
        }
        let new_id = new_files.len();
        file_remap[old_id] = Some(new_id);
        let mut new_file = file.clone();
        new_file.file_id = new_id;
        new_files.push(new_file);
    }

    let mut function_remap: Vec<Option<usize>> = vec![None; report.functions.len()];
    let mut new_functions = Vec::new();
    for (old_id, function) in report.functions.iter().enumerate() {
        let Some(new_file_id) = file_remap[function.file_id] else {
            continue;
        };
        let new_id = new_functions.len();
        function_remap[old_id] = Some(new_id);
        let mut new_function = function.clone();
        new_function.function_id = new_id;
        new_function.file_id = new_file_id;
        new_functions.push(new_function);
    }

    let mut new_entry_points = Vec::new();
    for entry in &report.entry_points {
        let Some(new_file_id) = file_remap[entry.file_id] else {
            continue;
        };
        new_entry_points.push(EntryPointFact {
            entry_id: new_entry_points.len(),
            file_id: new_file_id,
            kind: entry.kind,
            symbol: entry.symbol.clone(),
        });
    }

    let mut new_imports = Vec::new();
    for import in &report.imports {
        let Some(new_from) = file_remap[import.from_file] else {
            continue;
        };
        let new_resolved = match import.resolved_file {
            Some(resolved) => match file_remap[resolved] {
                Some(remapped) => Some(remapped),
                None => continue,
            },
            None => None,
        };
        new_imports.push(ImportFact {
            import_id: new_imports.len(),
            from_file: new_from,
            target: import.target.clone(),
            kind: import.kind.clone(),
            resolution: import.resolution,
            resolved_file: new_resolved,
        });
    }

    let mut call_remap: Vec<Option<usize>> = vec![None; report.calls.len()];
    let mut new_calls = Vec::new();
    for (old_id, call) in report.calls.iter().enumerate() {
        let Some(new_file_id) = file_remap[call.file_id] else {
            continue;
        };
        let new_caller = match call.caller_function {
            Some(caller) => match function_remap[caller] {
                Some(remapped) => Some(remapped),
                None => continue,
            },
            None => None,
        };
        let new_id = new_calls.len();
        call_remap[old_id] = Some(new_id);
        new_calls.push(CallFact {
            call_id: new_id,
            file_id: new_file_id,
            caller_function: new_caller,
            target: call.target.clone(),
            line: call.line,
        });
    }

    let mut new_call_edges = Vec::new();
    for edge in &report.call_edges {
        let (Some(new_caller), Some(new_callee)) = (
            function_remap[edge.caller_function],
            function_remap[edge.callee_function],
        ) else {
            continue;
        };
        let Some(new_call_id) = call_remap.get(edge.call_id).copied().flatten() else {
            continue;
        };
        new_call_edges.push(CallEdgeFact {
            edge_id: new_call_edges.len(),
            call_id: new_call_id,
            caller_function: new_caller,
            callee_function: new_callee,
        });
    }

    let graph = compute_graph_metrics(&new_files, &new_imports);

    Ok(ScanReport {
        snapshot: SnapshotFact {
            snapshot_id: format!("{}+remove_file:{}", report.snapshot.snapshot_id, file_path),
            root: report.snapshot.root.clone(),
            file_count: new_files.len(),
            function_count: new_functions.len(),
            import_count: new_imports.len(),
            call_count: new_calls.len(),
        },
        files: new_files,
        functions: new_functions,
        entry_points: new_entry_points,
        imports: new_imports,
        calls: new_calls,
        call_edges: new_call_edges,
        graph,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{
        CallEdgeFact, CallFact, EntryPointFact, EntryPointKind, FileFact, FunctionFact, ImportFact,
        ImportResolution, Language,
    };
    use std::path::PathBuf;

    fn file(file_id: usize, path: &str) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language: Language::Rust,
            language_name: "rust".to_string(),
            module: path.trim_end_matches(".rs").to_string(),
            lines: 100,
            bytes: 100,
            content_hash: String::new(),
        }
    }

    fn function(function_id: usize, file_id: usize, name: &str) -> FunctionFact {
        FunctionFact {
            function_id,
            file_id,
            name: name.to_string(),
            start_line: 1,
            end_line: 10,
        }
    }

    fn import(import_id: usize, from_file: usize, resolved: Option<usize>) -> ImportFact {
        ImportFact {
            import_id,
            from_file,
            target: String::new(),
            kind: "use".to_string(),
            resolution: ImportResolution::Local,
            resolved_file: resolved,
        }
    }

    fn report(
        files: Vec<FileFact>,
        functions: Vec<FunctionFact>,
        imports: Vec<ImportFact>,
        calls: Vec<CallFact>,
        call_edges: Vec<CallEdgeFact>,
        entry_points: Vec<EntryPointFact>,
    ) -> ScanReport {
        let graph = compute_graph_metrics(&files, &imports);
        ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "before".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: functions.len(),
                import_count: imports.len(),
                call_count: calls.len(),
            },
            files,
            functions,
            entry_points,
            imports,
            calls,
            call_edges,
            graph,
        }
    }

    #[test]
    fn remove_file_drops_file_and_dependent_facts() {
        // Three files: a -> b -> c. Remove b: a's import to b is dropped,
        // c's incoming import from b is dropped.
        let files = vec![
            file(0, "src/a.rs"),
            file(1, "src/b.rs"),
            file(2, "src/c.rs"),
        ];
        let functions = vec![
            function(0, 0, "a_main"),
            function(1, 1, "b_helper"),
            function(2, 2, "c_util"),
        ];
        let imports = vec![import(0, 0, Some(1)), import(1, 1, Some(2))];
        let calls = vec![CallFact {
            call_id: 0,
            file_id: 1,
            caller_function: Some(1),
            target: "c_util".to_string(),
            line: 5,
        }];
        let call_edges = vec![CallEdgeFact {
            edge_id: 0,
            call_id: 0,
            caller_function: 1,
            callee_function: 2,
        }];
        let entry_points = vec![EntryPointFact {
            entry_id: 0,
            file_id: 1,
            kind: EntryPointKind::Test,
            symbol: "b_test".to_string(),
        }];
        let before = report(files, functions, imports, calls, call_edges, entry_points);

        let after = remove_file(&before, "src/b.rs").unwrap();

        assert_eq!(after.files.len(), 2);
        assert_eq!(after.functions.len(), 2);
        assert_eq!(after.imports.len(), 0);
        assert_eq!(after.calls.len(), 0);
        assert_eq!(after.call_edges.len(), 0);
        assert_eq!(after.entry_points.len(), 0);

        // ids must be sequential after renumbering.
        for (idx, file) in after.files.iter().enumerate() {
            assert_eq!(file.file_id, idx);
        }
        for (idx, function) in after.functions.iter().enumerate() {
            assert_eq!(function.function_id, idx);
        }

        // surviving function for src/c.rs must point at the new file_id.
        let c_file_id = after
            .files
            .iter()
            .find(|file| file.path == PathBuf::from("src/c.rs"))
            .map(|file| file.file_id)
            .expect("src/c.rs survives");
        assert!(after
            .functions
            .iter()
            .any(|function| function.file_id == c_file_id));

        assert_eq!(after.snapshot.file_count, 2);
        assert!(after.snapshot.snapshot_id.contains("+remove_file:src/b.rs"));
    }

    #[test]
    fn remove_file_preserves_unrelated_edges() {
        let files = vec![
            file(0, "src/a.rs"),
            file(1, "src/b.rs"),
            file(2, "src/c.rs"),
            file(3, "src/d.rs"),
        ];
        // a -> b, c -> d. Removing b leaves c -> d intact.
        let imports = vec![import(0, 0, Some(1)), import(1, 2, Some(3))];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let after = remove_file(&before, "src/b.rs").unwrap();

        assert_eq!(after.files.len(), 3);
        assert_eq!(after.imports.len(), 1);
        let preserved = &after.imports[0];
        let from = &after.files[preserved.from_file];
        let to = preserved.resolved_file.map(|id| &after.files[id]);
        assert_eq!(from.path, PathBuf::from("src/c.rs"));
        assert_eq!(to.unwrap().path, PathBuf::from("src/d.rs"));
    }

    #[test]
    fn remove_file_returns_error_for_unknown_path() {
        let before = report(
            vec![file(0, "src/a.rs")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let err = remove_file(&before, "src/missing.rs").unwrap_err();
        assert!(matches!(err, SimulateError::FileNotFound(_)));
    }
}
