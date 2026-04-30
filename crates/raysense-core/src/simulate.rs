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

use std::path::PathBuf;

use thiserror::Error;

use crate::facts::{
    CallEdgeFact, CallFact, EntryPointFact, ImportFact, ImportResolution, ScanReport, SnapshotFact,
    TypeFact,
};
use crate::graph::compute_graph_metrics;
use crate::health::RaysenseConfig;
use crate::scanner::{matching_plugin, module_name};

#[derive(Debug, Error)]
pub enum SimulateError {
    #[error("file not found in scan: {0}")]
    FileNotFound(String),
    #[error("file already exists at destination: {0}")]
    DestinationOccupied(String),
    #[error("no matching local edge from {from} to {to}")]
    EdgeNotFound { from: String, to: String },
    #[error("matching local edge already exists from {from} to {to}")]
    EdgeAlreadyExists { from: String, to: String },
    #[error("edge from {from} to {to} does not participate in a cycle")]
    EdgeNotInCycle { from: String, to: String },
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

    let mut new_types = Vec::new();
    for type_fact in &report.types {
        let Some(new_file_id) = file_remap[type_fact.file_id] else {
            continue;
        };
        new_types.push(TypeFact {
            type_id: new_types.len(),
            file_id: new_file_id,
            name: type_fact.name.clone(),
            is_abstract: type_fact.is_abstract,
            line: type_fact.line,
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
        types: new_types,
        graph,
    })
}

/// Produce a `ScanReport` representing the codebase as if `from_path` had been
/// moved to `to_path`. The file keeps its `file_id` (and so all imports/calls
/// referencing it stay valid); only `path`, `module`, and the
/// graph-derived metrics that depend on path/module change.
pub fn move_file(
    report: &ScanReport,
    config: &RaysenseConfig,
    from_path: &str,
    to_path: &str,
) -> Result<ScanReport, SimulateError> {
    let target_id = report
        .files
        .iter()
        .position(|file| file.path.to_string_lossy() == from_path)
        .ok_or_else(|| SimulateError::FileNotFound(from_path.to_string()))?;
    if report
        .files
        .iter()
        .any(|file| file.path.to_string_lossy() == to_path)
    {
        return Err(SimulateError::DestinationOccupied(to_path.to_string()));
    }

    let mut new_report = report.clone();
    let new_path = PathBuf::from(to_path);
    let language = new_report.files[target_id].language;
    let plugin = matching_plugin(&new_path, config);
    new_report.files[target_id].path = new_path.clone();
    new_report.files[target_id].module = module_name(&new_path, language, plugin.as_ref());
    new_report.snapshot.snapshot_id = format!(
        "{}+move_file:{}->{}",
        report.snapshot.snapshot_id, from_path, to_path
    );
    new_report.graph = compute_graph_metrics(&new_report.files, &new_report.imports);
    Ok(new_report)
}

/// Remove the local import edge from `from_path` to `to_path`. Returns
/// `EdgeNotFound` if no such local edge exists.
pub fn remove_edge(
    report: &ScanReport,
    from_path: &str,
    to_path: &str,
) -> Result<ScanReport, SimulateError> {
    let from_id = file_id_for_path(report, from_path)?;
    let to_id = file_id_for_path(report, to_path)?;

    let mut after = report.clone();
    let before_imports = after.imports.len();
    after.imports.retain(|import| {
        !(import.from_file == from_id
            && import.resolved_file == Some(to_id)
            && import.resolution == ImportResolution::Local)
    });
    if after.imports.len() == before_imports {
        return Err(SimulateError::EdgeNotFound {
            from: from_path.to_string(),
            to: to_path.to_string(),
        });
    }
    after.snapshot.import_count = after.imports.len();
    after.graph = compute_graph_metrics(&after.files, &after.imports);
    after.snapshot.snapshot_id = format!(
        "{}+remove_edge:{}->{}",
        report.snapshot.snapshot_id, from_path, to_path
    );
    Ok(after)
}

/// Add a local import edge from `from_path` to `to_path`. Returns
/// `EdgeAlreadyExists` if the same local edge is already present.
pub fn add_edge(
    report: &ScanReport,
    from_path: &str,
    to_path: &str,
) -> Result<ScanReport, SimulateError> {
    let from_id = file_id_for_path(report, from_path)?;
    let to_id = file_id_for_path(report, to_path)?;
    if report.imports.iter().any(|import| {
        import.from_file == from_id
            && import.resolved_file == Some(to_id)
            && import.resolution == ImportResolution::Local
    }) {
        return Err(SimulateError::EdgeAlreadyExists {
            from: from_path.to_string(),
            to: to_path.to_string(),
        });
    }

    let mut after = report.clone();
    after.imports.push(ImportFact {
        import_id: after.imports.len(),
        from_file: from_id,
        target: to_path.to_string(),
        kind: "what_if".to_string(),
        resolution: ImportResolution::Local,
        resolved_file: Some(to_id),
    });
    after.snapshot.import_count = after.imports.len();
    after.graph = compute_graph_metrics(&after.files, &after.imports);
    after.snapshot.snapshot_id = format!(
        "{}+add_edge:{}->{}",
        report.snapshot.snapshot_id, from_path, to_path
    );
    Ok(after)
}

/// Remove the local import edge from `from_path` to `to_path` and confirm the
/// reduction lowers the report's cycle count. Returns `EdgeNotFound` if the
/// edge does not exist, or `EdgeNotInCycle` if removal does not break a cycle
/// (i.e., the edge is not load-bearing for any cycle).
pub fn break_cycle(
    report: &ScanReport,
    from_path: &str,
    to_path: &str,
) -> Result<ScanReport, SimulateError> {
    let before_cycles = report.graph.cycle_count;
    let after = remove_edge(report, from_path, to_path)?;
    if after.graph.cycle_count >= before_cycles {
        return Err(SimulateError::EdgeNotInCycle {
            from: from_path.to_string(),
            to: to_path.to_string(),
        });
    }
    let mut after = after;
    after.snapshot.snapshot_id = format!(
        "{}+break_cycle:{}->{}",
        report.snapshot.snapshot_id, from_path, to_path
    );
    Ok(after)
}

/// One candidate edge whose removal would reduce the report's cycle count.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CycleBreakCandidate {
    pub from: String,
    pub to: String,
    pub cycle_count_before: usize,
    pub cycle_count_after: usize,
    pub cycle_count_reduction: usize,
}

/// Rank candidate local edges by how much each one's removal reduces the
/// report's cycle count. Considers up to `max_candidates` distinct local edges
/// (capped to avoid quadratic cost on large graphs); returns at most `limit`
/// recommendations sorted by reduction (descending), then path. Returns an
/// empty list when the report has no cycles.
pub fn break_cycle_recommendations(
    report: &ScanReport,
    limit: usize,
    max_candidates: usize,
) -> Vec<CycleBreakCandidate> {
    let baseline_cycles = report.graph.cycle_count;
    if baseline_cycles == 0 {
        return Vec::new();
    }

    let mut seen: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    let mut candidates = Vec::new();
    let mut considered = 0usize;
    for import in &report.imports {
        if considered >= max_candidates {
            break;
        }
        if import.resolution != ImportResolution::Local {
            continue;
        }
        let Some(to_id) = import.resolved_file else {
            continue;
        };
        if !seen.insert((import.from_file, to_id)) {
            continue;
        }
        let Some(from_file) = report.files.get(import.from_file) else {
            continue;
        };
        let Some(to_file) = report.files.get(to_id) else {
            continue;
        };
        let from_path = from_file.path.to_string_lossy().into_owned();
        let to_path = to_file.path.to_string_lossy().into_owned();
        considered += 1;

        let after_imports: Vec<ImportFact> = report
            .imports
            .iter()
            .filter(|other| {
                !(other.from_file == import.from_file
                    && other.resolved_file == Some(to_id)
                    && other.resolution == ImportResolution::Local)
            })
            .cloned()
            .collect();
        let after_graph = compute_graph_metrics(&report.files, &after_imports);
        if after_graph.cycle_count < baseline_cycles {
            candidates.push(CycleBreakCandidate {
                from: from_path,
                to: to_path,
                cycle_count_before: baseline_cycles,
                cycle_count_after: after_graph.cycle_count,
                cycle_count_reduction: baseline_cycles - after_graph.cycle_count,
            });
        }
    }

    candidates.sort_by(|a, b| {
        b.cycle_count_reduction
            .cmp(&a.cycle_count_reduction)
            .then_with(|| a.from.cmp(&b.from))
            .then_with(|| a.to.cmp(&b.to))
    });
    candidates.truncate(limit);
    candidates
}

fn file_id_for_path(report: &ScanReport, path: &str) -> Result<usize, SimulateError> {
    report
        .files
        .iter()
        .position(|file| file.path.to_string_lossy() == path)
        .ok_or_else(|| SimulateError::FileNotFound(path.to_string()))
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
            types: Vec::new(),
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
    fn move_file_updates_path_and_module() {
        let files = vec![file(0, "src/foo.rs"), file(1, "src/bar.rs")];
        let imports = vec![import(0, 0, Some(1))];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        let mut config = RaysenseConfig::default();
        config.scan.module_roots = vec!["src".to_string()];

        let after = move_file(&before, &config, "src/foo.rs", "lib/foo.rs").unwrap();

        let moved = after
            .files
            .iter()
            .find(|file| file.path == PathBuf::from("lib/foo.rs"))
            .expect("destination present");
        assert_eq!(moved.file_id, 0);
        assert!(!moved.module.contains("src"));
        assert_eq!(after.imports[0].from_file, 0);
        assert_eq!(after.imports[0].resolved_file, Some(1));
        assert!(after.snapshot.snapshot_id.contains("move_file"));
    }

    #[test]
    fn move_file_rejects_destination_collision() {
        let files = vec![file(0, "src/foo.rs"), file(1, "src/bar.rs")];
        let before = report(
            files,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let config = RaysenseConfig::default();
        let err = move_file(&before, &config, "src/foo.rs", "src/bar.rs").unwrap_err();
        assert!(matches!(err, SimulateError::DestinationOccupied(_)));
    }

    #[test]
    fn move_file_returns_error_for_unknown_source() {
        let before = report(
            vec![file(0, "src/foo.rs")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let config = RaysenseConfig::default();
        let err = move_file(&before, &config, "src/missing.rs", "src/dest.rs").unwrap_err();
        assert!(matches!(err, SimulateError::FileNotFound(_)));
    }

    #[test]
    fn break_cycle_removes_edge_and_lowers_cycle_count() {
        // Three-file cycle: a -> b -> c -> a. Remove c -> a to break it.
        let files = vec![
            file(0, "src/a.rs"),
            file(1, "src/b.rs"),
            file(2, "src/c.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1)),
            import(1, 1, Some(2)),
            import(2, 2, Some(0)),
        ];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(before.graph.cycle_count > 0);

        let after = break_cycle(&before, "src/c.rs", "src/a.rs").unwrap();
        assert!(after.graph.cycle_count < before.graph.cycle_count);
        assert_eq!(after.imports.len(), 2);
        assert!(after.snapshot.snapshot_id.contains("break_cycle"));
    }

    #[test]
    fn break_cycle_rejects_edge_not_in_cycle() {
        // a -> b, plus a separate cycle c -> d -> c.
        let files = vec![
            file(0, "src/a.rs"),
            file(1, "src/b.rs"),
            file(2, "src/c.rs"),
            file(3, "src/d.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1)),
            import(1, 2, Some(3)),
            import(2, 3, Some(2)),
        ];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let err = break_cycle(&before, "src/a.rs", "src/b.rs").unwrap_err();
        assert!(matches!(err, SimulateError::EdgeNotInCycle { .. }));
    }

    #[test]
    fn remove_edge_drops_matching_local_import() {
        let files = vec![file(0, "src/a.rs"), file(1, "src/b.rs")];
        let imports = vec![import(0, 0, Some(1))];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let after = remove_edge(&before, "src/a.rs", "src/b.rs").unwrap();
        assert_eq!(after.imports.len(), 0);
        assert!(after.snapshot.snapshot_id.contains("remove_edge"));
    }

    #[test]
    fn add_edge_creates_local_import() {
        let files = vec![file(0, "src/a.rs"), file(1, "src/b.rs")];
        let before = report(
            files,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let after = add_edge(&before, "src/a.rs", "src/b.rs").unwrap();
        assert_eq!(after.imports.len(), 1);
        let edge = &after.imports[0];
        assert_eq!(edge.from_file, 0);
        assert_eq!(edge.resolved_file, Some(1));
        assert_eq!(edge.kind, "what_if");
        assert!(matches!(
            add_edge(&after, "src/a.rs", "src/b.rs").unwrap_err(),
            SimulateError::EdgeAlreadyExists { .. }
        ));
    }

    #[test]
    fn break_cycle_recommendations_empty_when_acyclic() {
        let files = vec![file(0, "src/a.rs"), file(1, "src/b.rs")];
        let imports = vec![import(0, 0, Some(1))];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(before.graph.cycle_count, 0);
        let recs = break_cycle_recommendations(&before, 5, 100);
        assert!(recs.is_empty());
    }

    #[test]
    fn break_cycle_recommendations_ranks_edges_by_reduction() {
        // Two cycles share file b: a -> b -> a, and c -> b -> c via b -> c, c -> b.
        // Removing edges in or out of b should reduce cycle count.
        let files = vec![
            file(0, "src/a.rs"),
            file(1, "src/b.rs"),
            file(2, "src/c.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1)), // a -> b
            import(1, 1, Some(0)), // b -> a (cycle 1)
            import(2, 1, Some(2)), // b -> c
            import(3, 2, Some(1)), // c -> b (cycle 2)
        ];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(before.graph.cycle_count > 0);

        let recs = break_cycle_recommendations(&before, 10, 100);
        assert!(!recs.is_empty());
        // Highest-reduction recommendation must come first.
        let top = &recs[0];
        assert!(top.cycle_count_reduction >= 1);
        assert_eq!(top.cycle_count_before, before.graph.cycle_count);
        // Reductions must be monotonically non-increasing across the list.
        for window in recs.windows(2) {
            assert!(window[0].cycle_count_reduction >= window[1].cycle_count_reduction);
        }
    }

    #[test]
    fn break_cycle_recommendations_respects_limit() {
        let files = vec![
            file(0, "src/a.rs"),
            file(1, "src/b.rs"),
            file(2, "src/c.rs"),
        ];
        let imports = vec![
            import(0, 0, Some(1)),
            import(1, 1, Some(2)),
            import(2, 2, Some(0)),
        ];
        let before = report(
            files,
            Vec::new(),
            imports,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let recs = break_cycle_recommendations(&before, 1, 100);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn break_cycle_rejects_missing_edge() {
        let files = vec![file(0, "src/a.rs"), file(1, "src/b.rs")];
        let before = report(
            files,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let err = break_cycle(&before, "src/a.rs", "src/b.rs").unwrap_err();
        assert!(matches!(err, SimulateError::EdgeNotFound { .. }));
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
