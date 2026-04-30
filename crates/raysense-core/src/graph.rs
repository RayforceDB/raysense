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

use crate::facts::{FileFact, ImportFact};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphMetrics {
    pub edge_count: usize,
    pub resolved_edge_count: usize,
    pub cycle_count: usize,
    pub max_fan_in: usize,
    pub max_fan_out: usize,
}

pub fn compute_graph_metrics(files: &[FileFact], imports: &[ImportFact]) -> GraphMetrics {
    let mut adjacency: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut fan_in: HashMap<usize, usize> = HashMap::new();
    let mut fan_out: HashMap<usize, usize> = HashMap::new();
    let mut resolved_edge_count = 0;

    for import in imports {
        if let Some(to_file) = import.resolved_file {
            resolved_edge_count += 1;
            adjacency.entry(import.from_file).or_default().push(to_file);
            *fan_in.entry(to_file).or_default() += 1;
            *fan_out.entry(import.from_file).or_default() += 1;
        }
    }

    let cycle_count = count_cycle_participants(files, &adjacency);

    GraphMetrics {
        edge_count: imports.len(),
        resolved_edge_count,
        cycle_count,
        max_fan_in: fan_in.values().copied().max().unwrap_or(0),
        max_fan_out: fan_out.values().copied().max().unwrap_or(0),
    }
}

fn count_cycle_participants(files: &[FileFact], adjacency: &HashMap<usize, Vec<usize>>) -> usize {
    files
        .iter()
        .filter(|file| reaches_itself(file.file_id, adjacency))
        .count()
}

fn reaches_itself(start: usize, adjacency: &HashMap<usize, Vec<usize>>) -> bool {
    let mut stack = adjacency.get(&start).cloned().unwrap_or_default();
    let mut seen = HashSet::new();

    while let Some(next) = stack.pop() {
        if next == start {
            return true;
        }
        if seen.insert(next) {
            if let Some(children) = adjacency.get(&next) {
                stack.extend(children);
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{FileFact, ImportFact, ImportResolution, Language};
    use std::path::PathBuf;

    #[test]
    fn counts_cycle_participants() {
        let files = vec![file(0, "a.rs"), file(1, "b.rs"), file(2, "c.rs")];
        let imports = vec![edge(0, 0, 1), edge(1, 1, 0), edge(2, 2, 1)];

        let metrics = compute_graph_metrics(&files, &imports);

        assert_eq!(metrics.edge_count, 3);
        assert_eq!(metrics.resolved_edge_count, 3);
        assert_eq!(metrics.cycle_count, 2);
        assert_eq!(metrics.max_fan_in, 2);
        assert_eq!(metrics.max_fan_out, 1);
    }

    fn file(file_id: usize, path: &str) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language: Language::Rust,
            module: path.trim_end_matches(".rs").replace('/', "."),
            lines: 1,
            bytes: 1,
            content_hash: String::new(),
        }
    }

    fn edge(import_id: usize, from_file: usize, to_file: usize) -> ImportFact {
        ImportFact {
            import_id,
            from_file,
            target: String::new(),
            kind: "use".to_string(),
            resolution: ImportResolution::Local,
            resolved_file: Some(to_file),
        }
    }
}
