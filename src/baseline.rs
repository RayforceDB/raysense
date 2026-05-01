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

use crate::facts::ScanReport;
use crate::health::{FileHotspot, HealthSummary, RuleFinding};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectBaseline {
    pub schema_version: u32,
    pub root: PathBuf,
    pub snapshot_id: String,
    pub file_count: usize,
    pub function_count: usize,
    pub import_count: usize,
    pub call_count: usize,
    pub call_edge_count: usize,
    pub score: u8,
    pub coverage_score: u8,
    pub structural_score: u8,
    pub rules: Vec<RuleFinding>,
    pub hotspots: Vec<FileHotspot>,
    pub module_edges: Vec<BaselineModuleEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BaselineModuleEdge {
    pub from_module: String,
    pub to_module: String,
    pub edges: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineDiff {
    pub score_delta: i16,
    pub coverage_score_delta: i16,
    pub structural_score_delta: i16,
    pub file_count_delta: isize,
    pub function_count_delta: isize,
    pub import_count_delta: isize,
    pub call_count_delta: isize,
    pub call_edge_count_delta: isize,
    pub added_rules: Vec<RuleFinding>,
    pub removed_rules: Vec<RuleFinding>,
    pub added_hotspots: Vec<FileHotspot>,
    pub removed_hotspots: Vec<FileHotspot>,
    pub added_module_edges: Vec<BaselineModuleEdge>,
    pub removed_module_edges: Vec<BaselineModuleEdge>,
    pub changed_module_edges: Vec<ModuleEdgeDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEdgeDelta {
    pub from_module: String,
    pub to_module: String,
    pub before: usize,
    pub after: usize,
    pub delta: isize,
}

pub fn build_baseline(report: &ScanReport, health: &HealthSummary) -> ProjectBaseline {
    ProjectBaseline {
        schema_version: 1,
        root: report.snapshot.root.clone(),
        snapshot_id: report.snapshot.snapshot_id.clone(),
        file_count: report.snapshot.file_count,
        function_count: report.snapshot.function_count,
        import_count: report.snapshot.import_count,
        call_count: report.snapshot.call_count,
        call_edge_count: report.call_edges.len(),
        score: health.score,
        coverage_score: health.coverage_score,
        structural_score: health.structural_score,
        rules: health.rules.clone(),
        hotspots: health.hotspots.clone(),
        module_edges: health
            .metrics
            .dsm
            .top_module_edges
            .iter()
            .map(|edge| BaselineModuleEdge {
                from_module: edge.from_module.clone(),
                to_module: edge.to_module.clone(),
                edges: edge.edges,
            })
            .collect(),
    }
}

pub fn diff_baselines(before: &ProjectBaseline, after: &ProjectBaseline) -> BaselineDiff {
    let before_rules = keyed_rules(&before.rules);
    let after_rules = keyed_rules(&after.rules);
    let before_hotspots = keyed_hotspots(&before.hotspots);
    let after_hotspots = keyed_hotspots(&after.hotspots);
    let before_module_edges = keyed_module_edges(&before.module_edges);
    let after_module_edges = keyed_module_edges(&after.module_edges);

    BaselineDiff {
        score_delta: after.score as i16 - before.score as i16,
        coverage_score_delta: after.coverage_score as i16 - before.coverage_score as i16,
        structural_score_delta: after.structural_score as i16 - before.structural_score as i16,
        file_count_delta: after.file_count as isize - before.file_count as isize,
        function_count_delta: after.function_count as isize - before.function_count as isize,
        import_count_delta: after.import_count as isize - before.import_count as isize,
        call_count_delta: after.call_count as isize - before.call_count as isize,
        call_edge_count_delta: after.call_edge_count as isize - before.call_edge_count as isize,
        added_rules: added_values(&before_rules, &after_rules),
        removed_rules: removed_values(&before_rules, &after_rules),
        added_hotspots: added_values(&before_hotspots, &after_hotspots),
        removed_hotspots: removed_values(&before_hotspots, &after_hotspots),
        added_module_edges: added_values(&before_module_edges, &after_module_edges),
        removed_module_edges: removed_values(&before_module_edges, &after_module_edges),
        changed_module_edges: changed_module_edges(&before_module_edges, &after_module_edges),
    }
}

fn keyed_rules(rules: &[RuleFinding]) -> BTreeMap<String, RuleFinding> {
    rules
        .iter()
        .map(|rule| {
            (
                format!(
                    "{}\u{1f}{}\u{1f}{}\u{1f}{:?}",
                    rule.code, rule.path, rule.message, rule.severity
                ),
                rule.clone(),
            )
        })
        .collect()
}

fn keyed_hotspots(hotspots: &[FileHotspot]) -> BTreeMap<String, FileHotspot> {
    hotspots
        .iter()
        .map(|hotspot| (hotspot.path.clone(), hotspot.clone()))
        .collect()
}

fn keyed_module_edges(edges: &[BaselineModuleEdge]) -> BTreeMap<String, BaselineModuleEdge> {
    edges
        .iter()
        .map(|edge| {
            (
                format!("{}\u{1f}{}", edge.from_module, edge.to_module),
                edge.clone(),
            )
        })
        .collect()
}

fn added_values<T: Clone>(before: &BTreeMap<String, T>, after: &BTreeMap<String, T>) -> Vec<T> {
    after
        .iter()
        .filter(|(key, _)| !before.contains_key(*key))
        .map(|(_, value)| value.clone())
        .collect()
}

fn removed_values<T: Clone>(before: &BTreeMap<String, T>, after: &BTreeMap<String, T>) -> Vec<T> {
    before
        .iter()
        .filter(|(key, _)| !after.contains_key(*key))
        .map(|(_, value)| value.clone())
        .collect()
}

fn changed_module_edges(
    before: &BTreeMap<String, BaselineModuleEdge>,
    after: &BTreeMap<String, BaselineModuleEdge>,
) -> Vec<ModuleEdgeDelta> {
    before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|key| {
            let before = before.get(key)?;
            let after = after.get(key)?;
            if before.edges == after.edges {
                return None;
            }
            Some(ModuleEdgeDelta {
                from_module: after.from_module.clone(),
                to_module: after.to_module.clone(),
                before: before.edges,
                after: after.edges,
                delta: after.edges as isize - before.edges as isize,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::RuleSeverity;

    #[test]
    fn diffs_baseline_score_and_rules() {
        let before = baseline(90, vec![rule("old")], vec![edge("a", "b", 1)]);
        let after = baseline(95, vec![rule("new")], vec![edge("a", "b", 3)]);

        let diff = diff_baselines(&before, &after);

        assert_eq!(diff.score_delta, 5);
        assert_eq!(diff.added_rules.len(), 1);
        assert_eq!(diff.added_rules[0].code, "new");
        assert_eq!(diff.removed_rules.len(), 1);
        assert_eq!(diff.changed_module_edges.len(), 1);
        assert_eq!(diff.changed_module_edges[0].delta, 2);
    }

    fn baseline(
        score: u8,
        rules: Vec<RuleFinding>,
        module_edges: Vec<BaselineModuleEdge>,
    ) -> ProjectBaseline {
        ProjectBaseline {
            schema_version: 1,
            root: PathBuf::from("."),
            snapshot_id: String::new(),
            file_count: 0,
            function_count: 0,
            import_count: 0,
            call_count: 0,
            call_edge_count: 0,
            score,
            coverage_score: score,
            structural_score: score,
            rules,
            hotspots: Vec::new(),
            module_edges,
        }
    }

    fn rule(code: &str) -> RuleFinding {
        RuleFinding {
            severity: RuleSeverity::Info,
            code: code.to_string(),
            path: "src/lib.rs".to_string(),
            message: "message".to_string(),
        }
    }

    fn edge(from: &str, to: &str, edges: usize) -> BaselineModuleEdge {
        BaselineModuleEdge {
            from_module: from.to_string(),
            to_module: to.to_string(),
            edges,
        }
    }
}
