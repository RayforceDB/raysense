use crate::facts::{ImportResolution, ScanReport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub score: u8,
    pub coverage_score: u8,
    pub structural_score: u8,
    pub resolution: ResolutionBreakdown,
    pub hotspots: Vec<FileHotspot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolutionBreakdown {
    pub local: usize,
    pub external: usize,
    pub system: usize,
    pub unresolved: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHotspot {
    pub file_id: usize,
    pub path: String,
    pub module: String,
    pub fan_in: usize,
    pub fan_out: usize,
}

pub fn compute_health(report: &ScanReport) -> HealthSummary {
    let resolution = resolution_breakdown(report);
    let hotspots = hotspots(report);

    HealthSummary {
        score: health_score(report, &resolution),
        coverage_score: coverage_score(report, &resolution),
        structural_score: structural_score(report),
        resolution,
        hotspots,
    }
}

fn resolution_breakdown(report: &ScanReport) -> ResolutionBreakdown {
    let mut breakdown = ResolutionBreakdown::default();
    for import in &report.imports {
        match import.resolution {
            ImportResolution::External => breakdown.external += 1,
            ImportResolution::Local => breakdown.local += 1,
            ImportResolution::System => breakdown.system += 1,
            ImportResolution::Unresolved => breakdown.unresolved += 1,
        }
    }
    breakdown
}

fn health_score(report: &ScanReport, resolution: &ResolutionBreakdown) -> u8 {
    coverage_score(report, resolution).saturating_add(structural_score(report)) / 2
}

fn coverage_score(report: &ScanReport, resolution: &ResolutionBreakdown) -> u8 {
    let mut score = 100i32;
    if report.snapshot.import_count > 0 {
        let unresolved_pct = (resolution.unresolved as f64 / report.snapshot.import_count as f64
            * 100.0)
            .round() as i32;
        score -= unresolved_pct.min(70);
    }
    score.clamp(0, 100) as u8
}

fn structural_score(report: &ScanReport) -> u8 {
    let mut score = 100i32;
    score -= (report.graph.cycle_count as i32 * 20).min(80);
    score.clamp(0, 100) as u8
}

fn hotspots(report: &ScanReport) -> Vec<FileHotspot> {
    let mut fan_in: HashMap<usize, usize> = HashMap::new();
    let mut fan_out: HashMap<usize, usize> = HashMap::new();

    for import in &report.imports {
        if let Some(to_file) = import.resolved_file {
            *fan_in.entry(to_file).or_default() += 1;
            *fan_out.entry(import.from_file).or_default() += 1;
        }
    }

    let mut hotspots: Vec<FileHotspot> = report
        .files
        .iter()
        .map(|file| FileHotspot {
            file_id: file.file_id,
            path: file.path.to_string_lossy().into_owned(),
            module: file.module.clone(),
            fan_in: fan_in.get(&file.file_id).copied().unwrap_or(0),
            fan_out: fan_out.get(&file.file_id).copied().unwrap_or(0),
        })
        .filter(|hotspot| hotspot.fan_in > 0 || hotspot.fan_out > 0)
        .collect();

    hotspots.sort_by(|a, b| {
        let a_total = a.fan_in + a.fan_out;
        let b_total = b.fan_in + b.fan_out;
        b_total
            .cmp(&a_total)
            .then_with(|| b.fan_in.cmp(&a.fan_in))
            .then_with(|| a.path.cmp(&b.path))
    });
    hotspots.truncate(10);
    hotspots
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{FileFact, ImportFact, Language, SnapshotFact};
    use crate::graph::compute_graph_metrics;
    use std::path::PathBuf;

    #[test]
    fn computes_resolution_breakdown_and_hotspots() {
        let files = vec![file(0, "a.rs"), file(1, "b.rs")];
        let imports = vec![
            import(0, 0, Some(1), ImportResolution::Local),
            import(1, 0, None, ImportResolution::External),
            import(2, 1, None, ImportResolution::Unresolved),
        ];
        let graph = compute_graph_metrics(&files, &imports);
        let report = ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "test".to_string(),
                root: PathBuf::from("."),
                file_count: files.len(),
                function_count: 0,
                import_count: imports.len(),
            },
            files,
            functions: Vec::new(),
            imports,
            graph,
        };

        let health = compute_health(&report);

        assert_eq!(health.resolution.local, 1);
        assert_eq!(health.resolution.external, 1);
        assert_eq!(health.resolution.unresolved, 1);
        assert_eq!(health.hotspots[0].path, "b.rs");
        assert!(health.coverage_score < 100);
        assert_eq!(health.structural_score, 100);
        assert!(health.score < 100);
    }

    fn file(file_id: usize, path: &str) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language: Language::Rust,
            module: path.trim_end_matches(".rs").to_string(),
            lines: 1,
            bytes: 1,
            content_hash: String::new(),
        }
    }

    fn import(
        import_id: usize,
        from_file: usize,
        resolved_file: Option<usize>,
        resolution: ImportResolution,
    ) -> ImportFact {
        ImportFact {
            import_id,
            from_file,
            target: String::new(),
            kind: "use".to_string(),
            resolution,
            resolved_file,
        }
    }
}
