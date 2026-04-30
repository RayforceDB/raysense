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

use raysense_core::{compute_health_with_config, HealthSummary, RaysenseConfig, ScanReport};
use std::ffi::CString;
use std::ptr::NonNull;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("rayforce symbol table initialization failed with code {0}")]
    SymbolInit(i32),
    #[error("rayforce returned null while building {0}")]
    Null(&'static str),
    #[error("string contains an interior null byte: {0}")]
    StringNul(#[from] std::ffi::NulError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableSummary {
    pub columns: i64,
    pub rows: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySummary {
    pub files: TableSummary,
    pub functions: TableSummary,
    pub entry_points: TableSummary,
    pub imports: TableSummary,
    pub calls: TableSummary,
    pub call_edges: TableSummary,
    pub health: TableSummary,
    pub hotspots: TableSummary,
    pub rules: TableSummary,
    pub module_edges: TableSummary,
    pub changed_files: TableSummary,
}

pub struct RayMemory {
    files: RayObject,
    functions: RayObject,
    entry_points: RayObject,
    imports: RayObject,
    calls: RayObject,
    call_edges: RayObject,
    health: RayObject,
    hotspots: RayObject,
    rules: RayObject,
    module_edges: RayObject,
    changed_files: RayObject,
}

impl RayMemory {
    pub fn from_report(report: &ScanReport) -> Result<Self, MemoryError> {
        Self::from_report_with_config(report, &RaysenseConfig::default())
    }

    pub fn from_report_with_config(
        report: &ScanReport,
        config: &RaysenseConfig,
    ) -> Result<Self, MemoryError> {
        init_symbols()?;
        let health = compute_health_with_config(report, config);

        Ok(Self {
            files: build_files_table(report)?,
            functions: build_functions_table(report)?,
            entry_points: build_entry_points_table(report)?,
            imports: build_imports_table(report)?,
            calls: build_calls_table(report)?,
            call_edges: build_call_edges_table(report)?,
            health: build_health_table(report, &health)?,
            hotspots: build_hotspots_table(&health)?,
            rules: build_rules_table(&health)?,
            module_edges: build_module_edges_table(&health)?,
            changed_files: build_changed_files_table(&health)?,
        })
    }

    pub fn summary(&self) -> MemorySummary {
        MemorySummary {
            files: table_summary(self.files.as_ptr()),
            functions: table_summary(self.functions.as_ptr()),
            entry_points: table_summary(self.entry_points.as_ptr()),
            imports: table_summary(self.imports.as_ptr()),
            calls: table_summary(self.calls.as_ptr()),
            call_edges: table_summary(self.call_edges.as_ptr()),
            health: table_summary(self.health.as_ptr()),
            hotspots: table_summary(self.hotspots.as_ptr()),
            rules: table_summary(self.rules.as_ptr()),
            module_edges: table_summary(self.module_edges.as_ptr()),
            changed_files: table_summary(self.changed_files.as_ptr()),
        }
    }
}

struct RayObject {
    ptr: NonNull<rayforce_sys::ray_t>,
}

impl RayObject {
    fn new(ptr: *mut rayforce_sys::ray_t, context: &'static str) -> Result<Self, MemoryError> {
        NonNull::new(ptr)
            .map(|ptr| Self { ptr })
            .ok_or(MemoryError::Null(context))
    }

    fn as_ptr(&self) -> *mut rayforce_sys::ray_t {
        self.ptr.as_ptr()
    }

    fn into_raw(self) -> *mut rayforce_sys::ray_t {
        let ptr = self.ptr.as_ptr();
        std::mem::forget(self);
        ptr
    }
}

impl Drop for RayObject {
    fn drop(&mut self) {
        unsafe {
            rayforce_sys::ray_release(self.ptr.as_ptr());
        }
    }
}

fn init_symbols() -> Result<(), MemoryError> {
    let err = unsafe { rayforce_sys::ray_sym_init() };
    if err == rayforce_sys::RAY_OK {
        Ok(())
    } else {
        Err(MemoryError::SymbolInit(err))
    }
}

fn build_files_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let ids = i64_vec(
        report.files.len(),
        report.files.iter().map(|file| file.file_id as i64),
    )?;
    let paths = str_vec(
        report.files.len(),
        report
            .files
            .iter()
            .map(|file| file.path.to_string_lossy().into_owned()),
    )?;
    let languages = str_vec(
        report.files.len(),
        report
            .files
            .iter()
            .map(|file| format!("{:?}", file.language).to_lowercase()),
    )?;
    let modules = str_vec(
        report.files.len(),
        report.files.iter().map(|file| file.module.clone()),
    )?;
    let lines = i64_vec(
        report.files.len(),
        report.files.iter().map(|file| file.lines as i64),
    )?;
    let bytes = i64_vec(
        report.files.len(),
        report.files.iter().map(|file| file.bytes as i64),
    )?;
    let hashes = str_vec(
        report.files.len(),
        report.files.iter().map(|file| file.content_hash.clone()),
    )?;

    table(
        7,
        [
            ("file_id", ids),
            ("path", paths),
            ("language", languages),
            ("module", modules),
            ("lines", lines),
            ("bytes", bytes),
            ("content_hash", hashes),
        ],
    )
}

fn build_functions_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let ids = i64_vec(
        report.functions.len(),
        report
            .functions
            .iter()
            .map(|function| function.function_id as i64),
    )?;
    let file_ids = i64_vec(
        report.functions.len(),
        report
            .functions
            .iter()
            .map(|function| function.file_id as i64),
    )?;
    let names = str_vec(
        report.functions.len(),
        report
            .functions
            .iter()
            .map(|function| function.name.clone()),
    )?;
    let start_lines = i64_vec(
        report.functions.len(),
        report
            .functions
            .iter()
            .map(|function| function.start_line as i64),
    )?;
    let end_lines = i64_vec(
        report.functions.len(),
        report
            .functions
            .iter()
            .map(|function| function.end_line as i64),
    )?;

    table(
        5,
        [
            ("function_id", ids),
            ("file_id", file_ids),
            ("name", names),
            ("start_line", start_lines),
            ("end_line", end_lines),
        ],
    )
}

fn build_entry_points_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let ids = i64_vec(
        report.entry_points.len(),
        report
            .entry_points
            .iter()
            .map(|entry| entry.entry_id as i64),
    )?;
    let file_ids = i64_vec(
        report.entry_points.len(),
        report.entry_points.iter().map(|entry| entry.file_id as i64),
    )?;
    let kinds = str_vec(
        report.entry_points.len(),
        report
            .entry_points
            .iter()
            .map(|entry| format!("{:?}", entry.kind).to_lowercase()),
    )?;
    let symbols = str_vec(
        report.entry_points.len(),
        report.entry_points.iter().map(|entry| entry.symbol.clone()),
    )?;

    table(
        4,
        [
            ("entry_id", ids),
            ("file_id", file_ids),
            ("kind", kinds),
            ("symbol", symbols),
        ],
    )
}

fn build_imports_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let ids = i64_vec(
        report.imports.len(),
        report.imports.iter().map(|import| import.import_id as i64),
    )?;
    let from_files = i64_vec(
        report.imports.len(),
        report.imports.iter().map(|import| import.from_file as i64),
    )?;
    let targets = str_vec(
        report.imports.len(),
        report.imports.iter().map(|import| import.target.clone()),
    )?;
    let kinds = str_vec(
        report.imports.len(),
        report.imports.iter().map(|import| import.kind.clone()),
    )?;
    let resolutions = str_vec(
        report.imports.len(),
        report
            .imports
            .iter()
            .map(|import| format!("{:?}", import.resolution).to_lowercase()),
    )?;
    let resolved_files = i64_vec(
        report.imports.len(),
        report
            .imports
            .iter()
            .map(|import| import.resolved_file.map(|id| id as i64).unwrap_or(-1)),
    )?;

    table(
        6,
        [
            ("import_id", ids),
            ("from_file", from_files),
            ("target", targets),
            ("kind", kinds),
            ("resolution", resolutions),
            ("resolved_file", resolved_files),
        ],
    )
}

fn build_calls_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let ids = i64_vec(
        report.calls.len(),
        report.calls.iter().map(|call| call.call_id as i64),
    )?;
    let file_ids = i64_vec(
        report.calls.len(),
        report.calls.iter().map(|call| call.file_id as i64),
    )?;
    let caller_functions = i64_vec(
        report.calls.len(),
        report
            .calls
            .iter()
            .map(|call| call.caller_function.map(|id| id as i64).unwrap_or(-1)),
    )?;
    let targets = str_vec(
        report.calls.len(),
        report.calls.iter().map(|call| call.target.clone()),
    )?;
    let lines = i64_vec(
        report.calls.len(),
        report.calls.iter().map(|call| call.line as i64),
    )?;

    table(
        5,
        [
            ("call_id", ids),
            ("file_id", file_ids),
            ("caller_function", caller_functions),
            ("target", targets),
            ("line", lines),
        ],
    )
}

fn build_call_edges_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let ids = i64_vec(
        report.call_edges.len(),
        report.call_edges.iter().map(|edge| edge.edge_id as i64),
    )?;
    let call_ids = i64_vec(
        report.call_edges.len(),
        report.call_edges.iter().map(|edge| edge.call_id as i64),
    )?;
    let callers = i64_vec(
        report.call_edges.len(),
        report
            .call_edges
            .iter()
            .map(|edge| edge.caller_function as i64),
    )?;
    let callees = i64_vec(
        report.call_edges.len(),
        report
            .call_edges
            .iter()
            .map(|edge| edge.callee_function as i64),
    )?;

    table(
        4,
        [
            ("edge_id", ids),
            ("call_id", call_ids),
            ("caller_function", callers),
            ("callee_function", callees),
        ],
    )
}

fn build_health_table(
    report: &ScanReport,
    health: &HealthSummary,
) -> Result<RayObject, MemoryError> {
    table(
        26,
        [
            ("score", i64_vec(1, [health.score as i64])?),
            (
                "coverage_score",
                i64_vec(1, [health.coverage_score as i64])?,
            ),
            (
                "structural_score",
                i64_vec(1, [health.structural_score as i64])?,
            ),
            ("files", i64_vec(1, [report.snapshot.file_count as i64])?),
            (
                "functions",
                i64_vec(1, [report.snapshot.function_count as i64])?,
            ),
            (
                "imports",
                i64_vec(1, [report.snapshot.import_count as i64])?,
            ),
            ("calls", i64_vec(1, [report.snapshot.call_count as i64])?),
            ("call_edges", i64_vec(1, [report.call_edges.len() as i64])?),
            (
                "local_imports",
                i64_vec(1, [health.resolution.local as i64])?,
            ),
            (
                "external_imports",
                i64_vec(1, [health.resolution.external as i64])?,
            ),
            (
                "system_imports",
                i64_vec(1, [health.resolution.system as i64])?,
            ),
            (
                "unresolved_imports",
                i64_vec(1, [health.resolution.unresolved as i64])?,
            ),
            (
                "cross_module_edges",
                i64_vec(1, [health.metrics.coupling.cross_module_edges as i64])?,
            ),
            (
                "cross_module_ratio_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.coupling.cross_module_ratio * 1000.0).round() as i64],
                )?,
            ),
            (
                "call_resolution_ratio_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.calls.resolution_ratio * 1000.0).round() as i64],
                )?,
            ),
            (
                "max_function_fan_in",
                i64_vec(1, [health.metrics.calls.max_function_fan_in as i64])?,
            ),
            (
                "max_function_fan_out",
                i64_vec(1, [health.metrics.calls.max_function_fan_out as i64])?,
            ),
            (
                "max_file_lines",
                i64_vec(1, [health.metrics.size.max_file_lines as i64])?,
            ),
            (
                "max_function_lines",
                i64_vec(1, [health.metrics.size.max_function_lines as i64])?,
            ),
            (
                "large_files",
                i64_vec(1, [health.metrics.size.large_files as i64])?,
            ),
            (
                "long_functions",
                i64_vec(1, [health.metrics.size.long_functions as i64])?,
            ),
            (
                "production_files",
                i64_vec(1, [health.metrics.test_gap.production_files as i64])?,
            ),
            (
                "test_files",
                i64_vec(1, [health.metrics.test_gap.test_files as i64])?,
            ),
            (
                "files_without_nearby_tests",
                i64_vec(
                    1,
                    [health.metrics.test_gap.files_without_nearby_tests as i64],
                )?,
            ),
            (
                "module_edges",
                i64_vec(1, [health.metrics.dsm.module_edges as i64])?,
            ),
            (
                "commits_sampled",
                i64_vec(1, [health.metrics.evolution.commits_sampled as i64])?,
            ),
        ],
    )
}

fn build_hotspots_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.hotspots.len();
    table(
        5,
        [
            (
                "file_id",
                i64_vec(
                    rows,
                    health.hotspots.iter().map(|hotspot| hotspot.file_id as i64),
                )?,
            ),
            (
                "path",
                str_vec(
                    rows,
                    health.hotspots.iter().map(|hotspot| hotspot.path.clone()),
                )?,
            ),
            (
                "module",
                str_vec(
                    rows,
                    health.hotspots.iter().map(|hotspot| hotspot.module.clone()),
                )?,
            ),
            (
                "fan_in",
                i64_vec(
                    rows,
                    health.hotspots.iter().map(|hotspot| hotspot.fan_in as i64),
                )?,
            ),
            (
                "fan_out",
                i64_vec(
                    rows,
                    health.hotspots.iter().map(|hotspot| hotspot.fan_out as i64),
                )?,
            ),
        ],
    )
}

fn build_rules_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.rules.len();
    table(
        4,
        [
            (
                "severity",
                str_vec(
                    rows,
                    health
                        .rules
                        .iter()
                        .map(|rule| format!("{:?}", rule.severity).to_lowercase()),
                )?,
            ),
            (
                "code",
                str_vec(rows, health.rules.iter().map(|rule| rule.code.clone()))?,
            ),
            (
                "path",
                str_vec(rows, health.rules.iter().map(|rule| rule.path.clone()))?,
            ),
            (
                "message",
                str_vec(rows, health.rules.iter().map(|rule| rule.message.clone()))?,
            ),
        ],
    )
}

fn build_module_edges_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.metrics.dsm.top_module_edges.len();
    table(
        3,
        [
            (
                "from_module",
                str_vec(
                    rows,
                    health
                        .metrics
                        .dsm
                        .top_module_edges
                        .iter()
                        .map(|edge| edge.from_module.clone()),
                )?,
            ),
            (
                "to_module",
                str_vec(
                    rows,
                    health
                        .metrics
                        .dsm
                        .top_module_edges
                        .iter()
                        .map(|edge| edge.to_module.clone()),
                )?,
            ),
            (
                "edges",
                i64_vec(
                    rows,
                    health
                        .metrics
                        .dsm
                        .top_module_edges
                        .iter()
                        .map(|edge| edge.edges as i64),
                )?,
            ),
        ],
    )
}

fn build_changed_files_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.metrics.evolution.top_changed_files.len();
    table(
        2,
        [
            (
                "path",
                str_vec(
                    rows,
                    health
                        .metrics
                        .evolution
                        .top_changed_files
                        .iter()
                        .map(|file| file.path.clone()),
                )?,
            ),
            (
                "commits",
                i64_vec(
                    rows,
                    health
                        .metrics
                        .evolution
                        .top_changed_files
                        .iter()
                        .map(|file| file.commits as i64),
                )?,
            ),
        ],
    )
}

fn i64_vec(
    capacity: usize,
    values: impl IntoIterator<Item = i64>,
) -> Result<RayObject, MemoryError> {
    let mut vec = RayObject::new(
        unsafe { rayforce_sys::ray_vec_new(rayforce_sys::RAY_I64, capacity as i64) },
        "i64 vector",
    )?;

    for value in values {
        let next = unsafe {
            rayforce_sys::ray_vec_append(
                vec.into_raw(),
                (&value as *const i64).cast::<std::ffi::c_void>(),
            )
        };
        vec = RayObject::new(next, "i64 vector append")?;
    }

    Ok(vec)
}

fn str_vec(
    capacity: usize,
    values: impl IntoIterator<Item = String>,
) -> Result<RayObject, MemoryError> {
    let mut vec = RayObject::new(
        unsafe { rayforce_sys::ray_vec_new(rayforce_sys::RAY_STR, capacity as i64) },
        "string vector",
    )?;

    for value in values {
        let value = CString::new(value)?;
        let next = unsafe {
            rayforce_sys::ray_str_vec_append(vec.into_raw(), value.as_ptr(), value.as_bytes().len())
        };
        vec = RayObject::new(next, "string vector append")?;
    }

    Ok(vec)
}

fn table<const N: usize>(
    capacity: i64,
    columns: [(&'static str, RayObject); N],
) -> Result<RayObject, MemoryError> {
    let mut table = RayObject::new(
        unsafe { rayforce_sys::ray_table_new(capacity) },
        "rayforce table",
    )?;

    for (name, col) in columns {
        let name = CString::new(name)?;
        let name_id = unsafe { rayforce_sys::ray_sym_intern(name.as_ptr(), name.as_bytes().len()) };
        let next =
            unsafe { rayforce_sys::ray_table_add_col(table.into_raw(), name_id, col.as_ptr()) };
        table = RayObject::new(next, "rayforce table column")?;
    }

    Ok(table)
}

fn table_summary(table: *mut rayforce_sys::ray_t) -> TableSummary {
    TableSummary {
        columns: unsafe { rayforce_sys::ray_table_ncols(table) },
        rows: unsafe { rayforce_sys::ray_table_nrows(table) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use raysense_core::scan_path;

    #[test]
    fn builds_memory_tables_from_scan_report() {
        let report = scan_path(env!("CARGO_MANIFEST_DIR")).unwrap();
        let memory = RayMemory::from_report(&report).unwrap();
        let summary = memory.summary();

        assert_eq!(summary.files.rows as usize, report.files.len());
        assert_eq!(summary.functions.rows as usize, report.functions.len());
        assert_eq!(
            summary.entry_points.rows as usize,
            report.entry_points.len()
        );
        assert_eq!(summary.imports.rows as usize, report.imports.len());
        assert_eq!(summary.calls.rows as usize, report.calls.len());
        assert_eq!(summary.call_edges.rows as usize, report.call_edges.len());
        assert_eq!(summary.calls.columns, 5);
        assert_eq!(summary.call_edges.columns, 4);
        assert_eq!(summary.health.rows, 1);
        assert_eq!(summary.health.columns, 26);
        assert_eq!(summary.hotspots.columns, 5);
        assert_eq!(summary.rules.columns, 4);
        assert_eq!(summary.module_edges.columns, 3);
        assert_eq!(summary.changed_files.columns, 2);
    }
}
