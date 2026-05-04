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

use crate::health::{TrendHotspotSample, TrendSample};
use crate::{
    compute_health_with_config, HealthSummary, RaysenseConfig, RuleFinding, RuleSeverity,
    ScanReport,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// On-disk schema version for the splayed baseline tables. Bump whenever any
/// table builder gains, loses, renames a column, or changes a column's
/// physical type. The `meta` table stamps this value at save time; readers
/// refuse to decode mismatched baselines.
///
/// History:
/// - v1: initial schema, every string column stored as `RAY_STR`.
/// - v2: low-cardinality columns (`language`, `module`, `kind`,
///   `resolution`, `severity`, `top_author`) moved to dict-encoded
///   `RAY_SYM` for storage and load-time wins on large repos.
/// - v3: architecture analysis materialized as first-class baseline
///   tables (`arch_cycles`, `arch_unstable`, `arch_foundations`,
///   `arch_levels`, `arch_distance`, `arch_violations`) so agents
///   query architectural detail through Rayfall instead of by
///   jq-piping a JSON dump from the typed MCP tools.
/// - v4: trend history materialized as splayed tables
///   (`trend_health`, `trend_hotspots`, `trend_violations`) so agents
///   query "what got worse over the last N days" against the baseline
///   instead of parsing `.raysense/trends/history.json` themselves.
/// - v5: trend tables become the source of truth. JSON
///   (`.raysense/trends/history.json`) is gone. `trend record`
///   appends rows to the splayed tables in place via Rayfall
///   `concat`; `baseline save` reads them off disk and re-emits
///   them rather than rebuilding from JSON. Hard break: v4
///   baselines fail the schema check and require a fresh save.
/// - v6: `imports` table gains an `alias` column capturing
///   `as`-style renames (Rust `use foo::Bar as Baz`, ES
///   `import { foo as bar }`, Python `import x as y`). Empty
///   string when no alias is declared. Hard break: v5
///   baselines fail the schema check and require a fresh save.
/// - v7: `functions` and `types` tables gain a normalized
///   `visibility` symbol column (`public`, `protected`,
///   `internal`, `restricted`, `private`, `unknown`) populated
///   via per-plugin `visibility_patterns`. Hard break: v6
///   baselines fail the schema check and require a fresh save.
/// - v8: new `trait_impls` table records `impl Trait for Type`
///   relationships extracted from Rust sources, so blast-radius /
///   coupling tooling can follow the trait -> implementer edge
///   without round-tripping through `TypeFact.bases`. Hard break:
///   v7 baselines fail the schema check and require a fresh save.
pub const SCHEMA_VERSION: i64 = 8;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("rayforce symbol table initialization failed with code {0}")]
    SymbolInit(i32),
    #[error("rayforce returned null while building {0}")]
    Null(&'static str),
    #[error("string contains an interior null byte: {0}")]
    StringNul(#[from] std::ffi::NulError),
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("rayforce failed to save splayed table {table} with code {code}")]
    SplaySave { table: &'static str, code: i32 },
    #[error("rayforce failed to read splayed table {table}: {code}")]
    SplayRead { table: String, code: String },
    #[error("rayforce returned null while reading splayed table {table}")]
    SplayReadNull { table: String },
    #[error("failed to read baseline tables {path}: {source}")]
    ReadTables {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("baseline table {0} was not found")]
    TableNotFound(String),
    #[error("invalid baseline table name {0}")]
    InvalidTableName(String),
    #[error("unknown baseline table column {0}")]
    UnknownColumn(String),
    #[error("invalid regex for baseline table column {column}: {source}")]
    InvalidRegex {
        column: String,
        #[source]
        source: regex::Error,
    },
    #[error(
        "baseline schema version mismatch: found {found}, expected {expected}; \
         re-run `raysense baseline save` to refresh the on-disk format"
    )]
    SchemaMismatch { found: i64, expected: i64 },
    #[error("baseline meta table is malformed: {reason}")]
    MetaTableMalformed { reason: String },
    #[error("rayforce runtime initialization failed")]
    RuntimeInit,
    #[error("Rayfall eval failed: {code}: {detail}")]
    RayfallEval { code: String, detail: String },
    #[error("Rayfall result is not a table (type {type_tag}); expected RAY_TABLE")]
    RayfallResultNotTable { type_tag: i8 },
    #[error("policy file {path}: {source}")]
    PolicyFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "policy {path} returned a table without the required columns: missing {missing:?}; \
         expected severity, code, path, message"
    )]
    PolicySchema {
        path: PathBuf,
        missing: Vec<&'static str>,
    },
    #[error(
        "policy {path} severity {value:?} is not one of info, warning, error (case-insensitive)"
    )]
    PolicySeverity { path: PathBuf, value: String },
    #[error(
        "csv import path {path:?} contains characters that would break the Rayfall \
         interpolation (embedded double-quote or backslash)"
    )]
    CsvImportPath { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TableSummary {
    pub columns: i64,
    pub rows: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemorySummary {
    pub files: TableSummary,
    pub functions: TableSummary,
    pub entry_points: TableSummary,
    pub imports: TableSummary,
    pub calls: TableSummary,
    pub call_edges: TableSummary,
    pub types: TableSummary,
    pub health: TableSummary,
    pub hotspots: TableSummary,
    pub rules: TableSummary,
    pub module_edges: TableSummary,
    pub changed_files: TableSummary,
    pub file_ownership: TableSummary,
    pub temporal_hotspots: TableSummary,
    pub file_ages: TableSummary,
    pub change_coupling: TableSummary,
    pub inheritance: TableSummary,
    pub trait_impls: TableSummary,
    pub arch_cycles: TableSummary,
    pub arch_unstable: TableSummary,
    pub arch_foundations: TableSummary,
    pub arch_levels: TableSummary,
    pub arch_distance: TableSummary,
    pub arch_violations: TableSummary,
    pub trend_health: TableSummary,
    pub trend_hotspots: TableSummary,
    pub trend_violations: TableSummary,
    pub meta: TableSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaselineTableInfo {
    pub name: String,
    pub columns: i64,
    pub rows: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BaselineTableRows {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<serde_json::Value>,
    pub offset: usize,
    pub limit: usize,
    pub total_rows: i64,
    pub matched_rows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineFilterOp {
    Eq,
    Ne,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    NotRegex,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BaselineTableFilter {
    pub column: String,
    pub op: BaselineFilterOp,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineFilterMode {
    All,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineSortDirection {
    Asc,
    Desc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineTableSort {
    pub column: String,
    pub direction: BaselineSortDirection,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BaselineTableQuery {
    pub offset: usize,
    pub limit: usize,
    pub columns: Option<Vec<String>>,
    pub filters: Vec<BaselineTableFilter>,
    pub filter_mode: BaselineFilterMode,
    pub sort: Vec<BaselineTableSort>,
}

impl BaselineTableQuery {
    pub fn page(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            columns: None,
            filters: Vec::new(),
            filter_mode: BaselineFilterMode::All,
            sort: Vec::new(),
        }
    }
}

pub struct RayMemory {
    files: RayObject,
    functions: RayObject,
    entry_points: RayObject,
    imports: RayObject,
    calls: RayObject,
    call_edges: RayObject,
    types: RayObject,
    health: RayObject,
    hotspots: RayObject,
    rules: RayObject,
    module_edges: RayObject,
    changed_files: RayObject,
    file_ownership: RayObject,
    temporal_hotspots: RayObject,
    file_ages: RayObject,
    change_coupling: RayObject,
    inheritance: RayObject,
    trait_impls: RayObject,
    arch_cycles: RayObject,
    arch_unstable: RayObject,
    arch_foundations: RayObject,
    arch_levels: RayObject,
    arch_distance: RayObject,
    arch_violations: RayObject,
    trend_health: RayObject,
    trend_hotspots: RayObject,
    trend_violations: RayObject,
    meta: RayObject,
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

        let files = build_files_table(report)?;
        let functions = build_functions_table(report)?;
        let entry_points = build_entry_points_table(report)?;
        let imports = build_imports_table(report)?;
        let calls = build_calls_table(report)?;
        let call_edges = build_call_edges_table(report)?;
        let types = build_types_table(report)?;
        let health_table = build_health_table(report, &health)?;
        let hotspots = build_hotspots_table(&health)?;
        let rules = build_rules_table(&health)?;
        let module_edges = build_module_edges_table(&health)?;
        let changed_files = build_changed_files_table(&health)?;
        let file_ownership = build_file_ownership_table(&health)?;
        let temporal_hotspots = build_temporal_hotspots_table(&health)?;
        let file_ages = build_file_ages_table(&health)?;
        let change_coupling = build_change_coupling_table(&health)?;
        let inheritance = build_inheritance_table(report)?;
        let trait_impls = build_trait_impls_table(report)?;
        let arch_cycles = build_arch_cycles_table(&health)?;
        let arch_unstable = build_arch_unstable_table(&health)?;
        let arch_foundations = build_arch_foundations_table(&health)?;
        let arch_levels = build_arch_levels_table(&health)?;
        let arch_distance = build_arch_distance_table(&health)?;
        let arch_violations = build_arch_violations_table(&health)?;

        // v0.8: load existing splayed trend tables from the canonical
        // location so they survive the wholesale rewrite of the
        // tables/ directory. Falls back to empty-with-schema when the
        // baseline has never been saved before.
        let (trend_health, trend_hotspots, trend_violations) =
            load_or_empty_trend_tables(&report.snapshot.root)?;

        let meta = build_meta_table(
            report,
            &[
                ("arch_cycles", arch_cycles.as_ptr()),
                ("arch_distance", arch_distance.as_ptr()),
                ("arch_foundations", arch_foundations.as_ptr()),
                ("arch_levels", arch_levels.as_ptr()),
                ("arch_unstable", arch_unstable.as_ptr()),
                ("arch_violations", arch_violations.as_ptr()),
                ("call_edges", call_edges.as_ptr()),
                ("calls", calls.as_ptr()),
                ("change_coupling", change_coupling.as_ptr()),
                ("changed_files", changed_files.as_ptr()),
                ("entry_points", entry_points.as_ptr()),
                ("file_ages", file_ages.as_ptr()),
                ("file_ownership", file_ownership.as_ptr()),
                ("files", files.as_ptr()),
                ("functions", functions.as_ptr()),
                ("health", health_table.as_ptr()),
                ("hotspots", hotspots.as_ptr()),
                ("imports", imports.as_ptr()),
                ("inheritance", inheritance.as_ptr()),
                ("trait_impls", trait_impls.as_ptr()),
                ("module_edges", module_edges.as_ptr()),
                ("rules", rules.as_ptr()),
                ("temporal_hotspots", temporal_hotspots.as_ptr()),
                ("trend_health", trend_health.as_ptr()),
                ("trend_hotspots", trend_hotspots.as_ptr()),
                ("trend_violations", trend_violations.as_ptr()),
                ("types", types.as_ptr()),
            ],
        )?;

        Ok(Self {
            files,
            functions,
            entry_points,
            imports,
            calls,
            call_edges,
            types,
            health: health_table,
            hotspots,
            rules,
            module_edges,
            changed_files,
            file_ownership,
            temporal_hotspots,
            file_ages,
            change_coupling,
            inheritance,
            trait_impls,
            arch_cycles,
            arch_unstable,
            arch_foundations,
            arch_levels,
            arch_distance,
            arch_violations,
            trend_health,
            trend_hotspots,
            trend_violations,
            meta,
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
            types: table_summary(self.types.as_ptr()),
            health: table_summary(self.health.as_ptr()),
            hotspots: table_summary(self.hotspots.as_ptr()),
            rules: table_summary(self.rules.as_ptr()),
            module_edges: table_summary(self.module_edges.as_ptr()),
            changed_files: table_summary(self.changed_files.as_ptr()),
            file_ownership: table_summary(self.file_ownership.as_ptr()),
            temporal_hotspots: table_summary(self.temporal_hotspots.as_ptr()),
            file_ages: table_summary(self.file_ages.as_ptr()),
            change_coupling: table_summary(self.change_coupling.as_ptr()),
            inheritance: table_summary(self.inheritance.as_ptr()),
            trait_impls: table_summary(self.trait_impls.as_ptr()),
            arch_cycles: table_summary(self.arch_cycles.as_ptr()),
            arch_unstable: table_summary(self.arch_unstable.as_ptr()),
            arch_foundations: table_summary(self.arch_foundations.as_ptr()),
            arch_levels: table_summary(self.arch_levels.as_ptr()),
            arch_distance: table_summary(self.arch_distance.as_ptr()),
            arch_violations: table_summary(self.arch_violations.as_ptr()),
            trend_health: table_summary(self.trend_health.as_ptr()),
            trend_hotspots: table_summary(self.trend_hotspots.as_ptr()),
            trend_violations: table_summary(self.trend_violations.as_ptr()),
            meta: table_summary(self.meta.as_ptr()),
        }
    }

    pub fn save_splayed(&self, dir: impl AsRef<Path>) -> Result<(), MemoryError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).map_err(|source| MemoryError::CreateDir {
            path: dir.to_path_buf(),
            source,
        })?;
        let sym_path = dir.join(".sym");

        self.save_table("files", self.files.as_ptr(), dir, &sym_path)?;
        self.save_table("functions", self.functions.as_ptr(), dir, &sym_path)?;
        self.save_table("entry_points", self.entry_points.as_ptr(), dir, &sym_path)?;
        self.save_table("imports", self.imports.as_ptr(), dir, &sym_path)?;
        self.save_table("calls", self.calls.as_ptr(), dir, &sym_path)?;
        self.save_table("call_edges", self.call_edges.as_ptr(), dir, &sym_path)?;
        self.save_table("types", self.types.as_ptr(), dir, &sym_path)?;
        self.save_table("health", self.health.as_ptr(), dir, &sym_path)?;
        self.save_table("hotspots", self.hotspots.as_ptr(), dir, &sym_path)?;
        self.save_table("rules", self.rules.as_ptr(), dir, &sym_path)?;
        self.save_table("module_edges", self.module_edges.as_ptr(), dir, &sym_path)?;
        self.save_table("changed_files", self.changed_files.as_ptr(), dir, &sym_path)?;
        self.save_table(
            "file_ownership",
            self.file_ownership.as_ptr(),
            dir,
            &sym_path,
        )?;
        self.save_table(
            "temporal_hotspots",
            self.temporal_hotspots.as_ptr(),
            dir,
            &sym_path,
        )?;
        self.save_table("file_ages", self.file_ages.as_ptr(), dir, &sym_path)?;
        self.save_table(
            "change_coupling",
            self.change_coupling.as_ptr(),
            dir,
            &sym_path,
        )?;
        self.save_table("inheritance", self.inheritance.as_ptr(), dir, &sym_path)?;
        self.save_table("trait_impls", self.trait_impls.as_ptr(), dir, &sym_path)?;
        self.save_table("arch_cycles", self.arch_cycles.as_ptr(), dir, &sym_path)?;
        self.save_table("arch_unstable", self.arch_unstable.as_ptr(), dir, &sym_path)?;
        self.save_table(
            "arch_foundations",
            self.arch_foundations.as_ptr(),
            dir,
            &sym_path,
        )?;
        self.save_table("arch_levels", self.arch_levels.as_ptr(), dir, &sym_path)?;
        self.save_table("arch_distance", self.arch_distance.as_ptr(), dir, &sym_path)?;
        self.save_table(
            "arch_violations",
            self.arch_violations.as_ptr(),
            dir,
            &sym_path,
        )?;
        self.save_table("trend_health", self.trend_health.as_ptr(), dir, &sym_path)?;
        self.save_table(
            "trend_hotspots",
            self.trend_hotspots.as_ptr(),
            dir,
            &sym_path,
        )?;
        self.save_table(
            "trend_violations",
            self.trend_violations.as_ptr(),
            dir,
            &sym_path,
        )?;
        self.save_table("meta", self.meta.as_ptr(), dir, &sym_path)?;
        Ok(())
    }

    fn save_table(
        &self,
        name: &'static str,
        table: *mut crate::sys::ray_t,
        base: &Path,
        sym_path: &Path,
    ) -> Result<(), MemoryError> {
        let path = CString::new(base.join(name).to_string_lossy().into_owned())?;
        let sym_path = CString::new(sym_path.to_string_lossy().into_owned())?;
        let err = unsafe { crate::sys::ray_splay_save(table, path.as_ptr(), sym_path.as_ptr()) };
        if err == crate::sys::RAY_OK {
            Ok(())
        } else {
            Err(MemoryError::SplaySave {
                table: name,
                code: err,
            })
        }
    }
}

pub fn list_baseline_tables(dir: impl AsRef<Path>) -> Result<Vec<BaselineTableInfo>, MemoryError> {
    init_symbols()?;
    let dir = dir.as_ref();
    verify_baseline_schema(dir)?;
    let mut tables = Vec::new();
    let entries = fs::read_dir(dir).map_err(|source| MemoryError::ReadTables {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| MemoryError::ReadTables {
            path: dir.to_path_buf(),
            source,
        })?;
        let file_type = entry
            .file_type()
            .map_err(|source| MemoryError::ReadTables {
                path: entry.path(),
                source,
            })?;
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let table = read_table_object(dir, &name)?;
        tables.push(BaselineTableInfo {
            name,
            columns: unsafe { crate::sys::ray_table_ncols(table.as_ptr()) },
            rows: unsafe { crate::sys::ray_table_nrows(table.as_ptr()) },
        });
    }

    tables.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(tables)
}

pub fn read_baseline_table(
    dir: impl AsRef<Path>,
    name: &str,
    offset: usize,
    limit: usize,
) -> Result<BaselineTableRows, MemoryError> {
    query_baseline_table(dir, name, BaselineTableQuery::page(offset, limit))
}

pub fn query_baseline_table(
    dir: impl AsRef<Path>,
    name: &str,
    query: BaselineTableQuery,
) -> Result<BaselineTableRows, MemoryError> {
    init_symbols()?;
    validate_table_name(name)?;
    let dir = dir.as_ref();
    if name != "meta" {
        verify_baseline_schema(dir)?;
    }
    if !dir.join(name).is_dir() {
        return Err(MemoryError::TableNotFound(name.to_string()));
    }
    let table = read_table_object(dir, name)?;
    table_rows(name, table.as_ptr(), query)
}

/// Evaluate a Rayfall expression against a saved baseline table.
///
/// The named baseline table is loaded from `dir`, bound to the Rayfall
/// symbol `t`, and `expr` is evaluated against the global env. The result
/// must itself be a `RAY_TABLE`; scalar / vector / atom returns are not
/// supported in this slice (wrap with `select` to project columns into a
/// table).  Schema is verified against `SCHEMA_VERSION` first; mismatches
/// surface as `MemoryError::SchemaMismatch` before any eval runs.
///
/// Bind name is fixed at `t` rather than parameterized to keep the surface
/// small; agents can rename via `(set foo t)` inside `expr` if needed.
pub fn query_with_rayfall(
    dir: impl AsRef<Path>,
    name: &str,
    expr: &str,
) -> Result<BaselineTableRows, MemoryError> {
    ensure_runtime()?;
    validate_table_name(name)?;
    let dir = dir.as_ref();
    if name != "meta" {
        verify_baseline_schema(dir)?;
    }
    if !dir.join(name).is_dir() {
        return Err(MemoryError::TableNotFound(name.to_string()));
    }

    let table = read_table_object(dir, name)?;

    let bind_name = CString::new("t")?;
    let bind_id = unsafe { crate::sys::ray_sym_intern(bind_name.as_ptr(), 1) };
    let set_err = unsafe { crate::sys::ray_env_set(bind_id, table.as_ptr()) };
    if set_err != crate::sys::RAY_OK {
        return Err(MemoryError::RayfallEval {
            code: format!("env_set={set_err}"),
            detail: "failed to bind baseline table to symbol `t`".to_string(),
        });
    }

    let source = CString::new(expr)?;
    let raw_result = unsafe { crate::sys::ray_eval_str(source.as_ptr()) };

    if raw_result.is_null() {
        // null is rayforce's void / null result -- represent as an empty rowset.
        return Ok(BaselineTableRows {
            name: name.to_string(),
            columns: Vec::new(),
            rows: Vec::new(),
            offset: 0,
            limit: 0,
            total_rows: 0,
            matched_rows: 0,
        });
    }

    let result = RayObject::new(raw_result, "rayfall result")?;

    let result_type = unsafe { (*result.as_ptr()).type_ };
    if result_type == crate::sys::RAY_ERROR {
        let code = unsafe {
            let p = crate::sys::ray_err_code(result.as_ptr());
            if p.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        return Err(MemoryError::RayfallEval {
            code,
            detail: expr.to_string(),
        });
    }
    promote_result_to_rows(name, result.as_ptr())
}

/// Lift any non-error Rayfall result into a `BaselineTableRows`. Tables go
/// through the existing `table_rows` decoder; atoms become a 1x1 "value"
/// table; vectors become a 1-column N-row "value" table; dicts become a
/// 2-column key/value table. Anything else (lists with mixed types,
/// lambdas, GUID atoms) still surfaces as `RayfallResultNotTable` so the
/// caller can wrap with `select`.
fn promote_result_to_rows(
    name: &str,
    ptr: *mut crate::sys::ray_t,
) -> Result<BaselineTableRows, MemoryError> {
    let type_tag = unsafe { (*ptr).type_ };
    if type_tag == crate::sys::RAY_TABLE {
        return table_rows(name, ptr, BaselineTableQuery::page(0, usize::MAX));
    }
    if type_tag == crate::sys::RAY_DICT {
        return dict_to_rows(name, ptr);
    }
    if type_tag < 0 {
        // Negative tags are atoms; |tag| names the underlying type.
        return Ok(atom_to_rows(name, ptr));
    }
    if (crate::sys::RAY_BOOL..=crate::sys::RAY_STR).contains(&type_tag) {
        // Positive tags between BOOL and STR are typed vectors.
        return Ok(vector_to_rows(name, ptr));
    }
    Err(MemoryError::RayfallResultNotTable { type_tag })
}

fn atom_to_rows(name: &str, ptr: *mut crate::sys::ray_t) -> BaselineTableRows {
    let value = atom_to_json(ptr);
    let mut row = serde_json::Map::new();
    row.insert("value".to_string(), value);
    BaselineTableRows {
        name: name.to_string(),
        columns: vec!["value".to_string()],
        rows: vec![serde_json::Value::Object(row)],
        offset: 0,
        limit: 1,
        total_rows: 1,
        matched_rows: 1,
    }
}

fn atom_to_json(ptr: *mut crate::sys::ray_t) -> serde_json::Value {
    // Atom layout: header at 0..16, mmod/order/type/attrs/rc at 16..24,
    // 8-byte payload at 24..32. We read the payload as i64 raw bits and
    // reinterpret per type.
    let neg = unsafe { (*ptr).type_ };
    let base = -neg;
    let bits = unsafe { (*ptr).len };
    match base {
        crate::sys::RAY_BOOL => serde_json::Value::Bool((bits & 1) != 0),
        crate::sys::RAY_U8 => serde_json::Value::from(bits as u8),
        crate::sys::RAY_I16 => serde_json::Value::from(bits as i16),
        crate::sys::RAY_I32 => serde_json::Value::from(bits as i32),
        crate::sys::RAY_I64
        | crate::sys::RAY_DATE
        | crate::sys::RAY_TIME
        | crate::sys::RAY_TIMESTAMP => serde_json::Value::from(bits),
        crate::sys::RAY_F32 => {
            let v = f32::from_bits(bits as u32);
            serde_json::Number::from_f64(v as f64)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        crate::sys::RAY_F64 => {
            let v = f64::from_bits(bits as u64);
            serde_json::Number::from_f64(v)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        crate::sys::RAY_STR => string_atom(ptr)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
        crate::sys::RAY_SYM => {
            let atom = unsafe { crate::sys::ray_sym_str(bits) };
            if atom.is_null() {
                serde_json::Value::String(format!("#{bits}"))
            } else {
                string_atom(atom)
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null)
            }
        }
        _ => serde_json::Value::String(format!("<unsupported atom type {base}>")),
    }
}

fn vector_to_rows(name: &str, ptr: *mut crate::sys::ray_t) -> BaselineTableRows {
    let len = unsafe { (*ptr).len };
    let total = len.max(0) as usize;
    let rows: Vec<serde_json::Value> = (0..len)
        .map(|idx| {
            let mut row = serde_json::Map::new();
            row.insert("value".to_string(), cell_value(ptr, idx));
            serde_json::Value::Object(row)
        })
        .collect();
    BaselineTableRows {
        name: name.to_string(),
        columns: vec!["value".to_string()],
        rows,
        offset: 0,
        limit: total,
        total_rows: len,
        matched_rows: total,
    }
}

fn dict_to_rows(name: &str, ptr: *mut crate::sys::ray_t) -> Result<BaselineTableRows, MemoryError> {
    let keys = unsafe { crate::sys::ray_dict_keys(ptr) };
    let vals = unsafe { crate::sys::ray_dict_vals(ptr) };
    if keys.is_null() || vals.is_null() {
        return Err(MemoryError::RayfallResultNotTable {
            type_tag: crate::sys::RAY_DICT,
        });
    }
    let len = unsafe { crate::sys::ray_dict_len(ptr) };
    let total = len.max(0) as usize;
    let rows: Vec<serde_json::Value> = (0..len)
        .map(|idx| {
            let mut row = serde_json::Map::new();
            row.insert("key".to_string(), cell_value(keys, idx));
            row.insert("value".to_string(), cell_value(vals, idx));
            serde_json::Value::Object(row)
        })
        .collect();
    Ok(BaselineTableRows {
        name: name.to_string(),
        columns: vec!["key".to_string(), "value".to_string()],
        rows,
        offset: 0,
        limit: total,
        total_rows: len,
        matched_rows: total,
    })
}

/// Result of evaluating a single policy `.rfl` file.
///
/// `findings` is `Err` when the policy itself failed to parse, evaluate, or
/// returned a malformed result; the file path is preserved in the error so
/// callers can report which policy went bad without aborting the whole run.
#[derive(Debug)]
pub struct PolicyResult {
    pub path: PathBuf,
    pub findings: Result<Vec<RuleFinding>, MemoryError>,
}

/// CI exit code for a batch of policy results.
///
/// Returns 0 when every policy parsed and reported no error-severity
/// findings, 1 when any policy failed to evaluate (parse / type / schema
/// errors - "I cannot tell whether the rule passed"), or 2 when every
/// policy parsed cleanly but at least one reported an error-severity
/// finding ("the rule definitively failed"). Eval errors outrank findings
/// because a misconfigured policy is more dangerous than a known violation.
pub fn policy_exit_code(results: &[PolicyResult]) -> i32 {
    if results.iter().any(|r| r.findings.is_err()) {
        return 1;
    }
    if results.iter().any(|r| match &r.findings {
        Ok(findings) => findings
            .iter()
            .any(|f| matches!(f.severity, RuleSeverity::Error)),
        Err(_) => false,
    }) {
        return 2;
    }
    0
}

/// Read a CSV file and save it as a splayed table alongside the rest of the
/// baseline. The new table becomes addressable by `table_name` from every
/// surface that already speaks baseline tables: `raysense baseline table
/// <name>`, `raysense baseline query <name> ...`, MCP, and policies (which
/// pre-bind every saved table into the eval env).
///
/// The implementation goes through Rayfall (`(.csv.read ...)` plus
/// `(.db.splayed.set ...)`) rather than direct FFI so that header inference,
/// type detection, and serialization stay consistent with what users get if
/// they call those builtins from a query themselves.
///
/// Path interpolation: rayforce builds the eval expression by string
/// concatenation, so paths containing a literal double-quote or backslash
/// cannot be safely embedded.  Those return `CsvImportPath` rather than
/// risk a malformed expression.
pub fn import_csv_table(
    baseline_dir: impl AsRef<Path>,
    table_name: &str,
    csv_path: impl AsRef<Path>,
) -> Result<(), MemoryError> {
    ensure_runtime()?;
    validate_table_name(table_name)?;
    let baseline_dir = baseline_dir.as_ref();
    fs::create_dir_all(baseline_dir).map_err(|source| MemoryError::CreateDir {
        path: baseline_dir.to_path_buf(),
        source,
    })?;

    // Load the existing baseline's .sym into the global runtime BEFORE
    // running the eval.  rayforce's runtime singleton interns column names
    // through a process-global sym table; without this step, .csv.read would
    // intern "path" / "lines" / ... at fresh IDs starting from whatever the
    // runtime currently has, then .db.splayed.set would overwrite the
    // baseline's existing .sym file with the new ID space, corrupting every
    // already-saved table whose .d file references the old IDs.
    // verify_baseline_schema does the right read for us when meta exists;
    // for a baseline created before the schema-version stamp landed (or for
    // the first table import into a fresh dir), there is nothing to merge
    // and the call returns Ok silently.
    verify_baseline_schema(baseline_dir)?;

    // Resolve to absolute paths before interpolation: relative paths combined
    // with the runtime's cwd-at-init snapshot can produce a "corrupt" splay
    // save when the dest dir doesn't yet exist.  canonicalize requires the
    // path to exist; fall back to the joined-absolute form for the dest dir
    // (which the splay save creates itself).
    let csv_path = csv_path.as_ref();
    let csv_abs = csv_path
        .canonicalize()
        .unwrap_or_else(|_| csv_path.to_path_buf());
    let baseline_abs = baseline_dir
        .canonicalize()
        .unwrap_or_else(|_| baseline_dir.to_path_buf());
    let csv_str = csv_abs.to_string_lossy();
    let dest_str = baseline_abs.join(table_name).to_string_lossy().into_owned();
    let sym_str = baseline_abs.join(".sym").to_string_lossy().into_owned();
    for path in [csv_str.as_ref(), dest_str.as_str(), sym_str.as_str()] {
        if path.contains('"') || path.contains('\\') {
            return Err(MemoryError::CsvImportPath {
                path: path.to_string(),
            });
        }
    }

    let expr = format!(r#"(.db.splayed.set "{dest_str}" (.csv.read "{csv_str}") "{sym_str}")"#,);
    let csource = CString::new(expr)?;
    let raw_result = unsafe { crate::sys::ray_eval_str(csource.as_ptr()) };
    if raw_result.is_null() {
        return Ok(());
    }
    let result = RayObject::new(raw_result, "csv import")?;
    if unsafe { (*result.as_ptr()).type_ } == crate::sys::RAY_ERROR {
        let code = unsafe {
            let p = crate::sys::ray_err_code(result.as_ptr());
            if p.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        return Err(MemoryError::RayfallEval {
            code,
            detail: format!("csv import {} -> {}", csv_path.display(), table_name),
        });
    }
    Ok(())
}

/// Evaluate every `.rfl` file in `policies_dir` against the saved baseline
/// at `baseline_dir`, in alphabetical order. Each policy is evaluated
/// independently; one bad file does not abort the rest. Missing
/// `policies_dir` is treated as zero policies (empty Vec).
pub fn eval_all_policies(
    baseline_dir: impl AsRef<Path>,
    policies_dir: impl AsRef<Path>,
) -> Result<Vec<PolicyResult>, MemoryError> {
    let policies_dir = policies_dir.as_ref();
    if !policies_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths: Vec<PathBuf> = fs::read_dir(policies_dir)
        .map_err(|source| MemoryError::PolicyFile {
            path: policies_dir.to_path_buf(),
            source,
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rfl"))
        .collect();
    paths.sort();

    let baseline_dir = baseline_dir.as_ref();
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let findings = eval_policy_pack(baseline_dir, &path);
        out.push(PolicyResult { path, findings });
    }
    Ok(out)
}

/// Evaluate a single `.rfl` policy file against the saved baseline.
///
/// The contract: every saved baseline table is bound into the global env
/// under its own name (`files`, `functions`, `call_edges`, ...) so the
/// policy can reference them directly. The policy must return a `RAY_TABLE`
/// with the four columns `severity`, `code`, `path`, `message` (any extras
/// are ignored). Severities are case-insensitively matched against
/// `info`, `warning`, `error`. An empty result is a passing policy.
pub fn eval_policy_pack(
    baseline_dir: impl AsRef<Path>,
    policy_path: impl AsRef<Path>,
) -> Result<Vec<RuleFinding>, MemoryError> {
    ensure_runtime()?;
    let baseline_dir = baseline_dir.as_ref();
    verify_baseline_schema(baseline_dir)?;

    // Pin every saved table into the global env under its own name. The
    // RayObjects must outlive the eval so refcounts stay >= 1; ray_env_set
    // also retains internally, but holding our owned reference is the
    // simpler discipline.
    let mut bound: Vec<RayObject> = Vec::new();
    for info in list_baseline_tables(baseline_dir)? {
        let table = read_table_object(baseline_dir, &info.name)?;
        let cname = CString::new(info.name.as_str())?;
        let sym_id = unsafe { crate::sys::ray_sym_intern(cname.as_ptr(), cname.as_bytes().len()) };
        let err = unsafe { crate::sys::ray_env_set(sym_id, table.as_ptr()) };
        if err != crate::sys::RAY_OK {
            return Err(MemoryError::RayfallEval {
                code: format!("env_set={err}"),
                detail: format!("failed to bind baseline table `{}`", info.name),
            });
        }
        bound.push(table);
    }

    let policy_path = policy_path.as_ref();
    let source = fs::read_to_string(policy_path).map_err(|source| MemoryError::PolicyFile {
        path: policy_path.to_path_buf(),
        source,
    })?;
    let csource = CString::new(source)?;
    let raw_result = unsafe { crate::sys::ray_eval_str(csource.as_ptr()) };

    if raw_result.is_null() {
        return Ok(Vec::new());
    }
    let result = RayObject::new(raw_result, "policy result")?;
    let result_type = unsafe { (*result.as_ptr()).type_ };
    if result_type == crate::sys::RAY_ERROR {
        let code = unsafe {
            let p = crate::sys::ray_err_code(result.as_ptr());
            if p.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        return Err(MemoryError::RayfallEval {
            code,
            detail: policy_path.display().to_string(),
        });
    }
    if result_type != crate::sys::RAY_TABLE {
        return Err(MemoryError::RayfallResultNotTable {
            type_tag: result_type,
        });
    }

    extract_findings(policy_path, result.as_ptr())
}

fn extract_findings(
    policy_path: &Path,
    table: *mut crate::sys::ray_t,
) -> Result<Vec<RuleFinding>, MemoryError> {
    let nrows = unsafe { crate::sys::ray_table_nrows(table) };
    let ncols = unsafe { crate::sys::ray_table_ncols(table) };

    let mut idx_severity: Option<i64> = None;
    let mut idx_code: Option<i64> = None;
    let mut idx_path: Option<i64> = None;
    let mut idx_message: Option<i64> = None;
    for idx in 0..ncols {
        let name_id = unsafe { crate::sys::ray_table_col_name(table, idx) };
        match symbol_text(name_id).as_str() {
            "severity" => idx_severity = Some(idx),
            "code" => idx_code = Some(idx),
            "path" => idx_path = Some(idx),
            "message" => idx_message = Some(idx),
            _ => {}
        }
    }

    let mut missing = Vec::new();
    if idx_severity.is_none() {
        missing.push("severity");
    }
    if idx_code.is_none() {
        missing.push("code");
    }
    if idx_path.is_none() {
        missing.push("path");
    }
    if idx_message.is_none() {
        missing.push("message");
    }
    if !missing.is_empty() {
        return Err(MemoryError::PolicySchema {
            path: policy_path.to_path_buf(),
            missing,
        });
    }
    let (sev, code, path, msg) = (
        idx_severity.unwrap(),
        idx_code.unwrap(),
        idx_path.unwrap(),
        idx_message.unwrap(),
    );

    let cols =
        [sev, code, path, msg].map(|idx| unsafe { crate::sys::ray_table_get_col_idx(table, idx) });

    let mut findings = Vec::with_capacity(nrows.max(0) as usize);
    for row in 0..nrows {
        let cell_str = |col: *mut crate::sys::ray_t| -> String {
            cell_value(col, row)
                .as_str()
                .map(str::to_string)
                .unwrap_or_default()
        };
        let severity_raw = cell_str(cols[0]);
        let severity = match severity_raw.to_ascii_lowercase().as_str() {
            "info" => RuleSeverity::Info,
            "warning" | "warn" => RuleSeverity::Warning,
            "error" | "err" => RuleSeverity::Error,
            _ => {
                return Err(MemoryError::PolicySeverity {
                    path: policy_path.to_path_buf(),
                    value: severity_raw,
                })
            }
        };
        findings.push(RuleFinding {
            severity,
            code: cell_str(cols[1]),
            path: cell_str(cols[2]),
            message: cell_str(cols[3]),
        });
    }
    Ok(findings)
}

fn validate_table_name(name: &str) -> Result<(), MemoryError> {
    if name.is_empty()
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
    {
        return Err(MemoryError::InvalidTableName(name.to_string()));
    }
    Ok(())
}

fn read_table_object(dir: &Path, name: &str) -> Result<RayObject, MemoryError> {
    validate_table_name(name)?;
    let path = CString::new(dir.join(name).to_string_lossy().into_owned())?;
    let sym_path_buf = dir.join(".sym");
    let sym_path = if sym_path_buf.exists() {
        Some(CString::new(sym_path_buf.to_string_lossy().into_owned())?)
    } else {
        None
    };
    let ptr = unsafe {
        crate::sys::ray_read_splayed(
            path.as_ptr(),
            sym_path
                .as_ref()
                .map(|path| path.as_ptr())
                .unwrap_or(std::ptr::null()),
        )
    };
    if ptr.is_null() {
        return Err(MemoryError::SplayReadNull {
            table: name.to_string(),
        });
    }
    if unsafe { (*ptr).type_ } == crate::sys::RAY_ERROR {
        let code = unsafe {
            let code = crate::sys::ray_err_code(ptr);
            if code.is_null() {
                "unknown".to_string()
            } else {
                std::ffi::CStr::from_ptr(code)
                    .to_string_lossy()
                    .into_owned()
            }
        };
        return Err(MemoryError::SplayRead {
            table: name.to_string(),
            code,
        });
    }
    RayObject::new(ptr, "rayforce splayed table")
}

fn table_rows(
    name: &str,
    table: *mut crate::sys::ray_t,
    query: BaselineTableQuery,
) -> Result<BaselineTableRows, MemoryError> {
    let total_rows = unsafe { crate::sys::ray_table_nrows(table) };
    let ncols = unsafe { crate::sys::ray_table_ncols(table) };
    let mut columns = Vec::new();
    let mut col_ptrs = Vec::new();

    for idx in 0..ncols {
        let name_id = unsafe { crate::sys::ray_table_col_name(table, idx) };
        columns.push(symbol_text(name_id));
        col_ptrs.push(unsafe { crate::sys::ray_table_get_col_idx(table, idx) });
    }

    let projected = project_columns(&columns, query.columns.as_deref())?;
    let filters = compile_filters(&columns, query.filters)?;
    let sort_cols = query
        .sort
        .iter()
        .map(|sort| column_index(&columns, &sort.column))
        .collect::<Result<Vec<_>, _>>()?;

    let all_rows = total_rows.max(0) as usize;
    let (matched_rows, page_indexes) = if query.sort.is_empty() {
        let mut matched_rows = 0usize;
        let mut page_indexes = Vec::new();
        for row_idx in 0..all_rows {
            if row_matches(&col_ptrs, row_idx, &filters, query.filter_mode) {
                if matched_rows >= query.offset && page_indexes.len() < query.limit {
                    page_indexes.push(row_idx);
                }
                matched_rows += 1;
            }
        }
        (matched_rows, page_indexes)
    } else {
        let mut row_indexes = Vec::new();
        for row_idx in 0..all_rows {
            if row_matches(&col_ptrs, row_idx, &filters, query.filter_mode) {
                row_indexes.push(row_idx);
            }
        }
        row_indexes.sort_by(|left, right| {
            for (sort, col_idx) in query.sort.iter().zip(&sort_cols) {
                let left = cell_value(col_ptrs[*col_idx], *left as i64);
                let right = cell_value(col_ptrs[*col_idx], *right as i64);
                let ordering = compare_values(&left, &right);
                let ordering = match sort.direction {
                    BaselineSortDirection::Asc => ordering,
                    BaselineSortDirection::Desc => ordering.reverse(),
                };
                if !ordering.is_eq() {
                    return ordering;
                }
            }
            left.cmp(right)
        });

        let matched_rows = row_indexes.len();
        let start = query.offset.min(matched_rows);
        let end = start.saturating_add(query.limit).min(matched_rows);
        (matched_rows, row_indexes[start..end].to_vec())
    };

    let mut rows = Vec::new();
    for row_idx in &page_indexes {
        let mut row = serde_json::Map::new();
        for col_idx in &projected {
            let col_name = &columns[*col_idx];
            row.insert(
                col_name.clone(),
                cell_value(col_ptrs[*col_idx], *row_idx as i64),
            );
        }
        rows.push(serde_json::Value::Object(row));
    }

    Ok(BaselineTableRows {
        name: name.to_string(),
        columns: projected.iter().map(|idx| columns[*idx].clone()).collect(),
        rows,
        offset: query.offset,
        limit: query.limit,
        total_rows,
        matched_rows,
    })
}

fn project_columns(
    columns: &[String],
    requested: Option<&[String]>,
) -> Result<Vec<usize>, MemoryError> {
    match requested {
        Some(requested) if !requested.is_empty() => requested
            .iter()
            .map(|name| column_index(columns, name))
            .collect(),
        _ => Ok((0..columns.len()).collect()),
    }
}

fn compile_filters(
    columns: &[String],
    filters: Vec<BaselineTableFilter>,
) -> Result<Vec<CompiledFilter>, MemoryError> {
    filters
        .into_iter()
        .map(|filter| {
            let col_idx = column_index(columns, &filter.column)?;
            let regex = match filter.op {
                BaselineFilterOp::Regex | BaselineFilterOp::NotRegex => Some(
                    regex::Regex::new(filter.value.as_str().unwrap_or_default()).map_err(
                        |source| MemoryError::InvalidRegex {
                            column: filter.column.clone(),
                            source,
                        },
                    )?,
                ),
                _ => None,
            };
            Ok(CompiledFilter {
                col_idx,
                op: filter.op,
                value: filter.value,
                regex,
            })
        })
        .collect()
}

fn column_index(columns: &[String], name: &str) -> Result<usize, MemoryError> {
    columns
        .iter()
        .position(|column| column == name)
        .ok_or_else(|| MemoryError::UnknownColumn(name.to_string()))
}

fn row_matches(
    col_ptrs: &[*mut crate::sys::ray_t],
    row_idx: usize,
    filters: &[CompiledFilter],
    filter_mode: BaselineFilterMode,
) -> bool {
    if filters.is_empty() {
        return true;
    }
    let matches = |filter: &CompiledFilter| {
        filter_matches(
            filter,
            &cell_value(col_ptrs[filter.col_idx], row_idx as i64),
            &filter.value,
        )
    };
    match filter_mode {
        BaselineFilterMode::All => filters.iter().all(matches),
        BaselineFilterMode::Any => filters.iter().any(matches),
    }
}

struct CompiledFilter {
    col_idx: usize,
    op: BaselineFilterOp,
    value: serde_json::Value,
    regex: Option<regex::Regex>,
}

fn filter_matches(
    filter: &CompiledFilter,
    actual: &serde_json::Value,
    expected: &serde_json::Value,
) -> bool {
    match filter.op {
        BaselineFilterOp::Eq => values_equal(actual, expected),
        BaselineFilterOp::Ne => !values_equal(actual, expected),
        BaselineFilterOp::In => value_set(expected)
            .is_some_and(|values| values.iter().any(|expected| values_equal(actual, expected))),
        BaselineFilterOp::NotIn => value_set(expected).is_some_and(|values| {
            values
                .iter()
                .all(|expected| !values_equal(actual, expected))
        }),
        BaselineFilterOp::Contains => string_pair(actual, expected)
            .is_some_and(|(actual, expected)| actual.contains(expected)),
        BaselineFilterOp::StartsWith => string_pair(actual, expected)
            .is_some_and(|(actual, expected)| actual.starts_with(expected)),
        BaselineFilterOp::EndsWith => string_pair(actual, expected)
            .is_some_and(|(actual, expected)| actual.ends_with(expected)),
        BaselineFilterOp::Regex => regex_match(actual, filter.regex.as_ref()),
        BaselineFilterOp::NotRegex => !regex_match(actual, filter.regex.as_ref()),
        BaselineFilterOp::Gt => compare_values(actual, expected).is_gt(),
        BaselineFilterOp::Gte => !compare_values(actual, expected).is_lt(),
        BaselineFilterOp::Lt => compare_values(actual, expected).is_lt(),
        BaselineFilterOp::Lte => !compare_values(actual, expected).is_gt(),
    }
}

fn regex_match(actual: &serde_json::Value, pattern: Option<&regex::Regex>) -> bool {
    actual
        .as_str()
        .zip(pattern)
        .is_some_and(|(actual, pattern)| pattern.is_match(actual))
}

fn value_set(value: &serde_json::Value) -> Option<&[serde_json::Value]> {
    value.as_array().map(Vec::as_slice)
}

fn values_equal(left: &serde_json::Value, right: &serde_json::Value) -> bool {
    if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
        (left - right).abs() < f64::EPSILON
    } else {
        left == right
    }
}

fn string_pair<'a>(
    actual: &'a serde_json::Value,
    expected: &'a serde_json::Value,
) -> Option<(&'a str, &'a str)> {
    Some((actual.as_str()?, expected.as_str()?))
}

fn compare_values(left: &serde_json::Value, right: &serde_json::Value) -> std::cmp::Ordering {
    match (left.as_f64(), right.as_f64()) {
        (Some(left), Some(right)) => left
            .partial_cmp(&right)
            .unwrap_or(std::cmp::Ordering::Equal),
        _ => value_sort_key(left).cmp(&value_sort_key(right)),
    }
}

fn value_sort_key(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => value.to_string(),
    }
}

fn symbol_text(name_id: i64) -> String {
    let atom = unsafe { crate::sys::ray_sym_str(name_id) };
    if atom.is_null() {
        return format!("#{name_id}");
    }
    string_atom(atom).unwrap_or_else(|| format!("#{name_id}"))
}

fn cell_value(col: *mut crate::sys::ray_t, row_idx: i64) -> serde_json::Value {
    if col.is_null() {
        return serde_json::Value::Null;
    }
    let len = unsafe { (*col).len };
    if row_idx < 0 || row_idx >= len {
        return serde_json::Value::Null;
    }

    match unsafe { (*col).type_ } {
        crate::sys::RAY_BOOL => {
            let data = ray_data(col);
            serde_json::Value::Bool(unsafe { *data.add(row_idx as usize) } != 0)
        }
        crate::sys::RAY_I32 => {
            let data = ray_data(col).cast::<i32>();
            serde_json::Value::from(unsafe { *data.add(row_idx as usize) })
        }
        crate::sys::RAY_I64 => {
            let data = ray_data(col).cast::<i64>();
            serde_json::Value::from(unsafe { *data.add(row_idx as usize) })
        }
        crate::sys::RAY_F32 => {
            let data = ray_data(col).cast::<f32>();
            serde_json::Number::from_f64(unsafe { *data.add(row_idx as usize) } as f64)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        crate::sys::RAY_F64 => {
            let data = ray_data(col).cast::<f64>();
            serde_json::Number::from_f64(unsafe { *data.add(row_idx as usize) })
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        crate::sys::RAY_SYM => {
            // Adaptive width encoded in the low 2 bits of attrs:
            // 0=W8 (uint8), 1=W16 (uint16), 2=W32 (uint32), 3=W64 (int64).
            // Decode the index, then resolve through the global sym table.
            let data = ray_data(col);
            let attrs = unsafe { (*col).attrs };
            let id: i64 = match attrs & 0b11 {
                0 => i64::from(unsafe { *data.add(row_idx as usize) }),
                1 => i64::from(unsafe { *data.cast::<u16>().add(row_idx as usize) }),
                2 => i64::from(unsafe { *data.cast::<u32>().add(row_idx as usize) }),
                _ => unsafe { *data.cast::<i64>().add(row_idx as usize) },
            };
            serde_json::Value::String(symbol_text(id))
        }
        crate::sys::RAY_STR => string_vec_value(col, row_idx)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
        crate::sys::RAY_LIST => {
            // Heterogeneous: each slot is a ray_t* atom.  Recurse via
            // atom_to_json so dicts and graph.info results render their
            // mixed-type values as proper JSON.
            let elem = unsafe { crate::sys::ray_list_get(col, row_idx) };
            if elem.is_null() {
                serde_json::Value::Null
            } else if unsafe { (*elem).type_ } < 0 {
                atom_to_json(elem)
            } else {
                serde_json::Value::String(format!("<unsupported list elem type {}>", unsafe {
                    (*elem).type_
                }))
            }
        }
        other => serde_json::Value::String(format!("<unsupported type {other}>")),
    }
}

fn ray_data(obj: *mut crate::sys::ray_t) -> *const u8 {
    unsafe {
        obj.cast::<u8>()
            .add(std::mem::size_of::<crate::sys::ray_t>())
    }
}

fn string_vec_value(col: *mut crate::sys::ray_t, row_idx: i64) -> Option<String> {
    let mut len = 0usize;
    let ptr = unsafe { crate::sys::ray_str_vec_get(col, row_idx, &mut len) };
    if ptr.is_null() {
        return None;
    }
    Some(
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
            .into_owned(),
    )
}

fn string_atom(atom: *mut crate::sys::ray_t) -> Option<String> {
    let len = unsafe { crate::sys::ray_str_len(atom) };
    let ptr = unsafe { crate::sys::ray_str_ptr(atom) };
    if ptr.is_null() {
        return None;
    }
    Some(
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
            .into_owned(),
    )
}

struct RayObject {
    ptr: NonNull<crate::sys::ray_t>,
}

impl RayObject {
    fn new(ptr: *mut crate::sys::ray_t, context: &'static str) -> Result<Self, MemoryError> {
        NonNull::new(ptr)
            .map(|ptr| Self { ptr })
            .ok_or(MemoryError::Null(context))
    }

    fn as_ptr(&self) -> *mut crate::sys::ray_t {
        self.ptr.as_ptr()
    }

    fn into_raw(self) -> *mut crate::sys::ray_t {
        let ptr = self.ptr.as_ptr();
        std::mem::forget(self);
        ptr
    }
}

impl Drop for RayObject {
    fn drop(&mut self) {
        unsafe {
            crate::sys::ray_release(self.ptr.as_ptr());
        }
    }
}

fn init_symbols() -> Result<(), MemoryError> {
    // ensure_runtime is a strict superset (heap + sym + lang + env + builtins).
    // Routing through it from the existing init_symbols call sites means the
    // Rayfall eval path inside query_with_rayfall always finds a fully-staged
    // runtime, regardless of which entry point reached rayforce first.
    ensure_runtime()
}

/// Process-lifetime rayforce runtime. Stored as a raw pointer cast to usize so
/// it fits in `OnceLock`; 0 marks an init failure that must be reported on
/// every subsequent call.  Never destroyed: a rayforce runtime is a singleton
/// that owns global state (heap + sym + env + builtins), and tearing it down
/// mid-process would invalidate every live `ray_t*` raysense holds.  Process
/// exit cleans up.
static RUNTIME: OnceLock<usize> = OnceLock::new();

fn ensure_runtime() -> Result<(), MemoryError> {
    let ptr =
        RUNTIME.get_or_init(
            || unsafe { crate::sys::ray_runtime_create_with_sym(std::ptr::null()) }
                as *mut crate::sys::ray_runtime_t as usize,
        );
    if *ptr == 0 {
        Err(MemoryError::RuntimeInit)
    } else {
        Ok(())
    }
}

/// Install a process-global progress callback that writes one line to
/// stderr per tick, throttled by the rayforce executor so quick queries
/// stay silent.  Idempotent; subsequent calls are no-ops.
///
/// CLI surfaces (`baseline query`, `policy check`) call this so users
/// see live feedback during long Rayfall evaluations.  MCP and unit
/// tests skip it -- progress lines on stderr would corrupt the JSON
/// stream parsers expect, and tests are noisy enough already.
pub fn enable_cli_progress() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        unsafe {
            // min_ms=200 hides quick queries entirely; tick=400 throttles
            // updates to ~2-3 lines per second on long ones.  Tuned for
            // human readability over machine-fast firehose.
            crate::sys::ray_progress_set_callback(
                Some(cli_progress_writer),
                std::ptr::null_mut(),
                200,
                400,
            );
        }
    });
}

unsafe extern "C" fn cli_progress_writer(
    snap: *const crate::sys::ray_progress_t,
    _user: *mut std::ffi::c_void,
) {
    use std::io::Write;

    if snap.is_null() {
        return;
    }
    let s = unsafe { &*snap };

    let op = c_str_or(s.op_name, "?");
    let phase = c_str_or(s.phase, "");
    let phase_segment = if phase.is_empty() {
        String::new()
    } else {
        format!(" / {phase}")
    };
    let progress = if s.rows_total > 0 {
        format!(
            "{:>5.1}%  ({} / {})",
            (s.rows_done as f64 / s.rows_total as f64) * 100.0,
            s.rows_done,
            s.rows_total,
        )
    } else if s.rows_done > 0 {
        format!("{} rows", s.rows_done)
    } else {
        String::from("...")
    };
    let mem_mb = (s.mem_used as f64) / (1024.0 * 1024.0);
    let suffix = if s.final_ { "\n" } else { "\r" };

    // Write straight through stderr() to avoid line buffering -- progress
    // lines need to land between rayforce ticks, not when Rust's buffer
    // happens to flush.
    let mut err = std::io::stderr().lock();
    let _ = write!(
        err,
        "[rayfall] {op}{phase_segment}  {progress}  elapsed={:.1}s  mem={mem_mb:.1}MB{suffix}",
        s.elapsed_sec,
    );
    let _ = err.flush();
}

unsafe fn c_str_or(ptr: *const std::os::raw::c_char, fallback: &str) -> String {
    if ptr.is_null() {
        return fallback.to_string();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
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
    let languages = sym_vec(
        report.files.len(),
        report.files.iter().map(|file| file.language_name.clone()),
    )?;
    let modules = sym_vec(
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
    let visibilities = sym_vec(
        report.functions.len(),
        report
            .functions
            .iter()
            .map(|function| function.visibility.as_str().to_string()),
    )?;

    table(
        6,
        [
            ("function_id", ids),
            ("file_id", file_ids),
            ("name", names),
            ("start_line", start_lines),
            ("end_line", end_lines),
            ("visibility", visibilities),
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
    let kinds = sym_vec(
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
    let kinds = sym_vec(
        report.imports.len(),
        report.imports.iter().map(|import| import.kind.clone()),
    )?;
    let resolutions = sym_vec(
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
    let aliases = str_vec(
        report.imports.len(),
        report
            .imports
            .iter()
            .map(|import| import.alias.clone().unwrap_or_default()),
    )?;

    table(
        7,
        [
            ("import_id", ids),
            ("from_file", from_files),
            ("target", targets),
            ("kind", kinds),
            ("resolution", resolutions),
            ("resolved_file", resolved_files),
            ("alias", aliases),
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

fn build_file_ownership_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.metrics.evolution.file_ownership.len();
    let paths = str_vec(
        rows,
        health
            .metrics
            .evolution
            .file_ownership
            .iter()
            .map(|file| file.path.clone()),
    )?;
    let top_authors = sym_vec(
        rows,
        health
            .metrics
            .evolution
            .file_ownership
            .iter()
            .map(|file| file.top_author.clone()),
    )?;
    let top_author_commits = i64_vec(
        rows,
        health
            .metrics
            .evolution
            .file_ownership
            .iter()
            .map(|file| file.top_author_commits as i64),
    )?;
    let total_commits = i64_vec(
        rows,
        health
            .metrics
            .evolution
            .file_ownership
            .iter()
            .map(|file| file.total_commits as i64),
    )?;
    let author_count = i64_vec(
        rows,
        health
            .metrics
            .evolution
            .file_ownership
            .iter()
            .map(|file| file.author_count as i64),
    )?;
    let bus_factor = i64_vec(
        rows,
        health
            .metrics
            .evolution
            .file_ownership
            .iter()
            .map(|file| file.bus_factor as i64),
    )?;
    table(
        6,
        [
            ("path", paths),
            ("top_author", top_authors),
            ("top_author_commits", top_author_commits),
            ("total_commits", total_commits),
            ("author_count", author_count),
            ("bus_factor", bus_factor),
        ],
    )
}

fn build_types_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let ids = i64_vec(
        report.types.len(),
        report
            .types
            .iter()
            .map(|type_fact| type_fact.type_id as i64),
    )?;
    let file_ids = i64_vec(
        report.types.len(),
        report
            .types
            .iter()
            .map(|type_fact| type_fact.file_id as i64),
    )?;
    let names = str_vec(
        report.types.len(),
        report.types.iter().map(|type_fact| type_fact.name.clone()),
    )?;
    let abstract_flags = i64_vec(
        report.types.len(),
        report
            .types
            .iter()
            .map(|type_fact| if type_fact.is_abstract { 1 } else { 0 }),
    )?;
    let lines = i64_vec(
        report.types.len(),
        report.types.iter().map(|type_fact| type_fact.line as i64),
    )?;
    let visibilities = sym_vec(
        report.types.len(),
        report
            .types
            .iter()
            .map(|type_fact| type_fact.visibility.as_str().to_string()),
    )?;

    table(
        6,
        [
            ("type_id", ids),
            ("file_id", file_ids),
            ("name", names),
            ("is_abstract", abstract_flags),
            ("line", lines),
            ("visibility", visibilities),
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
        48,
        [
            ("score", i64_vec(1, [health.score as i64])?),
            (
                "quality_signal",
                i64_vec(1, [health.quality_signal as i64])?,
            ),
            (
                "coverage_score",
                i64_vec(1, [health.coverage_score as i64])?,
            ),
            (
                "structural_score",
                i64_vec(1, [health.structural_score as i64])?,
            ),
            (
                "modularity_per_1000",
                i64_vec(1, [(health.root_causes.modularity * 1000.0).round() as i64])?,
            ),
            (
                "acyclicity_per_1000",
                i64_vec(1, [(health.root_causes.acyclicity * 1000.0).round() as i64])?,
            ),
            (
                "depth_per_1000",
                i64_vec(1, [(health.root_causes.depth * 1000.0).round() as i64])?,
            ),
            (
                "equality_per_1000",
                i64_vec(1, [(health.root_causes.equality * 1000.0).round() as i64])?,
            ),
            (
                "redundancy_per_1000",
                i64_vec(1, [(health.root_causes.redundancy * 1000.0).round() as i64])?,
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
                "max_function_complexity",
                i64_vec(
                    1,
                    [health.metrics.complexity.max_function_complexity as i64],
                )?,
            ),
            (
                "average_function_complexity_per_1000",
                i64_vec(
                    1,
                    [
                        (health.metrics.complexity.average_function_complexity * 1000.0).round()
                            as i64,
                    ],
                )?,
            ),
            (
                "complexity_gini_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.complexity.complexity_gini * 1000.0).round() as i64],
                )?,
            ),
            (
                "redundancy_ratio_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.complexity.redundancy_ratio * 1000.0).round() as i64],
                )?,
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
            (
                "file_size_entropy_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.size.file_size_entropy * 1000.0).round() as i64],
                )?,
            ),
            (
                "file_size_entropy_bits_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.size.file_size_entropy_bits * 1000.0).round() as i64],
                )?,
            ),
            (
                "complexity_entropy_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.complexity.complexity_entropy * 1000.0).round() as i64],
                )?,
            ),
            (
                "complexity_entropy_bits_per_1000",
                i64_vec(
                    1,
                    [(health.metrics.complexity.complexity_entropy_bits * 1000.0).round() as i64],
                )?,
            ),
            (
                "structural_uniformity_per_1000",
                i64_vec(
                    1,
                    [(health.root_causes.structural_uniformity * 1000.0).round() as i64],
                )?,
            ),
            (
                "grade_overall",
                str_vec(1, [health.grades.overall.clone()])?,
            ),
            (
                "grade_modularity",
                str_vec(1, [health.grades.modularity.clone()])?,
            ),
            (
                "grade_acyclicity",
                str_vec(1, [health.grades.acyclicity.clone()])?,
            ),
            ("grade_depth", str_vec(1, [health.grades.depth.clone()])?),
            (
                "grade_equality",
                str_vec(1, [health.grades.equality.clone()])?,
            ),
            (
                "grade_redundancy",
                str_vec(1, [health.grades.redundancy.clone()])?,
            ),
            (
                "grade_structural_uniformity",
                str_vec(1, [health.grades.structural_uniformity.clone()])?,
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
                sym_vec(
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

fn build_temporal_hotspots_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.metrics.evolution.temporal_hotspots.len();
    let hotspots = &health.metrics.evolution.temporal_hotspots;
    table(
        4,
        [
            (
                "path",
                str_vec(rows, hotspots.iter().map(|h| h.path.clone()))?,
            ),
            (
                "commits",
                i64_vec(rows, hotspots.iter().map(|h| h.commits as i64))?,
            ),
            (
                "max_complexity",
                i64_vec(rows, hotspots.iter().map(|h| h.max_complexity as i64))?,
            ),
            (
                "risk_score",
                i64_vec(rows, hotspots.iter().map(|h| h.risk_score as i64))?,
            ),
        ],
    )
}

fn build_file_ages_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.metrics.evolution.file_ages.len();
    let ages = &health.metrics.evolution.file_ages;
    table(
        5,
        [
            ("path", str_vec(rows, ages.iter().map(|a| a.path.clone()))?),
            (
                "first_commit_unix",
                i64_vec(rows, ages.iter().map(|a| a.first_commit_unix))?,
            ),
            (
                "last_commit_unix",
                i64_vec(rows, ages.iter().map(|a| a.last_commit_unix))?,
            ),
            (
                "age_days",
                i64_vec(rows, ages.iter().map(|a| a.age_days as i64))?,
            ),
            (
                "last_changed_days",
                i64_vec(rows, ages.iter().map(|a| a.last_changed_days as i64))?,
            ),
        ],
    )
}

fn build_change_coupling_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = health.metrics.evolution.change_coupling.len();
    let pairs = &health.metrics.evolution.change_coupling;
    table(
        4,
        [
            ("left", str_vec(rows, pairs.iter().map(|p| p.left.clone()))?),
            (
                "right",
                str_vec(rows, pairs.iter().map(|p| p.right.clone()))?,
            ),
            (
                "co_commits",
                i64_vec(rows, pairs.iter().map(|p| p.co_commits as i64))?,
            ),
            (
                // Stored as integer milli to fit the i64-only column type;
                // divide by 1000 on read to recover the [0, 1] Jaccard.
                "coupling_strength_milli",
                i64_vec(
                    rows,
                    pairs
                        .iter()
                        .map(|p| (p.coupling_strength * 1000.0).round() as i64),
                )?,
            ),
        ],
    )
}

fn build_inheritance_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let rows: Vec<(usize, &str, &str)> = report
        .types
        .iter()
        .flat_map(|type_fact| {
            type_fact
                .bases
                .iter()
                .map(move |base| (type_fact.type_id, type_fact.name.as_str(), base.as_str()))
        })
        .collect();
    let n = rows.len();
    table(
        3,
        [
            (
                "type_id",
                i64_vec(n, rows.iter().map(|(id, _, _)| *id as i64))?,
            ),
            (
                "name",
                str_vec(n, rows.iter().map(|(_, name, _)| (*name).to_string()))?,
            ),
            (
                "base",
                str_vec(n, rows.iter().map(|(_, _, base)| (*base).to_string()))?,
            ),
        ],
    )
}

fn build_trait_impls_table(report: &ScanReport) -> Result<RayObject, MemoryError> {
    let rows = report.trait_impls.len();
    table(
        5,
        [
            (
                "impl_id",
                i64_vec(rows, report.trait_impls.iter().map(|i| i.impl_id as i64))?,
            ),
            (
                "file_id",
                i64_vec(rows, report.trait_impls.iter().map(|i| i.file_id as i64))?,
            ),
            (
                "type_name",
                str_vec(rows, report.trait_impls.iter().map(|i| i.type_name.clone()))?,
            ),
            (
                "trait_name",
                str_vec(
                    rows,
                    report.trait_impls.iter().map(|i| i.trait_name.clone()),
                )?,
            ),
            (
                "line",
                i64_vec(rows, report.trait_impls.iter().map(|i| i.line as i64))?,
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

/// One row per (cycle, module) pair.  `cycle_id` groups members of the
/// same SCC; `scc_size` repeats per row so a `(select {from: t where:
/// (> scc_size 3)})` style query can find multi-module cycles directly.
fn build_arch_cycles_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let mut cycle_ids: Vec<i64> = Vec::new();
    let mut modules: Vec<String> = Vec::new();
    let mut sizes: Vec<i64> = Vec::new();
    for (idx, scc) in health.metrics.architecture.cycles.iter().enumerate() {
        let size = scc.len() as i64;
        for module in scc {
            cycle_ids.push(idx as i64);
            modules.push(module.clone());
            sizes.push(size);
        }
    }
    let total = cycle_ids.len();
    table(
        3,
        [
            ("cycle_id", i64_vec(total, cycle_ids)?),
            ("module", sym_vec(total, modules)?),
            ("scc_size", i64_vec(total, sizes)?),
        ],
    )
}

fn build_arch_unstable_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    build_stability_table(&health.metrics.architecture.unstable_modules)
}

fn build_arch_foundations_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    build_stability_table(&health.metrics.architecture.stable_foundations)
}

fn build_stability_table(rows: &[crate::ModuleStabilityMetric]) -> Result<RayObject, MemoryError> {
    let n = rows.len();
    table(
        4,
        [
            ("module", sym_vec(n, rows.iter().map(|m| m.module.clone()))?),
            ("fan_in", i64_vec(n, rows.iter().map(|m| m.fan_in as i64))?),
            (
                "fan_out",
                i64_vec(n, rows.iter().map(|m| m.fan_out as i64))?,
            ),
            (
                "instability",
                f64_vec(n, rows.iter().map(|m| m.instability))?,
            ),
        ],
    )
}

fn build_arch_levels_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let pairs: Vec<(String, i64)> = health
        .metrics
        .architecture
        .levels
        .iter()
        .map(|(module, level)| (module.clone(), *level as i64))
        .collect();
    let n = pairs.len();
    table(
        2,
        [
            ("module", sym_vec(n, pairs.iter().map(|p| p.0.clone()))?),
            ("level", i64_vec(n, pairs.iter().map(|p| p.1))?),
        ],
    )
}

fn build_arch_distance_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = &health.metrics.architecture.distance_metrics;
    let n = rows.len();
    table(
        8,
        [
            ("module", sym_vec(n, rows.iter().map(|m| m.module.clone()))?),
            (
                "abstractness",
                f64_vec(n, rows.iter().map(|m| m.abstractness))?,
            ),
            (
                "instability",
                f64_vec(n, rows.iter().map(|m| m.instability))?,
            ),
            ("distance", f64_vec(n, rows.iter().map(|m| m.distance))?),
            (
                "abstract_count",
                i64_vec(n, rows.iter().map(|m| m.abstract_count as i64))?,
            ),
            (
                "total_types",
                i64_vec(n, rows.iter().map(|m| m.total_types as i64))?,
            ),
            ("fan_in", i64_vec(n, rows.iter().map(|m| m.fan_in as i64))?),
            (
                "fan_out",
                i64_vec(n, rows.iter().map(|m| m.fan_out as i64))?,
            ),
        ],
    )
}

fn build_arch_violations_table(health: &HealthSummary) -> Result<RayObject, MemoryError> {
    let rows = &health.metrics.architecture.upward_violations;
    let n = rows.len();
    table(
        7,
        [
            (
                "from_file_id",
                i64_vec(n, rows.iter().map(|v| v.from_file_id as i64))?,
            ),
            (
                "from_path",
                str_vec(n, rows.iter().map(|v| v.from_path.clone()))?,
            ),
            (
                "from_level",
                i64_vec(n, rows.iter().map(|v| v.from_level as i64))?,
            ),
            (
                "to_file_id",
                i64_vec(n, rows.iter().map(|v| v.to_file_id as i64))?,
            ),
            (
                "to_path",
                str_vec(n, rows.iter().map(|v| v.to_path.clone()))?,
            ),
            (
                "to_level",
                i64_vec(n, rows.iter().map(|v| v.to_level as i64))?,
            ),
            ("reason", sym_vec(n, rows.iter().map(|v| v.reason.clone()))?),
        ],
    )
}

/// Wide-format trend table: one row per persisted snapshot, one column
/// per tracked dimension. Aggregate scalars (`score`, `quality_signal`,
/// `rules`) sit alongside the six root-cause floats and the overall
/// letter grade. v1 samples (no `schema` field) lack the new
/// hotspot/rule-breakdown fields but still contribute a complete row
/// here, since every column comes from fields that already existed.
fn build_trend_health_table(samples: &[TrendSample]) -> Result<RayObject, MemoryError> {
    let n = samples.len();
    table(
        12,
        [
            (
                "timestamp",
                i64_vec(n, samples.iter().map(|s| s.timestamp))?,
            ),
            (
                "snapshot_id",
                sym_vec(n, samples.iter().map(|s| s.snapshot_id.clone()))?,
            ),
            ("score", i64_vec(n, samples.iter().map(|s| s.score as i64))?),
            (
                "quality_signal",
                i64_vec(n, samples.iter().map(|s| s.quality_signal as i64))?,
            ),
            ("rules", i64_vec(n, samples.iter().map(|s| s.rules as i64))?),
            (
                "modularity",
                f64_vec(n, samples.iter().map(|s| s.root_causes.modularity))?,
            ),
            (
                "acyclicity",
                f64_vec(n, samples.iter().map(|s| s.root_causes.acyclicity))?,
            ),
            (
                "depth",
                f64_vec(n, samples.iter().map(|s| s.root_causes.depth))?,
            ),
            (
                "equality",
                f64_vec(n, samples.iter().map(|s| s.root_causes.equality))?,
            ),
            (
                "redundancy",
                f64_vec(n, samples.iter().map(|s| s.root_causes.redundancy))?,
            ),
            (
                "structural_uniformity",
                f64_vec(
                    n,
                    samples.iter().map(|s| s.root_causes.structural_uniformity),
                )?,
            ),
            (
                "overall_grade",
                sym_vec(n, samples.iter().map(|s| s.overall_grade.clone()))?,
            ),
        ],
    )
}

/// Long-format trend table: one row per (snapshot, hotspot) pair. v1
/// samples carry no hotspots so they contribute zero rows. Files repeat
/// across snapshots, so `path` is dict-encoded.
fn build_trend_hotspots_table(samples: &[TrendSample]) -> Result<RayObject, MemoryError> {
    let mut timestamps: Vec<i64> = Vec::new();
    let mut snapshot_ids: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut commits: Vec<i64> = Vec::new();
    let mut max_complexities: Vec<i64> = Vec::new();
    let mut risk_scores: Vec<i64> = Vec::new();
    for sample in samples {
        for hotspot in &sample.top_hotspots {
            timestamps.push(sample.timestamp);
            snapshot_ids.push(sample.snapshot_id.clone());
            paths.push(hotspot.path.clone());
            commits.push(hotspot.commits as i64);
            max_complexities.push(hotspot.max_complexity as i64);
            risk_scores.push(hotspot.risk_score as i64);
        }
    }
    let n = timestamps.len();
    table(
        6,
        [
            ("timestamp", i64_vec(n, timestamps)?),
            ("snapshot_id", sym_vec(n, snapshot_ids)?),
            ("path", sym_vec(n, paths)?),
            ("commits", i64_vec(n, commits)?),
            ("max_complexity", i64_vec(n, max_complexities)?),
            ("risk_score", i64_vec(n, risk_scores)?),
        ],
    )
}

/// Splay-native trend log path. All trend appends and reads anchor at
/// `<root>/.raysense/baseline/tables/`, sharing the same `.sym`
/// dict-encoding file as the rest of the saved baseline.
const TREND_HEALTH_NAME: &str = "trend_health";
const TREND_HOTSPOTS_NAME: &str = "trend_hotspots";
const TREND_VIOLATIONS_NAME: &str = "trend_violations";

/// Concatenate two tables row-wise via Rayfall `concat`. The two
/// inputs must agree on column names and types; concat matches
/// columns by name so column order need not match. Both inputs are
/// bound under fresh names that won't collide with policy-pack
/// baseline-table bindings.
fn concat_tables(a: &RayObject, b: &RayObject) -> Result<RayObject, MemoryError> {
    init_symbols()?;

    let ka = CString::new("__rs_concat_a__")?;
    let kb = CString::new("__rs_concat_b__")?;
    let ida = unsafe { crate::sys::ray_sym_intern(ka.as_ptr(), ka.as_bytes().len()) };
    let idb = unsafe { crate::sys::ray_sym_intern(kb.as_ptr(), kb.as_bytes().len()) };

    let err = unsafe { crate::sys::ray_env_set(ida, a.as_ptr()) };
    if err != crate::sys::RAY_OK {
        return Err(MemoryError::RayfallEval {
            code: format!("env_set={err}"),
            detail: "concat: failed to bind first operand".to_string(),
        });
    }
    let err = unsafe { crate::sys::ray_env_set(idb, b.as_ptr()) };
    if err != crate::sys::RAY_OK {
        return Err(MemoryError::RayfallEval {
            code: format!("env_set={err}"),
            detail: "concat: failed to bind second operand".to_string(),
        });
    }

    let expr = CString::new("(concat __rs_concat_a__ __rs_concat_b__)")?;
    let raw = unsafe { crate::sys::ray_eval_str(expr.as_ptr()) };
    if raw.is_null() {
        return Err(MemoryError::RayfallEval {
            code: "null".to_string(),
            detail: "concat returned null".to_string(),
        });
    }
    let result = RayObject::new(raw, "concat result")?;
    let result_type = unsafe { (*result.as_ptr()).type_ };
    if result_type == crate::sys::RAY_ERROR {
        let code = unsafe {
            let p = crate::sys::ray_err_code(result.as_ptr());
            if p.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        return Err(MemoryError::RayfallEval {
            code,
            detail: "concat".to_string(),
        });
    }
    if result_type != crate::sys::RAY_TABLE {
        return Err(MemoryError::RayfallResultNotTable {
            type_tag: result_type,
        });
    }
    Ok(result)
}

/// Load a splayed table by directory using the non-mmap loader. The
/// returned table is buddy-allocated and survives deletion of the
/// source directory, which is essential for the load-then-rewrite
/// pattern used by `append_trend_sample_splay` and by
/// `RayMemory::from_report_with_config` (which reads existing trend
/// tables before `save_baseline` rebuilds the tables directory).
fn splay_load_owned(dir: &Path, sym_path: &Path) -> Result<Option<RayObject>, MemoryError> {
    if !dir.is_dir() {
        return Ok(None);
    }
    init_symbols()?;
    let dir_c = CString::new(dir.to_string_lossy().into_owned())?;
    let sym_c = if sym_path.exists() {
        Some(CString::new(sym_path.to_string_lossy().into_owned())?)
    } else {
        None
    };
    let raw = unsafe {
        crate::sys::ray_splay_load(
            dir_c.as_ptr(),
            sym_c
                .as_ref()
                .map(|p| p.as_ptr())
                .unwrap_or(std::ptr::null()),
        )
    };
    if raw.is_null() {
        return Ok(None);
    }
    if unsafe { (*raw).type_ } == crate::sys::RAY_ERROR {
        let code = unsafe {
            let p = crate::sys::ray_err_code(raw);
            if p.is_null() {
                "unknown".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        };
        unsafe { crate::sys::ray_release(raw) };
        return Err(MemoryError::SplayRead {
            table: dir.display().to_string(),
            code,
        });
    }
    Ok(Some(RayObject::new(raw, "splay_load_owned")?))
}

/// Resolve the canonical trend tables directory for a project root.
/// Trend tables always live alongside the rest of the saved baseline
/// at `<root>/.raysense/baseline/tables/`, regardless of whether
/// `baseline save` was last run with a custom output path. The
/// `.sym` file at that location is the shared dict-encoding store.
pub fn trend_tables_dir(root: &Path) -> PathBuf {
    root.join(".raysense/baseline/tables")
}

/// Load the three splayed trend tables for a project root. Each
/// table that's absent on disk is replaced with an empty splay table
/// of the right schema, so the caller always gets a valid in-memory
/// triple. The owned (non-mmap) loader is used so the returned
/// objects survive deletion of the source directory, which is what
/// `baseline save` does between read and rewrite.
fn load_or_empty_trend_tables(
    root: &Path,
) -> Result<(RayObject, RayObject, RayObject), MemoryError> {
    init_symbols()?;
    let tables_dir = trend_tables_dir(root);
    let sym_path = tables_dir.join(".sym");

    let load_or_empty = |name: &str,
                         build_empty: fn() -> Result<RayObject, MemoryError>|
     -> Result<RayObject, MemoryError> {
        let dir = tables_dir.join(name);
        // Tolerate corrupt or incompatible splay (e.g. a v0.7 baseline
        // left over after upgrade to v0.8): treat as missing and start
        // fresh. The user loses prior trend history, which matches the
        // no-back-compat policy of the v0.8 release notes.
        match splay_load_owned(&dir, &sym_path) {
            Ok(Some(table)) => Ok(table),
            Ok(None)
            | Err(MemoryError::SplayRead { .. })
            | Err(MemoryError::SplayReadNull { .. }) => build_empty(),
            Err(other) => Err(other),
        }
    };

    let health = load_or_empty(TREND_HEALTH_NAME, || build_trend_health_table(&[]))?;
    let hotspots = load_or_empty(TREND_HOTSPOTS_NAME, || build_trend_hotspots_table(&[]))?;
    let violations = load_or_empty(TREND_VIOLATIONS_NAME, || build_trend_violations_table(&[]))?;
    Ok((health, hotspots, violations))
}

/// Splay-native append: load existing trend tables (or treat as
/// empty if absent), build a one-sample delta from the current scan
/// + health, concat with the existing rows, splay-save back. Three
/// tables are touched: `trend_health` (one row), `trend_hotspots`
/// (up to 20 rows for the current scan's temporal hotspots), and
/// `trend_violations` (one row per distinct rule code).
///
/// Replaces the v0.7 JSON-write path. There is no JSON written or
/// read by raysense from v0.8 onwards.
///
/// Order matters: each `append_one_trend_table` call must load the
/// existing splay BEFORE building its delta. `ray_sym_load` enforces
/// position-equality (the disk file's symbol at index `i` must
/// intern at id `i` in the global sym table). Building a delta first
/// would intern new strings into slots the disk file expects to hold
/// its own previously-persisted strings, causing a `corrupt` failure
/// on the next process's append.
pub fn append_trend_sample_splay(
    report: &ScanReport,
    health: &HealthSummary,
    root: &Path,
) -> Result<(), MemoryError> {
    init_symbols()?;
    let tables_dir = trend_tables_dir(root);
    fs::create_dir_all(&tables_dir).map_err(|source| MemoryError::CreateDir {
        path: tables_dir.clone(),
        source,
    })?;
    let sym_path = tables_dir.join(".sym");

    let sample = crate::health::build_current_trend_sample(report, health);

    append_one_trend_table(&tables_dir, &sym_path, TREND_HEALTH_NAME, || {
        build_trend_health_table(std::slice::from_ref(&sample))
    })?;
    append_one_trend_table(&tables_dir, &sym_path, TREND_HOTSPOTS_NAME, || {
        build_trend_hotspots_table(std::slice::from_ref(&sample))
    })?;
    append_one_trend_table(&tables_dir, &sym_path, TREND_VIOLATIONS_NAME, || {
        build_trend_violations_table(std::slice::from_ref(&sample))
    })?;

    Ok(())
}

/// Append one row (or many) to a single splayed trend table. The
/// `delta_builder` is invoked AFTER `splay_load_owned` so any new
/// strings interned by the build land at id positions strictly
/// beyond what `ray_sym_load` populated from disk.
fn append_one_trend_table(
    tables_dir: &Path,
    sym_path: &Path,
    name: &'static str,
    delta_builder: impl FnOnce() -> Result<RayObject, MemoryError>,
) -> Result<(), MemoryError> {
    let table_dir = tables_dir.join(name);
    let combined = match splay_load_owned(&table_dir, sym_path)? {
        Some(existing) => {
            let delta = delta_builder()?;
            concat_tables(&existing, &delta)?
        }
        None => delta_builder()?,
    };
    let dir_c = CString::new(table_dir.to_string_lossy().into_owned())?;
    let sym_c = CString::new(sym_path.to_string_lossy().into_owned())?;
    let err =
        unsafe { crate::sys::ray_splay_save(combined.as_ptr(), dir_c.as_ptr(), sym_c.as_ptr()) };
    if err != crate::sys::RAY_OK {
        return Err(MemoryError::SplaySave {
            table: name,
            code: err,
        });
    }
    Ok(())
}

/// Read the persisted trend log from the splayed `trend_*` tables
/// and decode rows back into `Vec<TrendSample>`. Returns `None` if
/// `trend_health` is absent (no trend history yet); callers should
/// treat that as "no samples" rather than an error.
pub fn read_trend_history_from_splay(root: &Path) -> Option<Vec<TrendSample>> {
    let tables_dir = trend_tables_dir(root);
    let sym_path = tables_dir.join(".sym");
    let health_dir = tables_dir.join(TREND_HEALTH_NAME);
    if !health_dir.is_dir() {
        return None;
    }
    let health_table = splay_load_owned(&health_dir, &sym_path).ok().flatten()?;
    let hotspots_dir = tables_dir.join(TREND_HOTSPOTS_NAME);
    let hotspots_table = splay_load_owned(&hotspots_dir, &sym_path).ok().flatten();
    let violations_dir = tables_dir.join(TREND_VIOLATIONS_NAME);
    let violations_table = splay_load_owned(&violations_dir, &sym_path).ok().flatten();
    Some(decode_trend_samples(
        health_table.as_ptr(),
        hotspots_table.as_ref().map(|t| t.as_ptr()),
        violations_table.as_ref().map(|t| t.as_ptr()),
    ))
}

/// Decode the three trend tables into the typed sample form. Rows
/// in `trend_health` define the timeline; per-snapshot hotspots and
/// rule breakdowns are joined by `snapshot_id`. Reuses `cell_value`
/// so SYM/STR/numeric columns are decoded with the same width and
/// width-promotion logic as the rest of the baseline reader.
fn decode_trend_samples(
    health: *mut crate::sys::ray_t,
    hotspots: Option<*mut crate::sys::ray_t>,
    violations: Option<*mut crate::sys::ray_t>,
) -> Vec<TrendSample> {
    let nrows = unsafe { crate::sys::ray_table_nrows(health) };
    if nrows <= 0 {
        return Vec::new();
    }
    let nrows_us = nrows as usize;

    let null_col = std::ptr::null_mut::<crate::sys::ray_t>();
    fn cols_by_name(
        table: *mut crate::sys::ray_t,
    ) -> std::collections::BTreeMap<String, *mut crate::sys::ray_t> {
        let ncols = unsafe { crate::sys::ray_table_ncols(table) };
        let mut out = std::collections::BTreeMap::new();
        for idx in 0..ncols {
            let name_id = unsafe { crate::sys::ray_table_col_name(table, idx) };
            let col = unsafe { crate::sys::ray_table_get_col_idx(table, idx) };
            out.insert(symbol_text(name_id), col);
        }
        out
    }
    let cell_i64 = |col: *mut crate::sys::ray_t, idx: usize| -> i64 {
        cell_value(col, idx as i64).as_i64().unwrap_or(0)
    };
    let cell_f64 = |col: *mut crate::sys::ray_t, idx: usize| -> f64 {
        cell_value(col, idx as i64).as_f64().unwrap_or(0.0)
    };
    let cell_str = |col: *mut crate::sys::ray_t, idx: usize| -> String {
        cell_value(col, idx as i64)
            .as_str()
            .map(String::from)
            .unwrap_or_default()
    };

    let h_cols = cols_by_name(health);
    let h_ts = h_cols.get("timestamp").copied().unwrap_or(null_col);
    let h_sid = h_cols.get("snapshot_id").copied().unwrap_or(null_col);
    let h_score = h_cols.get("score").copied().unwrap_or(null_col);
    let h_qs = h_cols.get("quality_signal").copied().unwrap_or(null_col);
    let h_rules = h_cols.get("rules").copied().unwrap_or(null_col);
    let h_mod = h_cols.get("modularity").copied().unwrap_or(null_col);
    let h_acy = h_cols.get("acyclicity").copied().unwrap_or(null_col);
    let h_dep = h_cols.get("depth").copied().unwrap_or(null_col);
    let h_eq = h_cols.get("equality").copied().unwrap_or(null_col);
    let h_red = h_cols.get("redundancy").copied().unwrap_or(null_col);
    let h_su = h_cols
        .get("structural_uniformity")
        .copied()
        .unwrap_or(null_col);
    let h_grade = h_cols.get("overall_grade").copied().unwrap_or(null_col);

    let mut hotspots_by_snap: std::collections::BTreeMap<String, Vec<TrendHotspotSample>> =
        std::collections::BTreeMap::new();
    if let Some(table) = hotspots {
        let cols = cols_by_name(table);
        let nrows_h = unsafe { crate::sys::ray_table_nrows(table) } as usize;
        let c_sid = cols.get("snapshot_id").copied().unwrap_or(null_col);
        let c_path = cols.get("path").copied().unwrap_or(null_col);
        let c_commits = cols.get("commits").copied().unwrap_or(null_col);
        let c_max = cols.get("max_complexity").copied().unwrap_or(null_col);
        let c_risk = cols.get("risk_score").copied().unwrap_or(null_col);
        for idx in 0..nrows_h {
            let snap_id = cell_str(c_sid, idx);
            hotspots_by_snap
                .entry(snap_id)
                .or_default()
                .push(TrendHotspotSample {
                    path: cell_str(c_path, idx),
                    commits: cell_i64(c_commits, idx) as usize,
                    max_complexity: cell_i64(c_max, idx) as usize,
                    risk_score: cell_i64(c_risk, idx) as usize,
                });
        }
    }

    let mut violations_by_snap: std::collections::BTreeMap<String, BTreeMap<String, usize>> =
        std::collections::BTreeMap::new();
    if let Some(table) = violations {
        let cols = cols_by_name(table);
        let nrows_v = unsafe { crate::sys::ray_table_nrows(table) } as usize;
        let c_sid = cols.get("snapshot_id").copied().unwrap_or(null_col);
        let c_rule = cols.get("rule_id").copied().unwrap_or(null_col);
        let c_count = cols.get("count").copied().unwrap_or(null_col);
        for idx in 0..nrows_v {
            let snap_id = cell_str(c_sid, idx);
            let rule = cell_str(c_rule, idx);
            let count = cell_i64(c_count, idx) as usize;
            violations_by_snap
                .entry(snap_id)
                .or_default()
                .insert(rule, count);
        }
    }

    let mut samples: Vec<TrendSample> = Vec::with_capacity(nrows_us);
    for idx in 0..nrows_us {
        let snapshot_id = cell_str(h_sid, idx);
        let top_hotspots = hotspots_by_snap.remove(&snapshot_id).unwrap_or_default();
        let rule_breakdown = violations_by_snap.remove(&snapshot_id).unwrap_or_default();
        samples.push(TrendSample {
            timestamp: cell_i64(h_ts, idx),
            snapshot_id,
            score: cell_i64(h_score, idx) as u8,
            quality_signal: cell_i64(h_qs, idx) as u32,
            rules: cell_i64(h_rules, idx) as usize,
            root_causes: crate::health::RootCauseScores {
                modularity: cell_f64(h_mod, idx),
                acyclicity: cell_f64(h_acy, idx),
                depth: cell_f64(h_dep, idx),
                equality: cell_f64(h_eq, idx),
                redundancy: cell_f64(h_red, idx),
                structural_uniformity: cell_f64(h_su, idx),
            },
            overall_grade: cell_str(h_grade, idx),
            schema: 2,
            top_hotspots,
            rule_breakdown,
        });
    }
    samples
}

/// Long-format trend table: one row per (snapshot, rule_id) pair. v1
/// samples carry no rule breakdown so they contribute zero rows. Rule
/// codes repeat across snapshots, so `rule_id` is dict-encoded.
fn build_trend_violations_table(samples: &[TrendSample]) -> Result<RayObject, MemoryError> {
    let mut timestamps: Vec<i64> = Vec::new();
    let mut snapshot_ids: Vec<String> = Vec::new();
    let mut rule_ids: Vec<String> = Vec::new();
    let mut counts: Vec<i64> = Vec::new();
    for sample in samples {
        for (rule_id, count) in &sample.rule_breakdown {
            timestamps.push(sample.timestamp);
            snapshot_ids.push(sample.snapshot_id.clone());
            rule_ids.push(rule_id.clone());
            counts.push(*count as i64);
        }
    }
    let n = timestamps.len();
    table(
        4,
        [
            ("timestamp", i64_vec(n, timestamps)?),
            ("snapshot_id", sym_vec(n, snapshot_ids)?),
            ("rule_id", sym_vec(n, rule_ids)?),
            ("count", i64_vec(n, counts)?),
        ],
    )
}

/// Build the single-row `meta` table that stamps schema version, raysense and
/// rayforce versions, repo SHA, snapshot id, scan time, and a digest over every
/// other table's column shape. Readers compare the digest's `schema_version`
/// against `SCHEMA_VERSION` and refuse mismatched baselines.
fn build_meta_table(
    report: &ScanReport,
    other_tables: &[(&str, *mut crate::sys::ray_t)],
) -> Result<RayObject, MemoryError> {
    let raysense_version = env!("CARGO_PKG_VERSION").to_string();
    let rayforce_version = crate::sys::version_string();
    let repo_sha = git_head_sha(&report.snapshot.root).unwrap_or_default();
    let snapshot_id = report.snapshot.snapshot_id.clone();
    let scan_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let column_digest = compute_column_digest(other_tables);

    table(
        7,
        [
            (
                "schema_version",
                i64_vec(1, std::iter::once(SCHEMA_VERSION))?,
            ),
            ("raysense_version", str_vec(1, [raysense_version])?),
            ("rayforce_version", str_vec(1, [rayforce_version])?),
            ("repo_sha", str_vec(1, [repo_sha])?),
            ("snapshot_id", str_vec(1, [snapshot_id])?),
            ("scan_unix", i64_vec(1, std::iter::once(scan_unix))?),
            ("column_digest", str_vec(1, [column_digest])?),
        ],
    )
}

/// Best-effort `git rev-parse HEAD` against the scan root. Returns `None` if
/// the directory is not a git working tree, git is missing, or the call fails
/// for any reason; `repo_sha` is provenance, not a hard requirement.
fn git_head_sha(root: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.is_empty() {
        None
    } else {
        Some(sha)
    }
}

/// Hash a stable representation of every table's column shape so that any
/// schema drift (added / removed / renamed column) flips the digest. The
/// `meta` table itself is excluded; it would be circular and pollutes the
/// digest with values we control directly via `SCHEMA_VERSION`.
fn compute_column_digest(tables: &[(&str, *mut crate::sys::ray_t)]) -> String {
    let mut sorted: Vec<(&str, *mut crate::sys::ray_t)> = tables.to_vec();
    sorted.sort_by_key(|(name, _)| *name);

    let mut hasher = Sha256::new();
    for (name, table) in &sorted {
        hasher.update(name.as_bytes());
        hasher.update(b":");
        let ncols = unsafe { crate::sys::ray_table_ncols(*table) };
        for idx in 0..ncols {
            let name_id = unsafe { crate::sys::ray_table_col_name(*table, idx) };
            let column = symbol_text(name_id);
            hasher.update(column.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b";");
    }
    format!("{:x}", hasher.finalize())
}

/// Confirm a saved baseline's schema is compatible with the current build.
///
/// Behavior:
/// - `meta` table absent: legacy baseline written by an older raysense; pass
///   silently. Existing readers continue to work; the next save will stamp the
///   current version.
/// - `meta` table present: extract `schema_version`. Equal to `SCHEMA_VERSION`
///   passes; any other value fails with `MemoryError::SchemaMismatch`.
/// - `meta` table present but malformed (missing column, wrong type, no rows):
///   fail with `MemoryError::MetaTableMalformed` so we never silently accept a
///   broken provenance record.
pub fn verify_baseline_schema(dir: impl AsRef<Path>) -> Result<(), MemoryError> {
    init_symbols()?;
    let dir = dir.as_ref();
    if !dir.join("meta").is_dir() {
        return Ok(());
    }
    let table = read_table_object(dir, "meta")?;

    let ncols = unsafe { crate::sys::ray_table_ncols(table.as_ptr()) };
    let nrows = unsafe { crate::sys::ray_table_nrows(table.as_ptr()) };
    if nrows < 1 {
        return Err(MemoryError::MetaTableMalformed {
            reason: "meta table has zero rows".to_string(),
        });
    }

    let mut found: Option<i64> = None;
    for idx in 0..ncols {
        let name_id = unsafe { crate::sys::ray_table_col_name(table.as_ptr(), idx) };
        if symbol_text(name_id) != "schema_version" {
            continue;
        }
        let col = unsafe { crate::sys::ray_table_get_col_idx(table.as_ptr(), idx) };
        if col.is_null() || unsafe { (*col).type_ } != crate::sys::RAY_I64 {
            return Err(MemoryError::MetaTableMalformed {
                reason: "schema_version column is not RAY_I64".to_string(),
            });
        }
        let data = ray_data(col).cast::<i64>();
        found = Some(unsafe { *data });
        break;
    }

    let Some(version) = found else {
        return Err(MemoryError::MetaTableMalformed {
            reason: "schema_version column is missing".to_string(),
        });
    };
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(MemoryError::SchemaMismatch {
            found: version,
            expected: SCHEMA_VERSION,
        })
    }
}

fn i64_vec(
    capacity: usize,
    values: impl IntoIterator<Item = i64>,
) -> Result<RayObject, MemoryError> {
    let mut vec = RayObject::new(
        unsafe { crate::sys::ray_vec_new(crate::sys::RAY_I64, capacity as i64) },
        "i64 vector",
    )?;

    for value in values {
        let next = unsafe {
            crate::sys::ray_vec_append(
                vec.into_raw(),
                (&value as *const i64).cast::<std::ffi::c_void>(),
            )
        };
        vec = RayObject::new(next, "i64 vector append")?;
    }

    Ok(vec)
}

fn f64_vec(
    capacity: usize,
    values: impl IntoIterator<Item = f64>,
) -> Result<RayObject, MemoryError> {
    let mut vec = RayObject::new(
        unsafe { crate::sys::ray_vec_new(crate::sys::RAY_F64, capacity as i64) },
        "f64 vector",
    )?;

    for value in values {
        let next = unsafe {
            crate::sys::ray_vec_append(
                vec.into_raw(),
                (&value as *const f64).cast::<std::ffi::c_void>(),
            )
        };
        vec = RayObject::new(next, "f64 vector append")?;
    }

    Ok(vec)
}

fn str_vec(
    capacity: usize,
    values: impl IntoIterator<Item = String>,
) -> Result<RayObject, MemoryError> {
    let mut vec = RayObject::new(
        unsafe { crate::sys::ray_vec_new(crate::sys::RAY_STR, capacity as i64) },
        "string vector",
    )?;

    for value in values {
        let value = CString::new(value)?;
        let next = unsafe {
            crate::sys::ray_str_vec_append(vec.into_raw(), value.as_ptr(), value.as_bytes().len())
        };
        vec = RayObject::new(next, "string vector append")?;
    }

    Ok(vec)
}

/// Dict-encoded string column. Each value is interned through the global
/// symbol table once and stored as an i64 index in the resulting
/// `RAY_SYM` vector; repeated values share a single interned string.
/// Use this for low-cardinality columns (language tags, severity levels,
/// resolution states, author emails) where the storage and load-time win
/// over `str_vec` is meaningful.
fn sym_vec(
    capacity: usize,
    values: impl IntoIterator<Item = String>,
) -> Result<RayObject, MemoryError> {
    // W64 is the safe-default index width: the global sym table can grow
    // unboundedly across baselines, so picking a smaller width risks
    // overflow on a future re-save against a larger sym space.  The
    // adaptive-width support exists for cases where the cardinality is
    // known to be bounded (e.g. severity); this code keeps the contract
    // simple and uniform.
    let mut vec = RayObject::new(
        unsafe { crate::sys::ray_sym_vec_new(crate::sys::RAY_SYM_W64, capacity as i64) },
        "sym vector",
    )?;

    for value in values {
        let cstr = CString::new(value)?;
        let id: i64 = unsafe { crate::sys::ray_sym_intern(cstr.as_ptr(), cstr.as_bytes().len()) };
        let next = unsafe {
            crate::sys::ray_vec_append(
                vec.into_raw(),
                (&id as *const i64).cast::<std::ffi::c_void>(),
            )
        };
        vec = RayObject::new(next, "sym vector append")?;
    }

    Ok(vec)
}

fn table<const N: usize>(
    capacity: i64,
    columns: [(&'static str, RayObject); N],
) -> Result<RayObject, MemoryError> {
    let mut table = RayObject::new(
        unsafe { crate::sys::ray_table_new(capacity) },
        "rayforce table",
    )?;

    for (name, col) in columns {
        let name = CString::new(name)?;
        let name_id = unsafe { crate::sys::ray_sym_intern(name.as_ptr(), name.as_bytes().len()) };
        let next =
            unsafe { crate::sys::ray_table_add_col(table.into_raw(), name_id, col.as_ptr()) };
        table = RayObject::new(next, "rayforce table column")?;
    }

    Ok(table)
}

fn table_summary(table: *mut crate::sys::ray_t) -> TableSummary {
    TableSummary {
        columns: unsafe { crate::sys::ray_table_ncols(table) },
        rows: unsafe { crate::sys::ray_table_nrows(table) },
    }
}

#[cfg(test)]
mod test_lock {
    use std::sync::Mutex;

    /// Process-wide rayforce lock shared by every test module that
    /// touches the rayforce runtime (sym table, env, splay loaders,
    /// `ray_eval_str`). Cargo's parallel test runner would otherwise
    /// clobber global state.
    pub(super) static RAYFORCE_TEST_LOCK: Mutex<()> = Mutex::new(());
}

/// Test-only entry point for the shared rayforce lock. Exposed at
/// module scope so tests in other files (`cli.rs`, `mcp.rs`, ...)
/// can serialize without each redefining their own mutex (which
/// wouldn't actually share).
#[cfg(test)]
pub(crate) fn rayforce_test_guard() -> std::sync::MutexGuard<'static, ()> {
    match test_lock::RAYFORCE_TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Test-only: seed a project root's splayed trend tables with a
/// synthetic sample list. Replaces any existing trend tables. Used
/// by tests in other modules that previously wrote a synthetic
/// `history.json` and now need the splay equivalent.
#[cfg(test)]
pub(crate) fn write_trend_history_splay_for_tests(
    root: &Path,
    samples: &[TrendSample],
) -> Result<(), MemoryError> {
    init_symbols()?;
    let tables_dir = trend_tables_dir(root);
    fs::create_dir_all(&tables_dir).map_err(|source| MemoryError::CreateDir {
        path: tables_dir.clone(),
        source,
    })?;
    let sym_path = tables_dir.join(".sym");

    let health = build_trend_health_table(samples)?;
    let hotspots = build_trend_hotspots_table(samples)?;
    let violations = build_trend_violations_table(samples)?;

    let pairs = [
        (TREND_HEALTH_NAME, health),
        (TREND_HOTSPOTS_NAME, hotspots),
        (TREND_VIOLATIONS_NAME, violations),
    ];
    for (name, table) in pairs {
        let dir = tables_dir.join(name);
        let dir_c = CString::new(dir.to_string_lossy().into_owned())?;
        let sym_c = CString::new(sym_path.to_string_lossy().into_owned())?;
        let err =
            unsafe { crate::sys::ray_splay_save(table.as_ptr(), dir_c.as_ptr(), sym_c.as_ptr()) };
        if err != crate::sys::RAY_OK {
            return Err(MemoryError::SplaySave {
                table: name,
                code: err,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan_path, FileFact, Language, SnapshotFact};
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn rayforce_test_guard() -> std::sync::MutexGuard<'static, ()> {
        super::rayforce_test_guard()
    }

    #[test]
    fn builds_memory_tables_from_scan_report() {
        let _guard = rayforce_test_guard();
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
        assert_eq!(summary.types.rows as usize, report.types.len());
        assert_eq!(summary.types.columns, 6);
        assert_eq!(summary.functions.columns, 6);
        assert_eq!(summary.health.rows, 1);
        assert_eq!(summary.health.columns, 48);
        assert_eq!(summary.hotspots.columns, 5);
        assert_eq!(summary.rules.columns, 4);
        assert_eq!(summary.module_edges.columns, 3);
        assert_eq!(summary.changed_files.columns, 2);
        let health = crate::compute_health(&report);
        assert_eq!(summary.temporal_hotspots.columns, 4);
        assert_eq!(
            summary.temporal_hotspots.rows as usize,
            health.metrics.evolution.temporal_hotspots.len(),
        );
        assert_eq!(summary.file_ages.columns, 5);
        assert_eq!(summary.change_coupling.columns, 4);
        let inheritance_rows: usize = report
            .types
            .iter()
            .map(|type_fact| type_fact.bases.len())
            .sum();
        assert_eq!(summary.inheritance.columns, 3);
        assert_eq!(summary.inheritance.rows as usize, inheritance_rows);
        assert_eq!(summary.trait_impls.columns, 5);
        assert_eq!(
            summary.trait_impls.rows as usize,
            report.trait_impls.len(),
            "every trait_impls fact materializes a row"
        );
    }

    #[test]
    fn queries_saved_baseline_table_with_projection_filter_sort_and_pagination() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("query");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let rows = query_baseline_table(
            &dir,
            "files",
            BaselineTableQuery {
                offset: 1,
                limit: 1,
                columns: Some(vec!["path".to_string(), "lines".to_string()]),
                filters: vec![BaselineTableFilter {
                    column: "path".to_string(),
                    op: BaselineFilterOp::EndsWith,
                    value: json!(".c"),
                }],
                filter_mode: BaselineFilterMode::All,
                sort: vec![BaselineTableSort {
                    column: "lines".to_string(),
                    direction: BaselineSortDirection::Desc,
                }],
            },
        )
        .unwrap();

        assert_eq!(rows.total_rows, 4);
        assert_eq!(rows.matched_rows, 3);
        assert_eq!(rows.columns, ["path", "lines"]);
        assert_eq!(rows.offset, 1);
        assert_eq!(rows.limit, 1);
        assert_eq!(rows.rows, vec![json!({"path": "src/mid.c", "lines": 20})]);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_unknown_baseline_query_columns() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("unknown-column");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let err = query_baseline_table(
            &dir,
            "files",
            BaselineTableQuery {
                offset: 0,
                limit: 10,
                columns: Some(vec!["missing".to_string()]),
                filters: Vec::new(),
                filter_mode: BaselineFilterMode::All,
                sort: Vec::new(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, MemoryError::UnknownColumn(column) if column == "missing"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn queries_saved_baseline_table_with_set_filters_and_multi_sort() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("set-filter-sort");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let rows = query_baseline_table(
            &dir,
            "files",
            BaselineTableQuery {
                offset: 0,
                limit: 10,
                columns: Some(vec![
                    "path".to_string(),
                    "language".to_string(),
                    "lines".to_string(),
                ]),
                filters: vec![
                    BaselineTableFilter {
                        column: "language".to_string(),
                        op: BaselineFilterOp::In,
                        value: json!(["c", "rust"]),
                    },
                    BaselineTableFilter {
                        column: "path".to_string(),
                        op: BaselineFilterOp::NotIn,
                        value: json!(["src/small.c"]),
                    },
                ],
                filter_mode: BaselineFilterMode::All,
                sort: vec![
                    BaselineTableSort {
                        column: "language".to_string(),
                        direction: BaselineSortDirection::Asc,
                    },
                    BaselineTableSort {
                        column: "lines".to_string(),
                        direction: BaselineSortDirection::Desc,
                    },
                ],
            },
        )
        .unwrap();

        assert_eq!(rows.matched_rows, 3);
        assert_eq!(
            rows.rows,
            vec![
                json!({"path": "src/large.c", "language": "c", "lines": 30}),
                json!({"path": "src/mid.c", "language": "c", "lines": 20}),
                json!({"path": "src/lib.rs", "language": "rust", "lines": 40}),
            ]
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn queries_saved_baseline_table_with_any_filter_mode() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("any-filter");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let rows = query_baseline_table(
            &dir,
            "files",
            BaselineTableQuery {
                offset: 0,
                limit: 10,
                columns: Some(vec!["path".to_string(), "language".to_string()]),
                filters: vec![
                    BaselineTableFilter {
                        column: "path".to_string(),
                        op: BaselineFilterOp::Eq,
                        value: json!("src/small.c"),
                    },
                    BaselineTableFilter {
                        column: "language".to_string(),
                        op: BaselineFilterOp::Eq,
                        value: json!("rust"),
                    },
                ],
                filter_mode: BaselineFilterMode::Any,
                sort: vec![BaselineTableSort {
                    column: "path".to_string(),
                    direction: BaselineSortDirection::Asc,
                }],
            },
        )
        .unwrap();

        assert_eq!(rows.matched_rows, 2);
        assert_eq!(
            rows.rows,
            vec![
                json!({"path": "src/lib.rs", "language": "rust"}),
                json!({"path": "src/small.c", "language": "c"}),
            ]
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn queries_saved_baseline_table_with_regex_filters() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("regex-filter");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let rows = query_baseline_table(
            &dir,
            "files",
            BaselineTableQuery {
                offset: 0,
                limit: 10,
                columns: Some(vec!["path".to_string()]),
                filters: vec![
                    BaselineTableFilter {
                        column: "path".to_string(),
                        op: BaselineFilterOp::Regex,
                        value: json!(r"^src/.*\.(c|rs)$"),
                    },
                    BaselineTableFilter {
                        column: "path".to_string(),
                        op: BaselineFilterOp::NotRegex,
                        value: json!(r"small"),
                    },
                ],
                filter_mode: BaselineFilterMode::All,
                sort: vec![BaselineTableSort {
                    column: "path".to_string(),
                    direction: BaselineSortDirection::Asc,
                }],
            },
        )
        .unwrap();

        assert_eq!(rows.matched_rows, 3);
        assert_eq!(
            rows.rows,
            vec![
                json!({"path": "src/large.c"}),
                json!({"path": "src/lib.rs"}),
                json!({"path": "src/mid.c"}),
            ]
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_invalid_baseline_regex_filters() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("invalid-regex-filter");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let err = query_baseline_table(
            &dir,
            "files",
            BaselineTableQuery {
                offset: 0,
                limit: 10,
                columns: Some(vec!["path".to_string()]),
                filters: vec![BaselineTableFilter {
                    column: "path".to_string(),
                    op: BaselineFilterOp::Regex,
                    value: json!("["),
                }],
                filter_mode: BaselineFilterMode::All,
                sort: Vec::new(),
            },
        )
        .unwrap_err();

        assert!(matches!(err, MemoryError::InvalidRegex { column, .. } if column == "path"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    fn temp_tables_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "raysense-memory-{name}-{}-{suffix}",
            std::process::id()
        ))
    }

    fn sample_report() -> ScanReport {
        let files = vec![
            file(0, "src/small.c", Language::C, 10),
            file(1, "src/mid.c", Language::C, 20),
            file(2, "src/large.c", Language::C, 30),
            file(3, "src/lib.rs", Language::Rust, 40),
        ];
        ScanReport {
            snapshot: SnapshotFact {
                snapshot_id: "sample".to_string(),
                root: PathBuf::from("/tmp/raysense-sample"),
                file_count: files.len(),
                function_count: 0,
                import_count: 0,
                call_count: 0,
            },
            files,
            functions: Vec::new(),
            entry_points: Vec::new(),
            imports: Vec::new(),
            calls: Vec::new(),
            call_edges: Vec::new(),
            types: Vec::new(),
            trait_impls: Vec::new(),
            graph: crate::GraphMetrics::default(),
        }
    }

    #[test]
    fn meta_table_stamps_schema_version_and_provenance() {
        let _guard = rayforce_test_guard();
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        let summary = memory.summary();

        assert_eq!(summary.meta.rows, 1);
        assert_eq!(summary.meta.columns, 7);
    }

    #[test]
    fn policy_pack_eval_returns_findings_for_a_real_rfl_file() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("policy");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let policies_dir = dir.parent().unwrap().join(format!(
            "{}-policies",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&policies_dir).unwrap();
        let policy_path = policies_dir.join("size.rfl");
        std::fs::write(
            &policy_path,
            // Flags every file in the sample with > 15 lines.
            r#"(select {severity: "warning"
                       code:     "test-rule"
                       path:     path
                       message:  "exceeds threshold"
                       from:     files
                       where:    (> lines 15)})"#,
        )
        .unwrap();

        let results = eval_all_policies(&dir, &policies_dir).unwrap();
        assert_eq!(results.len(), 1);
        let findings = results[0].findings.as_ref().expect("policy should run");
        // sample_report has 4 files with lines [10, 20, 30, 40]; three exceed 15.
        assert_eq!(findings.len(), 3);
        assert!(findings
            .iter()
            .all(|f| matches!(f.severity, RuleSeverity::Warning)
                && f.code == "test-rule"
                && f.message == "exceeds threshold"));

        std::fs::remove_dir_all(&policies_dir).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn policy_pack_eval_returns_typed_error_when_result_misses_columns() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("policy-bad");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        // Result table only has `path` -- missing severity / code / message.
        let err = eval_policy_pack_inline(&dir, "(select {path: path from: files})").unwrap_err();
        assert!(
            matches!(err, MemoryError::PolicySchema { ref missing, .. } if missing.len() == 3),
            "expected PolicySchema with 3 missing columns, got {:?}",
            err,
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn policy_exit_code_prioritizes_eval_errors_over_error_findings() {
        let ok_only = vec![PolicyResult {
            path: PathBuf::from("a.rfl"),
            findings: Ok(vec![RuleFinding {
                severity: RuleSeverity::Warning,
                code: "x".into(),
                path: "p".into(),
                message: "m".into(),
            }]),
        }];
        assert_eq!(policy_exit_code(&ok_only), 0);

        let with_error_finding = vec![PolicyResult {
            path: PathBuf::from("b.rfl"),
            findings: Ok(vec![RuleFinding {
                severity: RuleSeverity::Error,
                code: "x".into(),
                path: "p".into(),
                message: "m".into(),
            }]),
        }];
        assert_eq!(policy_exit_code(&with_error_finding), 2);

        let with_eval_error = vec![
            PolicyResult {
                path: PathBuf::from("c.rfl"),
                findings: Err(MemoryError::PolicySchema {
                    path: PathBuf::from("c.rfl"),
                    missing: vec!["severity"],
                }),
            },
            // Even with an error-severity finding alongside, eval error wins.
            PolicyResult {
                path: PathBuf::from("d.rfl"),
                findings: Ok(vec![RuleFinding {
                    severity: RuleSeverity::Error,
                    code: "x".into(),
                    path: "p".into(),
                    message: "m".into(),
                }]),
            },
        ];
        assert_eq!(policy_exit_code(&with_eval_error), 1);
    }

    fn eval_policy_pack_inline(
        baseline_dir: &PathBuf,
        rayfall: &str,
    ) -> Result<Vec<RuleFinding>, MemoryError> {
        let policies_dir = baseline_dir.parent().unwrap().join(format!(
            "{}-inline-policies",
            baseline_dir.file_name().unwrap().to_string_lossy(),
        ));
        std::fs::create_dir_all(&policies_dir).unwrap();
        let policy_path = policies_dir.join("inline.rfl");
        std::fs::write(&policy_path, rayfall).unwrap();
        let result = eval_policy_pack(baseline_dir, &policy_path);
        std::fs::remove_dir_all(&policies_dir).unwrap();
        result
    }

    #[test]
    fn csv_import_round_trips_into_a_queryable_table() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("csv-import");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let csv_path = dir.parent().unwrap().join(format!(
            "{}-coverage.csv",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(
            &csv_path,
            "path,covered_pct\nsrc/a.rs,42.0\nsrc/b.rs,87.5\n",
        )
        .unwrap();

        import_csv_table(&dir, "coverage", &csv_path).unwrap();

        let rows = query_with_rayfall(
            &dir,
            "coverage",
            "(select {from: t where: (< covered_pct 50)})",
        )
        .unwrap();

        assert_eq!(rows.matched_rows, 1);
        assert_eq!(rows.rows[0]["path"], json!("src/a.rs"));
        assert_eq!(rows.rows[0]["covered_pct"], json!(42.0));

        // Pre-existing baseline tables remain queryable -- proves the sym
        // merge at import time did not corrupt the global sym table.
        let files_count = query_with_rayfall(&dir, "files", "(count t)").unwrap();
        assert_eq!(
            files_count.rows[0]["value"],
            json!(report.files.len() as i64)
        );

        std::fs::remove_file(csv_path).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sym_columns_round_trip_through_save_and_query() {
        // Regression for the Lane C sym migration: language and module
        // columns now ship as RAY_SYM (dict-encoded) instead of RAY_STR.
        // The wire is invisible to agents -- string predicates like
        // (== language "rust") must keep working, and the cell decoder
        // must resolve sym IDs back to the original interned strings.
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("sym-roundtrip");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let rows = query_with_rayfall(
            &dir,
            "files",
            r#"(select {from: t where: (== language "rust")})"#,
        )
        .unwrap();

        // sample_report has exactly one rust file (src/lib.rs).
        assert_eq!(rows.matched_rows, 1);
        assert_eq!(rows.rows[0]["path"], json!("src/lib.rs"));
        assert_eq!(rows.rows[0]["language"], json!("rust"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rayfall_query_auto_promotes_atom_result_to_one_by_one_table() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("rayfall-atom");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let rows = query_with_rayfall(&dir, "files", "(count t)").unwrap();
        assert_eq!(rows.columns, vec!["value"]);
        assert_eq!(rows.matched_rows, 1);
        assert_eq!(rows.rows.len(), 1);
        assert_eq!(rows.rows[0]["value"], json!(report.files.len() as i64));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rayfall_query_auto_promotes_vector_result_to_single_value_column() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("rayfall-vec");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let rows = query_with_rayfall(&dir, "files", "(at t (quote lines))").unwrap();
        assert_eq!(rows.columns, vec!["value"]);
        assert_eq!(rows.matched_rows, report.files.len());
        // sample_report files have lines [10, 20, 30, 40] in id order.
        let extracted: Vec<i64> = rows
            .rows
            .iter()
            .map(|r| r["value"].as_i64().unwrap())
            .collect();
        assert_eq!(extracted, vec![10, 20, 30, 40]);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rayfall_query_returns_full_table_when_evaluating_bind_name() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("rayfall-bind");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        // The simplest possible Rayfall expression: just reference the bound
        // symbol `t`.  Confirms the runtime is up, the table was bound via
        // ray_env_set, and ray_eval_str round-trips it back unchanged.
        let rows = query_with_rayfall(&dir, "files", "t").unwrap();

        assert_eq!(rows.matched_rows, report.files.len());
        assert!(rows.columns.contains(&"path".to_string()));
        assert!(rows.columns.contains(&"lines".to_string()));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rayfall_query_surfaces_parse_errors_with_a_typed_error() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("rayfall-parse-err");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        // Deliberately malformed Rayfall: an unterminated list literal.
        let err = query_with_rayfall(&dir, "files", "(select").unwrap_err();
        assert!(
            matches!(err, MemoryError::RayfallEval { .. }),
            "expected RayfallEval, got {:?}",
            err,
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn meta_table_round_trips_through_splay_save_and_query() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("meta-roundtrip");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        // Note: list_baseline_tables would also exercise meta, but it iterates
        // every saved table. With sample_report's empty fact vectors several
        // tables (module_edges, inheritance, ...) get 0-row STRV columns which
        // hit a pre-existing rayforce v2.1.0 bug -- ray_col_mmap rejects
        // STRV files smaller than 32 bytes with code "corrupt", and the splay
        // loader's fallback only triggers on "nyi". That is unrelated to the
        // schema-version feature, so this test queries meta directly.
        let rows = query_baseline_table(&dir, "meta", BaselineTableQuery::page(0, 10)).unwrap();

        assert_eq!(rows.matched_rows, 1);
        assert_eq!(rows.rows.len(), 1);
        let row = &rows.rows[0];
        assert_eq!(row["schema_version"], serde_json::json!(SCHEMA_VERSION));
        assert_eq!(
            row["raysense_version"],
            serde_json::json!(env!("CARGO_PKG_VERSION")),
        );
        assert!(
            row["snapshot_id"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "snapshot_id should be a non-empty string, got {:?}",
            row["snapshot_id"],
        );
        assert!(
            row["column_digest"]
                .as_str()
                .map(|s| s.len() == 64)
                .unwrap_or(false),
            "column_digest should be a 64-char SHA-256 hex, got {:?}",
            row["column_digest"],
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verify_baseline_schema_passes_for_legacy_baseline_without_meta() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("legacy");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        std::fs::remove_dir_all(dir.join("meta")).unwrap();
        verify_baseline_schema(&dir).expect("legacy baselines should pass");

        let rows = query_baseline_table(&dir, "files", BaselineTableQuery::page(0, 10)).unwrap();
        assert_eq!(rows.total_rows, 4);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verify_baseline_schema_rejects_mismatched_version() {
        let _guard = rayforce_test_guard();
        let dir = temp_tables_dir("mismatch");
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        memory.save_splayed(&dir).unwrap();

        let bogus = build_meta_table_with_version(&report, 999).unwrap();
        let bogus_dir = dir.join("meta");
        std::fs::remove_dir_all(&bogus_dir).unwrap();
        let path = CString::new(bogus_dir.to_string_lossy().into_owned()).unwrap();
        let sym_path = CString::new(dir.join(".sym").to_string_lossy().into_owned()).unwrap();
        let err =
            unsafe { crate::sys::ray_splay_save(bogus.as_ptr(), path.as_ptr(), sym_path.as_ptr()) };
        assert_eq!(
            err,
            crate::sys::RAY_OK,
            "rewriting meta with bogus version failed"
        );

        let result = query_baseline_table(&dir, "files", BaselineTableQuery::page(0, 10));
        assert!(
            matches!(
                result,
                Err(MemoryError::SchemaMismatch { found: 999, expected }) if expected == SCHEMA_VERSION,
            ),
            "expected SchemaMismatch, got {:?}",
            result,
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn raymemory_v4_contains_trend_tables() {
        // Even with no history.json on disk, the three trend tables must
        // exist and be empty. Schema v4 is incomplete without them.
        let _guard = rayforce_test_guard();
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        let summary = memory.summary();

        assert_eq!(summary.trend_health.columns, 12);
        assert_eq!(summary.trend_health.rows, 0);
        assert_eq!(summary.trend_hotspots.columns, 6);
        assert_eq!(summary.trend_hotspots.rows, 0);
        assert_eq!(summary.trend_violations.columns, 4);
        assert_eq!(summary.trend_violations.rows, 0);
    }

    #[test]
    fn trend_health_table_has_one_row_per_sample() {
        let _guard = rayforce_test_guard();
        let mut breakdown = std::collections::BTreeMap::new();
        breakdown.insert("max_function_complexity".to_string(), 2usize);
        let samples = vec![
            TrendSample {
                timestamp: 1_700_000_000,
                snapshot_id: "snap-1".to_string(),
                score: 70,
                quality_signal: 7000,
                rules: 3,
                root_causes: crate::health::RootCauseScores {
                    modularity: 0.9,
                    acyclicity: 0.95,
                    depth: 1.0,
                    equality: 0.5,
                    redundancy: 0.7,
                    structural_uniformity: 0.6,
                },
                overall_grade: "C".to_string(),
                schema: 2,
                top_hotspots: vec![crate::health::TrendHotspotSample {
                    path: "src/big.rs".to_string(),
                    commits: 12,
                    max_complexity: 18,
                    risk_score: 216,
                }],
                rule_breakdown: breakdown.clone(),
            },
            TrendSample {
                timestamp: 1_700_001_000,
                snapshot_id: "snap-2".to_string(),
                score: 75,
                quality_signal: 7500,
                rules: 2,
                root_causes: crate::health::RootCauseScores {
                    modularity: 0.92,
                    acyclicity: 0.95,
                    depth: 1.0,
                    equality: 0.55,
                    redundancy: 0.72,
                    structural_uniformity: 0.62,
                },
                overall_grade: "B".to_string(),
                schema: 2,
                top_hotspots: vec![crate::health::TrendHotspotSample {
                    path: "src/big.rs".to_string(),
                    commits: 13,
                    max_complexity: 18,
                    risk_score: 234,
                }],
                rule_breakdown: breakdown,
            },
        ];

        let health_table = build_trend_health_table(&samples).unwrap();
        let hotspots_table = build_trend_hotspots_table(&samples).unwrap();
        let violations_table = build_trend_violations_table(&samples).unwrap();

        assert_eq!(table_summary(health_table.as_ptr()).rows, 2);
        assert_eq!(table_summary(health_table.as_ptr()).columns, 12);
        assert_eq!(table_summary(hotspots_table.as_ptr()).rows, 2);
        assert_eq!(table_summary(hotspots_table.as_ptr()).columns, 6);
        assert_eq!(table_summary(violations_table.as_ptr()).rows, 2);
        assert_eq!(table_summary(violations_table.as_ptr()).columns, 4);
    }

    #[test]
    fn trend_tables_are_empty_for_v1_samples_without_hotspots() {
        // v1 samples (schema=0) have no top_hotspots or rule_breakdown,
        // so they only contribute to trend_health, not the long tables.
        let _guard = rayforce_test_guard();
        let samples = vec![TrendSample {
            timestamp: 1_700_000_000,
            snapshot_id: "v1".to_string(),
            score: 70,
            quality_signal: 7000,
            rules: 1,
            ..TrendSample::default()
        }];

        let health_table = build_trend_health_table(&samples).unwrap();
        let hotspots_table = build_trend_hotspots_table(&samples).unwrap();
        let violations_table = build_trend_violations_table(&samples).unwrap();

        assert_eq!(table_summary(health_table.as_ptr()).rows, 1);
        assert_eq!(table_summary(hotspots_table.as_ptr()).rows, 0);
        assert_eq!(table_summary(violations_table.as_ptr()).rows, 0);
    }

    fn build_meta_table_with_version(
        report: &ScanReport,
        version: i64,
    ) -> Result<RayObject, MemoryError> {
        init_symbols()?;
        table(
            7,
            [
                ("schema_version", i64_vec(1, std::iter::once(version))?),
                ("raysense_version", str_vec(1, ["bogus".to_string()])?),
                ("rayforce_version", str_vec(1, ["bogus".to_string()])?),
                ("repo_sha", str_vec(1, ["".to_string()])?),
                (
                    "snapshot_id",
                    str_vec(1, [report.snapshot.snapshot_id.clone()])?,
                ),
                ("scan_unix", i64_vec(1, std::iter::once(0))?),
                ("column_digest", str_vec(1, ["bogus".to_string()])?),
            ],
        )
    }

    fn file(file_id: usize, path: &str, language: Language, lines: usize) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language,
            language_name: format!("{:?}", language).to_lowercase(),
            module: path.replace(['/', '.'], "."),
            lines,
            bytes: lines * 10,
            content_hash: format!("hash-{file_id}"),
            comment_lines: 0,
        }
    }
}
