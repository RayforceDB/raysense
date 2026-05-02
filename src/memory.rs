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

use crate::{
    compute_health_with_config, HealthSummary, RaysenseConfig, RuleFinding, RuleSeverity,
    ScanReport,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// On-disk schema version for the splayed baseline tables. Bump whenever any
/// table builder gains, loses, or renames a column. The `meta` table stamps
/// this value at save time; readers refuse to decode mismatched baselines.
pub const SCHEMA_VERSION: i64 = 1;

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

        let meta = build_meta_table(
            report,
            &[
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
                ("module_edges", module_edges.as_ptr()),
                ("rules", rules.as_ptr()),
                ("temporal_hotspots", temporal_hotspots.as_ptr()),
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
    if result_type != crate::sys::RAY_TABLE {
        return Err(MemoryError::RayfallResultNotTable {
            type_tag: result_type,
        });
    }

    table_rows(
        name,
        result.as_ptr(),
        BaselineTableQuery::page(0, usize::MAX),
    )
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
        crate::sys::RAY_STR => string_vec_value(col, row_idx)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
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
        report.files.iter().map(|file| file.language_name.clone()),
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
    let top_authors = str_vec(
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

    table(
        5,
        [
            ("type_id", ids),
            ("file_id", file_ids),
            ("name", names),
            ("is_abstract", abstract_flags),
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

/// Build the single-row `meta` table that stamps schema version, raysense and
/// rayforce versions, repo SHA, snapshot id, scan time, and a digest over every
/// other table's column shape. Readers compare the digest's `schema_version`
/// against `SCHEMA_VERSION` and refuse mismatched baselines.
fn build_meta_table(
    report: &ScanReport,
    other_tables: &[(&str, *mut crate::sys::ray_t)],
) -> Result<RayObject, MemoryError> {
    // Workaround for rayforce v2.1.0: ray_col_mmap rejects on-disk column files
    // smaller than 32 bytes with code "corrupt" (col_validate_mapped at
    // store/col.c:727). The splay loader's fallback to ray_col_load only fires
    // on "nyi", not "corrupt", so short STRV files become unreadable via
    // ray_read_splayed. STRV file size = 22 + content_len, so a 1-row column
    // needs content >= 10 bytes to clear 32. We label-prefix every short string
    // value to stay safely above the threshold; longer values (snapshot_id,
    // column_digest, real git SHAs) are already long enough on their own.
    let raysense_version = format!("raysense {}", env!("CARGO_PKG_VERSION"));
    let rayforce_version = format!("rayforce {}", crate::sys::version_string());
    let repo_sha =
        git_head_sha(&report.snapshot.root).unwrap_or_else(|| "git-unavailable".to_string());
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
mod tests {
    use super::*;
    use crate::{scan_path, FileFact, Language, SnapshotFact};
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        assert_eq!(summary.types.rows as usize, report.types.len());
        assert_eq!(summary.types.columns, 5);
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
    }

    #[test]
    fn queries_saved_baseline_table_with_projection_filter_sort_and_pagination() {
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
                // 64-char hex stub mirrors what scanner::snapshot_id produces in
                // production. Anything under 10 chars trips a rayforce-side
                // limit on splayed STRV columns (see build_meta_table comment).
                snapshot_id: "0".repeat(64),
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
            graph: crate::GraphMetrics::default(),
        }
    }

    #[test]
    fn meta_table_stamps_schema_version_and_provenance() {
        let report = sample_report();
        let memory = RayMemory::from_report(&report).unwrap();
        let summary = memory.summary();

        assert_eq!(summary.meta.rows, 1);
        assert_eq!(summary.meta.columns, 7);
    }

    #[test]
    fn policy_pack_eval_returns_findings_for_a_real_rfl_file() {
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
    fn rayfall_query_returns_full_table_when_evaluating_bind_name() {
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
            serde_json::json!(format!("raysense {}", env!("CARGO_PKG_VERSION"))),
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

    fn build_meta_table_with_version(
        report: &ScanReport,
        version: i64,
    ) -> Result<RayObject, MemoryError> {
        init_symbols()?;
        // All bogus strings are >= 10 bytes -- shorter values would trip the
        // same rayforce 0-row-STRV bug noted in build_meta_table.
        table(
            7,
            [
                ("schema_version", i64_vec(1, std::iter::once(version))?),
                (
                    "raysense_version",
                    str_vec(1, ["bogus-version".to_string()])?,
                ),
                (
                    "rayforce_version",
                    str_vec(1, ["bogus-version".to_string()])?,
                ),
                ("repo_sha", str_vec(1, ["bogus-sha-bogus".to_string()])?),
                (
                    "snapshot_id",
                    str_vec(1, [report.snapshot.snapshot_id.clone()])?,
                ),
                ("scan_unix", i64_vec(1, std::iter::once(0))?),
                (
                    "column_digest",
                    str_vec(1, ["bogus-digest-padding".to_string()])?,
                ),
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
