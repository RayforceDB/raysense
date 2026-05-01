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

use crate::{compute_health_with_config, HealthSummary, RaysenseConfig, ScanReport};
use serde::Serialize;
use std::ffi::CString;
use std::fs;
use std::path::Path;
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
            types: build_types_table(report)?,
            health: build_health_table(report, &health)?,
            hotspots: build_hotspots_table(&health)?,
            rules: build_rules_table(&health)?,
            module_edges: build_module_edges_table(&health)?,
            changed_files: build_changed_files_table(&health)?,
            file_ownership: build_file_ownership_table(&health)?,
            temporal_hotspots: build_temporal_hotspots_table(&health)?,
            file_ages: build_file_ages_table(&health)?,
            change_coupling: build_change_coupling_table(&health)?,
            inheritance: build_inheritance_table(report)?,
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
    if !dir.join(name).is_dir() {
        return Err(MemoryError::TableNotFound(name.to_string()));
    }
    let table = read_table_object(dir, name)?;
    table_rows(name, table.as_ptr(), query)
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
    let err = unsafe { crate::sys::ray_sym_init() };
    if err == crate::sys::RAY_OK {
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
            graph: crate::GraphMetrics::default(),
        }
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
