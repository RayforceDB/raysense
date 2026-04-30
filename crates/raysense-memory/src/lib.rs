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
    pub health: TableSummary,
    pub hotspots: TableSummary,
    pub rules: TableSummary,
    pub module_edges: TableSummary,
    pub changed_files: TableSummary,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineFilterOp {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
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
    pub sort: Option<BaselineTableSort>,
}

impl BaselineTableQuery {
    pub fn page(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            columns: None,
            filters: Vec::new(),
            sort: None,
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
        self.save_table("health", self.health.as_ptr(), dir, &sym_path)?;
        self.save_table("hotspots", self.hotspots.as_ptr(), dir, &sym_path)?;
        self.save_table("rules", self.rules.as_ptr(), dir, &sym_path)?;
        self.save_table("module_edges", self.module_edges.as_ptr(), dir, &sym_path)?;
        self.save_table("changed_files", self.changed_files.as_ptr(), dir, &sym_path)?;
        Ok(())
    }

    fn save_table(
        &self,
        name: &'static str,
        table: *mut rayforce_sys::ray_t,
        base: &Path,
        sym_path: &Path,
    ) -> Result<(), MemoryError> {
        let path = CString::new(base.join(name).to_string_lossy().into_owned())?;
        let sym_path = CString::new(sym_path.to_string_lossy().into_owned())?;
        let err = unsafe { rayforce_sys::ray_splay_save(table, path.as_ptr(), sym_path.as_ptr()) };
        if err == rayforce_sys::RAY_OK {
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
            columns: unsafe { rayforce_sys::ray_table_ncols(table.as_ptr()) },
            rows: unsafe { rayforce_sys::ray_table_nrows(table.as_ptr()) },
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
        rayforce_sys::ray_read_splayed(
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
    if unsafe { (*ptr).type_ } == rayforce_sys::RAY_ERROR {
        let code = unsafe {
            let code = rayforce_sys::ray_err_code(ptr);
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
    table: *mut rayforce_sys::ray_t,
    query: BaselineTableQuery,
) -> Result<BaselineTableRows, MemoryError> {
    let total_rows = unsafe { rayforce_sys::ray_table_nrows(table) };
    let ncols = unsafe { rayforce_sys::ray_table_ncols(table) };
    let mut columns = Vec::new();
    let mut col_ptrs = Vec::new();

    for idx in 0..ncols {
        let name_id = unsafe { rayforce_sys::ray_table_col_name(table, idx) };
        columns.push(symbol_text(name_id));
        col_ptrs.push(unsafe { rayforce_sys::ray_table_get_col_idx(table, idx) });
    }

    let projected = project_columns(&columns, query.columns.as_deref())?;
    validate_filters(&columns, &query.filters)?;
    let sort_col = query
        .sort
        .as_ref()
        .map(|sort| column_index(&columns, &sort.column))
        .transpose()?;

    let mut row_indexes = Vec::new();
    for row_idx in 0..total_rows.max(0) as usize {
        if row_matches(&columns, &col_ptrs, row_idx, &query.filters) {
            row_indexes.push(row_idx);
        }
    }

    if let (Some(sort), Some(col_idx)) = (&query.sort, sort_col) {
        row_indexes.sort_by(|left, right| {
            let left = cell_value(col_ptrs[col_idx], *left as i64);
            let right = cell_value(col_ptrs[col_idx], *right as i64);
            let ordering = compare_values(&left, &right);
            match sort.direction {
                BaselineSortDirection::Asc => ordering,
                BaselineSortDirection::Desc => ordering.reverse(),
            }
        });
    }

    let matched_rows = row_indexes.len();
    let start = query.offset.min(matched_rows);
    let end = start.saturating_add(query.limit).min(matched_rows);
    let mut rows = Vec::new();
    for row_idx in &row_indexes[start..end] {
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

fn validate_filters(
    columns: &[String],
    filters: &[BaselineTableFilter],
) -> Result<(), MemoryError> {
    for filter in filters {
        column_index(columns, &filter.column)?;
    }
    Ok(())
}

fn column_index(columns: &[String], name: &str) -> Result<usize, MemoryError> {
    columns
        .iter()
        .position(|column| column == name)
        .ok_or_else(|| MemoryError::UnknownColumn(name.to_string()))
}

fn row_matches(
    columns: &[String],
    col_ptrs: &[*mut rayforce_sys::ray_t],
    row_idx: usize,
    filters: &[BaselineTableFilter],
) -> bool {
    filters.iter().all(|filter| {
        let Some(col_idx) = columns.iter().position(|column| column == &filter.column) else {
            return false;
        };
        filter_matches(
            &filter.op,
            &cell_value(col_ptrs[col_idx], row_idx as i64),
            &filter.value,
        )
    })
}

fn filter_matches(
    op: &BaselineFilterOp,
    actual: &serde_json::Value,
    expected: &serde_json::Value,
) -> bool {
    match op {
        BaselineFilterOp::Eq => values_equal(actual, expected),
        BaselineFilterOp::Ne => !values_equal(actual, expected),
        BaselineFilterOp::Contains => string_pair(actual, expected)
            .is_some_and(|(actual, expected)| actual.contains(expected)),
        BaselineFilterOp::StartsWith => string_pair(actual, expected)
            .is_some_and(|(actual, expected)| actual.starts_with(expected)),
        BaselineFilterOp::EndsWith => string_pair(actual, expected)
            .is_some_and(|(actual, expected)| actual.ends_with(expected)),
        BaselineFilterOp::Gt => compare_values(actual, expected).is_gt(),
        BaselineFilterOp::Gte => !compare_values(actual, expected).is_lt(),
        BaselineFilterOp::Lt => compare_values(actual, expected).is_lt(),
        BaselineFilterOp::Lte => !compare_values(actual, expected).is_gt(),
    }
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
    let atom = unsafe { rayforce_sys::ray_sym_str(name_id) };
    if atom.is_null() {
        return format!("#{name_id}");
    }
    string_atom(atom).unwrap_or_else(|| format!("#{name_id}"))
}

fn cell_value(col: *mut rayforce_sys::ray_t, row_idx: i64) -> serde_json::Value {
    if col.is_null() {
        return serde_json::Value::Null;
    }
    let len = unsafe { (*col).len };
    if row_idx < 0 || row_idx >= len {
        return serde_json::Value::Null;
    }

    match unsafe { (*col).type_ } {
        rayforce_sys::RAY_I32 => {
            let data = ray_data(col).cast::<i32>();
            serde_json::Value::from(unsafe { *data.add(row_idx as usize) })
        }
        rayforce_sys::RAY_I64 => {
            let data = ray_data(col).cast::<i64>();
            serde_json::Value::from(unsafe { *data.add(row_idx as usize) })
        }
        rayforce_sys::RAY_F64 => {
            let data = ray_data(col).cast::<f64>();
            serde_json::Number::from_f64(unsafe { *data.add(row_idx as usize) })
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        rayforce_sys::RAY_STR => string_vec_value(col, row_idx)
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null),
        other => serde_json::Value::String(format!("<unsupported type {other}>")),
    }
}

fn ray_data(obj: *mut rayforce_sys::ray_t) -> *const u8 {
    unsafe {
        obj.cast::<u8>()
            .add(std::mem::size_of::<rayforce_sys::ray_t>())
    }
}

fn string_vec_value(col: *mut rayforce_sys::ray_t, row_idx: i64) -> Option<String> {
    let mut len = 0usize;
    let ptr = unsafe { rayforce_sys::ray_str_vec_get(col, row_idx, &mut len) };
    if ptr.is_null() {
        return None;
    }
    Some(
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
            .into_owned(),
    )
}

fn string_atom(atom: *mut rayforce_sys::ray_t) -> Option<String> {
    let len = unsafe { rayforce_sys::ray_str_len(atom) };
    let ptr = unsafe { rayforce_sys::ray_str_ptr(atom) };
    if ptr.is_null() {
        return None;
    }
    Some(
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len) })
            .into_owned(),
    )
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
    use raysense_core::{scan_path, FileFact, Language, SnapshotFact};
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
        assert_eq!(summary.health.rows, 1);
        assert_eq!(summary.health.columns, 26);
        assert_eq!(summary.hotspots.columns, 5);
        assert_eq!(summary.rules.columns, 4);
        assert_eq!(summary.module_edges.columns, 3);
        assert_eq!(summary.changed_files.columns, 2);
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
                sort: Some(BaselineTableSort {
                    column: "lines".to_string(),
                    direction: BaselineSortDirection::Desc,
                }),
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
                sort: None,
            },
        )
        .unwrap_err();

        assert!(matches!(err, MemoryError::UnknownColumn(column) if column == "missing"));

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
            graph: raysense_core::GraphMetrics::default(),
        }
    }

    fn file(file_id: usize, path: &str, language: Language, lines: usize) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language,
            module: path.replace(['/', '.'], "."),
            lines,
            bytes: lines * 10,
            content_hash: format!("hash-{file_id}"),
        }
    }
}
