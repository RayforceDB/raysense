use raysense_core::ScanReport;
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
    pub imports: TableSummary,
}

pub struct RayMemory {
    files: RayObject,
    functions: RayObject,
    imports: RayObject,
}

impl RayMemory {
    pub fn from_report(report: &ScanReport) -> Result<Self, MemoryError> {
        init_symbols()?;

        Ok(Self {
            files: build_files_table(report)?,
            functions: build_functions_table(report)?,
            imports: build_imports_table(report)?,
        })
    }

    pub fn summary(&self) -> MemorySummary {
        MemorySummary {
            files: table_summary(self.files.as_ptr()),
            functions: table_summary(self.functions.as_ptr()),
            imports: table_summary(self.imports.as_ptr()),
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
        assert_eq!(summary.imports.rows as usize, report.imports.len());
    }
}
