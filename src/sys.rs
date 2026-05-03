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

#![allow(non_camel_case_types)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

// Type tags. Must stay aligned with `RAY_*` macros in upstream
// `include/rayforce.h`; the values shifted between versions (RAY_F64
// moved from 8 to 7 once RAY_DATE was inserted) so this list is the
// source of truth on the Rust side.
pub const RAY_LIST: i8 = 0;
pub const RAY_BOOL: i8 = 1;
pub const RAY_U8: i8 = 2;
pub const RAY_I16: i8 = 3;
pub const RAY_I32: i8 = 4;
pub const RAY_I64: i8 = 5;
pub const RAY_F32: i8 = 6;
pub const RAY_F64: i8 = 7;
pub const RAY_DATE: i8 = 8;
pub const RAY_TIME: i8 = 9;
pub const RAY_TIMESTAMP: i8 = 10;
pub const RAY_GUID: i8 = 11;
pub const RAY_SYM: i8 = 12;
pub const RAY_STR: i8 = 13;
pub const RAY_TABLE: i8 = 98;
pub const RAY_DICT: i8 = 99;
pub const RAY_ERROR: i8 = 127;

// RAY_SYM index widths (low 2 bits of vec attrs). W64 is the safe default
// when the global symbol table can grow past the small caps; W8/W16/W32
// are storage wins when the cardinality is bounded.
pub const RAY_SYM_W8: u8 = 0;
pub const RAY_SYM_W16: u8 = 1;
pub const RAY_SYM_W32: u8 = 2;
pub const RAY_SYM_W64: u8 = 3;

#[repr(C)]
pub struct ray_t {
    pub header: [u8; 16],
    pub mmod: u8,
    pub order: u8,
    pub type_: i8,
    pub attrs: u8,
    pub rc: u32,
    pub len: i64,
}

unsafe extern "C" {
    pub fn ray_version_major() -> c_int;
    pub fn ray_version_minor() -> c_int;
    pub fn ray_version_patch() -> c_int;
    pub fn ray_version_string() -> *const c_char;

    pub fn ray_release(v: *mut ray_t);
    pub fn ray_err_code(err: *mut ray_t) -> *const c_char;

    pub fn ray_sym_init() -> ray_err_t;
    pub fn ray_sym_destroy();
    pub fn ray_sym_intern(str: *const c_char, len: usize) -> i64;
    pub fn ray_sym_str(id: i64) -> *mut ray_t;

    pub fn ray_vec_new(type_: i8, capacity: i64) -> *mut ray_t;
    pub fn ray_sym_vec_new(sym_width: u8, capacity: i64) -> *mut ray_t;
    pub fn ray_vec_append(vec: *mut ray_t, elem: *const std::ffi::c_void) -> *mut ray_t;
    pub fn ray_str_vec_append(vec: *mut ray_t, s: *const c_char, len: usize) -> *mut ray_t;
    pub fn ray_str_vec_get(vec: *mut ray_t, idx: i64, out_len: *mut usize) -> *const c_char;
    pub fn ray_str_ptr(s: *mut ray_t) -> *const c_char;
    pub fn ray_str_len(s: *mut ray_t) -> usize;

    pub fn ray_table_new(ncols: i64) -> *mut ray_t;
    pub fn ray_table_add_col(tbl: *mut ray_t, name_id: i64, col_vec: *mut ray_t) -> *mut ray_t;
    pub fn ray_table_get_col(tbl: *mut ray_t, name_id: i64) -> *mut ray_t;
    pub fn ray_table_get_col_idx(tbl: *mut ray_t, idx: i64) -> *mut ray_t;
    pub fn ray_table_col_name(tbl: *mut ray_t, idx: i64) -> i64;
    pub fn ray_table_ncols(tbl: *mut ray_t) -> i64;
    pub fn ray_table_nrows(tbl: *mut ray_t) -> i64;

    pub fn ray_splay_save(
        tbl: *mut ray_t,
        dir: *const c_char,
        sym_path: *const c_char,
    ) -> ray_err_t;
    pub fn ray_read_splayed(dir: *const c_char, sym_path: *const c_char) -> *mut ray_t;
    /// Non-mmap splay loader. Returns a buddy-allocated copy of the table
    /// so the caller can safely mutate or even delete the on-disk source
    /// directory afterwards. Use this when the load-then-rewrite flow
    /// destructively replaces the directory between read and save.
    pub fn ray_splay_load(dir: *const c_char, sym_path: *const c_char) -> *mut ray_t;

    pub fn ray_env_set(sym_id: i64, val: *mut ray_t) -> ray_err_t;

    pub fn ray_dict_keys(d: *mut ray_t) -> *mut ray_t;
    pub fn ray_dict_vals(d: *mut ray_t) -> *mut ray_t;
    pub fn ray_dict_len(d: *mut ray_t) -> i64;
    pub fn ray_list_get(list: *mut ray_t, idx: i64) -> *mut ray_t;

    pub fn ray_runtime_create_with_sym(sym_path: *const c_char) -> *mut ray_runtime_t;
    pub fn ray_runtime_destroy(rt: *mut ray_runtime_t);
    pub fn ray_eval_str(source: *const c_char) -> *mut ray_t;

    pub fn ray_progress_set_callback(
        cb: ray_progress_cb,
        user: *mut std::ffi::c_void,
        min_ms: u64,
        tick_interval_ms: u64,
    );
    pub fn ray_request_interrupt();
    pub fn ray_clear_interrupt();
    pub fn ray_interrupted() -> bool;
}

/// Snapshot delivered to a progress callback.  Mirrors `ray_progress_t` in
/// `include/rayforce.h`.  Worker threads never touch this struct; the
/// callback fires on the main thread between ops or at pivot phase
/// boundaries, so reading `op_name` / `phase` raw pointers is safe for
/// the lifetime of the callback invocation.
#[repr(C)]
pub struct ray_progress_t {
    pub op_name: *const c_char,
    pub phase: *const c_char,
    pub rows_done: u64,
    pub rows_total: u64,
    pub elapsed_sec: f64,
    pub mem_used: i64,
    pub mem_budget: i64,
    pub final_: bool,
}

pub type ray_progress_cb =
    Option<unsafe extern "C" fn(snapshot: *const ray_progress_t, user: *mut std::ffi::c_void)>;

#[repr(C)]
pub struct ray_runtime_t {
    _opaque: [u8; 0],
}

pub type ray_err_t = c_int;

pub const RAY_OK: ray_err_t = 0;

pub fn version_string() -> String {
    unsafe {
        let ptr = ray_version_string();
        if ptr.is_null() {
            return format!(
                "{}.{}.{}",
                ray_version_major(),
                ray_version_minor(),
                ray_version_patch()
            );
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}
