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

pub const RAY_I32: i8 = 4;
pub const RAY_I64: i8 = 5;
pub const RAY_STR: i8 = 13;
pub const RAY_TABLE: i8 = 98;

#[repr(C)]
pub struct ray_t {
    _private: [u8; 0],
}

unsafe extern "C" {
    pub fn ray_version_major() -> c_int;
    pub fn ray_version_minor() -> c_int;
    pub fn ray_version_patch() -> c_int;
    pub fn ray_version_string() -> *const c_char;

    pub fn ray_release(v: *mut ray_t);

    pub fn ray_sym_init() -> ray_err_t;
    pub fn ray_sym_destroy();
    pub fn ray_sym_intern(str: *const c_char, len: usize) -> i64;

    pub fn ray_vec_new(type_: i8, capacity: i64) -> *mut ray_t;
    pub fn ray_vec_append(vec: *mut ray_t, elem: *const std::ffi::c_void) -> *mut ray_t;
    pub fn ray_str_vec_append(vec: *mut ray_t, s: *const c_char, len: usize) -> *mut ray_t;

    pub fn ray_table_new(ncols: i64) -> *mut ray_t;
    pub fn ray_table_add_col(tbl: *mut ray_t, name_id: i64, col_vec: *mut ray_t) -> *mut ray_t;
    pub fn ray_table_ncols(tbl: *mut ray_t) -> i64;
    pub fn ray_table_nrows(tbl: *mut ray_t) -> i64;
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
