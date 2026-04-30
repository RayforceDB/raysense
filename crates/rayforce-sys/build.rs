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

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..");
    let checkout_dir = repo_root.join("deps/rayforce");
    let sibling_dir = repo_root.join("../rayforce");
    let rayforce_dir = env::var_os("RAYFORCE_DIR").map(PathBuf::from).unwrap_or({
        if checkout_dir.exists() {
            checkout_dir
        } else {
            sibling_dir
        }
    });

    let include_dir = rayforce_dir.join("include");
    let lib_dir = rayforce_dir.clone();
    let lib_path = lib_dir.join("librayforce.a");

    if !lib_path.exists() {
        panic!(
            "missing {}; build Rayforce with `make -C {} lib` or set RAYFORCE_DIR",
            lib_path.display(),
            rayforce_dir.display()
        );
    }

    println!("cargo:include={}", include_dir.display());
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=rayforce");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=pthread");
    } else {
        println!("cargo:rustc-link-lib=m");
    }

    println!("cargo:rerun-if-env-changed=RAYFORCE_DIR");
    println!("cargo:rerun-if-changed={}", lib_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("rayforce.h").display()
    );
}
