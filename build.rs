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

//! Compile the vendored C library directly via `cc`. No external checkout
//! required — `cargo build` works from a fresh clone with no extra steps.
//! Set `RAYFORCE_DIR` only if you want to link against an outside build for
//! development.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    if let Some(external_dir) = env::var_os("RAYFORCE_DIR") {
        link_external(PathBuf::from(external_dir));
    } else {
        compile_vendored(&manifest_dir.join("vendor/rayforce"));
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=pthread");
    } else {
        println!("cargo:rustc-link-lib=m");
    }

    println!("cargo:rerun-if-env-changed=RAYFORCE_DIR");
}

/// Default path: build the vendored sources with `cc::Build`. Excludes the
/// REPL binary entry (`src/app/main.c`) since we only need the library.
fn compile_vendored(vendor_dir: &Path) {
    let include_dir = vendor_dir.join("include");
    let src_dir = vendor_dir.join("src");
    let mut build = cc::Build::new();
    build
        .std("c17")
        .include(&include_dir)
        .include(&src_dir)
        .flag_if_supported("-fPIC")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-but-set-variable")
        .flag_if_supported("-Wno-unused-variable")
        .flag_if_supported("-Wno-unused-function");

    if let Ok(profile) = env::var("PROFILE") {
        if profile == "release" {
            build
                .opt_level(3)
                .flag_if_supported("-funroll-loops")
                .flag_if_supported("-fomit-frame-pointer")
                .flag_if_supported("-fno-math-errno");
        }
    }

    let mut count = 0usize;
    for entry in walk_c_sources(&src_dir) {
        if entry.ends_with(Path::new("app/main.c"))
            || entry.ends_with(Path::new("app/repl.c"))
            || entry.ends_with(Path::new("app/term.c"))
        {
            continue;
        }
        println!("cargo:rerun-if-changed={}", entry.display());
        build.file(&entry);
        count += 1;
    }
    if count == 0 {
        panic!(
            "no C sources found under {} — vendor/ is empty?",
            src_dir.display()
        );
    }
    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:include={}", include_dir.display());
    build.compile("rayforce");
}

/// Optional: link against an externally-built `librayforce.a`. Used only for
/// rayforce development; everyone else gets the vendored compile path above.
fn link_external(rayforce_dir: PathBuf) {
    let include_dir = rayforce_dir.join("include");
    let lib_path = rayforce_dir.join("librayforce.a");
    if !lib_path.exists() {
        panic!(
            "RAYFORCE_DIR={} but {} is missing — build with `make -C {} lib`",
            rayforce_dir.display(),
            lib_path.display(),
            rayforce_dir.display(),
        );
    }
    println!("cargo:include={}", include_dir.display());
    println!("cargo:rustc-link-search=native={}", rayforce_dir.display());
    println!("cargo:rustc-link-lib=static=rayforce");
    println!("cargo:rerun-if-changed={}", lib_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        include_dir.join("rayforce.h").display()
    );
}

/// Walk a directory tree collecting all `*.c` files. Pure-std (no walkdir
/// dep) to keep build-deps minimal.
fn walk_c_sources(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("c") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}
