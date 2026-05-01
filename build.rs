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

//! Build raysense by linking the upstream rayforce static library.
//!
//! Three resolution modes, in priority order:
//!
//! 1. `RAYFORCE_DIR` env var — link an externally built `librayforce.a`
//!    from a developer-provided rayforce checkout (you build rayforce
//!    yourself, point raysense at it).
//!
//! 2. `vendor/rayforce/Makefile` exists in the source tree (bundled
//!    inside the published `.crate` tarball, or populated by CI before
//!    `cargo package`) — copy that source into `OUT_DIR` and build it
//!    there.
//!
//! 3. Otherwise — clone upstream rayforce at the SHA pinned in
//!    `.rayforce-version` directly into `OUT_DIR`, then build it there.
//!
//! All `make lib` work happens inside `OUT_DIR/rayforce-build/`. The
//! source tree is never modified — required by `cargo package`'s
//! verification step (build scripts must not write outside `OUT_DIR`).
//!
//! The Makefile's stock `RELEASE_CFLAGS` includes `-march=native`, which
//! bakes the build host's CPU features into the static library and would
//! crash on older CPUs of the same arch. We override `RELEASE_CFLAGS` to
//! a portable baseline so the produced `.a` is shippable across hosts.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const RAYFORCE_REPO: &str = "https://github.com/RayforceDB/rayforce.git";

/// Portable release CFLAGS. Differs from upstream `RELEASE_CFLAGS` by
/// dropping `-march=native` (build-host-specific) and `-Werror` (would
/// fail downstream builds on new compiler warnings).
const PORTABLE_CFLAGS: &str = "-fPIC -O3 -fomit-frame-pointer -fno-math-errno \
    -funroll-loops -std=c17 -Wall -Wextra -Wstrict-prototypes \
    -Wno-unused-parameter";

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    if let Some(external) = env::var_os("RAYFORCE_DIR") {
        link_external(PathBuf::from(external));
    } else {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let build_dir = out_dir.join("rayforce-build");
        ensure_build_dir(&manifest_dir, &build_dir);
        run_make_lib(&build_dir);
        link_static_lib(&build_dir);
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=pthread");
    } else {
        println!("cargo:rustc-link-lib=m");
    }

    println!("cargo:rerun-if-env-changed=RAYFORCE_DIR");
    println!("cargo:rerun-if-changed=.rayforce-version");
}

/// Materialize rayforce source under `build_dir`. Either copy bundled
/// `vendor/rayforce/` from the source tree, or clone upstream at the
/// pinned SHA. Skips work if `build_dir` already holds the right SHA.
fn ensure_build_dir(manifest_dir: &Path, build_dir: &Path) {
    let pinned_sha = read_pin(manifest_dir);
    let sentinel = build_dir.join(".raysense-built-sha");

    if let Ok(prev) = fs::read_to_string(&sentinel) {
        if prev.trim() == pinned_sha {
            return;
        }
    }

    if build_dir.exists() {
        fs::remove_dir_all(build_dir).expect("rm previous rayforce-build/");
    }

    let bundled = manifest_dir.join("vendor/rayforce");
    if bundled.join("Makefile").exists() {
        copy_tree(&bundled, build_dir);
    } else {
        clone_at_pin(build_dir, &pinned_sha);
    }

    fs::write(&sentinel, &pinned_sha).expect("write sentinel");
}

fn read_pin(manifest_dir: &Path) -> String {
    let path = manifest_dir.join(".rayforce-version");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let sha = raw.trim();
    if sha.len() < 7 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        panic!("`.rayforce-version` does not contain a hex SHA: {sha:?}");
    }
    sha.to_string()
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("mkdir build_dir");
    // `cp -r` is robust on Linux/macOS; the upstream Makefile only
    // supports those platforms anyway. Trailing dot copies contents,
    // not the src dir itself.
    let status = Command::new("cp")
        .arg("-R")
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .status()
        .unwrap_or_else(|e| panic!("`cp -R {src:?} -> {dst:?}` failed: {e}"));
    if !status.success() {
        panic!("`cp -R` exited {status}");
    }
}

fn clone_at_pin(build_dir: &Path, sha: &str) {
    if let Some(parent) = build_dir.parent() {
        fs::create_dir_all(parent).expect("mkdir build_dir parent");
    }
    fs::create_dir_all(build_dir).expect("mkdir build_dir");

    run_git(build_dir, &["init", "-q"]);
    run_git(build_dir, &["remote", "add", "origin", RAYFORCE_REPO]);
    run_git(build_dir, &["fetch", "--depth", "1", "origin", sha]);
    run_git(build_dir, &["checkout", "--quiet", "FETCH_HEAD"]);
    // Strip .git/ — keeps OUT_DIR small and prevents stale clone state
    // from confusing future cache hits.
    let dot_git = build_dir.join(".git");
    if dot_git.exists() {
        let _ = fs::remove_dir_all(&dot_git);
    }
}

fn run_git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `git {}`: {e}", args.join(" ")));
    if !status.success() {
        panic!("`git {}` failed with status {}", args.join(" "), status);
    }
}

fn run_make_lib(build_dir: &Path) {
    let status = Command::new("make")
        .current_dir(build_dir)
        .arg("lib")
        .arg(format!("RELEASE_CFLAGS={PORTABLE_CFLAGS}"))
        .status()
        .unwrap_or_else(|e| panic!("failed to run `make lib`: {e}"));
    if !status.success() {
        panic!(
            "`make lib` in {} exited with status {}",
            build_dir.display(),
            status
        );
    }
    let lib = build_dir.join("librayforce.a");
    if !lib.exists() {
        panic!(
            "expected {} after `make lib`, but it is missing",
            lib.display()
        );
    }
    println!("cargo:rerun-if-changed={}", lib.display());
}

fn link_static_lib(build_dir: &Path) {
    let include_dir = build_dir.join("include");
    println!("cargo:include={}", include_dir.display());
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=rayforce");
}

/// Optional: link against an externally-built `librayforce.a`. Used only
/// for rayforce development; everyone else gets the auto-vendored path.
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
