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
