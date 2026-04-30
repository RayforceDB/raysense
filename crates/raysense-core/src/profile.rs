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

use crate::facts::{FileFact, Language};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProjectProfile {
    pub include_roots: Vec<PathBuf>,
}

impl ProjectProfile {
    pub fn infer(files: &[FileFact]) -> Self {
        Self {
            include_roots: infer_include_roots(files),
        }
    }
}

fn infer_include_roots(files: &[FileFact]) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();

    for file in files {
        match file.language {
            Language::C | Language::Cpp => {
                for root in c_include_root_candidates(&file.path) {
                    roots.insert(root);
                }
            }
            _ => {}
        }
    }

    roots.into_iter().collect()
}

fn c_include_root_candidates(path: &std::path::Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(first) = path.components().next() {
        if let std::path::Component::Normal(component) = first {
            candidates.push(PathBuf::from(component));
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::FileFact;

    #[test]
    fn infers_c_include_roots_from_top_level_source_dirs() {
        let files = vec![
            file(0, "src/core/runtime.c", Language::C),
            file(1, "include/public.h", Language::C),
            file(2, "test/test.h", Language::C),
            file(3, "crates/app/src/main.rs", Language::Rust),
        ];

        let profile = ProjectProfile::infer(&files);

        assert_eq!(
            profile.include_roots,
            vec![
                PathBuf::from("include"),
                PathBuf::from("src"),
                PathBuf::from("test")
            ]
        );
    }

    fn file(file_id: usize, path: &str, language: Language) -> FileFact {
        FileFact {
            file_id,
            path: PathBuf::from(path),
            language,
            language_name: format!("{:?}", language).to_lowercase(),
            module: String::new(),
            lines: 1,
            bytes: 1,
            content_hash: String::new(),
        }
    }
}
