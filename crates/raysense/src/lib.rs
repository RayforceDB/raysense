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

pub const NAME: &str = "raysense";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use raysense_core::{
    compute_health, scan_path, EntryPointFact, EntryPointKind, FileFact, FileHotspot, FunctionFact,
    GraphMetrics, HealthSummary, ImportFact, ImportResolution, Language, ResolutionBreakdown,
    RuleFinding, RuleSeverity, ScanError, ScanReport, SnapshotFact,
};

pub fn package_name() -> &'static str {
    NAME
}

pub fn package_version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_package_identity() {
        assert_eq!(package_name(), "raysense");
        assert_eq!(package_version(), env!("CARGO_PKG_VERSION"));
    }
}
