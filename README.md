<!--
  Copyright (c) 2025-2026 Anton Kundenko <singaraiona@gmail.com>
  All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
-->

# Raysense

Raysense is local architectural telemetry for AI coding agents.

It scans a repository, extracts files/functions/imports, resolves local
dependency edges, classifies imports, computes graph health, and can materialize
the scan into Rayforce-backed memory tables.

## Current Test Commands

```bash
cargo run -q -p raysense-cli -- health .
cargo run -q -p raysense-cli -- edges .
cargo run -q -p raysense-cli -- observe . --memory
```

Against Rayforce from this workspace layout:

```bash
cargo run -q -p raysense-cli -- health ../rayforce
cargo run -q -p raysense-cli -- edges ../rayforce | head
cargo run -q -p raysense-cli -- observe ../rayforce --memory
cargo run -q -p raysense-cli -- baseline save ../rayforce
cargo run -q -p raysense-cli -- baseline diff ../rayforce
```

Current Rayforce baseline:

```text
score 96
coverage_score 100
structural_score 92
facts files=190 functions=2705 calls=25269 call_edges=15408 imports=1038
entry_points total=50 binaries=6 examples=4 tests=40
imports local=656 external=0 system=382 unresolved=0
graph resolved_edges=656 cycles=0
coupling local_edges=656 cross_module_edges=240 cross_module_ratio=0.366
calls total=25269 resolved_edges=15408 resolution_ratio=0.610 max_function_fan_in=2527 max_function_fan_out=293
size max_file_lines=6329 max_function_lines=2334 large_files=63 long_functions=208
test_gap production_files=150 test_files=40 files_without_nearby_tests=150
dsm modules=5 module_edges=240
evolution available=true commits_sampled=500 changed_files=186
rules high_fan_in=2
```

## Commands

```text
raysense observe <path> [--json] [--memory] [--config <path>]
raysense health <path> [--json] [--config <path>]
raysense edges <path> [--all] [--config <path>]
raysense memory <path> [--config <path>]
raysense baseline save <path> [--output <path>] [--config <path>]
raysense baseline diff <path> [--baseline <path>] [--config <path>] [--json]
raysense mcp
raysense rayforce-version
```

If `<path>/.raysense.toml` exists, health-producing commands load it
automatically. `--config` overrides that path.

`raysense mcp` runs a stdio MCP server for agents. It exposes tools to read and
write config, run health, inspect scan facts, list dependency edges, read
hotspots, read rule findings, read DSM module edges, and materialize memory
table summaries. It can also save and diff baselines.

Baselines are stored under `<path>/.raysense/baseline` by default. The manifest
is JSON for fast agent diffs, and baseline tables are written under `tables/`
in Rayforce splayed-table format.

Example config:

```toml
[scan]
ignored_paths = ["target", "fixtures/generated"]
enabled_languages = []
disabled_languages = []

[rules]
high_file_fan_in = 50
large_file_lines = 500
max_large_file_findings = 20
low_call_resolution_min_calls = 100
low_call_resolution_ratio = 0.5
high_function_fan_in = 200
high_function_fan_out = 100
max_call_hotspot_findings = 5
no_tests_detected = true

[[boundaries.forbidden_edges]]
from = "src"
to = "test"
```

## Status

The first testable version focuses on Rust, C/C++, Python, and TypeScript
codebases:

- Configurable scan filtering by ignored paths and enabled/disabled languages.
- Tree-sitter-backed Rust, C, C++, Python, and TypeScript function discovery
  with lightweight fallback extraction.
- Tree-sitter-backed Rust `use`/`mod`, C/C++ include, Python import, and
  TypeScript import extraction with lightweight fallback extraction.
- Tree-sitter-backed Rust, C, C++, Python, and TypeScript call facts with
  enclosing function ids.
- Conservative call-edge resolution for unambiguous function names.
- Function-level call metrics: resolution ratio, fan-in/fan-out, and top
  called/calling functions.
- Project profile inference for reusable include-root discovery.
- Entry point facts for binaries, examples, and tests.
- Local, external, system, and unresolved import classification.
- Graph metrics: resolved edges, cycles, fan-in, fan-out.
- Health summary with score, import breakdown, hotspots, coupling, size,
  entry point, test-gap, DSM, and evolution-availability metrics.
- Built-in rules for high fan-in, production dependencies on test paths,
  large-file/no-test findings, and call-resolution/function-call hotspots.
- Rule thresholds can be configured with TOML.
- Forbidden top-level module dependencies can be configured with TOML.
- Config read/write, health runs, scan facts, edges, hotspots, rule findings,
  module edges, and memory summaries are exposed through the MCP interface.
- Baseline save/diff is available through the CLI and MCP, with Rayforce
  splayed-table storage for baseline tables.
- Rayforce table materialization for scan facts, call facts, call edges,
  health summary, hotspots, rules, module edges, and changed-file evolution
  metrics.

CI and publish workflows are currently manual-only while the project stabilizes.
