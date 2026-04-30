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
```

Current Rayforce baseline:

```text
score 96
coverage_score 100
structural_score 92
facts files=186 functions=8269 imports=1015
entry_points total=50 binaries=6 examples=4 tests=40
imports local=639 external=0 system=376 unresolved=0
graph resolved_edges=639 cycles=0
coupling local_edges=639 cross_module_edges=238 cross_module_ratio=0.372
size max_file_lines=6329 max_function_lines=2334 large_files=62 long_functions=696
test_gap production_files=146 test_files=40 files_without_nearby_tests=146
dsm modules=5 module_edges=238
evolution available=true commits_sampled=500 changed_files=186
rules high_fan_in=2
```

## Commands

```text
raysense observe <path> [--json] [--memory]
raysense health <path> [--json]
raysense edges <path> [--all]
raysense memory <path>
raysense rayforce-version
```

## Status

The first testable version focuses on Rust and C/C++ codebases:

- Rust `use` and `mod` extraction.
- C/C++ local and system include extraction.
- Project profile inference for reusable include-root discovery.
- Entry point facts for binaries, examples, and tests.
- Local, external, system, and unresolved import classification.
- Graph metrics: resolved edges, cycles, fan-in, fan-out.
- Health summary with score, import breakdown, hotspots, coupling, size,
  entry point, test-gap, DSM, and evolution-availability metrics.
- Built-in rules for high fan-in, production dependencies on test paths, and
  large-file/no-test informational findings.
- Rayforce table materialization for scan facts, health summary, hotspots,
  rules, module edges, and changed-file evolution metrics.

CI and publish workflows are currently manual-only while the project stabilizes.
