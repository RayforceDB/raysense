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
facts files=186 functions=8233 imports=1010
imports local=639 external=0 system=371 unresolved=0
graph resolved_edges=639 cycles=0
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
- Local, external, system, and unresolved import classification.
- Graph metrics: resolved edges, cycles, fan-in, fan-out.
- Health summary with score, import breakdown, and hotspots.
- Built-in rules for high fan-in and production dependencies on test paths.
- Rayforce table materialization for files, functions, and imports.

CI and publish workflows are currently manual-only while the project stabilizes.
