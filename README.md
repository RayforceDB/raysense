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
score 77
quality_signal 7708
coverage_score 100
structural_score 72
facts files=190 functions=2662 calls=25704 call_edges=15492 imports=1039
entry_points total=50 binaries=6 examples=4 tests=40
imports local=657 external=0 system=382 unresolved=0
graph resolved_edges=657 cycles=0
coupling local_edges=657 cross_module_edges=240 cross_module_ratio=0.365
calls total=25704 resolved_edges=15492 resolution_ratio=0.603 max_function_fan_in=2537 max_function_fan_out=293
size max_file_lines=6329 max_function_lines=2334 large_files=63 long_functions=209
test_gap production_files=150 test_files=40 files_without_nearby_tests=150
dsm modules=5 module_edges=240
root_causes modularity=0.635 acyclicity=1.000 depth=1.000 equality=0.450 redundancy=0.952
architecture depth=3 max_blast_radius=25 max_blast_radius_file=src/ops/query.c
complexity max=131 avg=3.904 gini=0.550 dead_functions=50 duplicate_groups=20 redundancy_ratio=0.048
evolution available=true commits_sampled=500 changed_files=190
rules warnings=7 info=31
```

## Commands

Install from crates.io after building a local Rayforce library:

```sh
git clone git@github.com:RayforceDB/rayforce.git
make -C rayforce lib
RAYFORCE_DIR="$PWD/rayforce" cargo install raysense
```

For library use:

```sh
cargo add raysense
```

```text
raysense observe <path> [--json] [--memory] [--config <path>]
raysense health <path> [--json] [--config <path>]
raysense edges <path> [--all] [--config <path>]
raysense memory <path> [--config <path>]
raysense check [path] [--json] [--sarif <path>] [--config <path>]
raysense gate [path] [--save] [--baseline <path>] [--json] [--config <path>]
raysense watch [path] [--interval <seconds>] [--config <path>]
raysense visualize [path] [--watch] [--interval <seconds>] [--output <path>] [--config <path>]
raysense plugin list [path] [--config <path>]
raysense plugin add <name> <extensions...> [--file-name <name>] [--path <path>] [--config <path>]
raysense plugin add-standard [--path <path>] [--config <path>]
raysense plugin remove <name> [--path <path>] [--config <path>]
raysense plugin init <name> <extension> [--path <path>] [--config <path>]
raysense policy list
raysense policy init <preset> [path] [--config <path>]
raysense trend record [path] [--config <path>]
raysense trend show [path] [--json] [--config <path>]
raysense remediate [path] [--json] [--config <path>]
raysense what-if [path] [--ignore <pattern>] [--generated <pattern>] [--json] [--config <path>]
raysense baseline save <path> [--output <path>] [--config <path>]
raysense baseline diff <path> [--baseline <path>] [--config <path>] [--json]
raysense baseline tables [--baseline <path>] [--json]
raysense baseline table <name> [--baseline <path>] [--columns <a,b>] [--filter <column:op:value>] [--filter-mode <all|any>] [--sort <column[:asc|desc]>] [--desc] [--offset <n>] [--limit <n>] [--json]
raysense mcp
raysense rayforce-version
```

If `<path>/.raysense.toml` exists, health-producing commands load it
automatically. `--config` overrides that path.
Project-local plugin manifests under `.raysense/plugins/*/plugin.toml` are also
loaded during scans, using the same fields as `[[scan.plugins]]`.
When `.raysense/plugins/<name>/queries/tags.scm` is present and the plugin
selects a compiled grammar with `grammar = "rust"`, `c`, `cpp`, `python`, or
`typescript`, or with `grammar_path` and optional `grammar_symbol`, Raysense
uses query captures for functions and imports before falling back to token
prefixes.

`raysense mcp` runs a stdio MCP server for agents. It exposes tools to read and
write config, run health, inspect scan facts, list dependency edges, read
hotspots, read rule findings, read DSM module edges, inspect architecture,
coupling, cycles, hottest files/functions, blast radius, module levels, run
what-if config simulations, and materialize memory table summaries. It can also
write visualization dashboards, emit SARIF reports, apply policy presets,
save/diff baselines, and query saved baseline tables with projection, filters,
sorting, and pagination. Agent session tools can save an in-memory baseline,
rescan, end the session, check rules, inspect evolution, inspect DSM data,
inspect test gaps, list configured language plugins, and add generic or
standard plugin profiles, or remove plugin profiles.

`raysense visualize` writes a self-refreshing local HTML dashboard with file
size blocks, module graph edges, hotspots, rules, complexity, test gaps, and an
embedded telemetry JSON payload. Use `--watch` to keep regenerating the page
from fresh scans.

Baselines are stored under `<path>/.raysense/baseline` by default. The manifest
is JSON for fast agent diffs, and baseline tables are written under `tables/`
in Rayforce splayed-table format.

Baseline table filters use `column:op:value`, where `op` is one of `eq`, `ne`,
`in`, `not_in`, `contains`, `starts_with`, `ends_with`, `regex`, `not_regex`,
`gt`, `gte`, `lt`, or `lte`. Filters default to AND semantics; use
`--filter-mode any` for OR.
Repeat `--sort` to apply ordered multi-column sorting.

CLI examples:

```sh
raysense baseline save .
raysense baseline tables --baseline .raysense/baseline
raysense baseline table files --baseline .raysense/baseline --columns path,language,lines --filter 'language:in:["c","rust"]' --sort language:asc --sort lines:desc --limit 10
raysense baseline table files --baseline .raysense/baseline --columns path --filter 'path:regex:^src/ops/.*\.c$' --filter 'path:not_regex:query' --limit 10
```

MCP query example:

```json
{
  "name": "raysense_baseline_table_read",
  "arguments": {
    "baseline_path": ".raysense/baseline",
    "table": "files",
    "columns": ["path", "language", "lines"],
    "filters": [
      {"column": "language", "op": "in", "value": ["c", "rust"]},
      {"column": "path", "op": "regex", "value": "^src/.*\\.(c|rs)$"}
    ],
    "filter_mode": "all",
    "sort": [
      {"column": "language", "direction": "asc"},
      {"column": "lines", "direction": "desc"}
    ],
    "limit": 10
  }
}
```

Release checks:

```sh
cargo package -p rayforce-sys
cargo package -p raysense-core
cargo package -p raysense-memory
cargo package -p raysense-cli
cargo package -p raysense
```

Run the `publish` workflow manually with `dry_run=true` before publishing a
release. The workflow publishes packages in dependency order, waits for each
new package to appear in the registry index, and then runs a post-release
install and library smoke check.

Example config:

```toml
[scan]
ignored_paths = ["target", "fixtures/generated"]
generated_paths = ["**/generated/*"]
enabled_languages = []
disabled_languages = []
module_roots = ["crates", "src"]
test_roots = ["tests"]
public_api_paths = ["src/lib.rs"]

[[scan.plugins]]
name = "foo"
grammar = "rust"
grammar_path = "grammars/foo.so"
grammar_symbol = "tree_sitter_foo"
extensions = ["foo"]
file_names = ["Foofile"]
function_prefixes = ["function "]
import_prefixes = ["load "]
call_suffixes = ["("]
tags_query = """
(function_item
  name: (identifier) @name) @definition.function
"""
package_index_files = ["index.foo"]
test_path_patterns = ["tests/*", "*_test.foo"]
source_roots = ["src"]
ignored_paths = ["build/*"]
local_import_prefixes = ["."]

[rules]
min_quality_signal = 0
min_modularity = 0.0
min_acyclicity = 0.0
min_depth = 0.0
min_equality = 0.0
min_redundancy = 0.0
max_cycles = 0
max_coupling_ratio = 1.0
max_function_complexity = 15
max_file_lines = 0
max_function_lines = 0
no_god_files = true
high_file_fan_in = 50
large_file_lines = 500
max_large_file_findings = 20
low_call_resolution_min_calls = 100
low_call_resolution_ratio = 0.5
high_function_fan_in = 200
high_function_fan_out = 100
max_call_hotspot_findings = 5
max_upward_layer_violations = 0
no_tests_detected = true

[[boundaries.forbidden_edges]]
from = "src"
to = "test"
reason = "runtime code must not depend on tests"

[[boundaries.layers]]
name = "core"
path = "src/core/*"
order = 0

[score]
modularity_weight = 1.0
acyclicity_weight = 1.0
depth_weight = 1.0
equality_weight = 1.0
redundancy_weight = 1.0
```

## Status

The first testable version has grammar-backed support for Rust, C/C++, Python,
and TypeScript, plus a built-in generic catalog for common project languages
and formats:

- Configurable scan filtering by ignored paths and enabled/disabled languages.
- Configurable module roots for DSM and architecture grouping.
- Generic configured language plugins by file extension with configurable
  function, import, and call token extraction.
- Standard language plugin profiles can be listed through MCP or materialized
  into project config with `raysense plugin add-standard`.
- Project-local plugin manifests can be loaded from
  `.raysense/plugins/*/plugin.toml`.
- Built-in generic analyzers for Go, Java, Kotlin, Scala, C#, PHP, Ruby, Swift,
  shell, SQL, Lua, Perl, Dart, Elixir, Haskell, OCaml, F#, Clojure, Solidity,
  protobuf, GraphQL, build/config formats, and other common file types.
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
- Health summary with score, 0-10000 quality signal, root-cause scores,
  import breakdown, hotspots, coupling, size, entry point, test-gap, DSM,
  architecture, complexity, and evolution metrics.
- Source-aware complexity, duplicate-body grouping, and public API aware
  dead-function filtering.
- Semantic-shape duplicate grouping for code that is structurally similar after
  names and literals are normalized.
- Ecosystem-aware module grouping for common monorepo, Rust, Python, Java, and
  Kotlin layouts.
- Test-gap candidates include expected test file paths for each unmatched
  production file.
- Framework-aware test-gap naming for Rust, Python, TypeScript, Go, Java, and
  .NET-style projects.
- Built-in policy presets for Rust crates, monorepos, backend services, and
  libraries.
- Remediation suggestions are exposed through the CLI and MCP.
- Persisted trend samples can be recorded and read back for score/rule deltas.
- Score calibration weights can be configured for the root-cause dimensions.
- Built-in rules for high fan-in, production dependencies on test paths,
  large-file/no-test findings, call-resolution/function-call hotspots, max
  cycles, max coupling, max function complexity, god-file pressure, and ordered
  layer constraints.
- Rule thresholds can be configured with TOML.
- Forbidden top-level module dependencies can be configured with TOML.
- Config read/write, health runs, scan facts, edges, hotspots, rule findings,
  module edges, architecture, coupling, cycles, hottest files/functions, blast
  radius, module levels, what-if simulations, session start/end, rescans, rule
  checks, evolution, DSM, test gaps, plugin listing, remediation suggestions,
  trend metrics, policy presets, memory summaries, and saved baseline table
  queries are exposed through the MCP interface.
- Baseline save/diff is available through the CLI and MCP, with Rayforce
  splayed-table storage for baseline tables.
- MCP session baselines are persisted by default and can be compared across
  process restarts.
- CLI quality gate, watch loop, plugin management, and generated self-refreshing
  local HTML architecture visualization are available.
- Rayforce table materialization for scan facts, call facts, call edges,
  health summary, hotspots, rules, module edges, and changed-file evolution
  metrics.

CI runs on pushes and pull requests. Publish runs when a release is published
and can also be started manually.
