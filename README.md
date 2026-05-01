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

**An agent writes the code. Raysense keeps the architecture honest.**

AI coding agents work at machine speed. The codebase they leave behind
— cycles, god files, files that quietly change together every commit,
areas no test covers — drifts at the same speed, and you can't see any
of it from a diff. Raysense scans the repository, scores its structure,
and shows the result to you, your CI, your live dashboard, and (most
importantly) to the agent itself, before it edits next.

## The problem

A coding agent reads one file at a time. It doesn't see the *shape* of
your project: which modules are tangled, which files are load-bearing,
where complexity is concentrated, what changed together every commit
last quarter. Reviewers don't see it either. By the time a structural
regression is obvious in production, the cost of unwinding it has
compounded.

## One quality signal

Six A–F dimensions, computed from your repository's dependency graph
and commit history, distilled into one 0–100 score:

- **Modularity** — how cleanly modules separate
- **Acyclicity** — how much the dependency graph really is a graph
- **Depth** — how layered (or how flat-and-tangled) the code is
- **Equality** — how evenly responsibility is distributed
- **Redundancy** — how much logic is duplicated
- **Structural uniformity** — how consistent the patterns are

The score is ungameable. You can't trick it by adding tests or
shuffling files; the graph either has cycles or it doesn't.

## Install

```bash
cargo install raysense
```

## Use

```bash
raysense .              # health report
raysense . --check      # CI gate, exits non-zero on rule violations
raysense . --watch      # rescan + reprint on a 2s loop
raysense . --ui         # live dashboard at http://localhost:7000
raysense --mcp          # stdio MCP server for agents
```

## For coding agents

Raysense ships as a Claude Code plugin:

```text
/plugin marketplace add RayforceDB/raysense
/plugin install raysense
```

Four phase-scoped skills: scan + baseline at session start, blast
radius before edits, regression diff after, on-demand architecture
audits. Multi-codebase isolation is cwd-driven — per-project state
stays in `<repo>/.raysense/`. Two sessions on two repos = two
independent baselines, zero cross-project bleed.

## What you get

- **Live treemap dashboard** — every file, every metric, every cycle,
  open in your browser while you work
- **Baselines and what-if** — diff against a saved snapshot; simulate
  an edit (delete a file, break a cycle) before touching the tree
- **Splayed-table agent memory** — scan results materialized as
  columnar tables so an agent's follow-up questions are instant
  reads, not re-scans
- **Test gap detection** — files without nearby tests, ranked by risk
- **Evolution signal** — bus factor, change-coupling pairs, temporal
  hotspots (churn × complexity)
- **45 languages out of the box** — Rust, Python, TypeScript, C, C++
  via tree-sitter; 40 more (Go, Java, Kotlin, Swift, Ruby, Elixir,
  Haskell, Clojure, Zig, …) via configurable plugins. Add your own in
  `.raysense/plugins/`.

## Built on Rayforce

The splayed-table agent memory, the baseline tables you can query
back, and the columnar storage behind the live dashboard are all
powered by **[Rayforce](https://github.com/RayforceDB/rayforce)** —
an in-memory analytics runtime optimized for graph-shaped queries.
Rayforce is what makes "ask the same question a hundred times during
a coding session" cost a hundred microseconds instead of a hundred
re-scans. It's open-source and linked statically into the raysense
binary; there is nothing extra to install.

If you're building structural-analysis tooling of your own, take a
look — Rayforce is a standalone project and useful well beyond this
one.

## Configuration

`.raysense.toml` at the repo root overrides everything: rule
thresholds, plugin language definitions, baseline scoring, what-if
ignored paths. Per-language rule overrides let one language demand
stricter caps than another. `raysense --help` lists every flag.

## Building from source

```bash
git clone https://github.com/RayforceDB/raysense.git
cd raysense
cargo build --release
```

The rayforce C runtime is sourced from upstream at the SHA pinned in
`.rayforce-version`. `build.rs` clones it on first build, or uses a
`RAYFORCE_DIR=/abs/path` you provide. Requires `git`, `make`, and a C
compiler (clang or gcc).

## License

MIT. See [LICENSE](LICENSE).
