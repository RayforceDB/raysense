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

**A structural X-ray for the codebases AI agents are writing.**

Raysense reads your repository as a graph: who imports who, where the
cycles are, which files are now load-bearing, what tends to change
together. It runs locally, refreshes on save, and serves the whole
picture to your coding agent over MCP. Before an edit, the agent can
ask *what depends on this file*. After a chunk of edits, it can ask
*did this regress anything*.

## Why

A coding agent reads source one file at a time. The shape of the
project (its modules, its layers, its cycles, the files that always
change together) never reaches its working memory. Reviewers operate
on diffs, and a diff hides structure by definition. So architectural
drift is invisible until it shows up as a production bug, a
regression, or a refactor that takes a week.

## Grading model

Six dimensions, each graded A through F against the dependency graph
and commit history of the repo. The overall score, 0 to 100, is their
weighted aggregate:

- **Modularity** - how cleanly modules separate
- **Acyclicity** - how much the dependency graph really is a graph
- **Depth** - how layered (or how flat-and-tangled) the code is
- **Equality** - how evenly responsibility is distributed
- **Redundancy** - how much logic is duplicated
- **Structural uniformity** - how consistent the patterns are

The score moves with structure, not with cosmetics: adding tests or
shuffling files around will not lift it.

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

## Agent integration

Raysense ships as a Claude Code plugin:

```text
/plugin marketplace add RayforceDB/raysense
/plugin install raysense
```

Four phase-scoped skills: scan + baseline at session start, blast
radius before edits, regression diff after, on-demand architecture
audits. Multi-codebase isolation is cwd-driven, so per-project state
stays in `<repo>/.raysense/`. Two sessions on two repos = two
independent baselines, zero cross-project bleed.

## Capabilities

- **Live treemap dashboard** - every file, every metric, every cycle,
  open in your browser while you work
- **Baselines and what-if** - diff against a saved snapshot; simulate
  an edit (delete a file, break a cycle) before touching the tree
- **Splayed-table agent memory** - scan results materialized as
  columnar tables so an agent's follow-up questions are instant
  reads, not re-scans
- **Edit-risk per file** - one number per file ranking which the next
  agent edit is most likely to break. Composite of churn, max
  complexity, single-owner penalty, and missing-tests penalty,
  refreshed on every save
- **Score drift per session** - every baseline save appends a sample;
  verify diffs against the previous one and surfaces per-dimension
  drift (Equality went B to D) instead of a single aggregate delta
- **Bug-density per file** - files where most of the churn is fix
  commits float to the top. Conventional Commits prefixes (fix,
  hotfix, revert) drive the classifier; absolute count and ratio
  against total commits both feed the ranking
- **Test gap detection** - files without nearby tests, ranked by
  structural risk. Feeds directly into the edit-risk score so
  untested files in churn-heavy areas surface first
- **Evolution signal** - bus factor per file, change-coupling pairs,
  temporal hotspots (churn x complexity), file age windows, and
  bug-fix concentration over the last 500 commits
- **68 language profiles out of the box** - Rust, Python, TypeScript,
  C, C++ via tree-sitter; 63 more standard profiles (Go, Java,
  Kotlin, Swift, Ruby, Elixir, Haskell, Clojure, Zig, GLSL,
  Terraform, Dockerfile, ...) via configurable plugins. Add your own
  in `.raysense/plugins/`.

## Built on Rayforce

<a href="https://github.com/RayforceDB/rayforce">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-light.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/logo-dark.svg">
    <img alt="Rayforce" src="docs/logo-dark.svg" width="320">
  </picture>
</a>

The splayed-table agent memory, the baseline tables you can query
back, and the columnar storage behind the live dashboard are all
powered by **[Rayforce](https://github.com/RayforceDB/rayforce)**, an
in-memory analytics runtime optimized for graph-shaped queries.
Rayforce is what makes "ask the same question a hundred times during
a coding session" cost a hundred microseconds instead of a hundred
re-scans. It's open-source and linked statically into the raysense
binary; there is nothing extra to install.

If you're building structural-analysis tooling of your own, take a
look. Rayforce is a standalone project and useful well beyond this
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
