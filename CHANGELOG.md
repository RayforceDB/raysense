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

# Changelog

## 1.0.0 — 2026-05-01

The first stable release. Single binary, single crate, vendored C dependency,
flag-based CLI, live UI.

### Highlights

- **One tool, flag options.** `raysense [PATH]` runs a health report by default.
  Top-level flags select the mode: `--json`, `--check`, `--watch`, `--ui`,
  `--mcp`. Power-user operations (`baseline`, `plugin`, `policy`, `trend`,
  `whatif`) live as subcommands so their multi-arg shapes don't pollute the
  simple path.
- **Live UI.** `raysense . --ui` starts a tokio + axum HTTP server with SSE
  push. The page reloads only when the new scan's content hash differs —
  interactive state (filter selections, scroll, click highlights) survives
  idle periods.
- **Zero-setup builds.** The C library is vendored under `vendor/rayforce/`
  and compiled by `build.rs` via `cc::Build`. No external checkout, no
  submodule, no env var.
- **Single crate.** Five workspace crates collapsed into one, with modules
  under `src/` and a single `[[bin]]`.

### Metrics & analysis

- Coupling, cohesion, instability (Robert Martin), blast radius,
  main-sequence distance, attack surface, coupling entropy, file size
  entropy, complexity entropy, structural uniformity.
- Cyclomatic and cognitive complexity, body-hash duplication, dead code,
  comment ratio.
- Six A–F dimensions: modularity, acyclicity, depth, equality, redundancy,
  structural uniformity. One 0–100 quality signal.
- Evolution: bus factor, file ownership, change-coupling pairs, temporal
  hotspots (churn × complexity), file age.
- Type facts with base-class extraction (Python and TypeScript via
  tree-sitter; line-based fallback for other languages). Inheritance edges
  surfaced as their own memory table.
- Test gap analysis with risk-weighted candidates.
- Per-language rule constraint overrides for the per-file rule thresholds.

### What-if

- Single-step actions: `remove_file`, `move_file`, `add_edge`,
  `remove_edge`, `break_cycle`, plus `break_cycle_recommendations`.
- Typed `Action` enum and `simulate_sequence` for chained simulations,
  with indexed `SequenceError` so callers know which step failed.

### Visualization

- Color modes: language, mono, lines, churn, age, risk, instability.
- Focus modes: language, directory, entry points, impact radius.
- Edge filter: imports, calls, inherits.
- File-level edge overlay rendered as SVG, color-coded by edge type.
- Click-to-highlight upstream / downstream routes.

### MCP

- 43 tools spanning scan, edges, hotspots, architecture, coupling, cycles,
  blast radius, level, evolution, dsm, test gaps, what-if simulation
  (typed action chain), break-cycle recommendations, baseline save / diff
  / table read, plugin lifecycle, policy presets, trend record / show,
  visualize, sarif, memory summary.
- Health cache with declarative invalidation: mutating tools clear it
  before they run; read tools consult it first.

### Build & distribution

- Single `Cargo.toml` with `[[bin]] name = "raysense"`.
- `build.rs` compiles the vendored C library on every fresh build.
- `RAYFORCE_DIR` env var still honored for C-side development.
- CI workflow: `cargo fmt --check` + `cargo test`. Publish workflow: a
  single `cargo publish raysense`.
