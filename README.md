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

**Architectural X-ray for your codebase. Live, local, agent-ready.**

Point Raysense at a repository and it tells you, in seconds, where the
load-bearing files are, which modules are tangled, where complexity is
hiding, and which parts of the codebase are bus-factor-of-one. It runs
locally, ships zero data anywhere, and exposes everything to AI coding
agents through MCP.

## Why

LLM coding agents read source one file at a time. They don't see the
*shape* of your project: the cycles, the god files, the dead code, the
files that change together every commit. Raysense computes that shape
once and serves it back as queryable structure — to your agents, to
your CI, and to a live dashboard you can keep open while you work.

## Install

```bash
cargo install raysense
```

Or build from source — see [Building](#building) below.

## Use

One command, a few flags. The default is a health report.

```bash
raysense .                  # health report
raysense . --json           # machine-readable JSON
raysense . --check          # CI gate, exits non-zero on rule failures
raysense . --watch          # rescan + reprint on a 2s loop
raysense . --ui             # live dashboard at http://localhost:7000
raysense --mcp              # stdio MCP server for agents
```

Power-user operations live as subcommands: `baseline save|diff`,
`plugin sync`, `policy init`, `trend record|show`, `whatif`. See
`raysense --help` for the full surface.

## What it measures

- **Coupling, cohesion, instability** — Robert Martin's stable-foundation
  model, plus blast radius and main-sequence distance.
- **Complexity** — cyclomatic and cognitive, per function and aggregated.
- **Cycles and depth** — strongly-connected components, longest acyclic
  path, upward-layer violations.
- **Evolution** — bus factor, change-coupling pairs, temporal hotspots
  (churn × complexity), file age.
- **Types and inheritance** — type facts with base-class extraction
  (Python and TypeScript via tree-sitter, others via line parsing).
- **Test gaps** — files without nearby tests, ranked by risk.
- **Six A–F dimensions** — modularity, acyclicity, depth, equality,
  redundancy, structural uniformity. One 0–100 quality signal.

## Configuration

Everything is overridable in `.raysense.toml` at the repo root: rule
thresholds, plugin language definitions, baseline scoring, what-if
ignored paths. Per-language rule overrides let one language demand
stricter caps than another. `raysense --help` lists every flag.

## Building from source

The C dependency is vendored. Clone and build — that's it:

```bash
git clone https://github.com/RayforceDB/raysense.git
cd raysense
cargo build --release
```

No external setup, no submodules, no environment variables.

## License

MIT. See [LICENSE](LICENSE).
