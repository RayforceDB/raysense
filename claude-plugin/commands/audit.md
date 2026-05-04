---
description: Heavy structural audit — architecture review, evolution hotspots, test gaps, DSM. Run on demand, not in routine edit loop.
argument-hint: <project-path>
---

Run a heavy structural audit of the project at `$1`.

If `$1` is empty, treat the project root as the current working directory.

1. Call `raysense_architecture` with `path: $1` for top-level metrics, root-cause scores, cycles, levels, and unstable modules.
2. Call `raysense_evolution` with `path: $1` for churn × coupling hotspots.
3. Call `raysense_test_gaps` with `path: $1` for under-tested high-traffic files.
4. Call `raysense_dsm` with `path: $1` for the dependency structure matrix.

Synthesize a written architecture review: structural strengths, the three biggest risks, and three concrete remediations to consider.
