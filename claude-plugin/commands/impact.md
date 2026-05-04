---
description: Compute the blast radius of a file before refactoring or deleting it. Reports dependents, coupling, cycle exposure.
argument-hint: <project-path> <file>
---

Compute the structural impact of changing `$2` in the project at `$1`.

If `$1` is empty, treat the project root as the current working directory.

1. Call `raysense_blast_radius` with `path: $1` and `file: $2` to enumerate direct and transitive dependents.
2. Call `raysense_coupling` with `path: $1` to read the fan-in / fan-out profile for `$2`.
3. Call `raysense_cycles` with `path: $1` to check whether `$2` participates in any cycle.

Finish with a verdict: is changing `$2` a local edit, a coupled edit (touch-and-test the dependents), or a structural edit (cycle / high fan-in — split the work)?
