---
description: Rescan after edits and diff against the session baseline. Flags new rule failures, newly-hot files, dimensions that worsened.
argument-hint: <project-path>
---

Verify that recent edits in `$1` have not regressed structural health.

If `$1` is empty, treat the project root as the current working directory.

1. Call `raysense_rescan` with `path: $1` to refresh the live scan and trend log.
2. Call `raysense_baseline_diff` with `path: $1` to compare the current scan against the saved baseline.

Report deltas only: rules that newly tripped, files that became hot, dimensions that worsened. If nothing regressed, say so explicitly.
