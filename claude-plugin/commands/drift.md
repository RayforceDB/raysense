---
description: Detect structural drift over a time window. Ranks worsened dimensions, newly hot files, newly tripped rules.
argument-hint: <project-path> [window=30d]
---

Detect structural drift in the project at `$1` over the `$2` window.

If `$1` is empty, treat the project root as the current working directory.
If `$2` is empty, default the window to `30d`. Accepted values: `7d`, `30d`, `90d`, `all`.

1. Call `raysense_drift` with `path: $1` and `window: $2` (or `30d` if not given).
2. Cross-check with `raysense_trend` over the same window for any dimension that visibly trended down.

Produce a punch list, ranked: dimensions that worsened most, files that became newly hot, rules that newly tripped. Include the magnitude of each delta.
