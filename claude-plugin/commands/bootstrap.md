---
description: Scan the project, save a baseline, and surface top hotspots / failing rules. Run once at the start of a session.
argument-hint: <project-path>
---

Bootstrap a raysense session for the project at `$1`.

If `$1` is empty, treat the project root as the current working directory.

1. Call `raysense_health` with `path: $1`. Note the overall grade and the weakest dimension.
2. Call `raysense_baseline_save` with `path: $1` to persist the baseline (`$1/.raysense/baseline/`).
3. Call `raysense_memory_summary` with `path: $1` to confirm the splayed tables are live; report row/column counts.
4. Call `raysense_hotspots` and `raysense_rules` with `path: $1`. List the three hottest files and any rules currently failing.

Finish with a short summary: overall grade, weakest dimension, the three hottest files, and pre-existing rule failures (so later regressions can be told apart from baseline noise).
