---
name: drift
description: Use after a rescan to surface structural regressions across a time window. Diffs the latest scan against the saved baseline AND the trend history, ranking dimensions that worsened, files newly hot, and rules newly tripped. Configurable window (7d, 30d, 90d). Use periodically (daily, weekly, or pre-PR).
---

# Drift

`drift` answers one question: "what got worse since N days ago?"
It is heavier than `verify` (which only diffs against the saved
baseline) but lighter than `audit` (which sweeps the whole repo).
Run it when the question is shaped like "are we slowly losing
modularity?" or "did a bad pattern creep in over the last sprint?"

All tools take a `path` argument; pass the current repo root as an
absolute path.

## Steps

1. **Rescan**. Call `raysense_rescan` with `path: <cwd>` so the
   active health is current.
2. **Drift summary**. Call `raysense_drift` with `path: <cwd>` and
   `window: 30d` (the default). Returns:
   - `worsened_dimensions`: the dimensions whose scores dropped
     (or rule count rose) across the window.
   - `hotspots_new_or_risen`: files that newly entered the top
     hotspots or whose `risk_score` climbed.
   - `rules_new_or_increased`: rule codes that newly tripped or
     whose violation count grew.
3. **Trend context**. When `drift` reports `available: false`
   (fewer than 2 samples in the window), call `raysense_trend` with
   `window: all` so the user sees how short the history is. Suggest
   they call `raysense_baseline_save` to seed a sample.
4. **Remediations on regression**. For each entry in
   `rules_new_or_increased`, call `raysense_remediations` and
   surface the suggestion alongside the regression.

## What to surface to the user

A good drift report leads with the worst regression, not the full
list. Three focused lines beat one wall of metrics:

- "Modularity dropped 0.92 to 0.78 (worst dimension this window)."
- "src/big.rs is the new top hotspot (risk_score 50 to 216)."
- "Rule `max_function_complexity` newly tripped (0 to 2)."

If `drift` returns nothing in any of the three categories, say so
plainly: "No drift detected in the last 30d." Do not pad with empty
sections.

## Window choice

- `7d`: catches regressions from the current week's edits.
- `30d`: default. Sees a typical sprint's worth of structural
  movement.
- `90d`: quarterly review cadence. Often spans refactors that
  haven't fully settled.
- `all`: every recorded sample. Use when you want the full arc.

Drift compares the *oldest* in-window sample to the *newest*
in-window sample. Wider windows give bigger deltas but blur acute
regressions.

## When to skip

- Fewer than 2 samples in the trend history. The skill will return
  `available: false` and the report will be empty. Run
  `raysense_baseline_save` first to seed history.json.
- The user asked "what's broken right now?" That is a `verify` or
  `audit` question, not a drift question.

## See also

- `verify`: snapshot diff against the session baseline (no time
  axis). Use after a focused chunk of edits.
- `audit`: whole-repo structural sweep, no time axis. Use when the
  question is shape, not change.
- `raysense_baseline_query`: the `query` skill covers Rayfall
  directly. The splayed `trend_health`, `trend_hotspots`, and
  `trend_violations` tables are queryable from there for custom
  drift analyses (per-dimension regressions, file-specific arcs).
