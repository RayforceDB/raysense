---
name: raysense-audit
description: Use when the user explicitly asks for a structural audit, architecture review, dead-code report, test-gap analysis, or evolution hotspot scan. Heavier and noisier than the other raysense skills — only run on demand, not as part of the routine edit loop.
---

# Raysense Audit

This skill is for deliberate "look at the whole codebase" requests.
It calls multiple raysense MCP tools and produces a multi-section
report. Do not run it as part of routine edits — it is loud by design
and will pollute the working context.

All tools take a `path` argument; pass the current repo root.

## Steps

1. **Architecture** — call `raysense_architecture`. Reports root
   causes, cycles by SCC, layer levels, and unstable modules. Lead
   the report with the worst root cause.
2. **DSM** — call `raysense_dsm` for the module dependency matrix and
   level assignments. Useful for showing the user the *shape* of the
   project, not just the metrics.
3. **Evolution** — call `raysense_evolution`. Surfaces bus factor,
   change-coupling pairs (files that change together), and temporal
   hotspots (commits × max complexity).
4. **Test gaps** — call `raysense_test_gaps`. Files without nearby
   tests, ranked by risk.
5. **Optional dashboard** — call `raysense_visualize` if the user
   asked for something they can browse. Writes a self-contained HTML
   file the user can open.

## Report structure

When summarising back to the user, lead with the *one* finding that
matters most — usually the worst architectural root cause or the
highest-risk untested file. Long lists overwhelm; a single
prioritized headline plus a short table of next-three-things tends to
land better.

## When to skip

- The user asked a narrow question. Use `raysense-impact` or a
  single targeted MCP call instead.
- The repo is tiny (under ~50 files). The audit will produce mostly
  noise -- just call `raysense_health` and read out the grade.

## See also

The audit's typed tools surface what raysense already knows.  When
the user asks an audit-shaped question that doesn't fit a typed
tool, the **raysense-query** skill exposes Rayfall directly via
`raysense_baseline_query`:

- Custom architectural breakdowns -- group calls by caller module,
  count cross-layer imports, find ownership-by-language splits.
- `.graph.pagerank` / `.graph.louvain` / `.graph.betweenness` over
  call_edges or module_edges for centrality-based audits.
- `raysense_baseline_import_csv` to bring external audit data
  (coverage, lint counts, test runtime) into the same query
  substrate as the structural baseline.
