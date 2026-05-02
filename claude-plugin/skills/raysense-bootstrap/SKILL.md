---
name: raysense-bootstrap
description: Use at the start of any coding session in a repository to scan the structure, save a baseline, and materialize splayed-table memory for fast follow-up queries. Establishes the "before" reference point that raysense-verify diffs against later.
---

# Raysense Bootstrap

Run this once per session, before any non-trivial edits. It produces a
persisted baseline plus live splayed-table memory that the other
raysense skills (`raysense-impact`, `raysense-verify`,
`raysense-audit`) read against.

All tools take a `path` argument. Always pass the current working
directory as an absolute path so per-project state stays inside the
repo (`<repo>/.raysense/`).

## Steps

1. **Health overview** — call `raysense_health` with `path: <cwd>`.
   Note the overall grade and the worst dimension.
2. **Save the baseline** — call `raysense_baseline_save` with
   `path: <cwd>`. This writes `<cwd>/.raysense/baseline/manifest.json`
   plus splayed tables under `<cwd>/.raysense/baseline/tables/`.
3. **Confirm memory is live** — call `raysense_memory_summary` with
   `path: <cwd>`. Report the row/column counts so the user can see the
   memory is materialized.
4. **Surface the top 3 hotspots** — call `raysense_hotspots` and
   `raysense_rules`. List the three highest-traffic files and any
   already-failing rules. These are the spots most likely to bite
   during the session.

## What to keep in working memory

After bootstrap, the agent should remember (briefly):

- The overall health grade and the lowest-scoring dimension.
- The three hottest files (high coupling × high churn).
- Whether any rules are currently failing (so a later regression isn't
  mistaken for pre-existing breakage).

## When to skip

- Session is read-only (the user just asked a question -- no edits
  planned). Skip bootstrap; reach for `raysense-audit` instead if
  structural context is needed.
- A baseline already exists from a recent session and no commits have
  landed since (`git log -1 --since='1 hour ago'` shows nothing).
  Re-using the previous baseline is fine; just call `raysense_health`
  for a fresh grade and skip the rest.

## See also

The baseline this skill produces is queryable, not just a dump.
After bootstrap, the agent has access to:

- `raysense_baseline_query` -- run any Rayfall expression against a
  saved table.  Syntax and worked examples in the **raysense-query**
  skill (select / `.graph.*` / Datalog / vector search).
- `raysense_policy_check` -- evaluate `.rfl` policy packs in
  `<repo>/.raysense/policies/`; ships its own exit-code semantics for
  CI gating.
- `raysense_baseline_import_csv` -- bring external CSVs (coverage,
  lint counts, embeddings) into the baseline as queryable tables.
