---
name: raysense-impact
description: Use before refactoring, deleting, moving, or substantially modifying a file to compute its blast radius, coupling profile, and cycle exposure. Lets the agent edit with awareness of downstream effects rather than discovering them after the fact.
---

# Raysense Impact

Call this *before* a non-trivial edit (deletion, rename, signature
change, extraction, file move). It tells the agent what depends on the
target and what the target depends on, so the edit plan can account
for the blast radius up front.

All tools take a `path` argument (absolute, current repo root) plus
the target file path relative to that root.

## Steps

1. **Blast radius** — call `raysense_blast_radius` with `path: <cwd>`
   and `file: <target>`. Returns the set of files reachable downstream
   under the active edge filter. A blast radius >20 files is a strong
   signal to break the change into smaller commits.
2. **Coupling profile** — call `raysense_coupling`. Look up the
   target's module in the response: afferent (incoming) and efferent
   (outgoing) counts, plus main-sequence distance. High-afferent
   modules are stable foundations — breaking changes there cascade
   widely.
3. **Cycle exposure** — call `raysense_cycles`. If the target appears
   in any reported cycle, call
   `raysense_break_cycle_recommendations` for ranked candidate edges
   to remove. The recommended edge is often *not* the obvious one.
4. **Optional simulation** — when the planned change is mechanical
   (file removal, edge removal), call `raysense_what_if` to preview
   the health delta without touching the working tree.

## What to keep in working memory

- Number of files in the blast radius — quote it back to the user
  before starting an edit that exceeds 20.
- Whether the target is on any cycle — informs whether the edit is
  likely to introduce or break a cycle.
- The `instability` score — a value near 1.0 means the file is
  expected to depend on stable foundations, not be one.

## When to skip

- Local-only edit inside one file with no signature changes (typo
  fix, comment, internal rename). No downstream effect, no need.
- Brand-new file. Nothing depends on it yet.

## See also

For cases the typed tools above don't cover, the **raysense-query**
skill exposes Rayfall directly via `raysense_baseline_query`:

- Custom reachability rules through Datalog -- declarative
  `(reaches ?a ?b)` plus a recursive arm gives the same shape as
  `raysense_blast_radius` but with a rule the agent picks at query
  time.
- `.graph.shortest-path` / `.graph.k-shortest` for path-aware impact
  ("which call paths reach this entry point") that go beyond the
  blast-radius set.
- Ad-hoc joins between `call_edges` and `change_coupling` /
  `file_ownership` to weight blast radius by author / commit history.
