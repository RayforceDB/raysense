---
name: verify
description: Use after completing a logical chunk of edits to rescan the project and detect new rule violations or health regressions against the session baseline. Catches structural regressions before they reach review.
---

# Verify

Call this after a meaningful chunk of edits — typically before
suggesting the user run tests or commit. It rescans the project and
diffs the result against the baseline that `bootstrap`
established.

All tools take a `path` argument; pass the current repo root as an
absolute path.

## Steps

1. **Rescan** — call `raysense_rescan` with `path: <cwd>`. Forces a
   fresh walk; uses cached config and plugin state.
2. **Rule status** — call `raysense_check_rules`. Pass/fail per rule.
   A rule that was passing at bootstrap and is failing now is a
   regression to flag explicitly.
3. **Baseline diff** — call `raysense_baseline_diff` with
   `path: <cwd>`. Health-dimension deltas vs the saved baseline.
   Anything that dropped a grade letter (B → C, etc.) is worth
   surfacing.
4. **Remediations on regression** — if step 2 or 3 reports
   regressions, call `raysense_remediations` for suggested fixes.
   Surface the regression *and* the suggestion to the user before
   continuing.

## What to surface to the user

Be concise. The user does not want a wall of metrics. A good verify
report is:

- "Rules: all pass" *or* "Rules: 1 new failure (`max_blast_radius`,
  was 18 / threshold 25 / now 27)."
- "Baseline diff: modularity B → C-, redundancy stable, others
  unchanged." Only the dimensions that moved.

## When to skip

- Edits were limited to comments, docs, or config that does not
  affect imports.
- The session bootstrapped less than a minute ago and the working
  tree shows trivial changes (`git diff --stat` is one or two lines).

## See also

For verify checks the typed tools don't cover natively:

- `raysense_policy_check` -- evaluates `.rfl` files in
  `<repo>/.raysense/policies/`.  Use this when the team has shipped
  custom architectural rules; they fire alongside the built-in
  `raysense_check_rules` but are code-reviewable in the repo.  Exit
  code 1 = a policy itself failed to evaluate, 2 = at least one
  error-severity finding.
- `raysense_baseline_query` -- the **query** skill covers
  the syntax.  Useful when a verify-time question is shaped like "did
  any new file land that violates X" and X needs a custom Rayfall
  expression.
