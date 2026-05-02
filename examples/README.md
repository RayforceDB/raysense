# Examples

Starter content for the policy-pack and CSV-import surfaces. Each
file here is meant to be copied into your repo's `.raysense/` tree
and adapted to your codebase's specifics.

## `policies/`

Four `.rfl` policies that work end-to-end against any baseline
saved with `raysense baseline save`. Drop them into
`<repo>/.raysense/policies/` and run `raysense policy check`.

| File | What it flags | Severity |
|---|---|---|
| `no-huge-files.rfl` | Files over 2000 lines | warning |
| `concentrated-ownership.rfl` | Files where one author owns every commit (bus_factor == 1) and the file has at least 5 commits of history | warning |
| `change-hotspot.rfl` | Files with `risk_score > 200` in `temporal_hotspots` (churn x complexity) | warning |
| `tightly-coupled-pairs.rfl` | File pairs that co-change more than 50% of the time with at least 3 co-commits | info |

A policy is just a Rayfall expression that returns a `RAY_TABLE` with
the four columns `severity`, `code`, `path`, `message`. Severities
are case-insensitive `info` / `warning` / `error`. Empty result table
means the policy passed. Exit codes from `raysense policy check`:

- `0` -- every policy parsed and reported no error-severity findings
- `1` -- at least one policy itself failed to evaluate (parse / type
  / schema error)
- `2` -- every policy parsed cleanly but at least one reported an
  error-severity finding

## `sample-data/`

Toy CSVs that demonstrate the `raysense baseline import-csv` shape.
Useful for walking through cross-table joins or pairing with the
vector primitives without needing a real coverage / embeddings
pipeline first.

| File | Columns | What to try |
|---|---|---|
| `coverage.csv` | `path`, `covered_lines`, `total_lines`, `covered_pct` | Join with `temporal_hotspots` to find low-coverage files that also see frequent change |
| `embeddings.csv` | `file_id`, `e0`, `e1`, `e2`, `e3` | Toy 4-dim vectors over four files. Pair with `cos-dist` / `knn` to find near-duplicates |

```bash
# Save a baseline first
raysense baseline save .

# Import the toy coverage CSV and query it
raysense baseline import-csv coverage examples/sample-data/coverage.csv
raysense baseline query coverage \
    '(select {from: t where: (< covered_pct 50)})'

# Cross-table: low-coverage AND high churn
raysense baseline query temporal_hotspots \
    '(select {from: t
              where: (in path
                         (at (select {from: coverage where: (< covered_pct 50)})
                             (quote path)))})'

# Vector search demo on the toy embeddings
raysense baseline import-csv embeddings examples/sample-data/embeddings.csv
raysense baseline query embeddings \
    '(knn (list [0.1 0.2 0.3 0.4]
                [0.15 0.18 0.32 0.41]
                [0.9 0.1 0.05 0.02]
                [0.92 0.08 0.07 0.01])
          [0.12 0.19 0.31 0.4]
          2)'
```

## Writing your own

The full Rayfall reference (select syntax, `.graph.*` algorithms,
Datalog rules, vector primitives) ships as the `raysense-query`
skill in the bundled Claude Code plugin. Install with:

```text
/plugin marketplace add RayforceDB/raysense
/plugin install raysense
```

The skill content lives in
`claude-plugin/skills/raysense-query/SKILL.md` if you want to read
it directly without installing.
