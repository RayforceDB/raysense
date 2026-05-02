---
name: raysense-query
description: Use when the agent has a structural question about the saved baseline that the typed MCP tools (health, hotspots, rules, blast radius, coupling, cycles, evolution) do not directly answer. Runs Rayfall expressions against splayed baseline tables via raysense_baseline_query. Three modes are available - select queries for filter/project/aggregate (most common), .graph.* algorithms (PageRank, Louvain, topsort, shortest-path, betweenness, closeness, MST, k-shortest, BFS expand) for centrality and reachability over the call graph, and Datalog rules with transitive closure for declarative reachability ("reaches", "depends-on", "tainted-by"). Reach for this when the question shape is "files where X and Y," "most-central callers," "what does X transitively reach," or any custom slice across the 18 baseline tables.
---

# Raysense Query

`raysense_baseline_query` evaluates a Rayfall expression against a
single baseline table, which is bound to the symbol `t` before
evaluation. The result must itself be a `RAY_TABLE`. Wrap scalar /
column queries with `select` to keep the result tabular.

Use this when the question shape isn't covered by the dedicated tools.
For pure paginate / filter / sort, prefer `raysense_baseline_table_read`
(no Rayfall needed). For graph-shaped questions (blast radius, cycles),
prefer `raysense_blast_radius` / `raysense_cycles`.

## Inputs

```text
raysense_baseline_query
    path:     <absolute repo root, defaults to cwd>
    table:    one of files | functions | imports | calls | call_edges
              | types | hotspots | rules | module_edges | changed_files
              | file_ownership | temporal_hotspots | file_ages
              | change_coupling | inheritance | entry_points | health
              | meta
    rayfall:  Rayfall source, e.g. "(select {from: t where: (> lines 500)})"
```

Call `raysense_baseline_tables` first if you are unsure what is saved
(empty / missing tables fail loudly rather than silently).

## Schema cheat sheet

The columns most agents ask about. For the full list, query the table
once with `t` (no filter) and read the column names off the result.

- **files**: `file_id i64`, `path str`, `language str`, `module str`,
  `lines i64`, `bytes i64`, `content_hash str`
- **functions**: `function_id i64`, `file_id i64`, `name str`,
  `start_line i64`, `end_line i64`
- **calls**: `call_id i64`, `file_id i64`, `caller_function i64`,
  `target str`, `line i64`
- **call_edges**: `edge_id i64`, `call_id i64`, `caller_function i64`,
  `callee_function i64`
- **imports**: `import_id i64`, `from_file i64`, `target str`,
  `kind str`, `resolution str`, `resolved_file i64`
- **hotspots**: `file_id i64`, `path str`, `module str`,
  `fan_in i64`, `fan_out i64`
- **rules**: `severity str`, `code str`, `path str`, `message str`
- **module_edges**: `from_module str`, `to_module str`, `edges i64`
- **change_coupling**: `left str`, `right str`, `co_commits i64`,
  `coupling_strength_milli i64`
- **file_ownership**: `path str`, `top_author str`,
  `top_author_commits i64`, `total_commits i64`, `author_count i64`,
  `bus_factor i64`
- **meta**: `schema_version i64`, `raysense_version str`,
  `rayforce_version str`, `repo_sha str`, `snapshot_id str`,
  `scan_unix i64`, `column_digest str`

## Rayfall in 30 seconds

S-expression, prefix notation, strict arity. The bound symbol is `t`.

```rfl
t                                     ; the whole bound table
(count t)                             ; row count, scalar -- NOT a table
(at t 'path)                          ; column vector, NOT a table

(select {from: t})                    ; full table back, RAY_TABLE
(select {from: t where: (> lines 500)})
(select {path: path lines: lines from: t where: (> lines 500)})

;; aggregation: group with `by`
(select {n: (count path) total: (sum lines)
         from: t by: language})

;; combined predicates
(select {from: t where: (and (== language "rust") (> lines 1000))})

;; sort + take
(select {from: t asc: lines take: 10})
(select {from: t desc: lines take: 10})
```

Operators are **functions, not infix**: `(> a b)`, `(== a b)`,
`(and p q)`, `(or p q)`, `(in x set)`. String literals use double
quotes; symbols use a leading apostrophe.

## Worked examples

Files over 500 lines, sorted by size:

```rfl
(select {path: path lines: lines from: t
         where: (> lines 500) desc: lines})
```

Files where a single author owns more than 80% of commits:

```rfl
;; against table file_ownership -- div is float divide; % is modulo
(select {from: t
         where: (> (div top_author_commits total_commits) 0.8)})
```

LOC by language, descending:

```rfl
;; against table files
(select {loc: (sum lines) files: (count path)
         from: t by: language desc: loc})
```

Top 5 most-changed paths:

```rfl
;; against table changed_files
(select {from: t desc: commits take: 5})
```

## Graph algorithms

Rayfall ships a CSR-backed graph engine that runs against any edge
table. Build a handle with `.graph.build`, then dispatch any of the
algorithms.  The handle is auto-released when the result drops.

`call_edges` is the canonical raysense graph (caller and callee are
already integer function ids). For module-level work the columns are
strings, so wrap with `(.sym ...)` or query `imports`/`call_edges`
joined back to `files.module` instead.

```rfl
;; PageRank centrality over the call graph (30 iters, damping 0.85).
;; Result columns: _node, _rank.
(select {from: (.graph.pagerank
                 (.graph.build t 'caller_function 'callee_function)
                 30 0.85)
         desc: _rank take: 10})

;; Total degree centrality (in + out).  Columns: _node, _in_degree,
;; _out_degree, _degree.  Highest-degree functions are the hot ones.
(select {from: (.graph.degree
                 (.graph.build t 'caller_function 'callee_function))
         desc: _degree take: 10})

;; Topological sort -- only meaningful if the graph is acyclic.
;; Columns: _node, _order.  If a cycle exists, the algorithm returns
;; the partial order it managed to compute.
(.graph.topsort (.graph.build t 'caller_function 'callee_function))

;; Weakly-connected components.  Columns: _node, _component.
(.graph.connected (.graph.build t 'caller_function 'callee_function))
```

Available `.graph.*` ops: `build`, `info`, `free`, `pagerank`,
`degree`, `connected`, `topsort`, `dijkstra`, `shortest-path`,
`k-shortest`, `expand`, `var-expand`, `dfs`, `cluster`, `betweenness`,
`closeness`, `louvain`, `mst`, `random-walk`.

`.graph.info` returns a `DICT` (not a table) -- use it for sanity
checks on a handle (`(.graph.info G)` -> `{n_nodes: ... n_edges: ...
has_weights: ...}`) but pull values out with `(at info-dict 'key)`
before returning to an agent if you need a tabular result.

## Datalog rules and transitive closure

The store is `(datoms)` -- an EAV (entity / attribute / value) triple
store.  Facts are asserted with `assert-fact`, retracted with
`retract-fact`, and queried by pattern.  Rules let you derive
relations from base facts; recursive rules give you transitive
closure for free.

```rfl
;; Treat call_edges as datoms: (caller :calls callee).
(do
  (set Db (datoms))
  ;; In a real query you would loop over rows; this is the shape.
  (set Db (assert-fact Db 0 'calls 1))
  (set Db (assert-fact Db 1 'calls 2))
  (set Db (assert-fact Db 2 'calls 3))

  ;; Direct + transitive reachability.  The second clause closes
  ;; over the rule recursively, so `reaches` covers any path length.
  (rule (reaches ?a ?b) (?a :calls ?b))
  (rule (reaches ?a ?b) (?a :calls ?c) (reaches ?c ?b))

  ;; Functions reachable from caller 0 (3 in this example).
  (count (query Db (find ?b) (where (reaches 0 ?b)))))
```

Useful query shapes for raysense baselines:

- **Blast radius** -- recursive `reaches` rule, query starting from
  the target function id; result is the set of every function it
  transitively calls.  Equivalent to `raysense_blast_radius` but
  computed declaratively in Rayfall.
- **Cycle membership** -- `(reaches ?a ?a)` returns every function
  that reaches itself (i.e. is on at least one cycle).
- **Affected-by** -- bind the rule the other way (`(rule (affects ?a
  ?b) (?b :calls ?a))` plus the recursive arm) to enumerate what
  *uses* a target -- the inverse blast radius.

`_` is a wildcard that matches but does not bind.
`?name` is a logic variable.  Constants in object slots act as
filters: `(?e :calls 42)` matches only callers of function 42.

## Policy packs (`raysense_policy_check`)

Policies are `.rfl` files in `<repo>/.raysense/policies/`. Each one is
a Rayfall program that returns a `RAY_TABLE` of findings; raysense
walks the directory, evaluates every file, and reports per-policy
results. Unlike `raysense_baseline_query` (one table bound as `t`),
policy evaluation pre-binds **every** saved baseline table under its
own name -- the file can reference `files`, `functions`, `imports`,
`call_edges`, `module_edges`, etc. directly.

Required result shape: a table with the four columns

- `severity` -- one of `"info"`, `"warning"`, `"error"` (case-insensitive)
- `code`     -- short stable id, e.g. `"huge-file"` or `"layer-violation"`
- `path`     -- file or module the finding is about
- `message`  -- human-readable explanation

Empty result table = policy passed.

```rfl
;; .raysense/policies/no-huge-files.rfl
(select {severity: "warning"
         code:     "huge-file"
         path:     path
         message:  "file exceeds 2000 lines, consider splitting"
         from:     files
         where:    (> lines 2000)})

;; .raysense/policies/no-domain-imports-from-infra.rfl
;; Domain modules must not import from infra modules; infra is allowed
;; to depend on domain. Pure architectural rule, not an invariant of
;; the language. Evaluated against module_edges.
(select {severity: "error"
         code:     "layer-violation"
         path:     from_module
         message:  "domain layer imports from infra layer"
         from:     module_edges
         where:    (and (.starts-with from_module "domain.")
                        (.starts-with to_module   "infra."))})
```

When to use this vs `raysense_baseline_query`:
- One-off question? Use the query tool.
- Persistent rule the team wants to commit alongside the code? Drop
  it as an `.rfl` file under `.raysense/policies/` and run
  `raysense_policy_check` in CI.

## Result handling

- `RAY_TABLE` returns: rows are returned as JSON; the agent reports
  what it found and stops. Don't paginate Rayfall results -- if the
  result is too wide, narrow `where` or add `take`.
- Non-table return: surfaces as `RayfallResultNotTable` with the type
  tag. Wrap with `(select {from: t})` or project explicit columns.
- Parse / type / runtime errors: surfaces as `RayfallEval { code }`.
  Common codes: `parse` (bad syntax), `type` (wrong column type for
  the operator), `name` (unknown column or symbol).

## When to skip

- Use `raysense_baseline_table_read` for plain filter / sort / page
  with no joins or aggregations. It does not require Rayfall and is
  simpler for the agent to construct correctly.
- Use the typed tools (`raysense_hotspots`, `raysense_rules`, etc.)
  whenever they cover the question. Rayfall is for the long tail.
