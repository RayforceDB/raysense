---
description: Answer a custom structural question against the saved baseline using Rayfall (select / .graph.* / Datalog).
argument-hint: <project-path> <question…>
---

Answer the following structural question against the raysense baseline at `$1`:

> $2

The first argument is the project path; everything after it is the question. If the project path is missing, treat it as the current working directory and the entire `$ARGUMENTS` as the question.

1. Call `raysense_baseline_tables` with `path: $1` to see the available tables and their columns.
2. Decide the query shape:
   - **Select** (filter / project / aggregate) — for "files where X and Y" style questions.
   - **Graph algorithm** (`.graph.pagerank`, `.graph.louvain`, `.graph.topsort`, `.graph.shortest_path`, `.graph.k_shortest`, `.graph.betweenness`, `.graph.closeness`, `.graph.bfs`, `.graph.mst`) — for centrality, clustering, or reachability.
   - **Datalog** (transitive closure: `reaches`, `depends-on`, `tainted-by`) — for declarative reachability.
3. Call `raysense_baseline_query` with `path: $1` and the chosen Rayfall expression.

Show the query you ran, then the result, then a one-line interpretation.
