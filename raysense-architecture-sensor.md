<!--
  Copyright (c) 2025-2026 Anton Kundenko <singaraiona@gmail.com>
  All rights reserved.

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
-->

# Raysense: Real-Time Architectural Sensor for AI Agents

## Thesis

Raysense is a local, real-time architectural memory for AI coding sessions.
Every file change, dependency edge, function metric, rule violation, test gap,
agent action, and quality score becomes queryable telemetry.

The goal is not a static dashboard. The goal is a control surface that can
answer:

```text
what changed?
what architectural risk did it create?
which next edit is most likely to improve the structure without increasing blast radius?
```

Rayforce provides the analytical core: embeddable C, columnar tables, graph
algorithms, Datalog, vector search, IPC, and fast local execution.

## Product Shape

Raysense has three cooperating layers:

```text
collector     -> turns code and events into normalized facts
ray memory    -> Rayforce tables, graph relations, and derived signals
agent surface -> commands, subscriptions, guardrails, and UI overlays
```

The collector is owned by this repository. It should be self-contained and
adapted for incremental architectural sensing rather than general static
analysis.

The ray memory embeds Rayforce directly through a thin FFI layer, or runs a
Rayforce sidecar over IPC during early iteration. Direct embedding is better
for the product; IPC is acceptable for a first prototype.

The agent surface should be event-oriented. It should support current state,
delta queries, reverse dependency slices, risk checks, and ranked corrective
actions.

## Core Data Model

Store scans and edits as append-only facts.

### Tables

```text
snapshots(snapshot_id, ts, root, git_sha, quality_signal)
files(snapshot_id, file_id, path, lang, lines, bytes, module, hash)
functions(snapshot_id, func_id, file_id, name, start_line, end_line, cc, cog, params, body_hash)
imports(snapshot_id, from_file, to_file, kind, resolved)
calls(snapshot_id, from_func, to_func, from_file, to_file, resolved)
inherits(snapshot_id, from_type, to_type, from_file, to_file)
entry_points(snapshot_id, file_id, kind, symbol)
rules(snapshot_id, rule_id, severity, path, message)
tests(snapshot_id, test_id, file_id, target_file_id, kind, status)
events(event_id, ts, kind, path, adds, dels, agent_id, session_id)
agent_actions(action_id, ts, session_id, prompt_hash, tool, files_touched)
embeddings(snapshot_id, entity_kind, entity_id, vector)
```

### Derived Relations

```text
depends_on(A, B)
reaches(A, B)
cycle_member(file)
blast_radius(file, count)
module_boundary_violation(from_file, to_file)
dead_function(func)
duplicate_function(func_a, func_b)
semantic_neighbor(entity_a, entity_b, distance)
regression_cause(event_id, root_cause, delta)
```

Derived relations should come from Rayforce graph traversal, Datalog rules, and
regular columnar queries.

## Agent API

### Sensor Tools

```text
observe(path)                     start watching and ingest current snapshot
stream_events(session_id)          subscribe to file, score, rule, and graph deltas
health()                          current score and root-cause breakdown
delta(since_snapshot | session)    what changed structurally
explain_drop(delta_id)             likely causes of degradation
```

### Decision Tools

```text
next_best_actions(limit)           ranked refactor candidates
what_if(action)                    simulate graph or metric impact
rank_moves(files, target_modules)  score file moves before editing
guard_patch(diff)                  predict architecture risk before applying
find_context(goal, budget)         context-window optimizer for agent prompts
```

### Memory Tools

```text
similar_code(entity, k)            vector or code similarity
why_exists(path | function)        provenance across history, tests, deps, and rules
who_depends_on(path)               reverse dependency slice
contract(path)                     inferred module constraints and public surface
```

Recommendations should be structured commands, not prose only:

```json
{
  "objective": "improve_modularity",
  "expected_delta": 183,
  "confidence": 0.74,
  "actions": [
    {
      "kind": "move_file",
      "from": "src/app/payment_utils.ts",
      "to": "src/payments/utils.ts",
      "reason": "reduces 7 cross-module edges"
    },
    {
      "kind": "remove_import",
      "from": "src/ui/Form.tsx",
      "to": "src/db/client.ts",
      "reason": "breaks upward dependency"
    }
  ]
}
```

## Feedback Loop

Raysense should run a control loop during agent sessions:

```text
1. Save baseline.
2. Watch file events.
3. Incrementally rescan touched regions.
4. Append facts into Rayforce tables.
5. Recompute affected derived relations.
6. Emit score deltas and ranked corrective actions.
7. Let the agent apply a correction.
8. Verify convergence.
```

The loop catches architectural damage while the agent still has relevant
editing context.

## MVP

Build the first version as a small Rust binary in this repository:

```text
raysense observe <path>
```

Implementation sequence:

1. Keep the repository self-contained.
2. Implement an owned scanner and fact model.
3. Start with full rescans after debounce.
4. Add a `rayforce-sys` FFI crate around `include/rayforce.h`.
5. Convert facts into Rayforce tables: files, imports, calls, and functions.
6. Add commands: `observe`, `health`, `delta`, `what_if`, `next_best_actions`.
7. Add Rayfall scripts for candidate ranking before implementing native queries.
8. Add vector search only after the graph and time-series loop is stable.

The first useful demo:

```text
Agent starts session.
Raysense baseline: quality 7342.
Agent edits 4 files.
Raysense detects modularity -211 and one new cycle.
Agent calls next_best_actions.
Raysense proposes removing or moving one dependency.
Agent applies fix.
Raysense verifies quality 7418 and no cycle.
```

## Technical Risks

- Rust-to-C ownership has to be strict. Wrap `ray_t*` in safe RAII types and
  never expose raw ownership to scanner code.
- Rayforce global symbol and environment state needs clear synchronization if
  scanner and request handlers are concurrent.
- Full rescans are fine for MVP, but the product promise needs incremental
  invalidation by file hash, dependency edge, and function body hash.
- The score must not become the only objective. Agents need constraints:
  preserve behavior, do not delete reachable code without test evidence, and
  keep public APIs stable unless requested.
- Vector search is useful, but graph facts and test evidence should dominate
  architecture decisions.

## Positioning

```text
Raysense is a local architectural nervous system for AI coding agents.
It observes every edit, models code structure as live facts, and recommends
the next correction before architectural drift compounds.
```
