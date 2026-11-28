---
description: Observation readout — tamper diffs, signals vs noise, hidden param mining
agent: orchestrator
---
Observation operations for: $ARGUMENTS (diff | signals | discover <source> | pending)

- `diff <source_a> <source_b>` → `res_diff` normalized readout: status/field deltas, volatile fields excluded, signal + attribution.
- `signals` → all tamper signals by class with attribution and confidence; flag anything still `low` (repeat-once rule pending).
- `discover <source>` → `param_discover(source, note=...)` hidden-param mining; hits feed `tamper_matrix_build`.
- `pending` → canary confirmations and diff-analyst reviews still owed, with ages.
- Empty args → `signals` + `pending`.

Every nontrivial or uncertain diff goes to the `diff-analyst` subagent before a verdict is written.
