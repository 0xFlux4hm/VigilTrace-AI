---
description: Layer 12 tamper run — matrix, baseline, one-variable ladder, observe every change
agent: orchestrator
---
Execute the Layer 12 tamper flow for: $ARGUMENTS (format: `<endpoint_key>` to build the matrix, or `<source_ref> <param>` to run the ladder on one parameter)

1. Verify the endpoint is authorized (`get_scope`). Refused → flag and stop, zero packets.
2. Bare endpoint form → `tamper_matrix_build(source)` — print the per-class matrix, probe counts, budget state; recommend the highest-value class first (identity on object-bearing endpoints, authz on role-bearing).
3. Parameter form → run the loop per `skills/param_tampering.md` (load it first):
   a. `param_tamper_run(source, param, tamper_class, note=...)` — baseline first, ONE variable per probe, `res_diff` classification after EVERY probe, repeat-once confirm on hits/rejects
   b. `data_cross` / `state_change` → design the canary confirmation (ATAP account A's session, account B's object) and run it
   c. uncertain diffs → `diff-analyst` subagent before writing any verdict
   d. verdict per the four legal values; probes land in tamper.json with attribution
4. End with: signals by class, verdicts updated, budget remaining, canary confirmations owed.
