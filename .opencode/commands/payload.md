---
description: Payload pack stats, next variants, WAF-adapted ladders
agent: orchestrator
---
Payload operations for: $ARGUMENTS

1. Empty → pack inventory from `packs/payloads/`: classes available, per-class hit/blocked stats from memory + coverage.
2. `next <class>` → next bypass-first variants from the pack (up to 5) with ladder-stage notes and the `_waf_matrix.json` boost for the last `waf_fingerprint` seen on this endpoint.
3. `mark <id> <result>` → `memory_save` the result and show updated class stats. Every attempt gets marked — marks are the program's WAF memory.
4. On persistent blocks: `waf_fingerprint` → `waf_adapt` → budgeted `waf_test_bypass` (probe/bypass budgets per host are hard caps).
