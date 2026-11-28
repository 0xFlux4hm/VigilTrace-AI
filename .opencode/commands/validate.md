---
description: Validate findings (validator subagent) — PoC re-runs, FP kills, closure sign-off
agent: orchestrator
---
Validation operations for: $ARGUMENTS (finding id, "closure <endpoint>", or empty = queue)

1. Finding form → spawn the `validator` subagent (fresh child session) with the finding's evidence: it re-runs the PoC independently, runs the self-FP pass, and returns `CONFIRMED / NEEDS_MORE_EVIDENCE / FALSE_POSITIVE`.
2. Feed its verdict into `validate_finding(finding_id, verdict, notes)` — score ≥90 validated, 60–89 auto-enqueues a kill-test task, <60 watchlist (never raised). Local duplicates never raise twice.
3. `closure <endpoint>` → `closure_check(asset, strict=true)`; hand the result to the validator for sign-off. Any probe it names as missing reopens the asset.
4. Validated high+ findings become `raise_issue` candidates — never before validation.
