---
description: Draft the mission report (validated findings only, compliance tables included)
agent: orchestrator
---
Draft the report for: $ARGUMENTS (empty = all validated findings)

1. Gather VALIDATED findings only (`validate_finding` verdicts) — never draft hypotheses or watchlist items.
2. Per-finding sections: **Title → Severity (+rationale) → Asset → Summary → Impact (in the program's own terms: data, users, money) → Reproduction (exact, re-runnable) → Evidence (request/response excerpts with bridge audit notes, callback logs for OOB, tamper field-diffs for access control) → Remediation.**
3. MUST include:
   - the **Coverage Matrix**: endpoint × vuln class × verdict × evidence count (`mission_status` coverage section)
   - the **Tamper Ledger appendix**: tamper class → probes → signals → outcomes (proves access-control testing was systematic, not lucky)
   - the **Directive Compliance table**: every operator directive → disposition (completed/blocked) → evidence
   - an ordered submission checklist (what the operator must verify/attach before sending)
4. Severity matches evidence, never ambition. Canary-account evidence only; third-party data stays summarized. Unknown details stay visible as `[unknown: ...]` — never smoothed over. Save the draft to `reports/report-<program>-<date>.md`.
