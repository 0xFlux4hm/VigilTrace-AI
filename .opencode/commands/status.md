---
description: Full mission status readout (phase gates, coverage, tamper stats, budgets)
agent: orchestrator
---
Run `mission_status` (all sections), `sequence_next`, `budget_status`, `closure_check` (advisory mode) and summarize in at most 20 lines:

- Phase + next legal step (from `sequence_next`) and its gate readout
- Recon debt: untriaged count — RED if > 0; saturation flag
- Coverage: endpoints registered, tested/vulnerable/untested by class; top 3 gaps (`coverage_gaps`)
- Tamper ledger: probes spent, signals by class (data_cross / state_change / behavior_change / rejected / noise), pending canary confirmations
- Findings by severity + validation verdicts; pinned tasks open/blocked
- Budgets: rows with pct + verdict; egress = bridge rate limit state; OOB: live unpolled registrations
- One recommended next action

$ARGUMENTS may carry a focus filter ("tamper only", "coverage only") — trim the readout, do not skip the engine calls.
