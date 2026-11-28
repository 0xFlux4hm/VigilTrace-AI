---
description: Resolve an approval gate (approve | deny | list)
agent: orchestrator
---
Resolve approvals for: $ARGUMENTS

1. Empty or `list` → print pending `request_approval` records (id, action, justification, age).
2. `approve <id> <operator_reference>` → `mission_control(action="approve", approval_id=..., operator_reference=...)` — print which gate it unlocks (Tier-3 invasive action, budget change, account provisioning).
3. `deny <id> <reason>` → resolve with deny; the requesting task receives the block and reroutes per the obedience policy (alternate tool → alternate technique → continue other sequences).
4. Approvals are the only lawful way past a Tier-3 gate. Never work around one; budget caps change only via `mission_control(action="budget", budget=..., operator_reference=...)`.
