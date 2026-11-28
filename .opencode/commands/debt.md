---
description: Recon debt queue — untriaged endpoints blocking progress claims
agent: orchestrator
---
Report and clear recon debt for: $ARGUMENTS

1. List untriaged coverage endpoints with age (from coverage + memory notes).
2. Triage the oldest first (spawn `recon-triage` for batches > 5): live/parked, auth context, param classification.
3. Recompute and print remaining debt + the KPI (triaged testable surface per hour — raw discovery count is vanity).
4. Repeat the hard rule in the output: while debt > 0, no progress claims — `sequence_next` gates on it.
