---
description: Emergency stop — pause hard, stop packets, final OOB poll, handoff
agent: orchestrator
---
Abort the session. Reason: $ARGUMENTS

1. `mission_control(action="pause", hard=true)` (or the engine's abort path) — after this, NO new requests to any target, no exceptions.
2. Stop all in-flight work; do not start new probes, ladders or tamper runs.
3. Final OOB sweep: `oob_poll` over all live registrations so no callback expires unobserved; record correlations.
4. Write the handoff into memory (`memory_save`: state, coverage, findings, walls, pinned tasks, pending approvals, next steps) and print a one-paragraph summary. State lives in the engagement dir — a fresh session resumes from the files alone.
5. Resume later: `/mission` with the same authorization, then `mission_control(action="resume")`.
