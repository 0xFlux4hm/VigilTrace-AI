---
description: Initialize or switch the active mission (scope, policy, budgets, canary accounts)
agent: orchestrator
---
Load or initialize the mission for: $ARGUMENTS

1. If `$ARGUMENTS` is a path to a mission JSON → read it and run `mission_init(target, authorization_reference, program_url)` with its values; otherwise construct the arguments from the program information already in this conversation, using `examples/mission.template.json` as the policy shape. Missing values stay clearly-marked CHANGEME placeholders — do not invent scope or authorization.
2. Read the scope file (`examples/scope.example.md` shape) and authorize prefixes explicitly: `add_to_scope(url_prefix, added_from="scope.md line N")` for each entry.
3. Print the readiness readout: mission id + phase, authorized prefixes, budgets (`budget_status`), tamper policy (baseline/one-variable/canary requirements), OOB readiness, ATAP account policy.
4. Run `sequence_next` and state the next legal step. No recon or testing until scope entries are real — if scope is placeholder-only, stop here and name what is missing.
5. Pause/resume support: `mission_control(action="pause"|"resume")` with the operator's reason.
