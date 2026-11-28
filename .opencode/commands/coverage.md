---
description: Coverage ledger readout + next untested (endpoint, class) target
agent: orchestrator
---
Coverage operations for: $ARGUMENTS

1. `mission_status` coverage section + `coverage_gaps` (ranked untested cells: class weight + endpoint weight).
2. Show the next 3 (endpoint, vuln_class) pairs with the reason for each.
3. Unless $ARGUMENTS says otherwise ("dry" = plan only), immediately begin S2 on the #1 pair: baseline → reflection → error → boolean (`res_diff`) → time → OOB (`oob_register` first if applicable) → bypass (`waf_fingerprint`/`waf_adapt`) → minimal PoC (`create_repeater_tab`).
4. Every outcome → `coverage_update`; walls → `memory_save` + targeted recon note.
