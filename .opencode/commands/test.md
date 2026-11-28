---
description: Run the full S2 probe sequence for one (endpoint, vuln_class) pair
agent: orchestrator
---
Execute the per-class probe sequence for: $ARGUMENTS (format: <endpoint_key> <vuln_class>)

Walk S2 in order, no skips without an `n_a` justification in coverage:
1. baseline request (`send_http_request`, note carries the intent) — record status/length/shape
2. reflection & context detection (`extract_parameters(check_reflection=true)`)
3. error-based probes → 4. boolean pairs with `res_diff` → 5. time-based (limiter aware, tiny volume)
6. OOB-capable class → `oob_register` FIRST, `{OOB}` placeholders resolved at send, `oob_poll` after the sequence
7. on WAF block: `waf_fingerprint` → `waf_adapt` (boost stages from `_waf_matrix.json`) → `run_simple_fuzz` within the fuzz budget
8. minimal PoC confirm on any hit (`create_repeater_tab` for the operator); verdict per the four legal values; `coverage_update` + evidence refs.

Payloads come from `packs/payloads/<class>.json` in ladder order — complete means hit or exhausted. A blocked wall also gets `memory_save` + a targeted-recon note.
