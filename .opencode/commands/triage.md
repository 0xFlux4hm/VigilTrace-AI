---
description: Triage endpoints (live/auth state, param classification, scores)
agent: orchestrator
---
Triage: $ARGUMENTS (endpoint key, or "all" for the debt queue)

1. For each endpoint: determine live/parked, auth context (anon/user/admin from proxy history evidence), tech fingerprint.
2. `extract_parameters(source, include_cookies=true, include_headers=true, deep_json=true, check_reflection=true)` — record which params are identity/authz/value/state candidates for the Layer 12 tamper matrix.
3. Recompute coverage cell notes with `coverage_update`; spawn `recon-triage` for batches > 5.
4. End with: remaining debt count, oldest debt age, and the next debt item. While debt > 0, no progress claims.
