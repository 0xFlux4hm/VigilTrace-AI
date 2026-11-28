---
description: Governed recon on a target (proxy history first, passive OSINT, registration)
agent: orchestrator
---
Run governed recon for: $ARGUMENTS

1. Verify the target is inside an authorized prefix (`get_scope`); refused → flag and stop, zero packets.
2. Proxy history first: `get_proxy_history` broad (limit 30) → narrow by `url_contains` — extract sessions, roles, endpoints, parameter names the human already touched. Zero packets spent.
3. Passive OSINT: dork packs from `packs/dorks/` via websearch (passive-only; secrets → report-only findings).
4. Register everything discovered: `coverage_update` per endpoint with auth context; `extract_parameters(check_reflection=true, deep_json=true)` so Layer 12 gets a real tamper matrix; `memory_save` for quirks/intel.
5. Spawn the `recon-triage` subagent for scoring/triage of large batches. Close with: novelty counters, debt count, saturation verdict.
