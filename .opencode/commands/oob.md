---
description: OOB operations — register, poll, status (Burp Collaborator via the bridge)
agent: orchestrator
---
OOB operations for: $ARGUMENTS (register | poll [payload_id] | status)

- `register` → `oob_register(count, ttl_minutes, note=...)`; print payloads, expiry, and the reminder: register BEFORE the first payload of any OOB-capable class (SSRF/RCE/XXE/JNDI/deserialization).
- `poll [payload_id]` → `oob_poll` — link each interaction back to the probe that planted it; state plainly whether any blind finding may now be claimed.
- `status` → live registrations, unpolled probes, time to expiry (read from the engagement's oob.json).
- Empty args → status + the standing rules: no blind claim without a callback; final poll before closure (`closure_check` condition 3).
