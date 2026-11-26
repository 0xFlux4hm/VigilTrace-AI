# Architecture

## Layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│ agent (docs/01-system-prompt.md: control loop, budgets, safety rules)    │
└───────────────▲──────────────────────────────────────────────────────────┘
                │ stdio MCP (envelope {ok,data}/{ok,error,hint})
┌───────────────┴──────────────────────────────────────────────────────────┐
│ aobh.tools: FastMCP server → registry.dispatch (48 tools, tools.json)    │
│                     │                                                    │
│             ┌───────┴──────────────────────────────────────────────┐     │
│             │ aobh.core: config · bridge client · authz gate · utils│    │
│             └───────┬──────────────────────────────────────────────┘     │
└─────────────────────┼────────────────────────────────────────────────────┘
        │                            │
   burp_bridge (15)        local engines (33 tools)
        │                            │
┌───────┴──────────┐  ┌──────────────┼───────────────────┬─────────────────┐
│ extension/ (Java)│  │ orchestrator │ rag               │ atap / waf /    │
│ BridgeServer     │  │ mission·DAG  │ chunk·embed·store │ recaptcha       │
│ ScopeGuard       │  │ triggers·cov │ retrieve·dedup    │ vault·sessions  │
│ RateLimiter      │  │ budget·appro │ ingest            │ fingerprints·   │
│ TrafficCounters  │  │ memory·phase │ 15,219 reports    │ transforms·     │
│ ToolRegistry     │  │ validator    │                   │ solver policies │
│ MontoyaGateway   │  └──────────────┴───────────────────┴─────────────────┘
└──────────────────┘         engagement dir (JSON docs + JSONL audit trails)
```

## The three perimeters

1. **Agent perimeter (Python, new):** `aobh.core.authz` — scope registry with provenance, prefix-boundary matching (no wildcard magic), exclusions that always win, fail-closed on empty/corrupt state, tier-3 gating. `BridgeGuard` wraps every target send.
2. **Bridge perimeter (Java, enforcement):** every request passes `ScopeGuard.assertInScope` → `RateLimiter.acquire` → `TrafficCounters.recordSend` → Burp. Refusals are counted (`rejected_out_of_scope` / `rejected_other`); sent attempts always count (`requests_sent`, incremented before Burp is called). `/health` exposes the counters and an `instance` id.
3. **State perimeter:** everything the orchestrator decides lives in the engagement dir as plain JSON documents + JSONL audit trails (atomic writes, resumable by a fresh process).

## Wire contract (bridge)

`GET /health` (3s) · `GET /tools` (5s) · `POST /tools/{name}` (300s); `Authorization: Bearer <token>` everywhere; no CORS, `Origin`/non-local-`Host` refused 403, 401 otherwise, 16 MiB body cap, keep-alive + chunked supported. Envelope: `{"ok": true, "data": …}` / `{"ok": false, "error": "<code>", "hint": "…"}`. Full detail: `docs/bridge-protocol.md`.

## Tool surface (48)

| Group | Count | Notes |
|---|---|---|
| `burp_bridge` | 15 | proxied to the Java extension; the only group that touches targets |
| `mission_control` | 14 | mission, tasks, coverage, events, memory, budget, approvals, validate_finding |
| `rag` | 4 | query / find-similar / pattern stats / playbook over the disclosed corpus |
| `atap` | 8 | policy check, create/verify account, login, sessions, health, list, cleanup |
| `waf` | 4 | fingerprint, probe battery, adapt/transforms, bypass tester |
| `captcha` | 3 | detect, sanctioned solver strategies, validation-bypass tester |

Folded tools (5 of the old 53) keep their capability inside survivors — see `meta.folding` in `aobh/tools/tools.json` and `docs/02-tools.md`.

## Key flows

- **Hypothesis → proof:** `rag_playbook` → `send_http_request` / `modify_and_resend_request` / `run_simple_fuzz` (counted, annotated, optional `{{P}}` Collaborator tokens) → `validate_finding` (kill-test plan, 0–100 evidence score, triage, local dedup, corpus precedents) → `raise_issue` (evidence required for high+).
- **Account lifecycle:** `atap_policy_check` → `atap_create_account` → `atap_verify_account` (mail link via IMAP strategy or the built-in SMTP catcher) → `atap_login` → `atap_get_session` → `atap_account_health` → `atap_cleanup` (close-out), all under the vault's scrypt+HMAC-CTR encryption.
- **Defense feedback:** `waf_fingerprint` / `waf_probe` / `waf_adapt` / `waf_test_bypass` and `captcha_detect` / `captcha_solve` / `captcha_test_bypass` write per-engagement budget state and emit `waf_block` / `captcha_challenge` events the trigger engine turns into tasks.
