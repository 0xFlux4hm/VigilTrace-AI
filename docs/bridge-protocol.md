# Bridge protocol (Burp "AI Agent Bridge" extension)

The extension (Java 17, Montoya API 2026.7) serves HTTP on the loopback interface and is the **only** path target-facing traffic may take. This document is the contract the Python client (`aobh/core/bridge.py`) and the self-test (`extension/src/main/java/dev/agent/burp/selftest/`) both implement.

## Endpoints

| Method | Path | Timeout | Response |
|---|---|---|---|
| GET | `/health` | 3s | `{"ok": true, "instance": "...", "tools": 15, "requests_sent": N, "fuzz_requests": N, "rejected_out_of_scope": N, "rejected_other": N, ...}` |
| GET | `/tools` | 5s | `{"tools": [ {name, description, inputSchema, returns, example}, × 15 ]}` |
| POST | `/tools/{name}` | 300s | `{"ok": true, "data": ...}` or `{"ok": false, "error": "<code>", "hint": "..."}` |

`/tools/{name}` serves exactly the 15 tools listed in `aobh/tools/tools.json → meta.bridge.tool_names`; the packaged resource is generated from that manifest at build time and the SelfTest parity-checks served names/order/descriptions/schemas against it.

## Auth and origin policy

- `Authorization: Bearer <token>` required on every endpoint; 401 with an error envelope otherwise. The bridge refuses to start serving unless a token is configured (≥16 chars via the UI's Generate or `BURP_BRIDGE_TOKEN`).
- Requests carrying an `Origin` header or a non-local `Host` are refused 403 — no browser page may drive the bridge.
- No CORS headers are ever sent.
- Request body cap: 16 MiB. Keep-alive and chunked transfer are supported.

## Envelope semantics

- Tool-level failures come back **HTTP 200 with `{"ok": false, "error", "hint"}`** — clients must return them, not raise.
- Transport/auth/protocol problems (connection refused, 401, non-JSON, unexpected status) raise client-side `BridgeError(error, hint)`; codes used by the Python client: `bridge unreachable`, `unauthorized`, `bridge rejected request: <code>`.
- Out-of-scope sends are refused with `error: "out_of_scope"` (hint names the reason: "explicitly excluded" / "not covered by registry") and counted in `rejected_out_of_scope`. Other refusals (host mismatch, bad request) count in `rejected_other`.

## Counters (budget reconciliation)

- `requests_sent` and `fuzz_requests` increment **before** Burp sends — refusals never reduce spend, and a counted send is always a real send.
- `/health.instance` changes on every Burp/extension restart (counters reset). The budget governor reconciles agent-reported numbers with bridge-measured ones when the bridge is reachable; it does not yet baseline per instance (known limitation, `docs/03-implementation-notes.md`).

## The 15 tools

`get_proxy_history`, `get_site_map`, `search_history`, `extract_parameters`, `send_http_request`, `modify_and_resend_request`, `get_response`, `create_repeater_tab`, `get_scope`, `add_to_scope`, `remove_from_scope`, `run_simple_fuzz`, `get_collaborator_payload`, `poll_collaborator`, `raise_issue`.

Notes: `send_http_request` accepts `{{P}}` Collaborator payload tokens (collaborator round-trips: `get_collaborator_payload` → poll with `poll_collaborator`); `add_to_scope`/`remove_from_scope` maintain BOTH Burp's scope and the agent registry with provenance (`added_from`), and removal excludes fail-closed (exclusions are checked before registry coverage; the registry entry stays as provenance unless `drop_from_registry=true`).

## Building and self-testing without Burp

```bash
python3 extension/build.py --test --jdk <jdk17> --api-jar <montoya-api.jar> --test-java /usr/bin/java
```
runs the raw-socket SelfTest in 4 modes (classes ± API jar, system java, packaged jar) covering auth, origin/Host policy, counters, scope rules, every tool handler against a fake Montoya gateway, keep-alive/chunked framing and manifest parity. A `pom.xml` is provided for Maven workflows, but **build.py is the verified path** (a Maven-built jar lacks the generated manifest resource).
