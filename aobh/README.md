# aobh — Autonomous Orchestrated Bug Hunter

**AUTHORIZED SECURITY TESTING ONLY** — wire this up only for targets covered by a bug bounty program scope or a signed pentest contract.

An MCP server exposes **48 tools** in six groups over stdio. Four local Python engines do the orchestration and analysis; a Burp Suite Montoya extension carries every target-facing request so scope, rate limits, counters and audit notes are enforced in Burp itself — and a Python-side authorization gate (`aobh.core.authz`) refuses anything the engagement doesn't cover before it even reaches the bridge.

```
agent (docs/01-system-prompt.md) ──stdio MCP── aobh.tools.server (48 tools)
                        │
     burp_bridge 15 → Burp "AI Agent Bridge" extension (extension/, Java 17)
     mission_control 14 → orchestrator (DAG, coverage, budget, approvals, validator)
     rag 4 → disclosed-report corpus (15,219 HackerOne reports)
     atap 8 → account vault + registrar/verifier + session leases
     waf 4 → fingerprint / probe battery / transforms / bypass tester
     captcha 3 → detection + sanctioned solver strategies
```

## Repo map

| Path | What it is |
|---|---|
| `aobh/tools/tools.json` | The 48-tool manifest — single source of truth (names, groups, schemas, folding map) |
| `aobh/tools/server.py` | FastMCP stdio server; every call funnels through `registry.dispatch` |
| `aobh/tools/cli.py` | `aobh serve|list-tools|ingest|smoke|doctor` |
| `aobh/core/` | config (env-first), bridge client, **authorization gate**, shared utils |
| `aobh/orchestrator/` | mission lifecycle: DAG queue, triggers, coverage, memory, budget, approvals, phases, adversarial validator |
| `aobh/rag/` | ingest, chunk, embed, retrieve, dedup + the bundled corpus |
| `aobh/atap/` | encrypted vault (scrypt+HMAC-CTR), registrar/verifier, session leases, mailcatch |
| `aobh/waf/`, `aobh/recaptcha/` | WAF fingerprint/probe/transform/bypass; CAPTCHA detection + sanctioned strategies only |
| `extension/` | the Burp extension (build.py = verified path; pom.xml for Maven users) |
| `docs/` | 01 system prompt · 02 tool index (generated) · 03 implementation notes · 04 architecture · bridge protocol |
| `examples/` | sample mission brief + scope authorization file |
| `scripts/` | gen_docs, ingest, smoke |
| `tests/` | pytest suite (33 tests; the ported harnesses carry 163 in-suite checks) |

## Quickstart

```bash
make install                      # pip install -e ".[dev]"
make build-extension              # JDK17: python3 extension/build.py --test  → 69/70-check self-test in 4 modes
make docs && make ingest          # regenerate docs/02-tools.md, rebuild the RAG index
make smoke                        # offline end-to-end smoke (no Burp needed)
```

1. **Load the jar in Burp**: Extensions → add `extension/build/burp-agent-bridge.jar` → *AI Agent Bridge* tab → **Generate token** (≥16 chars) → **Apply and restart bridge**. Without a token the bridge stays off.
2. **Configure the environment** (`cp .env.example .env`): `BURP_BRIDGE_URL`, `BURP_BRIDGE_TOKEN`, `ATAP_ENGAGEMENT_DIR`, budgets, optional solver-service key (unset = human strategies only).
3. **Run the server**:
   ```bash
   aobh serve                       # stdio MCP; register as "aobh" in your MCP client
   aobh list-tools                  # the 48-tool surface
   aobh doctor                      # config (redacted) + bridge health
   ```
4. **Attach the agent prompt** (`docs/01-system-prompt.md`) and start the mission loop: `mission_init(target, authorization_reference)` → `task_next` loop → `validate_finding` → `raise_issue`. Authorize prefixes explicitly: `add_to_scope(url_prefix, added_from="scope.md line N")` against `examples/scope.example.md`.

## Tests

```bash
make test                         # 34 pytest tests (orchestrator 93, atap 35, waf+captcha 41 checks,
                                  #  cross-language bridge e2e — real Java server vs real Python client)
python3 extension/build.py --test # extension self-test, 4 modes, no Burp needed
java -jar extension/build/burp-agent-bridge.jar --serve --port 8799 --token <16+ chars>
                                  # run the bridge outside Burp (fake gateway) for the e2e/dev loop
```

## Boundaries enforced in code

- **Scope is law, twice:** the Python gate refuses unauthorized sends before the Java ScopeGuard re-checks them; exclusions always win; corrupt state authorizes nothing.
- Tier-3 (invasive) actions need an APPROVED `request_approval` record; budget caps are operator-only; probe/bypass budgets (`WAF_PROBE_MAX`, `WAF_BYPASS_MAX`) are per-engagement.
- No CAPTCHA/anti-bot circumvention, no IP rotation, no TLS fingerprint mutation, no rate-limit evasion — anywhere.
- Accounts ≤3 per target, credentials encrypted at rest, disclosed + cleaned up at close-out (`atap_cleanup`).

The RAG dataset is public disclosure data (attribution + license: `aobh/rag/data/SOURCE.md`). MIT license — see `LICENSE` for the authorized-testing notice.
