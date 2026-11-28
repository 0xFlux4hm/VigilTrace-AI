# aobh — Autonomous Orchestrated Bug Hunter

**AUTHORIZED SECURITY TESTING ONLY** — wire this up only for targets covered by a bug bounty program scope or a signed pentest contract.

An MCP server exposes **56 tools** in eight groups over stdio. Five local Python engines do the orchestration and analysis; a Burp Suite Montoya extension carries every target-facing request so scope, rate limits, counters and audit notes are enforced in Burp itself — and a Python-side authorization gate (`aobh.core.authz`) refuses anything the engagement doesn't cover before it even reaches the bridge.

```
agent (.opencode/agents/orchestrator.md) ──stdio MCP── aobh.tools.server (56 tools)
                        │
     burp_bridge 15 → Burp "AI Agent Bridge" extension (extension/, Java 17)
     mission_control 16 → orchestrator (DAG, coverage, budget, approvals, validator)
                          + Layer 11 gates (sequence_next, closure_check)
     rag 4 → disclosed-report corpus (15,219 HackerOne reports)
     atap 8 → account vault + registrar/verifier + session leases (canary accounts)
     waf 4 → fingerprint / probe battery / transforms / bypass tester
     captcha 3 → detection + sanctioned solver strategies
     tamper 4 → Layer 12: tamper matrix / one-variable runs / res_diff / param discovery
     oob 2 → out-of-band registration + polling with TTL + closure-gate bookkeeping
```

## Repo map

| Path | What it is |
|---|---|
| `aobh/tools/tools.json` | The 56-tool manifest — single source of truth (names, groups, schemas, folding map) |
| `aobh/tools/server.py` | FastMCP stdio server; every call funnels through `registry.dispatch` |
| `aobh/tools/cli.py` | `aobh serve|list-tools|ingest|smoke|doctor` |
| `aobh/core/` | config (env-first), bridge client, **authorization gate**, shared utils |
| `aobh/orchestrator/` | mission lifecycle: DAG queue, triggers, coverage, memory, budget, approvals, phases, adversarial validator |
| `aobh/rag/` | ingest, chunk, embed, retrieve, dedup + the bundled corpus |
| `aobh/atap/` | encrypted vault (scrypt+HMAC-CTR), registrar/verifier, session leases, mailcatch |
| `aobh/waf/`, `aobh/recaptcha/` | WAF fingerprint/probe/transform/bypass; CAPTCHA detection + sanctioned strategies only |
| `extension/` | the Burp extension (build.py = verified path; pom.xml for Maven users) |
| `.opencode/` + `opencode.json` + `AGENTS.md` | the OpenCode runtime: orchestrator + 3 subagents, 16 operator commands, V2 config, session rules |
| `packs/` | Layer 9 + Layer 12 payload ladders (`_ladders.json`, `_waf_matrix.json`, `access_control.json`), OSINT dorks, wordlists |
| `skills/` | doctrine documents tracked by the skill ledger (`param_tampering.md` = Layer 12 law) |
| `docs/` | 01 system prompt · 02 tool index (generated) · 03 implementation notes · 04 architecture · bridge protocol · **IMPLEMENTATION.md** (runtime, sequences, OOB infra, Layer 12 pipeline) |
| `examples/` | sample mission brief + **full Layer 6–12 mission template** + scope authorization file |
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
   aobh list-tools                  # the 56-tool surface
   aobh doctor                      # config (redacted) + bridge health
   ```
4. **Attach the agent and start the mission loop.** Two ways:
   - **OpenCode (recommended):** `cd` here and run `opencode` — `opencode.json` starts
     the `aobh` MCP server and the orchestrator agent automatically. Drive with the
     slash commands: `/mission examples/mission.template.json` → `/status` → `/recon`
     → `/test` → `/tamper` → `/observe` → `/validate` → `/report`.
   - **Any MCP client:** attach `docs/01-system-prompt.md`, register `aobh serve`, and
     run `mission_init(target, authorization_reference)` → `task_next` loop →
     `validate_finding` → `raise_issue`. Authorize prefixes explicitly:
     `add_to_scope(url_prefix, added_from="scope.md line N")` against `examples/scope.example.md`.

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
