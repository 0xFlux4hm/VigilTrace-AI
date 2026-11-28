# IMPLEMENTATION.md — runtime, sequences, OOB infra, Layer 12 pipeline

This document is the implementation companion to `docs/01-system-prompt.md` (agent
doctrine), `docs/02-tools.md` (generated 56-tool index), `docs/03-implementation-notes.md`
and `docs/bridge-protocol.md`. It covers the four systems that make the doctrine
mechanical: the OpenCode runtime layer, the sequence/closure gates, the out-of-band
channel, and the Layer 12 parameter-tamper pipeline.

## 1. OpenCode runtime layer (`.opencode/` + `opencode.json` + `AGENTS.md`)

The agent side runs on OpenCode (V2 config schema):

- `opencode.json` — `default_agent: orchestrator`; `aobh` MCP server via
  `python3 -m aobh.tools.server` (stdio) with `ATAP_ENGAGEMENT_DIR` wired; provider
  `zai/glm-4.6` through `@opencode/ai/providers/openai-compatible` (`ZAI_API_KEY`),
  switchable to any Anthropic model by editing `"model"`.
- Permissions are **ordered rules with last-match-wins semantics**: broad allows first,
  destructive shell denies last. The same shape appears in every agent frontmatter —
  the orchestrator denies shell/edit entirely (mission actions only through MCP tools,
  so every action lands in `run_log.jsonl`).
- `.opencode/agents/` — `orchestrator` (primary) + `validator`, `recon-triage`,
  `diff-analyst` (subagents; fresh child sessions, their own permission sets).
- `.opencode/commands/` — 16 operator commands: mission · status · scope · recon ·
  triage · debt · coverage · test · tamper · observe · payload · oob · validate ·
  approve · abort · report.
- `AGENTS.md` — project rules auto-loaded into every session (law ladder, hard gates,
  sequences, obedience mechanics).

Split of responsibilities: **the prompt carries doctrine, the engines carry law.**
Sequences, coverage caps, closure gates, skim detection, budgets and the tamper matrix
are engine-side state machines — a model cannot argue its way past a coverage gate.

## 2. Sequences and gates (aobh.orchestrator.sequences)

- `sequence_next` — the S0–S5 state machine gate (bootstrap → recon → triage → testing
  → validation → report). Returns phase, next legal step and gate readout: mission
  paused → no work; triage debt > 0 → no progress claims; budgets exhausted → testing
  blocked, validation/report never; coverage unregistered → recon first.
- `closure_check` — the 7-condition closure gate: (1) coverage complete (tested or
  `n_a(justified)`), (2) tamper ladder complete for access-control classes, (3) OOB
  registrations all observed or expired, (4) ≥2 auth contexts (advisory while the vault
  is encrypted — verify via `atap_list_accounts`), (5) evidence refs on findings,
  (6) validator sign-off on high+/critical, (7) skim detection (≥0.4 tool calls per
  coverage cell, ≥6 probes per tampered param; `strict=true` promotes warnings to
  failures). `can_close=false` → verdict `incomplete(reason)`; the four-legal-verdicts
  vocabulary is `confirmed | suspected | no_findings_complete | incomplete`.
- State files (engagement dir): `mission.json`, `tasks.json`, `coverage.json`,
  `memory.json`, `findings.json`, `approvals.json`, `tamper.json`, `oob.json` +
  append-only `events/notifications/run_log .jsonl`. A fresh session resumes from these
  files alone.

## 3. Out-of-band channel (aobh.orchestrator.oob_tools)

Shipped backend: **Burp Collaborator via the bridge** — `oob_register` wraps
`get_collaborator_payload` and adds TTL + correlation bookkeeping (`oob.json`:
payload_id, location, registered_at, expires_at, polls, interactions); `oob_poll` wraps
`poll_collaborator` and records poll times per registration. Discipline enforced by
tools + closure gate: register BEFORE the first payload of an OOB-capable class, poll
before claiming, final poll before closure.

Self-hosted interactsh replacement (when Burp Collaborator is not wanted): run an
interactsh-compatible server on your own domain, swap the bridge calls for its
register/poll HTTP API behind the same `oob_register`/`oob_poll` tool surface — no
agent-side changes. Keep `cred_metadata_policy: detect_not_exfiltrate`: cloud metadata
checks prove reachability with a canary path and never exfiltrate contents.

## 4. Layer 12 — parameter tampering with change observation (aobh.tamper)

Doctrine: `skills/param_tampering.md`. Pack: `packs/payloads/access_control.json`.
The pipeline, all through the bridge (scope gate + limiter + audit notes):

1. **`tamper_matrix_build(source)`** — parses the request (query / body_json / body_form
   / x-headers), classifies every parameter into identity / authz / value / state /
   type_confusion / hidden, returns the per-class probe matrix.
2. **`param_tamper_run(source, param, tamper_class, note)`** — baseline first (bridge
   replay of the untouched request), then the ladder ONE VARIABLE PER PROBE
   (`tamper_policy.one_variable_per_probe`), repeat-once confirm for hits and
   deterministic rejects, budget-capped (`tamper_policy.budget_probes_per_asset`).
   Probes land in `tamper.json` with param, variant, signal, attribution, confidence,
   field deltas.
3. **`res_diff(source_a, source_b)`** — the observation engine: volatile fields
   normalized out (`timestamp/nonce/csrf/request_id/tracking/session/trace_id`), lists
   sorted, per-field added/removed/changed deltas → signal classification
   `data_cross | state_change | behavior_change | rejected | noise` with attribution.
   Non-JSON bodies need a >20% length delta to count as behavior change.
4. **`param_discover(source, note)`** — hidden-param mining (debug/verbose/admin/
   internal/test/... ) with reflection and behavior-delta detection; hits feed the
   matrix.
5. **Attribution law** — one variable per probe; two changes ⇒ `NOT_ATTRIBUTABLE`
   (the `diff-analyst` subagent answers exactly that) ⇒ both probes re-run.
6. **Canary law** — `data_cross`/`state_change` confirm only through ATAP canary
   accounts you control (A's session, B's object); third-party data stays `suspected`
   and summarized. Then `validate_finding` (score ≥90 validated; duplicates never
   raise twice) and `raise_issue`.
7. **Verdict mapping** — confirmed (canary-verified `data_cross` / read-path-verified
   `state_change`), suspected (reproducible `behavior_change`), no_findings_complete
   only after full ladder exhaustion with deterministic rejects on record (earned via
   `closure_check`).

## 5. Operating notes

- Run the agent side: `pip install -e ".[dev]"`, load the extension jar in Burp,
  `cp .env.example .env`, then `opencode` in the repo root (the `aobh` MCP server
  auto-starts via `opencode.json`).
- Regenerate the tool index after manifest changes: `make docs` (56-tool surface).
- Offline verification: `make smoke` (6 checks incl. authz gate refusal + manifest
  surface) and `make test` (40 pytest tests incl. the Layer 11/12 suite).
