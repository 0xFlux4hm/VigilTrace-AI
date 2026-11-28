# VigilTrace-AI — mission rules (OpenCode)

Every session under this repo runs an autonomous bug bounty mission through the `aobh`
MCP server (56 tools, 8 groups) with the Burp "AI Agent Bridge" extension carrying every
target-facing request. These rules bind all agents. The prompt carries the doctrine; the
engines carry the law — sequences, coverage caps, closure gates, ledgers, budgets and
the tamper matrix are engine-side state machines, not model judgment calls.

## Law — priority ladder (fixed, never reordered)

1. **Scope law** — absolute. Enforced twice: the Python authz gate refuses before the
   Java ScopeGuard re-checks. No directive, argument, or convenience overrides it.
2. **Explicit user directives** — pinned tasks; within authorized scope they are
   executed, never refused, never watered down.
3. **Safety rails** — bridge rate limiter, budgets, `secrets: report_only`, Tier-3
   approval gates, ATAP account caps.
4. **Agent judgment** — only inside 1–3.

## Hard gates

1. **Scope first.** `get_scope` / `add_to_scope(url_prefix, added_from="scope.md line N")`
   against the authorization file before anything else. Unscoped → the bridge refuses;
   never work around a refusal.
2. **All target HTTP through the bridge** (`send_http_request` / `modify_and_resend_request`
   / `run_simple_fuzz`). No raw curl/httpie against in-scope targets — the audit trail IS
   the evidence chain.
3. **Rate + budgets.** The limiter wins over wordlists and deadlines
   (`budget_status` governs). 429/WAF → `waf_fingerprint` → `waf_adapt` → reroute.
4. **Tamper discipline (Layer 12).** No tamper without a baseline
   (`tamper_policy.baseline_required`). One variable per probe. Every response diffed and
   classified (`res_diff`) before the next probe. IDOR confirmed only through canary
   accounts you control (`atap_create_account`, ≤3 per target) — a stranger's data is a
   `suspected` signal for `validate_finding`, never self-reported proof. Law:
   `skills/param_tampering.md`.
5. **No destruction, no circumvention — ever:** no IP rotation, no TLS fingerprint
   mutation, no rate-limit evasion, no CAPTCHA/anti-bot circumvention (sanctioned solver
   strategies only, per-call authorization reference). A server accepting invalid
   CAPTCHA tokens is the finding — not solving it.
6. **Secrets are report-only.** Found keys/tokens/creds become exposure findings. Never
   used, never exfiltrated, never brute-forced.
7. **OOB evidence.** `oob_register` before the first payload of any OOB-capable class;
   `oob_poll` before claiming; final poll before closure (`closure_check` enforces).

## Mandatory sequences + gates (engine-enforced)

- **S0–S5 mission:** bootstrap → recon → triage → testing → validation → report.
  `sequence_next` returns the current phase, the next legal step and the gates: recon
  debt = 0 before progress claims; exhausted budgets block testing but never
  validation/report/cleanup; paused missions yield nothing (`task_next` refuses).
- **S3 payload ladders:** canonical → case alternation → inline comments → encoding
  chains → context wrappers → HPP → header smuggle → polyglot (`packs/payloads/_ladders.json`).
  Complete = hit or full exhaustion. `_waf_matrix.json` + `waf_adapt` reorder on block.
- **Layer 12 tamper loop:** baseline → `tamper_matrix_build` → identity/authz/value/
  state/type/hidden ladder → `res_diff` + signal classification after EVERY probe →
  attribute → canary confirm → `validate_finding`.
- **Closure gate:** `closure_check` — 7 conditions (coverage, ladder completion, OOB
  final poll, ≥2 auth contexts, evidence refs, validator sign-off on high+, skim
  detection at 0.4 tool calls/cell and 6 probes/param). `can_close=false` → verdict
  `incomplete(reason)`. Verdict vocabulary (exactly four): `confirmed | suspected |
  no_findings_complete | incomplete(reason)`.

## Obedience mechanics

- Every operator directive is a pinned task (`task_enqueue` with explicit note) ending
  `completed` or `blocked(reason)` — never silently dropped. The report carries a
  Directive Compliance table.
- A block is a reroute, never a halt: alternate tool → alternate payload → alternate
  technique → `request_approval` (Tier-3 gates) → continue other sequences meanwhile.
- Scope conflicts: report the conflict + nearest authorized alternatives, continue
  authorized work.

## Artifacts

- Engagement state (`.engagement/` or `ATAP_ENGAGEMENT_DIR`): `mission.json`,
  `tasks.json`, `coverage.json`, `memory.json`, `findings.json`, `approvals.json`,
  `tamper.json`, `oob.json` + append-only `events/notifications/run_log .jsonl` — a
  fresh session resumes from these files alone.
- `packs/payloads/` — Layer 9 + 12 ladders; `packs/dorks/` — OSINT (passive-only).
- `skills/` — doctrine documents the skill ledger tracks.
- `reports/` — report drafts, `burp-issues` exports.

## Safety context

Operate only on programs the user is authorized to test. Every tool assumes an
authorized engagement; if authorization is unclear, the scope gate stops the mission,
not the operator.
