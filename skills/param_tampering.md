# Skill: parameter tampering with change observation (Layer 12)

Required skill whenever an asset exposes object identifiers, role-bearing state, priced
actions, or server-trusted parameters (the closure gate enforces this via
`required_skills_when_applicable`). Core loop: **BASELINE → TAMPER (one variable per
probe) → OBSERVE (res_diff) → ATTRIBUTE → VERDICT**. A tamper without observation is a
random request, not testing.

## 1. Baseline first (no exceptions)

`param_tamper_run` captures the baseline automatically (bridge replay of the untouched
request). Rules the engine enforces:

1. The baseline is the ONLY comparison target — never compare tampered responses to
   each other; that hides the delta you are hunting.
2. Run the baseline twice mentally: if the endpoint is `noisy` (cache variants, rotating
   tokens, A/B), the normalizer strips volatile fields
   (`tamper_policy.normalize_volatile_fields`) and `res_diff` classifies leftover jitter
   as `noise` — it must NAME the excluded fields.

## 2. The tamper matrix (`tamper_matrix_build`)

Classifies every parameter/header into a tamper class:

| Class | Candidates | Typical tamper |
|---|---|---|
| **identity** | user_id, account_id, order_id, doc_id, uuid, email | substitute canary peer identifier; sequential/zero/negative/high ids; concatenation |
| **authz** | role, is_admin, admin, level, permissions, groups, verified | add or flip (mass assignment): `"role":"admin"`, `"is_admin":true`, `"permissions":["*"]` |
| **value** | price, amount, quantity, discount, total, limit | negative, zero, sub-unit (`0.0000001`), int-max, overflow |
| **state** | status, approved, active, locked, paid | forward flips (`"paid"`) and backward flips (map guardrails) |
| **type** | any scalar | `"1"`→`1`→`[1]`→`{"$ne":null}`→`null`→`true` |
| **hidden** | discovered via `param_discover` | debug/verbose/admin/internal/test/source |

Sort by expected value: identity on object-bearing endpoints, authz on role-bearing
endpoints, value/state on transaction endpoints, type/hidden everywhere cheap.

## 3. One variable per probe (attribution law)

`param_tamper_run` changes exactly ONE parameter per probe. Two changes in one probe =
unattributable delta = wasted budget. When a tamper needs a matching pair (id +
signature), treat the pair as ONE variable and note it in the run note.

## 4. Observe every change (`res_diff`)

Every probe is diffed against baseline and classified:

- **`data_cross`** — another principal's data appears (identity-field regex on added/changed
  fields). → canary confirmation path, then `validate_finding`.
- **`state_change`** — server accepted a mutation. → verify on an independent READ path;
  echo-back alone is not proof.
- **`behavior_change`** — different code path (status change, new field set, different error
  class) without principal data. → suspected tier.
- **`rejected`** — deterministic explicit denial (403). Guardrail mapped; record and continue.
- **`noise`** — volatile jitter only. Normalizer strips `timestamp/nonce/csrf/request_id/
  tracking/session/trace_id`; non-JSON bodies need a >20% length delta to count.

Repeat-once rule: hits and deterministic rejects are repeated once (the engine does this
automatically when budget allows). A single observation is `low` confidence, never a verdict.

## 5. Canary confirmation (IDOR law)

`data_cross` and `state_change` confirm ONLY through accounts you control: session of
canary account A, object owned by canary account B — provisioned via `atap_create_account`
(max 3 per target, credentials encrypted, disclosed + cleaned up at close-out).
Observing a real third party's data = `suspected` signal, evidence for the operator,
summarized in the report — never quoted, never re-fetched for volume.

## 6. Budgets and rate

- `tamper_policy.budget_probes_per_asset` (default 60) — the engine refuses beyond it.
- The bridge limiter wins (2 req/s default). 429/WAF → `waf_fingerprint` → `waf_adapt`
  (boost stages from `_waf_matrix.json`) → reroute. Never retry harder.
- Destructive tamper values exist only when the mission explicitly authorizes them AND
  the Tier-3 approval gate is cleared (budgets/ATAP/WAF boundaries still apply).

## 7. Verdict mapping and evidence

| Observation | Verdict | Evidence bundle |
|---|---|---|
| `data_cross` confirmed via canaries | confirmed | baseline/tampered refs + field diff + canary walkthrough |
| `state_change` verified on read path | confirmed | refs + independent read showing the change |
| `behavior_change` reproducible | suspected | refs + diff + named uncertainty |
| `noise` only | no signal | nothing raised; class marked exercised |
| all classes exhausted, deterministic rejects | no_findings_complete (this class) | matrix + rejects ledger — earned, not assumed |

Every verdict writes probe records to `tamper.json` (param, class, variant, signal,
attribution, confidence, field deltas). No attribution, no verdict.

## 8. Common false positives (memorize)

- Reflected-in-response params (the app echoes your tamper — not server-side trust)
- Cache/CDN variant bleed (stabilize with cache-busters before diffing)
- A/B experiment buckets (stable per session — compare within one session)
- Length-only deltas with identical parsed bodies (normalize before believing)
- CSRF/token rotation changing hashes every replay (normalized out; verify)
- HPP first-vs-last parser ambiguity (test both orders before claiming)
