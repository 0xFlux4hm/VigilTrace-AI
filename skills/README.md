# skills/ — operator skill library

Skills are doctrine documents the agents load before exercising the capability they
govern; the mission skill ledger tracks them per asset, and `closure_check` refuses a
close-out when a required skill for an exercised capability was never loaded.

## Live

| Skill | Governs | Mandatory when |
|---|---|---|
| [`param_tampering.md`](param_tampering.md) | Layer 12: tamper matrix, baseline law, one-variable probes, `res_diff` observation, signal taxonomy, canary IDOR confirmation, FP list | asset exposes object IDs, role-bearing state, priced actions, or server-trusted params |

## Planned

- `payload_ladders.md` — S3 stage order (`_ladders.json`), `waf_adapt` mutation policy
- `oob_hunting.md` — `oob_register`/`oob_poll` discipline, correlation, poll-before-claim
- `recon_triage.md` — proxy-history-first recon, scoring vocabulary, saturation honesty
- `report_quality.md` — evidence bundles, severity discipline, Directive Compliance table

Adding a skill: one markdown file with the same section discipline as
`param_tampering.md` (when-mandatory → loop/matrix → rules → verdicts → FP list),
then register it here and in the closure gate's `required_skills_when_applicable`.
