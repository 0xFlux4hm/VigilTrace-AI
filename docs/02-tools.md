# AOBH tool surface (48 tools)

Generated from `aobh/tools/tools.json` v1.0.0 — the source of truth.
Six groups; every tool keeps the JSON Schema of the proven implementation it wraps.
Folded tools are listed at the bottom.

## burp_bridge (15)

| Tool | Summary | Required args |
|---|---|---|
| `get_proxy_history` | Reads Burp Proxy HTTP history — everything that passed through the proxy (the human's browsing plus agent traffic routed through it). | — |
| `get_site_map` | Reads Burp's site map: every request/response Burp has seen for a host tree, across ALL tools (Proxy, Repeater, scanner, extension traffic added via … | — |
| `search_history` | Regex search across Proxy history AND the agent's own request log (requests and responses). | pattern |
| `extract_parameters` | Enumerates every parameter of a request — query, body form fields, JSON properties (nested, with paths), cookies, multipart attributes, XML — with ty… | source |
| `send_http_request` | Sends a fully controlled HTTP request through Burp's HTTP stack (uses Burp's upstream proxy/TLS configuration; traffic is recorded, annotated and opt… | note |
| `modify_and_resend_request` | The workhorse of differential testing: take an existing request (proxy history item, agent request, or raw), apply precise modifications — set/remove… | source, note |
| `get_response` | Fetches a stored request/response without re-sending anything: from the agent request log, proxy history, or the site map. | source |
| `create_repeater_tab` | Materializes a request as a named tab in Burp Repeater so the human can see, edit and replay it. | — |
| `get_scope` | Returns the current Burp scope plus the agent's authorized-target registry: every prefix authorized in scope. | — |
| `add_to_scope` | Adds a URL prefix to Burp's scope AND to the agent's authorization registry, with provenance (added_from = where the authorization for it came from). | url_prefix, added_from |
| `remove_from_scope` | Removes a prefix from Burp's scope (and, if requested, from the agent registry). | url_prefix |
| `run_simple_fuzz` | Bounded, single-threaded fuzzing in the Burp tradition: take a request template containing the {{FUZZ}} marker, substitute one payload per request, s… | request_template, note_prefix |
| `get_collaborator_payload` | Generates Burp Collaborator payload(s) — unique hostnames that record out-of-band interactions (DNS, HTTP, SMTP) from the target. | — |
| `poll_collaborator` | Polls Collaborator for interactions recorded against generated payloads. | — |
| `raise_issue` | Registers a VALIDATED finding as a real issue in Burp (site map issues list + extension log) with full evidence attached. | title, severity, confidence, url, description |

## mission_control (14)

| Tool | Summary | Required args |
|---|---|---|
| `mission_init` | Initialize the mission: registers target + authorization artifact, declares budgets (default 600 requests / 200 fuzz / 240 min / 2000 tool calls), se… | target, authorization_reference |
| `mission_status` | The dashboard — call it at every checkpoint and whenever unsure what to do next: mission state, budget verdict, queue counts + top ready tasks with p… | — |
| `mission_control` | Mission lifecycle operations: pause/resume, resolve_pause (operator only — lifts the hard pauses raised by scope_drift/target_down events), abort, en… | action |
| `task_enqueue` | Add work to the orchestrated queue: {type, title, priority 0-4, tier 0-3, deps [T-nn], params, hypothesis, max_attempts}. | tasks |
| `task_next` | The planner's hand: returns the highest-priority ready task (dependencies satisfied) with its playbook hint, claims it as running, and enforces the g… | — |
| `task_update` | Close the loop on a claimed task: done (with structured result — the queue unblocks dependents), failed (auto-requeued while attempts < max_attempts,… | task_id |
| `coverage_update` | Record a cell in the coverage matrix (endpoint × vulnerability class): states untested / in_progress / tested_clean / vulnerable / na. | endpoint, vuln_class, state |
| `coverage_gaps` | Ranked untested cells (class weight + endpoint weight: value flows and auth'd endpoints first, state-changing methods +1). | — |
| `event_emit` | Feed an observation to the trigger engine — this is how findings push work instead of the agent polling: collaborator_hit → priority-0 OOB investigat… | type |
| `memory_save` | Persist a target fact that must survive sessions: quirk (target behaves oddly — 'WAF blocks all references'), intel (structure: 'v2 API lacks rate li… | kind, text |
| `memory_search` | Recall target memory by free-text query, kind or tag — call at bootstrap (resume protocol §13. | — |
| `budget_status` | Budget governor readout: usage vs caps (requests, fuzz, tool calls, session minutes) with warn(≥80%) and exhausted(≥100%) flags, observed pace (reque… | — |
| `request_approval` | Create a human approval gate for a risky action (Tier-3 by policy: payloads reaching other users, blind-XSS to admins, race-condition tests, mass OOB… | title, action |
| `validate_finding` | The adversarial validator between 'candidate' and 'finding': scores the declared evidence (differential pair, OOB interaction, cold reproductions, se… | finding |

## rag (4)

| Tool | Summary | Required args |
|---|---|---|
| `rag_query_reports` | Search the corpus of 15,000+ publicly disclosed HackerOne bug bounty reports (reddelexc/hackerone-reports) by free-text query with optional filters. | query |
| `rag_find_similar` | Given a description of YOUR target (tech stack, framework, surface, feature), find the most analogous disclosed HackerOne reports. | target_description |
| `rag_pattern_stats` | Aggregate statistics over the disclosed-report corpus: vulnerability-type heat map with count, median upvotes, paid share, average and max bounty, an… | — |
| `rag_playbook` | Build a playbook seed for a concrete hypothesis: retrieves the closest field-proven disclosed reports (min 2 upvotes), extracts the dominant vuln typ… | hypothesis |

## atap (8)

| Tool | Summary | Required args |
|---|---|---|
| `atap_policy_check` | Determine whether autonomous test-account provisioning is permitted for the target. | — |
| `atap_create_account` | Create a test account on an in-scope target: generates credentials (username, strong random password, strategy-appropriate email), submits the signup… | target, authorization_reference |
| `atap_verify_account` | Complete email verification for a provisioned account: waits for the confirmation mail (catcher or IMAP strategy), extracts the verification link, cl… | account_id |
| `atap_login` | Authenticate a provisioned account through the Burp bridge and capture the session (Set-Cookie pairs and/or bearer/JWT token from the response) into … | account_id |
| `atap_get_session` | Return ready-to-use session material for an account (Cookie header string, Authorization bearer) so hunting tools (send_http_request / modify_and_res… | account_id |
| `atap_account_health` | Maintenance: validate an account's session still works (authenticated GET through the bridge); on 401/403 optionally re-login once and re-check. | — |
| `atap_list_accounts` | List every provisioned test account with lifecycle status (planned → created → awaiting_verification → verified → active → expired → locked → human_a… | — |
| `atap_cleanup` | End-of-engagement lifecycle management (checkpoint A-3): attempt authenticated self-service deletion/deactivation for each account through the bridge… | — |

## waf (4)

| Tool | Summary | Required args |
|---|---|---|
| `waf_fingerprint` | Classify the WAF/CDN in front of a target from one benign response: vendor (Cloudflare, Akamai, Imperva, F5, AWS WAF, ModSecurity, Sucuri, Fastly, . | — |
| `waf_probe` | Run the capped inert probe battery (single GETs, dummy param, non-executing payload strings — . | target |
| `waf_adapt` | Given a blocked request, produce a RANKED list of WAF-normalization transformations (UA normalization, IP-header tricks, X-Original-URL/X-Rewrite-URL… | request |
| `waf_test_bypass` | Apply selected transformations to a blocked request and send each variant through the bridge (annotated 'WAF bypass test [id]'), comparing against th… | request, transform_ids |

## captcha (3)

| Tool | Summary | Required args |
|---|---|---|
| `captcha_detect` | Detect and classify a CAPTCHA/challenge from a page: reCAPTCHA v2/v3, hCaptcha, Turnstile, GeeTest or custom — with the sitekey extracted and the san… | — |
| `captcha_solve` | Get a CAPTCHA token via a sanctioned strategy. | challenge |
| `captcha_test_bypass` | Test whether the TARGET actually validates CAPTCHA tokens server-side — not a solver. | url |

## Folded tools (capability preserved, not exposed separately)

- `task_list` → mission_status already summarizes the queue; engine.task_list stays public for tests
- `check_duplicates` → validate_finding already runs local dedup; validate_finding(dedup_only=true) returns just the verdict
- `notify_operator` → mission_control(action="notify", ...)
- `get_scanner_issues` → dropped from the bridge surface; scanner issues stay visible in Burp's UI
- `send_to_organizer` → dropped from the bridge surface; Organizer stays a manual Burp step
