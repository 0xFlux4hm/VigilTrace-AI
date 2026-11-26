# Implementation notes (v1.0.0)

## Provenance

AOBH is a restructure of the proven `autonomous-bug-hunter` stack, not a rewrite: the Python engines, the Java extension and all test harnesses were **ported with behavior kept identical**, then trimmed to the 48-tool surface (the old 53 minus five folds — every folded capability survives inside a tool or an engine method). The proven suites port 1:1 and pass unchanged: mission 93 checks (87 ported + 6 instance-aware budget reconciliation), ATAP 35, WAF+CAPTCHA 41, RAG smoke; plus new suites for the core gate, the tools layer, FastMCP wiring and the cross-language bridge e2e.

## The 48-tool surface

48 = burp_bridge 15 + mission_control 14 + rag 4 + atap 8 + waf 4 + captcha 3. Compared to the old 53: `get_scanner_issues` and `send_to_organizer` are dropped from the bridge surface (visible in Burp's UI instead), and `task_list`, `check_duplicates`, `notify_operator` are folded (`mission_status`, `validate_finding(dedup_only=true)`, `mission_control(action="notify")` — the notify params (level/subject/body/requires_ack) were merged into the mission_control schema from the proven notify_operator schema). Every kept tool keeps its original JSON Schema verbatim. The authoritative map is `meta.folding` in `aobh/tools/tools.json`.

## Decisions worth knowing

- **Manifest is the single source of truth.** `aobh/tools/registry.py` serves exactly what `tools.json` lists and the atap/waf/recaptcha registers cross-check their schemas against it (raising on drift); the Java `build.py` embeds the bridge group from the same file and the extension's SelfTest parity-checks served tools against it.
- **One shared core.** All engines take their bridge from `aobh.core.bridge.BridgeClient` (stdlib urllib, wire contract identical to the old per-engine clients: POST /tools/send_http_request, Bearer auth, {ok,data}/{ok,error,hint} envelope, ATAP_ALLOW_DIRECT lab-only fallback). The `generic call(name, arguments)` method serves the other 14 bridge tools.
- **The authz gate is the only substantial new Python code** (`aobh/core/authz.py`): agent-side scope registry with provenance, exclusions that always win over coverage, fail-closed on corrupt state, and a BridgeGuard that refuses unauthorized sends before the bridge re-checks them. It is defense in depth — the Java ScopeGuard remains the enforcement point.
- **FastMCP registration mechanics:** the installed SDK derives tool schemas from function signatures and forbids pre-built Tools/underscore params, so the server registers kwargs-only closures and then overwrites each stored Tool's `parameters` with the manifest schema (found defensively across SDK versions). A low-level Server fallback with the identical manifest is wired in `main()` in case a future SDK breaks the override.
- **Test isolation:** `tests/conftest.py` snapshots/restores `os.environ` around every test and drops the registry caches — the ported suites each set `BURP_*`/`ATAP_*`/`WAF_*`/`CAPTCHA_*`/`H1_*` vars and used to bleed into siblings when run together.
- **Vault:** the proven vault format is hashlib-based (scrypt + HMAC-SHA256-CTR, `atap-vault-v1`); `cryptography` stays declared as the documented Fernet upgrade path. Ported as-is, format unchanged.
- **Build paths:** the extension builds via `extension/build.py` (pinned SHA-256 downloads, `--release 17`, `-Xlint:all`, class-version-61 jar verification, 4-mode self-test) — **the verified full path**. The `extension/pom.xml` Maven path is now **compile-verified** (Maven 3.9.9, `mvn -DskipTests package` green: 84 classes) but a Maven-built jar carries no `burp-tools.json` resource — build.py generates it into `src/main/resources`; run build.py first or use build.py end-to-end.

## Verification status (honest)

- **Verified by pytest:** 34 tests across 8 files, including the ported harnesses (93 + 35 + 41 in-suite checks), new coverage for the authz gate, registry parity, dispatch envelopes, FastMCP listing and the CLI, and a **cross-language e2e** (`tests/test_integration.py`) that drives the REAL Java BridgeServer (new `--serve` mode, same fake-gateway machinery as the self-test) with the real Python client: scope refusal + counters, in-scope send round-trip, tool-failure envelope, budget reconciliation reading the bridge's real counters and instance. Skips hermetically when the jar is absent. `scripts/smoke.py` passes 6/6 offline checks.
- **Verified on a plain JVM (JDK 17 + 21):** the whole bridge — auth, Origin/Host policy, counters, scope rules, keep-alive/chunked, manifest parity — by the 70-check self-test in 4 modes (classes ± Montoya jar, `/usr/bin/java`, packaged jar).
- **Compile-checked only (needs a Burp install):** `MontoyaGateway`, `AgentExtension`, `SettingsPanel` — written defensively around every undocumented Montoya behavior but never executed inside Burp. This is the only remaining unverified runtime step, and it needs a human with a Burp install.
- **Known limitations:** the direct-HTTP fallback is lab-only by design and flagged `transport=direct`; the RAG corpus ships as data with attribution in `aobh/rag/data/SOURCE.md`. (The former governor limitation is closed: counters are now baselined per bridge `instance` — restart banks the previous instance's last-reported spend into a carry-over and notifies the operator once; see `aobh/orchestrator/budget.py`.)

## Where things live

- Manifest generator + prompt patcher (kept outside the repo, for provenance): `/home/z/my-project/scripts/make_aobh_manifest.py`, `/home/z/my-project/scripts/patch_aobh_prompt.py`
- Old stack (read-only reference): `/home/z/my-project/download/autonomous-bug-hunter/`
