"""aobh — Autonomous Orchestrated Bug Hunter (AUTHORIZED SECURITY TESTING ONLY).

An MCP server exposing 48 tools over six groups, backed by four local engines
and a Burp Suite Montoya extension that carries every target-facing request:

  aobh.core          config, bridge client, authorization gate, shared utils
  aobh.orchestrator  mission lifecycle, task DAG, coverage, memory, budget,
                     approvals, triggers, phases, adversarial validator
  aobh.rag           disclosed-report corpus: ingest, embed, retrieve precedents
  aobh.atap          account vault, registrar/verifier, session leases, mailcatch
  aobh.waf           WAF fingerprinting, probe battery, bypass transforms
  aobh.recaptcha     CAPTCHA detection, sanctioned solver strategies
  aobh.tools         48-tool manifest, handler registry, FastMCP server, CLI

See docs/01-system-prompt.md (the agent's system prompt), docs/02-tools.md
(generated tool index), docs/04-architecture.md and docs/bridge-protocol.md.
"""

from __future__ import annotations

__version__ = "1.0.0"
